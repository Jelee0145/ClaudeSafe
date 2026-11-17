using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ClaudeSafe.Models;

namespace ClaudeSafe.Services;

/// <summary>
/// 启动前 6 维网络与风控安全检测引擎
/// </summary>
public sealed class NetworkCheckService
{
    private static readonly HashSet<string> BlockedCountryCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        "CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU"
    };

    private static readonly HashSet<string> AsianUtc8Or9Countries = new(StringComparer.OrdinalIgnoreCase)
    {
        "TW", "SG", "MY", "PH", "JP", "KR", "AU"
    };

    private static readonly string[] DatacenterKeywords =
    {
        "Cloudflare", "Datacamp", "Choopa", "Vultr", "DigitalOcean", "Linode", "Akamai",
        "Amazon", "AWS", "Google", "Microsoft", "Azure", "Hetzner", "OVH", "DMIT",
        "IT7", "Cogent", "Zenlayer", "Leaseweb", "M247", "Tzulo", "Multacom", "RackNerd",
        "Aliyun", "Alibaba", "Tencent", "Oracle", "Contabo", "BuyVM", "Bandwagon",
        "Misaka", "ColoCrossing", "GCore", "Quadranet", "Psychz", "Scaleway", "Kamatera"
    };

    private const string BrowserUserAgent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

    private readonly ProxyDetectorService _proxyDetector;

    public NetworkCheckService(ProxyDetectorService proxyDetector)
    {
        _proxyDetector = proxyDetector;
    }

    public static bool IsBlockedCountryCode(string? countryCode)
    {
        return !string.IsNullOrWhiteSpace(countryCode) && BlockedCountryCodes.Contains(countryCode);
    }

    public async Task<PreFlightReport> RunPreFlightCheckAsync(
        AppConfig config,
        CancellationToken cancellationToken = default)
    {
        var proxyProbe = await _proxyDetector
            .DetectBestUpstreamProxyAsync(config.UpstreamProxyHost, config.UpstreamProxyPort, config.GatekeeperPort, cancellationToken)
            .ConfigureAwait(false);

        IpGeoInfo? exitIp = null;
        bool anthropicReachable = false;
        string? anthropicTraceCountry = null;

        if (proxyProbe.IsReachable)
        {
            using var httpClient = CreateProxiedHttpClient(proxyProbe.Host, proxyProbe.Port, TimeSpan.FromSeconds(7));

            // 第一步：先直连探测 claude.ai/cdn-cgi/trace 获取抵达 Claude 的真实出口 IP（免疫通用规则分流干扰）
            IpGeoInfo? traceInfo;
            (anthropicReachable, anthropicTraceCountry, traceInfo) =
                await ProbeAnthropicTraceAndConnectivityAsync(httpClient, cancellationToken).ConfigureAwait(false);

            // 第二步：以 claude.ai 真实出口 IP 反查 ASN/ISP/纯净度画像（若 claude.ai 不可达则回退通用探测辅助排查）
            exitIp = await FetchExitIpInfoAsync(httpClient, traceInfo?.Ip, traceInfo, cancellationToken)
                .ConfigureAwait(false);
        }

        var items = EvaluateRiskItems(proxyProbe, exitIp, anthropicReachable, anthropicTraceCountry, config);
        var hasDanger = items.Any(x => x.RiskLevel == RiskLevel.Danger);
        var hasWarnings = items.Any(x => x.RiskLevel == RiskLevel.Warning);

        string summary;
        if (hasDanger)
        {
            var firstDanger = items.First(x => x.RiskLevel == RiskLevel.Danger);
            summary = $"发现高危阻断项：{firstDanger.Title} — {firstDanger.StatusText}";
        }
        else if (hasWarnings)
        {
            var warnCount = items.Count(x => x.RiskLevel == RiskLevel.Warning);
            summary = $"未发现高危阻断，存在 {warnCount} 项风控提醒，请确认后启动";
        }
        else
        {
            summary = "全部 6 项检测均为安全，可放心启动 Claude Desktop";
        }

        return new PreFlightReport
        {
            CheckedAt = DateTimeOffset.Now,
            ProxyProbe = proxyProbe,
            ExitIpInfo = exitIp,
            AnthropicReachable = anthropicReachable,
            AnthropicTraceCountry = anthropicTraceCountry,
            CheckItems = items,
            CanLaunch = !hasDanger,
            HasWarnings = hasWarnings,
            Summary = summary
        };
    }

    public async Task<IpGeoInfo?> FetchExitIpThroughProxyAsync(
        string proxyHost,
        int proxyPort,
        CancellationToken cancellationToken = default)
    {
        using var httpClient = CreateProxiedHttpClient(proxyHost, proxyPort, TimeSpan.FromSeconds(6));
        return await FetchClaudeTraceInfoAsync(httpClient, cancellationToken).ConfigureAwait(false);
    }

    public List<CheckItemResult> EvaluateRiskItems(
        ProxyProbeResult proxyProbe,
        IpGeoInfo? exitIp,
        bool anthropicReachable,
        string? anthropicTraceCountry,
        AppConfig config)
    {
        var items = new List<CheckItemResult>(6)
        {
            EvaluateProxyChannel(proxyProbe),
            EvaluateExitIpCompliance(proxyProbe, exitIp),
            EvaluateIpPurity(proxyProbe, exitIp),
            EvaluateHistoricalIpDrift(proxyProbe, exitIp, config.LastSafeIpRecord),
            EvaluateAnthropicConnectivity(proxyProbe, exitIp, anthropicReachable, anthropicTraceCountry),
            EvaluateSystemEnvironment(proxyProbe, exitIp)
        };

        return items;
    }

    private static CheckItemResult EvaluateProxyChannel(ProxyProbeResult proxyProbe)
    {
        if (!proxyProbe.IsReachable)
        {
            return new CheckItemResult
            {
                Id = "proxy_channel",
                Title = "1. 本地代理通道与模式检测",
                ShortTitle = "代理模式",
                Category = "代理连通",
                RiskLevel = RiskLevel.Danger,
                StatusText = $"端口 {proxyProbe.Host}:{proxyProbe.Port} 不可达",
                ShortStatus = "未连接",
                Detail = "未能连接到本地代理软件（如 FlClash / Clash / v2rayN）。严禁在无代理时直连启动 Claude。",
                Recommendation = "请先启动代理客户端并确认混合/HTTP 代理端口（常见为 7890 / 7897 / 10809），然后点击重新检测。"
            };
        }

        if (!proxyProbe.TunModeEnabled && !proxyProbe.SystemProxyEnabled)
        {
            return new CheckItemResult
            {
                Id = "proxy_channel",
                Title = "1. 本地代理通道与模式检测",
                ShortTitle = "代理模式",
                Category = "代理连通",
                RiskLevel = RiskLevel.Danger,
                StatusText = "高危阻断：TUN 模式与系统代理均未开启",
                ShortStatus = "未开TUN/系代",
                Detail = $"虽然本地代理端口 ({proxyProbe.Host}:{proxyProbe.Port}) 在监听，但当前系统处于直连状态（未开 TUN 虚拟网卡，也未开启系统代理），直接放行会导致网页端或子进程裸连暴露真实 IP！",
                Recommendation = "请在代理软件中开启【TUN 模式】（强烈推荐）或开启【系统代理】后，再点击重新检测。"
            };
        }

        if (!proxyProbe.TunModeEnabled && proxyProbe.SystemProxyEnabled)
        {
            return new CheckItemResult
            {
                Id = "proxy_channel",
                Title = "1. 本地代理通道与模式检测",
                ShortTitle = "代理模式",
                Category = "代理连通",
                RiskLevel = RiskLevel.Warning,
                StatusText = $"仅开启系统代理 · 未开 TUN ({proxyProbe.LatencyMs} ms)",
                ShortStatus = "仅系统代理",
                Detail = $"代理通道：{proxyProbe.SourceDescription}。当前仅开启了 Windows 系统代理，未检测到 TUN 虚拟网卡。",
                Recommendation = "建议在代理软件中开启【TUN 模式】后再启动，以更彻底地接管所有子进程与浏览器流量。"
            };
        }

        if (proxyProbe.LatencyMs > 500)
        {
            return new CheckItemResult
            {
                Id = "proxy_channel",
                Title = "1. 本地代理通道与模式检测",
                ShortTitle = "代理模式",
                Category = "代理连通",
                RiskLevel = RiskLevel.Warning,
                StatusText = $"TUN 已开启但延迟偏高 ({proxyProbe.LatencyMs} ms)",
                ShortStatus = "TUN 偏慢",
                Detail = $"上游代理：{proxyProbe.SourceDescription}，TUN 网卡：{proxyProbe.TunAdapterName}，系统代理：{(proxyProbe.SystemProxyEnabled ? "已开启" : "未开启（已由 TUN 接管）")}。",
                Recommendation = "本地回环响应延迟偏高，请检查代理软件是否卡顿。"
            };
        }

        return new CheckItemResult
        {
            Id = "proxy_channel",
            Title = "1. 本地代理通道与模式检测",
            ShortTitle = "代理模式",
            Category = "代理连通",
            RiskLevel = RiskLevel.Safe,
            StatusText = $"TUN 模式已开启 ({proxyProbe.TunAdapterName} · {proxyProbe.LatencyMs} ms)",
            ShortStatus = $"TUN · {proxyProbe.LatencyMs}ms",
            Detail = $"上游代理：{proxyProbe.SourceDescription}，TUN 网卡：{proxyProbe.TunAdapterName}，系统代理：{(proxyProbe.SystemProxyEnabled ? "已开启" : "未开启（已由 TUN 接管）")}。",
            Recommendation = "已开启 TUN 模式配合守门代理，全局防泄漏保护最佳。"
        };
    }

    private static CheckItemResult EvaluateExitIpCompliance(ProxyProbeResult proxyProbe, IpGeoInfo? exitIp)
    {
        if (!proxyProbe.IsReachable)
        {
            return new CheckItemResult
            {
                Id = "exit_region",
                Title = "2. 出口 IP 与地区合规检测",
                ShortTitle = "出口地区",
                Category = "地区合规",
                RiskLevel = RiskLevel.Danger,
                StatusText = "跳过（上游代理不可用）",
                ShortStatus = "未探测",
                Detail = "本地代理端口未连通，无法探测安全出口 IP。",
                Recommendation = "请先恢复本地代理服务。"
            };
        }

        if (exitIp == null || string.IsNullOrWhiteSpace(exitIp.Ip) || string.IsNullOrWhiteSpace(exitIp.CountryCode))
        {
            return new CheckItemResult
            {
                Id = "exit_region",
                Title = "2. 出口 IP 与地区合规检测",
                ShortTitle = "出口地区",
                Category = "地区合规",
                RiskLevel = RiskLevel.Danger,
                StatusText = "无法获取代理出口 IP",
                ShortStatus = "探测失败",
                Detail = "通过本地代理请求多路 GeoIP 检测源均超时或失败，当前节点可能已断网或无效。",
                Recommendation = "请在代理软件中切换可用节点，测试外网连通后重试。"
            };
        }

        if (BlockedCountryCodes.Contains(exitIp.CountryCode))
        {
            return new CheckItemResult
            {
                Id = "exit_region",
                Title = "2. 出口 IP 与地区合规检测",
                ShortTitle = "出口地区",
                Category = "地区合规",
                RiskLevel = RiskLevel.Danger,
                StatusText = $"高危禁区：{exitIp.CountryCode} ({exitIp.Ip})",
                ShortStatus = $"{exitIp.CountryCode} · 禁区",
                Detail = $"当前代理出口位于 {exitIp.DisplayLocation}，属于 Anthropic 明确封禁/不支持地区，启动即触发封号或拒绝服务！",
                Recommendation = "请在代理软件中切换至美国(US)、日本(JP)、新加坡(SG)、英国(GB)或台湾(TW)等支持地区节点。"
            };
        }

        return new CheckItemResult
        {
            Id = "exit_region",
            Title = "2. 出口 IP 与地区合规检测",
            ShortTitle = "出口地区",
            Category = "地区合规",
            RiskLevel = RiskLevel.Safe,
            StatusText = $"合规地区：{exitIp.CountryCode} · {exitIp.Ip}",
            ShortStatus = $"{exitIp.CountryCode} · 合规",
            Detail = $"位置：{exitIp.DisplayLocation}（数据源：{exitIp.Source}，探测耗时 {exitIp.LatencyMs} ms）。",
            Recommendation = "当前出口地区在 Anthropic 服务支持范围内。"
        };
    }

    private static CheckItemResult EvaluateIpPurity(ProxyProbeResult proxyProbe, IpGeoInfo? exitIp)
    {
        if (!proxyProbe.IsReachable || exitIp == null)
        {
            return new CheckItemResult
            {
                Id = "ip_purity",
                Title = "3. IP 属性与机房纯净度评估",
                ShortTitle = "IP 纯净度",
                Category = "IP 质量",
                RiskLevel = RiskLevel.Warning,
                StatusText = "未获取到 ASN 信息",
                ShortStatus = "未获取",
                Detail = "依赖出口 IP 检测结果。",
                Recommendation = "请先解决代理连通与出口探测问题。"
            };
        }

        var combinedMeta = $"{exitIp.Isp} {exitIp.Org} {exitIp.Asn}";
        var matchedKeyword = DatacenterKeywords.FirstOrDefault(k =>
            combinedMeta.Contains(k, StringComparison.OrdinalIgnoreCase));

        if (exitIp.IsHosting || exitIp.IsProxy || matchedKeyword != null)
        {
            var reason = matchedKeyword != null
                ? $"命中机房/云厂商特征 ({matchedKeyword})"
                : exitIp.IsHosting ? "GeoIP 标记为 Hosting/IDC 数据中心" : "GeoIP 标记为公共代理节点";

            return new CheckItemResult
            {
                Id = "ip_purity",
                Title = "3. IP 属性与机房纯净度评估",
                ShortTitle = "IP 纯净度",
                Category = "IP 质量",
                RiskLevel = RiskLevel.Warning,
                StatusText = "机房 / 共享节点 IP（中等风控权重）",
                ShortStatus = "机房节点",
                Detail = $"{reason}。ISP：{exitIp.Isp} | ASN：{exitIp.Asn}。",
                Recommendation = "机场或普通 VPS 机房 IP 属于共享出口，切勿在会话期间频繁切换节点；如有条件建议使用独享静态住宅 IP。"
            };
        }

        return new CheckItemResult
        {
            Id = "ip_purity",
            Title = "3. IP 属性与机房纯净度评估",
            ShortTitle = "IP 纯净度",
            Category = "IP 质量",
            RiskLevel = RiskLevel.Safe,
            StatusText = "非数据中心 / 较纯净 ISP",
            ShortStatus = "较纯净 ISP",
            Detail = $"ISP：{exitIp.Isp} | Org：{exitIp.Org} | ASN：{exitIp.Asn}。",
            Recommendation = "当前 IP 未触发常见机房黑名单特征，风控风险较低。"
        };
    }

    private static CheckItemResult EvaluateHistoricalIpDrift(
        ProxyProbeResult proxyProbe,
        IpGeoInfo? exitIp,
        HistoricalIpRecord? lastSafe)
    {
        if (!proxyProbe.IsReachable || exitIp == null)
        {
            return new CheckItemResult
            {
                Id = "ip_drift",
                Title = "4. 历史 IP 漂移防风控对比",
                ShortTitle = "IP 防漂移",
                Category = "防漂移",
                RiskLevel = RiskLevel.Warning,
                StatusText = "暂无法比对",
                ShortStatus = "无法比对",
                Detail = "未能获取到本次出口 IP。",
                Recommendation = "等待出口探测成功后进行比对。"
            };
        }

        if (lastSafe == null || string.IsNullOrWhiteSpace(lastSafe.Ip))
        {
            return new CheckItemResult
            {
                Id = "ip_drift",
                Title = "4. 历史 IP 漂移防风控对比",
                ShortTitle = "IP 防漂移",
                Category = "防漂移",
                RiskLevel = RiskLevel.Safe,
                StatusText = "首次记录基线 IP",
                ShortStatus = "首次基线",
                Detail = $"暂无历史会话记录。本次安全启动后将把 {exitIp.Ip} ({exitIp.CountryCode}) 设为后续漂移基线。",
                Recommendation = "建议后续尽量固定同一地区与节点登录 Claude。"
            };
        }

        if (string.Equals(lastSafe.Ip, exitIp.Ip, StringComparison.OrdinalIgnoreCase))
        {
            return new CheckItemResult
            {
                Id = "ip_drift",
                Title = "4. 历史 IP 漂移防风控对比",
                ShortTitle = "IP 防漂移",
                Category = "防漂移",
                RiskLevel = RiskLevel.Safe,
                StatusText = "与上次安全 IP 完全一致",
                ShortStatus = "与上次一致",
                Detail = $"本次出口 {exitIp.Ip} ({exitIp.CountryCode}) 与上次启动（{lastSafe.RecordedAt:MM-dd HH:mm}）完全相同。",
                Recommendation = "IP 稳定性极佳，账号风控概率最低。"
            };
        }

        if (!string.Equals(lastSafe.CountryCode, exitIp.CountryCode, StringComparison.OrdinalIgnoreCase))
        {
            return new CheckItemResult
            {
                Id = "ip_drift",
                Title = "4. 历史 IP 漂移防风控对比",
                ShortTitle = "IP 防漂移",
                Category = "防漂移",
                RiskLevel = RiskLevel.Warning,
                StatusText = $"⚠️ 跨国 IP 瞬移：{lastSafe.CountryCode} → {exitIp.CountryCode}",
                ShortStatus = $"{lastSafe.CountryCode}→{exitIp.CountryCode} 跨国",
                Detail = $"上次安全 IP 为 {lastSafe.Ip} ({lastSafe.Country} · {lastSafe.RecordedAt:MM-dd HH:mm})，当前变为 {exitIp.Ip} ({exitIp.Country})。短时间跨国跳变极易触发风控！",
                Recommendation = "强烈建议切回原国家节点；若原节点已永久失效且必须更换国家，请确认间隔时间足够长再点击启动。"
            };
        }

        return new CheckItemResult
        {
            Id = "ip_drift",
            Title = "4. 历史 IP 漂移防风控对比",
            ShortTitle = "IP 防漂移",
            Category = "防漂移",
            RiskLevel = RiskLevel.Warning,
            StatusText = $"同国 IP 变更 ({exitIp.CountryCode})",
            ShortStatus = "同国 IP 变更",
            Detail = $"上次 IP：{lastSafe.Ip} ({lastSafe.Asn}) → 当前 IP：{exitIp.Ip} ({exitIp.Asn})，国家保持一致。",
            Recommendation = "同国家内更换 IP 风险可控，但仍建议在代理软件中固定具体节点而非使用自动测速/负载均衡。"
        };
    }

    private static CheckItemResult EvaluateAnthropicConnectivity(
        ProxyProbeResult proxyProbe,
        IpGeoInfo? exitIp,
        bool anthropicReachable,
        string? anthropicTraceCountry)
    {
        if (!proxyProbe.IsReachable)
        {
            return new CheckItemResult
            {
                Id = "anthropic_conn",
                Title = "5. Anthropic 连通性与防泄漏验证",
                ShortTitle = "分流防漏",
                Category = "分流防漏",
                RiskLevel = RiskLevel.Danger,
                StatusText = "无法验证（代理未连接）",
                ShortStatus = "未验证",
                Detail = "未发现可用代理端口。",
                Recommendation = "请开启本地代理后重新检测。"
            };
        }

        if (!anthropicReachable)
        {
            return new CheckItemResult
            {
                Id = "anthropic_conn",
                Title = "5. Anthropic 连通性与防泄漏验证",
                ShortTitle = "分流防漏",
                Category = "分流防漏",
                RiskLevel = RiskLevel.Danger,
                StatusText = "无法连接 claude.ai",
                ShortStatus = "连接失败",
                Detail = "通过当前代理访问 https://claude.ai/cdn-cgi/trace 失败或超时，可能节点被 Cloudflare 阻断或网络不通。",
                Recommendation = "请更换支持 Claude 访问的代理节点并重试。"
            };
        }

        if (!string.IsNullOrWhiteSpace(anthropicTraceCountry) && BlockedCountryCodes.Contains(anthropicTraceCountry))
        {
            return new CheckItemResult
            {
                Id = "anthropic_conn",
                Title = "5. Anthropic 连通性与防泄漏验证",
                ShortTitle = "分流防漏",
                Category = "分流防漏",
                RiskLevel = RiskLevel.Danger,
                StatusText = $"分流泄漏警告：Claude 侧识别为 {anthropicTraceCountry}",
                ShortStatus = $"泄漏 ({anthropicTraceCountry})",
                Detail = $"虽然 GeoIP 查询正常，但通过代理实际抵达 claude.ai 的出口国家代码为 {anthropicTraceCountry}（受限地区），存在严重的分流规则泄漏！",
                Recommendation = "请检查 Clash/代理分流规则，确保 *.anthropic.com 和 *.claude.ai 全部走海外代理而不是 DIRECT。"
            };
        }

        if (exitIp != null &&
            !string.IsNullOrWhiteSpace(anthropicTraceCountry) &&
            !string.Equals(exitIp.CountryCode, anthropicTraceCountry, StringComparison.OrdinalIgnoreCase))
        {
            return new CheckItemResult
            {
                Id = "anthropic_conn",
                Title = "5. Anthropic 连通性与防泄漏验证",
                ShortTitle = "分流防漏",
                Category = "分流防漏",
                RiskLevel = RiskLevel.Warning,
                StatusText = $"分流节点不一致 ({exitIp.CountryCode} vs {anthropicTraceCountry})",
                ShortStatus = $"{exitIp.CountryCode}/{anthropicTraceCountry} 混用",
                Detail = $"GeoIP 出口为 {exitIp.CountryCode}，但 claude.ai 落地国家为 {anthropicTraceCountry}，说明代理软件可能对 Anthropic 走了不同策略组。",
                Recommendation = "建议在代理规则中将 Anthropic / Claude 域名与 IP 检测站点归入同一策略组。"
            };
        }

        return new CheckItemResult
        {
            Id = "anthropic_conn",
            Title = "5. Anthropic 连通性与防泄漏验证",
            ShortTitle = "分流防漏",
            Category = "分流防漏",
            RiskLevel = RiskLevel.Safe,
            StatusText = string.IsNullOrWhiteSpace(anthropicTraceCountry)
                ? "claude.ai TLS 连通正常"
                : $"claude.ai 连通正常 (落地 {anthropicTraceCountry})",
            ShortStatus = string.IsNullOrWhiteSpace(anthropicTraceCountry)
                ? "TLS 畅通"
                : $"畅通 ({anthropicTraceCountry})",
            Detail = "经本地代理转发访问 Anthropic 域名链路畅通，未发现直连/DNS 泄漏。",
            Recommendation = "运行期间守门代理将持续锁死该路由。"
        };
    }

    private static CheckItemResult EvaluateSystemEnvironment(ProxyProbeResult proxyProbe, IpGeoInfo? exitIp)
    {
        if (proxyProbe.RunningAccelerators is { Count: > 0 })
        {
            var names = string.Join("、", proxyProbe.RunningAccelerators);
            return new CheckItemResult
            {
                Id = "sys_env",
                Title = "6. 加速器冲突与环境检测",
                ShortTitle = "加速/环境",
                Category = "冲突与环境",
                RiskLevel = RiskLevel.Warning,
                StatusText = $"检测到游戏加速器运行中：{names}",
                ShortStatus = "加速器运行中",
                Detail = $"后台检测到 {names} 进程或虚拟网卡。即便当前未开启加速，也请留意路由冲突；若正在加速游戏，其驱动极易将流量劫持至香港(HK)或国内中转节点导致触发 Claude 封禁！",
                Recommendation = "建议在使用 Claude 前关闭游戏加速器（或确认已停止加速并开启代理 TUN 模式），核对上方 Claude 出口 IP 无误后再启动。"
            };
        }

        var tz = TimeZoneInfo.Local;
        var isUtc8 = tz.BaseUtcOffset == TimeSpan.FromHours(8);

        if (exitIp != null && isUtc8 && !AsianUtc8Or9Countries.Contains(exitIp.CountryCode))
        {
            return new CheckItemResult
            {
                Id = "sys_env",
                Title = "6. 加速器冲突与环境检测",
                ShortTitle = "加速/环境",
                Category = "冲突与环境",
                RiskLevel = RiskLevel.Warning,
                StatusText = $"时区偏差：系统 UTC+8 vs 出口 {exitIp.CountryCode}",
                ShortStatus = "UTC+8 偏差",
                Detail = $"未检测到常见游戏加速器。本机系统时区为 {tz.DisplayName}，与当前代理出口国家（{exitIp.CountryCode}）时区不一致。",
                Recommendation = "桌面端一般仅作辅助风险提示；若使用网页端或新注册账号，建议同步系统时区或选择亚洲节点。"
            };
        }

        return new CheckItemResult
        {
            Id = "sys_env",
            Title = "6. 加速器冲突与环境检测",
            ShortTitle = "加速/环境",
            Category = "冲突与环境",
            RiskLevel = RiskLevel.Safe,
            StatusText = $"无加速器冲突 · 环境正常 ({tz.Id})",
            ShortStatus = "无冲突",
            Detail = $"未检测到常见游戏加速器运行。本机当前时区：{tz.DisplayName}。",
            Recommendation = "系统基础环境与路由环境检查通过。"
        };
    }

    private static HttpClient CreateProxiedHttpClient(string proxyHost, int proxyPort, TimeSpan timeout)
    {
        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy($"http://{proxyHost}:{proxyPort}"),
            UseProxy = true,
            UseCookies = false,
            AllowAutoRedirect = true
        };

        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = timeout
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(BrowserUserAgent);
        return client;
    }

    private static async Task<IpGeoInfo?> FetchExitIpInfoAsync(
        HttpClient client,
        string? targetIp,
        IpGeoInfo? fallbackTrace,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(targetIp))
        {
            var geoInfo = await QueryGeoProvidersAsync(client, targetIp, cancellationToken).ConfigureAwait(false);
            if (geoInfo != null)
            {
                geoInfo.Ip = targetIp;
                if (string.IsNullOrWhiteSpace(geoInfo.CountryCode) &&
                    fallbackTrace != null &&
                    !string.IsNullOrWhiteSpace(fallbackTrace.CountryCode))
                {
                    geoInfo.CountryCode = fallbackTrace.CountryCode;
                    if (string.IsNullOrWhiteSpace(geoInfo.Country))
                        geoInfo.Country = fallbackTrace.CountryCode;
                }

                geoInfo.Source = $"claude.ai + {geoInfo.Source}";
                if (fallbackTrace != null)
                {
                    geoInfo.LatencyMs = fallbackTrace.LatencyMs;
                }

                return geoInfo;
            }

            return fallbackTrace;
        }

        var fallbackGeo = await QueryGeoProvidersAsync(client, null, cancellationToken).ConfigureAwait(false);
        if (fallbackGeo != null)
            return fallbackGeo;

        return await TryCloudflareTraceAsync(client, "https://www.cloudflare.com/cdn-cgi/trace", "Cloudflare Trace", cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<IpGeoInfo?> QueryGeoProvidersAsync(
        HttpClient client,
        string? targetIp,
        CancellationToken cancellationToken)
    {
        // 源 1: ip-api.com (提供最完整的 hosting / proxy / asn 标志)
        var info = await TryIpApiAsync(client, targetIp, cancellationToken).ConfigureAwait(false);
        if (info != null) return info;

        // 源 2: ipwho.is
        info = await TryIpWhoIsAsync(client, targetIp, cancellationToken).ConfigureAwait(false);
        if (info != null) return info;

        // 源 3: api.ip.sb
        return await TryIpSbAsync(client, targetIp, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IpGeoInfo?> TryIpApiAsync(HttpClient client, string? targetIp, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var path = string.IsNullOrWhiteSpace(targetIp) ? string.Empty : Uri.EscapeDataString(targetIp);
            var url = $"http://ip-api.com/json/{path}?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query";
            using var resp = await client.GetAsync(url, cancellationToken).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;

            var json = await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            sw.Stop();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!root.TryGetProperty("status", out var statusEl) || statusEl.GetString() != "success")
                return null;

            return new IpGeoInfo
            {
                Ip = GetJsonString(root, "query"),
                Country = GetJsonString(root, "country"),
                CountryCode = GetJsonString(root, "countryCode"),
                Region = GetJsonString(root, "regionName"),
                City = GetJsonString(root, "city"),
                Isp = GetJsonString(root, "isp"),
                Org = GetJsonString(root, "org"),
                Asn = GetJsonString(root, "as"),
                IsHosting = GetJsonBool(root, "hosting"),
                IsProxy = GetJsonBool(root, "proxy"),
                Source = "ip-api.com",
                LatencyMs = Math.Max(1, sw.ElapsedMilliseconds)
            };
        }
        catch
        {
            return null;
        }
    }

    private static async Task<IpGeoInfo?> TryIpWhoIsAsync(HttpClient client, string? targetIp, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var path = string.IsNullOrWhiteSpace(targetIp) ? string.Empty : Uri.EscapeDataString(targetIp);
            var url = $"https://ipwho.is/{path}";
            using var resp = await client.GetAsync(url, cancellationToken).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;

            var json = await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            sw.Stop();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("success", out var succEl) && succEl.ValueKind == JsonValueKind.False)
                return null;

            string isp = string.Empty, org = string.Empty, asn = string.Empty;
            if (root.TryGetProperty("connection", out var conn) && conn.ValueKind == JsonValueKind.Object)
            {
                isp = GetJsonString(conn, "isp");
                org = GetJsonString(conn, "org");
                if (conn.TryGetProperty("asn", out var asnEl))
                    asn = $"AS{asnEl}";
            }

            return new IpGeoInfo
            {
                Ip = GetJsonString(root, "ip"),
                Country = GetJsonString(root, "country"),
                CountryCode = GetJsonString(root, "country_code"),
                Region = GetJsonString(root, "region"),
                City = GetJsonString(root, "city"),
                Isp = isp,
                Org = org,
                Asn = asn,
                IsHosting = false,
                IsProxy = false,
                Source = "ipwho.is",
                LatencyMs = Math.Max(1, sw.ElapsedMilliseconds)
            };
        }
        catch
        {
            return null;
        }
    }

    private static async Task<IpGeoInfo?> TryIpSbAsync(HttpClient client, string? targetIp, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var url = string.IsNullOrWhiteSpace(targetIp)
                ? "https://api.ip.sb/geoip"
                : $"https://api.ip.sb/geoip/{Uri.EscapeDataString(targetIp)}";
            using var resp = await client.GetAsync(url, cancellationToken).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;

            var json = await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            sw.Stop();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var ip = GetJsonString(root, "ip");
            if (string.IsNullOrWhiteSpace(ip)) return null;

            var asnNum = root.TryGetProperty("asn", out var asnEl) ? $"AS{asnEl}" : string.Empty;

            return new IpGeoInfo
            {
                Ip = ip,
                Country = GetJsonString(root, "country"),
                CountryCode = GetJsonString(root, "country_code"),
                Region = GetJsonString(root, "region"),
                City = GetJsonString(root, "city"),
                Isp = GetJsonString(root, "isp"),
                Org = GetJsonString(root, "organization"),
                Asn = asnNum,
                Source = "api.ip.sb",
                LatencyMs = Math.Max(1, sw.ElapsedMilliseconds)
            };
        }
        catch
        {
            return null;
        }
    }

    private static async Task<IpGeoInfo?> FetchClaudeTraceInfoAsync(HttpClient client, CancellationToken cancellationToken)
    {
        var trace = await TryCloudflareTraceAsync(client, "https://claude.ai/cdn-cgi/trace", "claude.ai trace", cancellationToken)
            .ConfigureAwait(false);
        if (trace != null && !string.IsNullOrWhiteSpace(trace.Ip))
            return trace;

        return await TryCloudflareTraceAsync(client, "https://www.claude.com/cdn-cgi/trace", "claude.com trace", cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<IpGeoInfo?> TryCloudflareTraceAsync(
        HttpClient client,
        string url,
        string sourceName,
        CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var resp = await client.GetAsync(url, cancellationToken).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;

            var body = await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            sw.Stop();

            string ip = string.Empty, loc = string.Empty;
            foreach (var line in body.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var idx = line.IndexOf('=');
                if (idx <= 0) continue;
                var k = line[..idx].Trim();
                var v = line[(idx + 1)..].Trim();
                if (k == "ip") ip = v;
                else if (k == "loc") loc = v;
            }

            if (string.IsNullOrWhiteSpace(ip)) return null;

            return new IpGeoInfo
            {
                Ip = ip,
                CountryCode = loc,
                Country = loc,
                Source = sourceName,
                LatencyMs = Math.Max(1, sw.ElapsedMilliseconds)
            };
        }
        catch
        {
            return null;
        }
    }

    private static async Task<(bool Reachable, string? TraceCountry, IpGeoInfo? TraceInfo)> ProbeAnthropicTraceAndConnectivityAsync(
        HttpClient client,
        CancellationToken cancellationToken)
    {
        var trace = await FetchClaudeTraceInfoAsync(client, cancellationToken).ConfigureAwait(false);
        if (trace != null && !string.IsNullOrWhiteSpace(trace.Ip))
        {
            var country = string.IsNullOrWhiteSpace(trace.CountryCode) ? null : trace.CountryCode;
            return (true, country, trace);
        }

        // 兜底直接探测 api.anthropic.com HEAD 响应（即使返回 403/401 也代表 TLS 链路已打通）
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Head, "https://api.anthropic.com");
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
            return (true, null, null);
        }
        catch
        {
            return (false, null, null);
        }
    }

    private static string GetJsonString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString() ?? string.Empty
            : string.Empty;
    }

    private static bool GetJsonBool(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.True;
    }
}
