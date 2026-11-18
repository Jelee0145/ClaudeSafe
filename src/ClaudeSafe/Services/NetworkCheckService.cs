using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ClaudeSafe.Localization;
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
            summary = L.Format("Chk_SummaryDanger", firstDanger.Title, firstDanger.StatusText);
        }
        else if (hasWarnings)
        {
            var warnCount = items.Count(x => x.RiskLevel == RiskLevel.Warning);
            summary = L.Format("Chk_SummaryWarning", warnCount);
        }
        else
        {
            summary = L.Get("Chk_SummarySafe");
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
                Title = L.Get("Chk1_Title"),
                ShortTitle = L.Get("Chk1_ShortTitle"),
                Category = L.Get("Chk1_Category"),
                RiskLevel = RiskLevel.Danger,
                StatusText = L.Format("Chk1_Unreachable_Status", proxyProbe.Host, proxyProbe.Port),
                ShortStatus = L.Get("Chk1_Unreachable_Short"),
                Detail = L.Get("Chk1_Unreachable_Detail"),
                Recommendation = L.Get("Chk1_Unreachable_Rec")
            };
        }

        if (!proxyProbe.TunModeEnabled && !proxyProbe.SystemProxyEnabled)
        {
            return new CheckItemResult
            {
                Id = "proxy_channel",
                Title = L.Get("Chk1_Title"),
                ShortTitle = L.Get("Chk1_ShortTitle"),
                Category = L.Get("Chk1_Category"),
                RiskLevel = RiskLevel.Danger,
                StatusText = L.Get("Chk1_NoTunNoSys_Status"),
                ShortStatus = L.Get("Chk1_NoTunNoSys_Short"),
                Detail = L.Format("Chk1_NoTunNoSys_Detail", proxyProbe.Host, proxyProbe.Port),
                Recommendation = L.Get("Chk1_NoTunNoSys_Rec")
            };
        }

        if (!proxyProbe.TunModeEnabled && proxyProbe.SystemProxyEnabled)
        {
            return new CheckItemResult
            {
                Id = "proxy_channel",
                Title = L.Get("Chk1_Title"),
                ShortTitle = L.Get("Chk1_ShortTitle"),
                Category = L.Get("Chk1_Category"),
                RiskLevel = RiskLevel.Warning,
                StatusText = L.Format("Chk1_SysOnly_Status", proxyProbe.LatencyMs),
                ShortStatus = L.Get("Chk1_SysOnly_Short"),
                Detail = L.Format("Chk1_SysOnly_Detail", proxyProbe.SourceDescription),
                Recommendation = L.Get("Chk1_SysOnly_Rec")
            };
        }

        var sysProxyLabel = proxyProbe.SystemProxyEnabled ? L.Get("Chk1_Enabled") : L.Get("Chk1_DisabledTun");

        if (proxyProbe.LatencyMs > 500)
        {
            return new CheckItemResult
            {
                Id = "proxy_channel",
                Title = L.Get("Chk1_Title"),
                ShortTitle = L.Get("Chk1_ShortTitle"),
                Category = L.Get("Chk1_Category"),
                RiskLevel = RiskLevel.Warning,
                StatusText = L.Format("Chk1_Slow_Status", proxyProbe.LatencyMs),
                ShortStatus = L.Get("Chk1_Slow_Short"),
                Detail = L.Format("Chk1_Slow_Detail", proxyProbe.SourceDescription, proxyProbe.TunAdapterName, sysProxyLabel),
                Recommendation = L.Get("Chk1_Slow_Rec")
            };
        }

        return new CheckItemResult
        {
            Id = "proxy_channel",
            Title = L.Get("Chk1_Title"),
            ShortTitle = L.Get("Chk1_ShortTitle"),
            Category = L.Get("Chk1_Category"),
            RiskLevel = RiskLevel.Safe,
            StatusText = L.Format("Chk1_Safe_Status", proxyProbe.TunAdapterName, proxyProbe.LatencyMs),
            ShortStatus = L.Format("Chk1_Safe_Short", proxyProbe.LatencyMs),
            Detail = L.Format("Chk1_Safe_Detail", proxyProbe.SourceDescription, proxyProbe.TunAdapterName, sysProxyLabel),
            Recommendation = L.Get("Chk1_Safe_Rec")
        };
    }

    private static CheckItemResult EvaluateExitIpCompliance(ProxyProbeResult proxyProbe, IpGeoInfo? exitIp)
    {
        if (!proxyProbe.IsReachable)
        {
            return new CheckItemResult
            {
                Id = "exit_region",
                Title = L.Get("Chk2_Title"),
                ShortTitle = L.Get("Chk2_ShortTitle"),
                Category = L.Get("Chk2_Category"),
                RiskLevel = RiskLevel.Danger,
                StatusText = L.Get("Chk2_Skip_Status"),
                ShortStatus = L.Get("Chk2_Skip_Short"),
                Detail = L.Get("Chk2_Skip_Detail"),
                Recommendation = L.Get("Chk2_Skip_Rec")
            };
        }

        if (exitIp == null || string.IsNullOrWhiteSpace(exitIp.Ip) || string.IsNullOrWhiteSpace(exitIp.CountryCode))
        {
            return new CheckItemResult
            {
                Id = "exit_region",
                Title = L.Get("Chk2_Title"),
                ShortTitle = L.Get("Chk2_ShortTitle"),
                Category = L.Get("Chk2_Category"),
                RiskLevel = RiskLevel.Danger,
                StatusText = L.Get("Chk2_Fail_Status"),
                ShortStatus = L.Get("Chk2_Fail_Short"),
                Detail = L.Get("Chk2_Fail_Detail"),
                Recommendation = L.Get("Chk2_Fail_Rec")
            };
        }

        if (BlockedCountryCodes.Contains(exitIp.CountryCode))
        {
            return new CheckItemResult
            {
                Id = "exit_region",
                Title = L.Get("Chk2_Title"),
                ShortTitle = L.Get("Chk2_ShortTitle"),
                Category = L.Get("Chk2_Category"),
                RiskLevel = RiskLevel.Danger,
                StatusText = L.Format("Chk2_Blocked_Status", exitIp.CountryCode, exitIp.Ip),
                ShortStatus = L.Format("Chk2_Blocked_Short", exitIp.CountryCode),
                Detail = L.Format("Chk2_Blocked_Detail", exitIp.DisplayLocation),
                Recommendation = L.Get("Chk2_Blocked_Rec")
            };
        }

        return new CheckItemResult
        {
            Id = "exit_region",
            Title = L.Get("Chk2_Title"),
            ShortTitle = L.Get("Chk2_ShortTitle"),
            Category = L.Get("Chk2_Category"),
            RiskLevel = RiskLevel.Safe,
            StatusText = L.Format("Chk2_Safe_Status", exitIp.CountryCode, exitIp.Ip),
            ShortStatus = L.Format("Chk2_Safe_Short", exitIp.CountryCode),
            Detail = L.Format("Chk2_Safe_Detail", exitIp.DisplayLocation, exitIp.Source, exitIp.LatencyMs),
            Recommendation = L.Get("Chk2_Safe_Rec")
        };
    }

    private static CheckItemResult EvaluateIpPurity(ProxyProbeResult proxyProbe, IpGeoInfo? exitIp)
    {
        if (!proxyProbe.IsReachable || exitIp == null)
        {
            return new CheckItemResult
            {
                Id = "ip_purity",
                Title = L.Get("Chk3_Title"),
                ShortTitle = L.Get("Chk3_ShortTitle"),
                Category = L.Get("Chk3_Category"),
                RiskLevel = RiskLevel.Warning,
                StatusText = L.Get("Chk3_NoAsn_Status"),
                ShortStatus = L.Get("Chk3_NoAsn_Short"),
                Detail = L.Get("Chk3_NoAsn_Detail"),
                Recommendation = L.Get("Chk3_NoAsn_Rec")
            };
        }

        var combinedMeta = $"{exitIp.Isp} {exitIp.Org} {exitIp.Asn}";
        var matchedKeyword = DatacenterKeywords.FirstOrDefault(k =>
            combinedMeta.Contains(k, StringComparison.OrdinalIgnoreCase));

        if (exitIp.IsHosting || exitIp.IsProxy || matchedKeyword != null)
        {
            var reason = matchedKeyword != null
                ? L.Format("Chk3_ReasonKeyword", matchedKeyword)
                : exitIp.IsHosting ? L.Get("Chk3_ReasonHosting") : L.Get("Chk3_ReasonProxy");

            return new CheckItemResult
            {
                Id = "ip_purity",
                Title = L.Get("Chk3_Title"),
                ShortTitle = L.Get("Chk3_ShortTitle"),
                Category = L.Get("Chk3_Category"),
                RiskLevel = RiskLevel.Warning,
                StatusText = L.Get("Chk3_Dc_Status"),
                ShortStatus = L.Get("Chk3_Dc_Short"),
                Detail = L.Format("Chk3_Dc_Detail", reason, exitIp.Isp, exitIp.Asn),
                Recommendation = L.Get("Chk3_Dc_Rec")
            };
        }

        return new CheckItemResult
        {
            Id = "ip_purity",
            Title = L.Get("Chk3_Title"),
            ShortTitle = L.Get("Chk3_ShortTitle"),
            Category = L.Get("Chk3_Category"),
            RiskLevel = RiskLevel.Safe,
            StatusText = L.Get("Chk3_Safe_Status"),
            ShortStatus = L.Get("Chk3_Safe_Short"),
            Detail = L.Format("Chk3_Safe_Detail", exitIp.Isp, exitIp.Org, exitIp.Asn),
            Recommendation = L.Get("Chk3_Safe_Rec")
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
                Title = L.Get("Chk4_Title"),
                ShortTitle = L.Get("Chk4_ShortTitle"),
                Category = L.Get("Chk4_Category"),
                RiskLevel = RiskLevel.Warning,
                StatusText = L.Get("Chk4_NoData_Status"),
                ShortStatus = L.Get("Chk4_NoData_Short"),
                Detail = L.Get("Chk4_NoData_Detail"),
                Recommendation = L.Get("Chk4_NoData_Rec")
            };
        }

        if (lastSafe == null || string.IsNullOrWhiteSpace(lastSafe.Ip))
        {
            return new CheckItemResult
            {
                Id = "ip_drift",
                Title = L.Get("Chk4_Title"),
                ShortTitle = L.Get("Chk4_ShortTitle"),
                Category = L.Get("Chk4_Category"),
                RiskLevel = RiskLevel.Safe,
                StatusText = L.Get("Chk4_First_Status"),
                ShortStatus = L.Get("Chk4_First_Short"),
                Detail = L.Format("Chk4_First_Detail", exitIp.Ip, exitIp.CountryCode),
                Recommendation = L.Get("Chk4_First_Rec")
            };
        }

        if (string.Equals(lastSafe.Ip, exitIp.Ip, StringComparison.OrdinalIgnoreCase))
        {
            return new CheckItemResult
            {
                Id = "ip_drift",
                Title = L.Get("Chk4_Title"),
                ShortTitle = L.Get("Chk4_ShortTitle"),
                Category = L.Get("Chk4_Category"),
                RiskLevel = RiskLevel.Safe,
                StatusText = L.Get("Chk4_Exact_Status"),
                ShortStatus = L.Get("Chk4_Exact_Short"),
                Detail = L.Format("Chk4_Exact_Detail", exitIp.Ip, exitIp.CountryCode, lastSafe.RecordedAt),
                Recommendation = L.Get("Chk4_Exact_Rec")
            };
        }

        if (!string.Equals(lastSafe.CountryCode, exitIp.CountryCode, StringComparison.OrdinalIgnoreCase))
        {
            return new CheckItemResult
            {
                Id = "ip_drift",
                Title = L.Get("Chk4_Title"),
                ShortTitle = L.Get("Chk4_ShortTitle"),
                Category = L.Get("Chk4_Category"),
                RiskLevel = RiskLevel.Warning,
                IsCrossCountryDrift = true,
                StatusText = L.Format("Chk4_Cross_Status", lastSafe.CountryCode, exitIp.CountryCode),
                ShortStatus = L.Format("Chk4_Cross_Short", lastSafe.CountryCode, exitIp.CountryCode),
                Detail = L.Format("Chk4_Cross_Detail", lastSafe.Ip, lastSafe.Country, lastSafe.RecordedAt, exitIp.Ip, exitIp.Country),
                Recommendation = L.Get("Chk4_Cross_Rec")
            };
        }

        return new CheckItemResult
        {
            Id = "ip_drift",
            Title = L.Get("Chk4_Title"),
            ShortTitle = L.Get("Chk4_ShortTitle"),
            Category = L.Get("Chk4_Category"),
            RiskLevel = RiskLevel.Warning,
            StatusText = L.Format("Chk4_SameCountry_Status", exitIp.CountryCode),
            ShortStatus = L.Get("Chk4_SameCountry_Short"),
            Detail = L.Format("Chk4_SameCountry_Detail", lastSafe.Ip, lastSafe.Asn, exitIp.Ip, exitIp.Asn),
            Recommendation = L.Get("Chk4_SameCountry_Rec")
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
                Title = L.Get("Chk5_Title"),
                ShortTitle = L.Get("Chk5_ShortTitle"),
                Category = L.Get("Chk5_Category"),
                RiskLevel = RiskLevel.Danger,
                StatusText = L.Get("Chk5_NoProxy_Status"),
                ShortStatus = L.Get("Chk5_NoProxy_Short"),
                Detail = L.Get("Chk5_NoProxy_Detail"),
                Recommendation = L.Get("Chk5_NoProxy_Rec")
            };
        }

        if (!anthropicReachable)
        {
            return new CheckItemResult
            {
                Id = "anthropic_conn",
                Title = L.Get("Chk5_Title"),
                ShortTitle = L.Get("Chk5_ShortTitle"),
                Category = L.Get("Chk5_Category"),
                RiskLevel = RiskLevel.Danger,
                StatusText = L.Get("Chk5_Unreachable_Status"),
                ShortStatus = L.Get("Chk5_Unreachable_Short"),
                Detail = L.Get("Chk5_Unreachable_Detail"),
                Recommendation = L.Get("Chk5_Unreachable_Rec")
            };
        }

        if (!string.IsNullOrWhiteSpace(anthropicTraceCountry) && BlockedCountryCodes.Contains(anthropicTraceCountry))
        {
            return new CheckItemResult
            {
                Id = "anthropic_conn",
                Title = L.Get("Chk5_Title"),
                ShortTitle = L.Get("Chk5_ShortTitle"),
                Category = L.Get("Chk5_Category"),
                RiskLevel = RiskLevel.Danger,
                StatusText = L.Format("Chk5_Leak_Status", anthropicTraceCountry),
                ShortStatus = L.Format("Chk5_Leak_Short", anthropicTraceCountry),
                Detail = L.Format("Chk5_Leak_Detail", anthropicTraceCountry),
                Recommendation = L.Get("Chk5_Leak_Rec")
            };
        }

        if (exitIp != null &&
            !string.IsNullOrWhiteSpace(anthropicTraceCountry) &&
            !string.Equals(exitIp.CountryCode, anthropicTraceCountry, StringComparison.OrdinalIgnoreCase))
        {
            return new CheckItemResult
            {
                Id = "anthropic_conn",
                Title = L.Get("Chk5_Title"),
                ShortTitle = L.Get("Chk5_ShortTitle"),
                Category = L.Get("Chk5_Category"),
                RiskLevel = RiskLevel.Warning,
                StatusText = L.Format("Chk5_Mismatch_Status", exitIp.CountryCode, anthropicTraceCountry),
                ShortStatus = L.Format("Chk5_Mismatch_Short", exitIp.CountryCode, anthropicTraceCountry),
                Detail = L.Format("Chk5_Mismatch_Detail", exitIp.CountryCode, anthropicTraceCountry),
                Recommendation = L.Get("Chk5_Mismatch_Rec")
            };
        }

        return new CheckItemResult
        {
            Id = "anthropic_conn",
            Title = L.Get("Chk5_Title"),
            ShortTitle = L.Get("Chk5_ShortTitle"),
            Category = L.Get("Chk5_Category"),
            RiskLevel = RiskLevel.Safe,
            StatusText = string.IsNullOrWhiteSpace(anthropicTraceCountry)
                ? L.Get("Chk5_SafeTls_Status")
                : L.Format("Chk5_SafeCountry_Status", anthropicTraceCountry),
            ShortStatus = string.IsNullOrWhiteSpace(anthropicTraceCountry)
                ? L.Get("Chk5_SafeTls_Short")
                : L.Format("Chk5_SafeCountry_Short", anthropicTraceCountry),
            Detail = L.Get("Chk5_Safe_Detail"),
            Recommendation = L.Get("Chk5_Safe_Rec")
        };
    }

    private static CheckItemResult EvaluateSystemEnvironment(ProxyProbeResult proxyProbe, IpGeoInfo? exitIp)
    {
        if (proxyProbe.RunningAccelerators is { Count: > 0 })
        {
            var names = string.Join(L.Get("Chk6_Separator"), proxyProbe.RunningAccelerators);
            return new CheckItemResult
            {
                Id = "sys_env",
                Title = L.Get("Chk6_Title"),
                ShortTitle = L.Get("Chk6_ShortTitle"),
                Category = L.Get("Chk6_Category"),
                RiskLevel = RiskLevel.Warning,
                StatusText = L.Format("Chk6_Booster_Status", names),
                ShortStatus = L.Get("Chk6_Booster_Short"),
                Detail = L.Format("Chk6_Booster_Detail", names),
                Recommendation = L.Get("Chk6_Booster_Rec")
            };
        }

        var tz = TimeZoneInfo.Local;
        var isUtc8 = tz.BaseUtcOffset == TimeSpan.FromHours(8);

        if (exitIp != null && isUtc8 && !AsianUtc8Or9Countries.Contains(exitIp.CountryCode))
        {
            return new CheckItemResult
            {
                Id = "sys_env",
                Title = L.Get("Chk6_Title"),
                ShortTitle = L.Get("Chk6_ShortTitle"),
                Category = L.Get("Chk6_Category"),
                RiskLevel = RiskLevel.Warning,
                StatusText = L.Format("Chk6_Tz_Status", exitIp.CountryCode),
                ShortStatus = L.Get("Chk6_Tz_Short"),
                Detail = L.Format("Chk6_Tz_Detail", tz.DisplayName, exitIp.CountryCode),
                Recommendation = L.Get("Chk6_Tz_Rec")
            };
        }

        return new CheckItemResult
        {
            Id = "sys_env",
            Title = L.Get("Chk6_Title"),
            ShortTitle = L.Get("Chk6_ShortTitle"),
            Category = L.Get("Chk6_Category"),
            RiskLevel = RiskLevel.Safe,
            StatusText = L.Format("Chk6_Safe_Status", tz.Id),
            ShortStatus = L.Get("Chk6_Safe_Short"),
            Detail = L.Format("Chk6_Safe_Detail", tz.DisplayName),
            Recommendation = L.Get("Chk6_Safe_Rec")
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
