using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using ClaudeSafe.Localization;
using ClaudeSafe.Models;
using Microsoft.Win32;

namespace ClaudeSafe.Services;

/// <summary>
/// 本地代理配置读取、TUN 网卡探测、加速器冲突检测与端口连通性探测服务
/// </summary>
public sealed class ProxyDetectorService
{
    private static readonly int[] CommonProxyPorts = { 7890, 7897, 10808, 10809, 1080, 2080, 7891 };

    private static readonly string[] ExcludedAdapterKeywords =
    {
        "vmware", "virtualbox", "hyper-v", "vethernet", "wsl", "docker",
        "teredo", "isatap", "bluetooth", "tailscale", "zerotier", "radmin",
        "hamachi", "leigod", "qiyou", "qeeyou", "xunyou", "uu_tap"
    };

    private static readonly string[] TunAdapterKeywords =
    {
        "mihomo", "clash", "flclash", "sing-box", "singbox", "wintun",
        "v2ray", "xray", "nekobox", "nekoray", "hiddify", "karing", "meta", "tun"
    };

    private static readonly Dictionary<string, string> AcceleratorProcessMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["uu"] = "网易UU加速器",
        ["uu_ball"] = "网易UU加速器",
        ["uuservice"] = "网易UU加速器",
        ["uu_service"] = "网易UU加速器",
        ["leigod"] = "雷神加速器",
        ["leigod_launcher"] = "雷神加速器",
        ["leigodservice"] = "雷神加速器",
        ["qiyou"] = "奇游加速器",
        ["qeeyou"] = "奇游加速器",
        ["qiyouservice"] = "奇游加速器",
        ["xunyou"] = "迅游加速器",
        ["xunyou_starter"] = "迅游加速器",
        ["xyservice"] = "迅游加速器",
        ["akaccelerator"] = "AK加速器",
        ["ak_accelerator"] = "AK加速器",
        ["bohe"] = "薄荷加速器",
        ["bohe_launcher"] = "薄荷加速器",
        ["qimiao"] = "奇妙加速器",
        ["qimiaoservice"] = "奇妙加速器",
        ["biubiu"] = "Biubiu加速器",
        ["biubiu_service"] = "Biubiu加速器",
        ["ht_accelerator"] = "海豚加速器",
        ["haitun"] = "海豚加速器",
        ["dolphin_accelerator"] = "海豚加速器",
        ["guguai"] = "古怪加速器",
        ["guguai_service"] = "古怪加速器",
        ["xianniu"] = "鲜牛加速器",
        ["baomiao"] = "暴喵加速器",
        ["nn_accelerator"] = "NN加速器",
        ["nnservice"] = "NN加速器",
        ["golink"] = "GoLink加速器",
        ["lonlife"] = "玲珑加速器"
    };

    private static readonly (string Keyword, string DisplayName)[] AcceleratorAdapterKeywords =
    {
        ("leigod", "雷神加速器"),
        ("qiyou", "奇游加速器"),
        ("qeeyou", "奇游加速器"),
        ("xunyou", "迅游加速器")
    };

    public (bool Enabled, string RawServer, string? Host, int? Port) ReadWindowsSystemProxy(int? excludeGatekeeperPort = null)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (key == null)
                return (false, string.Empty, null, null);

            var enableObj = key.GetValue("ProxyEnable");
            var proxyEnableFlag = enableObj is int i && i == 1;
            var rawServer = key.GetValue("ProxyServer")?.ToString() ?? string.Empty;

            var (host, port) = ParseProxyEndpoint(rawServer);
            if (excludeGatekeeperPort.HasValue &&
                port == excludeGatekeeperPort.Value &&
                (string.Equals(host, "127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)))
            {
                return (false, rawServer, null, null);
            }

            bool enabled = proxyEnableFlag && !string.IsNullOrWhiteSpace(host) && port.HasValue;
            return (enabled, rawServer, host, port);
        }
        catch
        {
            return (false, string.Empty, null, null);
        }
    }

    public (bool Enabled, string AdapterName) DetectActiveTunAdapter()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up ||
                    ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                var combinedText = $"{ni.Name} {ni.Description}";
                if (ExcludedAdapterKeywords.Any(k => combinedText.Contains(k, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                var ipv4Addresses = GetValidIpv4UnicastAddresses(ni);
                if (ipv4Addresses.Count == 0)
                {
                    continue;
                }

                bool matchesKeyword = TunAdapterKeywords.Any(k => combinedText.Contains(k, StringComparison.OrdinalIgnoreCase));
                bool matchesFakeIpRange = ipv4Addresses.Any(IsFakeIpRange);

                if (matchesKeyword || matchesFakeIpRange)
                {
                    var adapterName = !string.IsNullOrWhiteSpace(ni.Name) ? ni.Name : ni.Description;
                    return (true, adapterName);
                }
            }
        }
        catch
        {
            // Ignore network interface enumeration failures
        }

        return (false, string.Empty);
    }

    public List<string> DetectRunningGameAccelerators()
    {
        var detected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (AcceleratorProcessMap.TryGetValue(proc.ProcessName, out var displayName))
                {
                    detected.Add(displayName);
                }
            }
            catch
            {
                // Ignore inaccessible processes
            }
            finally
            {
                try { proc.Dispose(); } catch { }
            }
        }

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }

                var combinedText = $"{ni.Name} {ni.Description}";
                foreach (var (keyword, displayName) in AcceleratorAdapterKeywords)
                {
                    if (combinedText.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        detected.Add(displayName);
                    }
                }
            }
        }
        catch
        {
            // Ignore network interface enumeration failures
        }

        return detected.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static List<IPAddress> GetValidIpv4UnicastAddresses(NetworkInterface ni)
    {
        var result = new List<IPAddress>();
        try
        {
            var ipProps = ni.GetIPProperties();
            foreach (var addr in ipProps.UnicastAddresses)
            {
                if (addr.Address.AddressFamily != AddressFamily.InterNetwork)
                {
                    continue;
                }

                var bytes = addr.Address.GetAddressBytes();
                // 排除 APIPA 169.254.0.0/16 与回环 127.0.0.0/8
                if ((bytes[0] == 169 && bytes[1] == 254) || bytes[0] == 127)
                {
                    continue;
                }

                result.Add(addr.Address);
            }
        }
        catch
        {
            // Ignore adapter IP property failures
        }
        return result;
    }

    private static bool IsFakeIpRange(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork)
            return false;

        var bytes = ip.GetAddressBytes();
        return bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19);
    }

    public static (string? Host, int? Port) ParseProxyEndpoint(string rawServer)
    {
        if (string.IsNullOrWhiteSpace(rawServer))
            return (null, null);

        // 可能格式: "127.0.0.1:7890" 或 "http=127.0.0.1:7890;https=127.0.0.1:7890"
        var candidate = rawServer.Trim();
        if (candidate.Contains(';'))
        {
            var segments = candidate.Split(';', StringSplitOptions.RemoveEmptyEntries);
            foreach (var seg in segments)
            {
                var trimmed = seg.Trim();
                if (trimmed.StartsWith("https=", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.StartsWith("http=", StringComparison.OrdinalIgnoreCase))
                {
                    var eqIdx = trimmed.IndexOf('=');
                    candidate = trimmed[(eqIdx + 1)..].Trim();
                    break;
                }
            }
        }
        else if (candidate.Contains('='))
        {
            var eqIdx = candidate.IndexOf('=');
            candidate = candidate[(eqIdx + 1)..].Trim();
        }

        candidate = candidate.Replace("http://", "", StringComparison.OrdinalIgnoreCase)
                             .Replace("https://", "", StringComparison.OrdinalIgnoreCase)
                             .TrimEnd('/');

        var lastColon = candidate.LastIndexOf(':');
        if (lastColon > 0 && int.TryParse(candidate[(lastColon + 1)..], out var port) && port is > 0 and <= 65535)
        {
            var host = candidate[..lastColon].Trim();
            if (!string.IsNullOrWhiteSpace(host))
                return (host, port);
        }

        return (null, null);
    }

    public async Task<(bool Reachable, long LatencyMs)> ProbeTcpPortAsync(
        string host,
        int port,
        int timeoutMs = 800,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(host) || port is <= 0 or > 65535)
            return (false, 0);

        var sw = Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient();
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(timeoutMs);
            await client.ConnectAsync(host, port, timeoutCts.Token).ConfigureAwait(false);
            sw.Stop();
            return (true, Math.Max(1, sw.ElapsedMilliseconds));
        }
        catch
        {
            return (false, 0);
        }
    }

    public async Task<ProxyProbeResult> DetectBestUpstreamProxyAsync(
        string configuredHost,
        int configuredPort,
        int excludeGatekeeperPort = 17890,
        CancellationToken cancellationToken = default)
    {
        var (sysEnabled, sysRaw, sysHost, sysPort) = ReadWindowsSystemProxy(excludeGatekeeperPort);
        var (tunEnabled, tunAdapter) = DetectActiveTunAdapter();
        var accelerators = DetectRunningGameAccelerators();

        ProxyProbeResult BuildProbeResult(string host, int port, bool isReachable, long latencyMs, string sourceDescription) =>
            new()
            {
                Host = host,
                Port = port,
                IsReachable = isReachable,
                LatencyMs = latencyMs,
                SourceDescription = sourceDescription,
                SystemProxyEnabled = sysEnabled,
                SystemProxyRaw = sysRaw,
                TunModeEnabled = tunEnabled,
                TunAdapterName = tunAdapter,
                RunningAccelerators = accelerators
            };

        bool configuredIsGatekeeper =
            configuredPort == excludeGatekeeperPort &&
            (string.Equals(configuredHost, "127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(configuredHost, "localhost", StringComparison.OrdinalIgnoreCase));

        // 1. 优先检测用户当前配置的代理地址与端口（排除自身守门端口避免死循环）
        if (!configuredIsGatekeeper)
        {
            var (cfgReachable, cfgLatency) = await ProbeTcpPortAsync(configuredHost, configuredPort, 400, cancellationToken)
                .ConfigureAwait(false);
            if (cfgReachable)
            {
                return BuildProbeResult(
                    configuredHost,
                    configuredPort,
                    true,
                    cfgLatency,
                    L.Format("Proxy_ConfigPort", configuredHost, configuredPort));
            }
        }

        // 2. 其次检测 Windows 系统代理（已排除自身守门端口）
        if (!string.IsNullOrWhiteSpace(sysHost) && sysPort.HasValue &&
            !(string.Equals(sysHost, configuredHost, StringComparison.OrdinalIgnoreCase) && sysPort.Value == configuredPort))
        {
            var (sysReachable, sysLatency) = await ProbeTcpPortAsync(sysHost, sysPort.Value, 400, cancellationToken)
                .ConfigureAwait(false);
            if (sysReachable)
            {
                return BuildProbeResult(
                    sysHost,
                    sysPort.Value,
                    true,
                    sysLatency,
                    L.Format("Proxy_SysProxyAuto", sysHost, sysPort.Value));
            }
        }

        // 3. 并发扫描本地常见代理软件端口 (FlClash / Clash / v2rayN / Mihomo)，避免梯子关闭时串行等待卡顿
        var scannedPorts = new HashSet<int> { configuredPort, excludeGatekeeperPort };
        if (sysPort.HasValue) scannedPorts.Add(sysPort.Value);

        var candidatePorts = new List<int>();
        foreach (var port in CommonProxyPorts)
        {
            if (scannedPorts.Add(port))
                candidatePorts.Add(port);
        }

        if (candidatePorts.Count > 0)
        {
            var probeTasks = candidatePorts.Select(async port =>
            {
                var (ok, latency) = await ProbeTcpPortAsync("127.0.0.1", port, 350, cancellationToken)
                    .ConfigureAwait(false);
                return (Port: port, Ok: ok, Latency: latency);
            }).ToArray();

            var results = await Task.WhenAll(probeTasks).ConfigureAwait(false);
            var hit = results.FirstOrDefault(r => r.Ok);
            if (hit.Ok)
            {
                return BuildProbeResult(
                    "127.0.0.1",
                    hit.Port,
                    true,
                    hit.Latency,
                    L.Format("Proxy_CommonPortAuto", hit.Port));
            }
        }

        return BuildProbeResult(
            configuredHost,
            configuredPort,
            false,
            0,
            L.Get("Proxy_NoneFound"));
    }
}
