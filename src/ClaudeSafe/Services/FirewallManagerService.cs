using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using ClaudeSafe.Localization;

namespace ClaudeSafe.Services;

public sealed record FirewallActionResult(bool Success, bool IsAdmin, string Message);

/// <summary>
/// Windows 防火墙出站规则（程序路径 + Anthropic 网段 IP）与 Hosts 域名黑洞封锁服务
/// </summary>
public sealed class FirewallManagerService
{
    public const string FirewallRuleName = "ClaudeSafe_Block_Outbound";
    public const string FirewallIpRuleName = "ClaudeSafe_Block_Anthropic_IPs";
    public const string FirewallForceProxyOnlyRuleName = "ClaudeSafe_Force_Proxy_Only";
    // 屏蔽全部公网 IPv4 与公网 IPv6 (2000::/3)，仅放行本地回环 (127.0.0.0/8, ::1) 与局域网私网 (10/8, 172.16/12, 192.168/16, 169.254/16, fe80::/10, fc00::/7)
    private const string NonLoopbackRemoteIps =
        "0.0.0.0-9.255.255.255," +
        "11.0.0.0-126.255.255.255," +
        "128.0.0.0-169.253.255.255," +
        "169.255.0.0-172.15.255.255," +
        "172.32.0.0-192.167.255.255," +
        "192.169.0.0-255.255.255.255," +
        "2000::/3";
    private const string HostsBeginMarker = "# BEGIN CLAUDESAFE BLOCK";
    private const string HostsEndMarker = "# END CLAUDESAFE BLOCK";

    private static readonly string[] BlockedDomains =
    {
        "claude.ai",
        "www.claude.ai",
        "claude.com",
        "www.claude.com",
        "api.anthropic.com",
        "a-api.anthropic.com",
        "auth.anthropic.com",
        "statsig.anthropic.com",
        "console.anthropic.com"
    };

    private static string HostsFilePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");

    public bool IsRunningAsAdmin()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public FirewallActionResult ApplyTrafficBlock(
        IEnumerable<string> claudeExePaths,
        bool enableFirewall,
        bool enableHosts)
    {
        bool isAdmin = IsRunningAsAdmin();
        if (!isAdmin)
        {
            return new FirewallActionResult(
                false,
                false,
                L.Get("Fw_StandardModeNote"));
        }

        var actions = new List<string>();
        var errors = new List<string>();

        if (enableFirewall)
        {
            try
            {
                // 先清理旧规则，避免重复堆积
                RunHiddenCommand("netsh", $"advfirewall firewall delete rule name=\"{FirewallRuleName}\"");
                RunHiddenCommand("netsh", $"advfirewall firewall delete rule name=\"{FirewallIpRuleName}\"");

                var validExes = claudeExePaths
                    .Where(p => !string.IsNullOrWhiteSpace(p) && File.Exists(p))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                int added = 0;
                foreach (var exe in validExes)
                {
                    var (code, output) = RunHiddenCommand(
                        "netsh",
                        $"advfirewall firewall add rule name=\"{FirewallRuleName}\" dir=out action=block program=\"{exe}\" enable=yes profile=any");
                    if (code == 0)
                    {
                        added++;
                    }
                    else
                    {
                        errors.Add(L.Format("Fw_RuleAddFail", Path.GetFileName(exe), output));
                    }
                }

                // 追加 Anthropic 专属公网 IP 段阻断规则（覆盖物理网卡与 TUN 虚拟网卡上的所有进程含浏览器）
                var remoteIps = CollectAnthropicRemoteIpTargets();
                var (ipCode, ipOut) = RunHiddenCommand(
                    "netsh",
                    $"advfirewall firewall add rule name=\"{FirewallIpRuleName}\" dir=out action=block remoteip=\"{string.Join(",", remoteIps)}\" enable=yes profile=any");

                if (ipCode == 0)
                {
                    actions.Add(L.Format("Fw_IpBlockAdded", remoteIps.Count));
                }
                else
                {
                    errors.Add(L.Format("Fw_IpRuleFail", ipOut));
                }

                // 常驻强制仅走代理规则：即使未来放行运行 Claude，也只允许回环 127.0.0.1，永久禁止任何直连公网
                int proxyOnlyAdded = ApplyForceProxyOnlyRuleInternal(validExes);
                if (proxyOnlyAdded > 0)
                {
                    actions.Add(L.Format("Fw_ProxyOnlyAdded", proxyOnlyAdded));
                }

                if (added > 0)
                {
                    actions.Add(L.Format("Fw_OutboundAdded", added));
                }
            }
            catch (Exception ex)
            {
                errors.Add(L.Format("Fw_Exception", ex.Message));
            }
        }

        if (enableHosts)
        {
            try
            {
                WriteHostsBlockSection();
                RunHiddenCommand("ipconfig", "/flushdns");
                actions.Add(L.Format("Fw_HostsAdded", BlockedDomains.Length));
            }
            catch (Exception ex)
            {
                errors.Add(L.Format("Fw_HostsException", ex.Message));
            }
        }

        if (errors.Count > 0 && actions.Count == 0)
        {
            return new FirewallActionResult(false, true, string.Join("；", errors));
        }

        var msg = string.Join("；", actions.Concat(errors));
        return new FirewallActionResult(errors.Count == 0, true, string.IsNullOrWhiteSpace(msg) ? L.Get("Fw_DefaultApplied") : msg);
    }

    public FirewallActionResult RemoveTrafficBlock(IEnumerable<string>? claudeExePaths = null, bool keepForceProxyOnly = true)
    {
        if (!IsRunningAsAdmin())
        {
            if (!keepForceProxyOnly && HasResidualSystemBlocks())
            {
                if (TryRunElevatedCleanAll())
                {
                    return new FirewallActionResult(true, false, L.Get("Fw_ElevatedCleaned"));
                }
            }

            return new FirewallActionResult(true, false, L.Get("Fw_StandardRelease"));
        }

        var notes = new List<string>();
        try
        {
            RunHiddenCommand("netsh", $"advfirewall firewall delete rule name=\"{FirewallRuleName}\"");
            RunHiddenCommand("netsh", $"advfirewall firewall delete rule name=\"{FirewallIpRuleName}\"");
            notes.Add(L.Get("Fw_UnblockedAll"));

            if (keepForceProxyOnly && claudeExePaths != null)
            {
                var validExes = claudeExePaths
                    .Where(p => !string.IsNullOrWhiteSpace(p) && File.Exists(p))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                int forced = ApplyForceProxyOnlyRuleInternal(validExes);
                if (forced > 0)
                {
                    notes.Add(L.Format("Fw_KeepProxyOnly", forced));
                }
            }
            else if (!keepForceProxyOnly)
            {
                RunHiddenCommand("netsh", $"advfirewall firewall delete rule name=\"{FirewallForceProxyOnlyRuleName}\"");
                notes.Add(L.Get("Fw_RemovedAll"));
            }
        }
        catch (Exception ex)
        {
            notes.Add(L.Format("Fw_UpdateException", ex.Message));
        }

        try
        {
            if (RemoveHostsBlockSection())
            {
                RunHiddenCommand("ipconfig", "/flushdns");
                notes.Add(L.Get("Fw_HostsRemoved"));
            }
        }
        catch (Exception ex)
        {
            notes.Add(L.Format("Fw_HostsCleanException", ex.Message));
        }

        return new FirewallActionResult(true, true, string.Join("；", notes));
    }

    public bool HasResidualSystemBlocks()
    {
        try
        {
            var path = HostsFilePath;
            if (File.Exists(path))
            {
                var content = File.ReadAllText(path, Encoding.UTF8);
                if (content.Contains(HostsBeginMarker, StringComparison.Ordinal))
                    return true;
            }
        }
        catch
        {
            // Ignore hosts read failure and still check firewall rules
        }

        foreach (var ruleName in new[] { FirewallRuleName, FirewallIpRuleName, FirewallForceProxyOnlyRuleName })
        {
            try
            {
                var (code, _) = RunHiddenCommand("netsh", $"advfirewall firewall show rule name=\"{ruleName}\"");
                if (code == 0)
                    return true;
            }
            catch
            {
                // Ignore netsh query failures
            }
        }

        return false;
    }

    public FirewallActionResult RestoreAllOnExit(bool allowElevateIfNeeded = true)
    {
        if (IsRunningAsAdmin())
        {
            return RemoveTrafficBlock(keepForceProxyOnly: false);
        }

        if (!HasResidualSystemBlocks())
        {
            return new FirewallActionResult(true, false, L.Get("Fw_NoResidual"));
        }

        if (allowElevateIfNeeded && TryRunElevatedCleanAll())
        {
            return new FirewallActionResult(true, false, L.Get("Fw_ResidualElevatedCleaned"));
        }

        return new FirewallActionResult(false, false, L.Get("Fw_ResidualNeedsAdmin"));
    }

    public static bool TryRunElevatedCleanAll()
    {
        try
        {
            var exePath = ResolveSelfExecutablePath();
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                return false;

            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = "--clean-all --elevated",
                UseShellExecute = true,
                Verb = "runas"
            };

            using var proc = Process.Start(psi);
            if (proc == null)
                return false;

            proc.WaitForExit(8000);
            return proc.HasExited && proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static string? ResolveSelfExecutablePath()
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exePath))
            return null;

        if (Path.GetFileName(exePath).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
        {
            var candidate = Path.ChangeExtension(typeof(FirewallManagerService).Assembly.Location, ".exe");
            if (File.Exists(candidate))
                exePath = candidate;
        }

        return exePath;
    }

    private static int ApplyForceProxyOnlyRuleInternal(IReadOnlyCollection<string> validExes)
    {
        RunHiddenCommand("netsh", $"advfirewall firewall delete rule name=\"{FirewallForceProxyOnlyRuleName}\"");
        int added = 0;
        foreach (var exe in validExes)
        {
            var (code, _) = RunHiddenCommand(
                "netsh",
                $"advfirewall firewall add rule name=\"{FirewallForceProxyOnlyRuleName}\" dir=out action=block program=\"{exe}\" remoteip=\"{NonLoopbackRemoteIps}\" enable=yes profile=any");
            if (code == 0)
            {
                added++;
            }
        }

        return added;
    }

    public bool TryRestartAsAdmin()
    {
        try
        {
            var exePath = ResolveSelfExecutablePath();
            if (string.IsNullOrWhiteSpace(exePath))
                return false;

            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = "--wait-relaunch",
                UseShellExecute = true,
                Verb = "runas"
            };
            Process.Start(psi);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static List<string> CollectAnthropicRemoteIpTargets()
    {
        // Anthropic 官方 AS399358 网段
        var targets = new List<string> { "160.79.104.0/21" };
        var seen = new HashSet<string>(targets, StringComparer.OrdinalIgnoreCase);

        foreach (var domain in new[] { "claude.ai", "api.anthropic.com" })
        {
            try
            {
                foreach (var ip in Dns.GetHostAddresses(domain))
                {
                    if (IPAddress.IsLoopback(ip) ||
                        ip.Equals(IPAddress.Any) ||
                        ip.Equals(IPAddress.IPv6Any) ||
                        ip.Equals(IPAddress.IPv6Loopback))
                    {
                        continue;
                    }

                    if (ip.AddressFamily == AddressFamily.InterNetwork ||
                        ip.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        var text = ip.ToString();
                        if (seen.Add(text))
                            targets.Add(text);
                    }
                }
            }
            catch
            {
                // Ignore DNS failures
            }
        }

        return targets;
    }

    private static void WriteHostsBlockSection() => WriteHostsBlockSectionToFile(HostsFilePath);

    internal static void WriteHostsBlockSectionToFile(string path)
    {
        var existing = File.Exists(path) ? File.ReadAllText(path, Encoding.UTF8) : string.Empty;
        var cleaned = StripHostsBlockSection(existing);

        var sb = new StringBuilder(cleaned.TrimEnd());
        if (sb.Length > 0)
        {
            sb.AppendLine();
            sb.AppendLine();
        }

        sb.AppendLine(HostsBeginMarker);
        foreach (var domain in BlockedDomains)
        {
            sb.AppendLine($"0.0.0.0 {domain}");
            sb.AppendLine($":: {domain}");
        }
        sb.AppendLine(HostsEndMarker);

        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static bool RemoveHostsBlockSection() => RemoveHostsBlockSectionFromFile(HostsFilePath);

    internal static bool RemoveHostsBlockSectionFromFile(string path)
    {
        if (!File.Exists(path))
            return false;

        var existing = File.ReadAllText(path, Encoding.UTF8);
        if (!existing.Contains(HostsBeginMarker, StringComparison.Ordinal))
            return false;

        var cleaned = StripHostsBlockSection(existing);
        File.WriteAllText(path, cleaned, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return true;
    }

    internal static string StripHostsBlockSection(string content)
    {
        var lines = content.Replace("\r\n", "\n").Split('\n');
        var result = new List<string>(lines.Length);
        bool insideBlock = false;

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.Equals(HostsBeginMarker, StringComparison.Ordinal))
            {
                insideBlock = true;
                continue;
            }

            if (trimmed.Equals(HostsEndMarker, StringComparison.Ordinal))
            {
                insideBlock = false;
                continue;
            }

            if (!insideBlock)
            {
                result.Add(line);
            }
        }

        var joined = string.Join(Environment.NewLine, result).TrimEnd();
        return string.IsNullOrEmpty(joined) ? string.Empty : joined + Environment.NewLine;
    }

    private static (int ExitCode, string Output) RunHiddenCommand(string fileName, string arguments)
    {
        using var proc = new Process();
        proc.StartInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        proc.Start();
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(5000);
        var combined = string.IsNullOrWhiteSpace(stderr) ? stdout : $"{stdout} {stderr}";
        return (proc.ExitCode, combined.Trim());
    }
}
