using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;

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
                "当前为标准用户权限，已启用守门代理与进程级封锁（如需写入系统防火墙和 Hosts，请点击提权以管理员运行）。");
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
                        errors.Add($"防火墙规则添加失败({Path.GetFileName(exe)}): {output}");
                    }
                }

                // 追加 Anthropic 专属公网 IP 段阻断规则（覆盖物理网卡与 TUN 虚拟网卡上的所有进程含浏览器）
                var remoteIps = CollectAnthropicRemoteIpTargets();
                var (ipCode, ipOut) = RunHiddenCommand(
                    "netsh",
                    $"advfirewall firewall add rule name=\"{FirewallIpRuleName}\" dir=out action=block remoteip=\"{string.Join(",", remoteIps)}\" enable=yes profile=any");

                if (ipCode == 0)
                {
                    actions.Add($"已添加 Anthropic IP 段防火墙阻断（{remoteIps.Count} 项）");
                }
                else
                {
                    errors.Add($"Anthropic IP 防火墙规则添加失败: {ipOut}");
                }

                // 常驻强制仅走代理规则：即使未来放行运行 Claude，也只允许回环 127.0.0.1，永久禁止任何直连公网
                int proxyOnlyAdded = ApplyForceProxyOnlyRuleInternal(validExes);
                if (proxyOnlyAdded > 0)
                {
                    actions.Add($"已开启禁直连规则（{proxyOnlyAdded} 个进程仅允许走本地代理）");
                }

                if (added > 0)
                {
                    actions.Add($"已添加 {added} 条 Claude 进程出站拦截规则");
                }
            }
            catch (Exception ex)
            {
                errors.Add($"防火墙操作异常: {ex.Message}");
            }
        }

        if (enableHosts)
        {
            try
            {
                WriteHostsBlockSection();
                RunHiddenCommand("ipconfig", "/flushdns");
                actions.Add($"已将 {BlockedDomains.Length} 个 Claude/Anthropic 域名写入 Hosts 黑洞并刷新 DNS");
            }
            catch (Exception ex)
            {
                errors.Add($"Hosts 写入异常: {ex.Message}");
            }
        }

        if (errors.Count > 0 && actions.Count == 0)
        {
            return new FirewallActionResult(false, true, string.Join("；", errors));
        }

        var msg = string.Join("；", actions.Concat(errors));
        return new FirewallActionResult(errors.Count == 0, true, string.IsNullOrWhiteSpace(msg) ? "系统级封锁已生效" : msg);
    }

    public FirewallActionResult RemoveTrafficBlock(IEnumerable<string>? claudeExePaths = null, bool keepForceProxyOnly = true)
    {
        if (!IsRunningAsAdmin())
        {
            return new FirewallActionResult(true, false, "标准权限模式（仅由守门代理与启动参数限制代理通道）");
        }

        var notes = new List<string>();
        try
        {
            RunHiddenCommand("netsh", $"advfirewall firewall delete rule name=\"{FirewallRuleName}\"");
            RunHiddenCommand("netsh", $"advfirewall firewall delete rule name=\"{FirewallIpRuleName}\"");
            notes.Add("已解除全量出站封锁");

            if (keepForceProxyOnly && claudeExePaths != null)
            {
                var validExes = claudeExePaths
                    .Where(p => !string.IsNullOrWhiteSpace(p) && File.Exists(p))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                int forced = ApplyForceProxyOnlyRuleInternal(validExes);
                if (forced > 0)
                {
                    notes.Add($"保持 Claude 禁直连防火墙（{forced} 个程序仅允许连接 127.0.0.1 代理）");
                }
            }
            else if (!keepForceProxyOnly)
            {
                RunHiddenCommand("netsh", $"advfirewall firewall delete rule name=\"{FirewallForceProxyOnlyRuleName}\"");
                notes.Add("已临时移除 Claude 禁直连防火墙（允许 3P 模式自由联网）");
            }
        }
        catch (Exception ex)
        {
            notes.Add($"更新防火墙规则异常: {ex.Message}");
        }

        try
        {
            if (RemoveHostsBlockSection())
            {
                RunHiddenCommand("ipconfig", "/flushdns");
                notes.Add("已解除 Hosts 域名封锁并刷新 DNS");
            }
        }
        catch (Exception ex)
        {
            notes.Add($"清理 Hosts 异常: {ex.Message}");
        }

        return new FirewallActionResult(true, true, string.Join("；", notes));
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
            var exePath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exePath))
                return false;

            if (Path.GetFileName(exePath).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
            {
                var candidate = Path.ChangeExtension(typeof(FirewallManagerService).Assembly.Location, ".exe");
                if (File.Exists(candidate))
                    exePath = candidate;
            }

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

    private static void WriteHostsBlockSection()
    {
        var path = HostsFilePath;
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

    private static bool RemoveHostsBlockSection()
    {
        var path = HostsFilePath;
        if (!File.Exists(path))
            return false;

        var existing = File.ReadAllText(path, Encoding.UTF8);
        if (!existing.Contains(HostsBeginMarker, StringComparison.Ordinal))
            return false;

        var cleaned = StripHostsBlockSection(existing);
        File.WriteAllText(path, cleaned, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return true;
    }

    private static string StripHostsBlockSection(string content)
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

        return string.Join(Environment.NewLine, result).TrimEnd() + Environment.NewLine;
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
