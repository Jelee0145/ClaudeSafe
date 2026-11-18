using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using ClaudeSafe.Localization;
using Microsoft.Win32;

namespace ClaudeSafe.Services;

/// <summary>
/// Claude Desktop 路径自动发现、安全参数启动与全量强杀服务
/// </summary>
public sealed class ClaudeProcessService
{
    public string? DiscoverClaudeExecutable()
    {
        return DiscoverAllClaudeExecutableCandidates().FirstOrDefault();
    }

    public List<string> DiscoverAllClaudeExecutableCandidates()
    {
        var candidates = new List<string>();
        var localAppDataRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddRoot(string? path)
        {
            if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
                localAppDataRoots.Add(path);
        }

        AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        AddRoot(Environment.GetEnvironmentVariable("LOCALAPPDATA"));
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(userProfile))
            AddRoot(Path.Combine(userProfile, "AppData", "Local"));

        foreach (var localAppData in localAppDataRoots)
        {
            // 1. WindowsApps 根目录下的 Microsoft Store 执行别名
            var msStoreAlias = Path.Combine(localAppData, "Microsoft", "WindowsApps", "claude-desktop-msstore.exe");
            if (File.Exists(msStoreAlias) && !candidates.Contains(msStoreAlias, StringComparer.OrdinalIgnoreCase))
                candidates.Add(msStoreAlias);

            // 2. WindowsApps\AnthropicPBC.Claude_* 子目录下的别名
            var windowsAppsDir = Path.Combine(localAppData, "Microsoft", "WindowsApps");
            if (Directory.Exists(windowsAppsDir))
            {
                try
                {
                    foreach (var dir in Directory.GetDirectories(windowsAppsDir, "AnthropicPBC.Claude_*"))
                    {
                        var exe = Path.Combine(dir, "claude-desktop-msstore.exe");
                        if (File.Exists(exe) && !candidates.Contains(exe, StringComparer.OrdinalIgnoreCase))
                            candidates.Add(exe);
                    }
                }
                catch
                {
                    // Ignore permission errors
                }
            }

            // 3. 传统 Squirrel 安装路径: %LOCALAPPDATA%\AnthropicClaude\claude.exe
            var anthropicClaudeDir = Path.Combine(localAppData, "AnthropicClaude");
            if (Directory.Exists(anthropicClaudeDir))
            {
                var directExe = Path.Combine(anthropicClaudeDir, "claude.exe");
                if (File.Exists(directExe) && !candidates.Contains(directExe, StringComparer.OrdinalIgnoreCase))
                    candidates.Add(directExe);

                try
                {
                    // 4. app-* 目录中按修改时间排序取最新版本
                    var appExes = Directory.GetDirectories(anthropicClaudeDir, "app-*")
                        .Select(d => Path.Combine(d, "claude.exe"))
                        .Where(File.Exists)
                        .OrderByDescending(File.GetLastWriteTimeUtc);

                    foreach (var exe in appExes)
                    {
                        if (!candidates.Contains(exe, StringComparer.OrdinalIgnoreCase))
                            candidates.Add(exe);
                    }
                }
                catch
                {
                    // Ignore
                }
            }

            // 5. 兜底扫描 %LOCALAPPDATA%\Programs
            var programsClaude = Path.Combine(localAppData, "Programs", "Claude", "Claude.exe");
            if (File.Exists(programsClaude) && !candidates.Contains(programsClaude, StringComparer.OrdinalIgnoreCase))
                candidates.Add(programsClaude);
        }

        return candidates;
    }

    public List<Process> GetRunningClaudeProcesses()
    {
        var result = new List<Process>();
        var currentPid = Environment.ProcessId;

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id == currentPid)
                {
                    proc.Dispose();
                    continue;
                }

                var name = proc.ProcessName;
                if (string.Equals(name, "ClaudeSafe", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(name, "ClaudeMom", StringComparison.OrdinalIgnoreCase))
                {
                    proc.Dispose();
                    continue;
                }

                string? filePath = TryGetMainModulePath(proc);

                bool isClaudeDesktop = false;
                if (string.Equals(name, "claude-desktop-msstore", StringComparison.OrdinalIgnoreCase))
                {
                    isClaudeDesktop = true;
                }
                else if (string.Equals(name, "claude", StringComparison.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrWhiteSpace(filePath))
                    {
                        // MSIX 容器进程有时对非提权进程返回拒绝访问，但进程名为 claude
                        isClaudeDesktop = true;
                    }
                    else if (filePath.Contains("AnthropicClaude", StringComparison.OrdinalIgnoreCase) ||
                             filePath.Contains("AnthropicPBC.Claude", StringComparison.OrdinalIgnoreCase) ||
                             filePath.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase) ||
                             filePath.Contains("Claude\\app-", StringComparison.OrdinalIgnoreCase))
                    {
                        isClaudeDesktop = true;
                    }
                }
                else if (string.Equals(name, "Update", StringComparison.OrdinalIgnoreCase) &&
                         !string.IsNullOrWhiteSpace(filePath) &&
                         filePath.Contains("AnthropicClaude", StringComparison.OrdinalIgnoreCase))
                {
                    isClaudeDesktop = true;
                }
                else if (!string.IsNullOrWhiteSpace(filePath) &&
                         (filePath.Contains("AnthropicClaude", StringComparison.OrdinalIgnoreCase) ||
                          filePath.Contains("AnthropicPBC.Claude", StringComparison.OrdinalIgnoreCase)))
                {
                    isClaudeDesktop = true;
                }

                if (isClaudeDesktop)
                {
                    result.Add(proc);
                }
                else
                {
                    proc.Dispose();
                }
            }
            catch
            {
                try { proc.Dispose(); } catch { }
            }
        }

        return result;
    }

    public int GetRunningClaudeProcessCount()
    {
        var list = GetRunningClaudeProcesses();
        var count = list.Count;
        foreach (var p in list)
        {
            try { p.Dispose(); } catch { }
        }
        return count;
    }

    public List<string> CollectObservedExecutablePaths()
    {
        var paths = DiscoverAllClaudeExecutableCandidates();
        foreach (var realMsixExe in DiscoverMsixRealExecutables())
        {
            if (!paths.Contains(realMsixExe, StringComparer.OrdinalIgnoreCase))
                paths.Add(realMsixExe);
        }

        var running = GetRunningClaudeProcesses();
        try
        {
            foreach (var proc in running)
            {
                var path = TryGetMainModulePath(proc);
                if (!string.IsNullOrWhiteSpace(path) &&
                    !paths.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    paths.Add(path);
                }
            }
        }
        finally
        {
            foreach (var p in running)
            {
                try { p.Dispose(); } catch { }
            }
        }

        return paths;
    }

    public List<string> DiscoverMsixRealExecutables()
    {
        var results = new List<string>();
        try
        {
            const string packagesKey = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
            using var root = Registry.CurrentUser.OpenSubKey(packagesKey);
            if (root == null) return results;

            foreach (var subKeyName in root.GetSubKeyNames())
            {
                if (!subKeyName.StartsWith("AnthropicPBC.Claude_", StringComparison.OrdinalIgnoreCase))
                    continue;

                using var pkgKey = root.OpenSubKey(subKeyName);
                var rootFolder = pkgKey?.GetValue("PackageRootFolder")?.ToString();
                if (string.IsNullOrWhiteSpace(rootFolder))
                    continue;

                var mainExe = Path.Combine(rootFolder, "app", "claude.exe");
                if (File.Exists(mainExe) && !results.Contains(mainExe, StringComparer.OrdinalIgnoreCase))
                    results.Add(mainExe);

                var svcExe = Path.Combine(rootFolder, "app", "resources", "cowork-svc.exe");
                if (File.Exists(svcExe) && !results.Contains(svcExe, StringComparer.OrdinalIgnoreCase))
                    results.Add(svcExe);
            }
        }
        catch
        {
            // Ignore registry/permission errors
        }

        return results;
    }

    public (bool Success, string Message) LaunchClaudeWithGatekeeper(string exePath, int gatekeeperPort)
    {
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
        {
            return (false, L.Get("Proc_ExeNotFound"));
        }

        try
        {
            var proxyUrl = $"http://127.0.0.1:{gatekeeperPort}";
            const string bypassList = "<-loopback>;10.0.0.0/8;172.16.0.0/12;192.168.0.0/16;169.254.0.0/16;*.local";
            const string noProxy = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local";

            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = $"--proxy-server=\"{proxyUrl}\" --proxy-bypass-list=\"{bypassList}\" --force-webrtc-ip-handling-policy=disable_non_proxied_udp --enforce-webrtc-ip-permission-check",
                UseShellExecute = false
            };

            psi.Environment["HTTP_PROXY"] = proxyUrl;
            psi.Environment["HTTPS_PROXY"] = proxyUrl;
            psi.Environment["ALL_PROXY"] = proxyUrl;
            psi.Environment["http_proxy"] = proxyUrl;
            psi.Environment["https_proxy"] = proxyUrl;
            psi.Environment["all_proxy"] = proxyUrl;
            psi.Environment["NO_PROXY"] = noProxy;
            psi.Environment["no_proxy"] = noProxy;

            // 让内置 Node.js / MCP 工具 (Node 22.21+ / 24 及 global-agent) 自动读取代理环境变量，不走直连
            psi.Environment["NODE_USE_ENV_PROXY"] = "1";
            psi.Environment["GLOBAL_AGENT_HTTP_PROXY"] = proxyUrl;
            psi.Environment["GLOBAL_AGENT_HTTPS_PROXY"] = proxyUrl;
            psi.Environment["GLOBAL_AGENT_NO_PROXY"] = noProxy;
            psi.Environment["npm_config_proxy"] = proxyUrl;
            psi.Environment["npm_config_https_proxy"] = proxyUrl;

            var proc = Process.Start(psi);
            if (proc == null)
            {
                return (false, L.Get("Proc_NullHandle"));
            }

            return (true, L.Format("Proc_Launched", proxyUrl, proc.Id));
        }
        catch (Exception ex)
        {
            return (false, L.Format("Proc_LaunchFail", ex.Message));
        }
    }

    public int KillAllClaudeProcesses()
    {
        int killedCount = 0;
        var procs = GetRunningClaudeProcesses();
        try
        {
            foreach (var proc in procs)
            {
                try
                {
                    if (!proc.HasExited)
                    {
                        proc.Kill(entireProcessTree: true);
                        proc.WaitForExit(1500);
                        killedCount++;
                    }
                }
                catch
                {
                    // 交由下方 taskkill 兜底
                }
            }
        }
        finally
        {
            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { }
            }
        }

        // taskkill 兜底确保无任何残余进程树（如 GPU/Renderer 子进程）
        RunTaskKill("claude.exe");
        RunTaskKill("claude-desktop-msstore.exe");

        return killedCount;
    }

    private static string? TryGetMainModulePath(Process proc)
    {
        try
        {
            return proc.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static void RunTaskKill(string imageName)
    {
        try
        {
            using var tk = new Process();
            tk.StartInfo = new ProcessStartInfo
            {
                FileName = "taskkill",
                Arguments = $"/F /IM \"{imageName}\" /T",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            tk.Start();
            tk.WaitForExit(3000);
        }
        catch
        {
            // Ignore
        }
    }
}
