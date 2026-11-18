using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using ClaudeSafe.Localization;
using Microsoft.Win32;

namespace ClaudeSafe.Services;

/// <summary>
/// Windows WinInet 系统代理与动态 PAC 脚本接管服务（无需管理员权限即可拦截浏览器对 claude.ai 的访问）
/// </summary>
public sealed class SystemProxyService
{
    private const string InternetSettingsSubKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int InternetOptionSettingsChanged = 39;
    private const int InternetOptionRefresh = 37;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private sealed class ProxyBackupState
    {
        public int ProxyEnable { get; set; }
        public string? ProxyServer { get; set; }
        public string? AutoConfigURL { get; set; }
        public string? ProxyOverride { get; set; }
    }

    private readonly string _backupFilePath;
    private readonly object _syncRoot = new();
    private ProxyBackupState? _backup;

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    public SystemProxyService(string? customBackupPath = null)
    {
        if (!string.IsNullOrWhiteSpace(customBackupPath))
        {
            _backupFilePath = customBackupPath;
        }
        else
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA")
                               ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            _backupFilePath = Path.Combine(localAppData, "ClaudeSafe", "proxy_backup.json");
        }
    }

    public (bool Success, string Message) CaptureBackupAndApplyGatekeeper(int gatekeeperPort, bool isGateOpen)
    {
        lock (_syncRoot)
        {
            try
            {
                CaptureInitialProxyBackupInternal(gatekeeperPort);
                return ApplyGatekeeperInternal(gatekeeperPort, isGateOpen);
            }
            catch (Exception ex)
            {
                return (false, L.Format("SysProxy_TakeoverFail", ex.Message));
            }
        }
    }

    public (bool Success, string Message) UpdateGatekeeperState(int gatekeeperPort, bool isGateOpen)
    {
        lock (_syncRoot)
        {
            try
            {
                if (_backup == null)
                    CaptureInitialProxyBackupInternal(gatekeeperPort);
                return ApplyGatekeeperInternal(gatekeeperPort, isGateOpen);
            }
            catch (Exception ex)
            {
                return (false, L.Format("SysProxy_RefreshFail", ex.Message));
            }
        }
    }

    public (bool Success, string Message) RestoreSystemProxyOnExit(int gatekeeperPort)
    {
        lock (_syncRoot)
        {
            try
            {
                var backup = _backup ?? TryLoadBackupFile();
                using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsSubKey, writable: true);
                if (key == null)
                    return (false, L.Get("SysProxy_RegOpenFail"));

                if (backup != null)
                {
                    key.SetValue("ProxyEnable", backup.ProxyEnable, RegistryValueKind.DWord);

                    RestoreOrDeleteValue(key, "ProxyServer", backup.ProxyServer, gatekeeperPort);
                    RestoreOrDeleteValue(key, "AutoConfigURL", backup.AutoConfigURL, gatekeeperPort);
                    RestoreOrDeleteValue(key, "ProxyOverride", backup.ProxyOverride, gatekeeperPort);
                }
                else
                {
                    // 兜底：若当前仍指向守门代理且无有效备份，则安全关闭代理避免断网
                    var curServer = key.GetValue("ProxyServer")?.ToString();
                    var curPac = key.GetValue("AutoConfigURL")?.ToString();
                    if (PointsToGatekeeper(curServer, gatekeeperPort))
                        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                    if (PointsToGatekeeper(curPac, gatekeeperPort))
                        key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
                }

                NotifyWinInetChanged(synchronous: true);
                TryDeleteBackupFile();
                _backup = null;
                return (true, L.Get("SysProxy_Restored"));
            }
            catch (Exception ex)
            {
                return (false, L.Format("SysProxy_RestoreError", ex.Message));
            }
        }
    }

    private void CaptureInitialProxyBackupInternal(int gatekeeperPort)
    {
        if (_backup != null)
            return;

        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsSubKey, writable: false);
        var curEnable = key?.GetValue("ProxyEnable") is int i ? i : 0;
        var curServer = key?.GetValue("ProxyServer")?.ToString();
        var curPac = key?.GetValue("AutoConfigURL")?.ToString();
        var curOverride = key?.GetValue("ProxyOverride")?.ToString();

        // 若注册表已指向自身守门端口（例如上次异常退出未还原），优先读取本地备份而不覆盖
        if (PointsToGatekeeper(curServer, gatekeeperPort) || PointsToGatekeeper(curPac, gatekeeperPort))
        {
            var existingBackup = TryLoadBackupFile();
            if (existingBackup != null)
            {
                _backup = existingBackup;
                return;
            }
        }

        _backup = new ProxyBackupState
        {
            ProxyEnable = curEnable,
            ProxyServer = PointsToGatekeeper(curServer, gatekeeperPort) ? null : curServer,
            AutoConfigURL = PointsToGatekeeper(curPac, gatekeeperPort) ? null : curPac,
            ProxyOverride = curOverride
        };

        SaveBackupFile(_backup);
    }

    private (bool Success, string Message) ApplyGatekeeperInternal(int gatekeeperPort, bool isGateOpen)
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsSubKey, writable: true);
        if (key == null)
            return (false, L.Get("SysProxy_RegWriteFail"));

        var stateTag = isGateOpen ? "open" : "locked";
        var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var pacUrl = $"http://127.0.0.1:{gatekeeperPort}/pac.js?state={stateTag}&ts={ts}";

        // 仅下发动态 PAC 地址，不篡改用户原有的 ProxyEnable / ProxyServer，确保没挂代理时普通国内网页照常直连
        key.SetValue("AutoConfigURL", pacUrl, RegistryValueKind.String);

        NotifyWinInetChanged();
        return (true, L.Format("SysProxy_PacApplied", isGateOpen ? L.Get("SysProxy_PacOpen") : L.Get("SysProxy_PacLocked")));
    }

    private static void RestoreOrDeleteValue(RegistryKey key, string name, string? value, int gatekeeperPort)
    {
        if (string.IsNullOrWhiteSpace(value) || PointsToGatekeeper(value, gatekeeperPort))
        {
            key.DeleteValue(name, throwOnMissingValue: false);
        }
        else
        {
            key.SetValue(name, value, RegistryValueKind.String);
        }
    }

    private static bool PointsToGatekeeper(string? value, int gatekeeperPort)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        if (value.Contains("/pac.js?state=", StringComparison.OrdinalIgnoreCase))
            return true;

        if (gatekeeperPort <= 0)
            return false;

        return value.Contains($"127.0.0.1:{gatekeeperPort}", StringComparison.OrdinalIgnoreCase) ||
               value.Contains($"localhost:{gatekeeperPort}", StringComparison.OrdinalIgnoreCase);
    }

    private static void NotifyWinInetChanged(bool synchronous = false)
    {
        if (synchronous)
        {
            InvokeWinInetRefresh();
            return;
        }

        // 在后台触发 WinInet 刷新通知，避免阻塞 WPF UI 线程
        System.Threading.Tasks.Task.Run(InvokeWinInetRefresh);
    }

    private static void InvokeWinInetRefresh()
    {
        try
        {
            InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
        }
        catch
        {
            // Ignore WinInet refresh errors
        }
    }

    private ProxyBackupState? TryLoadBackupFile()
    {
        try
        {
            if (!File.Exists(_backupFilePath))
                return null;
            var json = File.ReadAllText(_backupFilePath);
            return JsonSerializer.Deserialize<ProxyBackupState>(json, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    private void SaveBackupFile(ProxyBackupState backup)
    {
        try
        {
            var dir = Path.GetDirectoryName(_backupFilePath);
            if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(_backupFilePath, JsonSerializer.Serialize(backup, JsonOptions));
        }
        catch
        {
            // Ignore backup persistence errors
        }
    }

    private void TryDeleteBackupFile()
    {
        try
        {
            if (File.Exists(_backupFilePath))
                File.Delete(_backupFilePath);
        }
        catch
        {
            // Ignore
        }
    }
}
