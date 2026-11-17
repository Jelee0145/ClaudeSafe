using System;
using System.IO;
using System.Text.Json;
using ClaudeSafe.Models;
using Microsoft.Win32;

namespace ClaudeSafe.Services;

/// <summary>
/// 线程安全的配置文件与历史 IP 记录持久化服务
/// </summary>
public sealed class ConfigService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private readonly object _syncRoot = new();

    public string ConfigFilePath { get; }

    public ConfigService(string? customConfigPath = null)
    {
        if (!string.IsNullOrWhiteSpace(customConfigPath))
        {
            ConfigFilePath = customConfigPath;
        }
        else
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var dir = Path.Combine(localAppData, "ClaudeSafe");
            ConfigFilePath = Path.Combine(dir, "config.json");
        }
    }

    public AppConfig Load()
    {
        lock (_syncRoot)
        {
            try
            {
                if (!File.Exists(ConfigFilePath))
                {
                    var defaults = new AppConfig();
                    SaveInternal(defaults);
                    return defaults;
                }

                var json = File.ReadAllText(ConfigFilePath);
                var config = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions) ?? new AppConfig();
                if (config.UpstreamProxyPort <= 0) config.UpstreamProxyPort = 7890;
                if (string.IsNullOrWhiteSpace(config.UpstreamProxyHost)) config.UpstreamProxyHost = "127.0.0.1";
                if (config.GatekeeperPort <= 0) config.GatekeeperPort = 17890;
                if (config.CooldownDurationSeconds <= 0) config.CooldownDurationSeconds = 300;
                config.IpHistory ??= new();
                return config;
            }
            catch
            {
                return new AppConfig();
            }
        }
    }

    public void Save(AppConfig config)
    {
        lock (_syncRoot)
        {
            SaveInternal(config);
        }
    }

    public void RecordSafeLaunchIp(AppConfig config, IpGeoInfo geo)
    {
        if (string.IsNullOrWhiteSpace(geo.Ip))
            return;

        lock (_syncRoot)
        {
            var record = new HistoricalIpRecord
            {
                Ip = geo.Ip,
                CountryCode = geo.CountryCode,
                Country = geo.Country,
                City = geo.City,
                Asn = geo.Asn,
                Isp = geo.Isp,
                RecordedAt = DateTimeOffset.Now
            };

            config.LastSafeIpRecord = record;
            config.IpHistory ??= new();
            config.IpHistory.Insert(0, record);
            if (config.IpHistory.Count > 50)
            {
                config.IpHistory.RemoveRange(50, config.IpHistory.Count - 50);
            }

            SaveInternal(config);
        }
    }

    public void ClearIpBaseline(AppConfig config)
    {
        lock (_syncRoot)
        {
            config.LastSafeIpRecord = null;
            config.IpHistory?.Clear();
            SaveInternal(config);
        }
    }

    public bool IsWindowsStartupEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: false);
            return key?.GetValue("ClaudeSafe") is string val && !string.IsNullOrWhiteSpace(val);
        }
        catch
        {
            return false;
        }
    }

    public (bool Success, string Message) SetWindowsStartup(bool enable)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true);
            if (key == null)
                return (false, "无法打开开机启动注册表键");

            if (enable)
            {
                var exePath = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(exePath) &&
                    Path.GetFileName(exePath).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
                {
                    var candidate = Path.ChangeExtension(typeof(ConfigService).Assembly.Location, ".exe");
                    if (File.Exists(candidate)) exePath = candidate;
                }

                if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                    return (false, "未找到可执行文件路径");

                key.SetValue("ClaudeSafe", $"\"{exePath}\" --minimized", RegistryValueKind.String);
                return (true, "已开启开机自启动（静默驻留系统托盘守护）");
            }
            else
            {
                key.DeleteValue("ClaudeSafe", throwOnMissingValue: false);
                return (true, "已关闭开机自启动");
            }
        }
        catch (Exception ex)
        {
            return (false, $"设置开机自启动失败: {ex.Message}");
        }
    }

    private void SaveInternal(AppConfig config)
    {
        var dir = Path.GetDirectoryName(ConfigFilePath);
        if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var json = JsonSerializer.Serialize(config, JsonOptions);
        File.WriteAllText(ConfigFilePath, json);
    }
}
