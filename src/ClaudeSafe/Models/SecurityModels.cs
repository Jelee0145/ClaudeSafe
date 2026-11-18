using System;
using System.Collections.Generic;
using ClaudeSafe.Localization;

namespace ClaudeSafe.Models;

/// <summary>
/// 单项安全检测的风险等级
/// </summary>
public enum RiskLevel
{
    Pending,
    Safe,
    Warning,
    Danger
}

/// <summary>
/// 小助手当前所处的安全防护状态机
/// </summary>
public enum AppProtectionState
{
    /// <summary>常态安全封锁中（未授权启动前禁止外连）</summary>
    LockedIdle,
    /// <summary>正在执行网络与风险检测</summary>
    Checking,
    /// <summary>体检通过，安全就绪，允许启动 Claude</summary>
    ReadyToLaunch,
    /// <summary>Claude 运行中，受守门代理与看门狗保护</summary>
    RunningProtected,
    /// <summary>运行期检测到掉线或 IP 异动，已毫秒级断流熔断</summary>
    CircuitBreakerTripped,
    /// <summary>用户选择锁定网络，处于 5 分钟冷静期倒计时</summary>
    CooldownLocked,
    /// <summary>用户长按 Logo 1 秒临时解锁（3P 模式自由启动，看门狗不拦截）</summary>
    ManualUnlocked
}

/// <summary>
/// 单项风险检测结果
/// </summary>
public sealed class CheckItemResult
{
    public string Id { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string ShortTitle { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Pending;
    public string StatusText { get; set; } = string.Empty;
    public string ShortStatus { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public bool IsCrossCountryDrift { get; set; }

    public bool IsIssue => RiskLevel is RiskLevel.Warning or RiskLevel.Danger;
    public string DisplayShortTitle => string.IsNullOrWhiteSpace(ShortTitle) ? Title : ShortTitle;
    public string DisplayShortStatus => string.IsNullOrWhiteSpace(ShortStatus) ? StatusText : ShortStatus;

    public string IconText => RiskLevel switch
    {
        RiskLevel.Safe => "✅",
        RiskLevel.Warning => "⚠️",
        RiskLevel.Danger => "❌",
        _ => "⏳"
    };

    public string RiskBadgeText => RiskLevel switch
    {
        RiskLevel.Safe => L.Get("Risk_Safe"),
        RiskLevel.Warning => L.Get("Risk_Warning"),
        RiskLevel.Danger => L.Get("Risk_Danger"),
        _ => L.Get("Risk_Pending")
    };
}

/// <summary>
/// 出口 IP 地理与 ASN 情报
/// </summary>
public sealed class IpGeoInfo
{
    public string Ip { get; set; } = string.Empty;
    public string Country { get; set; } = string.Empty;
    public string CountryCode { get; set; } = string.Empty;
    public string Region { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string Isp { get; set; } = string.Empty;
    public string Org { get; set; } = string.Empty;
    public string Asn { get; set; } = string.Empty;
    public bool IsHosting { get; set; }
    public bool IsProxy { get; set; }
    public string Source { get; set; } = string.Empty;
    public long LatencyMs { get; set; }

    public string DisplayLocation
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(Country)) parts.Add(Country);
            if (!string.IsNullOrWhiteSpace(Region)) parts.Add(Region);
            if (!string.IsNullOrWhiteSpace(City) && !string.Equals(City, Region, StringComparison.OrdinalIgnoreCase))
                parts.Add(City);
            return parts.Count > 0 ? string.Join(" · ", parts) : L.Get("Common_UnknownLocation");
        }
    }
}

/// <summary>
/// 历史安全启动记录（用于 IP 漂移对比）
/// </summary>
public sealed class HistoricalIpRecord
{
    public string Ip { get; set; } = string.Empty;
    public string CountryCode { get; set; } = string.Empty;
    public string Country { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string Asn { get; set; } = string.Empty;
    public string Isp { get; set; } = string.Empty;
    public DateTimeOffset RecordedAt { get; set; } = DateTimeOffset.Now;
}

/// <summary>
/// 本地代理端口探测结果
/// </summary>
public sealed class ProxyProbeResult
{
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; }
    public bool IsReachable { get; set; }
    public long LatencyMs { get; set; }
    public string SourceDescription { get; set; } = string.Empty;
    public bool SystemProxyEnabled { get; set; }
    public string SystemProxyRaw { get; set; } = string.Empty;
    public bool TunModeEnabled { get; set; }
    public string TunAdapterName { get; set; } = string.Empty;
    public List<string> RunningAccelerators { get; set; } = new();
}

/// <summary>
/// 启动前完整安全体检报告
/// </summary>
public sealed class PreFlightReport
{
    public DateTimeOffset CheckedAt { get; set; } = DateTimeOffset.Now;
    public ProxyProbeResult ProxyProbe { get; set; } = new();
    public IpGeoInfo? ExitIpInfo { get; set; }
    public string? AnthropicTraceCountry { get; set; }
    public bool AnthropicReachable { get; set; }
    public List<CheckItemResult> CheckItems { get; set; } = new();
    public bool CanLaunch { get; set; }
    public bool HasWarnings { get; set; }
    public string Summary { get; set; } = string.Empty;
}

/// <summary>
/// 持久化应用配置
/// </summary>
public sealed class AppConfig
{
    public string UpstreamProxyHost { get; set; } = "127.0.0.1";
    public int UpstreamProxyPort { get; set; } = 7890;
    public int GatekeeperPort { get; set; } = 17890;
    public string ClaudeExecutablePath { get; set; } = string.Empty;
    public bool EnableFirewallRule { get; set; } = true;
    public bool EnableHostsBlock { get; set; } = true;
    public bool BlockUnauthorizedClaudeLaunch { get; set; } = true;
    public bool LaunchOnWindowsStartup { get; set; } = false;
    public int CooldownDurationSeconds { get; set; } = 300;
    public string Language { get; set; } = L.Auto;
    public HistoricalIpRecord? LastSafeIpRecord { get; set; }
    public List<HistoricalIpRecord> IpHistory { get; set; } = new();
}
