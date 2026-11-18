using System;
using System.Threading;
using System.Threading.Tasks;
using ClaudeSafe.Localization;
using ClaudeSafe.Models;

namespace ClaudeSafe.Services;

public sealed class CircuitBreakerTrippedEventArgs : EventArgs
{
    public required string Reason { get; init; }
    public IpGeoInfo? ExpectedIp { get; init; }
    public IpGeoInfo? CurrentIp { get; init; }
    public int SeveredConnections { get; init; }
    public DateTimeOffset TrippedAt { get; init; } = DateTimeOffset.Now;
}

/// <summary>
/// 运行期进程看门狗、断流/IP异动毫秒级熔断器与 5 分钟冷静期调度服务
/// </summary>
public sealed class RuntimeWatchdogService : IDisposable
{
    private readonly ProxyDetectorService _proxyDetector;
    private readonly NetworkCheckService _networkCheck;
    private readonly GatekeeperProxyServer _gatekeeper;
    private readonly FirewallManagerService _firewall;
    private readonly ClaudeProcessService _processService;
    private readonly SystemProxyService _systemProxy;

    private readonly object _stateLock = new();
    private CancellationTokenSource? _loopCts;
    private Task? _watchdogTask;

    private AppProtectionState _state = AppProtectionState.LockedIdle;
    private IpGeoInfo? _boundSafeIp;
    private string _boundProxyHost = "127.0.0.1";
    private int _boundProxyPort = 7890;
    private AppConfig _currentConfig = new();
    private DateTimeOffset _launchGraceUntil = DateTimeOffset.MinValue;
    private DateTimeOffset _lastIpCheckAt = DateTimeOffset.MinValue;
    private int _tickCounter;
    private int _remainingCooldownSeconds;
    private bool _cooldownHadRunningClaude;
    private int _recoveryProbeRunning;
    private volatile bool _isExitPromptActive;

    public bool IsExitPromptActive
    {
        get => _isExitPromptActive;
        set => _isExitPromptActive = value;
    }

    public AppProtectionState State
    {
        get { lock (_stateLock) return _state; }
    }

    public int RemainingCooldownSeconds
    {
        get { lock (_stateLock) return _remainingCooldownSeconds; }
    }

    public IpGeoInfo? BoundSafeIp
    {
        get { lock (_stateLock) return _boundSafeIp; }
    }

    public event Action<AppProtectionState>? OnStateChanged;
    public event Action<string>? OnLog;
    public event Action<CircuitBreakerTrippedEventArgs>? OnCircuitBreakerTripped;
    public event Action<int>? OnCooldownTick;
    public event Action? OnCooldownExpired;
    public event Action<PreFlightReport, bool>? OnCooldownAutoRecovered;
    public event Action<string>? OnClaudeExitedCleanly;
    public event Action<string>? OnUnauthorizedLaunchBlocked;

    public RuntimeWatchdogService(
        ProxyDetectorService proxyDetector,
        NetworkCheckService networkCheck,
        GatekeeperProxyServer gatekeeper,
        FirewallManagerService firewall,
        ClaudeProcessService processService,
        SystemProxyService systemProxy)
    {
        _proxyDetector = proxyDetector;
        _networkCheck = networkCheck;
        _gatekeeper = gatekeeper;
        _firewall = firewall;
        _processService = processService;
        _systemProxy = systemProxy;
    }

    public void Start(AppConfig config)
    {
        lock (_stateLock)
        {
            _currentConfig = config;
            if (_loopCts != null) return;
            _loopCts = new CancellationTokenSource();
            _watchdogTask = Task.Run(() => WatchdogLoopAsync(_loopCts.Token));
        }
    }

    public void UpdateConfig(AppConfig config)
    {
        lock (_stateLock)
        {
            _currentConfig = config;
        }
    }

    public void SetState(AppProtectionState newState)
    {
        lock (_stateLock)
        {
            if (_state == newState) return;
            _state = newState;
        }
        OnStateChanged?.Invoke(newState);
    }

    public void BeginProtectedSession(IpGeoInfo boundIp, string proxyHost, int proxyPort, AppConfig config)
    {
        lock (_stateLock)
        {
            _boundSafeIp = boundIp;
            _boundProxyHost = proxyHost;
            _boundProxyPort = proxyPort;
            _currentConfig = config;
            _launchGraceUntil = DateTimeOffset.UtcNow.AddSeconds(8);
            _lastIpCheckAt = DateTimeOffset.UtcNow;
            _remainingCooldownSeconds = 0;
            _state = AppProtectionState.RunningProtected;
        }

        _systemProxy.UpdateGatekeeperState(_gatekeeper.ListeningPort, isGateOpen: true);
        OnStateChanged?.Invoke(AppProtectionState.RunningProtected);
        OnLog?.Invoke(L.Format("Wd_Activated", boundIp.Ip, boundIp.CountryCode));
    }

    public void ResumeProtectedSessionAfterCooldown(IpGeoInfo newBoundIp, string proxyHost, int proxyPort, AppConfig config)
    {
        BeginProtectedSession(newBoundIp, proxyHost, proxyPort, config);
    }

    public void StartCooldown(int? customSeconds = null)
    {
        int duration;
        bool hasClaude = _processService.GetRunningClaudeProcessCount() > 0;
        lock (_stateLock)
        {
            duration = customSeconds ?? Math.Max(30, _currentConfig.CooldownDurationSeconds);
            _remainingCooldownSeconds = duration;
            _cooldownHadRunningClaude = hasClaude;
            _state = AppProtectionState.CooldownLocked;
        }

        OnStateChanged?.Invoke(AppProtectionState.CooldownLocked);
        OnCooldownTick?.Invoke(duration);
        OnLog?.Invoke(L.Format("Wd_CooldownEntered", duration / 60, duration % 60));
    }

    public void EnterManualUnlockedMode(string reason)
    {
        lock (_stateLock)
        {
            _remainingCooldownSeconds = 0;
            _boundSafeIp = null;
            _state = AppProtectionState.ManualUnlocked;
        }

        _gatekeeper.SetManualBypass(true);
        _systemProxy.UpdateGatekeeperState(_gatekeeper.ListeningPort, isGateOpen: true);
        var fwResult = _firewall.RemoveTrafficBlock(keepForceProxyOnly: false);

        OnStateChanged?.Invoke(AppProtectionState.ManualUnlocked);
        OnLog?.Invoke(L.Format("Wd_Unlocked3P", reason, fwResult.Message));
    }

    public void CleanExitClaudeAndLockAll(string reason)
    {
        // 1. 第一优先级：毫秒级断流 + 刷新系统/浏览器 PAC 封锁 + 防火墙/Hosts 封锁
        _gatekeeper.SetManualBypass(false);
        int severed = _gatekeeper.LockGateAndSeverAll(reason);
        _systemProxy.UpdateGatekeeperState(_gatekeeper.ListeningPort, isGateOpen: false);
        var paths = _processService.CollectObservedExecutablePaths();
        var fwResult = _firewall.ApplyTrafficBlock(paths, _currentConfig.EnableFirewallRule, _currentConfig.EnableHostsBlock);

        // 2. 第二步：彻底清理 Claude 进程树
        int killed = _processService.KillAllClaudeProcesses();

        lock (_stateLock)
        {
            _remainingCooldownSeconds = 0;
            _boundSafeIp = null;
            _state = AppProtectionState.LockedIdle;
        }

        OnStateChanged?.Invoke(AppProtectionState.LockedIdle);
        OnLog?.Invoke(L.Format("Wd_CleanExitLog", reason, severed, killed, fwResult.Message));
    }

    /// <summary>
    /// 程序彻底退出时停止看门狗、按需关闭运行中的 Claude，并彻底还原防火墙与 Hosts 设置（不留痕）
    /// </summary>
    public void ShutdownAndRestoreAllOnExit(string reason, bool allowElevateIfNeeded = true, bool killClaudeProcesses = true)
    {
        CancellationTokenSource? ctsToStop;
        Task? taskToWait;

        lock (_stateLock)
        {
            ctsToStop = _loopCts;
            taskToWait = _watchdogTask;
            _loopCts = null;
            _watchdogTask = null;
        }

        // 1. 先停看门狗线程，防止退出清理期间并发巡检重新下发封锁规则
        try { ctsToStop?.Cancel(); } catch { }
        try { taskToWait?.Wait(800); } catch { }
        try { ctsToStop?.Dispose(); } catch { }

        // 2. 切断守门代理活跃连接，并根据用户选择决定是否同步关闭 Claude 进程
        _gatekeeper.SetManualBypass(false);
        int severed = _gatekeeper.LockGateAndSeverAll(reason);
        int killed = killClaudeProcesses
            ? _processService.KillAllClaudeProcesses()
            : 0;

        // 3. 彻底移除所有防火墙规则与 Hosts 黑洞，还原不留痕
        var fwRestore = _firewall.RestoreAllOnExit(allowElevateIfNeeded);

        lock (_stateLock)
        {
            _remainingCooldownSeconds = 0;
            _cooldownHadRunningClaude = false;
            _boundSafeIp = null;
            _state = AppProtectionState.LockedIdle;
        }

        OnLog?.Invoke(L.Format("Wd_ExitRestoreLog", reason, severed, killed, fwRestore.Message));
    }

    public void TriggerCircuitBreaker(string reason, IpGeoInfo? currentIp, bool isSimulation = false)
    {
        IpGeoInfo? expectedIp;
        AppConfig cfg;

        lock (_stateLock)
        {
            if (!isSimulation &&
                _state != AppProtectionState.RunningProtected)
            {
                return;
            }

            expectedIp = _boundSafeIp;
            cfg = _currentConfig;
            _state = AppProtectionState.CircuitBreakerTripped;
        }

        // 0ms 物理切断所有活跃 TCP 连接并锁定守门阀门 + 刷新浏览器 PAC 断开连接池（注意：不杀 Claude 进程）
        int severed = _gatekeeper.LockGateAndSeverAll(reason);
        _systemProxy.UpdateGatekeeperState(_gatekeeper.ListeningPort, isGateOpen: false);
        var paths = _processService.CollectObservedExecutablePaths();
        var fwResult = _firewall.ApplyTrafficBlock(paths, cfg.EnableFirewallRule, cfg.EnableHostsBlock);

        OnStateChanged?.Invoke(AppProtectionState.CircuitBreakerTripped);
        OnLog?.Invoke(L.Format("Wd_TrippedLog", reason, severed) + " " + fwResult.Message);

        OnCircuitBreakerTripped?.Invoke(new CircuitBreakerTrippedEventArgs
        {
            Reason = reason,
            ExpectedIp = expectedIp,
            CurrentIp = currentIp,
            SeveredConnections = severed,
            TrippedAt = DateTimeOffset.Now
        });
    }

    private async Task WatchdogLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(1000, ct).ConfigureAwait(false);
                if (_isExitPromptActive)
                    continue;
                _tickCounter++;

                AppProtectionState snapshotState;
                AppConfig cfg;
                IpGeoInfo? boundIp;
                string proxyHost;
                int proxyPort;
                DateTimeOffset graceUntil;
                DateTimeOffset lastIpCheck;

                lock (_stateLock)
                {
                    snapshotState = _state;
                    cfg = _currentConfig;
                    boundIp = _boundSafeIp;
                    proxyHost = _boundProxyHost;
                    proxyPort = _boundProxyPort;
                    graceUntil = _launchGraceUntil;
                    lastIpCheck = _lastIpCheckAt;
                }

                // 1. 冷静期每秒倒计时
                if (snapshotState == AppProtectionState.CooldownLocked)
                {
                    int remaining;
                    bool expired = false;
                    lock (_stateLock)
                    {
                        if (_state == AppProtectionState.CooldownLocked)
                        {
                            _remainingCooldownSeconds = Math.Max(0, _remainingCooldownSeconds - 1);
                            remaining = _remainingCooldownSeconds;
                            expired = remaining <= 0;
                        }
                        else
                        {
                            remaining = _remainingCooldownSeconds;
                        }
                    }

                    OnCooldownTick?.Invoke(remaining);

                    if (expired)
                    {
                        CleanExitClaudeAndLockAll(L.Get("Wd_CooldownExpiredReason"));
                        OnCooldownExpired?.Invoke();
                        continue;
                    }

                    bool hadRunningClaude;
                    lock (_stateLock) hadRunningClaude = _cooldownHadRunningClaude;

                    // 冷静期内如果原本有 Claude 运行且用户自己手动关掉了 Claude 窗口，自动回收到 LockedIdle
                    if (hadRunningClaude && _tickCounter % 2 == 0 && _processService.GetRunningClaudeProcessCount() == 0)
                    {
                        CleanExitClaudeAndLockAll(L.Get("Wd_UserClosedInCooldownReason"));
                        OnClaudeExitedCleanly?.Invoke(L.Get("Wd_UserClosedInCooldownNotify"));
                        continue;
                    }

                    // 每 3 秒异步巡检网络是否已调整好，若安全则自动恢复连接并通知
                    if (_tickCounter % 3 == 0 && Interlocked.CompareExchange(ref _recoveryProbeRunning, 1, 0) == 0)
                    {
                        _ = TryAutoRecoverFromCooldownAsync(cfg, ct);
                    }

                    continue;
                }

                // 2. 每 2 秒检查一次 Claude 进程状态
                if (_tickCounter % 2 == 0)
                {
                    if (snapshotState == AppProtectionState.RunningProtected)
                    {
                        if (DateTimeOffset.UtcNow > graceUntil)
                        {
                            int procCount = _processService.GetRunningClaudeProcessCount();
                            if (procCount == 0)
                            {
                                CleanExitClaudeAndLockAll(L.Get("Wd_ClaudeExitedReason"));
                                OnClaudeExitedCleanly?.Invoke(L.Get("Wd_ClaudeExitedNotify"));
                                continue;
                            }
                        }
                    }
                    else if (cfg.BlockUnauthorizedClaudeLaunch &&
                             snapshotState is AppProtectionState.LockedIdle or AppProtectionState.ReadyToLaunch)
                    {
                        // 常态封锁：防止用户绕过小助手直接双击 Claude Desktop 裸连
                        int unauthorizedCount = _processService.GetRunningClaudeProcessCount();
                        if (unauthorizedCount > 0)
                        {
                            _gatekeeper.LockGateAndSeverAll(L.Get("Wd_BlockUnauthGateReason"));
                            var paths = _processService.CollectObservedExecutablePaths();
                            _firewall.ApplyTrafficBlock(paths, cfg.EnableFirewallRule, cfg.EnableHostsBlock);
                            int killed = _processService.KillAllClaudeProcesses();

                            var msg = L.Format("Wd_BlockUnauthNotify", killed);
                            OnLog?.Invoke($"🛡️ {msg}");
                            OnUnauthorizedLaunchBlocked?.Invoke(msg);
                            continue;
                        }
                    }
                }

                // 3. 运行保护期内：每 3 秒巡检上游代理端口及 TUN/系统代理模式，每 15 秒校验出口 IP 是否变动
                if (snapshotState == AppProtectionState.RunningProtected)
                {
                    if (_tickCounter % 3 == 0)
                    {
                        var (reachable, _) = await _proxyDetector.ProbeTcpPortAsync(proxyHost, proxyPort, 1200, ct)
                            .ConfigureAwait(false);
                        if (!reachable)
                        {
                            // 二次瞬时复检（250ms 后）避免单次调度毛刺
                            await Task.Delay(250, ct).ConfigureAwait(false);
                            var (retryOk, _) = await _proxyDetector.ProbeTcpPortAsync(proxyHost, proxyPort, 1200, ct)
                                .ConfigureAwait(false);
                            if (!retryOk)
                            {
                                TriggerCircuitBreaker(L.Format("Wd_ProxyPortLost", proxyHost, proxyPort), null);
                                continue;
                            }
                        }

                        var sysProxy = _proxyDetector.ReadWindowsSystemProxy(cfg.GatekeeperPort);
                        var tunState = _proxyDetector.DetectActiveTunAdapter();
                        if (!tunState.Enabled && !sysProxy.Enabled)
                        {
                            await Task.Delay(250, ct).ConfigureAwait(false);
                            var retrySys = _proxyDetector.ReadWindowsSystemProxy(cfg.GatekeeperPort);
                            var retryTun = _proxyDetector.DetectActiveTunAdapter();
                            if (!retryTun.Enabled && !retrySys.Enabled)
                            {
                                TriggerCircuitBreaker(L.Get("Wd_TunAndSysProxyOff"), null);
                                continue;
                            }
                        }
                    }

                    if ((DateTimeOffset.UtcNow - lastIpCheck).TotalSeconds >= 15)
                    {
                        lock (_stateLock)
                        {
                            _lastIpCheckAt = DateTimeOffset.UtcNow;
                        }

                        var currentIp = await _networkCheck.FetchExitIpThroughProxyAsync(proxyHost, proxyPort, ct)
                            .ConfigureAwait(false);

                        // 再次确认仍处于 RunningProtected
                        if (State != AppProtectionState.RunningProtected)
                            continue;

                        if (currentIp == null || string.IsNullOrWhiteSpace(currentIp.Ip))
                        {
                            TriggerCircuitBreaker(L.Get("Wd_ExitIpLost"), null);
                        }
                        else if (NetworkCheckService.IsBlockedCountryCode(currentIp.CountryCode))
                        {
                            TriggerCircuitBreaker(
                                L.Format("Wd_ExitIpBlocked", currentIp.Ip, currentIp.CountryCode),
                                currentIp);
                        }
                        else if (boundIp != null && !string.Equals(currentIp.Ip, boundIp.Ip, StringComparison.OrdinalIgnoreCase))
                        {
                            TriggerCircuitBreaker(
                                L.Format("Wd_ExitIpDrifted", boundIp.Ip, boundIp.CountryCode, currentIp.Ip, currentIp.CountryCode),
                                currentIp);
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                OnLog?.Invoke(L.Format("Wd_PollException", ex.Message));
            }
        }
    }

    private async Task TryAutoRecoverFromCooldownAsync(AppConfig cfg, CancellationToken ct)
    {
        try
        {
            var probe = await _proxyDetector
                .DetectBestUpstreamProxyAsync(cfg.UpstreamProxyHost, cfg.UpstreamProxyPort, cfg.GatekeeperPort, ct)
                .ConfigureAwait(false);
            if (!probe.IsReachable || State != AppProtectionState.CooldownLocked)
                return;

            var report = await _networkCheck.RunPreFlightCheckAsync(cfg, ct).ConfigureAwait(false);
            if (!report.CanLaunch || report.ExitIpInfo == null)
                return;

            bool stillInCooldown;
            bool shouldResumeClaude;
            lock (_stateLock)
            {
                stillInCooldown = _state == AppProtectionState.CooldownLocked;
                shouldResumeClaude = _cooldownHadRunningClaude || _processService.GetRunningClaudeProcessCount() > 0;
            }

            if (!stillInCooldown)
                return;

            _gatekeeper.SetUpstreamEndpoint(report.ProxyProbe.Host, report.ProxyProbe.Port, true);

            if (shouldResumeClaude && _processService.GetRunningClaudeProcessCount() > 0)
            {
                _firewall.RemoveTrafficBlock(_processService.CollectObservedExecutablePaths(), keepForceProxyOnly: true);
                _gatekeeper.OpenGate(report.ProxyProbe.Host, report.ProxyProbe.Port);
                ResumeProtectedSessionAfterCooldown(
                    report.ExitIpInfo,
                    report.ProxyProbe.Host,
                    report.ProxyProbe.Port,
                    cfg);
                OnLog?.Invoke(L.Format("Wd_AutoRecoveredResumed", report.ExitIpInfo.Ip, report.ExitIpInfo.CountryCode));
                OnCooldownAutoRecovered?.Invoke(report, true);
            }
            else
            {
                lock (_stateLock)
                {
                    if (_state != AppProtectionState.CooldownLocked) return;
                    _remainingCooldownSeconds = 0;
                    _cooldownHadRunningClaude = false;
                    _state = AppProtectionState.ReadyToLaunch;
                }
                _systemProxy.UpdateGatekeeperState(_gatekeeper.ListeningPort, isGateOpen: false);
                OnStateChanged?.Invoke(AppProtectionState.ReadyToLaunch);
                OnLog?.Invoke(L.Format("Wd_AutoRecoveredIdle", report.ExitIpInfo.Ip, report.ExitIpInfo.CountryCode));
                OnCooldownAutoRecovered?.Invoke(report, false);
            }
        }
        catch
        {
            // Ignore probe errors during cooldown
        }
        finally
        {
            Interlocked.Exchange(ref _recoveryProbeRunning, 0);
        }
    }

    public void Dispose()
    {
        try { _loopCts?.Cancel(); } catch { }
        try { _watchdogTask?.Wait(800); } catch { }
        _loopCts?.Dispose();
        _loopCts = null;
    }
}
