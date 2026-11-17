using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using ClaudeSafe.Models;
using ClaudeSafe.Services;
using ClaudeSafe.Views;
using WinForms = System.Windows.Forms;

namespace ClaudeSafe;

public partial class MainWindow : Window
{
    private readonly ConfigService _configService;
    private readonly ProxyDetectorService _proxyDetector;
    private readonly NetworkCheckService _networkCheck;
    private readonly GatekeeperProxyServer _gatekeeper;
    private readonly FirewallManagerService _firewall;
    private readonly ClaudeProcessService _processService;
    private readonly SystemProxyService _systemProxy;
    private readonly RuntimeWatchdogService _watchdog;

    private readonly ObservableCollection<CheckItemResult> _checkItems = new();
    private readonly ObservableCollection<CheckItemResult> _issueItems = new();
    private AppConfig _config = new();
    private PreFlightReport? _lastReport;
    private CancellationTokenSource? _checkCts;
    private WinForms.NotifyIcon? _trayIcon;
    private System.Drawing.Icon? _trayCustomIcon;
    private bool _isExplicitExit;
    private bool _isClosingOrClosed;
    private bool _isExitPromptOpen;
    private bool _isRestartingAsAdmin;
    private bool _killClaudeOnExit = true;
    private int _exitCleanupExecuted;
    private bool _isCircuitBreakerDialogOpen;

    public bool IsClosingOrClosed => _isClosingOrClosed || _isExplicitExit;
    private bool _hasShownTrayHint;
    private bool _isLaunchingOrChecking;
    private readonly bool _startMinimized;
    private DispatcherTimer? _longPressTimer;
    private Stopwatch? _longPressStopwatch;
    private bool _isLongPressingLogo;

    public MainWindow(bool startMinimized = false)
    {
        _startMinimized = startMinimized;
        InitializeComponent();

        if (_startMinimized)
        {
            ShowInTaskbar = false;
            Opacity = 0;
        }

        _configService = new ConfigService();
        _proxyDetector = new ProxyDetectorService();
        _networkCheck = new NetworkCheckService(_proxyDetector);
        _gatekeeper = new GatekeeperProxyServer();
        _firewall = new FirewallManagerService();
        _processService = new ClaudeProcessService();
        _systemProxy = new SystemProxyService();
        _watchdog = new RuntimeWatchdogService(_proxyDetector, _networkCheck, _gatekeeper, _firewall, _processService, _systemProxy);

        RiskItemsList.ItemsSource = _checkItems;
        IssueItemsList.ItemsSource = _issueItems;
        Closed += (_, _) => _isClosingOrClosed = true;

        WireEvents();
        InitializeTrayIcon();
    }

    private void WireEvents()
    {
        _gatekeeper.OnTrafficLog += msg => Dispatcher.BeginInvoke(() => AppendLog(msg));
        _gatekeeper.OnStatsChanged += () => Dispatcher.BeginInvoke(() =>
        {
            if (IsClosingOrClosed) return;
            UpdateGatekeeperStatusUi();
        });

        _watchdog.OnLog += msg => Dispatcher.BeginInvoke(() => AppendLog(msg));
        _watchdog.OnStateChanged += state => Dispatcher.BeginInvoke(() => ApplyStateUi(state));
        _watchdog.OnCooldownTick += rem => Dispatcher.BeginInvoke(() =>
        {
            if (IsClosingOrClosed) return;
            UpdateCooldownCountdownUi(rem);
        });
        _watchdog.OnCircuitBreakerTripped += args => Dispatcher.BeginInvoke(() => HandleCircuitBreakerTripped(args));

        _watchdog.OnCooldownExpired += () => Dispatcher.BeginInvoke(() =>
        {
            if (IsClosingOrClosed) return;
            ShowTrayBalloon("冷静期已结束", "超时未恢复安全网络，已自动退出 Claude 并继续封锁流量。", WinForms.ToolTipIcon.Warning);
            AppendLog("⏳ 冷静期倒计时结束，已自动清理 Claude 进程并保持封锁。");
        });

        _watchdog.OnCooldownAutoRecovered += (report, resumedRunningClaude) => Dispatcher.BeginInvoke(() =>
        {
            if (IsClosingOrClosed) return;
            _lastReport = report;
            ApplyReportToUi(report);

            if (resumedRunningClaude && report.ExitIpInfo != null)
            {
                _configService.RecordSafeLaunchIp(_config, report.ExitIpInfo);
                UpdateIpBaselineSummaryUi();
            }

            var ipLabel = report.ExitIpInfo != null
                ? $"{report.ExitIpInfo.Ip} ({report.ExitIpInfo.CountryCode})"
                : "安全节点";
            ShowTrayBalloon(
                resumedRunningClaude ? "✅ 网络已恢复，Claude 连接已自动重连" : "✅ 网络已恢复，已解除熔断锁定",
                $"当前出口：{ipLabel}。可继续安全使用 Claude。",
                WinForms.ToolTipIcon.Info);
        });

        _watchdog.OnClaudeExitedCleanly += msg => Dispatcher.BeginInvoke(() =>
        {
            if (IsClosingOrClosed || _isExitPromptOpen) return;
            ShowTrayBalloon("Claude 已退出并自动封锁", msg, WinForms.ToolTipIcon.Info);
        });

        _watchdog.OnUnauthorizedLaunchBlocked += msg => Dispatcher.BeginInvoke(() =>
        {
            if (IsClosingOrClosed || _isExitPromptOpen) return;
            ShowTrayBalloon("防裸连拦截已触发", msg, WinForms.ToolTipIcon.Error);
            RestoreAndFocusWindow();
        });
    }

    private void InitializeTrayIcon()
    {
        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("打开 ClaudeSafe 窗口", null, (_, _) => Dispatcher.BeginInvoke(RestoreAndFocusWindow));
        menu.Items.Add("封锁并安全退出 Claude", null, (_, _) => Dispatcher.BeginInvoke(() =>
        {
            _watchdog.CleanExitClaudeAndLockAll("托盘菜单手动封锁并安全退出 Claude");
        }));
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("彻底退出后台守护", null, (_, _) => Dispatcher.BeginInvoke(ExitApplicationCompletely));

        _trayCustomIcon = LoadTrayIcon();
        _trayIcon = new WinForms.NotifyIcon
        {
            Icon = _trayCustomIcon ?? System.Drawing.SystemIcons.Shield,
            Text = "ClaudeSafe - 后台安全守护中",
            Visible = true,
            ContextMenuStrip = menu
        };
        _trayIcon.DoubleClick += (_, _) => Dispatcher.BeginInvoke(RestoreAndFocusWindow);
    }

    private static System.Drawing.Icon? LoadTrayIcon()
    {
        try
        {
            var streamInfo = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/ClaudeSafe.ico"));
            if (streamInfo?.Stream != null)
            {
                using var stream = streamInfo.Stream;
                return new System.Drawing.Icon(stream, 32, 32);
            }
        }
        catch
        {
            // Fallback to system shield icon if embedded resource cannot be loaded
        }

        return null;
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        _config = _configService.Load();

        if (string.IsNullOrWhiteSpace(_config.ClaudeExecutablePath) || !File.Exists(_config.ClaudeExecutablePath))
        {
            var discovered = _processService.DiscoverClaudeExecutable();
            if (!string.IsNullOrWhiteSpace(discovered))
            {
                _config.ClaudeExecutablePath = discovered;
                _configService.Save(_config);
            }
        }

        TxtProxyHost.Text = _config.UpstreamProxyHost;
        TxtProxyPort.Text = _config.UpstreamProxyPort.ToString();
        TxtGatekeeperPort.Text = _config.GatekeeperPort.ToString();
        TxtClaudePath.Text = _config.ClaudeExecutablePath;
        ChkFirewall.IsChecked = _config.EnableFirewallRule;
        ChkHosts.IsChecked = _config.EnableHostsBlock;
        ChkBlockUnauthorized.IsChecked = _config.BlockUnauthorizedClaudeLaunch;
        ChkAutoStart.IsChecked = _configService.IsWindowsStartupEnabled();
        SelectCooldownComboItem(_config.CooldownDurationSeconds);
        UpdateIpBaselineSummaryUi();

        UpdateAdminBadgeUi();

        // 1. 启动本地守门代理（默认阀门锁死）
        try
        {
            _gatekeeper.Start(_config.GatekeeperPort);
        }
        catch (Exception ex)
        {
            AppendLog($"❌ 守门代理端口 {_config.GatekeeperPort} 绑定失败（自动分配空闲端口）: {ex.Message}");
            _gatekeeper.Start(0);
            _config.GatekeeperPort = _gatekeeper.ListeningPort;
            TxtGatekeeperPort.Text = _config.GatekeeperPort.ToString();
            _configService.Save(_config);
        }

        // 2. 启动即应用常态流量封锁（动态 PAC 仅拦截 Claude，不影响其他普通网站直连）
        _gatekeeper.SetUpstreamEndpoint(_config.UpstreamProxyHost, _config.UpstreamProxyPort, false);
        var sysProxyRes = _systemProxy.CaptureBackupAndApplyGatekeeper(_gatekeeper.ListeningPort, isGateOpen: false);
        AppendLog($"系统 PAC 接管：{sysProxyRes.Message}");

        var observedPaths = _processService.CollectObservedExecutablePaths();
        var initFw = _firewall.ApplyTrafficBlock(observedPaths, _config.EnableFirewallRule, _config.EnableHostsBlock);
        AppendLog($"初始安全封锁：{initFw.Message}");

        // 3. 若启动前已有残余未经许可的 Claude 进程，立即安全清理
        if (_processService.GetRunningClaudeProcessCount() > 0)
        {
            _watchdog.CleanExitClaudeAndLockAll("启动时发现未受保护运行的 Claude 进程，已自动清理并封锁");
        }

        // 4. 启动后台运行期看门狗
        _watchdog.Start(_config);
        ApplyStateUi(_watchdog.State);
        UpdateGatekeeperStatusUi();

        // 5. 自动执行一次初始网络预检，展示当前网络与风险清单
        await RunPreFlightCheckAsync();

        if (_startMinimized)
        {
            Hide();
            Opacity = 1;
            ShowInTaskbar = true;
        }
    }

    private void UpdateAdminBadgeUi()
    {
        bool isAdmin = _firewall.IsRunningAsAdmin();
        if (isAdmin)
        {
            BtnAdminMini.Background = CreateBrush("#E7F6EE");
            BtnAdminMini.IsEnabled = false;
            BtnAdminMini.ToolTip = "已以管理员运行，Windows 内核级禁直连防火墙与 Hosts 封锁已激活";
            AdminMiniText.Text = "管理员 · 禁直连已开启";
            AdminMiniText.Foreground = CreateBrush("#18794E");
            BtnRestartAdmin.Visibility = Visibility.Collapsed;
        }
        else
        {
            BtnAdminMini.Background = CreateBrush("#FEF3C7");
            BtnAdminMini.IsEnabled = true;
            BtnAdminMini.ToolTip = "点击以管理员身份重启，启用 Windows 内核级禁止 Claude 直连防火墙";
            AdminMiniText.Text = "标准守护 · 点此开启禁直连";
            AdminMiniText.Foreground = CreateBrush("#B45309");
            BtnRestartAdmin.Visibility = Visibility.Visible;
        }
    }

    private void UpdateGatekeeperStatusUi()
    {
        var gateStatus = _gatekeeper.IsManualBypass
            ? "3P 临时解锁"
            : (_gatekeeper.IsGateOpen ? "已放行 Claude" : "已锁死 Claude");
        GatekeeperStatsText.Text = $"守门端口 127.0.0.1:{_gatekeeper.ListeningPort} [{gateStatus}] · 已拦截 {_gatekeeper.BlockedRequestsCount} 次";
    }

    private void ApplyStateUi(AppProtectionState state)
    {
        if (IsClosingOrClosed || _isExitPromptOpen)
            return;

        CooldownPill.Visibility = state == AppProtectionState.CooldownLocked ? Visibility.Visible : Visibility.Collapsed;
        BtnSecondaryKill.Visibility = state is AppProtectionState.CooldownLocked or AppProtectionState.CircuitBreakerTripped
            ? Visibility.Visible
            : Visibility.Collapsed;

        // 重置 Logo 视觉外观
        ClaudeLogoBorder.Background = CreateBrush(state == AppProtectionState.ManualUnlocked ? "#FFFBEB" : "#FFFFFF");
        ClaudeLogoBorder.BorderBrush = CreateBrush(state == AppProtectionState.ManualUnlocked ? "#F59E0B" : "#EAE7DF");
        ClaudeLogoPath.Fill = CreateBrush(state == AppProtectionState.ManualUnlocked ? "#D97706" : "#D97757");

        switch (state)
        {
            case AppProtectionState.LockedIdle:
            case AppProtectionState.ReadyToLaunch:
                TitleDot.Fill = CreateBrush(state == AppProtectionState.ReadyToLaunch ? "#18794E" : "#D97757");
                MainStatusTitle.Text = state == AppProtectionState.ReadyToLaunch
                    ? (_lastReport?.HasWarnings == true ? "检测完成（含风险提醒）" : "网络环境安全 · 可启动")
                    : "已开启流量封锁 · 待安全启动";
                BtnPrimaryAction.Style = (Style)FindResource("PrimaryClaudeButtonStyle");
                BtnPrimaryAction.Content = "检测网络并安全启动";
                BtnPrimaryAction.IsEnabled = !_isLaunchingOrChecking;
                FooterHintText.Text = "长按 Logo 1 秒解锁 3P 模式 · 关窗后台守护";
                break;

            case AppProtectionState.Checking:
                TitleDot.Fill = CreateBrush("#D97757");
                MainStatusTitle.Text = "正在检测网络与风险项...";
                BtnPrimaryAction.Style = (Style)FindResource("PrimaryClaudeButtonStyle");
                BtnPrimaryAction.Content = "正在检测网络并准备启动...";
                BtnPrimaryAction.IsEnabled = false;
                FooterHintText.Text = "🛡️ 后台守护运行中 · 关窗不退出";
                break;

            case AppProtectionState.RunningProtected:
                TitleDot.Fill = CreateBrush("#18794E");
                MainStatusTitle.Text = "Claude 受控安全运行中";
                BtnPrimaryAction.Style = (Style)FindResource("DangerClaudeButtonStyle");
                BtnPrimaryAction.Content = "封锁并安全退出";
                BtnPrimaryAction.IsEnabled = true;
                FooterHintText.Text = "🛡️ 运行期断流熔断守护中 · 关窗不退出";
                break;

            case AppProtectionState.ManualUnlocked:
                TitleDot.Fill = CreateBrush("#D97706");
                MainStatusTitle.Text = "已临时解锁 · 3P 自由启动模式";
                BtnPrimaryAction.Style = (Style)FindResource("DangerClaudeButtonStyle");
                BtnPrimaryAction.Content = "重新上锁并恢复封锁";
                BtnPrimaryAction.IsEnabled = true;
                FooterHintText.Text = "🔓 已暂时放行 3P 模式 · 完成后请点上方恢复封锁";
                break;

            case AppProtectionState.CircuitBreakerTripped:
                TitleDot.Fill = CreateBrush("#C93B2B");
                MainStatusTitle.Text = "网络异常 · 流量已毫秒级熔断";
                BtnPrimaryAction.Style = (Style)FindResource("PrimaryClaudeButtonStyle");
                BtnPrimaryAction.Content = "重新检测并恢复连接";
                BtnPrimaryAction.IsEnabled = true;
                FooterHintText.Text = "🚨 流量已物理切断 · 关窗后台守护";
                break;

            case AppProtectionState.CooldownLocked:
                TitleDot.Fill = CreateBrush("#D97706");
                MainStatusTitle.Text = "5 分钟冷静期锁定中";
                BtnPrimaryAction.Style = (Style)FindResource("PrimaryClaudeButtonStyle");
                BtnPrimaryAction.Content = "重新检测并恢复连接";
                BtnPrimaryAction.IsEnabled = true;
                FooterHintText.Text = "⏳ 保持断网等待修复 · 关窗后台守护";
                break;
        }

        UpdateGatekeeperStatusUi();
    }

    private void UpdateCooldownCountdownUi(int remainingSeconds)
    {
        var ts = TimeSpan.FromSeconds(Math.Max(0, remainingSeconds));
        CooldownTimerText.Text = $"⏳ {ts:mm\\:ss}";
    }

    private void SaveUiConfigInputs()
    {
        _config.UpstreamProxyHost = string.IsNullOrWhiteSpace(TxtProxyHost.Text) ? "127.0.0.1" : TxtProxyHost.Text.Trim();
        if (int.TryParse(TxtProxyPort.Text.Trim(), out int upPort) && upPort is > 0 and <= 65535)
            _config.UpstreamProxyPort = upPort;
        if (int.TryParse(TxtGatekeeperPort.Text.Trim(), out int gatePort) && gatePort is > 0 and <= 65535)
            _config.GatekeeperPort = gatePort;
        _config.ClaudeExecutablePath = TxtClaudePath.Text.Trim();
        _config.EnableFirewallRule = ChkFirewall.IsChecked == true;
        _config.EnableHostsBlock = ChkHosts.IsChecked == true;
        _config.BlockUnauthorizedClaudeLaunch = ChkBlockUnauthorized.IsChecked == true;
        if (CmbCooldownMinutes.SelectedItem is ComboBoxItem cbi &&
            int.TryParse(cbi.Tag?.ToString(), out int cooldownSec) &&
            cooldownSec > 0)
        {
            _config.CooldownDurationSeconds = cooldownSec;
        }
        _configService.Save(_config);
        _watchdog.UpdateConfig(_config);
    }

    private void SelectCooldownComboItem(int seconds)
    {
        foreach (var obj in CmbCooldownMinutes.Items)
        {
            if (obj is ComboBoxItem item &&
                int.TryParse(item.Tag?.ToString(), out int val) &&
                val == seconds)
            {
                CmbCooldownMinutes.SelectedItem = item;
                return;
            }
        }
        CmbCooldownMinutes.SelectedIndex = 2; // 默认 5 分钟
    }

    private void UpdateIpBaselineSummaryUi()
    {
        if (_config.LastSafeIpRecord != null && !string.IsNullOrWhiteSpace(_config.LastSafeIpRecord.Ip))
        {
            TxtIpBaselineSummary.Text = $"IP 基线：{_config.LastSafeIpRecord.Ip} ({_config.LastSafeIpRecord.CountryCode})";
        }
        else
        {
            TxtIpBaselineSummary.Text = "IP 基线：暂无记录";
        }
    }

    private async Task<PreFlightReport?> RunPreFlightCheckAsync(bool preserveCooldownState = false)
    {
        SaveUiConfigInputs();

        _checkCts?.Cancel();
        _checkCts?.Dispose();
        _checkCts = new CancellationTokenSource();
        var ct = _checkCts.Token;

        var prevState = _watchdog.State;
        if (!preserveCooldownState && prevState != AppProtectionState.RunningProtected)
        {
            _watchdog.SetState(AppProtectionState.Checking);
        }

        BtnOnlyCheck.IsEnabled = false;
        AppendLog("🔍 开始执行 6 维网络与风控体检...");

        try
        {
            var report = await _networkCheck.RunPreFlightCheckAsync(_config, ct);
            if (ct.IsCancellationRequested) return null;

            _lastReport = report;

            // 同步更新守门代理上游通道（仅在代理可达状态变化时才刷新 PAC，避免无谓阻塞）
            _gatekeeper.SetUpstreamEndpoint(report.ProxyProbe.Host, report.ProxyProbe.Port, report.ProxyProbe.IsReachable);

            if (report.ProxyProbe.IsReachable &&
                (report.ProxyProbe.Port != _config.UpstreamProxyPort ||
                 !string.Equals(report.ProxyProbe.Host, _config.UpstreamProxyHost, StringComparison.OrdinalIgnoreCase)))
            {
                _config.UpstreamProxyHost = report.ProxyProbe.Host;
                _config.UpstreamProxyPort = report.ProxyProbe.Port;
                TxtProxyHost.Text = _config.UpstreamProxyHost;
                TxtProxyPort.Text = _config.UpstreamProxyPort.ToString();
                _configService.Save(_config);
                AppendLog($"✨ 已自动定位可用本地代理: {report.ProxyProbe.SourceDescription}");
            }

            ApplyReportToUi(report);

            AppendLog($"体检结果：{report.Summary}");

            if (!preserveCooldownState && _watchdog.State == AppProtectionState.Checking)
            {
                _watchdog.SetState(report.CanLaunch ? AppProtectionState.ReadyToLaunch : AppProtectionState.LockedIdle);
            }

            return report;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (Exception ex)
        {
            AppendLog($"❌ 体检异常: {ex.Message}");
            if (!preserveCooldownState)
                _watchdog.SetState(AppProtectionState.LockedIdle);
            return null;
        }
        finally
        {
            BtnOnlyCheck.IsEnabled = true;
        }
    }

    private void ApplyReportToUi(PreFlightReport report)
    {
        _checkItems.Clear();
        _issueItems.Clear();
        foreach (var item in report.CheckItems)
        {
            _checkItems.Add(item);
            if (item.IsIssue)
            {
                _issueItems.Add(item);
            }
        }

        bool hasItems = _checkItems.Count > 0;
        EmptyCheckHint.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
        CheckContentGrid.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;

        if (_issueItems.Count > 0)
        {
            AllSafeSummaryBox.Visibility = Visibility.Collapsed;
            IssueScrollBox.Visibility = Visibility.Visible;
        }
        else
        {
            IssueScrollBox.Visibility = Visibility.Collapsed;
            AllSafeSummaryBox.Visibility = Visibility.Visible;
            AllSafeSummaryText.Text = _firewall.IsRunningAsAdmin()
                ? "🛡️ 6 项检测全绿 · 已开启「仅走代理、禁止直连」防火墙保护"
                : "6 项检测全部安全（悬停上方胶囊可看详情）\n提示：点击顶部黄色标签提权，可额外开启防火墙禁止 Claude 直连";
        }

        if (report.ExitIpInfo != null && !string.IsNullOrWhiteSpace(report.ExitIpInfo.Ip))
        {
            IpPillText.Text = $"🌐 {report.ExitIpInfo.Ip} · {report.ExitIpInfo.CountryCode} ({report.ExitIpInfo.LatencyMs}ms)";
            IpPillBorder.Background = CreateBrush(report.CanLaunch ? "#E7F6EE" : "#FEF2F2");
            IpPillBorder.BorderBrush = CreateBrush(report.CanLaunch ? "#BBE5CE" : "#FECACA");
            IpPillText.Foreground = CreateBrush(report.CanLaunch ? "#18794E" : "#C93B2B");
        }
        else
        {
            IpPillText.Text = "🌐 未检测到可用海外代理出口";
            IpPillBorder.Background = CreateBrush("#FEF2F2");
            IpPillBorder.BorderBrush = CreateBrush("#FECACA");
            IpPillText.Foreground = CreateBrush("#C93B2B");
        }
    }

    private async void BtnPrimaryAction_Click(object sender, RoutedEventArgs e)
    {
        // 运行中 -> 一键封锁并安全退出
        if (_watchdog.State == AppProtectionState.RunningProtected)
        {
            _watchdog.CleanExitClaudeAndLockAll("用户点击【封锁并安全退出】");
            return;
        }

        // 3P 临时解锁态 -> 重新上锁并恢复安全封锁
        if (_watchdog.State == AppProtectionState.ManualUnlocked)
        {
            _watchdog.CleanExitClaudeAndLockAll("用户结束 3P 临时解锁，恢复安全封锁");
            await RunPreFlightCheckAsync();
            return;
        }

        if (_isLaunchingOrChecking)
            return;

        _isLaunchingOrChecking = true;
        try
        {
            SaveUiConfigInputs();

            // 冷静期或熔断态 -> 重新体检并恢复连接
            if (_watchdog.State is AppProtectionState.CooldownLocked or AppProtectionState.CircuitBreakerTripped)
            {
                BtnPrimaryAction.IsEnabled = false;
                BtnPrimaryAction.Content = "正在重新检测网络...";
                var recoveryReport = await RunPreFlightCheckAsync(preserveCooldownState: true);
                if (recoveryReport == null || !recoveryReport.CanLaunch || recoveryReport.ExitIpInfo == null)
                {
                    MessageBox.Show(
                        recoveryReport?.Summary ?? "当前网络仍存在高危风险，无法恢复 Claude 连接！请先修复代理后重试。",
                        "无法恢复连接",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    return;
                }

                if (!ConfirmCrossCountryDriftIfNeeded(recoveryReport))
                    return;

                var unblocked = _firewall.RemoveTrafficBlock(_processService.CollectObservedExecutablePaths(), keepForceProxyOnly: true);
                AppendLog($"解除全量封锁：{unblocked.Message}");
                _gatekeeper.OpenGate(recoveryReport.ProxyProbe.Host, recoveryReport.ProxyProbe.Port);
                _configService.RecordSafeLaunchIp(_config, recoveryReport.ExitIpInfo);
                UpdateIpBaselineSummaryUi();

                if (_processService.GetRunningClaudeProcessCount() > 0)
                {
                    _watchdog.ResumeProtectedSessionAfterCooldown(
                        recoveryReport.ExitIpInfo,
                        recoveryReport.ProxyProbe.Host,
                        recoveryReport.ProxyProbe.Port,
                        _config);
                    AppendLog("✅ 网络已恢复安全，原有 Claude 进程已恢复受控通信！");
                    return;
                }

                var relaunch = _processService.LaunchClaudeWithGatekeeper(_config.ClaudeExecutablePath, _gatekeeper.ListeningPort);
                AppendLog(relaunch.Message);
                if (relaunch.Success)
                {
                    _watchdog.BeginProtectedSession(
                        recoveryReport.ExitIpInfo,
                        recoveryReport.ProxyProbe.Host,
                        recoveryReport.ProxyProbe.Port,
                        _config);
                }
                else
                {
                    _watchdog.CleanExitClaudeAndLockAll("恢复启动 Claude 失败，回滚封锁");
                }
                return;
            }

            // 常态未启动 -> 先检测网络，安全后直接拉起 Claude Desktop
            var report = await RunPreFlightCheckAsync();
            if (report == null || !report.CanLaunch || report.ExitIpInfo == null)
            {
                // 界面中部已展开具体的红色高危阻断卡片与建议，无需弹出阻塞弹窗
                return;
            }

            if (string.IsNullOrWhiteSpace(_config.ClaudeExecutablePath) || !File.Exists(_config.ClaudeExecutablePath))
            {
                MessageBox.Show("未能自动找到 Claude Desktop，请点击右下角【设置】手动选择路径。", "缺少程序路径", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!ConfirmCrossCountryDriftIfNeeded(report))
                return;

            BtnPrimaryAction.Content = "安全通过 · 正在启动 Claude...";
            var fwUnlock = _firewall.RemoveTrafficBlock(_processService.CollectObservedExecutablePaths(), keepForceProxyOnly: true);
            AppendLog($"放行准备：{fwUnlock.Message}");

            _gatekeeper.OpenGate(report.ProxyProbe.Host, report.ProxyProbe.Port);
            _configService.RecordSafeLaunchIp(_config, report.ExitIpInfo);
            UpdateIpBaselineSummaryUi();

            var launchRes = _processService.LaunchClaudeWithGatekeeper(_config.ClaudeExecutablePath, _gatekeeper.ListeningPort);
            AppendLog(launchRes.Message);

            if (launchRes.Success)
            {
                _watchdog.BeginProtectedSession(report.ExitIpInfo, report.ProxyProbe.Host, report.ProxyProbe.Port, _config);
            }
            else
            {
                _watchdog.CleanExitClaudeAndLockAll("启动 Claude 失败，自动回滚流量封锁");
                MessageBox.Show(launchRes.Message, "启动失败", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        finally
        {
            _isLaunchingOrChecking = false;
            ApplyStateUi(_watchdog.State);
        }
    }

    private void BtnSecondaryKill_Click(object sender, RoutedEventArgs e)
    {
        _watchdog.CleanExitClaudeAndLockAll("用户手动点击【封锁并立即退出 Claude】");
    }

    private static bool ConfirmCrossCountryDriftIfNeeded(PreFlightReport report)
    {
        var driftItem = report.CheckItems.FirstOrDefault(x => x.Id == "ip_drift");
        if (driftItem != null &&
            driftItem.RiskLevel == RiskLevel.Warning &&
            driftItem.StatusText.Contains("跨国", StringComparison.Ordinal))
        {
            var answer = MessageBox.Show(
                $"{driftItem.StatusText}\n\n{driftItem.Detail}\n\n是否仍确认使用当前国家节点继续启动/恢复 Claude？",
                "跨国 IP 漂移预警",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            return answer == MessageBoxResult.Yes;
        }

        return true;
    }

    private async void BtnOnlyCheck_Click(object sender, RoutedEventArgs e)
    {
        bool keepCooldown = _watchdog.State is AppProtectionState.CooldownLocked or AppProtectionState.CircuitBreakerTripped;
        SettingsViewGrid.Visibility = Visibility.Collapsed;
        MainViewGrid.Visibility = Visibility.Visible;
        await RunPreFlightCheckAsync(preserveCooldownState: keepCooldown);
    }

    private void BtnSimulateTrip_Click(object sender, RoutedEventArgs e)
    {
        AppendLog("⚡ 触发模拟测试：模拟运行期 VPN 掉线/IP 变动...");
        _watchdog.TriggerCircuitBreaker(
            "【模拟演练】检测到上游代理意外断开 / 出口 IP 回落境内",
            new IpGeoInfo { Ip = "114.114.114.114", CountryCode = "CN", Country = "China" },
            isSimulation: true);
    }

    private void HandleCircuitBreakerTripped(CircuitBreakerTrippedEventArgs args)
    {
        if (IsClosingOrClosed || _isExitPromptOpen || _isCircuitBreakerDialogOpen)
            return;

        _isCircuitBreakerDialogOpen = true;
        try
        {
            RestoreAndFocusWindow();
            if (IsClosingOrClosed || _isExitPromptOpen)
                return;

            ShowTrayBalloon("🚨 网络异常已毫秒级熔断", $"{args.Reason}。已切断流量并保留 Claude 进程。", WinForms.ToolTipIcon.Error);

            var dialog = new CircuitBreakerWindow(args, _config.CooldownDurationSeconds);
            if (IsLoaded && IsVisible && !IsClosingOrClosed && PresentationSource.FromVisual(this) != null)
            {
                dialog.Owner = this;
            }

            bool? dialogResult;
            try
            {
                dialogResult = dialog.ShowDialog();
            }
            catch (InvalidOperationException)
            {
                return;
            }

            if (IsClosingOrClosed)
                return;

            if (dialogResult == true && dialog.SelectedAction == CircuitBreakerAction.KillClaudeProcesses)
            {
                _watchdog.CleanExitClaudeAndLockAll("网络变动熔断：5 秒倒计时结束或用户确认立即退出 Claude");
            }
            else
            {
                _watchdog.StartCooldown(_config.CooldownDurationSeconds);
            }
        }
        finally
        {
            _isCircuitBreakerDialogOpen = false;
        }
    }

    private void ClaudeLogoBorder_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (_isLaunchingOrChecking ||
            _watchdog.State is not (AppProtectionState.LockedIdle or AppProtectionState.ReadyToLaunch))
        {
            return;
        }

        _isLongPressingLogo = true;
        _longPressStopwatch = Stopwatch.StartNew();
        LogoScaleTransform.ScaleX = 0.93;
        LogoScaleTransform.ScaleY = 0.93;
        LogoProgressArc.Visibility = Visibility.Visible;
        UpdateLogoProgressArc(0.01);
        MainStatusTitle.Text = "长按解锁 3P 模式... 0%";
        Mouse.Capture(ClaudeLogoBorder);

        _longPressTimer?.Stop();
        _longPressTimer = new DispatcherTimer(DispatcherPriority.Render)
        {
            Interval = TimeSpan.FromMilliseconds(16)
        };
        _longPressTimer.Tick += LongPressTimer_Tick;
        _longPressTimer.Start();
    }

    private void ClaudeLogoBorder_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (_isLongPressingLogo)
        {
            CancelLongPressLogo();
        }
    }

    private void ClaudeLogoBorder_LostMouseCapture(object sender, MouseEventArgs e)
    {
        if (_isLongPressingLogo)
        {
            CancelLongPressLogo();
        }
    }

    private void LongPressTimer_Tick(object? sender, EventArgs e)
    {
        if (!_isLongPressingLogo || _longPressStopwatch == null)
            return;

        double elapsedMs = _longPressStopwatch.Elapsed.TotalMilliseconds;
        double progress = Math.Min(1.0, elapsedMs / 1000.0);

        LogoRotateTransform.Angle = progress * 360.0;
        UpdateLogoProgressArc(progress);
        MainStatusTitle.Text = $"长按解锁 3P 模式... {(int)(progress * 100)}%";

        if (progress >= 1.0)
        {
            CompleteLongPressUnlock();
        }
    }

    private void CompleteLongPressUnlock()
    {
        _isLongPressingLogo = false;
        _longPressTimer?.Stop();
        _longPressStopwatch?.Stop();
        if (Mouse.Captured == ClaudeLogoBorder)
            Mouse.Capture(null);

        LogoRotateTransform.Angle = 0;
        LogoScaleTransform.ScaleX = 1.0;
        LogoScaleTransform.ScaleY = 1.0;
        LogoProgressArc.Visibility = Visibility.Collapsed;

        _watchdog.EnterManualUnlockedMode("用户长按 Logo 1 秒临时解锁（允许 Claude 3P 模式自由启动）");
    }

    private void CancelLongPressLogo()
    {
        _isLongPressingLogo = false;
        _longPressTimer?.Stop();
        _longPressStopwatch?.Stop();
        if (Mouse.Captured == ClaudeLogoBorder)
            Mouse.Capture(null);

        LogoRotateTransform.Angle = 0;
        LogoScaleTransform.ScaleX = 1.0;
        LogoScaleTransform.ScaleY = 1.0;
        LogoProgressArc.Visibility = Visibility.Collapsed;
        ApplyStateUi(_watchdog.State);
    }

    private void UpdateLogoProgressArc(double progress)
    {
        const double center = 31.0;
        const double radius = 26.0;

        double clamped = Math.Clamp(progress, 0.01, 0.999);
        double angleRad = (-90.0 + clamped * 360.0) * Math.PI / 180.0;

        var startPoint = new Point(center, center - radius);
        var endPoint = new Point(
            center + radius * Math.Cos(angleRad),
            center + radius * Math.Sin(angleRad));

        var figure = new PathFigure
        {
            StartPoint = startPoint,
            IsClosed = false,
            Segments =
            {
                new ArcSegment
                {
                    Point = endPoint,
                    Size = new Size(radius, radius),
                    SweepDirection = SweepDirection.Clockwise,
                    IsLargeArc = clamped > 0.5
                }
            }
        };

        var geometry = new PathGeometry();
        geometry.Figures.Add(figure);
        LogoProgressArc.Data = geometry;
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed)
        {
            DragMove();
        }
    }

    private void BtnMinimize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void BtnHideToTray_Click(object sender, RoutedEventArgs e)
    {
        HideToTrayWithHint();
    }

    private void BtnOpenSettings_Click(object sender, RoutedEventArgs e)
    {
        UpdateIpBaselineSummaryUi();
        LogOverlayGrid.Visibility = Visibility.Collapsed;
        MainViewGrid.Visibility = Visibility.Collapsed;
        SettingsViewGrid.Visibility = Visibility.Visible;
    }

    private void BtnCloseSettings_Click(object sender, RoutedEventArgs e)
    {
        SaveUiConfigInputs();
        SettingsViewGrid.Visibility = Visibility.Collapsed;
        MainViewGrid.Visibility = Visibility.Visible;
    }

    private void BtnAdminMini_Click(object sender, RoutedEventArgs e)
    {
        if (!_firewall.IsRunningAsAdmin())
        {
            BtnRestartAdmin_Click(sender, e);
        }
    }

    private void BtnRestartAdmin_Click(object sender, RoutedEventArgs e)
    {
        if (_firewall.TryRestartAsAdmin())
        {
            _isRestartingAsAdmin = true;
            ExitApplicationCompletely();
        }
        else
        {
            AppendLog("用户取消了管理员 UAC 提权。");
        }
    }

    private void BtnBrowseClaude_Click(object sender, RoutedEventArgs e)
    {
        using var ofd = new WinForms.OpenFileDialog
        {
            Title = "选择 Claude Desktop 主程序 (claude.exe / claude-desktop-msstore.exe)",
            Filter = "Claude 可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*",
            CheckFileExists = true
        };

        if (ofd.ShowDialog() == WinForms.DialogResult.OK)
        {
            TxtClaudePath.Text = ofd.FileName;
            SaveUiConfigInputs();
            AppendLog($"已更新 Claude Desktop 路径: {ofd.FileName}");
        }
    }

    private void ProtectionOption_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        SaveUiConfigInputs();
    }

    private void ChkAutoStart_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        bool enable = ChkAutoStart.IsChecked == true;
        var res = _configService.SetWindowsStartup(enable);
        _config.LaunchOnWindowsStartup = enable && res.Success;
        _configService.Save(_config);
        AppendLog(res.Message);
        if (!res.Success)
        {
            MessageBox.Show(res.Message, "开机启动设置失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void CmbCooldownMinutes_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        SaveUiConfigInputs();
    }

    private async void BtnResetIpBaseline_Click(object sender, RoutedEventArgs e)
    {
        _configService.ClearIpBaseline(_config);
        UpdateIpBaselineSummaryUi();
        AppendLog("已重置历史登录 IP 基线，下次安全启动将记录新基线。");
        if (_watchdog.State is AppProtectionState.LockedIdle or AppProtectionState.ReadyToLaunch)
        {
            await RunPreFlightCheckAsync();
        }
    }

    private void BtnOpenLogOverlay_Click(object sender, RoutedEventArgs e)
    {
        SettingsViewGrid.Visibility = Visibility.Collapsed;
        LogOverlayGrid.Visibility = Visibility.Visible;
    }

    private void BtnCloseLogOverlay_Click(object sender, RoutedEventArgs e)
    {
        LogOverlayGrid.Visibility = Visibility.Collapsed;
        SettingsViewGrid.Visibility = Visibility.Visible;
    }

    private void BtnCopyLog_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(TxtAuditLog.Text ?? string.Empty);
        }
        catch
        {
            // Ignore clipboard errors
        }
    }

    private void BtnClearLog_Click(object sender, RoutedEventArgs e)
    {
        TxtAuditLog.Clear();
    }

    private void BtnExitCompletely_Click(object sender, RoutedEventArgs e)
    {
        ExitApplicationCompletely();
    }

    private void AppendLog(string message)
    {
        if (IsClosingOrClosed)
            return;

        var line = $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}";
        TxtAuditLog.AppendText(line);
        if (TxtAuditLog.Text.Length > 40000)
        {
            TxtAuditLog.Text = TxtAuditLog.Text[^20000..];
        }
        TxtAuditLog.ScrollToEnd();
    }

    public void RestoreAndFocusWindow()
    {
        if (IsClosingOrClosed)
            return;

        try
        {
            if (!IsVisible) Show();
            if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
            Activate();
            Topmost = true;
            Topmost = false;
            Focus();
        }
        catch (InvalidOperationException)
        {
            // Ignore window state operations after window has closed
        }
    }

    private void HideToTrayWithHint()
    {
        if (IsClosingOrClosed)
            return;

        try
        {
            Hide();
        }
        catch (InvalidOperationException)
        {
            return;
        }

        if (!_hasShownTrayHint)
        {
            _hasShownTrayHint = true;
            ShowTrayBalloon(
                "ClaudeSafe 已转入后台常驻守护",
                "防直连封锁与进程看门狗仍在运行。双击托盘图标可重新打开窗口，右键可彻底退出。",
                WinForms.ToolTipIcon.Info);
        }
    }

    private void ShowTrayBalloon(string title, string text, WinForms.ToolTipIcon icon)
    {
        try
        {
            _trayIcon?.ShowBalloonTip(3500, title, text, icon);
        }
        catch
        {
            // Ignore tray notification failures
        }
    }

    private void ExitApplicationCompletely()
    {
        if (_isClosingOrClosed || _isExplicitExit || _isExitPromptOpen)
            return;

        _killClaudeOnExit = true;

        if (!_isRestartingAsAdmin && _processService.GetRunningClaudeProcessCount() > 0)
        {
            _isExitPromptOpen = true;
            _watchdog.IsExitPromptActive = true;
            try
            {
                RestoreAndFocusWindow();

                const string promptText =
                    "Claude Desktop 正在运行，是否同步退出？\n\n• 点击【是】：同步关闭 Claude Desktop，并退出 ClaudeSafe（还原所有网络、防火墙与 Hosts 设置）。\n• 点击【否】：保留 Claude Desktop，仅退出 ClaudeSafe 并还原系统设置。\n• 点击【取消】：取消退出，继续保持后台安全守护。";
                bool canUseOwner = IsLoaded && IsVisible && !_isClosingOrClosed && PresentationSource.FromVisual(this) != null;
                var answer = canUseOwner
                    ? MessageBox.Show(this, promptText, "退出确认", MessageBoxButton.YesNoCancel, MessageBoxImage.Question)
                    : MessageBox.Show(promptText, "退出确认", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);

                if (answer == MessageBoxResult.Cancel || answer == MessageBoxResult.None)
                    return;

                _killClaudeOnExit = answer == MessageBoxResult.Yes;
            }
            finally
            {
                _isExitPromptOpen = false;
                _watchdog.IsExitPromptActive = false;
            }
        }

        _isExplicitExit = true;
        _isClosingOrClosed = true;
        PerformExitCleanup(_isRestartingAsAdmin);

        try
        {
            Close();
        }
        catch (InvalidOperationException)
        {
            // Window may already be closing or closed
        }

        Application.Current?.Shutdown(0);
    }

    public void PerformExitCleanup(bool isRestartingAsAdmin = false)
    {
        _isExplicitExit = true;
        if (Interlocked.Exchange(ref _exitCleanupExecuted, 1) != 0)
            return;

        try
        {
            _checkCts?.Cancel();
            _checkCts?.Dispose();
            _checkCts = null;
        }
        catch
        {
            // Ignore cancellation cleanup errors
        }

        _watchdog.ShutdownAndRestoreAllOnExit(
            "ClaudeSafe 退出，还原所有系统网络、防火墙与 Hosts 设置",
            allowElevateIfNeeded: !isRestartingAsAdmin,
            killClaudeProcesses: !isRestartingAsAdmin && _killClaudeOnExit);
        _watchdog.Dispose();

        var restoreRes = _systemProxy.RestoreSystemProxyOnExit(_gatekeeper.ListeningPort);
        if (Dispatcher.CheckAccess())
        {
            AppendLog(restoreRes.Message);
        }

        _gatekeeper.Dispose();

        if (_trayIcon != null)
        {
            try
            {
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
            }
            catch
            {
                // Ignore tray disposal errors during shutdown
            }
            _trayIcon = null;
        }

        if (_trayCustomIcon != null)
        {
            try
            {
                _trayCustomIcon.Dispose();
            }
            catch
            {
                // Ignore tray icon disposal errors during shutdown
            }
            _trayCustomIcon = null;
        }
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        // 关闭窗口默认最小化到托盘保持后台常驻守护；仅通过托盘菜单、设置内“彻底退出”或系统注销关机才结束进程
        if (!_isExplicitExit)
        {
            e.Cancel = true;
            HideToTrayWithHint();
            return;
        }

        PerformExitCleanup(_isRestartingAsAdmin);
    }

    private static SolidColorBrush CreateBrush(string hex)
    {
        var brush = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        brush.Freeze();
        return brush;
    }
}
