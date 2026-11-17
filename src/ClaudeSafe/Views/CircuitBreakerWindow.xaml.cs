using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using ClaudeSafe.Services;

namespace ClaudeSafe.Views;

public enum CircuitBreakerAction
{
    EnterCooldown,
    KillClaudeProcesses
}

public partial class CircuitBreakerWindow : Window
{
    private readonly DispatcherTimer _countdownTimer;
    private int _secondsRemaining = 5;
    private bool _decided;

    public CircuitBreakerAction SelectedAction { get; private set; } = CircuitBreakerAction.KillClaudeProcesses;

    public CircuitBreakerWindow(CircuitBreakerTrippedEventArgs args, int cooldownDurationSeconds = 300)
    {
        InitializeComponent();

        ReasonText.Text = args.Reason;
        ExpectedIpText.Text = args.ExpectedIp != null
            ? $"{args.ExpectedIp.Ip} ({args.ExpectedIp.CountryCode})"
            : "暂无基线";

        var currentIpDisplay = args.CurrentIp != null && !string.IsNullOrWhiteSpace(args.CurrentIp.Ip)
            ? $"{args.CurrentIp.Ip} ({args.CurrentIp.CountryCode})"
            : "无出口";
        CurrentStatusText.Text = $"{currentIpDisplay} · 切断 {args.SeveredConnections} 连接";

        int mins = Math.Max(1, cooldownDurationSeconds / 60);
        BtnCooldownLock.Content = $"取消（熔断保护 {mins} 分钟）";
        BehaviorDescText.Text =
            $"• 点击【确定】（或倒计时结束）：立即强杀并退出 Claude Desktop。\n" +
            $"• 点击【取消】：保持断网并进入 {mins} 分钟熔断保护，检测到网络调整好后自动恢复连接并发送系统通知。";

        UpdateCountdownUi();

        _countdownTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _countdownTimer.Tick += CountdownTimer_Tick;
        _countdownTimer.Start();
    }

    private void CountdownTimer_Tick(object? sender, EventArgs e)
    {
        if (_decided)
            return;

        _secondsRemaining--;
        if (_secondsRemaining <= 0)
        {
            _decided = true;
            _countdownTimer.Stop();
            SelectedAction = CircuitBreakerAction.KillClaudeProcesses;
            DialogResult = true;
            Close();
            return;
        }

        UpdateCountdownUi();
    }

    private void UpdateCountdownUi()
    {
        CountdownSublineText.Text = $"已立即切断网络连接 · {_secondsRemaining} 秒后将自动退出 Claude";
        BtnKillClaude.Content = $"确定（立即退出 · {_secondsRemaining}s）";
    }

    private void Border_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed)
        {
            DragMove();
        }
    }

    private void BtnCooldownLock_Click(object sender, RoutedEventArgs e)
    {
        _decided = true;
        _countdownTimer.Stop();
        SelectedAction = CircuitBreakerAction.EnterCooldown;
        DialogResult = true;
        Close();
    }

    private void BtnKillClaude_Click(object sender, RoutedEventArgs e)
    {
        _decided = true;
        _countdownTimer.Stop();
        SelectedAction = CircuitBreakerAction.KillClaudeProcesses;
        DialogResult = true;
        Close();
    }

    protected override void OnClosed(EventArgs e)
    {
        _countdownTimer.Stop();
        base.OnClosed(e);
    }
}
