using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using ClaudeSafe.Localization;
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
            : L.Get("CB_NoBaseline");

        var currentIpDisplay = args.CurrentIp != null && !string.IsNullOrWhiteSpace(args.CurrentIp.Ip)
            ? $"{args.CurrentIp.Ip} ({args.CurrentIp.CountryCode})"
            : L.Get("CB_NoExit");
        CurrentStatusText.Text = L.Format("CB_CurrentStatusFormat", currentIpDisplay, args.SeveredConnections);

        int mins = Math.Max(1, cooldownDurationSeconds / 60);
        BtnCooldownLock.Content = L.Format("CB_BtnCooldown", mins);
        BehaviorDescText.Text = L.Format("CB_Desc", mins);

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
        CountdownSublineText.Text = L.Format("CB_Subline", _secondsRemaining);
        BtnKillClaude.Content = L.Format("CB_BtnKill", _secondsRemaining);
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
