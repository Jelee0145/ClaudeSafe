using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using ClaudeSafe.Services;

namespace ClaudeSafe;

public partial class App : Application
{
    private const string MutexName = @"Local\ClaudeSafe_SingleInstance_Mutex";
    private const string ActivateEventName = @"Local\ClaudeSafe_Activate_Event";

    private Mutex? _singleInstanceMutex;
    private bool _hasMutexHandle;
    private EventWaitHandle? _activateEvent;
    private RegisteredWaitHandle? _registeredWait;
    private MainWindow? _mainWindow;

    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int dwProcessId);

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(
                $"界面运行发生未捕获异常（已拦截防止闪退）：\n{args.Exception.Message}",
                "ClaudeSafe 异常保护",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            args.Handled = true;
        };

        if (e.Args.Any(a => string.Equals(a, "--self-test", StringComparison.OrdinalIgnoreCase)))
        {
            if (!Console.IsOutputRedirected)
            {
                AttachConsole(-1);
            }

            int exitCode = SelfTestRunner.RunAsync().GetAwaiter().GetResult();
            Environment.ExitCode = exitCode;
            Shutdown(exitCode);
            return;
        }

        if (e.Args.Any(a => string.Equals(a, "--clean-all", StringComparison.OrdinalIgnoreCase)))
        {
            bool alreadyElevatedAttempt = e.Args.Any(a => string.Equals(a, "--elevated", StringComparison.OrdinalIgnoreCase));
            var fw = new FirewallManagerService();
            int exitCode;

            if (fw.IsRunningAsAdmin())
            {
                var fwRes = fw.RemoveTrafficBlock(keepForceProxyOnly: false);
                var sysRes = new SystemProxyService().RestoreSystemProxyOnExit(0);
                exitCode = fwRes.Success && sysRes.Success ? 0 : 1;
            }
            else
            {
                var sysRes = new SystemProxyService().RestoreSystemProxyOnExit(0);
                bool fwCleanOk = !fw.HasResidualSystemBlocks() ||
                                 (!alreadyElevatedAttempt && FirewallManagerService.TryRunElevatedCleanAll());
                exitCode = sysRes.Success && fwCleanOk ? 0 : 1;
            }

            Environment.ExitCode = exitCode;
            Shutdown(exitCode);
            return;
        }

        bool waitRelaunch = e.Args.Any(a => string.Equals(a, "--wait-relaunch", StringComparison.OrdinalIgnoreCase));
        _singleInstanceMutex = new Mutex(false, MutexName);
        try
        {
            _hasMutexHandle = _singleInstanceMutex.WaitOne(waitRelaunch ? 10000 : 0, false);
        }
        catch (AbandonedMutexException)
        {
            _hasMutexHandle = true;
        }

        if (!_hasMutexHandle)
        {
            // 唤醒已在后台托盘运行的 ClaudeSafe 主窗口
            try
            {
                using var evt = EventWaitHandle.OpenExisting(ActivateEventName);
                evt.Set();
            }
            catch
            {
                MessageBox.Show(
                    "ClaudeSafe 已在系统托盘后台守护中。",
                    "ClaudeSafe",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }

            Shutdown(0);
            return;
        }

        bool startMinimized = e.Args.Any(a => string.Equals(a, "--minimized", StringComparison.OrdinalIgnoreCase));
        var mainWindow = new MainWindow(startMinimized);
        _mainWindow = mainWindow;
        MainWindow = mainWindow;
        AppDomain.CurrentDomain.ProcessExit += CurrentDomain_ProcessExit;

        _activateEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ActivateEventName);
        _registeredWait = ThreadPool.RegisterWaitForSingleObject(
            _activateEvent,
            (_, _) => Dispatcher.BeginInvoke(() => mainWindow.RestoreAndFocusWindow()),
            null,
            Timeout.Infinite,
            executeOnlyOnce: false);

        mainWindow.Show();
    }

    private void CurrentDomain_ProcessExit(object? sender, EventArgs e)
    {
        try
        {
            _mainWindow?.PerformExitCleanup(isRestartingAsAdmin: true);
        }
        catch
        {
            // Ignore cleanup errors during process exit
        }
    }

    protected override void OnSessionEnding(SessionEndingCancelEventArgs e)
    {
        base.OnSessionEnding(e);
        try
        {
            _mainWindow?.PerformExitCleanup(isRestartingAsAdmin: true);
        }
        catch
        {
            // Ignore cleanup errors during OS shutdown/logoff
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            AppDomain.CurrentDomain.ProcessExit -= CurrentDomain_ProcessExit;
            _mainWindow?.PerformExitCleanup();
        }
        catch
        {
            // Ignore cleanup errors on exit
        }

        try
        {
            _registeredWait?.Unregister(null);
            _activateEvent?.Dispose();
        }
        catch
        {
            // Ignore event cleanup
        }

        try
        {
            if (_hasMutexHandle)
            {
                _singleInstanceMutex?.ReleaseMutex();
                _hasMutexHandle = false;
            }
            _singleInstanceMutex?.Dispose();
        }
        catch
        {
            // Ignore mutex cleanup on exit
        }

        base.OnExit(e);
    }
}
