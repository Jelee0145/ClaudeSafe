using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClaudeSafe.Services;

/// <summary>
/// 内置本地守门代理：接管 Claude Desktop 与浏览器 Claude 流量，支持动态 PAC 分流与毫秒级物理断流
/// </summary>
public sealed class GatekeeperProxyServer : IDisposable
{
    private sealed class ActiveConnection : IDisposable
    {
        public long Id { get; init; }
        public bool IsClaudeTarget { get; init; }
        public required TcpClient Client { get; init; }
        public required TcpClient Upstream { get; init; }
        public required CancellationTokenSource Cts { get; init; }

        public void Dispose()
        {
            try { Cts.Cancel(); } catch { }
            try { Client.Close(); } catch { }
            try { Upstream.Close(); } catch { }
            try { Client.Dispose(); } catch { }
            try { Upstream.Dispose(); } catch { }
        }
    }

    private sealed record RequestMeta(string Method, string RawTarget, string TargetHost, bool IsPacRequest);

    private readonly object _gateStateLock = new();
    private readonly ConcurrentDictionary<long, ActiveConnection> _activeConnections = new();

    private TcpListener? _listener;
    private CancellationTokenSource? _serverCts;
    private Task? _acceptLoopTask;
    private long _nextConnId;
    private long _totalBytesTransferred;
    private long _blockedRequestsCount;
    private volatile bool _isGateOpen;
    private volatile bool _isManualBypass;
    private string _upstreamHost = "127.0.0.1";
    private int _upstreamPort = 7890;
    private bool _upstreamReachable;

    public bool IsRunning { get; private set; }
    public int ListeningPort { get; private set; }
    public bool IsGateOpen => _isGateOpen;
    public bool IsManualBypass => _isManualBypass;
    public int ActiveConnectionsCount => _activeConnections.Count;
    public long TotalBytesTransferred => Interlocked.Read(ref _totalBytesTransferred);
    public long BlockedRequestsCount => Interlocked.Read(ref _blockedRequestsCount);

    public event Action<string>? OnTrafficLog;
    public event Action? OnStatsChanged;

    public void Start(int listenPort)
    {
        if (IsRunning)
            return;

        _listener = new TcpListener(IPAddress.Loopback, listenPort);
        _listener.Start();
        ListeningPort = ((IPEndPoint)_listener.LocalEndpoint).Port;

        _serverCts = new CancellationTokenSource();
        IsRunning = true;
        _acceptLoopTask = Task.Run(() => AcceptLoopAsync(_serverCts.Token));
        OnTrafficLog?.Invoke($"守门代理已在 127.0.0.1:{ListeningPort} 启动（初始状态：Claude 阀门锁死，PAC 已就绪）");
        OnStatsChanged?.Invoke();
    }

    public void SetUpstreamEndpoint(string upstreamHost, int upstreamPort, bool isReachable)
    {
        lock (_gateStateLock)
        {
            _upstreamHost = string.IsNullOrWhiteSpace(upstreamHost) ? "127.0.0.1" : upstreamHost;
            _upstreamPort = upstreamPort > 0 ? upstreamPort : 7890;
            _upstreamReachable = isReachable;
        }
    }

    public void SetManualBypass(bool enabled)
    {
        lock (_gateStateLock)
        {
            _isManualBypass = enabled;
        }
        OnStatsChanged?.Invoke();
    }

    public void OpenGate(string upstreamHost, int upstreamPort)
    {
        lock (_gateStateLock)
        {
            _upstreamHost = string.IsNullOrWhiteSpace(upstreamHost) ? "127.0.0.1" : upstreamHost;
            _upstreamPort = upstreamPort > 0 ? upstreamPort : 7890;
            _upstreamReachable = true;
            _isManualBypass = false;
            _isGateOpen = true;
        }

        OnTrafficLog?.Invoke($"守门代理阀门已开启 → 上游通道 {_upstreamHost}:{_upstreamPort}");
        OnStatsChanged?.Invoke();
    }

    /// <summary>
    /// 毫秒级锁死 Claude 阀门并强行切断所有已建立的 Claude/Anthropic 活跃连接
    /// </summary>
    public int LockGateAndSeverAll(string reason)
    {
        lock (_gateStateLock)
        {
            _isGateOpen = false;
        }

        int severedCount = 0;
        foreach (var kvp in _activeConnections)
        {
            if (kvp.Value.IsClaudeTarget && _activeConnections.TryRemove(kvp.Key, out var conn))
            {
                conn.Dispose();
                severedCount++;
            }
        }

        OnTrafficLog?.Invoke($"[熔断封锁] {reason} — 已锁死 Claude 阀门并毫秒级切断 {severedCount} 条活跃连接");
        OnStatsChanged?.Invoke();
        return severedCount;
    }

    public static bool IsClaudeOrAnthropicTarget(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return false;

        var normalized = host.Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(normalized))
            return false;

        if (normalized == "claude.ai" || normalized.EndsWith(".claude.ai", StringComparison.Ordinal) ||
            normalized == "anthropic.com" || normalized.EndsWith(".anthropic.com", StringComparison.Ordinal) ||
            normalized == "claude.com" || normalized.EndsWith(".claude.com", StringComparison.Ordinal))
        {
            return true;
        }

        // 匹配 Anthropic 官方 AS399358 网段 160.79.104.0/21 (160.79.104.0 ~ 160.79.111.255)
        if (IPAddress.TryParse(normalized, out var ip) &&
            ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            if (bytes[0] == 160 && bytes[1] == 79 && bytes[2] >= 104 && bytes[2] <= 111)
            {
                return true;
            }
        }

        return false;
    }

    public string BuildPacScript()
    {
        string upstreamHost;
        int upstreamPort;
        bool upstreamReachable;
        bool isManualBypass;
        lock (_gateStateLock)
        {
            upstreamHost = _upstreamHost;
            upstreamPort = _upstreamPort;
            upstreamReachable = _upstreamReachable;
            isManualBypass = _isManualBypass;
        }

        var defaultRoute = upstreamReachable
            ? $"PROXY {upstreamHost}:{upstreamPort}; DIRECT"
            : "DIRECT";

        if (isManualBypass)
        {
            return
                "function FindProxyForURL(url, host) {\n" +
                $"    return \"{defaultRoute}\";\n" +
                "}\n";
        }

        return
            "function FindProxyForURL(url, host) {\n" +
            "    host = (host || \"\").toLowerCase();\n" +
            "    if (host === \"claude.ai\" || dnsDomainIs(host, \".claude.ai\") ||\n" +
            "        host === \"anthropic.com\" || dnsDomainIs(host, \".anthropic.com\") ||\n" +
            "        host === \"claude.com\" || dnsDomainIs(host, \".claude.com\") ||\n" +
            "        /^160\\.79\\.(10[4-9]|11[01])\\./.test(host)) {\n" +
            $"        return \"PROXY 127.0.0.1:{ListeningPort}\";\n" +
            "    }\n" +
            $"    return \"{defaultRoute}\";\n" +
            "}\n";
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener != null)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                {
                    OnTrafficLog?.Invoke($"守门代理接收连接异常: {ex.Message}");
                }
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken serverCt)
    {
        client.NoDelay = true;
        var connId = Interlocked.Increment(ref _nextConnId);
        using var connCts = CancellationTokenSource.CreateLinkedTokenSource(serverCt);

        var initialBuffer = ArrayPool<byte>.Shared.Rent(8192);
        TcpClient? upstream = null;
        ActiveConnection? activeConn = null;

        try
        {
            var clientStream = client.GetStream();

            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(connCts.Token);
            readCts.CancelAfter(TimeSpan.FromSeconds(10));
            int firstBytes = await clientStream.ReadAsync(initialBuffer.AsMemory(0, initialBuffer.Length), readCts.Token)
                .ConfigureAwait(false);

            if (firstBytes <= 0)
            {
                client.Dispose();
                return;
            }

            var meta = ParseRequestMeta(initialBuffer, firstBytes);

            // 1. 响应系统 / 浏览器的动态 PAC 请求
            if (meta.IsPacRequest)
            {
                await SendPacResponseAndCloseAsync(client, clientStream).ConfigureAwait(false);
                return;
            }

            bool isClaudeTarget = IsClaudeOrAnthropicTarget(meta.TargetHost);
            string targetLabel = string.IsNullOrWhiteSpace(meta.TargetHost)
                ? $"{meta.Method} {meta.RawTarget}".Trim()
                : $"{meta.Method} {meta.TargetHost}";

            // 2. 判定守门阀门状态（仅在锁死时拦截 Claude/Anthropic，非 Claude 普通站点正常放行透传）
            string targetHost;
            int targetPort;
            bool shouldBlock = false;
            lock (_gateStateLock)
            {
                if (isClaudeTarget && !_isGateOpen && !_isManualBypass)
                {
                    shouldBlock = true;
                }

                targetHost = _upstreamHost;
                targetPort = _upstreamPort;
            }

            if (shouldBlock)
            {
                await SendBlockedResponseAndCloseAsync(client, clientStream, targetLabel).ConfigureAwait(false);
                return;
            }

            upstream = new TcpClient { NoDelay = true };
            using (var dialCts = CancellationTokenSource.CreateLinkedTokenSource(connCts.Token))
            {
                dialCts.CancelAfter(TimeSpan.FromSeconds(6));
                await upstream.ConnectAsync(targetHost, targetPort, dialCts.Token).ConfigureAwait(false);
            }

            activeConn = new ActiveConnection
            {
                Id = connId,
                IsClaudeTarget = isClaudeTarget,
                Client = client,
                Upstream = upstream,
                Cts = connCts
            };

            bool blockedBeforeRegister = false;
            lock (_gateStateLock)
            {
                if (isClaudeTarget && !_isGateOpen && !_isManualBypass)
                {
                    blockedBeforeRegister = true;
                }
                else
                {
                    _activeConnections[connId] = activeConn;
                }
            }

            if (blockedBeforeRegister)
            {
                upstream.Dispose();
                activeConn = null;
                await SendBlockedResponseAndCloseAsync(client, clientStream, targetLabel).ConfigureAwait(false);
                return;
            }

            OnStatsChanged?.Invoke();
            if (isClaudeTarget && !string.IsNullOrWhiteSpace(targetLabel))
            {
                OnTrafficLog?.Invoke($"[放行转发] {targetLabel} → {targetHost}:{targetPort}");
            }

            var upstreamStream = upstream.GetStream();
            await upstreamStream.WriteAsync(initialBuffer.AsMemory(0, firstBytes), connCts.Token).ConfigureAwait(false);
            Interlocked.Add(ref _totalBytesTransferred, firstBytes);

            var upTask = RelayAsync(clientStream, upstreamStream, connCts.Token);
            var downTask = RelayAsync(upstreamStream, clientStream, connCts.Token);

            await Task.WhenAny(upTask, downTask).ConfigureAwait(false);
            connCts.Cancel();
            try
            {
                await Task.WhenAll(upTask, downTask).ConfigureAwait(false);
            }
            catch
            {
                // 任意一侧关闭或被熔断强杀均属正常结束
            }
        }
        catch
        {
            // 连接异常或被熔断取消
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(initialBuffer);

            if (activeConn != null)
            {
                _activeConnections.TryRemove(connId, out _);
                activeConn.Dispose();
            }
            else
            {
                try { upstream?.Dispose(); } catch { }
                try { client.Dispose(); } catch { }
            }

            OnStatsChanged?.Invoke();
        }
    }

    private async Task SendPacResponseAndCloseAsync(TcpClient client, NetworkStream stream)
    {
        try
        {
            var body = BuildPacScript();
            var bodyBytes = Encoding.UTF8.GetBytes(body);
            var headers =
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\n" +
                "Cache-Control: no-store, no-cache, must-revalidate\r\n" +
                $"Content-Length: {bodyBytes.Length}\r\n" +
                "Connection: close\r\n\r\n";
            var headerBytes = Encoding.ASCII.GetBytes(headers);
            var combined = new byte[headerBytes.Length + bodyBytes.Length];
            Buffer.BlockCopy(headerBytes, 0, combined, 0, headerBytes.Length);
            Buffer.BlockCopy(bodyBytes, 0, combined, headerBytes.Length, bodyBytes.Length);

            using var writeCts = new CancellationTokenSource(1000);
            await stream.WriteAsync(combined, writeCts.Token).ConfigureAwait(false);
            await stream.FlushAsync(writeCts.Token).ConfigureAwait(false);
        }
        catch
        {
            // Ignore write errors
        }
        finally
        {
            try { client.Close(); } catch { }
            try { client.Dispose(); } catch { }
        }
    }

    private async Task SendBlockedResponseAndCloseAsync(TcpClient client, NetworkStream stream, string targetHint)
    {
        Interlocked.Increment(ref _blockedRequestsCount);
        try
        {
            const string payload =
                "HTTP/1.1 503 Service Unavailable\r\n" +
                "Content-Type: text/plain; charset=utf-8\r\n" +
                "Connection: close\r\n\r\n" +
                "Blocked by ClaudeSafe Gatekeeper: Claude/Anthropic access is locked.\r\n";
            var bytes = Encoding.ASCII.GetBytes(payload);
            using var writeCts = new CancellationTokenSource(300);
            await stream.WriteAsync(bytes, writeCts.Token).ConfigureAwait(false);
            await stream.FlushAsync(writeCts.Token).ConfigureAwait(false);
        }
        catch
        {
            // Ignore write errors
        }
        finally
        {
            try { client.Close(); } catch { }
            try { client.Dispose(); } catch { }
            var label = string.IsNullOrWhiteSpace(targetHint) ? "未知 Claude 出站请求" : targetHint;
            OnTrafficLog?.Invoke($"[已拦截] 守门阀门已锁死，拒绝连接: {label}");
            OnStatsChanged?.Invoke();
        }
    }

    private async Task RelayAsync(Stream source, Stream destination, CancellationToken ct)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(16384);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                if (read <= 0) break;

                await destination.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                Interlocked.Add(ref _totalBytesTransferred, read);
            }
        }
        catch
        {
            // Stream closed or cancelled
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static RequestMeta ParseRequestMeta(byte[] buffer, int length)
    {
        try
        {
            var previewLen = Math.Min(length, 4096);
            var text = Encoding.ASCII.GetString(buffer, 0, previewLen);
            var lines = text.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length == 0)
                return new RequestMeta(string.Empty, string.Empty, string.Empty, false);

            var firstParts = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var method = firstParts.Length >= 1 ? firstParts[0].Trim().ToUpperInvariant() : string.Empty;
            var rawTarget = firstParts.Length >= 2 ? firstParts[1].Trim() : string.Empty;

            // 判断是否为 PAC 请求: GET /pac.js... 或 GET http://127.0.0.1:PORT/pac.js...
            if (method == "GET")
            {
                if (rawTarget.StartsWith("/pac", StringComparison.OrdinalIgnoreCase))
                {
                    return new RequestMeta(method, rawTarget, "127.0.0.1", true);
                }

                if (Uri.TryCreate(rawTarget, UriKind.Absolute, out var pacUri) &&
                    (pacUri.Host == "127.0.0.1" || pacUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) &&
                    pacUri.AbsolutePath.StartsWith("/pac", StringComparison.OrdinalIgnoreCase))
                {
                    return new RequestMeta(method, rawTarget, pacUri.Host, true);
                }
            }

            var targetHost = string.Empty;
            if (method == "CONNECT")
            {
                targetHost = StripPortFromHost(rawTarget);
            }
            else if (Uri.TryCreate(rawTarget, UriKind.Absolute, out var reqUri))
            {
                targetHost = reqUri.Host;
            }

            if (string.IsNullOrWhiteSpace(targetHost))
            {
                foreach (var line in lines)
                {
                    if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                    {
                        targetHost = StripPortFromHost(line[5..].Trim());
                        break;
                    }
                }
            }

            return new RequestMeta(method, rawTarget, targetHost, false);
        }
        catch
        {
            return new RequestMeta(string.Empty, string.Empty, string.Empty, false);
        }
    }

    private static string StripPortFromHost(string hostPort)
    {
        if (string.IsNullOrWhiteSpace(hostPort))
            return string.Empty;

        var trimmed = hostPort.Trim();
        if (trimmed.StartsWith('['))
        {
            var closeBracket = trimmed.IndexOf(']');
            return closeBracket > 1 ? trimmed[1..closeBracket] : trimmed;
        }

        var colonIdx = trimmed.LastIndexOf(':');
        if (colonIdx > 0 && int.TryParse(trimmed[(colonIdx + 1)..], out _))
        {
            return trimmed[..colonIdx];
        }

        return trimmed;
    }

    public void Stop()
    {
        if (!IsRunning)
            return;

        LockGateAndSeverAll("守门代理服务停止");
        IsRunning = false;

        foreach (var kvp in _activeConnections)
        {
            if (_activeConnections.TryRemove(kvp.Key, out var conn))
            {
                conn.Dispose();
            }
        }

        try { _serverCts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        try { _acceptLoopTask?.Wait(500); } catch { }
        _serverCts?.Dispose();
        _serverCts = null;
        _listener = null;
    }

    public void Dispose()
    {
        Stop();
    }
}
