using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ClaudeSafe.Localization;
using ClaudeSafe.Models;
using Microsoft.Win32;

namespace ClaudeSafe.Services;

/// <summary>
/// 命令行自检验证套件（通过 --self-test 触发）
/// </summary>
public static class SelfTestRunner
{
    public static async Task<int> RunAsync()
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        var results = new List<(string Name, bool Passed, string Detail)>();

        // 1. 测试 GatekeeperProxyServer 域名分流拦截、动态 PAC 响应、普通站点透传与毫秒级熔断切断
        results.Add(await TestGatekeeperProxyAsync().ConfigureAwait(false));

        // 2. 测试 ProxyDetectorService 端点解析、排除守门端口防环路与 6 维风控规则
        results.Add(await TestRiskEvaluationRulesAsync().ConfigureAwait(false));

        // 3. 测试 ClaudeProcessService 自动发现本机 Claude Desktop 路径
        results.Add(TestClaudeDiscovery());

        // 4. 测试 ConfigService 持久化读写与历史 IP 基线记录
        results.Add(TestConfigPersistence());

        // 5. 测试退出还原（系统代理还原、PAC 清理及 Hosts 区块无痕移除）
        results.Add(TestExitCleanupLeavesNoTrace());

        // 6. 测试多语言字典完整性与切换
        results.Add(TestLocalizationParity());

        Console.WriteLine("============================================================");
        Console.WriteLine("ClaudeSafe 自动化自检报告 (--self-test)");
        Console.WriteLine("============================================================");
        foreach (var (name, passed, detail) in results)
        {
            Console.WriteLine($"[{(passed ? "PASS" : "FAIL")}] {name}");
            Console.WriteLine($"       {detail}");
        }
        Console.WriteLine("============================================================");

        bool allPassed = results.All(r => r.Passed);
        Console.WriteLine($"总计: {results.Count(r => r.Passed)}/{results.Count} 项通过");
        return allPassed ? 0 : 1;
    }

    private static async Task<(string Name, bool Passed, string Detail)> TestGatekeeperProxyAsync()
    {
        try
        {
            // 启动本地模拟上游服务器（持续保持长连接并回显数据）
            using var mockUpstream = new TcpListener(IPAddress.Loopback, 0);
            mockUpstream.Start();
            int upstreamPort = ((IPEndPoint)mockUpstream.LocalEndpoint).Port;

            using var mockCts = new CancellationTokenSource();
            var acceptMockTask = Task.Run(async () =>
            {
                while (!mockCts.IsCancellationRequested)
                {
                    try
                    {
                        var client = await mockUpstream.AcceptTcpClientAsync(mockCts.Token).ConfigureAwait(false);
                        _ = Task.Run(async () =>
                        {
                            using (client)
                            {
                                var stream = client.GetStream();
                                var buf = new byte[1024];
                                while (!mockCts.IsCancellationRequested)
                                {
                                    int n = await stream.ReadAsync(buf, mockCts.Token).ConfigureAwait(false);
                                    if (n <= 0) break;
                                    await stream.WriteAsync(buf.AsMemory(0, n), mockCts.Token).ConfigureAwait(false);
                                }
                            }
                        }, mockCts.Token);
                    }
                    catch
                    {
                        break;
                    }
                }
            });

            using var gatekeeper = new GatekeeperProxyServer();
            gatekeeper.Start(0);
            int gatePort = gatekeeper.ListeningPort;
            if (gatePort <= 0)
                return ("GatekeeperProxyServer 守门代理核心验证", false, "未能绑定有效本地监听端口");

            gatekeeper.SetUpstreamEndpoint("127.0.0.1", upstreamPort, true);

            // A1. 锁死状态下访问 claude.ai，必须被立即拦截并返回 503
            using (var blockedClient = new TcpClient())
            {
                await blockedClient.ConnectAsync(IPAddress.Loopback, gatePort).ConfigureAwait(false);
                var s = blockedClient.GetStream();
                var reqBytes = Encoding.ASCII.GetBytes("CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n");
                await s.WriteAsync(reqBytes).ConfigureAwait(false);
                var respBuf = new byte[512];
                int n = await s.ReadAsync(respBuf).ConfigureAwait(false);
                var respText = Encoding.ASCII.GetString(respBuf, 0, n);
                if (!respText.Contains("503 Service Unavailable", StringComparison.Ordinal) ||
                    gatekeeper.BlockedRequestsCount < 1)
                {
                    return ("GatekeeperProxyServer 守门代理核心验证", false, $"锁死态未返回预期 503 拦截响应: {respText}");
                }
            }

            // A2. 验证动态 PAC 脚本输出
            using (var pacClient = new TcpClient())
            {
                await pacClient.ConnectAsync(IPAddress.Loopback, gatePort).ConfigureAwait(false);
                var s = pacClient.GetStream();
                var pacReq = Encoding.ASCII.GetBytes("GET /pac.js?state=locked&ts=123 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
                await s.WriteAsync(pacReq).ConfigureAwait(false);
                using var ms = new MemoryStream();
                var respBuf = new byte[2048];
                int n;
                while ((n = await s.ReadAsync(respBuf).ConfigureAwait(false)) > 0)
                {
                    ms.Write(respBuf, 0, n);
                }
                var pacText = Encoding.UTF8.GetString(ms.ToArray());
                if (!pacText.Contains("application/x-ns-proxy-autoconfig", StringComparison.Ordinal) ||
                    !pacText.Contains($"PROXY 127.0.0.1:{gatePort}", StringComparison.Ordinal) ||
                    !pacText.Contains($"PROXY 127.0.0.1:{upstreamPort}; DIRECT", StringComparison.Ordinal))
                {
                    return ("GatekeeperProxyServer 守门代理核心验证", false, $"PAC 脚本内容不符合预期: {pacText}");
                }
            }

            // A3. 锁死状态下访问非 Claude 普通网站，必须正常透传至上游代理
            using (var normalClient = new TcpClient())
            {
                await normalClient.ConnectAsync(IPAddress.Loopback, gatePort).ConfigureAwait(false);
                var s = normalClient.GetStream();
                var reqBytes = Encoding.ASCII.GetBytes("CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n");
                await s.WriteAsync(reqBytes).ConfigureAwait(false);
                var respBuf = new byte[512];
                int n = await s.ReadAsync(respBuf).ConfigureAwait(false);
                var respText = Encoding.ASCII.GetString(respBuf, 0, n);
                if (!respText.Contains("CONNECT www.google.com:443", StringComparison.Ordinal))
                {
                    return ("GatekeeperProxyServer 守门代理核心验证", false, $"锁死态误拦截了普通网站: {respText}");
                }
            }

            // A4. 验证域名/IP 识别准确性
            if (!GatekeeperProxyServer.IsClaudeOrAnthropicTarget("claude.ai") ||
                !GatekeeperProxyServer.IsClaudeOrAnthropicTarget("api.anthropic.com") ||
                !GatekeeperProxyServer.IsClaudeOrAnthropicTarget("160.79.104.5") ||
                GatekeeperProxyServer.IsClaudeOrAnthropicTarget("www.google.com"))
            {
                return ("GatekeeperProxyServer 守门代理核心验证", false, "Claude 域名或 Anthropic IP 段匹配逻辑有误");
            }

            // A5. 验证 3P 临时解锁（ManualBypass）放行与 PAC 放开
            gatekeeper.SetManualBypass(true);
            var bypassPac = gatekeeper.BuildPacScript();
            if (!gatekeeper.IsManualBypass || bypassPac.Contains($"PROXY 127.0.0.1:{gatePort}", StringComparison.Ordinal))
            {
                return ("GatekeeperProxyServer 守门代理核心验证", false, "3P 临时解锁 PAC 放行状态有误");
            }
            gatekeeper.SetManualBypass(false);

            // B. 开启阀门并建立长连接转发，再触发毫秒级熔断切断
            gatekeeper.OpenGate("127.0.0.1", upstreamPort);
            using var activeClient = new TcpClient();
            await activeClient.ConnectAsync(IPAddress.Loopback, gatePort).ConfigureAwait(false);
            var activeStream = activeClient.GetStream();
            var msgBytes = Encoding.ASCII.GetBytes("CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n");
            await activeStream.WriteAsync(msgBytes).ConfigureAwait(false);

            var echoBuf = new byte[256];
            int echoLen = await activeStream.ReadAsync(echoBuf).ConfigureAwait(false);
            var echoText = Encoding.ASCII.GetString(echoBuf, 0, echoLen);
            if (!echoText.Contains("CONNECT claude.ai:443", StringComparison.Ordinal))
            {
                return ("GatekeeperProxyServer 守门代理核心验证", false, "阀门开启后未能正常转发到上游服务");
            }

            if (gatekeeper.ActiveConnectionsCount != 1)
            {
                return ("GatekeeperProxyServer 守门代理核心验证", false, $"活跃连接计数异常: {gatekeeper.ActiveConnectionsCount}");
            }

            // 触发毫秒级熔断
            var sw = Stopwatch.StartNew();
            int severed = gatekeeper.LockGateAndSeverAll("自测断流熔断");
            sw.Stop();

            if (severed < 1 || gatekeeper.IsGateOpen || gatekeeper.ActiveConnectionsCount != 0)
            {
                return ("GatekeeperProxyServer 守门代理核心验证", false, $"熔断状态异常 severed={severed}, isOpen={gatekeeper.IsGateOpen}");
            }

            // 验证旧长连接已被立即切断（读取应立刻返回 0 或抛出 IOException）
            using var postCts = new CancellationTokenSource(500);
            bool disconnected = false;
            try
            {
                int postRead = await activeStream.ReadAsync(echoBuf, postCts.Token).ConfigureAwait(false);
                disconnected = postRead == 0;
            }
            catch
            {
                disconnected = true;
            }

            mockCts.Cancel();
            if (!disconnected)
            {
                return ("GatekeeperProxyServer 守门代理核心验证", false, "熔断后旧 TCP 长连接未被及时切断");
            }

            return ("GatekeeperProxyServer 守门代理核心验证", true,
                $"端口={gatePort}，PAC 脚本、锁死拦截 claude.ai (503)、普通站点透传、以及 {sw.ElapsedMilliseconds}ms 熔断切断全部通过");
        }
        catch (Exception ex)
        {
            return ("GatekeeperProxyServer 守门代理核心验证", false, $"异常: {ex.Message}");
        }
    }

    private static async Task<(string Name, bool Passed, string Detail)> TestRiskEvaluationRulesAsync()
    {
        try
        {
            var (h1, p1) = ProxyDetectorService.ParseProxyEndpoint("http=127.0.0.1:7897;https=127.0.0.1:7897");
            if (h1 != "127.0.0.1" || p1 != 7897)
                return ("代理探测与 6 维风控规则引擎验证", false, $"ProxyServer 解析异常: {h1}:{p1}");

            var detector = new ProxyDetectorService();

            // 验证排除守门端口防环路死锁
            using (var dummyGate = new TcpListener(IPAddress.Loopback, 0))
            {
                dummyGate.Start();
                int dummyGatePort = ((IPEndPoint)dummyGate.LocalEndpoint).Port;
                var probe = await detector.DetectBestUpstreamProxyAsync("127.0.0.1", dummyGatePort, dummyGatePort)
                    .ConfigureAwait(false);
                if (probe.IsReachable && probe.Port == dummyGatePort)
                {
                    return ("代理探测与 6 维风控规则引擎验证", false, $"未能排除守门端口 {dummyGatePort}，可能造成回环死锁");
                }
            }

            var checker = new NetworkCheckService(detector);
            var proxyTunOk = new ProxyProbeResult
            {
                Host = "127.0.0.1",
                Port = 7890,
                IsReachable = true,
                LatencyMs = 12,
                TunModeEnabled = true,
                TunAdapterName = "Mihomo"
            };

            // Case 1: CN / HK 高危地区阻断
            var cnGeo = new IpGeoInfo { Ip = "114.114.114.114", Country = "China", CountryCode = "CN", Isp = "China Telecom" };
            var cnItems = checker.EvaluateRiskItems(proxyTunOk, cnGeo, true, "CN", new AppConfig());
            if (cnItems.First(x => x.Id == "exit_region").RiskLevel != RiskLevel.Danger ||
                cnItems.First(x => x.Id == "anthropic_conn").RiskLevel != RiskLevel.Danger)
            {
                return ("代理探测与 6 维风控规则引擎验证", false, "未能阻断 CN 地区 IP 与分流泄漏");
            }

            var hkGeo = new IpGeoInfo { Ip = "1.1.1.2", Country = "Hong Kong", CountryCode = "HK", Isp = "HKBN" };
            var hkItems = checker.EvaluateRiskItems(proxyTunOk, hkGeo, true, "HK", new AppConfig());
            if (hkItems.First(x => x.Id == "exit_region").RiskLevel != RiskLevel.Danger)
            {
                return ("代理探测与 6 维风控规则引擎验证", false, "未能阻断 HK 地区 IP");
            }

            // Case 2: 美国 Vultr 机房 IP + 上次安全节点为日本（跨国漂移 Warning + 机房 Warning + TUN Safe）
            var usVultr = new IpGeoInfo
            {
                Ip = "45.32.10.20",
                Country = "United States",
                CountryCode = "US",
                Isp = "Vultr Holdings, LLC",
                Asn = "AS20473",
                IsHosting = true
            };
            var cfgWithJp = new AppConfig
            {
                LastSafeIpRecord = new HistoricalIpRecord
                {
                    Ip = "203.0.113.10",
                    Country = "Japan",
                    CountryCode = "JP",
                    Asn = "AS2516"
                }
            };
            var usItems = checker.EvaluateRiskItems(proxyTunOk, usVultr, true, "US", cfgWithJp);
            if (usItems.First(x => x.Id == "proxy_channel").RiskLevel != RiskLevel.Safe ||
                usItems.First(x => x.Id == "exit_region").RiskLevel != RiskLevel.Safe ||
                usItems.First(x => x.Id == "ip_purity").RiskLevel != RiskLevel.Warning ||
                usItems.First(x => x.Id == "ip_drift").RiskLevel != RiskLevel.Warning)
            {
                return ("代理探测与 6 维风控规则引擎验证", false, "TUN 安全态、机房 IP 或跨国 IP 漂移警告规则未触发");
            }

            // Case 3: 美国节点但 Anthropic 分流返回 CN -> 必须 Danger
            var leakItems = checker.EvaluateRiskItems(proxyTunOk, usVultr, true, "CN", new AppConfig());
            if (leakItems.First(x => x.Id == "anthropic_conn").RiskLevel != RiskLevel.Danger)
            {
                return ("代理探测与 6 维风控规则引擎验证", false, "Anthropic 分流泄漏至 CN 未触发高危阻断");
            }

            if (usItems.Any(x => string.IsNullOrWhiteSpace(x.ShortTitle) || string.IsNullOrWhiteSpace(x.ShortStatus)))
            {
                return ("代理探测与 6 维风控规则引擎验证", false, "存在未填充 ShortTitle/ShortStatus 的检测项");
            }

            // Case 4: 未开 TUN 仅开系统代理 -> proxy_channel 必须 Warning（提示建议开启 TUN）
            var proxySysOnly = new ProxyProbeResult
            {
                Host = "127.0.0.1",
                Port = 7890,
                IsReachable = true,
                LatencyMs = 12,
                TunModeEnabled = false,
                SystemProxyEnabled = true
            };
            var sysOnlyItems = checker.EvaluateRiskItems(proxySysOnly, usVultr, true, "US", new AppConfig());
            if (sysOnlyItems.First(x => x.Id == "proxy_channel").RiskLevel != RiskLevel.Warning)
            {
                return ("代理探测与 6 维风控规则引擎验证", false, "仅开启系统代理（未开 TUN）时未触发黄色警告");
            }

            // Case 5: TUN 与系统代理均未开启（即便端口可达） -> proxy_channel 必须 Danger（阻止启动）
            var proxyNoMode = new ProxyProbeResult
            {
                Host = "127.0.0.1",
                Port = 7890,
                IsReachable = true,
                LatencyMs = 12,
                TunModeEnabled = false,
                SystemProxyEnabled = false
            };
            var noModeItems = checker.EvaluateRiskItems(proxyNoMode, usVultr, true, "US", new AppConfig());
            if (noModeItems.First(x => x.Id == "proxy_channel").RiskLevel != RiskLevel.Danger)
            {
                return ("代理探测与 6 维风控规则引擎验证", false, "TUN 与系统代理均未开启时未触发红色高危阻断");
            }

            // Case 6: 游戏加速器运行中 -> sys_env 必须 Warning
            var proxyWithAccelerator = new ProxyProbeResult
            {
                Host = "127.0.0.1",
                Port = 7890,
                IsReachable = true,
                LatencyMs = 12,
                TunModeEnabled = true,
                TunAdapterName = "Mihomo",
                RunningAccelerators = new List<string> { "雷神加速器" }
            };
            var accelItems = checker.EvaluateRiskItems(proxyWithAccelerator, usVultr, true, "US", new AppConfig());
            if (accelItems.First(x => x.Id == "sys_env").RiskLevel != RiskLevel.Warning)
            {
                return ("代理探测与 6 维风控规则引擎验证", false, "检测到游戏加速器运行时未触发黄色警告");
            }

            // Case 7: 无代理（梯子关闭）状态：并发探测耗时应极短，且所有风险项均能正常生成
            var offlineSw = Stopwatch.StartNew();
            var offlineProbe = await detector.DetectBestUpstreamProxyAsync("127.0.0.1", 59998, 59997)
                .ConfigureAwait(false);
            offlineSw.Stop();
            var offlineItems = checker.EvaluateRiskItems(
                new ProxyProbeResult { Host = "127.0.0.1", Port = 59998, IsReachable = false },
                null,
                false,
                null,
                new AppConfig());
            if (!offlineItems.Any(x => x.IsIssue) || offlineItems.Any(x => string.IsNullOrWhiteSpace(x.DisplayShortTitle)))
            {
                return ("代理探测与 6 维风控规则引擎验证", false, "无代理状态下风险项生成异常");
            }

            return ("代理探测与 6 维风控规则引擎验证", true,
                $"CN/HK 拦截、TUN/系统代理三级风控、加速器冲突提醒、机房 ASN、跨国漂移、分流泄漏及无代理探测({offlineSw.ElapsedMilliseconds}ms)全部通过");
        }
        catch (Exception ex)
        {
            return ("代理探测与 6 维风控规则引擎验证", false, $"异常: {ex.Message}");
        }
    }

    private static (string Name, bool Passed, string Detail) TestClaudeDiscovery()
    {
        try
        {
            var svc = new ClaudeProcessService();
            var candidates = svc.DiscoverAllClaudeExecutableCandidates();
            var msixReal = svc.DiscoverMsixRealExecutables();
            var primary = svc.DiscoverClaudeExecutable();
            return ("ClaudeProcessService 路径发现验证", !string.IsNullOrWhiteSpace(primary),
                candidates.Count > 0
                    ? $"发现 {candidates.Count} 个启动路径、{msixReal.Count} 个 MSIX 真实核心程序，首选: {primary}"
                    : "未在本机发现 Claude Desktop 可执行文件");
        }
        catch (Exception ex)
        {
            return ("ClaudeProcessService 路径发现验证", false, $"异常: {ex.Message}");
        }
    }

    private static (string Name, bool Passed, string Detail) TestConfigPersistence()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"claudesafe_test_{Guid.NewGuid():N}.json");
        try
        {
            var svc = new ConfigService(tempFile);
            var cfg = svc.Load();
            cfg.UpstreamProxyPort = 7897;
            cfg.GatekeeperPort = 17899;
            svc.RecordSafeLaunchIp(cfg, new IpGeoInfo
            {
                Ip = "198.51.100.42",
                CountryCode = "JP",
                Country = "Japan",
                City = "Tokyo",
                Asn = "AS2516",
                Isp = "KDDI"
            });

            var reloadedSvc = new ConfigService(tempFile);
            var reloaded = reloadedSvc.Load();
            bool ok = reloaded.UpstreamProxyPort == 7897 &&
                      reloaded.GatekeeperPort == 17899 &&
                      reloaded.LastSafeIpRecord?.Ip == "198.51.100.42" &&
                      reloaded.IpHistory.Count == 1;

            return ("ConfigService 持久化与历史 IP 记录验证", ok,
                ok ? $"配置读写及历史基线 IP ({reloaded.LastSafeIpRecord?.Ip}) 校验通过" : "重读配置字段不匹配");
        }
        catch (Exception ex)
        {
            return ("ConfigService 持久化与历史 IP 记录验证", false, $"异常: {ex.Message}");
        }
        finally
        {
            try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
        }
    }

    private static (string Name, bool Passed, string Detail) TestExitCleanupLeavesNoTrace()
    {
        var tempBackup = Path.Combine(Path.GetTempPath(), $"claudesafe_proxy_bak_{Guid.NewGuid():N}.json");
        var tempHosts = Path.Combine(Path.GetTempPath(), $"claudesafe_hosts_{Guid.NewGuid():N}.txt");
        try
        {
            // A. 验证 Hosts 写入与退出剥离无残留
            const string originalHosts = "127.0.0.1 custom-dev.local\r\n";
            File.WriteAllText(tempHosts, originalHosts, Encoding.UTF8);
            FirewallManagerService.WriteHostsBlockSectionToFile(tempHosts);
            var blockedContent = File.ReadAllText(tempHosts, Encoding.UTF8);
            if (!blockedContent.Contains("# BEGIN CLAUDESAFE BLOCK", StringComparison.Ordinal) ||
                !blockedContent.Contains("0.0.0.0 claude.ai", StringComparison.Ordinal))
            {
                return ("退出无痕还原验证 (代理/PAC/Hosts)", false, "Hosts 测试区块写入失败");
            }

            if (!FirewallManagerService.RemoveHostsBlockSectionFromFile(tempHosts))
            {
                return ("退出无痕还原验证 (代理/PAC/Hosts)", false, "Hosts 测试区块移除返回 false");
            }

            var restoredHosts = File.ReadAllText(tempHosts, Encoding.UTF8);
            if (!string.Equals(restoredHosts.Trim(), "127.0.0.1 custom-dev.local", StringComparison.Ordinal) ||
                restoredHosts.Contains("CLAUDESAFE", StringComparison.Ordinal) ||
                restoredHosts.Contains("claude.ai", StringComparison.Ordinal))
            {
                return ("退出无痕还原验证 (代理/PAC/Hosts)", false, $"Hosts 移除后仍有残留: {restoredHosts}");
            }

            // 空 Hosts 场景：剥离后应彻底为空
            var emptyStripped = FirewallManagerService.StripHostsBlockSection(
                "# BEGIN CLAUDESAFE BLOCK\r\n0.0.0.0 claude.ai\r\n# END CLAUDESAFE BLOCK\r\n");
            if (!string.IsNullOrEmpty(emptyStripped))
            {
                return ("退出无痕还原验证 (代理/PAC/Hosts)", false, "空 Hosts 剥离后仍有空白残留");
            }

            // B. 验证 SystemProxyService 备份、PAC 写入及无痕恢复（包含 gatekeeperPort=0 的跨会话兜底清理）
            const string subKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
            string? beforePac;
            object? beforeEnable;
            string? beforeServer;
            using (var key = Registry.CurrentUser.OpenSubKey(subKey, writable: false))
            {
                beforePac = key?.GetValue("AutoConfigURL")?.ToString();
                beforeEnable = key?.GetValue("ProxyEnable");
                beforeServer = key?.GetValue("ProxyServer")?.ToString();
            }

            var proxySvc = new SystemProxyService(tempBackup);
            var applyRes = proxySvc.CaptureBackupAndApplyGatekeeper(59997, isGateOpen: false);
            if (!applyRes.Success || !File.Exists(tempBackup))
            {
                return ("退出无痕还原验证 (代理/PAC/Hosts)", false, $"系统代理接管或备份失败: {applyRes.Message}");
            }

            // 以 gatekeeperPort=0 验证基于 /pac.js?state= 的通用残留清理
            var restoreRes = new SystemProxyService(tempBackup).RestoreSystemProxyOnExit(0);
            if (!restoreRes.Success || File.Exists(tempBackup))
            {
                return ("退出无痕还原验证 (代理/PAC/Hosts)", false, $"系统代理恢复或清理备份文件失败: {restoreRes.Message}");
            }

            using (var keyAfter = Registry.CurrentUser.OpenSubKey(subKey, writable: false))
            {
                var afterPac = keyAfter?.GetValue("AutoConfigURL")?.ToString();
                var afterEnable = keyAfter?.GetValue("ProxyEnable");
                var afterServer = keyAfter?.GetValue("ProxyServer")?.ToString();
                if (!string.Equals(beforePac, afterPac, StringComparison.Ordinal) ||
                    !Equals(beforeEnable, afterEnable) ||
                    !string.Equals(beforeServer, afterServer, StringComparison.Ordinal))
                {
                    return ("退出无痕还原验证 (代理/PAC/Hosts)", false, "注册表系统代理设置未完全还原至测试前状态");
                }
            }

            return ("退出无痕还原验证 (代理/PAC/Hosts)", true,
                "Hosts 区块无痕剥离、注册表代理/PAC 还原及备份文件清理全部校验通过");
        }
        catch (Exception ex)
        {
            return ("退出无痕还原验证 (代理/PAC/Hosts)", false, $"异常: {ex.Message}");
        }
        finally
        {
            try { if (File.Exists(tempBackup)) File.Delete(tempBackup); } catch { }
            try { if (File.Exists(tempHosts)) File.Delete(tempHosts); } catch { }
        }
    }

    private static (string Name, bool Passed, string Detail) TestLocalizationParity()
    {
        var previous = L.SelectedSetting;
        try
        {
            var (isValid, missingInEn, missingInZh) = L.ValidateDictionaries();
            if (!isValid)
            {
                return ("多语言字典完整性与切换验证", false,
                    $"字典键不匹配: MissingInEn=[{string.Join(", ", missingInEn)}], MissingInZh=[{string.Join(", ", missingInZh)}]");
            }

            L.SetLanguage(L.ZhCN, notify: false);
            var zhTitle = L.Get("Settings_Title");
            L.SetLanguage(L.EnUS, notify: false);
            var enTitle = L.Get("Settings_Title");

            if (zhTitle != "设置" || enTitle != "Settings")
            {
                return ("多语言字典完整性与切换验证", false,
                    $"语言切换结果异常: zh={zhTitle}, en={enTitle}");
            }

            return ("多语言字典完整性与切换验证", true,
                $"zh-CN 与 en-US 字典键完全一致，运行时切换校验通过");
        }
        finally
        {
            L.SetLanguage(previous, notify: false);
        }
    }
}
