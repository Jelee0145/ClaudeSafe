# ClaudeSafe — Claude Desktop 网络安全启动器与代理泄漏防护工具

ClaudeSafe 是一款面向需要监控代理连接和网络出口环境的 Windows 用户的 **Claude Desktop 安全启动器、本地守门代理与运行期断流保护工具**，使用 .NET 8 WPF 开发。

**English:** ClaudeSafe is an open-source Windows safety launcher and local proxy gatekeeper for Claude Desktop. It checks proxy connectivity, outbound IP information and routing before launch, then monitors the connection during use and can disconnect the controlled proxy when it detects a change. Built with .NET 8 and WPF.

**Keywords:** ClaudeSafe, Claude Desktop, proxy monitoring, IP leak detection, network kill switch, Windows, WPF.

> **说明 / Disclaimer:** ClaudeSafe 是独立开源项目，并非 Anthropic 官方产品。网络检查与断流机制旨在减少意外直连和网络环境变化带来的风险，**不保证避免账号限制、封禁或其他风控结果**。

> 🌐 **项目主页 (Home)**：https://ccsafe.lyzi.cloud  
> 📦 **最新版本下载**：[GitHub Releases (v1.0.2)](https://github.com/Jelee0145/ClaudeSafe/releases/tag/v1.0.2)

## 快速下载 (v1.0.2)

| 版本 | 说明 | 下载链接 | SHA256 |
| --- | --- | --- | --- |
| **独立单文件版（推荐）** | Windows x64 自包含单文件（约 154.6 MB），内置 .NET 8 运行时，双击即用 | [ClaudeSafe-v1.0.2-win-x64-standalone.exe](https://github.com/Jelee0145/ClaudeSafe/releases/download/v1.0.2/ClaudeSafe-v1.0.2-win-x64-standalone.exe) | `3A998F2A4EE5C2DB6ED70A20C4E5B82EE9C30289779B74E23B193886656F65E8` |
| **精简框架依赖版** | 轻量压缩包（约 335.0 KB），需本机已安装 .NET 8 Desktop Runtime | [ClaudeSafe-v1.0.2-win-framework-dependent.zip](https://github.com/Jelee0145/ClaudeSafe/releases/download/v1.0.2/ClaudeSafe-v1.0.2-win-framework-dependent.zip) | `E05F7311930F1DD51A1835AC440F9D6315C598391369AD8CBBDD4478ADC4CD7F` |

## 核心安全机制

1. **启动前 6 维网络与风控体检**
   - **本地代理通道检测**：自动读取系统代理并扫描常见代理端口（`7890` / `7897` / `10808` / `10809` 等），确认代理可用性与延迟。
   - **出口 IP 与地区合规检测**：并发/级联探测多个 GeoIP 源，若出口位于受限/封禁地区（`CN`、`HK`、`MO`、`RU` 等）直接**高危阻断**，严禁启动。
   - **IP 属性与机房纯净度评估**：识别 Hosting / Proxy 标记及常见云厂商/机房 ASN，提示共享机房风控权重。
   - **历史 IP 漂移防风控对比**：本地持久化记录上次安全登录 IP 与国家，若发生跨国跳变则弹窗预警。
   - **Anthropic 连通性与分流防泄漏验证**：直接经代理验证 `https://claude.ai/cdn-cgi/trace`，防止 GeoIP 走代理但 Claude 分流漏走 `DIRECT` 的隐蔽风险。
   - **系统时区与环境一致性检查**：校验本地时区与出口 IP 归属地偏差并给出风险提示。

2. **内置本地守门代理 (`GatekeeperProxyServer`)**
   - 启动时在 `127.0.0.1:17890`（可自定义）建立受控 HTTP/HTTPS 代理阀门，默认锁死。
   - 仅在安全体检全部通过后开启阀门，并通过 `--proxy-server="http://127.0.0.1:17890"` 及代理环境变量引导 Claude Desktop 的网络请求经过本地代理。实际覆盖范围仍取决于应用内部的网络实现，不能仅凭启动参数保证所有流量均被接管。

3. **运行期断流 / IP 异动检测与熔断 + 5 分钟冷静期**
   - Claude 运行期间每 3 秒巡检代理端口连通性、每 15 秒校验出口 IP 是否变动。
   - 一旦巡检检测到 VPN 掉线或出口 IP 漂移，**立即锁死守门代理并尝试切断其管理的活跃 TCP 连接（不直接杀 Claude 进程，以尽量保留工作现场）**。注意巡检采用 3 秒/15 秒间隔，异常发生到被检测到之间可能存在时间窗口，置顶弹出紧急熔断窗口：
     - **锁定网络并进入 5 分钟冷静期**：保持 100% 断网状态并开启 5 分钟倒计时供您修复 VPN，修复后点击【重新体检并恢复连接】即可恢复通信；超时未恢复则自动强杀。
     - **立即退出并强杀所有 Claude 进程**：立刻终止全部进程树并锁定网络。

4. **退出无痕还原与防裸连常态封锁**
   - 后台驻留守护期间，检测到 Claude Desktop 退出或点击【封锁并安全退出】时，会立即锁死守门阀门并启用 Windows 防火墙出站规则与 Hosts 域名黑洞封锁（需管理员权限），同时拦截未经体检的直接双击启动，防止误触裸连。
   - 彻底退出 ClaudeSafe 时，会先检测 Claude Desktop 是否正在运行并弹窗确认是否同步退出，随后停止看门狗并**无痕还原**全部 Windows 系统代理 / PAC、防火墙规则与 Hosts 设置（支持 `--clean-all` 手动兜底清理）。

## 构建与运行

```powershell
# 编译 Release 版本
dotnet build -c Release

# 运行命令行核心模块自检
dotnet run --project src/ClaudeSafe -- --self-test

# 启动桌面程序
dotnet run --project src/ClaudeSafe -c Release
```

## Frequently Asked Questions / 常见问题

### What is ClaudeSafe?

ClaudeSafe is an open-source Windows utility for checking Claude Desktop's proxy/network environment before launch and monitoring connectivity while the app is running. It includes a local proxy gatekeeper and connection-interruption controls.

### Is ClaudeSafe an official Anthropic or Claude product?

No. ClaudeSafe is an independent community project and is not affiliated with, endorsed by or supported by Anthropic.

### Can ClaudeSafe prevent Claude account bans?

No tool can guarantee that an account will not be restricted. ClaudeSafe focuses on network diagnostics and reducing accidental direct connections. Account eligibility and enforcement are determined by the service provider.

### Does ClaudeSafe protect all Claude Desktop traffic?

The launcher configures proxy arguments and environment variables and provides a local gatekeeper. Some application components may use their own networking stack, so complete traffic coverage requires independent testing.

### Which operating systems are supported?

The published binaries target **Windows x64**. ClaudeSafe is developed with **.NET 8 and WPF**; it is not a native macOS or Linux application.

### Where can I download ClaudeSafe?

Download published builds from the [official GitHub Releases page](https://github.com/Jelee0145/ClaudeSafe/releases). The [project website](https://ccsafe.lyzi.cloud) provides an additional entry point.

## Project links / 项目链接

- Website / 官网：https://ccsafe.lyzi.cloud
- Source code / 源代码：https://github.com/Jelee0145/ClaudeSafe
- Releases / 版本下载：https://github.com/Jelee0145/ClaudeSafe/releases
- Issues / 问题反馈：https://github.com/Jelee0145/ClaudeSafe/issues
