[English](README.md) | **简体中文**

# ClaudeSafe — Claude Desktop 网络安全启动器与代理泄漏防护工具

ClaudeSafe 是一款面向需要监控代理连接和网络出口环境的 Windows 用户的 **Claude Desktop 安全启动器、本地守门代理与运行期断流保护工具**，使用 **.NET 8 WPF** 开发。

**关键词：** ClaudeSafe、Claude Desktop、代理监控、IP 泄漏检测、网络断流开关、Windows、WPF。

> **免责声明：** ClaudeSafe 是独立开源项目，并非 Anthropic 官方产品。网络检查与断流机制旨在减少意外直连和网络环境变化带来的风险，**不保证避免账号限制、封禁或其他风控结果**。

> 🌐 **项目主页**：https://ccsafe.lyzi.cloud  
> 📦 **最新版本下载**：[GitHub Releases (v1.1.0)](https://github.com/Jelee0145/ClaudeSafe/releases/tag/v1.1.0)

## 快速下载 (v1.1.0)

| 版本 | 说明 | 下载链接 | SHA256 |
| --- | --- | --- | --- |
| **独立单文件版（推荐）** | Windows x64 自包含单文件（约 154.7 MB），内置 .NET 8 运行时，双击即用 | [ClaudeSafe-v1.1.0-win-x64-standalone.exe](https://github.com/Jelee0145/ClaudeSafe/releases/download/v1.1.0/ClaudeSafe-v1.1.0-win-x64-standalone.exe) | `85EC48EB072CDEBC6C32DE2DA0182FBA8F72C060B0745DF10B5C64EB322F1FF1` |
| **精简框架依赖版** | 轻量压缩包（约 394.9 KB），需本机已安装 .NET 8 Desktop Runtime | [ClaudeSafe-v1.1.0-win-framework-dependent.zip](https://github.com/Jelee0145/ClaudeSafe/releases/download/v1.1.0/ClaudeSafe-v1.1.0-win-framework-dependent.zip) | `994E067B7FAAF1AC34CF2B0C16991AE28B289AD042505855BC6606E8FEDB026C` |

## 核心安全机制

1. **启动前 6 维网络与风控体检**
   - **本地代理通道检测**：自动读取系统代理并扫描常见代理端口（`7890` / `7897` / `10808` / `10809` 等），确认代理可用性、延迟以及 TUN / 系统代理模式。
   - **出口 IP 与地区合规检测**：通过代理探测 GeoIP 信息，若出口位于受限/封禁地区（`CN`、`HK`、`MO`、`RU` 等）直接**高危阻断**，严禁启动。
   - **IP 属性与机房纯净度评估**：识别 Hosting / Proxy 标记及常见云厂商/机房 ASN，提示共享机房风控权重。
   - **历史 IP 漂移防风控对比**：本地持久化记录上次安全登录 IP 与国家，若发生跨国跳变则弹窗预警。
   - **Anthropic 连通性与分流防泄漏验证**：直接经代理验证 `https://claude.ai/cdn-cgi/trace`，防止 GeoIP 走代理但 Claude 分流漏走 `DIRECT` 的隐蔽风险。
   - **加速器冲突与系统环境检测**：检测运行中的游戏加速器进程或虚拟网卡，并校验本地时区与出口 IP 归属地一致性。

2. **内置本地守门代理 (`GatekeeperProxyServer`)**
   - 启动时在 `127.0.0.1:17890`（可自定义）建立受控 HTTP/HTTPS 代理阀门，默认锁死。
   - 仅在安全体检全部通过后开启阀门，并通过 `--proxy-server="http://127.0.0.1:17890"` 及代理环境变量引导 Claude Desktop 的网络请求经过本地代理。实际覆盖范围仍取决于应用内部的网络实现，不能仅凭启动参数保证所有流量均被接管。

3. **运行期断流 / IP 异动检测与熔断 + 冷静期保护**
   - Claude 运行期间每 3 秒巡检代理端口连通性、每 15 秒校验出口 IP 是否变动。
   - 一旦巡检检测到 VPN 掉线或出口 IP 漂移，**立即锁死守门代理并尝试切断其管理的活跃 TCP 连接（不直接杀 Claude 进程，以尽量保留工作现场）**。注意巡检采用 3 秒/15 秒间隔，异常发生到被检测到之间可能存在时间窗口，置顶弹出紧急熔断窗口：
     - **取消（熔断保护，默认 5 分钟）**：保持 100% 断网状态并开启倒计时供您修复 VPN，修复后自动恢复通信并发送系统通知；超时未恢复则自动强杀。
     - **确定（立即退出）**：立刻终止全部 Claude 进程树并锁定网络。

4. **退出无痕还原与防裸连常态封锁**
   - 后台驻留守护期间，检测到 Claude Desktop 退出或点击【封锁并安全退出】时，会立即锁死守门阀门并启用 Windows 防火墙出站规则与 Hosts 域名黑洞封锁（需管理员权限），同时拦截未经体检的直接双击启动，防止误触裸连。
   - 彻底退出 ClaudeSafe 时，会先检测 Claude Desktop 是否正在运行并弹窗确认是否同步退出，随后停止看门狗并**无痕还原**全部 Windows 系统代理 / PAC、防火墙规则与 Hosts 设置（支持 `--clean-all` 手动兜底清理）。

5. **中/英双语界面支持**
   - 首次启动自动匹配系统语言（`跟随系统`），也可在 **设置 → 界面语言** 中随时切换（`跟随系统` / `简体中文` / `English`），即时生效。

## 构建与运行

```powershell
# 编译 Release 版本
dotnet build -c Release

# 运行命令行核心模块自检
dotnet run --project src/ClaudeSafe -- --self-test

# 启动桌面程序
dotnet run --project src/ClaudeSafe -c Release
```

## 常见问题

### ClaudeSafe 是什么？
ClaudeSafe 是一款开源 Windows 工具，用于在启动 Claude Desktop 前检测代理和网络环境，并在运行期间监控连接状态，内置本地守门代理与断流熔断控制。

### ClaudeSafe 是 Anthropic 或 Claude 官方产品吗？
不是。ClaudeSafe 是独立社区开源项目，与 Anthropic 没有任何隶属、背书或官方支持关系。

### ClaudeSafe 能保证不被封号吗？
没有任何工具能保证账号不受限制。ClaudeSafe 专注于网络诊断与减少意外直连，账号资格与风控规则由服务提供方决定。

### ClaudeSafe 能保护 Claude Desktop 的全部流量吗？
启动器会配置代理参数、环境变量并提供本地守门代理。但部分应用组件可能使用独立的网络栈，完整流量覆盖仍需自行验证。

### 支持哪些操作系统？
当前发布版本仅针对 **Windows x64**，基于 **.NET 8 和 WPF** 开发，不提供原生 macOS 或 Linux 版本。

### 在哪里下载 ClaudeSafe？
请前往 [GitHub Releases 官方页面](https://github.com/Jelee0145/ClaudeSafe/releases) 下载，也可通过[项目主页](https://ccsafe.lyzi.cloud)访问。

## 项目链接

- 官网：https://ccsafe.lyzi.cloud
- 源代码：https://github.com/Jelee0145/ClaudeSafe
- 版本下载：https://github.com/Jelee0145/ClaudeSafe/releases
- 问题反馈：https://github.com/Jelee0145/ClaudeSafe/issues
