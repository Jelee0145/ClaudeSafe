# ClaudeSafe — Claude 中国用户安全启动与防封号卫士

ClaudeSafe 是一款专为中国大陆及受限网络环境用户设计的 **Claude Desktop 安全启动器、本地守门代理与运行期断流熔断助手**（基于 .NET 8 WPF，零第三方运行库依赖）。

> 🌐 **项目主页 (Home)**：https://ccsafe.lyzi.cloud  
> 📦 **最新版本下载**：[GitHub Releases (v1.0.1)](https://github.com/Jelee0145/ClaudeSafe/releases/tag/v1.0.1)

## 快速下载 (v1.0.1)

| 版本 | 说明 | 下载链接 | SHA256 |
| --- | --- | --- | --- |
| **独立单文件版（推荐）** | Windows x64 自包含单文件（约 154.4 MB），内置 .NET 8 运行时，双击即用 | [ClaudeSafe-v1.0.1-win-x64-standalone.exe](https://github.com/Jelee0145/ClaudeSafe/releases/download/v1.0.1/ClaudeSafe-v1.0.1-win-x64-standalone.exe) | `1D55FE4F0B56A3EEE5C8C8DEC9E4F001E12273568FD4809230BB446693B0116C` |
| **精简框架依赖版** | 轻量压缩包（约 150.3 KB），需本机已安装 .NET 8 Desktop Runtime | [ClaudeSafe-v1.0.1-win-framework-dependent.zip](https://github.com/Jelee0145/ClaudeSafe/releases/download/v1.0.1/ClaudeSafe-v1.0.1-win-framework-dependent.zip) | `B1E2FCC16D717DA33059C2E8ED4204C19F65BFEDA4AEB1514238F9C6A05B1FF8` |

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
   - 仅在安全体检全部通过后开启阀门，并通过 `--proxy-server="http://127.0.0.1:17890"` 及代理环境变量接管 Claude Desktop 全部网络流量。

3. **运行期断流 / IP 异动毫秒级熔断 + 5 分钟冷静期**
   - Claude 运行期间每 3 秒巡检代理端口连通性、每 15 秒校验出口 IP 是否变动。
   - 一旦检测到 VPN 掉线或出口 IP 漂移，**第 0 毫秒立即锁死守门代理并强制切断全部活跃 TCP 连接（不直接杀 Claude 进程，保留您的工作现场）**，置顶弹出紧急熔断窗口：
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
