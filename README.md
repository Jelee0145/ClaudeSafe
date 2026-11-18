**English** | [简体中文](README.zh-CN.md)

# ClaudeSafe — Network Safety Launcher & Anti-Leak Gatekeeper for Claude Desktop

ClaudeSafe is an open-source Windows safety launcher, local proxy gatekeeper, and runtime circuit breaker for **Claude Desktop**, built with **.NET 8 and WPF**. It inspects proxy connectivity, outbound IP geolocation, and routing before launch, then monitors the connection during use and severs controlled traffic if the network changes.

**Keywords:** ClaudeSafe, Claude Desktop, proxy monitoring, IP leak detection, network kill switch, Windows, WPF.

> **Disclaimer:** ClaudeSafe is an independent open-source project and is not affiliated with, endorsed by, or supported by Anthropic. Network checks and circuit-breaker controls are designed to reduce accidental direct connections and risks from network changes, and **do not guarantee prevention of account restrictions, bans, or other enforcement actions**.

> 🌐 **Project Home:** https://ccsafe.lyzi.cloud  
> 📦 **Latest Release:** [GitHub Releases (v1.1.0)](https://github.com/Jelee0145/ClaudeSafe/releases/tag/v1.1.0)

## Quick Download (v1.1.0)

| Edition | Description | Download | SHA256 |
| --- | --- | --- | --- |
| **Standalone Single-File (Recommended)** | Windows x64 self-contained single executable (~154.7 MB) with .NET 8 runtime bundled | [ClaudeSafe-v1.1.0-win-x64-standalone.exe](https://github.com/Jelee0145/ClaudeSafe/releases/download/v1.1.0/ClaudeSafe-v1.1.0-win-x64-standalone.exe) | `85EC48EB072CDEBC6C32DE2DA0182FBA8F72C060B0745DF10B5C64EB322F1FF1` |
| **Framework-Dependent** | Lightweight archive (~394.9 KB); requires .NET 8 Desktop Runtime installed | [ClaudeSafe-v1.1.0-win-framework-dependent.zip](https://github.com/Jelee0145/ClaudeSafe/releases/download/v1.1.0/ClaudeSafe-v1.1.0-win-framework-dependent.zip) | `994E067B7FAAF1AC34CF2B0C16991AE28B289AD042505855BC6606E8FEDB026C` |

## Core Safety Mechanisms

1. **6-Dimension Pre-Flight Network & Risk Check**
   - **Local Proxy Channel & Mode Detection:** Reads Windows system proxy settings and scans common local proxy ports (`7890`, `7897`, `10808`, `10809`, etc.) to verify reachability, latency, and TUN/system-proxy mode.
   - **Exit IP & Region Compliance:** Probes GeoIP sources through the proxy and **blocks launch** if the exit IP falls in restricted/unsupported regions (`CN`, `HK`, `MO`, `RU`, etc.).
   - **IP Type & Datacenter Purity:** Detects Hosting/Proxy flags and common cloud/datacenter ASNs to warn about shared-IP risk.
   - **Historical IP Drift Comparison:** Persists the last safe launch IP and country locally, warning on cross-country jumps.
   - **Anthropic Reachability & Split-Tunnel Guard:** Verifies `https://claude.ai/cdn-cgi/trace` directly through the proxy to catch split-tunnel leaks where GeoIP is proxied but Claude traffic leaks via `DIRECT`.
   - **Game Booster Conflict & System Environment Check:** Detects running game boosters and checks local timezone consistency against the exit IP country.

2. **Built-In Local Gatekeeper Proxy (`GatekeeperProxyServer`)**
   - Listens on `127.0.0.1:17890` (configurable) with the Claude valve locked by default.
   - Opens the valve only after pre-flight checks pass, passing `--proxy-server="http://127.0.0.1:17890"` and proxy environment variables to Claude Desktop. Actual traffic coverage depends on the application's internal networking stack; launch arguments alone cannot guarantee interception of every component.

3. **Runtime Circuit Breaker & Cooldown Protection**
   - Polls proxy port connectivity every 3 seconds and verifies the outbound IP every 15 seconds while Claude is running.
   - If the VPN drops or the exit IP drifts, ClaudeSafe **immediately locks the gatekeeper and severs managed active TCP connections (without killing the Claude process immediately, preserving your workspace)**. Note that a brief window may exist between an actual network drop and the 3s/15s polling interval. A topmost circuit-breaker dialog lets you choose:
     - **Cancel (Cooldown Lock, default 5 min):** Keeps all Claude traffic locked and starts a countdown while you repair your VPN; auto-reconnects once checks pass, or terminates Claude if the timer expires.
     - **Confirm (Exit Immediately):** Terminates all Claude process trees right away and locks traffic.

4. **Clean Exit Restoration & Anti-Direct Guard**
   - While guarding in the background, if Claude Desktop exits or you click **Lock & Exit Claude Safely**, ClaudeSafe locks the gatekeeper, applies Windows Firewall outbound rules and Hosts blackhole rules (when running as Administrator), and intercepts unverified direct launches.
   - When exiting ClaudeSafe completely, it checks whether Claude Desktop is running and asks for confirmation, then stops the watchdog and **cleanly restores** Windows system proxy/PAC, firewall rules, and Hosts entries (also supports `--clean-all` for manual recovery).

5. **Bilingual UI (English / 简体中文)**
   - Automatically follows the OS display language on first launch (`Follow System`), or can be switched at runtime in **Settings → Language** (`Follow System` / `简体中文` / `English`).

## Build & Run

```powershell
# Build Release configuration
dotnet build -c Release

# Run CLI core module self-tests
dotnet run --project src/ClaudeSafe -- --self-test

# Launch desktop application
dotnet run --project src/ClaudeSafe -c Release
```

## Frequently Asked Questions

### What is ClaudeSafe?
ClaudeSafe is an open-source Windows utility for checking Claude Desktop's proxy/network environment before launch and monitoring connectivity while the app is running. It includes a local proxy gatekeeper and connection-interruption controls.

### Is ClaudeSafe an official Anthropic or Claude product?
No. ClaudeSafe is an independent community project and is not affiliated with, endorsed by, or supported by Anthropic.

### Can ClaudeSafe prevent Claude account bans?
No tool can guarantee that an account will not be restricted. ClaudeSafe focuses on network diagnostics and reducing accidental direct connections. Account eligibility and enforcement are determined by the service provider.

### Does ClaudeSafe protect all Claude Desktop traffic?
The launcher configures proxy arguments and environment variables and provides a local gatekeeper. Some application components may use their own networking stack, so complete traffic coverage requires independent testing.

### Which operating systems are supported?
The published binaries target **Windows x64**. ClaudeSafe is developed with **.NET 8 and WPF**; it is not a native macOS or Linux application.

### Where can I download ClaudeSafe?
Download published builds from the [official GitHub Releases page](https://github.com/Jelee0145/ClaudeSafe/releases). The [project website](https://ccsafe.lyzi.cloud) provides an additional entry point.

## Project Links

- Website: https://ccsafe.lyzi.cloud
- Source Code: https://github.com/Jelee0145/ClaudeSafe
- Releases: https://github.com/Jelee0145/ClaudeSafe/releases
- Issues: https://github.com/Jelee0145/ClaudeSafe/issues
