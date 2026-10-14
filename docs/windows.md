# Windows portable EXE and per-user install

GreyLog's Windows EXE has the same CLI as the Python package. Running the EXE without arguments starts the loopback dashboard and uses `%LOCALAPPDATA%\GreyLog\greylog.db`. The console must stay open while GreyLog runs. The standalone EXE can be run from any directory and does not need Python.

## Portable use

Run `GreyLog-windows-x64.exe` and open the local dashboard URL printed in the console. Copy the **dashboard token** from the `Generated local dashboard token:` line into the dashboard prompt. The separate ingest token is for the HTTP ingest API and `ingest` CLI command. Generated tokens are valid for the running server process; if you restart GreyLog, use the newly printed token.

To list detected default gateway routes or select one manually, use:

```powershell
.\GreyLog-windows-x64.exe gateways
.\GreyLog-windows-x64.exe serve --gateway YOUR_GATEWAY_IP
```

The second command accepts a gateway IP even if route discovery did not list it. `--gateway auto` follows the preferred default route. If multiple routes use the same IP, add `--gateway-interface NAME`. The dashboard also offers gateway selection after login. GreyLog reads the host's route state; a listed route does not prove the router is reachable.

## Install for one Windows user

Download the `GreyLog-windows-x64-installable.zip` bundle from a release that includes it, extract the entire ZIP, and run `Install-GreyLog.cmd`. It installs to `%LOCALAPPDATA%\Programs\GreyLog`, adds a Start menu shortcut, and registers an entry in Windows Installed Apps. Administrator rights are not required. Installation does not start GreyLog automatically.

The shortcut uses the detected default gateway unless you choose a different one in the dashboard. To keep an explicit gateway choice in the shortcut, or enable gateway syslog reception, pass installer options:

```powershell
.\Install-GreyLog.cmd -Gateway YOUR_GATEWAY_IP -SyslogPort 5514 -SyslogBind YOUR_WINDOWS_LAN_IP -GatewayPingInterval 30
```

`-Gateway` accepts `auto` or an IP address. Add `-GatewayInterface "Wi-Fi"` if the same gateway address appears on more than one interface. A VPN may have the preferred default route, so choose the router's actual gateway address when enabling router syslog. The syslog listener is off unless `-SyslogPort` is provided. `-SyslogBind` is an IPv4 address on this Windows host; omitting it binds UDP on all local IPv4 interfaces. `-GatewayPingInterval 30` opts in to one ICMP echo every 30 seconds; omit it to leave active checks off. To change these settings, run the installer again with the new options.

For the common case where automatic gateway selection is sufficient, use `Install-GreyLog.cmd -SyslogPort 5514`. A plain install observes only the host's local route state; it receives no router logs.

Open **GreyLog** from Start. The console prints the dashboard URL and token. The installed CLI is `%LOCALAPPDATA%\Programs\GreyLog\GreyLog.exe`; for example:

```powershell
& "$env:LOCALAPPDATA\Programs\GreyLog\GreyLog.exe" gateways
& "$env:LOCALAPPDATA\Programs\GreyLog\GreyLog.exe" serve --db "$env:LOCALAPPDATA\GreyLog\greylog.db" --gateway YOUR_GATEWAY_IP --syslog-port 5514 --syslog-bind YOUR_WINDOWS_LAN_IP
```

Configure the router to forward syslog to this computer's LAN IP and the selected UDP port. Permit that inbound port through the host firewall for the router if needed. GreyLog accepts syslog only from the selected IPv4 gateway address. UDP syslog has no sender authentication and source addresses can be spoofed, so investigate alerts before acting on them. The optional ICMP result only indicates whether that gateway replied; a missing reply does not prove an outage, and a reply does not prove internet connectivity. Gateway monitoring does not capture packets, measure network throughput, discover devices, or guarantee intrusion detection.

Run `Install-GreyLog.cmd -DesktopShortcut` to add a desktop shortcut. To uninstall, use Windows Installed Apps or run the installed `Uninstall-GreyLog.ps1` in PowerShell. Uninstall removes the program and shortcuts. It leaves the database and other user data in `%LOCALAPPDATA%\GreyLog` for manual backup or removal.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\GreyLog\Uninstall-GreyLog.ps1"
```

## Build and verify for an operator release

From a Windows checkout with Python 3.11+:

```powershell
python -m pip install pyinstaller==6.19.0
.\packaging\windows\build.ps1
python .\packaging\windows\smoke_portable.py .\dist\windows\GreyLog-windows-x64.exe
Get-FileHash .\dist\windows\GreyLog-windows-x64.exe -Algorithm SHA256
Get-FileHash .\dist\windows\GreyLog-windows-x64-installable.zip -Algorithm SHA256
```

The build writes a standalone EXE and an installable ZIP to `dist\windows`. CI builds both and exercises dashboard login, bundled assets, and the install/uninstall scripts. Release assets should be built from the tagged commit and published with SHA256 hashes. Existing release assets are not changed by a local build.
