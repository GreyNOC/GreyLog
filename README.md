# GreyLog

GreyLog is a local log monitor for security analysts. Its CLI tails files or receives JSON events, stores normalized events in SQLite, evaluates alert rules, and serves a live dashboard. The heartbeat chart shows received log events per second.

## Install

Python 3.11 or newer is required. Windows and Linux are supported. The app has no third-party runtime dependencies.

```powershell
# Windows PowerShell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
```

```bash
# Linux
python3 -m venv .venv
.venv/bin/python -m pip install .
```

### Windows portable EXE and installer

The Windows `GreyLog-windows-x64.exe` runs without Python. Double-click it to start the local dashboard, then enter the **dashboard token** printed in its console. The separate ingest token is only for CLI/API event submission. Keep the console open while GreyLog runs.

For a per-user installation, extract a release's `GreyLog-windows-x64-installable.zip` and run `Install-GreyLog.cmd`. It adds a Start menu shortcut and a Windows Installed Apps entry without requiring administrator rights. Installation does not start GreyLog automatically. The installed CLI is `%LOCALAPPDATA%\Programs\GreyLog\GreyLog.exe`. To receive router logs, install with `Install-GreyLog.cmd -SyslogPort 5514`, then configure the router to forward syslog to this PC's LAN IP on UDP port 5514. Without that option, GreyLog observes local gateway routes only. See [Windows setup and release build](docs/windows.md) for gateway selection, syslog setup, uninstall, and build details.

### Debian and Ubuntu

Install the Debian package with `apt`; it includes the `greylog` command for the CLI and dashboard.

```bash
sudo apt install ./greylog_0.1.3-1_all.deb
greylog serve --db "$HOME/.local/share/greylog/greylog.db"
```

To build the package from a checkout, run `bash packaging/debian/build-deb.sh`. The result is written to `dist/`.

## Run

Use separate long, random tokens for ingestion and the dashboard. Set `GREYLOG_TOKEN` for collectors and `GREYLOG_DASHBOARD_TOKEN` to unlock the dashboard. Keep both out of source control. If either is unset, the server prints a generated replacement at startup.

```powershell
# Windows PowerShell
$env:GREYLOG_TOKEN = "YOUR_RANDOM_TOKEN"
$env:GREYLOG_DASHBOARD_TOKEN = "YOUR_DASHBOARD_TOKEN"
.\.venv\Scripts\python.exe -m greylog serve --db .\data\greylog.db --watch 'postgres:postgresql:C:\logs\postgresql.log'
```

```bash
# Linux
export GREYLOG_TOKEN='YOUR_RANDOM_TOKEN'
export GREYLOG_DASHBOARD_TOKEN='YOUR_DASHBOARD_TOKEN'
.venv/bin/python -m greylog serve --db ./data/greylog.db --watch 'postgres:postgresql:/var/log/postgresql/postgresql.log'
```

Open <http://127.0.0.1:8765> and unlock the dashboard with the **dashboard** token printed at startup or set with `--dashboard-token` / `GREYLOG_DASHBOARD_TOKEN`. The ingest token is separate and will not unlock the dashboard. It starts empty and updates as events arrive. Repeat `--watch NAME:FORMAT:PATH` for multiple files. Watchers read appended lines by default; add `--from-start` to read existing content. The watcher account needs read access to each file and write access to the database directory.

For timestamps without a timezone, GreyLog uses the host's local timezone. Use `serve --timezone UTC` for all watched files or `--source-timezone NAME=-04:00` for one source. The `ingest` and `check` commands accept `--timezone` too. Timestamps with an explicit offset are converted to UTC using that offset.

To forward a JSONL stream from a local collector, run this in another terminal with the same token:

```powershell
Get-Content .\events.jsonl -Wait | .\.venv\Scripts\python.exe -m greylog ingest --source vendor-a --format json -
```

```bash
tail -F ./events.jsonl | .venv/bin/python -m greylog ingest --source vendor-a --format json -
```

Parser profiles: `auto`, `json`, `postgresql`, `mysql`, `mongodb`, `mssql`, `redis`, `oracle`, `syslog`. These are best-effort matches for common log formats. They do not connect to databases or cover every vendor configuration. Check representative lines with `python -m greylog check "LINE" --format FORMAT` before relying on a parser. See [collector integration](docs/collector-integration.md) for the HTTP event format.

## Gateway routes and router logs

Run `greylog gateways` (or `python -m greylog gateways`) to list this computer's current default gateway routes and interfaces. The same routes appear in the unlocked dashboard. Choose one there, or start the CLI with `serve --gateway ADDRESS --gateway-interface NAME`; `--gateway auto` chooses the lowest route metric. If your gateway is absent, enter its IP address in the dashboard or with `--gateway ADDRESS`. The dashboard then labels it as **not in current default routes** until the operating system reports it. A dashboard choice is saved in a small JSON file beside the database and restored on the next launch; an explicit CLI `--gateway` overrides it for that run. GreyLog checks local route state every five seconds and records changes. Route presence alone does not prove a gateway responds or that the internet is working.

For an optional availability signal, add `--gateway-ping-interval 30` to send one ICMP echo to the selected gateway every 30 seconds. The interval can be 30 to 3600 seconds. This is off by default, including for automatically selected VPN gateways. The dashboard reports **reply**, **no reply**, or **unknown** separately from route status. A router may ignore ICMP, so no reply does not prove an outage; a reply does not prove internet connectivity.

To collect actual router events, configure the router to forward **UDP syslog** to this computer's LAN IP and enable GreyLog's receiver. For example, if the computer's LAN IP is `192.168.1.10` and the gateway is `192.168.1.1`:

```text
greylog serve --gateway 192.168.1.1 --syslog-bind 192.168.1.10 --syslog-port 5514 --db ./data/greylog.db
```

The receiver is off unless `--syslog-port` is supplied. `--syslog-bind` defaults to `0.0.0.0` (all local IPv4 interfaces); binding to the LAN IP limits where it listens. The receiver accepts records only when their sender IP matches the selected IPv4 gateway. Select a different gateway in the dashboard to update that filter. Router syslog settings vary by vendor; use a port the router supports and allow UDP traffic to that port in the host firewall as needed. An IPv6 gateway can be tracked as a route, but this receiver accepts IPv4 senders only.

UDP syslog does not authenticate the router and packets may be lost or spoofed. GreyLog highlights explicit intrusion or security wording as a **possible signal** for review, not a confirmed compromise. A gateway IP or syslog feed does not provide packet capture, network throughput, device inventory, or complete intrusion detection. The chart counts received log events, not network bytes or packets.

## Alerts

Default rules alert after five authentication failures for one actor and source, five non-authentication errors from one source, or three queries lasting at least two seconds from one source. Each rule uses a 60-second event-time window and a five-minute cooldown. Alerts include the rule, count, window, and matching event IDs. Events over five minutes from receipt are stored but excluded from alert counts, including replays and logs from skewed clocks. Tune `maxTimestampSkewSeconds` only after validating source clocks.

Pass `--rules PATH` to configure thresholds and timing. See [examples/rules.json](examples/rules.json). Rules are deterministic but cannot guarantee detection of every incident or eliminate false positives.

## Export

Use **Export** on the Events or Alerts panel to save all records still retained in SQLite as JSON Lines (`.jsonl`). Supported browsers show a save picker; other browsers use their normal download location or download prompt. The export includes more than the 100 rows shown on the dashboard. Handle exported files as sensitive log data.

For a direct database export, create a destination directory and run:

```text
python -m greylog export --db ./data/greylog.db --dir ./exports both
```

`both` is the default; choose `events` or `alerts` for one file. The command reads the existing SQLite database and writes timestamped JSONL files with unique names. It never overwrites an existing export. The destination directory must already exist. Exported records reflect what is still retained in the database, including alerts outside the dashboard's current 100-row view. If the destination filesystem lacks hard-link support, a process crash during the fallback copy may leave a partial file; success is reported only after the file is synced to disk.

## Security and scope

- The server binds to loopback only. The dashboard and read APIs require a dashboard token-backed browser session; there are no separate user accounts or roles. The browser session expires when the server restarts. Do not publish the port or put it behind a public proxy without separate authentication and TLS.
- HTTP ingestion requires its own bearer token. The CLI sender connects to loopback only. Treat both tokens as secrets and do not use the same value for both.
- SQLite contains event details and alert evidence. Restrict file access, back it up as needed, and set a retention policy suitable for your data. GreyLog caps stored events at 50,000 and alerts at 5,000 by default. Exports contain only records still retained when the export runs.
- Redaction of common secret fields and inline patterns is best effort. Review source logs and field mappings before forwarding sensitive data.
- File watchers poll even when quiet. HTTP sources appear stale after 60 seconds without an event because there is no separate heartbeat endpoint.
- Gateway route discovery reads the host operating system's route table. Manual gateway addresses and route status do not themselves collect router logs; enable UDP syslog and configure forwarding on the router for those events. The receiver trusts an IPv4 sender address only, which is not cryptographic authentication.
- This release is a single-host app. It does not provide multi-user access control, hosted tenant isolation, vendor API polling, or long-term archive storage.

For a hosted deployment, see [cloud path](docs/cloud-path.md).

## Develop

```text
python -m greylog serve --help
python -m greylog gateways --help
python -m greylog ingest --help
python -m greylog check --help
python -m greylog export --help
python -m unittest discover -s tests -v
```

The source tree includes Windows and Linux CI. See [contributing](CONTRIBUTING.md) for local checks.

## License

GreyLog, including the supplied owl image, is licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE).
