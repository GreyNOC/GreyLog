# GreyLog

GreyLog is a local log monitor for security analysts. Its CLI tails files or receives JSON events, stores normalized events in SQLite, evaluates alert rules, and serves a live dashboard. The heartbeat chart shows observed events per second.

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

### Debian and Ubuntu

Install the Debian package with `apt`; it includes the `greylog` command for the CLI and dashboard.

```bash
sudo apt install ./greylog_0.1.1-1_all.deb
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

Open <http://127.0.0.1:8765> and unlock the dashboard with the server token. It starts empty and updates as events arrive. Repeat `--watch NAME:FORMAT:PATH` for multiple files. Watchers read appended lines by default; add `--from-start` to read existing content. The watcher account needs read access to each file and write access to the database directory.

For timestamps without a timezone, GreyLog uses the host's local timezone. Use `serve --timezone UTC` for all watched files or `--source-timezone NAME=-04:00` for one source. The `ingest` and `check` commands accept `--timezone` too. Timestamps with an explicit offset are converted to UTC using that offset.

To forward a JSONL stream from a local collector, run this in another terminal with the same token:

```powershell
Get-Content .\events.jsonl -Wait | .\.venv\Scripts\python.exe -m greylog ingest --source vendor-a --format json -
```

```bash
tail -F ./events.jsonl | .venv/bin/python -m greylog ingest --source vendor-a --format json -
```

Parser profiles: `auto`, `json`, `postgresql`, `mysql`, `mongodb`, `mssql`, `redis`, `oracle`, `syslog`. These are best-effort matches for common log formats. They do not connect to databases or cover every vendor configuration. Check representative lines with `python -m greylog check "LINE" --format FORMAT` before relying on a parser. See [collector integration](docs/collector-integration.md) for the HTTP event format.

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
- This release is a single-host app. It does not provide multi-user access control, hosted tenant isolation, vendor API polling, or long-term archive storage.

For a hosted deployment, see [cloud path](docs/cloud-path.md).

## Develop

```text
python -m greylog serve --help
python -m greylog ingest --help
python -m greylog check --help
python -m greylog export --help
python -m unittest discover -s tests -v
```

The source tree includes Windows and Linux CI. See [contributing](CONTRIBUTING.md) for local checks.

## License

GreyLog, including the supplied owl image, is licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE).
