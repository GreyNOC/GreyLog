# GreyLog v0.1.1

Security and Debian packaging release.

- Add the universal Debian package `greylog_0.1.1-1_all.deb` for Debian and Ubuntu, including the `greylog` CLI and local dashboard.
- Generate separate ingestion and dashboard tokens unless the operator supplies both.
- Bound concurrent local HTTP handlers and keep SQLite WAL and shared-memory sidecars private on POSIX systems.
- Expand default redaction for session IDs, JWTs, access keys, signatures, and credential-bearing query parameters.

Existing `GREYLOG_TOKEN` deployments must set `GREYLOG_DASHBOARD_TOKEN` or use the generated dashboard token printed at startup.
