# GreyLog v0.1.3

- Make the generated dashboard token distinct and easy to identify in the console and login prompt. The generated ingest token remains separate and does not unlock the dashboard.
- List this host's default gateway routes in the CLI and dashboard. Select a detected route or enter a gateway IP manually; monitor route changes from the host's OS state.
- Offer an optional low-rate ICMP availability check for the selected gateway, off by default. The result is separate from route presence and does not prove internet connectivity.
- Add optional UDP syslog reception from the selected IPv4 gateway. The router must forward syslog to the host's LAN IP and configured port. Sender addresses in UDP syslog are unauthenticated, and route presence does not prove reachability or compromise.
- Add a reproducible Windows one-file EXE build and a per-user installable ZIP with Start menu and uninstall support. The EXE keeps the existing no-argument dashboard startup behavior and needs no Python runtime on the target host.

The Windows installer does not start GreyLog automatically. A plain install observes local route state only; `Install-GreyLog.cmd -SyslogPort 5514` enables router log reception after the operator configures forwarding and the host firewall. See [Windows setup](https://github.com/GreyNOC/GreyLog/blob/v0.1.3/docs/windows.md).
