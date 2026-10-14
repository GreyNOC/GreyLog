# Security

Security reports are evaluated against the latest published GreyLog version. There is no announced backport policy for older versions.

Use GitHub private vulnerability reporting if it is enabled on the published repository. If it is unavailable, open a public issue requesting a private reporting channel without including vulnerability details, credentials, customer logs, or personal data.

GreyLog serves only on loopback. Dashboard and read access require a dashboard token-backed browser session, while ingestion uses a separate bearer token. Unlocking sets an HttpOnly, SameSite=Strict cookie for the current server process. GreyLog has no separate user accounts or roles. Operators must restrict host, SQLite, and export-file access and keep both tokens secret. Redaction is best effort; review source logs before sending sensitive data.
