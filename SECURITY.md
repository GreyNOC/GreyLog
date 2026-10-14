# Security

Security reports are evaluated against the latest published GreyLog version. There is no announced backport policy for older versions.

Use GitHub private vulnerability reporting if it is enabled on the published repository. If it is unavailable, open a public issue requesting a private reporting channel without including vulnerability details, credentials, customer logs, or personal data.

GreyLog serves only on loopback. Dashboard and read access require a token-backed browser session. Unlocking sets an HttpOnly, SameSite=Strict cookie for the current server process. GreyLog has no separate user accounts or roles. Operators must restrict host, SQLite, and export-file access and keep the shared token secret. Redaction is best effort; review source logs before sending sensitive data.
