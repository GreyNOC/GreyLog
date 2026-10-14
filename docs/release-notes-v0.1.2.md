# GreyLog v0.1.2

Patch release for PR #2 review findings.

- Redact `sig` only when it is the full attribute name; fields such as `signal`, `design`, and `assigned` retain their values.
- Run the Debian launcher with Python safe-path mode so a package in the current directory cannot shadow the installed GreyLog package.
