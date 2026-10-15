# Contributing

GreyLog targets Python 3.11+ on Windows and Linux. Keep runtime dependencies small, preserve loopback-only serving, and avoid adding real customer logs or secrets to tests, issues, and pull requests.

Run checks before submitting a change:

```text
python -m unittest discover -s tests -v
python -m pip wheel . --no-deps --wheel-dir dist
```

If you change the dashboard in `greylog/web/`, also run `node --check greylog/web/app.js` when Node.js is available. Parser and rule changes should include representative positive and negative cases. Describe supported log formats narrowly; a parser profile does not imply complete vendor support.
