# Collector integration

GreyLog receives one event per `POST http://127.0.0.1:8765/api/ingest`. The collector must run on the same host. Set `GREYLOG_TOKEN` in the server and send `Authorization: Bearer TOKEN` with `Content-Type: application/json`.

For a line from a vendor log file, send:

```json
{"source":"SOURCE_NAME","format":"postgresql","timezone":"UTC","line":"RAW_LOG_LINE"}
```

For an already structured event, send:

```json
{"source":"SOURCE_NAME","format":"json","timezone":"UTC","event":{"timestamp":"UTC_ISO_8601_TIME","kind":"auth","outcome":"failure","actor":"ACCOUNT","message":"LOG_MESSAGE"}}
```

Replace the uppercase placeholders. Useful fields for accurate rules are `timestamp`, `kind`, `outcome`, `actor`, `severity`, and `durationMs`. Set a stable source identifier for each collector stream. If `timestamp` is absent, GreyLog uses receipt time. The optional envelope `timezone` sets how timezone-free timestamps are interpreted: `local` (default, using the server host's timezone), `UTC`, or a fixed offset such as `-04:00`. Timestamps with explicit offsets are unaffected.

The response is HTTP `201` with the normalized `event` and any triggered `alerts`. Invalid input returns `400`, a missing or wrong token returns `401`, and a request over 65,536 bytes returns `413`. A single log line is limited to 32,768 characters. Clients should handle failed requests and preserve their own retry queue. GreyLog does not provide batch ingest, idempotency keys, or delivery acknowledgements beyond the response for one request; replayed events can be counted again.

Parser profiles are best effort. Run `python -m greylog check "LINE" --format FORMAT` with real, sanitized log lines to confirm mapping before connecting a source. For RFC 3164 syslog timestamps without a year, GreyLog selects the year nearest receipt. Event timestamps more than `maxTimestampSkewSeconds` from receipt are stored but excluded from alert counts. A quiet HTTP source appears stale after 60 seconds without a new event because GreyLog has no separate source heartbeat endpoint.
