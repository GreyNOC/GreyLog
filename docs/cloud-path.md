# From local console to SaaS

The first release runs on the analyst's machine. Its collector, normalizer, rule engine, HTTP ingest envelope, and dashboard API are deliberately separate so the same event model can be used in a hosted deployment.

Before accepting customer logs in a cloud service, add these controls:

1. **Tenant identity and authorization.** User sign-in, organization membership, role-based access, per-tenant ingestion credentials, and a tenant identifier on every event, alert, and source.
2. **Transport and storage.** TLS for ingestion and viewing; encryption at rest; per-tenant retention and deletion; separate hot event storage from long-term archive. Remove the local SQLite assumption behind the storage interface.
3. **Reliable collection.** Collector batching, bounded disk spool, retry with idempotency keys, server-side quotas, ingestion acknowledgements, and source heartbeat endpoints. A quiet source should not be shown as disconnected solely because it had no log events.
4. **Alert lifecycle.** Versioned rules, per-tenant thresholds, acknowledgements and assignments, suppression schedules, audit records, and evaluation against representative benign and malicious fixtures.
5. **Operations.** Metrics for ingestion lag and dropped events, health checks, backup and recovery, safe migrations, access logs, and incident procedures.

Vendor API connectors should be added one at a time with the vendor's documented auth, pagination, rate limits, and replay behavior. The current `POST /api/ingest` format provides a bridge for vendor forwarders and local shippers in the meantime.
