# Auth release and migration order

1. Run `just check`, `just test`, `pnpm check:web`, and `pnpm test:web`.
2. Back up PostgreSQL and verify the restore procedure before a schema release.
3. Run `just migrate "$DATABASE_URL"` once with the migration role.
4. Deploy auth-service replicas with readiness checks enabled; replicas never run
   migrations at startup.
5. Deploy auth-web only after the public auth endpoints it references are live.

Liveness is process-only. Readiness fails closed when PostgreSQL or a required
key provider is unavailable. During a graceful shutdown, remove the replica
from intake first and allow only bounded in-flight requests to complete.
