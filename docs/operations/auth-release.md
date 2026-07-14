# Auth release and migration order

1. Run `just ci` with `TEST_DATABASE_URL` pointing to an isolated disposable
   PostgreSQL database. This includes the database concurrency suite and browser
   tests.
2. Back up PostgreSQL and verify the restore procedure before a schema release.
3. Export `AUTH_DATABASE_URL` only in the migration process environment and run
   `just migrate` once with the migration role; never pass credentials in argv.
4. Create a dedicated `piquel-auth-edge` Docker network. Attach only Traefik,
   auth-service, and auth-web. Do not publish either application port on the
   host.
5. Deploy auth-service with `AUTH_PUBLIC_LISTENER=0.0.0.0:8080`,
   `AUTH_HEALTH_LISTENER=0.0.0.0:8081`, and
   `AUTH_TRUSTED_PROXY_CIDRS=<exact-edge-network-cidr>`. Health checks use port
   8081 directly; replicas never run migrations at startup.
6. Deploy auth-web on port 3000, load `infra/traefik/auth-static.yml` and
   `infra/traefik/auth-dynamic.yml`, provision the `auth.piquel.fr` certificate,
   and verify the route ownership documented in ADR 0001 before accepting
   public traffic.
7. Keep the mTLS gRPC listener on a distinct private Docker network. Each client
   certificate must have the exact SPIFFE URI SAN documented in ADR 0001.

Liveness is process-only. Readiness fails closed when PostgreSQL or a required
key provider is unavailable. During a graceful shutdown, remove the replica
from intake first and allow only bounded in-flight requests to complete.
Signing and service-key rotation remains explicitly deferred; see
`docs/operations/auth-key-rotation.md` before replacing any production key.
