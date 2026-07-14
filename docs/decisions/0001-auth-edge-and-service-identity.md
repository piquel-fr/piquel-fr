# ADR 0001: Auth edge and service identity

Status: accepted for the first version

## Context

The SvelteKit application and the protocol authority must share
`https://auth.piquel.fr` so WebAuthn, cookies, OAuth redirects, and CSRF checks
have one exact origin. The Rust public listener intentionally serves plaintext
HTTP and therefore needs an enforced TLS and forwarding boundary. Private RPC
also needs a certificate identity that can be compared with the signed client
assertion.

## Decision

Traefik terminates public TLS and routes a single origin by path. The checked-in
static and dynamic configurations are `infra/traefik/auth-static.yml` and
`infra/traefik/auth-dynamic.yml`.

- Protocol and account API paths go to `auth-service:8080`.
- All remaining paths, including `/login`, `/authorize`, `/security`, and
  SvelteKit assets, go to `auth-web:3000`.
- Neither backend publishes its application port on the Docker host. Traefik
  and the two applications share a dedicated `piquel-auth-edge` network.
- Traefik discards untrusted inbound forwarding headers (`insecure: false`). If
  a separately reviewed upstream load balancer is later introduced, only its
  exact CIDRs may be added to Traefik's `forwardedHeaders.trustedIPs`. Auth-service
  independently accepts `X-Forwarded-For` only when the TCP peer belongs to
  `AUTH_TRUSTED_PROXY_CIDRS`, which is the exact Docker edge-network CIDR.
- `AUTH_HEALTH_LISTENER` is reachable only by container health checks and the
  orchestrator. It is not a Traefik route and is not rate limited.
- `AUTH_INTERNAL_LISTENER` is reachable only on the private service network and
  requires mTLS. A service certificate has exactly one identity URI SAN of the
  form `spiffe://piquel.fr/service/<service-id>`. That service ID must equal the
  assertion subject before a service token is issued.

The public issuer and WebAuthn relying-party origin are both exactly
`https://auth.piquel.fr`. No application trusts `X-Forwarded-Host` or
`X-Forwarded-Proto` to change configured security policy.

## Route ownership

Auth-service owns `/.well-known/*`, `/oauth/*`, `/oidc/*`, `/webauthn/*`,
`/account/*`, `/session/*`, `/login/github*`, and `/login/google*`. Auth-web
owns every other public path. The protocol router has higher Traefik priority,
so `/login/github` and `/login/google` cannot fall through to SvelteKit.

## Consequences

Changing either route set is an architecture change: update the Traefik
configuration, this ADR, and browser contract tests together. A deployment
must not bypass Traefik to reach the public authority. Horizontal replicas use
per-process rate-limit budgets in this first version; PostgreSQL remains the
authority for all replay and revocation state.
