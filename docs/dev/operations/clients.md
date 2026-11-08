# OIDC clients

Clients live in the database. Register and change them with `auth-service client`
(`just auth client` here). A change applies to the next request on every replica,
without a restart, and is recorded as an event attributed to the operator.

```sh
just auth client create blog --name Blog --trusted \
    --redirect-uri https://blog.piquel.fr/callback --post-logout-uri https://blog.piquel.fr/
just auth client create notes --name Notes --confidential --refresh \
    --redirect-uri https://notes.example/callback --scope openid --scope notes:read
just auth client list                # --output json for scripts
just auth client show notes          # registration and secret lifetimes
just auth client update blog --add-redirect-uri https://blog.piquel.fr/auth/callback
just auth client update notes --backchannel-logout-uri https://notes.example/auth/backchannel-logout
just auth client disable notes       # enable undoes it
just auth client rotate-secret notes --grace 24h
just auth client suspend notes       # its owner cannot enable it; unsuspend lifts it
just auth client delete notes        # for good: the ID is never reused, the name and URIs are erased
```

Clients are public by default and authenticate with PKCE alone (`none`).
Confidential clients (`--confidential`) use `client_secret_basic` with a secret
that auth generates; both require S256 PKCE. `create` and `rotate-secret` print
the secret once, and auth stores only its SHA-256 digest. Secrets start with
`pqcs_` so secret scanners can recognize them. After `rotate-secret`, the earlier
secrets keep working for the grace period (24 hours by default, at most 30 days;
`--grace 0` revokes them at once, and asks first), so the client can switch without downtime.

A client that a deployment manages, such as the admin dashboard, is registered
with `client apply` instead, which takes the same options as `create`. It
registers the client, or updates what differs and records nothing when nothing
does, so a deploy job can run it every time. A confidential client's secret comes
from the deployment, `--secret file://PATH` (or `env://NAME`): 32 random bytes in
unpadded base64url, never printed. The client's other secrets keep working for
`--grace` at most (1 hour by default) while the deployment rolls out; `--grace 0`
revokes them.

Redirect URIs must match exactly. They use HTTPS, or HTTP on a loopback IP for
native apps, without credentials or a fragment, and are written as URL parsing
normalizes them: `https://app.example/`, not `https://APP.example`. The origins of
an enabled public client's redirect URIs may call the token, revocation and
userinfo endpoints from a browser. Scopes default to `openid`, `profile` and
`email`. `--refresh` allows refresh tokens when the client also requests
`offline_access`; `--trusted` skips the consent screen and is meant for
first-party clients only. `--require-par` makes the client push its authorization
requests (`update --no-require-par` lifts it).

Accounts can also register clients for their own applications in the developer
console, at `auth.piquel.fr/developers`: see
[registering an app](../../user/apps/register-an-app.md).
Auth generates their IDs and limits their scopes to `openid`, `profile`, `email`
and `offline_access`; they are never trusted, their names cannot contain Piquel's
or another well-known brand (`RESERVED_BRANDS` in `piquel_common::clients`), and
an account can have 10 and register 20 a day. They never appear in other accounts' consoles, while
`client list` shows every client. Owners can disable and enable their clients;
`client suspend` disables one so that its owner cannot enable it until
`client unsuspend`, which leaves it disabled. Deleting a client, from either side, disables it, revokes its
refresh tokens and removes its secrets and consents. Its ID stays reserved, since
tokens carry it as `aud`.
