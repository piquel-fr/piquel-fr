# Summary

[piquel.fr](README.md)

# User guide

- [Introduction](user/introduction.md)
- [Registering an app](user/apps/register-an-app.md)
- [Step-up authentication](user/apps/step-up.md)
- [Back-channel logout](user/apps/back-channel-logout.md)
- [Passkey sign-in on your own pages](user/apps/passkey-sign-in.md)

# Reference

- [OpenID Connect](user/reference/oidc.md)

# Contributor guide

- [Getting started](dev/getting-started.md)
- [Contributing](dev/contributing.md)
- [Testing](dev/testing.md)
- [Rust conventions](dev/rust-conventions.md)
- [Changing the documentation](dev/documentation.md)

# Architecture

- [Monorepo boundaries](dev/architecture/overview.md)
- [Auth, account and admin surfaces](dev/architecture/surfaces.md)
- [PostgreSQL boundary](dev/architecture/database.md)
- [Outbound delivery queue](dev/architecture/delivery-queue.md)
- [Notifications](dev/architecture/notifications.md)
- [Email addresses](dev/architecture/email.md)
- [Data export and account deletion](dev/architecture/account-deletion.md)
- [Telemetry](dev/architecture/telemetry.md)
- [SDK design](dev/architecture/sdk.md)

# Security

- [Security properties](dev/security/properties.md)
- [Account recovery](dev/security/account-recovery.md)
- [Tamper-evident audit history](dev/security/audit-history.md)
- [Handles are public](dev/security/handles.md)
- [Email normalization](dev/security/email-normalization.md)

# Extending

- [Adding a federation provider](dev/extending/federation-providers.md)

# Operations

- [Deploying with piqueld](dev/operations/deploying.md)
- [Configuration](dev/operations/configuration.md)
- [Signing keys](dev/operations/signing-keys.md)
- [OIDC clients](dev/operations/clients.md)
- [Administration](dev/operations/administration.md)
- [Sign-in providers](dev/operations/sign-in-providers.md)
- [Email](dev/operations/email.md)
- [Telemetry stack](dev/operations/telemetry.md)
