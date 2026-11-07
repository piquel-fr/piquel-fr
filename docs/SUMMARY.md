# Summary

[piquel.fr](README.md)

# User guide

- [Introduction](user/introduction.md)
- [Your account]()
  - [Creating an account](user/account/creating-an-account.md)
  - [Signing in](user/account/signing-in.md)
  - [Sign-in methods](user/account/sign-in-methods.md)
  - [Profile](user/account/profile.md)
  - [Email addresses](user/account/email-addresses.md)
  - [Devices](user/account/devices.md)
  - [Connected apps](user/account/connected-apps.md)
  - [Notifications](user/account/notifications.md)
  - [Security history](user/account/security-history.md)
- [Your data]()
  - [Recover your account](user/your-data/recover-your-account.md)
  - [Undo a recovery](user/your-data/undo-a-recovery.md)
  - [Download your data](user/your-data/export-your-data.md)
  - [Delete your account](user/your-data/delete-your-account.md)

# Building apps

- [How sign-in works](user/apps/how-sign-in-works.md)
- [Registering an app](user/apps/register-an-app.md)
  - [Changing an app's settings](user/apps/app-settings.md)
  - [Rotating a client secret](user/apps/rotate-secrets.md)
- [Signing in with Rust](user/apps/sign-in-rust.md)
- [Signing in with TypeScript](user/apps/sign-in-typescript.md)
- [Browser apps](user/apps/browser-apps.md)
- [Protecting an API](user/apps/protect-an-api.md)
- [Step-up authentication](user/apps/step-up.md)
- [Back-channel logout](user/apps/back-channel-logout.md)
- [Passkey sign-in on your own pages](user/apps/passkey-sign-in.md)
- [Developing on your machine](user/apps/local-development.md)
- [Deploying with piqueld](user/apps/deploying-with-piqueld.md)
- [Troubleshooting sign-in](user/apps/troubleshooting.md)
- [Building with coding agents](user/agents/overview.md)
  - [Adding sign-in](user/agents/piquel-sign-in.md)
  - [Running your app locally](user/agents/piquel-dev-setup.md)
  - [Deploying on piqueld](user/agents/piquel-deploy.md)
  - [Debugging a sign-in](user/agents/piquel-debug-sign-in.md)

# Reference

- [OpenID Connect](user/reference/oidc.md)

# Contributor guide

- [Getting started](dev/getting-started.md)
- [Contributing](dev/contributing.md)
- [Testing](dev/testing.md)
- [Rust conventions](dev/rust-conventions.md)
- [Changing the documentation](dev/documentation.md)

# Architecture

- [Overview](dev/architecture/overview.md)
- [Request lifecycle](dev/architecture/request-lifecycle.md)
- [Sessions](dev/architecture/sessions.md)
- [Authorization flow](dev/architecture/oidc.md)
- [Keys](dev/architecture/keys.md)
- [Auth, account and admin surfaces](dev/architecture/surfaces.md)
- [PostgreSQL boundary](dev/architecture/database.md)
- [Outbound delivery queue](dev/architecture/delivery-queue.md)
- [Notifications](dev/architecture/notifications.md)
- [Email addresses](dev/architecture/email.md)
- [Data export and account deletion](dev/architecture/account-deletion.md)
- [Telemetry](dev/architecture/telemetry.md)
- [SDK design](dev/architecture/sdk.md)

# Security

- [Security boundaries](dev/security/boundaries.md)
- [Threat model](dev/security/threat-model.md)
- [Security properties](dev/security/properties.md)
- [Account recovery](dev/security/account-recovery.md)
- [Tamper-evident audit history](dev/security/audit-history.md)
- [Handles are public](dev/security/handles.md)
- [Email normalization](dev/security/email-normalization.md)

# Extending

- [Adding a page or route to auth](dev/extending/page.md)
- [Adding a database migration](dev/extending/migration.md)
- [Adding an administrative operation](dev/extending/admin-operation.md)
- [Adding an account setting](dev/extending/account-setting.md)
- [Adding a configuration variable](dev/extending/configuration-variable.md)
- [Adding a notification](dev/extending/notification.md)
- [Adding a feature to the SDKs](dev/extending/sdk-feature.md)
- [Adding a federation provider](dev/extending/federation-providers.md)
- [Adding a delivery channel](dev/extending/delivery-channel.md)

# Operations

- [Deploying with piqueld](dev/operations/deploying.md)
  - [Secrets](dev/operations/secrets.md)
  - [Running several replicas](dev/operations/replicas.md)
- [Configuration](dev/operations/configuration.md)
- [Signing keys](dev/operations/signing-keys.md)
- [OIDC clients](dev/operations/clients.md)
- [Administration](dev/operations/administration.md)
  - [auth-service commands](dev/operations/cli-commands.md)
- [Sign-in providers](dev/operations/sign-in-providers.md)
- [Email](dev/operations/email.md)
- [Telemetry stack](dev/operations/telemetry.md)
- [Incidents](dev/operations/incidents.md)
