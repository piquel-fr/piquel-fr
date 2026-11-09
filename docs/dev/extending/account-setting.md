# Adding an account setting

This guide adds a setting that an account's owner changes, and that support may
change on their behalf, such as the display name or the profile picture. One
`AccountService` operation serves every surface: the owner's settings page and
account API, the admin dashboard and the `auth-service account` command.

## What you'll have at the end

- An `AccountOperation` variant, which the owner's account API must serve and the
  CLI must run: a match and a test fail until they do.
- An `AccountService` method that runs the same rules whoever acts, and records
  the change, with an administrator's reason, in the account's history.
- The setting on the owner's settings page, on the account's dashboard page and
  in the `account` command.
- The setting in the account's data export, and the owner told when support
  changes it.

## Before you start

Decide who may do what, by the rule in
[changing an account on its owner's behalf](../architecture/surfaces.md#changing-an-account-on-its-owners-behalf):
administrators may view, edit and remove, but never add a way to sign in or to
receive the account's email.

- What both may do joins `AccountOperation`, and its method takes a `Viewer` to
  read or a `Subject` to change.
- What only the owner may do, such as adding a passkey, takes an `Owner`, which
  only the session cookie builds. It is no `AccountOperation`, so the CLI and the
  dashboard have nothing to add: give it a route of its feature's application,
  as setting the profile picture has in `PictureApplication`.

New tables or columns come first: [adding a migration](migration.md).

## 1. Name the operation

Add a variant, with its doc comment, to `AccountOperation` in
`apps/auth-service/src/account/mod.rs`:

```rust
/// Remove the account's profile picture.
RemovePicture,
```

The next steps fill in what this breaks:

- the build, until the account API serves it in `AccountApplication::route`;
- the tests' build, until `AccountOperation::invocation` and
  `AccountOperation::read` name it;
- the test `every_operation_has_its_command`, until an `account` command runs it.

## 2. Write the service method

Write the method in an `impl AccountService` block of the setting's module, such
as `apps/auth-service/src/pictures/mod.rs`:

- **A read** takes `&Viewer` and calls `viewer.authorize(&self.database)` first.
  For an administrator, that checks their rights and records a view of the
  account.
- **A change** takes `&Subject`. It locks the account with `subject.lock(&mut tx)`,
  or `subject.lock_confirmed(&mut tx)` when the owner must have confirmed with a
  passkey recently, records its event with `subject.context()`, and ends with
  `subject.commit(tx)`, which checks an administrator once more:

```rust
pub(crate) async fn remove_picture(&self, subject: &Subject) -> Result<(), AccountError> {
    let mut tx = self.database.begin().await?;
    subject.lock(&mut tx).await?;
    if !tx.pictures().remove(subject.user()).await? {
        return Err(PictureError::Missing.into());
    }
    tx.record(
        &subject.context(),
        Some(subject.user()),
        DomainEvent::PictureRemoved {},
    )
    .await?;
    subject.commit(tx).await
}
```

A `Subject` of an administrator carries their reason, and `subject.context()`
attaches it to the event. A change that signs the owner out elsewhere ends
`subject.others()`, every session but the owner's own, or every one when an
administrator acts, for `subject.revocation()`.

Its refusals are the module's error, such as `PictureError`, with its own `From`
into `ApiError`, which sets each refusal's status and message. A new module's
error joins `AccountError` (`apps/auth-service/src/account/error.rs`) as a
`#[from]` variant, with its arm in `From<AccountError> for ApiError`.

## 3. Serve it on the account API

Give it a path under `/account/` in `apps/auth-service/src/routes.rs`, then its
arm in `AccountApplication::route`, and its handler in `impl AccountApplication`:

```rust
Op::RemovePicture => (pictures::OWN, delete(Self::remove_picture)),
```

The handler extracts `Viewer`, `Subject`, or `ConfirmedSubject` for a change that
needs a recent passkey, which then answers `step_up_required` before reading the
path or body. Methods on one path merge, here and with the owner-only methods of
the same path.

## 4. Add it to the settings page

The owner's settings page calls the same method: its `AccountPage::apply` passes
`Subject::from(owner)`, and its `render` reads through `reader.viewer()`. Add the
change to the page's change type and its component in `sourceorigin-ui`, following
[adding a page](page.md). The component takes an `Audience`, so it renders the
owner's form or the administrator's, which asks for a reason.

## 5. Add the CLI command

In `apps/auth-service/src/cli/account.rs`, add a command to the setting's
subcommand enum, such as `Picture`, or a new `Setting` variant for a new setting:

```rust
/// Remove the picture, such as one that impersonates someone.
Remove {
    /// Why.
    #[command(flatten)]
    change: Change,
},
```

Then:

1. Name its operation in `AccountCommand::operation`:
   `Picture::Remove { .. } => Op::RemovePicture`.
2. Run it in `AccountCommand::run`: a change as `change.on(id, console)`, the
   operator's `Subject` with the `--reason` the `Change` flattens, and a read as
   `read()`, printed with `output.print`.
3. If it cuts off access, as removing a passkey does, flatten a `Confirm` into it.

## 6. Add it to the dashboard

The account's dashboard pages are in `apps/auth-service/src/web/admin/settings.rs`,
one per settings tab. Each renders the owner's own `sourceorigin-ui` section with
`Audience::Administrator`, and posts the owner's change with a reason:

```rust
let (admin, user) = App::settings(cx).await?;
let form = App::posted::<Administered<ConnectedAppChange>>(cx, body).await?;
let refused = App::submit(cx, form, App::here(cx), |posted| async move {
    let subject = App::subject(user, admin, posted.reason)?;
    // Call the service with `subject`, mapping its error with `Refusal::from`.
})
.await?;
```

Reads take `App::viewer(user, admin)`, and the page ends with
`App::settings_page`. A new tab is mounted with `.route(settings::…)` in
`AdminApplication::routes` (`web/admin/mod.rs`), and linked from
`App::settings_tab` and from the account's page in `web/admin/users.rs`.

## 7. Add it to the data export

The owner downloads everything auth stores about their account, as
`AccountExport` (`apps/auth-service/src/deletion/export/mod.rs`). If the setting
stores something new:

1. Add a field to `AccountExport`, with a doc comment saying what it holds.
2. Read it in `AccountExport::read`, from the export's transaction, so the export
   is one snapshot.
3. Raise `VERSION`, and say what the version added in the struct's doc comment.

The export never holds a secret, a digest or key material.

## 8. Record the event and tell the owner

The change records a `DomainEvent`, whose arms decide whether the owner sees it
in their security history and whether they are told. See
[recording its event](admin-operation.md#3-record-its-event): the steps are the
same. A change the owner makes to their own account usually tells them nothing
they don't know; one support makes does. `DomainEvent::notification` tells them
apart by its actor: see [adding a notification](notification.md).

## Test it

1. Test the method in the setting's module, such as
   `apps/auth-service/src/pictures/tests.rs`, as the owner and as an operator.
2. Say whether the operation reads, in `AccountOperation::read`
   (`apps/auth-service/src/account/tests.rs`).
   `every_settings_read_checks_its_administrator` runs every read as an
   administrator who may no longer read.
3. Give it a command line in `AccountOperation::invocation`
   (`apps/auth-service/src/cli/tests.rs`), which
   `every_operation_has_its_command` parses.
4. Test the settings page and the dashboard page, in
   `apps/auth-service/src/web/settings/tests.rs` and `web/admin/tests.rs`.
5. If the export grew, add the new field to
   `serializes_every_category_in_its_documented_shape`
   (`deletion/export/tests.rs`), which builds an export and checks each
   category's name and shape.

```console
just test -p auth-service
just db test -E 'test(account) | test(settings)'
```

## Document it

1. Run `just docs reference` for the new command's
   [reference](../operations/cli-commands.md).
2. Add the setting to the table in
   [changing an account on its owner's behalf](../architecture/surfaces.md#changing-an-account-on-its-owners-behalf),
   as shared or owner only.
3. Describe it in the user guide, through the settings page, and for support,
   in [administration](../operations/administration.md).
4. If it notifies the owner, add it to the list in
   [notifications](../architecture/notifications.md). If the export grew, say
   so in [data export and account deletion](../architecture/account-deletion.md).

Every surface gets the setting, as
[every surface gets the feature](../contributing.md#every-surface-gets-the-feature)
asks.
