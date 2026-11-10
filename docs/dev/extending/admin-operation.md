# Adding an administrative operation

This guide adds an operation administrators run, such as reserving a handle, on
every surface: the `auth-service` CLI and the admin dashboard, through one
`AdminService` method. The examples follow `ReserveHandle`, which reserves a
handle for a reason.

The operation's own logic lives once, in `AdminService`. The CLI and the
dashboard are thin adapters that say which `Operator` acts, so the operation
checks its operator itself and both surfaces run the same rules.

## What you'll have at the end

- An `AdminOperation` variant, which the CLI and the dashboard must both handle:
  a match and a test fail until they do.
- An `AdminService` method that authorizes its operator and records what it
  changed as a domain event, in the audit history.
- A CLI command, which a test checks runs the operation.
- A dashboard page, or a documented reason why only the CLI runs it.
- The owner told, when the operation changes their account.

## Before you start

- Decide whether the operation reads or changes. A read records nothing, unless
  it shows an account's personal data, which records a view. A change records
  an event, with the reason every change takes. The owner of an account it
  changes sees that reason in their history, as for disabling an account.
- If the operation changes a setting the owner also changes, it is an account
  setting instead: follow [adding an account setting](account-setting.md).
- New tables or columns come first: [adding a migration](migration.md).

## 1. Name the operation

Add a variant, with its doc comment, to `AdminOperation` in
`apps/auth-service/src/admin/operation.rs`:

```rust
/// Reserve a handle, so nobody takes it until an administrator gives it.
ReserveHandle,
```

The next steps fill in what this breaks:

- the build, until the dashboard maps the operation in `AdminApplication::page`;
- the tests' build, until `AdminOperation::invocation` and `AdminOperation::read`
  name it;
- the test `every_operation_has_its_command`, until a CLI command runs it.

## 2. Write the service method

Add the method to `AdminService`, in the module of its area under
`apps/auth-service/src/admin/service/`, such as `accounts.rs`. It takes the
`Operator` first, and checks it itself:

- **A read** calls `operator.authorize_read(&self.database)` before it reads
  anything, and returns views from `sourceorigin_common::admin`, which the dashboard
  renders and the CLI prints as JSON: `Self::views` converts stored records into
  them. A read of an account's personal data records a view with
  `operator.record_view`, as `view_user` does.
- **A change** takes the operator's `Reason` and runs in one transaction. On an
  account, it locks the account with `operator.lock(&mut tx, user_id)` first,
  which refuses another administrator's account unless the CLI acts. It ends
  with `Self::finish(tx, operator, &reason, subject, events)`, which checks the
  operator again after the last write, records the events with the reason and
  commits.

```rust
pub(crate) async fn reserve_handle(
    &self,
    operator: &Operator,
    handle: Handle,
    reason: Reason,
) -> Result<(), AdminError> {
    let mut tx = self.database.begin().await?;
    if !tx.handles().reserve(&handle, reason.as_str()).await? {
        return Err(AdminError::HandleReserved);
    }
    let reserved = DomainEvent::HandleReserved { handle };
    Self::finish(tx, operator, &reason, None, vec![reserved]).await
}
```

Every change takes a `Reason`, which is stored with each of its events as
personal data, and which the owner of an account it changes sees in their
history. `operator.context(&reason)` is the only way to attribute a change's
events, so none is recorded without one: use it for an event the change records
before `finish`, such as through another service. A read records with
`operator.reading()`, which has no reason. A change whose own content says why,
such as an announcement's text, records `Reason::see_message()` instead of
asking for one.

A refusal is an `AdminError` variant in `apps/auth-service/src/admin/error.rs`:
its message says what to fix, its `reason()` names it, and its arm in
`From<AdminError> for ApiError` sets its status.

## 3. Record its event

Add the event to `DomainEvent` in `crates/common/src/events/mod.rs`. It holds
only typed IDs, enums and timestamps; anything that identifies a person is
`Personal<T>`. The compiler then asks for its arms:

- `DomainEvent::kind`, the name it is stored under, which never changes, and
  `client_id` and `session_id`, the IDs stored in columns of their own;
- `DomainEvent::history_entry` (`crates/common/src/events/history.rs`): whether
  the owner sees it in their security history. An entry also needs its
  `HistoryEntry` variant and its text in `crates/ui/src/settings/timeline.rs`;
- `DomainEvent::notification`: whether the owner is told. See
  [adding a notification](notification.md);
- the dashboard's event list, in `crates/ui/src/admin/events.rs`.

Events join the [tamper-evident audit history](../security/audit-history.md)
with no change of yours. Before changing an event that already shipped, read
[domain events](../architecture/database.md#domain-events): older releases must
still read what a newer one writes.

## 4. Add the CLI command

Add a variant to the command enum of its area in `apps/auth-service/src/cli/`,
such as `HandleCommand` in `handle.rs`. Its doc comments are what `--help`
prints, and the [command reference](../operations/cli-commands.md):

```rust
/// Reserve a handle: signup and the settings refuse it and its look-alikes until
/// an administrator gives it with `rename --allow-reserved`, or `unreserve`s it.
Reserve {
    /// The handle.
    #[arg(value_parser = Handle::parse)]
    handle: Handle,
    /// Who or what it is kept for: 1 to 500 characters.
    #[arg(long)]
    reason: Reason,
},
```

Then:

1. Run it in the enum's `run`, through the `Console`'s `service` and `operator`.
   An account is named by `UserRef` and resolved with `console.user`.
2. Name its operation in `Administration::operation`, in
   `apps/auth-service/src/cli/mod.rs`:
   `HandleCommand::Reserve { .. } => Op::ReserveHandle`.
3. If it cuts off access, as disabling an account does, flatten a `Confirm` into
   it: the command then asks on a terminal, and needs `--yes` without one.

A new group of commands is a variant of `Administration`, with its arm in
`Administration::dispatch`.

## 5. Add the dashboard page

Add the page to the module of its tab in `apps/auth-service/src/web/admin/`, such
as `handles.rs`. A change's page shows its form on `GET` and makes the change on
`POST`. In outline:

```rust
/// `/handles/reserve`: reserves a handle, saying who or what it is kept for.
#[route([GET, POST] "/handles/reserve")]
pub(super) async fn reserve(cx: &Cx, form: Option<Form<Reservation>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let back = href!(check).resolve(cx);
    let refused = App::submit(cx, form, back.clone(), |input: Reservation| async move {
        // Parse the form, then call the service as `admin.operator`.
    })
    .await?;
    // Render `sourceorigin_ui::dashboard_change(change: Change::ReserveHandle, ...)`.
}
```

- `App::admin` finds the administrator, or sends the browser to sign in.
- `App::confirm` requires the dashboard's own recent passkey confirmation, or
  sends the browser to confirm and back.
- `App::submit` makes the change, goes back to `back` once it is made, and
  otherwise returns the refusal, which the form shows with what was typed. A
  change whose form posts only its reason uses `App::submit_reason` and
  `ReasonForm`, which parse the reason first.

The page's words are a `Change` variant in `crates/ui/src/admin/mod.rs`: its
title, description, button, label, whether it takes something away, and the
reason it asks for. Link the page from the list it belongs to, as the handles
page links its changes with an `Action`.

`AdminApplication::search_action`, beside it, decides whether the top bar's search
finds the operation, and the compiler asks for each new one. A change that acts
on no account or client, such as reserving a handle, has one page: make it a
`SearchAction` in `crates/ui/src/admin/mod.rs`, with its name and the other words
people search for it by, and search links it by its route. Any other
operation returns `None`, under the comment saying why.

Map the operation to its page in `AdminApplication::page`
(`apps/auth-service/src/web/admin/mod.rs`): `Op::ReserveHandle => &handles::reserve`.
The router mounts every page it maps, under the paths of
`routes::dashboard::PREFIXES`; a page under a new top-level path adds it there.

An operation that only the CLI may run maps to `None`, with the reason next to its
arm, as `PurgeUser` and `PruneAuditChain` have:

```rust
// Pruning needs the schema owner, which auth never holds: the audit page
// shows the command instead.
| Op::PruneAuditChain => return None,
```

## 6. Tell the owner

If the operation changes an account, its event's
`DomainEvent::notification` arm decides whether the owner is told, in their
inbox and by email. Support's changes usually tell them: see
[adding a notification](notification.md).

## Test it

1. Test the service method in `apps/auth-service/src/admin/tests/`, in the file
   of its area: what it changes, the event it records, and what it refuses.
2. Say whether the operation reads, in `AdminOperation::read`
   (`admin/tests/reads.rs`). A read runs there as an administrator who may no
   longer read, and must be refused before it reads; a change returns `None`.
3. Give the operation a command line in `AdminOperation::invocation`
   (`apps/auth-service/src/cli/tests.rs`).
   `every_operation_has_its_command` parses it and checks that it names the
   operation.
4. Test the dashboard page in `apps/auth-service/src/web/admin/tests.rs`, and in
   a browser in `tests/browser/admin.spec.ts`, if it does more than the pages
   tested already.

```console
just test -p auth-service
just db test -E 'test(admin)'
```

## Document it

1. Run `just docs reference`, which adds the command to the
   [command reference](../operations/cli-commands.md).
2. Show the task in [administration](../operations/administration.md), on the
   CLI and on the dashboard, or say why the dashboard can't do it.
3. If the operation changes what administrators may do to an account, update
   [auth, account and admin surfaces](../architecture/surfaces.md).
4. If the owner sees it, in their history or their inbox, say so in the user
   guide.

The CLI is the most complete surface: the
[surfaces rule](https://github.com/sourceorigin-dev/sourceorigin/blob/main/AGENTS.md#guidelines)
lets an operation stay CLI-only only with its documented reason.
