# Email normalization

Piquel normalizes an email by NFC-normalizing its local and domain components
and lowercasing the domain only. The local part is otherwise preserved exactly:
Piquel does not strip `+` suffixes, remove dots, or apply provider-specific
equivalence. Email is an optional verified contact attribute, never an account
identifier; `UserId` is the downstream identity reference. The policy is
`piquel_common::email::NormalizedEmail`.

Only the hourly limit on verification emails to one address folds further: it
counts an address by its `mailbox()`, the local part lowercased and without its
`+` tag, so case and tag variants of one mailbox share a budget. That fold never
decides equality or ownership.
