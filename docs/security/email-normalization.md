# Email normalization

Piquel normalizes an email by NFC-normalizing its local and domain components
and lowercasing the domain only. The local part is otherwise preserved exactly:
Piquel does not strip `+` suffixes, remove dots, or apply provider-specific
equivalence. Email is an optional verified contact attribute, never an account
identifier; `UserId` is the downstream identity reference.
