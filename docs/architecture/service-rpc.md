# Private service RPC

`piquel.auth.v1.AuthService` is private gRPC only. Production callers authenticate
with a distinct, short-lived service token for `piquel-internal-api`; browser
code never receives service credentials. Ordinary product requests continue to
validate Piquel user access JWTs locally and never call `ValidateAccessToken`.
