# Auth signing and service-key rotation

Create a new asymmetric signing key in the approved key provider with a stable
`kid`. Publish its public JWK while retaining the old public key, begin issuing
with the new key, and retain the old JWK for longer than the maximum token life
(five minutes for access and service tokens). Remove the old JWK only after that
overlap has elapsed and no token class depending on it remains valid.

Service public keys follow the same overlap rule: register the new `kid`, permit
both keys during transition, move the service signer, then revoke the old key.
Runtime services cannot self-register or rotate their own keys.
