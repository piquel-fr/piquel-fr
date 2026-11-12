-- An invitation may be mailed to the person it invites: it remembers their
-- normalized address, which their account starts with, verified, when they sign
-- up with it. Its link's token is derived from its ID, so the email sender
-- rebuilds the link from the stored digest, as it does a recovery's. Cleanup
-- deletes the address with its invitation, once it expires or a day after it
-- is redeemed.
ALTER TABLE invitations ADD COLUMN email TEXT;
