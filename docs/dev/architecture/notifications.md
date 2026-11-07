# Notifications

Every account has an inbox at `auth.piquel.fr/settings/notifications`: what
Piquel tells its owner about the account, newest first, with the unread count in
the settings sidebar and on the overview. Today that is a replaced primary
address, a removed address, a recovery that revoked the account's passkeys,
enrolled one or was undone, an account disabled, enabled, scheduled for deletion
or restored, and a handle or display name changed, or a profile picture removed,
by support. Each notification opens on a page of its own, which marks it read
when the browser came from auth's own pages, so a link from another site cannot
dismiss one, and shows the security history entry of the event it came from
while the history keeps it, with "This wasn’t me" where the history allows a
report. A notification holds no personal data, so it reads the same after its
event's personal data is erased or the event is pruned.

Each notification is also emailed: a recovery's to every verified address, a
replaced or removed address's to that address, and any other to the primary
verified address. The email says what the inbox says, and links the
notification's page.

The owner marks one unread, or every one read, in settings or through
`POST /account/notifications/{id}/read`, `…/{id}/unread` and
`/account/notifications/read`. `GET /account/notifications`, `…/{id}` and
`…/unread` read them without marking anything. Administrators read an account's
inbox on its dashboard page and operators with `account <user> notifications
list|show`; neither marks anything read. The data export includes the inbox.
