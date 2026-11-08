# Notifications

Every account has an inbox at `auth.piquel.fr/settings/notifications`: what
Piquel tells its owner about the account, newest first, with the unread count in
the settings sidebar and on the overview. Today that is a replaced primary
address, a removed address, a recovery that revoked the account's passkeys,
enrolled one or was undone, an account disabled, enabled, scheduled for deletion
or restored, a handle or display name changed, or a profile picture removed, by
support, and [administrators' announcements](../operations/administration.md#announcements). Each notification opens on a page of its own, which marks it read
when the browser came from auth's own pages, so a link from another site cannot
dismiss one, and shows the security history entry of the event it came from
while the history keeps it, with "This wasn’t me" where the history allows a
report. A notification holds no personal data, so it reads the same after its
event's personal data is erased or the event is pruned; an announcement holds the
text its administrators wrote, which goes with its recipients.

Each notification is also emailed, except an announcement whose recipient
turned announcements' email off (see [email preferences](#email-preferences)): a
recovery's to every verified address, a
replaced or removed address's to that address, and any other to the primary
verified address. The email says what the inbox says, and links the
notification's page; an announcement's goes out on a channel of its own and
links the inbox.

The owner marks one unread, or every one read, in settings or through
`POST /account/notifications/{id}/read`, `…/{id}/unread` and
`/account/notifications/read`. `GET /account/notifications`, `…/{id}` and
`…/unread` read them without marking anything. Administrators read an account's
inbox on its dashboard page and operators with `account <user> notifications
list|show`; neither marks anything read. The data export includes the inbox.
[Notifications](../../user/account/notifications.md) is the owner's guide.

## Email preferences

Notifications about the account itself are always emailed, so no switch can
hide one from its owner. The categories whose email the owner may turn off are
`EmailCategory`'s variants, today only `announcements`, on by default.
`notification_preferences` stores a row only once the owner chooses, and
`NotificationRepository::preferences` fills in the default for the others. An
announcement that is not essential is emailed only to recipients whose
Announcements email is on, both when its deliveries are queued and when each is
sent; an essential one goes to every recipient with a primary verified address
(see [the delivery queue](delivery-queue.md#announcements)).

The owner turns a category on or off in the inbox's **Email preferences**
dialog, which a change reopens, or with
`PUT /account/notifications/preferences` and a body such as
`{"category": "announcements", "email": false}`; their session is enough. A
change records `NotificationPreferenceChanged`, which the security history
shows, and a choice that changes nothing records nothing.
`GET /account/notifications/preferences` lists every category. Administrators
see them, read-only, on the account's Notifications page of the dashboard, and
operators with `account <user> notifications preferences`: an operator turning
email off could hide a notice from the owner. The data export includes them.

An announcement's email that is not essential carries an unsubscribe link,
`/unsubscribe?account=<id>&token=<token>`, in its body and in the
`List-Unsubscribe` header, with `List-Unsubscribe-Post: List-Unsubscribe=One-Click`
(RFC 8058), so mail clients offer it in one click. They do so only when the
relay's DKIM signature covers both headers, which the relay must be set up to
sign. The token is the HMAC of the
account's ID under a key derived from the token digest key, so it is stored
nowhere and never expires; holding it only turns that account's announcements'
email off. Opening the link shows a page asking first, so a mail scanner that
follows links changes nothing. A `POST` to it, from that page or a mail client,
turns the email off as the owner without a session, and the security layer
accepts it from any origin: the link is its credential.
