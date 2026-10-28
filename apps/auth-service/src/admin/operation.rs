//! The list of administrative operations, which the dashboard and the CLI must
//! both cover.

use crate::operations::operations;

operations! {
    /// Every operation [`AdminService`](super::AdminService) performs, which each
    /// new operation must join. The dashboard maps each to the page running it,
    /// or to none when only the CLI may run it. Every CLI command names the
    /// operation it runs, and a CLI test checks that each operation has a command
    /// naming it: the terminal can do whatever the dashboard does.
    pub(crate) enum AdminOperation {
        /// Search accounts.
        SearchUsers,
        /// Show one account, recording that it was viewed.
        ViewUser,
        /// Disable an account and end its sessions.
        DisableUser,
        /// Reactivate a disabled account.
        EnableUser,
        /// Start recovering an account whose owner lost every passkey.
        RecoverAccount,
        /// Undo an account's recovery for its owner, once they are confirmed.
        UndoRecovery,
        /// End every session of an account.
        RevokeUserSessions,
        /// End one session.
        RevokeSession,
        /// List invitations.
        ListInvitations,
        /// Create a signup link.
        CreateInvitation,
        /// Revoke an unredeemed invitation.
        RevokeInvitation,
        /// List OIDC clients.
        ListClients,
        /// Show one OIDC client.
        ViewClient,
        /// Register a client operators manage.
        CreateClient,
        /// Register or update a client a deployment manages.
        ApplyClient,
        /// Change a client's registration.
        UpdateClient,
        /// Enable a client.
        EnableClient,
        /// Disable a client.
        DisableClient,
        /// Suspend a client, so that its owner cannot enable it.
        SuspendClient,
        /// Lift a client's suspension.
        UnsuspendClient,
        /// Delete a client for good.
        DeleteClient,
        /// Give a confidential client a new secret.
        RotateClientSecret,
        /// Page through domain events.
        ListEvents,
        /// List administrators.
        ListAdministrators,
        /// Make an account an administrator.
        GrantAdministrator,
        /// Remove an account's administrator rights.
        RevokeAdministrator,
        /// List accounts whose handle breaks the rules.
        CheckHandles,
        /// Give an account a new handle.
        RenameHandle,
        /// List outbound deliveries.
        ListDeliveries,
        /// Retry a failed or cancelled delivery.
        RetryDelivery,
        /// Cancel a pending or failed delivery.
        CancelDelivery,
    }
}
