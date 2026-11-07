//! Every read checks its administrator.

use super::{announcements::announcement, *};
use crate::AuditKeys;
use piquel_common::AnnouncementId;
use piquel_common::protocol::claims::Acr;

/// Production's committed audit keys.
fn committed_keys() -> AuditKeys {
    AuditKeys::committed(&"https://auth.piquel.fr".parse().expect("origin")).expect("keys")
}

impl AdminOperation {
    /// Runs the service methods behind this operation as `operator`, if it reads,
    /// with arguments that need not exist, since a read checks its operator before
    /// anything else. `None` for a change, which checks its operator before it
    /// commits. The match is exhaustive, so a new operation must say which it is.
    #[expect(
        clippy::too_many_lines,
        reason = "One arm per operation, so a new one cannot skip the decision."
    )]
    async fn read(
        self,
        service: &AdminService,
        operator: &Operator,
    ) -> Option<Vec<Result<(), AdminError>>> {
        let (user, client) = (UserId::new(), "notes");
        let (id, everyone) = (
            AnnouncementId::new(),
            announcement(AnnouncementRecipients::Everyone),
        );
        Some(match self {
            Self::SearchUsers => vec![service.search_users(operator, "", None).await.map(drop)],
            Self::ViewUser => vec![
                service
                    .find_user(operator, &UserRef::Id(user))
                    .await
                    .map(drop),
                service.view_user(operator, user).await.map(drop),
            ],
            Self::ListInvitations => vec![service.list_invitations(operator).await.map(drop)],
            Self::ListClients => vec![
                service.list_clients(operator).await.map(drop),
                service.list_related_origins(operator).await.map(drop),
            ],
            Self::ViewClient => vec![
                service
                    .client_details(operator, &client.parse().expect("client ID"))
                    .await
                    .map(drop),
            ],
            Self::ListEvents => vec![
                service
                    .events(operator, EventSearch::default())
                    .await
                    .map(drop),
            ],
            Self::ListAdministrators => vec![service.list_administrators(operator).await.map(drop)],
            Self::CheckHandles => vec![
                service.check_handles(operator).await.map(drop),
                service.list_released_handles(operator).await.map(drop),
                service.list_reserved_handles(operator).await.map(drop),
            ],
            Self::ListSigningKeys => vec![service.list_signing_keys(operator).await.map(drop)],
            Self::ListDeliveries => vec![
                service
                    .list_deliveries(operator, None, None, 1)
                    .await
                    .map(drop),
            ],
            Self::VerifyAuditChain => vec![
                service
                    .verify_audit_chain(operator, &committed_keys())
                    .await
                    .map(drop),
                service.audit_page(operator, None).await.map(drop),
            ],
            Self::ListAnnouncements => vec![service.list_announcements(operator).await.map(drop)],
            Self::ViewAnnouncement => vec![service.view_announcement(operator, id).await.map(drop)],
            // A draft is the administrators' own, so writing, changing and
            // discarding one need what a read needs, checked first.
            Self::DraftAnnouncement => vec![
                service
                    .draft_announcement(operator, &everyone)
                    .await
                    .map(drop),
            ],
            Self::EditAnnouncement => {
                vec![
                    service
                        .edit_announcement(operator, id, &everyone)
                        .await
                        .map(drop),
                ]
            }
            Self::DiscardAnnouncement => vec![service.discard_announcement(operator, id).await],
            // Pruning checks its operator before anything else too.
            Self::PruneAuditChain => vec![
                service
                    .prune_audit_chain(operator, &committed_keys(), 1)
                    .await
                    .map(drop),
            ],
            Self::DisableUser
            | Self::EnableUser
            | Self::ScheduleDeletion
            | Self::RestoreUser
            | Self::PurgeUser
            | Self::RevokeUserSessions
            | Self::RevokeSession
            | Self::CreateInvitation
            | Self::RevokeInvitation
            | Self::CreateClient
            | Self::ApplyClient
            | Self::UpdateClient
            | Self::EnableClient
            | Self::DisableClient
            | Self::SuspendClient
            | Self::UnsuspendClient
            | Self::DeleteClient
            | Self::RotateClientSecret
            | Self::ApproveRelatedOrigin
            | Self::RemoveRelatedOrigin
            | Self::GrantAdministrator
            | Self::RevokeAdministrator
            | Self::RenameHandle
            | Self::ReleaseHandle
            | Self::ReserveHandle
            | Self::UnreserveHandle
            | Self::RetryDelivery
            | Self::CancelDelivery
            | Self::RecoverAccount
            | Self::UndoRecovery
            | Self::RotateSigningKey
            | Self::RevokeSigningKey
            | Self::ImportSigningKey
            | Self::SendAnnouncement => return None,
        })
    }
}

impl Harness {
    /// Three administrators who may no longer read, with the refusal each gets:
    /// one whose rights were revoked, one whose session ended, and one whose
    /// session signed in without a passkey.
    pub(crate) async fn refused_readers(&self) -> [(Operator, AdminError); 3] {
        let (revoked, ended) = (self.admin().await, self.admin().await);
        let social = self
            .grant(self.signed_in(AuthenticationMethod::Federation).await)
            .await;
        self.service()
            .revoke_administrator(&cli(), revoked.user_id)
            .await
            .expect("revoke");
        let mut tx = self.database.begin().await.expect("transaction");
        ended.sign_out(&mut tx).await;
        tx.commit().await.expect("commit");
        // Any passkey sign-in, however old, as every read requires.
        let passkey = StepUpRequirement {
            acr: Some(Acr::PhishingResistant),
            max_age: None,
        };
        [
            (operator(revoked, Utc::now()), AdminError::NotAdministrator),
            (operator(ended, Utc::now()), AdminError::SessionEnded),
            (
                operator(social, Utc::now()),
                AdminError::StepUpRequired(passkey),
            ),
        ]
    }
}

/// Every read checks its operator itself, as the dashboard calls the service
/// in-process: an administrator whose rights were revoked, whose session ended,
/// or whose session signed in without a passkey reads nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_read_checks_its_administrator() {
    let harness = Harness::new().await;
    let service = harness.service();
    for (operator, refusal) in harness.refused_readers().await {
        for read in AdminOperation::ALL {
            let Some(results) = read.read(&service, &operator).await else {
                continue;
            };
            for result in results {
                assert_refused(
                    &result.expect_err("refused"),
                    &refusal,
                    &format!("{read:?}"),
                );
            }
        }
    }
}
