use super::*;

impl OidcRepository<'_> {
    /// Used inside the startup provisioning transaction so removed clients fail closed.
    pub async fn disable_all_clients(&mut self) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("UPDATE oidc_clients SET enabled=FALSE"))?;
        Ok(())
    }

    /// Idempotently provisions a statically reviewed client and exact URI allowlists.
    pub async fn bootstrap_client(
        &mut self,
        input: &BootstrapOidcClient,
    ) -> Result<(), DatabaseError> {
        validate_bootstrap_client(input)?;
        let scopes =
            serde_json::to_value(&input.allowed_scopes).map_err(|_| DatabaseError::Internal)?;
        let audiences =
            serde_json::to_value(&input.allowed_audiences).map_err(|_| DatabaseError::Internal)?;
        execute!(self, sqlx::query("WITH upsert AS (INSERT INTO oidc_clients(id,display_name,allowed_scopes,allowed_audiences,allow_refresh,enabled,trusted,client_secret_hash) VALUES($1,$2,$3,$4,$5,$8,$9,$10) ON CONFLICT(id) DO UPDATE SET display_name=EXCLUDED.display_name,allowed_scopes=EXCLUDED.allowed_scopes,allowed_audiences=EXCLUDED.allowed_audiences,allow_refresh=EXCLUDED.allow_refresh,enabled=EXCLUDED.enabled,trusted=EXCLUDED.trusted,client_secret_hash=EXCLUDED.client_secret_hash RETURNING id), desired(uri,kind) AS (SELECT unnest($6::text[]),'authorization' UNION ALL SELECT unnest($7::text[]),'post_logout'), inserted AS (INSERT INTO oidc_redirect_uris(client_id,uri,kind) SELECT $1,d.uri,d.kind FROM desired d,upsert ON CONFLICT DO NOTHING RETURNING uri), removed AS (DELETE FROM oidc_redirect_uris r WHERE r.client_id=$1 AND NOT EXISTS (SELECT 1 FROM desired d WHERE d.uri=r.uri AND d.kind=r.kind) RETURNING uri) SELECT id FROM upsert")
            .bind(&input.id).bind(&input.display_name).bind(scopes).bind(audiences).bind(input.allow_refresh).bind(&input.redirect_uris).bind(&input.post_logout_uris).bind(input.enabled).bind(input.trusted).bind(&input.client_secret_hash))?;
        Ok(())
    }

    pub async fn find_client(
        &mut self,
        id: &str,
    ) -> Result<Option<StoredOidcClient>, DatabaseError> {
        let row = fetch_optional!(self, sqlx::query("SELECT c.id,c.display_name,c.enabled,c.allowed_scopes,c.allowed_audiences,c.allow_refresh,c.trusted,c.client_secret_hash,COALESCE(jsonb_agg(r.uri) FILTER (WHERE r.kind='authorization'),'[]'::jsonb) AS redirect_uris,COALESCE(jsonb_agg(r.uri) FILTER (WHERE r.kind='post_logout'),'[]'::jsonb) AS post_logout_uris FROM oidc_clients c LEFT JOIN oidc_redirect_uris r ON r.client_id=c.id WHERE c.id=$1 GROUP BY c.id").bind(id))?;
        row.map(|row| {
            let strings = |column| -> Result<Vec<String>, DatabaseError> {
                serde_json::from_value(
                    row.try_get(column)
                        .map_err(|_| DatabaseError::InvalidStoredData)?,
                )
                .map_err(|_| DatabaseError::InvalidStoredData)
            };
            Ok(StoredOidcClient {
                id: row
                    .try_get("id")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                display_name: row
                    .try_get("display_name")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                enabled: row
                    .try_get("enabled")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                trusted: row
                    .try_get("trusted")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                client_secret_hash: row
                    .try_get("client_secret_hash")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
                redirect_uris: strings("redirect_uris")?,
                post_logout_uris: strings("post_logout_uris")?,
                allowed_scopes: strings("allowed_scopes")?,
                allowed_audiences: strings("allowed_audiences")?,
                allow_refresh: row
                    .try_get("allow_refresh")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            })
        })
        .transpose()
    }

    pub async fn insert_code(
        &mut self,
        input: &InsertAuthorizationCode,
    ) -> Result<(), DatabaseError> {
        let scopes = serde_json::to_value(&input.scopes).map_err(|_| DatabaseError::Internal)?;
        execute!(self, sqlx::query("INSERT INTO authorization_codes(id,secret_digest,client_id,user_id,session_id,redirect_uri,pkce_challenge,nonce,scopes,audience,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(input.id.as_uuid()).bind(&input.secret_digest).bind(&input.client_id)
            .bind(input.user_id.as_uuid()).bind(input.session_id.as_uuid()).bind(&input.redirect_uri)
            .bind(&input.pkce_challenge).bind(&input.nonce).bind(scopes).bind(&input.audience).bind(input.expires_at))?;
        Ok(())
    }

    pub async fn insert_authorization_request(
        &mut self,
        input: &InsertAuthorizationRequest,
    ) -> Result<(), DatabaseError> {
        let scopes = serde_json::to_value(&input.scopes).map_err(|_| DatabaseError::Internal)?;
        execute!(self, sqlx::query("INSERT INTO authorization_requests(id,secret_digest,client_id,redirect_uri,client_state,nonce,pkce_challenge,scopes,audience,force_login,max_age,expires_at,force_consent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
            .bind(input.id.as_uuid()).bind(&input.secret_digest).bind(&input.client_id)
            .bind(&input.redirect_uri).bind(&input.client_state).bind(&input.nonce)
            .bind(&input.pkce_challenge).bind(scopes).bind(&input.audience)
            .bind(input.force_login).bind(input.max_age).bind(input.expires_at).bind(input.force_consent))?;
        Ok(())
    }

    pub async fn find_authorization_request(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<Option<StoredAuthorizationRequest>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT r.id,r.client_id,c.display_name AS client_display_name,r.redirect_uri,r.client_state,r.nonce,r.pkce_challenge,r.scopes,r.audience,r.force_login,r.force_consent,r.max_age,r.created_at FROM authorization_requests r JOIN oidc_clients c ON c.id=r.client_id WHERE r.id=$1 AND r.secret_digest=$2 AND r.consumed_at IS NULL AND r.expires_at>now() AND c.enabled").bind(id.as_uuid()).bind(digest))?.map(|row| stored_authorization_request(&row)).transpose()
    }

    pub async fn consume_authorization_request(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<StoredAuthorizationRequest, DatabaseError> {
        let row = fetch_optional!(self, sqlx::query("UPDATE authorization_requests r SET consumed_at=now() FROM oidc_clients c WHERE r.id=$1 AND r.secret_digest=$2 AND r.consumed_at IS NULL AND r.expires_at>now() AND c.id=r.client_id AND c.enabled AND c.allowed_scopes @> r.scopes AND c.allowed_audiences ? r.audience AND EXISTS(SELECT 1 FROM oidc_redirect_uris d WHERE d.client_id=c.id AND d.kind='authorization' AND d.uri=r.redirect_uri) RETURNING r.id,r.client_id,c.display_name AS client_display_name,r.redirect_uri,r.client_state,r.nonce,r.pkce_challenge,r.scopes,r.audience,r.force_login,r.force_consent,r.max_age,r.created_at").bind(id.as_uuid()).bind(digest))?.ok_or(DatabaseError::NotFound)?;
        stored_authorization_request(&row)
    }

    pub async fn consume_code(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<ConsumedAuthorizationCode, DatabaseError> {
        let row = fetch_optional!(self, sqlx::query("UPDATE authorization_codes c SET consumed_at=now() FROM oidc_clients cl,sessions s,users u WHERE c.id=$1 AND c.secret_digest=$2 AND c.consumed_at IS NULL AND c.expires_at>now() AND cl.id=c.client_id AND cl.enabled AND cl.allowed_scopes @> c.scopes AND cl.allowed_audiences ? c.audience AND EXISTS(SELECT 1 FROM oidc_redirect_uris d WHERE d.client_id=cl.id AND d.kind='authorization' AND d.uri=c.redirect_uri) AND s.id=c.session_id AND s.revoked_at IS NULL AND s.expires_at>now() AND u.id=c.user_id AND u.status='active' RETURNING c.client_id,c.user_id,c.session_id,c.redirect_uri,c.pkce_challenge,c.nonce,c.scopes,c.audience").bind(id.as_uuid()).bind(digest))?.ok_or(DatabaseError::NotFound)?;
        Ok(ConsumedAuthorizationCode {
            client_id: row
                .try_get("client_id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            user_id: UserId::from_uuid(
                row.try_get("user_id")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            )
            .map_err(|_| DatabaseError::InvalidStoredData)?,
            session_id: SessionId::from_uuid(
                row.try_get("session_id")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            )
            .map_err(|_| DatabaseError::InvalidStoredData)?,
            redirect_uri: row
                .try_get("redirect_uri")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            pkce_challenge: row
                .try_get("pkce_challenge")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            nonce: row
                .try_get("nonce")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            scopes: serde_json::from_value(
                row.try_get("scopes")
                    .map_err(|_| DatabaseError::InvalidStoredData)?,
            )
            .map_err(|_| DatabaseError::InvalidStoredData)?,
            audience: row
                .try_get("audience")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        })
    }
}

fn validate_bootstrap_client(input: &BootstrapOidcClient) -> Result<(), DatabaseError> {
    let identifier = |value: &str| {
        (1..=64).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    let redirect = |value: &str| {
        url::Url::parse(value).is_ok_and(|url| {
            (url.scheme() == "https"
                || (url.scheme() == "http"
                    && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))))
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        })
    };
    let valid = input
        .client_secret_hash
        .as_ref()
        .is_none_or(|hash| hash.len() == 32)
        && identifier(&input.id)
        && !input.display_name.trim().is_empty()
        && input.display_name.chars().count() <= 80
        && !input.redirect_uris.is_empty()
        && input.redirect_uris.len() <= 16
        && input.post_logout_uris.len() <= 16
        && input.redirect_uris.iter().all(|uri| redirect(uri))
        && input.post_logout_uris.iter().all(|uri| redirect(uri))
        && !input.allowed_scopes.is_empty()
        && input.allowed_scopes.len() <= 32
        && input.allowed_scopes.iter().all(|scope| identifier(scope))
        && !input.allowed_audiences.is_empty()
        && input.allowed_audiences.len() <= 16
        && input
            .allowed_audiences
            .iter()
            .all(|audience| identifier(audience));
    valid.then_some(()).ok_or(DatabaseError::Conflict)
}

fn stored_authorization_request(
    row: &sqlx::postgres::PgRow,
) -> Result<StoredAuthorizationRequest, DatabaseError> {
    Ok(StoredAuthorizationRequest {
        id: TokenId::from_uuid(
            row.try_get("id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        client_id: row
            .try_get("client_id")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        client_display_name: row
            .try_get("client_display_name")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        redirect_uri: row
            .try_get("redirect_uri")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        client_state: row
            .try_get("client_state")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        nonce: row
            .try_get("nonce")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        pkce_challenge: row
            .try_get("pkce_challenge")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        scopes: serde_json::from_value(
            row.try_get("scopes")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        audience: row
            .try_get("audience")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        force_consent: row
            .try_get("force_consent")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        force_login: row
            .try_get("force_login")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        max_age: row
            .try_get("max_age")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
    })
}

impl TokenRepository<'_> {
    pub async fn insert_family(
        &mut self,
        family: &InsertRefreshFamily,
        token: &InsertRefreshToken,
    ) -> Result<(), DatabaseError> {
        let scopes = serde_json::to_value(&family.scopes).map_err(|_| DatabaseError::Internal)?;
        execute!(self, sqlx::query("INSERT INTO refresh_token_families(id,user_id,client_id,session_id,audience,scopes) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(family.id.as_uuid()).bind(family.user_id.as_uuid()).bind(&family.client_id)
            .bind(family.session_id.as_uuid()).bind(&family.audience).bind(scopes))?;
        self.insert_token(token).await
    }

    pub async fn insert_token(&mut self, token: &InsertRefreshToken) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("INSERT INTO refresh_tokens(id,family_id,secret_digest,expires_at) VALUES($1,$2,$3,$4)")
            .bind(token.id.as_uuid()).bind(token.family_id.as_uuid()).bind(&token.secret_digest).bind(token.expires_at))?;
        Ok(())
    }

    pub async fn consume_for_rotation(
        &mut self,
        id: TokenId,
        digest: &[u8],
        client: &str,
    ) -> Result<RotatedRefreshToken, RefreshRotationError> {
        let row = fetch_optional!(self, sqlx::query("SELECT t.family_id,t.consumed_at,f.user_id,f.client_id,f.session_id,f.audience,f.scopes,c.allow_refresh,c.allowed_scopes,c.allowed_audiences FROM refresh_tokens t JOIN refresh_token_families f ON f.id=t.family_id JOIN oidc_clients c ON c.id=f.client_id JOIN sessions s ON s.id=f.session_id JOIN users u ON u.id=f.user_id WHERE t.id=$1 AND t.secret_digest=$2 AND f.client_id=$3 AND t.expires_at>now() AND f.revoked_at IS NULL AND c.enabled AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active' FOR UPDATE OF t,f,c,s,u").bind(id.as_uuid()).bind(digest).bind(client)).map_err(RefreshRotationError::database)?.ok_or(RefreshRotationError::Invalid)?;
        let family_uuid: uuid::Uuid = row
            .try_get("family_id")
            .map_err(RefreshRotationError::database)?;
        let user_id = UserId::from_uuid(
            row.try_get("user_id")
                .map_err(RefreshRotationError::database)?,
        )
        .map_err(RefreshRotationError::database)?;
        if row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("consumed_at")
            .map_err(RefreshRotationError::database)?
            .is_some()
        {
            execute!(self, sqlx::query("UPDATE refresh_token_families SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL").bind(family_uuid)).map_err(RefreshRotationError::database)?;
            return Err(RefreshRotationError::Replay { user_id });
        }
        let family_scopes: Vec<String> = serde_json::from_value(
            row.try_get("scopes")
                .map_err(RefreshRotationError::database)?,
        )
        .map_err(RefreshRotationError::database)?;
        let allowed_scopes: Vec<String> = serde_json::from_value(
            row.try_get("allowed_scopes")
                .map_err(RefreshRotationError::database)?,
        )
        .map_err(RefreshRotationError::database)?;
        let allowed_audiences: Vec<String> = serde_json::from_value(
            row.try_get("allowed_audiences")
                .map_err(RefreshRotationError::database)?,
        )
        .map_err(RefreshRotationError::database)?;
        let audience: String = row
            .try_get("audience")
            .map_err(RefreshRotationError::database)?;
        let policy_valid = row
            .try_get::<bool, _>("allow_refresh")
            .map_err(RefreshRotationError::database)?
            && allowed_audiences.contains(&audience)
            && family_scopes
                .iter()
                .all(|scope| allowed_scopes.contains(scope));
        if !policy_valid {
            execute!(self, sqlx::query("UPDATE refresh_token_families SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL").bind(family_uuid)).map_err(RefreshRotationError::database)?;
            return Err(RefreshRotationError::Policy { user_id });
        }
        if execute!(
            self,
            sqlx::query(
                "UPDATE refresh_tokens SET consumed_at=now() WHERE id=$1 AND consumed_at IS NULL"
            )
            .bind(id.as_uuid())
        )
        .map_err(RefreshRotationError::database)?
        .rows_affected()
            != 1
        {
            return Err(RefreshRotationError::Invalid);
        }
        Ok(RotatedRefreshToken {
            family_id: TokenId::from_uuid(family_uuid).map_err(RefreshRotationError::database)?,
            user_id,
            client_id: row
                .try_get("client_id")
                .map_err(RefreshRotationError::database)?,
            session_id: SessionId::from_uuid(
                row.try_get("session_id")
                    .map_err(RefreshRotationError::database)?,
            )
            .map_err(RefreshRotationError::database)?,
            audience,
            scopes: family_scopes,
        })
    }

    pub async fn revoke_family_for_token(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("UPDATE refresh_token_families f SET revoked_at=COALESCE(revoked_at,now()) FROM refresh_tokens t WHERE t.id=$1 AND t.secret_digest=$2 AND t.family_id=f.id").bind(id.as_uuid()).bind(digest))?;
        Ok(())
    }

    pub async fn revoke_all_for_user(&mut self, user_id: UserId) -> Result<u64, DatabaseError> {
        Ok(execute!(self, sqlx::query("UPDATE refresh_token_families SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL").bind(user_id.as_uuid()))?.rows_affected())
    }
}

impl OidcRepository<'_> {
    pub async fn consented(
        &mut self,
        user: UserId,
        client: &str,
        audience: &str,
        scopes: &[String],
    ) -> Result<bool, DatabaseError> {
        let scopes = serde_json::to_value(scopes).map_err(|_| DatabaseError::Internal)?;
        Ok(fetch_optional!(self, sqlx::query("SELECT 1 FROM oidc_consents WHERE user_id=$1 AND client_id=$2 AND audience=$3 AND scopes @> $4").bind(user.as_uuid()).bind(client).bind(audience).bind(scopes))?.is_some())
    }
    pub async fn save_consent(
        &mut self,
        user: UserId,
        client: &str,
        audience: &str,
        scopes: &[String],
    ) -> Result<(), DatabaseError> {
        let scopes = serde_json::to_value(scopes).map_err(|_| DatabaseError::Internal)?;
        execute!(self, sqlx::query("INSERT INTO oidc_consents(user_id,client_id,audience,scopes) VALUES($1,$2,$3,$4) ON CONFLICT(user_id,client_id,audience) DO UPDATE SET scopes=(SELECT jsonb_agg(DISTINCT value) FROM jsonb_array_elements(oidc_consents.scopes || EXCLUDED.scopes))").bind(user.as_uuid()).bind(client).bind(audience).bind(scopes))?;
        Ok(())
    }
    pub async fn primary_email(&mut self, user: UserId) -> Result<Option<String>, DatabaseError> {
        fetch_optional!(self,sqlx::query("SELECT normalized_email FROM user_emails WHERE user_id=$1 AND verified_at IS NOT NULL ORDER BY is_primary DESC,created_at LIMIT 1").bind(user.as_uuid()))?.map(|row| row.try_get("normalized_email").map_err(|_| DatabaseError::InvalidStoredData)).transpose()
    }
    pub async fn revoke_session(&mut self, session: SessionId) -> Result<(), DatabaseError> {
        execute!(
            self,
            sqlx::query("UPDATE sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1")
                .bind(session.as_uuid())
        )?;
        execute!(self,sqlx::query("UPDATE refresh_token_families SET revoked_at=COALESCE(revoked_at,now()) WHERE session_id=$1").bind(session.as_uuid()))?;
        Ok(())
    }
}

impl TokenRepository<'_> {
    pub async fn revoke_family_for_client_token(
        &mut self,
        id: TokenId,
        digest: &[u8],
        client: &str,
    ) -> Result<(), DatabaseError> {
        execute!(self,sqlx::query("UPDATE refresh_token_families f SET revoked_at=COALESCE(revoked_at,now()) FROM refresh_tokens t WHERE t.id=$1 AND t.secret_digest=$2 AND t.family_id=f.id AND f.client_id=$3").bind(id.as_uuid()).bind(digest).bind(client))?;
        Ok(())
    }
}
