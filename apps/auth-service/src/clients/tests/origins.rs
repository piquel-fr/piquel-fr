//! Related origins: counting their registrable domains, and approving them.
use super::*;

/// Browsers count a related origin by its registrable domain's first label, so
/// `example.co.uk` is `example`, also within auth's own domain. An origin without
/// a registrable domain counts none within auth's domain, and is refused elsewhere.
#[test]
fn related_origins_count_registrable_domain_labels() {
    let domain = |origin: &str| {
        ClientRegistry::domain(&origin.parse().expect("origin"), "auth.sourceorigin.dev")
            .expect("countable origin")
    };
    assert_eq!(
        domain("https://app.example.co.uk").as_deref(),
        Some("example")
    );
    assert_eq!(
        domain("https://notes.alice.github.io").as_deref(),
        Some("alice")
    );
    assert_eq!(
        domain("https://sourceorigin.dev").as_deref(),
        Some("sourceorigin")
    );
    assert_eq!(
        domain("https://notes.auth.sourceorigin.dev").as_deref(),
        Some("sourceorigin")
    );
    let localhost = "https://localhost:4443".parse().expect("origin");
    assert_eq!(
        ClientRegistry::domain(&localhost, "localhost").expect("countable origin"),
        None
    );
    for public in ["https://github.io", "https://localhost"] {
        assert!(matches!(
            ClientRegistry::domain(&public.parse().expect("origin"), "auth.sourceorigin.dev"),
            Err(ClientRegistryError::PublicSuffix(_))
        ));
    }
}

/// Only a trusted client's redirect origins are approved, each once, and approved
/// origins never span more domains than every browser honours. Deleting the client
/// removes its origins.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn origin_approval_needs_trust_a_redirect_origin_and_few_domains() {
    let database = Replicas::database().await;
    let unique = UserId::new();
    // Six registrable domains, then a second origin on the first one.
    let mut origins: Vec<RelatedOrigin> = (0..6)
        .map(|domain| format!("https://d{domain}-{unique}.example"))
        .chain([format!("https://www.d0-{unique}.example")])
        .map(|origin| origin.parse().expect("origin"))
        .collect();
    let inside: RelatedOrigin = format!("https://{unique}.auth.sourceorigin.dev")
        .parse()
        .expect("origin");
    origins.push(inside.clone());
    let client = ClientRegistration {
        redirect_uris: RedirectUris::new(
            origins
                .iter()
                .map(|origin| format!("{origin}/callback").parse().expect("callback")),
        )
        .expect("callbacks"),
        ..registration(ClientKind::Public, inside.as_str())
    };
    register(&database, &client).await.expect("client");
    let approve = async |origin: &RelatedOrigin| {
        change(&database, async |registry| {
            registry
                .approve_origin(&client.id, origin, "auth.sourceorigin.dev")
                .await
        })
        .await
    };
    let remove = async |origin: &RelatedOrigin| {
        change(&database, async |registry| {
            registry.remove_origin(&client.id, origin).await
        })
        .await
    };
    assert!(matches!(
        approve(&inside).await,
        Err(ClientRegistryError::Untrusted(_))
    ));
    replace(
        &database,
        &ClientRegistration {
            trusted: true,
            ..client.clone()
        },
    )
    .await
    .expect("trusted");
    let elsewhere = format!("https://elsewhere-{unique}.auth.sourceorigin.dev")
        .parse()
        .expect("origin");
    assert!(matches!(
        approve(&elsewhere).await,
        Err(ClientRegistryError::NotRedirectOrigin { .. })
    ));
    approve(&inside)
        .await
        .expect("an origin within auth's domain");
    assert!(matches!(
        approve(&inside).await,
        Err(ClientRegistryError::OriginApproved { .. })
    ));
    let mut approved = Vec::new();
    let error = loop {
        match approve(&origins[approved.len()]).await {
            Ok(()) => approved.push(origins[approved.len()].clone()),
            Err(error) => break error,
        }
    };
    let ClientRegistryError::TooManyDomains(domains) = error else {
        panic!("a sixth domain is refused, not {error}");
    };
    assert_eq!(domains.len(), MAX_RELATED_ORIGIN_DOMAINS + 1);
    // Other tests' origins within auth's domain count as `sourceorigin`, and a database
    // other runs left full refuses the first domain. Otherwise another origin on an
    // approved domain still fits.
    if !approved.is_empty() {
        approve(&origins[6])
            .await
            .expect("an already counted domain");
        approved.push(origins[6].clone());
    }
    approved.push(inside.clone());
    for origin in &approved {
        remove(origin).await.expect("removed");
    }
    assert!(matches!(
        remove(&approved[0]).await,
        Err(ClientRegistryError::OriginNotApproved { .. })
    ));

    // Clients are tombstoned, so a trigger, not the query, removes the origins of a
    // deleted one, whichever release deleted it.
    approve(&inside).await.expect("approved again");
    change(&database, async |registry| {
        registry.delete(&client.id).await
    })
    .await
    .expect("deleted");
    let approved = database.oidc().related_origins().await.expect("origins");
    assert!(approved.iter().all(|origin| origin.client_id != client.id));
}
