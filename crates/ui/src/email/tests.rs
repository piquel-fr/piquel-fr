//! An email's two bodies.
use super::*;

/// Both bodies say every block, between the greeting and the sign-off: the
/// plain text gives each link's address after its paragraph and an action's
/// after its label, keeps written text's line breaks, and the HTML escapes
/// whatever it shows.
#[tokio::test]
async fn both_bodies_say_every_block() {
    let mail = Mail {
        subject: "Hi <there>".into(),
        blocks: vec![
            Block::Paragraph(inlines![
                "Added ",
                Inline::Strong("a@example.com".into()),
                ". Read it in ",
                Inline::Link {
                    text: "your notifications",
                    href: "https://auth.example/inbox".into(),
                },
                ".",
            ]),
            Block::Written("One\ntwo\n\n\n<three>  ".into()),
            Block::Action {
                label: "Confirm",
                href: "https://auth.example/verify#token=a&b".into(),
            },
            Block::Fine(inlines!["Small print."]),
        ],
    };
    assert_eq!(
        mail.text(),
        "Hello,\n\n\
         Added a@example.com. Read it in your notifications.\n\n\
         https://auth.example/inbox\n\n\
         One\ntwo\n\n<three>\n\n\
         Confirm:\n\nhttps://auth.example/verify#token=a&b\n\n\
         Small print.\n\n\
         SourceOrigin"
    );
    let html = mail.html().await.expect("HTML");
    for expected in [
        "<title>Hi &lt;there&gt;</title>",
        "<p>Hello,</p>",
        r#"<p>Added <strong>a@example.com</strong>. Read it in <a href="https://auth.example/inbox">your notifications</a>.</p>"#,
        "<p>One<br>two</p><p>&lt;three&gt;</p>",
        r#"<a href="https://auth.example/verify#token=a&amp;b" style="display:inline-block;"#,
        ">Confirm</a>",
        "Or copy this link: https://auth.example/verify#token=a&amp;b</p>",
        r#"<p style="font-size:14px;color:#555555">Small print.</p>"#,
        "<p>SourceOrigin</p>",
    ] {
        assert!(html.contains(expected), "{expected} in {html}");
    }
}
