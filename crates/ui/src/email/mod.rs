//! The emails Origin Auth sends, as blocks of what they say, rendered twice: as
//! the HTML body, styled inline since mail clients drop stylesheets, and as the
//! plain-text body. Each sentence is written once, so the two bodies cannot say
//! different things. The dashboard previews an email from the same blocks
//! ([`email_preview`]).
//!
//! ```
//! use sourceorigin_ui::{Block, Inline, Mail, inlines};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> topcoat::Result<()> {
//! let mail = Mail {
//!     subject: "Recover your Origin Account".into(),
//!     blocks: vec![
//!         Block::Paragraph(inlines!["Support started a recovery of ", Inline::Strong("@alice".into()), "."]),
//!         Block::Action { label: "Add a passkey", href: "https://auth.example/recover".into() },
//!     ],
//! };
//! assert!(mail.text().contains("Add a passkey:\n\nhttps://auth.example/recover"));
//! assert!(mail.html().await?.contains("<strong>@alice</strong>"));
//! # Ok(())
//! # }
//! ```

pub use content::EmailContent;

use crate::layout::announcement_text;
use sourceorigin_common::admin::Announcement;
use std::{borrow::Cow, iter};
use topcoat::{
    Result,
    context::Cx,
    view::{View, ViewExt, component, view},
};

// The email's styles. The dashboard's preview, whose policy forbids inline
// styles, draws the same with `.email-preview` in `assets/style/base.css`.

/// The `<body>`'s style: the page every email is read on.
const BODY: &str = "margin:0;padding:24px;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:16px;line-height:1.5;color:#1a1a1a;background:#ffffff";
/// The column the text reads in.
const COLUMN: &str = "max-width:560px;margin:0 auto";
/// An action's button.
const BUTTON: &str = "display:inline-block;padding:10px 18px;border-radius:8px;background:#1a1a1a;color:#ffffff;text-decoration:none";
/// Small print.
const FINE: &str = "font-size:14px;color:#555555";

/// How an email's blocks are styled: inline, in the email itself, or by the
/// stylesheet's `.email-preview` rules, in the dashboard's preview.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Look {
    /// Inline `style` attributes, which mail clients keep.
    Inline,
    /// Classes, which the dashboard's stylesheet draws.
    Classes,
}

impl Look {
    /// The `style` of an element styled `style` in the email itself.
    fn style(self, style: &'static str) -> Option<&'static str> {
        (self == Self::Inline).then_some(style)
    }

    /// The `class` of an element in the preview.
    fn class(self, class: &'static str) -> Option<&'static str> {
        (self == Self::Classes).then_some(class)
    }
}

/// An email: its subject, and what it says between the greeting and the
/// sign-off every email shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mail {
    /// The subject, which the HTML body's title repeats.
    pub subject: String,
    /// What it says, in order.
    pub blocks: Vec<Block>,
}

/// A part of an email, which each body renders its own way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    /// A paragraph. Its links' addresses follow it in the plain-text body, each
    /// on a line of its own.
    Paragraph(Vec<Inline>),
    /// Text kept as written, such as an administrator's message or a
    /// notification's body, as the inbox shows it: its paragraphs and line
    /// breaks are kept, and nothing in it is markup.
    Written(String),
    /// What the email asks the reader to do: a button, with its address to copy
    /// below it, or, in plain text, `label` and then the address.
    Action {
        /// The button's label.
        label: &'static str,
        /// Where it goes.
        href: String,
    },
    /// Small print, such as why the reader received the email, read like a
    /// [`Block::Paragraph`].
    Fine(Vec<Inline>),
}

/// A run of text within a paragraph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inline {
    /// Plain text.
    Text(Cow<'static, str>),
    /// Text in bold in HTML, such as an address or a handle.
    Strong(Cow<'static, str>),
    /// A link, whose address the plain-text body gives after its paragraph.
    Link {
        /// What the link says.
        text: &'static str,
        /// Where it goes.
        href: String,
    },
}

impl From<&'static str> for Inline {
    fn from(text: &'static str) -> Self {
        Self::Text(text.into())
    }
}

impl From<String> for Inline {
    fn from(text: String) -> Self {
        Self::Text(text.into())
    }
}

/// The runs of a paragraph, each anything that converts into an [`Inline`]:
/// `inlines!["Hello ", Inline::Strong(name.into()), "."]`.
#[macro_export]
macro_rules! inlines {
    ($($inline:expr),* $(,)?) => {
        vec![$($crate::Inline::from($inline)),*]
    };
}

impl Mail {
    /// The plain-text body: the greeting, each block, and the sign-off, a blank
    /// line apart. A link's address follows its paragraph, so a reader can open
    /// it whatever their client shows.
    #[must_use]
    pub fn text(&self) -> String {
        let blocks = self.blocks.iter().map(Block::text);
        iter::once("Hello,".to_owned())
            .chain(blocks)
            .chain(iter::once("SourceOrigin".to_owned()))
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// The HTML body: a whole document, styled inline, with no images, scripts
    /// or remote resources.
    ///
    /// # Errors
    /// Fails when the view cannot render.
    pub async fn html(&self) -> Result<String> {
        let cx = Cx::default();
        Ok(view! { cx => email(mail: self) }
            .single()
            .await?
            .render(&cx))
    }
}

impl Block {
    /// The block in the plain-text body, its paragraphs a blank line apart.
    fn text(&self) -> String {
        match self {
            Self::Paragraph(inlines) | Self::Fine(inlines) => {
                let said: String = inlines.iter().map(Inline::text).collect();
                let hrefs = inlines.iter().filter_map(Inline::href).map(str::to_owned);
                iter::once(said)
                    .chain(hrefs)
                    .collect::<Vec<_>>()
                    .join("\n\n")
            }
            Self::Written(written) => Announcement::paragraphs(written)
                .iter()
                .map(|lines| lines.join("\n"))
                .collect::<Vec<_>>()
                .join("\n\n"),
            Self::Action { label, href } => format!("{label}:\n\n{href}"),
        }
    }
}

impl Inline {
    /// What it says in the plain-text body.
    fn text(&self) -> &str {
        match self {
            Self::Text(run) | Self::Strong(run) => run,
            Self::Link { text, .. } => text,
        }
    }

    /// Where it links, if it is a link.
    fn href(&self) -> Option<&str> {
        match self {
            Self::Link { href, .. } => Some(href),
            Self::Text(_) | Self::Strong(_) => None,
        }
    }
}

/// An email's HTML document.
#[component]
async fn email<'a>(mail: &'a Mail) -> Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>(mail.subject.as_str())</title>
            </head>
            <body style=(BODY)>
                <div style=(COLUMN)>
                    mail_body(mail: mail, look: Look::Inline)
                </div>
            </body>
        </html>
    })
}

/// An email as the dashboard shows it before it is sent: what its HTML body
/// says, drawn by the stylesheet, and its plain-text body below, folded.
#[component]
pub async fn email_preview<'a>(mail: &'a Mail) -> Result<impl View> {
    Ok(view! {
        <div class="email-preview">
            mail_body(mail: mail, look: Look::Classes)
        </div>
        <details class="email-text">
            <summary>"Plain-text version"</summary>
            <pre class="email">(mail.text())</pre>
        </details>
    })
}

/// What an email says, between its greeting and its sign-off, styled by `look`.
#[component]
async fn mail_body<'a>(mail: &'a Mail, look: Look) -> Result<impl View> {
    Ok(view! {
        <p>"Hello,"</p>
        for block in &mail.blocks {
            match block {
                Block::Paragraph(inlines) => {
                    <p>runs(inlines: inlines)</p>
                }
                Block::Written(written) => {
                    announcement_text(body: written)
                }
                Block::Action { label, href } => {
                    <p>
                        <a href=(href.as_str()) style=(look.style(BUTTON)) class=(look.class("email-button"))>
                            (*label)
                        </a>
                    </p>
                    <p style=(look.style(FINE)) class=(look.class("email-fine"))>
                        "Or copy this link: " (href.as_str())
                    </p>
                }
                Block::Fine(inlines) => {
                    <p style=(look.style(FINE)) class=(look.class("email-fine"))>runs(inlines: inlines)</p>
                }
            }
        }
        <p>"SourceOrigin"</p>
    })
}

/// A paragraph's runs.
#[component]
async fn runs<'a>(inlines: &'a [Inline]) -> Result<impl View> {
    Ok(view! {
        for inline in inlines {
            match inline {
                Inline::Text(run) => {
                    (run.as_ref())
                }
                Inline::Strong(run) => {
                    <strong>(run.as_ref())</strong>
                }
                Inline::Link { text, href } => {
                    <a href=(href.as_str())>(*text)</a>
                }
            }
        }
    })
}

/// What each kind of email says.
mod content;
#[cfg(test)]
mod tests;
