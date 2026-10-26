//! `WWW-Authenticate: Bearer` challenges (RFC 6750 §3, RFC 9470 §3, RFC 9728 §5.1),
//! produced by resource servers and parsed by clients.
//!
//! Parameters are written in one fixed order (`error`, `error_description`, `scope`,
//! `acr_values`, `max_age`, `resource_metadata`) with every value quoted, so every SDK
//! produces byte-identical headers. Parsing follows the RFC 9110 §11 grammar: any
//! parameter order, token or quoted values, and other challenges in the same header,
//! including ones carrying `token68` credentials.
//!
//! ```
//! use piquel_common::protocol::{
//!     challenge::BearerChallenge,
//!     claims::Acr,
//!     step_up::StepUpRequirement,
//! };
//!
//! // A resource server asking for a recent passkey confirmation (RFC 9470).
//! let step_up = BearerChallenge::step_up(StepUpRequirement::passkey_within(300));
//! let header = step_up.to_string();
//! assert_eq!(
//!     header,
//!     r#"Bearer error="insufficient_user_authentication", acr_values="phr", max_age="300""#
//! );
//!
//! // A client reads it back, whatever the order, alongside other schemes. The
//! // requirement's class is the first `acr_values` entry this version knows.
//! let parsed: BearerChallenge =
//!     r#"Basic realm="api", Bearer max_age=300, acr_values="phrh phr", error=insufficient_user_authentication"#
//!         .parse()?;
//! assert_eq!(parsed, step_up);
//! assert_eq!(parsed.step_up.acr, Some(Acr::PhishingResistant));
//! # Ok::<(), piquel_common::protocol::challenge::ChallengeError>(())
//! ```

use super::{
    claims::Acr,
    oauth::{ErrorDescription, Scopes},
    step_up::StepUpRequirement,
};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;
use url::Url;

crate::open_str_enum! {
    /// Bearer `error` codes. Open, since the OAuth Extensions Error Registry grows
    /// (RFC 9470 added one): an unknown code must not hide the rest of a challenge.
    pub enum BearerError {
        /// The request is malformed (RFC 6750 §3.1).
        InvalidRequest = "invalid_request",
        /// The token is expired, revoked, malformed or otherwise invalid (RFC 6750 §3.1).
        InvalidToken = "invalid_token",
        /// The token lacks a scope the request needs (RFC 6750 §3.1).
        InsufficientScope = "insufficient_scope",
        /// The user must authenticate again, more strongly or more recently (RFC 9470 §3).
        InsufficientUserAuthentication = "insufficient_user_authentication",
    }
}

impl BearerError {
    /// HTTP status sent with this error; 401 for a code this version does not know.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::InvalidToken | Self::InsufficientUserAuthentication | Self::Other(_) => 401,
            Self::InsufficientScope => 403,
        }
    }
}

/// The authentication scheme of every challenge here.
const SCHEME: &str = "Bearer";

/// One `Bearer` challenge. Without `error` it means no token was sent (RFC 6750 §3.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BearerChallenge {
    /// What went wrong; `None` when the request carried no token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<BearerError>,
    /// Human-readable detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<ErrorDescription>,
    /// Every scope the request needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scopes>,
    /// The authentication the request needs, as `acr_values` and `max_age`
    /// (RFC 9470 §3). A client asks for it again with
    /// [`StepUpRequirement::authorize_params`].
    #[serde(flatten)]
    pub step_up: StepUpRequirement,
    /// Where the resource's protected resource metadata is served (RFC 9728 §5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_metadata: Option<Url>,
}

/// A `WWW-Authenticate` value that holds no valid `Bearer` challenge.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ChallengeError {
    /// The header breaks the RFC 9110 §11 challenge grammar.
    #[error("WWW-Authenticate is malformed at byte {0}")]
    Syntax(usize),
    /// No challenge uses the `Bearer` scheme.
    #[error("WWW-Authenticate has no Bearer challenge")]
    NotBearer,
    /// A parameter appears twice, which RFC 6750 §3 forbids.
    #[error("Bearer challenge repeats {0}")]
    Duplicate(String),
    /// A known parameter has an invalid value.
    #[error("Bearer challenge has an invalid {0}")]
    InvalidValue(&'static str),
}

impl BearerChallenge {
    /// A challenge for `error`, with no other parameters.
    #[must_use]
    pub fn error(error: BearerError) -> Self {
        Self {
            error: Some(error),
            ..Self::default()
        }
    }

    /// An `insufficient_user_authentication` challenge asking for `requirement`.
    #[must_use]
    pub fn step_up(requirement: StepUpRequirement) -> Self {
        Self {
            step_up: requirement,
            ..Self::error(BearerError::InsufficientUserAuthentication)
        }
    }

    /// HTTP status sent with this challenge: 401 when no token was sent.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.error.as_ref().map_or(401, BearerError::status)
    }

    /// Appends one parameter, quoting and escaping its value. A control character
    /// cannot appear in a header at all, so it is written as `?`: every value but an
    /// unknown [`BearerError`] comes from a validated type, and that one can be built
    /// from any string.
    fn write_parameter(
        formatter: &mut fmt::Formatter<'_>,
        first: &mut bool,
        name: &str,
        value: &str,
    ) -> fmt::Result {
        formatter.write_str(if *first { " " } else { ", " })?;
        *first = false;
        write!(formatter, "{name}=\"")?;
        for character in value.chars() {
            match character {
                '"' | '\\' => write!(formatter, "\\{character}")?,
                _ if character.is_control() && character != '\t' => formatter.write_str("?")?,
                _ => write!(formatter, "{character}")?,
            }
        }
        formatter.write_str("\"")
    }

    /// Builds the challenge from parsed parameters, ignoring unknown ones.
    fn from_parameters(parameters: Vec<(String, String)>) -> Result<Self, ChallengeError> {
        let mut challenge = Self::default();
        let mut seen = Vec::with_capacity(parameters.len());
        for (name, value) in parameters {
            let name = name.to_ascii_lowercase();
            if seen.contains(&name) {
                return Err(ChallengeError::Duplicate(name));
            }
            match name.as_str() {
                "error" => challenge.error = Some(BearerError::from(value.as_str())),
                "error_description" => {
                    challenge.error_description = Some(
                        value
                            .parse()
                            .map_err(|_| ChallengeError::InvalidValue("error_description"))?,
                    );
                }
                // RFC 6750 §3: scope tokens separated by single spaces.
                "scope" => {
                    challenge.scope = Some(
                        value
                            .split(' ')
                            .all(Scopes::is_token)
                            .then(|| value.parse().ok())
                            .flatten()
                            .ok_or(ChallengeError::InvalidValue("scope"))?,
                    );
                }
                // Most preferred first: the target is the first value this version
                // knows, as auth picks it (OIDC Core §3.1.2.1).
                "acr_values" => challenge.step_up.acr = Acr::select(&value),
                "max_age" => {
                    challenge.step_up.max_age = Some(
                        value
                            .parse()
                            .map_err(|_| ChallengeError::InvalidValue("max_age"))?,
                    );
                }
                "resource_metadata" => {
                    challenge.resource_metadata = Some(
                        value
                            .parse()
                            .map_err(|_| ChallengeError::InvalidValue("resource_metadata"))?,
                    );
                }
                _ => {}
            }
            seen.push(name);
        }
        Ok(challenge)
    }
}

impl fmt::Display for BearerChallenge {
    /// Writes the header value, parameters in their fixed order.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SCHEME)?;
        let mut first = true;
        if let Some(error) = &self.error {
            Self::write_parameter(formatter, &mut first, "error", error.as_str())?;
        }
        if let Some(description) = &self.error_description {
            Self::write_parameter(
                formatter,
                &mut first,
                "error_description",
                description.as_str(),
            )?;
        }
        if let Some(scope) = &self.scope {
            Self::write_parameter(formatter, &mut first, "scope", &scope.to_string())?;
        }
        for (name, value) in self.step_up.authorize_params() {
            Self::write_parameter(formatter, &mut first, name, &value)?;
        }
        if let Some(url) = &self.resource_metadata {
            Self::write_parameter(formatter, &mut first, "resource_metadata", url.as_str())?;
        }
        Ok(())
    }
}

impl FromStr for BearerChallenge {
    type Err = ChallengeError;
    /// Finds the `Bearer` challenge in a `WWW-Authenticate` value.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Parser::new(value)
            .challenges()?
            .into_iter()
            .find(|challenge| challenge.scheme.eq_ignore_ascii_case(SCHEME))
            .ok_or(ChallengeError::NotBearer)
            .and_then(|challenge| Self::from_parameters(challenge.parameters))
    }
}

/// One parsed challenge.
struct Challenge {
    /// Authentication scheme.
    scheme: String,
    /// Parameters, in header order.
    parameters: Vec<(String, String)>,
    /// Whether parameters may follow: the scheme was followed by a space, and not by
    /// `token68` credentials.
    accepts_parameters: bool,
}

/// Reads RFC 9110 §11 challenges:
///
/// ```text
/// WWW-Authenticate = 1#challenge
/// challenge        = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param       = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// List elements are separated by commas, and empty elements are allowed (§5.6.1).
struct Parser<'a> {
    /// The whole header value.
    input: &'a [u8],
    /// Next byte to read.
    position: usize,
}

impl<'a> Parser<'a> {
    /// Starts at the beginning of `input`.
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            position: 0,
        }
    }

    /// Every challenge in the header.
    fn challenges(mut self) -> Result<Vec<Challenge>, ChallengeError> {
        let mut challenges: Vec<Challenge> = Vec::new();
        loop {
            self.skip_whitespace();
            match self.peek() {
                None => return Ok(challenges),
                Some(b',') => {
                    self.position += 1;
                    continue;
                }
                Some(_) => {}
            }
            let start = self.position;
            let name = self.token()?;
            let spaced = self.skip_whitespace();
            if self.peek() == Some(b'=') {
                // A parameter continuing the current challenge's list.
                let value = self.value()?;
                challenges
                    .last_mut()
                    .filter(|challenge| challenge.accepts_parameters)
                    .ok_or(ChallengeError::Syntax(start))?
                    .parameters
                    .push((name, value));
            } else {
                // A new challenge, whose credentials follow after a space.
                let mut challenge = Challenge {
                    scheme: name,
                    parameters: Vec::new(),
                    // RFC 9110 §11: credentials follow the scheme after a space.
                    accepts_parameters: spaced,
                };
                if spaced && self.peek().is_some_and(|byte| byte != b',') {
                    if let Some(end) = self.token68_end() {
                        self.position = end;
                        challenge.accepts_parameters = false;
                    } else {
                        let parameter = self.position;
                        let name = self.token()?;
                        self.skip_whitespace();
                        if self.peek() != Some(b'=') {
                            return Err(ChallengeError::Syntax(parameter));
                        }
                        challenge.parameters.push((name, self.value()?));
                    }
                }
                challenges.push(challenge);
            }
            // Every element ends at a comma or the end of the header.
            self.skip_whitespace();
            if self.peek().is_some_and(|byte| byte != b',') {
                return Err(ChallengeError::Syntax(self.position));
            }
        }
    }

    /// The next byte, without consuming it.
    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    /// Consumes bytes while `predicate` holds, returning whether any were consumed.
    fn skip(&mut self, predicate: impl Fn(u8) -> bool) -> bool {
        let start = self.position;
        while self.peek().is_some_and(&predicate) {
            self.position += 1;
        }
        self.position > start
    }

    /// Consumes optional whitespace (`OWS`), returning whether there was any.
    fn skip_whitespace(&mut self) -> bool {
        self.skip(|byte| byte == b' ' || byte == b'\t')
    }

    /// Reads a `token`: one or more RFC 9110 `tchar`s.
    fn token(&mut self) -> Result<String, ChallengeError> {
        let start = self.position;
        if !self.skip(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)) {
            return Err(ChallengeError::Syntax(start));
        }
        Ok(String::from_utf8_lossy(&self.input[start..self.position]).into_owned())
    }

    /// Where a `token68` starting here ends, if what follows is one: base64-like
    /// characters, then `=` padding, then the end of the list element.
    fn token68_end(&self) -> Option<usize> {
        let mut end = self.position;
        let byte = |index: usize| self.input.get(index).copied();
        while byte(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
        {
            end += 1;
        }
        if end == self.position {
            return None;
        }
        while byte(end) == Some(b'=') {
            end += 1;
        }
        let mut next = end;
        while matches!(byte(next), Some(b' ' | b'\t')) {
            next += 1;
        }
        matches!(byte(next), None | Some(b',')).then_some(end)
    }

    /// Reads `BWS "=" BWS ( token / quoted-string )`, from the `=`.
    fn value(&mut self) -> Result<String, ChallengeError> {
        self.position += 1;
        self.skip_whitespace();
        if self.peek() == Some(b'"') {
            self.quoted()
        } else {
            self.token()
        }
    }

    /// Reads a `quoted-string`, resolving `quoted-pair`s. Control characters other
    /// than tab are rejected, as RFC 9110 §5.6.4 requires.
    fn quoted(&mut self) -> Result<String, ChallengeError> {
        let start = self.position;
        let text = |byte: u8| byte == b'\t' || (byte >= 0x20 && byte != 0x7F);
        self.position += 1;
        let mut value = Vec::new();
        loop {
            match self.peek() {
                Some(b'"') => {
                    self.position += 1;
                    return String::from_utf8(value).map_err(|_| ChallengeError::Syntax(start));
                }
                Some(b'\\') => {
                    self.position += 1;
                    match self.peek() {
                        Some(byte) if text(byte) => value.push(byte),
                        _ => return Err(ChallengeError::Syntax(start)),
                    }
                    self.position += 1;
                }
                Some(byte) if text(byte) => {
                    value.push(byte);
                    self.position += 1;
                }
                _ => return Err(ChallengeError::Syntax(start)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Challenge syntax at the parser's edges; the shared vectors cover the formats.
    use super::*;

    /// Other schemes, `token68` credentials, escapes and unknown parameters do not hide
    /// the Bearer challenge.
    #[test]
    fn finds_bearer_among_challenges() {
        let challenge: BearerChallenge =
            r#"Negotiate YWJjZA==, Basic realm="a, b", bearer error = invalid_token, error_description="say \'hi\'", foo=bar"#
                .parse()
                .expect("Bearer challenge");
        assert_eq!(challenge.error, Some(BearerError::InvalidToken));
        assert_eq!(
            challenge
                .error_description
                .as_ref()
                .map(ErrorDescription::as_str),
            Some("say 'hi'")
        );
        assert_eq!(
            challenge.to_string(),
            r#"Bearer error="invalid_token", error_description="say 'hi'""#
        );
    }

    /// No value can break the header: control characters are written as `?`.
    #[test]
    fn formatting_never_emits_control_characters() {
        let challenge = BearerChallenge::error(BearerError::from("new_error\r\nX-Test: yes"));
        assert_eq!(
            challenge.to_string(),
            r#"Bearer error="new_error??X-Test: yes""#
        );
    }

    /// Malformed, repeated or non-Bearer headers are rejected.
    #[test]
    fn rejects_invalid_headers() {
        for (header, expected) in [
            ("Basic realm=\"x\"", ChallengeError::NotBearer),
            ("Bearer error=\"unterminated", ChallengeError::Syntax(13)),
            ("=x", ChallengeError::Syntax(0)),
            ("Bearer error=\"a\"scope=\"b\"", ChallengeError::Syntax(16)),
            ("Bearer error=\"a\r\nb\"", ChallengeError::Syntax(13)),
            ("Negotiate abc==, error=x", ChallengeError::Syntax(17)),
            ("Bearer,error=x", ChallengeError::Syntax(7)),
            (
                "Bearer scope=\"a\tb\"",
                ChallengeError::InvalidValue("scope"),
            ),
            (
                "Bearer scope=a, scope=b",
                ChallengeError::Duplicate("scope".into()),
            ),
            (
                "Bearer max_age=soon",
                ChallengeError::InvalidValue("max_age"),
            ),
            (
                "Bearer error_description=\"say \\\"hi\\\"\"",
                ChallengeError::InvalidValue("error_description"),
            ),
        ] {
            assert_eq!(header.parse::<BearerChallenge>(), Err(expected), "{header}");
        }
    }
}
