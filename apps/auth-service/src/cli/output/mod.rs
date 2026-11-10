//! How commands print, the way piquelctl does: a command's result on standard
//! output, everything else on standard error.
//!
//! A result is a [`Report`]: its JSON for scripts with `--json`, and how people
//! read it, written through a [`HumanWriter`]. The writer escapes every value,
//! so text an account controls, such as a display name, cannot drive the
//! terminal, and aligns tables. Messages, prompts and failures go to standard
//! error as `Info:`, `Warning:` and `Error:` lines, or with `--json` as one
//! [`Event`] per line. Colour is used only on a terminal, unless `NO_COLOR` is
//! set or `TERM` is `dumb`.

#[cfg(test)]
mod tests;

use super::CliError;
use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeMap};
use sourceorigin_common::{
    AccountStatus,
    admin::{DeliveryStatus, Paging, SigningKeyState},
    alerts::AlertState,
};
use std::{
    error::Error,
    fmt,
    io::{self, BufRead, IsTerminal, Write},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

/// A command's result: its JSON for scripts, and how people read it.
pub(super) trait Report {
    /// What `--json` prints.
    type Json: Serialize + ?Sized;
    /// The value `--json` prints.
    fn json(&self) -> &Self::Json;
    /// Writes the result for people.
    fn human(&self, out: &mut HumanWriter<'_>) -> io::Result<()>;
}

// Implements `Report` with the block as `human`. The JSON is the value itself,
// or one of its fields:
//
// report!(Type, self, out, { ... })                    // Json = Type
// report!(Wrapper as Inner = field, self, out, { ... }) // Json = Inner, from `self.field`
macro_rules! report {
    (@impl $ty:ty, $json:ty, |$this:ident| $value:expr, $out:ident, $body:block) => {
        impl $crate::cli::output::Report for $ty {
            type Json = $json;
            fn json(&$this) -> &$json {
                $value
            }
            fn human(
                &$this,
                $out: &mut $crate::cli::output::HumanWriter<'_>,
            ) -> std::io::Result<()> $body
        }
    };
    ($ty:ty as $json:ty = $field:tt, $this:ident, $out:ident, $body:block) => {
        $crate::cli::output::report!(@impl $ty, $json, |$this| &$this.$field, $out, $body);
    };
    ($ty:ty, $this:ident, $out:ident, $body:block) => {
        $crate::cli::output::report!(@impl $ty, Self, |$this| $this, $out, $body);
    };
}
pub(super) use report;

/// One value a command makes, such as a link, a secret or an ID: alone on its
/// line for people, so a script can capture it, and `{"<name>": value}` with
/// `--json`.
pub(super) struct Single<T> {
    /// Its key in JSON.
    pub(super) name: &'static str,
    /// The value.
    pub(super) value: T,
}

impl<T: Serialize> Serialize for Single<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(self.name, &self.value)?;
        map.end()
    }
}

impl<T: Serialize + fmt::Display> Report for Single<T> {
    type Json = Self;

    fn json(&self) -> &Self {
        self
    }

    fn human(&self, out: &mut HumanWriter<'_>) -> io::Result<()> {
        out.line(&self.value)
    }
}

/// Where commands print, chosen once from `--json` and the terminal. Clones
/// share the streams.
#[derive(Clone)]
pub(super) struct Output(Arc<Streams>);

/// Standard output and error, and whether both carry JSON.
struct Streams {
    /// Whether results are JSON, and messages JSON lines.
    json: bool,
    /// Results.
    stdout: Mutex<Stream>,
    /// Messages, prompts and failures.
    stderr: Mutex<Stream>,
}

/// One stream, and whether it shows colour.
struct Stream {
    /// Where it writes.
    writer: Box<dyn Write + Send>,
    /// Whether styles are written as ANSI codes.
    color: bool,
}

impl Stream {
    /// `writer`, in colour when it is a terminal, `NO_COLOR` is unset or empty and
    /// `TERM` is not `dumb`.
    fn terminal(writer: impl Write + IsTerminal + Send + 'static) -> Self {
        let color = writer.is_terminal()
            && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
            && std::env::var_os("TERM").is_none_or(|term| term != "dumb");
        Self {
            writer: Box::new(writer),
            color,
        }
    }

    /// Writes with `write`, through a [`HumanWriter`], then flushes.
    fn human(
        &mut self,
        write: impl FnOnce(&mut HumanWriter<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        write(&mut HumanWriter {
            writer: &mut self.writer,
            color: self.color,
        })?;
        self.writer.flush()
    }

    /// Writes `value` as JSON, pretty or on one line, then a newline, and flushes.
    fn json(&mut self, value: &(impl Serialize + ?Sized), pretty: bool) -> io::Result<()> {
        if pretty {
            serde_json::to_writer_pretty(&mut self.writer, value)?;
        } else {
            serde_json::to_writer(&mut self.writer, value)?;
        }
        writeln!(self.writer)?;
        self.writer.flush()
    }
}

/// One message on standard error with `--json`: a single-line object whose only
/// key names its kind, e.g. `{"info":{"message":"…"}}`.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Event<'a> {
    /// What a command did, or how to go on.
    Info {
        /// The message.
        message: String,
    },
    /// Something surprising the command went on despite.
    Warning {
        /// The message.
        message: String,
    },
    /// What a command shows before it asks to go ahead, as its report's JSON.
    Context(serde_json::Value),
    /// A question, answered on standard input.
    Prompt {
        /// The question.
        message: &'a str,
    },
    /// Why the command failed, then each cause.
    Error {
        /// The failure.
        message: String,
        /// Its causes, outermost first.
        causes: Vec<String>,
    },
}

/// The kind of a message on standard error, which labels it.
#[derive(Clone, Copy)]
enum Role {
    /// What a command did, or how to go on.
    Info,
    /// Something surprising.
    Warning,
    /// The command's failure.
    Error,
}

impl Role {
    /// Its label, e.g. `Info`.
    const fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Warning => "Warning",
            Self::Error => "Error",
        }
    }

    /// Its label's style.
    const fn style(self) -> Style {
        match self {
            Self::Info => Style::Label,
            Self::Warning => Style::Notice,
            Self::Error => Style::Bad,
        }
    }
}

impl Output {
    /// Prints to this process's standard output and error, as JSON when `json`.
    pub(super) fn new(json: bool) -> Self {
        Self::with(
            json,
            Stream::terminal(io::stdout()),
            Stream::terminal(io::stderr()),
        )
    }

    /// Prints to the given streams.
    fn with(json: bool, stdout: Stream, stderr: Stream) -> Self {
        Self(Arc::new(Streams {
            json,
            stdout: Mutex::new(stdout),
            stderr: Mutex::new(stderr),
        }))
    }

    /// Prints a command's result on standard output.
    pub(super) fn emit<R: Report + ?Sized>(&self, report: &R) -> Result<(), CliError> {
        let mut stdout = lock(&self.0.stdout);
        if self.0.json {
            stdout.json(report.json(), true)
        } else {
            stdout.human(|out| report.human(out))
        }
        .map_err(CliError::Output)
    }

    /// Prints what a command shows before it asks to go ahead, such as the
    /// recoveries an account had, on standard error, leaving standard output to
    /// its result.
    pub(super) fn context<R: Report + ?Sized>(&self, report: &R) -> Result<(), CliError> {
        if self.0.json {
            let event = Event::Context(serde_json::to_value(report.json())?);
            return self.event(&event);
        }
        lock(&self.0.stderr)
            .human(|out| report.human(out))
            .map_err(CliError::Output)
    }

    /// Says what a command did, or how to go on.
    pub(super) fn info(&self, message: impl fmt::Display) -> Result<(), CliError> {
        self.message(Role::Info, &message)
    }

    /// Says what surprised a command that went on.
    pub(super) fn warning(&self, message: impl fmt::Display) -> Result<(), CliError> {
        self.message(Role::Warning, &message)
    }

    /// Prints the command's failure and each of its causes. A failure to print
    /// it is ignored, since the command fails anyway.
    pub(super) fn error(&self, error: &(dyn Error + 'static)) {
        let causes = std::iter::successors(error.source(), |&cause| cause.source());
        let _ = if self.0.json {
            self.event(&Event::Error {
                message: error.to_string(),
                causes: causes.map(ToString::to_string).collect(),
            })
        } else {
            lock(&self.0.stderr)
                .human(|out| {
                    out.label(Role::Error.label(), Role::Error.style(), error)?;
                    for cause in causes {
                        out.label("  Caused by", Style::Muted, cause)?;
                    }
                    Ok(())
                })
                .map_err(CliError::Output)
        };
    }

    /// Asks `question` on standard error with a `[y/N]` suffix, and reads the
    /// answer from `input`: whether it is yes.
    pub(super) fn ask(&self, question: &str, mut input: impl BufRead) -> Result<bool, CliError> {
        let question = format!("{question}. Continue? [y/N]");
        if self.0.json {
            self.event(&Event::Prompt { message: &question })?;
        } else {
            lock(&self.0.stderr)
                .human(|out| {
                    out.text(&question)?;
                    out.raw(" ")
                })
                .map_err(CliError::Output)?;
        }
        let mut answer = String::new();
        input.read_line(&mut answer).map_err(CliError::Prompt)?;
        Ok(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }

    /// Writes a labelled message, or its event with `--json`.
    fn message(&self, role: Role, message: &dyn fmt::Display) -> Result<(), CliError> {
        if self.0.json {
            let message = message.to_string();
            return self.event(&match role {
                Role::Info => Event::Info { message },
                Role::Warning => Event::Warning { message },
                Role::Error => Event::Error {
                    message,
                    causes: Vec::new(),
                },
            });
        }
        lock(&self.0.stderr)
            .human(|out| out.label(role.label(), role.style(), message))
            .map_err(CliError::Output)
    }

    /// Writes `event` as one line on standard error.
    fn event(&self, event: &Event<'_>) -> Result<(), CliError> {
        lock(&self.0.stderr)
            .json(event, false)
            .map_err(CliError::Output)
    }
}

/// Locks `stream`. A panic while it was held left at worst a partial line, so
/// printing goes on.
fn lock(stream: &Mutex<Stream>) -> MutexGuard<'_, Stream> {
    stream.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How a piece of text is styled, by what it means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Style {
    /// Column headings and titles.
    Heading,
    /// Labels and section titles.
    Label,
    /// What matters less: a missing value, how to page on.
    Muted,
    /// A healthy state, such as an active account.
    Good,
    /// A state that needs a look, such as a pending delivery.
    Notice,
    /// A failed or ended state, such as a disabled account.
    Bad,
}

impl Style {
    /// Its ANSI SGR parameters.
    const fn code(self) -> &'static str {
        match self {
            Self::Heading => "1",
            Self::Label => "1;36",
            Self::Muted => "2",
            Self::Good => "32",
            Self::Notice => "33",
            Self::Bad => "31",
        }
    }
}

/// Writes for people: every value escaped, styles only in colour.
pub(super) struct HumanWriter<'a> {
    /// Where it writes.
    writer: &'a mut dyn Write,
    /// Whether styles are written.
    color: bool,
}

impl HumanWriter<'_> {
    /// Writes an escaped value and a newline.
    pub(super) fn line(&mut self, value: impl fmt::Display) -> io::Result<()> {
        writeln!(self.writer, "{}", Escaped(value))
    }

    /// Writes an empty line.
    pub(super) fn blank(&mut self) -> io::Result<()> {
        writeln!(self.writer)
    }

    /// Writes a bold title line, such as an account's handle.
    pub(super) fn title(&mut self, title: impl fmt::Display) -> io::Result<()> {
        self.styled(Style::Heading, &Escaped(title).to_string())?;
        self.blank()
    }

    /// Writes a section's title after an empty line, e.g. `Emails:`.
    pub(super) fn section(&mut self, title: &str) -> io::Result<()> {
        self.blank()?;
        self.styled(Style::Label, &format!("{}:", Escaped(title)))?;
        self.blank()
    }

    /// Writes text of several lines, such as an announcement's body, keeping
    /// line breaks and tabs but escaping every other control character.
    pub(super) fn text(&mut self, text: &str) -> io::Result<()> {
        for character in text.chars() {
            if character.is_control() && !matches!(character, '\n' | '\t') {
                write!(self.writer, "{}", character.escape_default())?;
            } else {
                write!(self.writer, "{character}")?;
            }
        }
        Ok(())
    }

    /// Writes one fact per line, its label padded so the values line up:
    ///
    /// ```text
    /// Name:     Alice
    /// Status:   active
    /// ```
    pub(super) fn fields(&mut self, fields: &[(&str, Cell)]) -> io::Result<()> {
        let width = fields
            .iter()
            .map(|(label, _)| label.chars().count() + 1)
            .max()
            .unwrap_or_default();
        for (label, value) in fields {
            let label = format!("{label}:");
            self.styled(Style::Label, &label)?;
            self.pad(width - label.chars().count() + 2)?;
            self.cell(value)?;
            self.blank()?;
        }
        Ok(())
    }

    /// Writes a table: `empty` alone when there are no rows, else a heading
    /// line, then each row, every column padded to its widest cell and two
    /// spaces apart. Widths count characters, so a wide character, such as a
    /// CJK one, shifts its row by a column.
    ///
    /// ```text
    /// ID     HANDLE  STATUS
    /// 0199…  alice   active
    /// ```
    pub(super) fn table<const N: usize>(
        &mut self,
        headings: [&str; N],
        empty: &str,
        rows: impl IntoIterator<Item = [Cell; N]>,
    ) -> io::Result<()> {
        let rows: Vec<_> = rows.into_iter().collect();
        if rows.is_empty() {
            self.styled(Style::Muted, empty)?;
            return self.blank();
        }
        let headings = headings.map(|heading| Cell::new(heading).style(Style::Heading));
        let mut widths = [0; N];
        for row in std::iter::once(&headings).chain(&rows) {
            for (width, cell) in widths.iter_mut().zip(row) {
                *width = (*width).max(cell.width());
            }
        }
        for row in std::iter::once(&headings).chain(&rows) {
            for (column, cell) in row.iter().enumerate() {
                self.cell(cell)?;
                if column + 1 < N {
                    self.pad(widths[column] - cell.width() + 2)?;
                }
            }
            self.blank()?;
        }
        Ok(())
    }

    /// Writes where a page stands, and how to list the next, after a table that
    /// is not empty.
    pub(super) fn paging(&mut self, paging: Paging, what: &str) -> io::Result<()> {
        if paging.total == 0 {
            return Ok(());
        }
        let next = paging
            .next()
            .map(|next| format!(" Next: --page {next}"))
            .unwrap_or_default();
        self.styled(
            Style::Muted,
            &format!(
                "Page {} of {}, {} {what} in all.{next}",
                paging.page, paging.pages, paging.total
            ),
        )?;
        self.blank()
    }

    /// Writes how to list what follows a page, after a table, when more may.
    pub(super) fn more(&mut self, next: Option<impl fmt::Display>) -> io::Result<()> {
        match next {
            Some(next) => {
                self.styled(
                    Style::Muted,
                    &format!("More may follow. Next: --before {next}"),
                )?;
                self.blank()
            }
            None => Ok(()),
        }
    }

    /// Writes `label:` in `style`, then the escaped `value` and a newline.
    fn label(&mut self, label: &str, style: Style, value: impl fmt::Display) -> io::Result<()> {
        self.styled(style, &format!("{label}:"))?;
        write!(self.writer, " ")?;
        self.line(value)
    }

    /// Writes a cell, escaped when it was made.
    fn cell(&mut self, cell: &Cell) -> io::Result<()> {
        match cell.style {
            Some(style) => self.styled(style, &cell.text),
            None => self.raw(&cell.text),
        }
    }

    /// Writes `count` spaces.
    fn pad(&mut self, count: usize) -> io::Result<()> {
        write!(self.writer, "{:count$}", "")
    }

    /// Writes text that is already escaped, in `style` when in colour.
    fn styled(&mut self, style: Style, text: &str) -> io::Result<()> {
        if self.color {
            write!(self.writer, "\x1b[{}m{text}\x1b[0m", style.code())
        } else {
            self.raw(text)
        }
    }

    /// Writes text that is already escaped, as it is.
    fn raw(&mut self, text: &str) -> io::Result<()> {
        self.writer.write_all(text.as_bytes())
    }
}

/// One value in a table or a list of facts: escaped text, and its style.
/// Conversions format each kind of value the same way everywhere: a time as
/// `2026-11-10 14:03:22` in UTC, a flag as `yes` or `no`, nothing as a muted `-`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cell {
    /// The escaped text.
    text: String,
    /// How it is styled.
    style: Option<Style>,
}

impl Cell {
    /// `value`, escaped.
    pub(super) fn new(value: impl fmt::Display) -> Self {
        Self {
            text: Escaped(value).to_string(),
            style: None,
        }
    }

    /// A missing value.
    pub(super) fn none() -> Self {
        Cell::new("-").style(Style::Muted)
    }

    /// This value, in `style`.
    pub(super) const fn style(mut self, style: Style) -> Self {
        self.style = Some(style);
        self
    }

    /// Its width in characters.
    fn width(&self) -> usize {
        self.text.chars().count()
    }
}

/// Converts values that print as they display.
macro_rules! displayed {
    ($($ty:ty),* $(,)?) => {
        $(impl From<$ty> for Cell {
            fn from(value: $ty) -> Self {
                Self::new(value)
            }
        })*
    };
}
displayed!(&str, String, &String, u32, u64, usize, i64);

impl From<bool> for Cell {
    fn from(value: bool) -> Self {
        Self::new(if value { "yes" } else { "no" })
    }
}

impl From<DateTime<Utc>> for Cell {
    fn from(at: DateTime<Utc>) -> Self {
        Self::new(Time(at))
    }
}

/// Displays a time as every command shows one: `2026-11-10 14:03:22`, in UTC.
pub(super) struct Time(pub(super) DateTime<Utc>);

impl fmt::Display for Time {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.format("%Y-%m-%d %H:%M:%S"))
    }
}

impl<T: Into<Cell>> From<Option<T>> for Cell {
    fn from(value: Option<T>) -> Self {
        value.map_or_else(Self::none, Into::into)
    }
}

impl From<AccountStatus> for Cell {
    fn from(status: AccountStatus) -> Self {
        Self::new(status).style(match status {
            AccountStatus::Active => Style::Good,
            AccountStatus::Disabled => Style::Bad,
            AccountStatus::Deleting => Style::Notice,
        })
    }
}

impl From<DeliveryStatus> for Cell {
    fn from(status: DeliveryStatus) -> Self {
        Self::new(status).style(match status {
            DeliveryStatus::Pending => Style::Notice,
            DeliveryStatus::Succeeded => Style::Good,
            DeliveryStatus::Failed => Style::Bad,
            DeliveryStatus::Cancelled => Style::Muted,
        })
    }
}

impl From<SigningKeyState> for Cell {
    fn from(state: SigningKeyState) -> Self {
        Self::new(state).style(match state {
            SigningKeyState::Next => Style::Notice,
            SigningKeyState::Active => Style::Good,
            SigningKeyState::Retiring | SigningKeyState::Retired => Style::Muted,
        })
    }
}

impl From<AlertState> for Cell {
    fn from(state: AlertState) -> Self {
        match state {
            AlertState::Open => Self::new("open").style(Style::Bad),
            AlertState::Acknowledged => Self::new("acknowledged").style(Style::Notice),
            AlertState::Cleared => Self::new("cleared").style(Style::Good),
        }
    }
}

/// Displays each item with `separator` between them, such as a session's
/// methods: `Joined(&methods, ", ")`.
pub(super) struct Joined<'a, T>(pub(super) &'a [T], pub(super) &'a str);

impl<T: fmt::Display> fmt::Display for Joined<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, item) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(self.1)?;
            }
            write!(formatter, "{item}")?;
        }
        Ok(())
    }
}

/// Displays a value with every control character escaped, so it cannot drive
/// the terminal or break a table's line.
pub(super) struct Escaped<T>(pub(super) T);

impl<T: fmt::Display> fmt::Display for Escaped<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// Escapes each control character on its way to the formatter.
        struct Escape<'a, 'b>(&'a mut fmt::Formatter<'b>);
        impl fmt::Write for Escape<'_, '_> {
            fn write_str(&mut self, value: &str) -> fmt::Result {
                for character in value.chars() {
                    if character.is_control() {
                        write!(self.0, "{}", character.escape_default())?;
                    } else {
                        self.0.write_char(character)?;
                    }
                }
                Ok(())
            }
        }
        fmt::write(&mut Escape(formatter), format_args!("{}", self.0))
    }
}
