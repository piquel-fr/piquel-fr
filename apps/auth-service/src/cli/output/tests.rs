//! Tables line up and escape what they show, styles appear only in colour, and
//! `--json` keeps standard output to the result and standard error to one event
//! per line.

use super::*;
use chrono::TimeZone;

/// A stream whose bytes the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        lock_bytes(&self.0).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// What was written, as text.
    fn text(&self) -> String {
        String::from_utf8(lock_bytes(&self.0).clone()).expect("UTF-8")
    }

    /// A stream writing here, in colour or not.
    fn stream(&self, color: bool) -> Stream {
        Stream {
            writer: Box::new(self.clone()),
            color,
        }
    }
}

/// Locks captured bytes.
fn lock_bytes(bytes: &Mutex<Vec<u8>>) -> MutexGuard<'_, Vec<u8>> {
    bytes.lock().expect("captured")
}

impl Output {
    /// Prints nowhere, for tests of commands.
    pub(in crate::cli) fn sink() -> Self {
        let sink = || Stream {
            writer: Box::new(io::sink()),
            color: false,
        };
        Self::with(false, sink(), sink())
    }

    /// Prints to captured streams, returning them: standard output, then error.
    fn captured(json: bool, color: bool) -> (Self, Captured, Captured) {
        let (stdout, stderr) = (Captured::default(), Captured::default());
        let output = Self::with(json, stdout.stream(color), stderr.stream(color));
        (output, stdout, stderr)
    }
}

/// Two rows of accounts, the second's name trying to drive the terminal.
struct Accounts;

impl Serialize for Accounts {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("accounts")
    }
}

report!(Accounts, self, out, {
    out.table(
        ["HANDLE", "ADMIN", "NAME"],
        "No accounts.",
        [
            [Cell::new("alice"), true.into(), Cell::new("Alice")],
            [
                Cell::new("bob-the-builder"),
                Option::<bool>::None.into(),
                Cell::new("Bob\u{1b}[2J"),
            ],
        ],
    )
});

/// Every column is as wide as its widest cell, escaped, and no line ends in
/// spaces.
#[test]
fn tables_line_up() {
    let (output, stdout, _) = Output::captured(false, false);
    output.emit(&Accounts).expect("emit");
    assert_eq!(
        stdout.text(),
        "HANDLE           ADMIN  NAME\n\
         alice            yes    Alice\n\
         bob-the-builder  -      Bob\\u{1b}[2J\n"
    );
}

/// An empty table says so instead of printing a heading.
#[test]
fn empty_tables_say_so() {
    let mut text = Vec::new();
    let mut out = HumanWriter {
        writer: &mut text,
        color: false,
    };
    out.table(["ID"], "No accounts.", Vec::<[Cell; 1]>::new())
        .expect("table");
    assert_eq!(text, b"No accounts.\n");
}

/// Styles are written only in colour, and padding stays outside them.
#[test]
fn styles_only_in_colour() {
    let (output, stdout, _) = Output::captured(false, true);
    output.emit(&Accounts).expect("emit");
    let text = stdout.text();
    assert!(
        text.starts_with("\x1b[1mHANDLE\x1b[0m           "),
        "{text:?}"
    );
    assert!(text.contains("\x1b[2m-\x1b[0m      "), "{text:?}");
}

/// Facts line their values up after their labels.
#[test]
fn fields_line_up() {
    let mut text = Vec::new();
    let mut out = HumanWriter {
        writer: &mut text,
        color: false,
    };
    let at = Utc.with_ymd_and_hms(2026, 11, 10, 14, 3, 22).single();
    out.fields(&[("Name", Cell::new("Alice")), ("Created", at.into())])
        .expect("fields");
    assert_eq!(
        String::from_utf8(text).expect("UTF-8"),
        "Name:     Alice\nCreated:  2026-11-10 14:03:22\n"
    );
}

/// With `--json`, the result is JSON on standard output, and each message one
/// JSON object on its own line on standard error.
#[test]
fn json_keeps_each_stream_to_its_role() {
    let (output, stdout, stderr) = Output::captured(true, true);
    output.emit(&Accounts).expect("emit");
    output.info("Disabled alice.").expect("info");
    output.warning("Store it now.").expect("warning");
    assert_eq!(stdout.text(), "\"accounts\"\n");
    assert_eq!(
        stderr.text(),
        "{\"info\":{\"message\":\"Disabled alice.\"}}\n\
         {\"warning\":{\"message\":\"Store it now.\"}}\n"
    );
}

/// A failure is printed with each of its causes, for people or as one event.
#[test]
fn failures_list_their_causes() {
    let failure = CliError::BodyFile(io::Error::other("no such file"));
    let (output, _, stderr) = Output::captured(false, false);
    output.error(&failure);
    assert_eq!(
        stderr.text(),
        "Error: could not read the text given with --body-file\n  Caused by: no such file\n"
    );
    let (output, _, stderr) = Output::captured(true, false);
    output.error(&failure);
    assert_eq!(
        stderr.text(),
        "{\"error\":{\"message\":\"could not read the text given with --body-file\",\"causes\":[\"no such file\"]}}\n"
    );
}

/// A prompt goes to standard error, and only a yes goes ahead.
#[test]
fn prompts_take_only_yes() {
    let (output, stdout, stderr) = Output::captured(false, false);
    assert!(output.ask("Disable alice", &b"Yes\n"[..]).expect("answer"));
    assert!(!output.ask("Disable alice", &b"\n"[..]).expect("answer"));
    assert_eq!(stdout.text(), "");
    assert_eq!(
        stderr.text(),
        "Disable alice. Continue? [y/N] Disable alice. Continue? [y/N] "
    );
}
