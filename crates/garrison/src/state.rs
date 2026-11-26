//! A state a command reports: a refusal it ends with, or an outcome another
//! program acts on. Its name is what tests and scripts look for and never
//! changes once released; its sentence may.
//!
//! One constructor function makes each state, and the constructors of an
//! area stand together in its `states.rs`: no sentence of a state is built
//! anywhere else. Where a state's sentence is one text with its values, its
//! constructor is an entry of the area's table (`states!`); where the
//! sentence is decided, it is a function beside the table.

use std::fmt;

/// `name`: lower-case words joined by hyphens, the area first
/// (`install-no-room`). `fix`: what mends it, where that is said apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct State {
    pub(crate) name: &'static str,
    pub(crate) text: String,
    pub(crate) fix: Option<String>,
}

impl State {
    pub(crate) fn new(name: &'static str, text: impl Into<String>) -> Self {
        Self {
            name,
            text: text.into(),
            fix: None,
        }
    }

    #[must_use]
    pub(crate) fn with_fix(self, fix: impl Into<String>) -> Self {
        Self {
            fix: Some(fix.into()),
            ..self
        }
    }
}

/// The sentence, then the name in brackets; the fix on the next line,
/// indented as doctor indents the fix of its lines. There is no other form.
impl fmt::Display for State {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} [{}]", self.text, self.name)?;
        if let Some(fix) = &self.fix {
            write!(formatter, "\n      {fix}")?;
        }
        Ok(())
    }
}

/// The constructor functions of the states whose sentence is one text with
/// its values, as a table. An entry is the function's signature, the state's
/// name and its sentence, which takes its values as `format!` does; after
/// `=>` follows what mends the state, where that is said apart:
///
/// ```text
/// pub(super) fn no_room(folder: &Path, needed: u64) = "install-no-room":
///     "{} has no room for {needed} MiB", folder.display()
///     => "Free the room, then install again.";
/// ```
///
/// This is the one macro of the project that writes functions: several
/// hundred states are each a name and a sentence, and as functions each of
/// them was six lines around its one.
macro_rules! states {
    ($(
        $(#[$meta:meta])*
        $visibility:vis fn $function:ident($($argument:ident: $kind:ty),* $(,)?) = $name:literal:
            $text:literal $(, $value:expr)* $(=> $fix:literal $(, $mend:expr)*)?;
    )*) => {$(
        $(#[$meta])*
        $visibility fn $function($($argument: $kind),*) -> $crate::state::State {
            $crate::state::State::new($name, format!($text $(, $value)*))
                $(.with_fix(format!($fix $(, $mend)*)))?
        }
    )*};
}
pub(crate) use states;

/// The page that lists every state for operators, each one's whole line in
/// a block of its own.
#[cfg(test)]
const PAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/operator/states.md");

/// The table test of an area: `examples` hold every state that the
/// constructors in `sources` (their files' text) make, each once, made with
/// values such as a host has, and the operators' page shows each one's whole
/// line. That page is the one place where a state's line stands written out.
/// A sentence that changes is changed there too, by hand or by this test:
/// `GARRISON_STATES=write cargo test -p garrison` writes each state's block
/// anew, and the page's difference shows what an operator will read.
#[cfg(test)]
pub(crate) fn table(sources: &[&str], examples: &[State]) {
    use std::sync::{Mutex, PoisonError};
    // One area's test at a time reads and writes the page.
    static ONE: Mutex<()> = Mutex::new(());
    let _one = ONE.lock().unwrap_or_else(PoisonError::into_inner);
    let mut page = std::fs::read_to_string(PAGE).unwrap();
    if std::env::var_os("GARRISON_STATES").is_some_and(|asked| asked == "write") {
        page = written(&page, examples);
        std::fs::write(PAGE, &page).unwrap();
    }
    held(&page, sources, examples);
}

/// `table`, against `page` as the operators' page.
#[cfg(test)]
fn held(page: &str, sources: &[&str], examples: &[State]) {
    let mut made: Vec<&str> = sources.iter().flat_map(|source| names(source)).collect();
    made.sort_unstable();
    for pair in made.windows(2) {
        assert_ne!(pair[0], pair[1], "two constructors make {}", pair[0]);
    }
    let mut listed: Vec<&str> = examples.iter().map(|state| state.name).collect();
    listed.sort_unstable();
    for pair in listed.windows(2) {
        assert_ne!(pair[0], pair[1], "{} is in the table twice", pair[0]);
    }
    assert_eq!(
        listed, made,
        "the table and the constructors name other states"
    );
    for state in examples {
        assert!(
            well_named(state.name),
            "{} is not a state's name",
            state.name
        );
        let line = state.to_string();
        assert!(
            entries(page).any(|entry| entry == line),
            "docs/operator/states.md shows every state's line in a block of its own; that of {} \
             is now the line below, which `GARRISON_STATES=write cargo test -p garrison` writes \
             there:\n{line}",
            state.name
        );
    }
}

/// The blocks of the operators' page, each one state's whole line.
#[cfg(test)]
fn entries(page: &str) -> impl Iterator<Item = &str> {
    page.split("```text\n")
        .skip(1)
        .filter_map(|rest| rest.split_once("\n```").map(|(entry, _)| entry))
}

/// The state a block of the page is of: its line may carry other states'
/// lines inside it, so it is the last name in brackets that is a state's.
#[cfg(test)]
fn stated(entry: &str) -> Option<&str> {
    entry.rmatch_indices(" [").find_map(|(at, _)| {
        let bracketed = &entry[at + 2..];
        let name = &bracketed[..bracketed.find(']')?];
        well_named(name).then_some(name)
    })
}

/// `page` with the block of each of `examples` holding its line as it is
/// now. A state the page has no block of is entered by hand, in the section
/// of its area.
#[cfg(test)]
fn written(page: &str, examples: &[State]) -> String {
    let mut parts = page.split("```text\n");
    let mut written = parts.next().unwrap_or_default().to_owned();
    let mut found = Vec::new();
    for part in parts {
        let (entry, rest) = part.split_once("\n```").unwrap_or((part, ""));
        let now = examples
            .iter()
            .find(|state| stated(entry) == Some(state.name));
        found.extend(now.map(|state| state.name));
        let line = now.map_or_else(|| entry.to_owned(), ToString::to_string);
        for piece in ["```text\n", &line, "\n```", rest] {
            written.push_str(piece);
        }
    }
    for state in examples {
        assert!(
            found.contains(&state.name),
            "docs/operator/states.md has no block of {}: enter one in its area's section",
            state.name
        );
    }
    written
}

/// The names of the states that `source` makes: those `State::new` is given,
/// which are literals, and those of the entries of a `states!` table, each
/// after its signature's `) = `.
#[cfg(test)]
fn names(source: &str) -> Vec<&str> {
    let given = source.split("State::new(").skip(1).map(|rest| {
        let rest = rest.trim_start();
        let quoted = rest
            .strip_prefix('"')
            .unwrap_or_else(|| panic!("a state's name is a literal: {rest:.60}"));
        &quoted[..quoted.find('"').unwrap()]
    });
    let entered = source.split("= \"").skip(1).filter_map(|rest| {
        let (name, after) = rest.split_once('"')?;
        (after.starts_with(":\n") && name.contains('-')).then_some(name)
    });
    given.chain(entered).collect()
}

/// Lower-case words of letters and digits joined by hyphens, two at least:
/// the area and what the state is.
#[cfg(test)]
fn well_named(name: &str) -> bool {
    let words: Vec<&str> = name.split('-').collect();
    words.len() >= 2
        && name.starts_with(|first: char| first.is_ascii_lowercase())
        && words.iter().all(|word| {
            !word.is_empty()
                && word
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_says_its_sentence_then_its_name_then_its_fix() {
        let state = State::new(
            "install-no-room",
            "/opt has 29 MiB free; nothing was changed.",
        );
        assert_eq!(
            state.to_string(),
            "/opt has 29 MiB free; nothing was changed. [install-no-room]"
        );
        let fixed = state.clone().with_fix("Free space on /opt.");
        assert_eq!((fixed.name, &fixed.text), (state.name, &state.text));
        assert_eq!(
            fixed.to_string(),
            "/opt has 29 MiB free; nothing was changed. [install-no-room]\n      Free space on /opt."
        );
        assert_ne!(fixed, state);
    }

    #[test]
    fn names_are_lower_case_words_joined_by_hyphens() {
        for name in [
            "install-io",
            "upgrade-older-archive",
            "setup-account-full",
            "access-2fa-x",
        ] {
            assert!(well_named(name), "{name}");
        }
        for name in [
            "install",
            "Install-io",
            "install_io",
            "install--io",
            "-install",
            "1-io",
            "a-b-",
        ] {
            assert!(!well_named(name), "{name}");
        }
    }

    const SOURCE: &str = r#"
        fn one() -> State { State::new("area-one", "One.") }
        fn two(n: u8) -> State {
            State::new(
                "area-two",
                format!("Two {n}."),
            )
        }
    "#;

    /// The page of the two states of `SOURCE`.
    const LISTED: &str = "```text\nOne. [area-one]\n```\n```text\nTwo 2. [area-two]\n```\n";

    fn both() -> [State; 2] {
        [
            State::new("area-one", "One."),
            State::new("area-two", "Two 2."),
        ]
    }

    #[test]
    fn a_table_holds_every_state_its_constructors_make() {
        assert_eq!(names(SOURCE), ["area-one", "area-two"]);
        held(LISTED, &[SOURCE], &both());
        // An entry of a table of states is found as a function's is.
        let entered = "    pub(super) fn one() = \"area-one\":\n        \"One.\";\n    fn two(n: u8)\n        = \"area-two\":\n        \"Two {n}.\";";
        assert_eq!(names(entered), ["area-one", "area-two"]);
        assert_eq!(
            names("let name = \"not-a-state\";\nlet other = \"word\":\n"),
            [""; 0]
        );
    }

    #[test]
    #[should_panic(expected = "the table and the constructors name other states")]
    fn a_table_without_a_state_fails() {
        held(LISTED, &[SOURCE], &both()[..1]);
    }

    #[test]
    #[should_panic(expected = "area-one is in the table twice")]
    fn a_table_that_names_a_state_twice_fails() {
        let one = || State::new("area-one", "One.");
        held(LISTED, &[SOURCE], &[one(), one()]);
    }

    #[test]
    #[should_panic(expected = "two constructors make area-one")]
    fn two_constructors_of_one_name_fail() {
        let twice = format!("{SOURCE} State::new(\"area-one\", \"Again.\")");
        held(LISTED, &[&twice], &[]);
    }

    #[test]
    #[should_panic(expected = "that of area-two is now the line below")]
    fn a_line_the_page_does_not_show_fails() {
        let said = [
            State::new("area-one", "One."),
            State::new("area-two", "Two 3."),
        ];
        held(LISTED, &[SOURCE], &said);
    }

    #[test]
    #[should_panic(expected = "docs/operator/states.md shows every state's line")]
    fn a_line_the_page_does_not_show_whole_and_alone_fails() {
        // The second state's line is there, but not as a block of its own.
        held(
            "```text\nOne. [area-one]\n```\nTwo 2. [area-two]\n```text\nTwo 2. [area-two] and more\n```\n",
            &[SOURCE],
            &both(),
        );
    }

    /// Writing the page changes the blocks of the states at hand and nothing
    /// else: a block is a state's by the last name in it, another state's
    /// line inside it and the words around the blocks stay.
    #[test]
    fn a_states_block_is_written_anew_where_its_line_changed() {
        let page = "# States\n\nWords.\n\n```text\nOne. [area-one]\n```\nBetween.\n```text\nTwo 2, \
                    for One. [area-one] [area-two]\n      Mend it.\n```\n```text\nThree. [area-three]\n```\n";
        let now = [
            State::new("area-one", "The first."),
            State::new("area-two", "The second").with_fix("Mend it so."),
        ];
        assert_eq!(
            written(page, &now),
            "# States\n\nWords.\n\n```text\nThe first. [area-one]\n```\nBetween.\n```text\nThe second \
             [area-two]\n      Mend it so.\n```\n```text\nThree. [area-three]\n```\n"
        );
        assert_eq!(
            stated("Two 2, for One. [area-one] [area-two]\n      Mend [it]."),
            Some("area-two")
        );
        assert_eq!(stated("no state [here]"), None);
    }

    #[test]
    #[should_panic(expected = "has no block of area-two")]
    fn a_state_without_a_block_is_not_written() {
        written("```text\nOne. [area-one]\n```\n", &both());
    }
}
