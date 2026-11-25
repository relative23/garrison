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

/// The page that lists every state for operators.
#[cfg(test)]
const PAGE: &str = include_str!("../../../docs/operator/states.md");

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

/// The table test of an area: `rows` hold every state that the constructors
/// in `sources` (their files' text) make, each once, with its whole line
/// written out as an example, which the operators' page of the states shows
/// too. The only place in an area's tests where a state's words stand.
#[cfg(test)]
pub(crate) fn table(sources: &[&str], rows: &[(State, &str)]) {
    held(PAGE, sources, rows);
}

/// `table`, against `page` as the operators' page.
#[cfg(test)]
fn held(page: &str, sources: &[&str], rows: &[(State, &str)]) {
    let mut made: Vec<&str> = sources.iter().flat_map(|source| names(source)).collect();
    made.sort_unstable();
    for pair in made.windows(2) {
        assert_ne!(pair[0], pair[1], "two constructors make {}", pair[0]);
    }
    let mut listed: Vec<&str> = rows.iter().map(|(state, _)| state.name).collect();
    listed.sort_unstable();
    for pair in listed.windows(2) {
        assert_ne!(pair[0], pair[1], "{} is in the table twice", pair[0]);
    }
    assert_eq!(
        listed, made,
        "the table and the constructors name other states"
    );
    for (state, line) in rows {
        assert!(
            well_named(state.name),
            "{} is not a state's name",
            state.name
        );
        assert_eq!(state.to_string(), *line, "{}", state.name);
        assert!(
            entries(page).any(|entry| entry == *line),
            "docs/operator/states.md shows every state's line in a block of its own, as its \
             table has it; that of {} is:\n{line}",
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

    #[test]
    fn a_table_holds_every_state_its_constructors_make() {
        assert_eq!(names(SOURCE), ["area-one", "area-two"]);
        held(
            LISTED,
            &[SOURCE],
            &[
                (State::new("area-one", "One."), "One. [area-one]"),
                (State::new("area-two", "Two 2."), "Two 2. [area-two]"),
            ],
        );
    }

    #[test]
    #[should_panic(expected = "the table and the constructors name other states")]
    fn a_table_without_a_state_fails() {
        held(
            LISTED,
            &[SOURCE],
            &[(State::new("area-one", "One."), "One. [area-one]")],
        );
    }

    #[test]
    #[should_panic(expected = "area-one is in the table twice")]
    fn a_table_that_names_a_state_twice_fails() {
        let one = || State::new("area-one", "One.");
        held(
            LISTED,
            &[SOURCE],
            &[(one(), "One. [area-one]"), (one(), "One. [area-one]")],
        );
    }

    #[test]
    #[should_panic(expected = "two constructors make area-one")]
    fn two_constructors_of_one_name_fail() {
        let twice = format!("{SOURCE} State::new(\"area-one\", \"Again.\")");
        held(LISTED, &[&twice], &[]);
    }

    #[test]
    #[should_panic(expected = "area-two")]
    fn a_line_the_state_does_not_say_fails() {
        held(
            LISTED,
            &[SOURCE],
            &[
                (State::new("area-one", "One."), "One. [area-one]"),
                (State::new("area-two", "Two 2."), "Two 3. [area-two]"),
            ],
        );
    }

    #[test]
    #[should_panic(expected = "docs/operator/states.md shows every state's line")]
    fn a_line_the_page_does_not_show_whole_and_alone_fails() {
        // The second state's line is there, but not as a block of its own.
        held(
            "```text\nOne. [area-one]\n```\nTwo 2. [area-two]\n```text\nTwo 2. [area-two] and more\n```\n",
            &[SOURCE],
            &[
                (State::new("area-one", "One."), "One. [area-one]"),
                (State::new("area-two", "Two 2."), "Two 2. [area-two]"),
            ],
        );
    }
}
