//! A state a command reports: a refusal it ends with, or an outcome another
//! program acts on. Its name is what tests and scripts look for and never
//! changes once released; its sentence may.
//!
//! One constructor function makes each state, and the constructors of an
//! area stand together in its `states.rs`: no sentence of a state is built
//! anywhere else.

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

/// The table test of an area: `rows` hold every state that the constructors
/// in `sources` (their files' text) make, each once, with its whole line
/// written out as an example. The only place in an area's tests where a
/// state's words stand.
#[cfg(test)]
pub(crate) fn table(sources: &[&str], rows: &[(State, &str)]) {
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
    }
}

/// The names that `State::new` is given in `source`, which are literals.
#[cfg(test)]
fn names(source: &str) -> Vec<&str> {
    source
        .split("State::new(")
        .skip(1)
        .map(|rest| {
            let rest = rest.trim_start();
            let quoted = rest
                .strip_prefix('"')
                .unwrap_or_else(|| panic!("a state's name is a literal: {rest:.60}"));
            &quoted[..quoted.find('"').unwrap()]
        })
        .collect()
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

    #[test]
    fn a_table_holds_every_state_its_constructors_make() {
        assert_eq!(names(SOURCE), ["area-one", "area-two"]);
        table(
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
        table(
            &[SOURCE],
            &[(State::new("area-one", "One."), "One. [area-one]")],
        );
    }

    #[test]
    #[should_panic(expected = "area-one is in the table twice")]
    fn a_table_that_names_a_state_twice_fails() {
        let one = || State::new("area-one", "One.");
        table(
            &[SOURCE],
            &[(one(), "One. [area-one]"), (one(), "One. [area-one]")],
        );
    }

    #[test]
    #[should_panic(expected = "two constructors make area-one")]
    fn two_constructors_of_one_name_fail() {
        let twice = format!("{SOURCE} State::new(\"area-one\", \"Again.\")");
        table(&[&twice], &[]);
    }

    #[test]
    #[should_panic(expected = "area-two")]
    fn a_line_the_state_does_not_say_fails() {
        table(
            &[SOURCE],
            &[
                (State::new("area-one", "One."), "One. [area-one]"),
                (State::new("area-two", "Two 2."), "Two 3. [area-two]"),
            ],
        );
    }
}
