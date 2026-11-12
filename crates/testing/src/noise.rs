//! Deterministic random input for tests of the parsers that read what others
//! wrote: archive names, checksum lists, HTTP answers, tool output. The same
//! inputs on every run, and no dependency.

#[derive(Debug)]
pub struct Noise(u64);

impl Noise {
    /// A generator that starts from `seed`; each seed gives its own sequence.
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    /// The next number, by xorshift64.
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A number below `bound`, or 0 when `bound` is 0.
    pub fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(bound.max(1)).unwrap_or(1)).unwrap_or(0)
    }

    /// Up to `longest` characters drawn from `alphabet`; empty if it is empty.
    pub fn text(&mut self, alphabet: &str, longest: usize) -> String {
        let characters: Vec<char> = alphabet.chars().collect();
        if characters.is_empty() {
            return String::new();
        }
        let length = self.below(longest + 1);
        (0..length)
            .map(|_| characters[self.below(characters.len())])
            .collect()
    }
}
