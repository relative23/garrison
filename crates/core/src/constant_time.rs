//! Comparisons whose duration does not reveal where two secrets differ.
//!
//! The comparison itself is `subtle`'s, which keeps the compiler from turning
//! it back into one that stops at the first difference. A loop written here
//! would be at the mercy of every optimizer to come.

use subtle::ConstantTimeEq;

/// Whether `left` and `right` are equal, without an early exit on the first
/// difference. Only the length may leak, and it is not secret here.
pub fn eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_only_for_the_same_text() {
        assert!(eq("", ""));
        assert!(eq("RUN BACKUP", "RUN BACKUP"));
        assert!(!eq("RUN BACKUP", "RUN BACKUQ"));
        assert!(!eq("RUN", "RUN BACKUP"));
        assert!(!eq("a", ""));
        // Two differences with the same bits must not cancel each other out.
        assert!(!eq("ab", "ba"));
    }
}
