//! The character building blocks a password alphabet is composed from.

use std::ops::{BitOr, BitOrAssign};
use std::{fmt, iter};

const UPPERCASE_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_CHARS: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGIT_CHARS: &str = "0123456789";
const SYMBOL_CHARS: &str = "!@#$%^&*";

/// One of the building blocks a password can be composed from.
///
/// A password alphabet is the concatenation of the character classes enabled in
/// a [`CharClassSet`].
///
/// This enum is `#[non_exhaustive]`: matching on it must include a wildcard arm
/// so that a new variant in a future release does not break existing code.
///
/// # Examples
/// ```
/// use tayna::CharClass;
///
/// assert_eq!(CharClass::Symbols.chars(), "!@#$%^&*");
/// assert_eq!(CharClass::Digits.size(), 10);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CharClass {
    /// The ASCII upper-case letters `A`–`Z`.
    Uppercase,
    /// The ASCII lower-case letters `a`–`z`.
    Lowercase,
    /// The ASCII decimal digits `0`–`9`.
    Digits,
    /// The ASCII symbols `!@#$%^&*`.
    Symbols,
}

impl CharClass {
    /// Every character class, in the crate's canonical order.
    ///
    /// This order determines the layout of a generated alphabet and the iteration
    /// order of a [`CharClassSet`].
    pub const ALL: [Self; 4] = [
        Self::Uppercase,
        Self::Lowercase,
        Self::Digits,
        Self::Symbols,
    ];

    /// The characters belonging to this class.
    ///
    /// # Examples
    /// ```
    /// use tayna::CharClass;
    ///
    /// assert_eq!(CharClass::Digits.chars(), "0123456789");
    /// ```
    #[must_use]
    pub const fn chars(self) -> &'static str {
        match self {
            Self::Uppercase => UPPERCASE_CHARS,
            Self::Lowercase => LOWERCASE_CHARS,
            Self::Digits => DIGIT_CHARS,
            Self::Symbols => SYMBOL_CHARS,
        }
    }

    /// The number of characters in this class.
    ///
    /// # Examples
    /// ```
    /// use tayna::CharClass;
    ///
    /// assert_eq!(CharClass::Uppercase.size(), 26);
    /// ```
    #[must_use]
    pub const fn size(self) -> usize {
        // Every class is ASCII, so the byte length is the character count.
        self.chars().len()
    }

    /// The lower-case, hyphen-free name of this class, as used by
    /// [`Display`](fmt::Display).
    ///
    /// # Examples
    /// ```
    /// use tayna::CharClass;
    ///
    /// assert_eq!(CharClass::Lowercase.name(), "lowercase");
    /// ```
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Uppercase => "uppercase",
            Self::Lowercase => "lowercase",
            Self::Digits => "digits",
            Self::Symbols => "symbols",
        }
    }

    /// The bit representing this class inside a [`CharClassSet`].
    ///
    /// Each class occupies one bit in the set's bit mask.
    const fn bit(self) -> u8 {
        match self {
            Self::Uppercase => 1 << 0,
            Self::Lowercase => 1 << 1,
            Self::Digits => 1 << 2,
            Self::Symbols => 1 << 3,
        }
    }
}

impl fmt::Display for CharClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of [`CharClass`] values.
///
/// The set uses a bit-mask representation, making it cheap to copy and pass
/// around. Iteration always follows [`CharClass::ALL`], which keeps generated
/// alphabets deterministic.
///
/// # Examples
/// ```
/// use tayna::{CharClass, CharClassSet};
///
/// let set = CharClass::Uppercase | CharClass::Digits;
///
/// assert_eq!(set.len(), 2);
/// assert!(set.contains(CharClass::Digits));
/// assert!(!set.contains(CharClass::Symbols));
/// assert_eq!(set.alphabet(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CharClassSet(u8);

impl CharClassSet {
    /// The set containing no classes.
    pub const EMPTY: Self = Self(0);

    /// The set containing every class in [`CharClass::ALL`].
    pub const ALL: Self = Self(
        CharClass::Uppercase.bit()
            | CharClass::Lowercase.bit()
            | CharClass::Digits.bit()
            | CharClass::Symbols.bit(),
    );

    /// Creates an empty set.
    ///
    /// # Examples
    /// ```
    /// use tayna::CharClassSet;
    ///
    /// assert!(CharClassSet::new().is_empty());
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self::EMPTY
    }

    /// Returns `true` if `class` is a member of this set.
    #[must_use]
    pub const fn contains(self, class: CharClass) -> bool {
        self.0 & class.bit() != 0
    }

    /// Returns `true` if this set contains no classes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The number of classes in this set.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Returns this set with `class` added.
    ///
    /// # Examples
    /// ```
    /// use tayna::{CharClass, CharClassSet};
    ///
    /// let set = CharClassSet::new().with(CharClass::Symbols);
    ///
    /// assert!(set.contains(CharClass::Symbols));
    /// assert_eq!(set.len(), 1);
    /// ```
    #[must_use]
    pub const fn with(self, class: CharClass) -> Self {
        Self(self.0 | class.bit())
    }

    /// Returns this set with `class` removed.
    ///
    /// # Examples
    /// ```
    /// use tayna::{CharClass, CharClassSet};
    ///
    /// let set = CharClassSet::ALL.without(CharClass::Symbols);
    ///
    /// assert!(!set.contains(CharClass::Symbols));
    /// assert_eq!(set.len(), 3);
    /// ```
    #[must_use]
    pub const fn without(self, class: CharClass) -> Self {
        Self(self.0 & !class.bit())
    }

    /// Iterates over the classes in this set, in the order of [`CharClass::ALL`].
    ///
    /// # Examples
    /// ```
    /// use tayna::{CharClass, CharClassSet};
    ///
    /// let classes: Vec<_> = CharClassSet::ALL.iter().collect();
    ///
    /// assert_eq!(classes, CharClass::ALL);
    /// ```
    #[must_use]
    pub fn iter(&self) -> CharClassIter {
        CharClassIter {
            set: *self,
            position: 0,
        }
    }

    /// The alphabet spanned by this set: the characters of each member class,
    /// concatenated in [`CharClass::ALL`] order.
    ///
    /// # Examples
    /// ```
    /// use tayna::{CharClass, CharClassSet};
    ///
    /// assert_eq!(CharClassSet::from(CharClass::Digits).alphabet(), "0123456789");
    /// assert!(CharClassSet::EMPTY.alphabet().is_empty());
    /// ```
    #[must_use]
    pub fn alphabet(self) -> String {
        let capacity = self.iter().map(CharClass::size).sum();
        let mut alphabet = String::with_capacity(capacity);
        for class in self {
            alphabet.push_str(class.chars());
        }
        alphabet
    }
}

impl From<CharClass> for CharClassSet {
    fn from(class: CharClass) -> Self {
        Self::EMPTY.with(class)
    }
}

/// An iterator over the members of a [`CharClassSet`].
///
/// Created by [`CharClassSet::iter`]. Yields classes in the order of
/// [`CharClass::ALL`].
#[derive(Debug, Clone)]
pub struct CharClassIter {
    set: CharClassSet,
    position: usize,
}

impl Iterator for CharClassIter {
    type Item = CharClass;

    fn next(&mut self) -> Option<CharClass> {
        while let Some(&class) = CharClass::ALL.get(self.position) {
            self.position += 1;
            if self.set.contains(class) {
                return Some(class);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = CharClass::ALL[self.position..]
            .iter()
            .filter(|class| self.set.contains(**class))
            .count();
        (remaining, Some(remaining))
    }
}

impl iter::ExactSizeIterator for CharClassIter {}

impl iter::FusedIterator for CharClassIter {}

impl FromIterator<CharClass> for CharClassSet {
    fn from_iter<I: IntoIterator<Item = CharClass>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

impl IntoIterator for CharClassSet {
    type Item = CharClass;
    type IntoIter = CharClassIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for &CharClassSet {
    type Item = CharClass;
    type IntoIter = CharClassIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl BitOr for CharClassSet {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOr<CharClass> for CharClassSet {
    type Output = Self;

    fn bitor(self, rhs: CharClass) -> Self {
        self.with(rhs)
    }
}

impl BitOr for CharClass {
    type Output = CharClassSet;

    fn bitor(self, rhs: Self) -> CharClassSet {
        CharClassSet::from(self).with(rhs)
    }
}

impl BitOr<CharClassSet> for CharClass {
    type Output = CharClassSet;

    fn bitor(self, rhs: CharClassSet) -> CharClassSet {
        rhs.with(self)
    }
}

impl BitOrAssign for CharClassSet {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitOrAssign<CharClass> for CharClassSet {
    fn bitor_assign(&mut self, rhs: CharClass) {
        self.0 |= rhs.bit();
    }
}

/// Formats the set as its member names joined by `+`, or `none` when empty.
///
/// # Examples
/// ```
/// use tayna::{CharClass, CharClassSet};
///
/// assert_eq!(
///     (CharClass::Uppercase | CharClass::Digits).to_string(),
///     "uppercase+digits",
/// );
/// assert_eq!(CharClassSet::EMPTY.to_string(), "none");
/// ```
impl fmt::Display for CharClassSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("none");
        }

        for (index, class) in self.iter().enumerate() {
            if index > 0 {
                f.write_str("+")?;
            }
            f.write_str(class.name())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CharClass, CharClassSet, DIGIT_CHARS, LOWERCASE_CHARS, SYMBOL_CHARS, UPPERCASE_CHARS,
    };

    mod char_class {

        use super::*;

        // This verifies the current variants and their order, but cannot detect a new
        // variant that is added without also updating `ALL`.
        #[test]
        fn all_contains_every_class_in_canonical_order() {
            assert_eq!(
                CharClass::ALL,
                [
                    CharClass::Uppercase,
                    CharClass::Lowercase,
                    CharClass::Digits,
                    CharClass::Symbols,
                ]
            );
        }

        #[test]
        fn chars_returns_class_characters() {
            assert_eq!(CharClass::Uppercase.chars(), UPPERCASE_CHARS);
            assert_eq!(CharClass::Lowercase.chars(), LOWERCASE_CHARS);
            assert_eq!(CharClass::Digits.chars(), DIGIT_CHARS);
            assert_eq!(CharClass::Symbols.chars(), SYMBOL_CHARS);
        }

        #[test]
        fn size_returns_number_of_class_characters() {
            for class in CharClass::ALL {
                assert_eq!(class.size(), class.chars().len());
            }
        }

        #[test]
        fn name_returns_class_name() {
            assert_eq!(CharClass::Uppercase.name(), "uppercase");
            assert_eq!(CharClass::Lowercase.name(), "lowercase");
            assert_eq!(CharClass::Digits.name(), "digits");
            assert_eq!(CharClass::Symbols.name(), "symbols");
        }

        #[test]
        fn display_uses_class_name() {
            for class in CharClass::ALL {
                assert_eq!(class.to_string(), class.name());
            }
        }

        #[test]
        fn bits_are_distinct_so_a_set_can_hold_every_class_at_once() {
            let combined = CharClass::ALL
                .into_iter()
                .fold(0u8, |bits, class| bits | class.bit());

            assert_eq!(combined.count_ones() as usize, CharClass::ALL.len());
        }

        #[test]
        fn classes_contain_unique_ascii_characters_and_do_not_overlap() {
            // Overlapping classes would make `alphabet` weight the shared characters twice,
            // so a password would be drawn from a subtly non-uniform distribution.
            let mut seen = Vec::new();
            for class in CharClass::ALL {
                for character in class.chars().chars() {
                    assert!(character.is_ascii(), "{character:?} is not ASCII");
                    assert!(!seen.contains(&character), "{character:?} appears twice");
                    seen.push(character);
                }
            }
        }
    }

    mod char_class_set {
        use super::*;

        #[test]
        fn empty_does_not_contain_a_class() {
            for class in CharClass::ALL {
                assert!(!CharClassSet::EMPTY.contains(class));
            }
            assert!(CharClassSet::EMPTY.is_empty());
            assert_eq!(CharClassSet::EMPTY.len(), 0);
        }

        #[test]
        fn all_contains_every_class() {
            for class in CharClass::ALL {
                assert!(CharClassSet::ALL.contains(class));
            }
            assert!(!CharClassSet::ALL.is_empty());
            assert_eq!(CharClassSet::ALL.len(), CharClass::ALL.len());
        }

        #[test]
        fn new_and_default_both_start_from_the_empty_set() {
            assert_eq!(CharClassSet::new(), CharClassSet::EMPTY);
            assert_eq!(CharClassSet::default(), CharClassSet::EMPTY);
        }

        #[test]
        fn contains_distinguishes_members_from_non_members() {
            let set = CharClass::Uppercase | CharClass::Digits;

            assert!(set.contains(CharClass::Uppercase));
            assert!(set.contains(CharClass::Digits));
            assert!(!set.contains(CharClass::Lowercase));
            assert!(!set.contains(CharClass::Symbols));
        }

        #[test]
        fn is_empty_identifies_empty_and_nonempty_sets() {
            assert!(CharClassSet::EMPTY.is_empty());
            assert!(!CharClassSet::ALL.is_empty());
        }

        #[test]
        fn with_and_without_leave_the_original_untouched() {
            let original = CharClass::Uppercase | CharClass::Digits;

            let added = original.with(CharClass::Symbols);
            let removed = original.without(CharClass::Digits);

            assert_eq!(original, CharClass::Uppercase | CharClass::Digits);
            assert!(added.contains(CharClass::Symbols));
            assert!(!removed.contains(CharClass::Digits));
        }

        #[test]
        fn with_returns_the_same_set_when_class_is_already_present() {
            let set = CharClass::Uppercase | CharClass::Digits;

            assert_eq!(set.with(CharClass::Uppercase), set);
            assert_eq!(set.with(CharClass::Digits), set);
        }

        #[test]
        fn without_returns_the_same_set_when_class_is_already_absent() {
            let set = CharClass::Uppercase | CharClass::Digits;

            assert_eq!(set.without(CharClass::Lowercase), set);
            assert_eq!(set.without(CharClass::Symbols), set);
        }

        #[test]
        fn alphabet_concatenates_member_classes_in_canonical_order() {
            // The set is order-free, but the alphabet is not: it always follows
            // `CharClass::ALL`, regardless of the order the classes were combined in.
            let set = CharClass::Symbols | CharClass::Digits;

            assert_eq!(set.alphabet(), format!("{DIGIT_CHARS}{SYMBOL_CHARS}"));
            assert_eq!(
                CharClassSet::ALL.alphabet(),
                format!("{UPPERCASE_CHARS}{LOWERCASE_CHARS}{DIGIT_CHARS}{SYMBOL_CHARS}")
            );
        }

        #[test]
        fn alphabet_is_empty_for_empty_set() {
            assert_eq!(CharClassSet::EMPTY.alphabet(), "");
        }

        #[test]
        fn from_char_class_creates_a_singleton_set() {
            for class in CharClass::ALL {
                let set = CharClassSet::from(class);

                assert!(set.contains(class));
                assert_eq!(set.len(), 1);
            }
        }

        #[test]
        fn display_joins_member_names_with_plus() {
            assert_eq!(
                (CharClass::Uppercase | CharClass::Digits).to_string(),
                "uppercase+digits"
            );
            assert_eq!(
                CharClassSet::ALL.to_string(),
                "uppercase+lowercase+digits+symbols"
            );
            assert_eq!(CharClassSet::EMPTY.to_string(), "none");
        }
    }

    mod char_class_iter {
        use super::*;

        #[test]
        fn iteration_follows_canonical_order_regardless_of_insertion_order() {
            let set = CharClass::Symbols | CharClass::Digits | CharClass::Uppercase;

            let classes: Vec<_> = set.iter().collect();

            assert_eq!(
                classes,
                [CharClass::Uppercase, CharClass::Digits, CharClass::Symbols]
            );
        }

        #[test]
        fn iter_by_value_and_by_reference_agree() {
            let set = CharClass::Symbols | CharClass::Uppercase;

            let via_iter: Vec<_> = set.iter().collect();
            let via_value: Vec<_> = set.into_iter().collect();
            let via_reference: Vec<_> = (&set).into_iter().collect();

            assert_eq!(via_iter, via_value);
            assert_eq!(via_iter, via_reference);
        }

        #[test]
        fn iterator_reports_its_exact_remaining_length() {
            // `ExactSizeIterator` is only sound if `size_hint` stays truthful as the
            // iterator is consumed, so it is checked after every step rather than just at
            // the start.
            let mut iter = (CharClass::Uppercase | CharClass::Digits).iter();
            assert_eq!(iter.size_hint(), (2, Some(2)));
            assert_eq!(iter.len(), 2);

            assert_eq!(iter.next(), Some(CharClass::Uppercase));
            assert_eq!(iter.size_hint(), (1, Some(1)));

            assert_eq!(iter.next(), Some(CharClass::Digits));
            assert_eq!(iter.size_hint(), (0, Some(0)));

            assert_eq!(iter.next(), None);
            assert_eq!(iter.size_hint(), (0, Some(0)));
        }

        #[test]
        fn exhausted_iterator_keeps_returning_none() {
            // `FusedIterator` promises this, so callers may keep polling after exhaustion.
            let mut iter = CharClassSet::EMPTY.iter();

            assert_eq!(iter.next(), None);
            assert_eq!(iter.next(), None);
        }

        #[test]
        fn collecting_builds_a_set_and_collapses_duplicates() {
            let set: CharClassSet = [CharClass::Digits, CharClass::Digits, CharClass::Symbols]
                .into_iter()
                .collect();

            assert_eq!(set, CharClass::Digits | CharClass::Symbols);
        }

        #[test]
        fn collecting_empty_iterator_creates_empty_set() {
            let set: CharClassSet = std::iter::empty().collect();

            assert_eq!(set, CharClassSet::EMPTY);
        }
    }

    mod operators {
        use super::*;

        #[test]
        fn bitor_combines_two_classes() {
            let set = CharClass::Uppercase | CharClass::Digits;

            assert_eq!(set.len(), 2);
            assert!(set.contains(CharClass::Uppercase));
            assert!(set.contains(CharClass::Digits));
        }

        #[test]
        fn bitor_accepts_every_combination_of_class_and_set() {
            let expected = CharClass::Uppercase | CharClass::Lowercase;
            let set_uppercase = CharClassSet::from(CharClass::Uppercase);
            let set_lowercase = CharClassSet::from(CharClass::Lowercase);

            assert_eq!(set_uppercase | set_lowercase, expected);
            assert_eq!(set_uppercase | CharClass::Lowercase, expected);
            assert_eq!(CharClass::Uppercase | set_lowercase, expected);
        }

        #[test]
        fn bitor_assign_accepts_both_a_class_and_a_set() {
            let mut class_rhs = CharClassSet::from(CharClass::Uppercase);
            let mut set_rhs = CharClassSet::from(CharClass::Uppercase);

            class_rhs |= CharClass::Digits;
            set_rhs |= CharClassSet::from(CharClass::Digits);

            assert_eq!(class_rhs, CharClass::Uppercase | CharClass::Digits);
            assert_eq!(set_rhs, CharClass::Uppercase | CharClass::Digits);
        }

        #[test]
        fn bitor_assign_is_idempotent() {
            let mut set = CharClass::Uppercase | CharClass::Digits;

            set |= CharClass::Uppercase;
            assert_eq!(set, CharClass::Uppercase | CharClass::Digits);

            set |= CharClassSet::from(CharClass::Digits);
            assert_eq!(set, CharClass::Uppercase | CharClass::Digits);
        }
    }
}
