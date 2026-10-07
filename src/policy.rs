//! The password policy and its builder.

use rand::seq::SliceRandom as _;
use rand::{Rng, RngExt as _};

use crate::char_class::{CharClass, CharClassSet};
use crate::error::PolicyError;
use crate::password::Password;

/// A validated description of the passwords to generate.
///
/// A `PasswordPolicy` can only be created through [`PasswordPolicy::builder`],
/// and [`PasswordPolicyBuilder::build`] rejects every invalid combination of
/// settings. Holding a policy therefore proves that a password can be produced
/// from it, which is why [`generate`](Self::generate) returns a [`Password`]
/// rather than a `Result`.
///
/// Building a policy precomputes its alphabet, so a policy is cheap to reuse
/// across many generations.
///
/// # Examples
/// ```
/// use tayna::PasswordPolicy;
///
/// let policy = PasswordPolicy::builder()
///     .length(24)
///     .symbols(false)
///     .build()?;
///
/// let password = policy.generate();
///
/// assert_eq!(password.len(), 24);
/// assert!(password.as_str().chars().all(|c| c.is_ascii_alphanumeric()));
/// # Ok::<(), tayna::PolicyError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    length: usize,
    classes: CharClassSet,
    require_each_enabled_class: bool,
    alphabet: String,
}

impl PasswordPolicy {
    /// The shortest password this crate will generate.
    pub const MIN_LENGTH: usize = 6;

    /// The longest password this crate will generate.
    pub const MAX_LENGTH: usize = 128;

    /// Starts building a policy.
    ///
    /// The returned builder enables all four character classes and requires at
    /// least one character from each; only the length still has to be set.
    ///
    /// # Examples
    /// ```
    /// use tayna::{CharClassSet, PasswordPolicy};
    ///
    /// let policy = PasswordPolicy::builder().length(16).build()?;
    ///
    /// assert_eq!(policy.classes(), CharClassSet::ALL);
    /// # Ok::<(), tayna::PolicyError>(())
    /// ```
    #[must_use]
    pub fn builder() -> PasswordPolicyBuilder {
        PasswordPolicyBuilder::new()
    }

    /// The length of the passwords this policy produces.
    #[must_use]
    pub const fn length(&self) -> usize {
        self.length
    }

    /// The character classes this policy draws from.
    #[must_use]
    pub const fn classes(&self) -> CharClassSet {
        self.classes
    }

    /// Whether every enabled class must appear at least once in the result.
    #[must_use]
    pub const fn requires_each_enabled_class(&self) -> bool {
        self.require_each_enabled_class
    }

    /// The characters in this policy's alphabet, with character classes in
    /// canonical order.
    ///
    /// # Examples
    /// ```
    /// use tayna::{CharClass, PasswordPolicy};
    ///
    /// let policy = PasswordPolicy::builder()
    ///     .length(10)
    ///     .classes(CharClass::Digits)
    ///     .build()?;
    ///
    /// assert_eq!(policy.alphabet(), "0123456789");
    /// # Ok::<(), tayna::PolicyError>(())
    /// ```
    #[must_use]
    pub fn alphabet(&self) -> &str {
        &self.alphabet
    }

    /// Generates a password using the default cryptographic random number
    /// generator.
    ///
    /// # Examples
    /// ```
    /// use tayna::PasswordPolicy;
    ///
    /// let policy = PasswordPolicy::builder().length(32).build()?;
    ///
    /// assert_ne!(policy.generate().as_str(), policy.generate().as_str());
    /// # Ok::<(), tayna::PolicyError>(())
    /// ```
    #[must_use]
    pub fn generate(&self) -> Password {
        self.generate_with(&mut rand::rng())
    }

    /// Generates a password using the supplied random number generator.
    ///
    /// This is the entry point for reproducible tests and for callers who want to
    /// supply their own source of randomness. For passwords intended to be used as
    /// secrets, the supplied generator should implement
    /// [`CryptoRng`](rand::CryptoRng).
    ///
    /// # Examples
    /// ```
    /// use rand::SeedableRng as _;
    /// use rand::rngs::StdRng;
    /// use tayna::PasswordPolicy;
    ///
    /// let policy = PasswordPolicy::builder().length(16).build()?;
    ///
    /// let first = policy.generate_with(&mut StdRng::seed_from_u64(42));
    /// let second = policy.generate_with(&mut StdRng::seed_from_u64(42));
    ///
    /// assert_eq!(first.as_str(), second.as_str());
    /// # Ok::<(), tayna::PolicyError>(())
    /// ```
    #[must_use]
    pub fn generate_with<R: Rng + ?Sized>(&self, rng: &mut R) -> Password {
        // The whole alphabet is ASCII, so the password can be assembled as bytes. This
        // avoids the larger 4-byte-per-character `char` representation.
        let mut bytes: Vec<u8> = Vec::with_capacity(self.length);

        if self.require_each_enabled_class {
            // One character per class first, so the requirement is satisfied by
            // construction. This can never overshoot `length`: see the compile-time
            // assertion below.
            for class in self.classes {
                bytes.push(pick(class.chars().as_bytes(), rng));
            }
        }

        while bytes.len() < self.length {
            bytes.push(pick(self.alphabet.as_bytes(), rng));
        }

        // Without this the mandatory characters would always occupy the leading
        // positions, which leaks the class layout and weakens the password.
        bytes.shuffle(rng);

        let password = Password::new(bytes.iter().map(|&byte| byte as char).collect());

        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize as _;

            // The buffer still holds a full copy of the secret.
            bytes.zeroize();
        }

        password
    }
}

/// Picks one element uniformly at random.
///
/// `pool` is never empty: class alphabets are non-empty compile-time constants
/// and a policy's alphabet is non-empty by construction, so the range passed to
/// `random_range` is never degenerate.
fn pick<R: Rng + ?Sized>(pool: &[u8], rng: &mut R) -> u8 {
    pool[rng.random_range(0..pool.len())]
}

/// Guarantees that "one character from every class" is always satisfiable.
///
/// The shortest permitted password must be able to hold one character from each
/// class. This holds today (6 >= 4) and is asserted at compile time so that
/// lowering [`PasswordPolicy::MIN_LENGTH`] or adding a fifth [`CharClass`]
/// breaks the build instead of producing passwords that silently violate their
/// own policy.
const _: () = assert!(PasswordPolicy::MIN_LENGTH >= CharClass::ALL.len());

/// A builder for [`PasswordPolicy`].
///
/// Created by [`PasswordPolicy::builder`]. Every setter takes and returns
/// `self`, so calls can be chained; [`build`](Self::build) performs all
/// validation.
///
/// # Examples
/// ```
/// use tayna::{CharClass, CharClassSet, PasswordPolicy, PolicyError};
///
/// let policy = PasswordPolicy::builder()
///     .length(12)
///     .without_class(CharClass::Symbols)
///     .without_class(CharClass::Digits)
///     .build()?;
///
/// assert_eq!(policy.classes().len(), 2);
///
/// // Disabling every class is rejected rather than silently producing nothing.
/// let error = PasswordPolicy::builder()
///     .length(12)
///     .classes(CharClassSet::EMPTY)
///     .build()
///     .unwrap_err();
///
/// assert_eq!(error, PolicyError::NoCharacterClasses);
/// # Ok::<(), PolicyError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicyBuilder {
    length: Option<usize>,
    classes: CharClassSet,
    require_each_enabled_class: bool,
}

impl PasswordPolicyBuilder {
    /// Creates a builder with all four character classes enabled, each of them
    /// required, and no length set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            length: None,
            classes: CharClassSet::ALL,
            require_each_enabled_class: true,
        }
    }

    /// Sets the password length.
    ///
    /// This is the one setting without a default. The length must be between
    /// [`PasswordPolicy::MIN_LENGTH`] and [`PasswordPolicy::MAX_LENGTH`],
    /// inclusive.
    #[must_use]
    pub const fn length(mut self, length: usize) -> Self {
        self.length = Some(length);
        self
    }

    /// Replaces the set of character classes.
    ///
    /// # Examples
    /// ```
    /// use tayna::{CharClass, PasswordPolicy};
    ///
    /// let policy = PasswordPolicy::builder()
    ///     .length(10)
    ///     .classes(CharClass::Lowercase | CharClass::Digits)
    ///     .build()?;
    ///
    /// assert_eq!(policy.classes().len(), 2);
    /// # Ok::<(), tayna::PolicyError>(())
    /// ```
    #[must_use]
    pub fn classes<T: Into<CharClassSet>>(mut self, classes: T) -> Self {
        self.classes = classes.into();
        self
    }

    /// Enables one character class.
    ///
    /// # Examples
    /// ```
    /// use tayna::{CharClass, PasswordPolicy};
    ///
    /// let policy = PasswordPolicy::builder()
    ///     .length(10)
    ///     .classes(CharClass::Lowercase)
    ///     .with_class(CharClass::Digits)
    ///     .build()?;
    ///
    /// assert_eq!(policy.alphabet(), "abcdefghijklmnopqrstuvwxyz0123456789");
    /// # Ok::<(), tayna::PolicyError>(())
    /// ```
    #[must_use]
    pub const fn with_class(mut self, class: CharClass) -> Self {
        self.classes = self.classes.with(class);
        self
    }

    /// Disables one character class.
    ///
    /// # Examples
    /// ```
    /// use tayna::{CharClass, PasswordPolicy};
    ///
    /// let policy = PasswordPolicy::builder()
    ///     .length(10)
    ///     .without_class(CharClass::Symbols)
    ///     .build()?;
    ///
    /// assert!(!policy.classes().contains(CharClass::Symbols));
    /// # Ok::<(), tayna::PolicyError>(())
    /// ```
    #[must_use]
    pub const fn without_class(mut self, class: CharClass) -> Self {
        self.classes = self.classes.without(class);
        self
    }

    /// Enables or disables one character class.
    const fn set_class(self, class: CharClass, enabled: bool) -> Self {
        if enabled {
            self.with_class(class)
        } else {
            self.without_class(class)
        }
    }

    /// Enables or disables the upper-case letters `A`–`Z`.
    #[must_use]
    pub const fn uppercase(self, enabled: bool) -> Self {
        self.set_class(CharClass::Uppercase, enabled)
    }

    /// Enables or disables the lower-case letters `a`–`z`.
    #[must_use]
    pub const fn lowercase(self, enabled: bool) -> Self {
        self.set_class(CharClass::Lowercase, enabled)
    }

    /// Enables or disables the digits `0`–`9`.
    #[must_use]
    pub const fn digits(self, enabled: bool) -> Self {
        self.set_class(CharClass::Digits, enabled)
    }

    /// Enables or disables the symbols `!@#$%^&*`.
    #[must_use]
    pub const fn symbols(self, enabled: bool) -> Self {
        self.set_class(CharClass::Symbols, enabled)
    }

    /// Requires or merely permits at least one character from every enabled
    /// character class to appear.
    ///
    /// When `required` is `true`, a generated password contains at least one
    /// character from every enabled class. When `false`, characters are drawn
    /// freely from the combined alphabet, so a short password may omit a class.
    ///
    /// # Examples
    /// ```
    /// use rand::SeedableRng as _;
    /// use rand::rngs::StdRng;
    /// use tayna::{CharClass, PasswordPolicy};
    ///
    /// let strict = PasswordPolicy::builder().length(6).build()?;
    /// let relaxed = PasswordPolicy::builder()
    ///     .length(6)
    ///     .require_each_enabled_class(false)
    ///     .build()?;
    ///
    /// // The strict policy guarantees a digit in every password it produces.
    /// let password = strict.generate_with(&mut StdRng::seed_from_u64(7));
    /// assert!(password.as_str().chars().any(|c| c.is_ascii_digit()));
    ///
    /// // The relaxed one draws freely, so six characters need not cover all four
    /// // classes.
    /// assert!(!relaxed.requires_each_enabled_class());
    /// # Ok::<(), tayna::PolicyError>(())
    /// ```
    #[must_use]
    pub const fn require_each_enabled_class(mut self, required: bool) -> Self {
        self.require_each_enabled_class = required;
        self
    }

    /// Validates the settings and produces a [`PasswordPolicy`].
    ///
    /// # Errors
    /// * [`PolicyError::MissingLength`] if [`length`](Self::length) was never
    ///   called.
    /// * [`PolicyError::InvalidLength`] if the length was not between
    ///   [`PasswordPolicy::MIN_LENGTH`] and [`PasswordPolicy::MAX_LENGTH`],
    ///   inclusive.
    /// * [`PolicyError::NoCharacterClasses`] if every class was disabled.
    ///
    /// Requiring at least one character from every enabled class is always
    /// satisfiable because [`PasswordPolicy::MIN_LENGTH`] is at least the number of
    /// character classes.
    ///
    /// # Examples
    /// ```
    /// use tayna::{PasswordPolicy, PolicyError};
    ///
    /// assert_eq!(
    ///     PasswordPolicy::builder().build().unwrap_err(),
    ///     PolicyError::MissingLength,
    /// );
    ///
    /// assert!(matches!(
    ///     PasswordPolicy::builder().length(5).build().unwrap_err(),
    ///     PolicyError::InvalidLength(5),
    /// ));
    /// ```
    pub fn build(self) -> Result<PasswordPolicy, PolicyError> {
        let length = self.length.ok_or(PolicyError::MissingLength)?;

        if !(PasswordPolicy::MIN_LENGTH..=PasswordPolicy::MAX_LENGTH).contains(&length) {
            return Err(PolicyError::InvalidLength(length));
        }

        if self.classes.is_empty() {
            return Err(PolicyError::NoCharacterClasses);
        }

        Ok(PasswordPolicy {
            length,
            classes: self.classes,
            require_each_enabled_class: self.require_each_enabled_class,
            alphabet: self.classes.alphabet(),
        })
    }
}

impl Default for PasswordPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    use super::{PasswordPolicy, PasswordPolicyBuilder};
    use crate::char_class::{CharClass, CharClassSet};
    use crate::error::PolicyError;

    /// A fixed seed keeps the statistical tests below reproducible across runs.
    fn seeded() -> StdRng {
        StdRng::seed_from_u64(528_491)
    }

    mod construction {
        use super::*;

        #[test]
        fn default_builder_enables_every_class_and_requires_each() {
            let builder = PasswordPolicyBuilder::default();

            assert_eq!(builder.length, None);
            assert_eq!(builder.classes, CharClassSet::ALL);
            assert!(builder.require_each_enabled_class);
        }

        #[test]
        fn build_rejects_a_missing_length() {
            assert_eq!(
                PasswordPolicy::builder().build().unwrap_err(),
                PolicyError::MissingLength
            );
        }

        #[test]
        fn build_rejects_lengths_just_outside_the_bounds() {
            for length in [
                PasswordPolicy::MIN_LENGTH - 1,
                PasswordPolicy::MAX_LENGTH + 1,
            ] {
                assert_eq!(
                    PasswordPolicy::builder()
                        .length(length)
                        .build()
                        .unwrap_err(),
                    PolicyError::InvalidLength(length),
                    "length {length} should be rejected"
                );
            }
        }

        #[test]
        fn build_accepts_the_boundary_lengths() {
            for length in [PasswordPolicy::MIN_LENGTH, PasswordPolicy::MAX_LENGTH] {
                assert!(
                    PasswordPolicy::builder().length(length).build().is_ok(),
                    "length {length} should be accepted"
                );
            }
        }

        #[test]
        fn build_rejects_an_empty_class_set() {
            let error = PasswordPolicy::builder()
                .length(12)
                .uppercase(false)
                .lowercase(false)
                .digits(false)
                .symbols(false)
                .build()
                .unwrap_err();

            assert_eq!(error, PolicyError::NoCharacterClasses);
        }

        #[test]
        fn policy_accessors_reflect_configured_settings() {
            let policy = PasswordPolicy::builder()
                .length(20)
                .symbols(false)
                .require_each_enabled_class(false)
                .build()
                .unwrap();

            assert_eq!(policy.length(), 20);
            assert_eq!(
                policy.classes(),
                CharClassSet::ALL.without(CharClass::Symbols)
            );
            assert!(!policy.requires_each_enabled_class());
            assert_eq!(
                policy.alphabet(),
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            );
        }
    }

    mod generation {
        use super::*;

        use core::convert::Infallible;

        // Tests that use `ScriptedRng` below are deterministic: the generator fixes
        // every random choice made by the code under test. Tests that use `seeded()`
        // are also reproducible, but exercise the implementation with a real seeded RNG
        // rather than forcing individual choices.

        /// A generator that replays a fixed sequence of values, cycling when exhausted.
        ///
        /// `values` contains the values the generator will return, while `position`
        /// tracks which value comes next. Once the end of `values` is reached, the
        /// generator starts again from the beginning.
        ///
        /// Tests use this to make random choices deterministic, including forcing the
        /// lowest or highest possible index.
        struct ScriptedRng {
            /// The sequence of values to return from the generator.
            values: &'static [u32],
            /// The index of the next value in `values`.
            position: usize,
        }

        impl ScriptedRng {
            /// Creates a generator that always returns zero.
            ///
            /// When `rand` maps the generated value to a range, zero selects the first
            /// element.
            const fn lowest() -> Self {
                Self::replaying(&[0])
            }

            /// Creates a generator that always returns the maximum `u32` value.
            ///
            /// When `rand` maps the generated value to a range, this selects the last
            /// element.
            const fn highest() -> Self {
                Self::replaying(&[u32::MAX])
            }

            /// Creates a generator that replays the given sequence of values.
            ///
            /// The sequence is repeated from the beginning when the generator reaches its
            /// end.
            const fn replaying(values: &'static [u32]) -> Self {
                Self {
                    values,
                    position: 0,
                }
            }
        }

        // `rand` 0.10 builds `Rng` functionality on top of `TryRng`. Implementing
        // `TryRng` therefore provides the random-number operations used by the code
        // under test. `Infallible` means this test generator never fails.
        impl rand::TryRng for ScriptedRng {
            type Error = Infallible;

            /// Returns the next scripted `u32`, then advances to the following value.
            ///
            /// The modulo makes the sequence repeat when `position` reaches the end of
            /// `values`.
            fn try_next_u32(&mut self) -> Result<u32, Infallible> {
                let value = self.values[self.position % self.values.len()];
                self.position += 1;
                Ok(value)
            }

            /// Produces a `u64` from two consecutive scripted `u32` values.
            ///
            /// The first value supplies the low 32 bits and the second supplies the high 32
            /// bits.
            fn try_next_u64(&mut self) -> Result<u64, Infallible> {
                let low = u64::from(self.try_next_u32()?);
                let high = u64::from(self.try_next_u32()?);
                Ok((high << 32) | low)
            }

            /// Fills a byte slice using consecutive scripted `u32` values.
            ///
            /// Each value is converted to four bytes in little-endian order. The final
            /// chunk may contain fewer than four bytes, in which case only the required
            /// bytes are copied.
            fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Infallible> {
                for chunk in destination.chunks_mut(4) {
                    let value = self.try_next_u32()?.to_le_bytes();
                    chunk.copy_from_slice(&value[..chunk.len()]);
                }
                Ok(())
            }
        }

        #[test]
        fn required_classes_are_present_in_generated_password() {
            // `lowest()` always selects the first character from every pool, so the
            // per-class seeding step is what contributes `A`, `a`, `0`, and `!`. Without
            // that step the same RNG would yield only `A`s, which is what makes this
            // assertion meaningful.
            let policy = PasswordPolicy::builder().length(8).build().unwrap();

            let password = policy.generate_with(&mut ScriptedRng::lowest());

            for class in policy.classes() {
                assert!(
                    password.as_str().chars().any(|c| class.chars().contains(c)),
                    "{class} missing from {password:?}"
                );
            }
        }

        #[test]
        fn optional_classes_can_be_absent_from_generated_password() {
            // With the requirement disabled, `lowest()` always selects the first character
            // of the combined alphabet, so every character is `A`. This pins the difference
            // exactly, rather than generating many passwords until one happens to omit a
            // class.
            let policy = PasswordPolicy::builder()
                .length(8)
                .require_each_enabled_class(false)
                .build()
                .unwrap();

            let password = policy.generate_with(&mut ScriptedRng::lowest());

            assert_eq!(password.as_str(), "AAAAAAAA");
        }

        #[test]
        fn first_and_last_alphabet_characters_can_be_selected() {
            // `lowest()` and `highest()` force `pick()` to select the two ends of the
            // allowed range. This catches an off-by-one error that could make the last
            // character of the alphabet unreachable, silently shrinking the alphabet.
            let policy = PasswordPolicy::builder()
                .length(8)
                .require_each_enabled_class(false)
                .build()
                .unwrap();

            let lowest = policy.generate_with(&mut ScriptedRng::lowest());
            let highest = policy.generate_with(&mut ScriptedRng::highest());

            assert_eq!(
                lowest.as_str().chars().next(),
                policy.alphabet().chars().next()
            );
            assert_eq!(
                highest.as_str().chars().next(),
                policy.alphabet().chars().last()
            );
        }

        #[test]
        fn seeded_characters_are_not_left_in_the_leading_positions() {
            // The seeded RNG is deterministic, but the assertion checks that at least one
            // of 64 generated passwords must start with a character outside the upper-case
            // class (probabilistic test). Without the shuffle, the first character would
            // always be upper-case.
            let policy = PasswordPolicy::builder()
                .length(PasswordPolicy::MIN_LENGTH)
                .build()
                .unwrap();
            let mut rng = seeded();

            let leading_class_varies = (0..64).any(|_| {
                let password = policy.generate_with(&mut rng);
                let first = password
                    .as_str()
                    .chars()
                    .next()
                    .expect("non-empty password");
                !CharClass::Uppercase.chars().contains(first)
            });

            assert!(
                leading_class_varies,
                "the first element was always upper-case, so the seeded elements were not shuffled"
            );
        }

        #[test]
        fn generation_honours_length_and_alphabet() {
            let policy = PasswordPolicy::builder().length(32).build().unwrap();

            let password = policy.generate_with(&mut seeded());

            assert_eq!(password.len(), 32);
            assert!(
                password
                    .as_str()
                    .chars()
                    .all(|c| policy.alphabet().contains(c))
            );
        }

        #[test]
        fn generation_with_one_class_uses_only_that_class() {
            let policy = PasswordPolicy::builder()
                .length(PasswordPolicy::MAX_LENGTH)
                .classes(CharClass::Digits)
                .build()
                .unwrap();

            let password = policy.generate_with(&mut seeded());

            assert!(
                password
                    .as_str()
                    .chars()
                    .all(|c| CharClass::Digits.chars().contains(c))
            );
        }

        #[test]
        fn generation_is_reproducible_for_a_given_seed() {
            let policy = PasswordPolicy::builder().length(32).build().unwrap();

            let first = policy.generate_with(&mut seeded()).into_string();
            let second = policy.generate_with(&mut seeded()).into_string();

            assert_eq!(first, second);
        }
    }
}
