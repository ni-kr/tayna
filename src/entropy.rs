//! The size of the password space a policy permits, measured in bits, and the
//! plain-language rating that follows from it.

use std::fmt;

use crate::char_class::CharClass;

/// A rating of how difficult a password is to guess, based on the password
/// entropy in bits.
///
/// Obtained from [`PasswordPolicy::strength`](crate::PasswordPolicy::strength)
/// or from [`from_bits`](Self::from_bits). It provides a plain-language
/// interpretation of [`entropy_bits`](crate::PasswordPolicy::entropy_bits).
///
/// The boundaries are practical guidelines, not a standard:
///
/// - `Weak`: fewer than 60 bits
/// - `Moderate`: at least 60 but fewer than 80 bits
/// - `Strong`: at least 80 but fewer than 128 bits
/// - `VeryStrong`: 128 bits or more
///
/// How much entropy is enough depends on what the password protects.
///
/// # Examples
/// ```
/// use tayna::{PasswordPolicy, PasswordStrength};
///
/// let policy = PasswordPolicy::builder().length(16).build()?;
///
/// assert_eq!(policy.strength(), PasswordStrength::Strong);
/// assert_eq!(policy.strength().to_string(), "strong");
///
/// // The ratings are ordered, so a minimum bar can be expressed directly.
/// assert!(policy.strength() >= PasswordStrength::Strong);
/// # Ok::<(), tayna::PolicyError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PasswordStrength {
    /// Fewer than 60 bits of entropy.
    Weak,
    /// At least 60 but fewer than 80 bits of entropy.
    Moderate,
    /// At least 80 but fewer than 128 bits of entropy.
    Strong,
    /// At least 128 bits of entropy.
    VeryStrong,
}

impl PasswordStrength {
    /// The entropy in bits at which a password becomes
    /// [`Moderate`](Self::Moderate).
    const MODERATE_BITS: f64 = 60.0;

    /// The entropy in bits at which a password becomes [`Strong`](Self::Strong).
    const STRONG_BITS: f64 = 80.0;

    /// The entropy in bits at which a password becomes
    /// [`VeryStrong`](Self::VeryStrong).
    const VERY_STRONG_BITS: f64 = 128.0;

    /// Rates a number of bits of entropy.
    ///
    /// A value that is not a number is rated [`Weak`](Self::Weak), which is the
    /// safest reading of an entropy figure that cannot be interpreted.
    ///
    /// # Examples
    /// ```
    /// use tayna::PasswordStrength;
    ///
    /// assert_eq!(PasswordStrength::from_bits(19.9), PasswordStrength::Weak);
    /// assert_eq!(PasswordStrength::from_bits(97.7), PasswordStrength::Strong);
    /// ```
    #[must_use]
    pub fn from_bits(bits: f64) -> Self {
        if bits.is_nan() || bits < Self::MODERATE_BITS {
            Self::Weak
        } else if bits < Self::STRONG_BITS {
            Self::Moderate
        } else if bits < Self::VERY_STRONG_BITS {
            Self::Strong
        } else {
            Self::VeryStrong
        }
    }

    /// The lower-case name of this rating, as used by [`Display`](fmt::Display).
    ///
    /// # Examples
    /// ```
    /// use tayna::PasswordStrength;
    ///
    /// assert_eq!(PasswordStrength::VeryStrong.name(), "very strong");
    /// ```
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Moderate => "moderate",
            Self::Strong => "strong",
            Self::VeryStrong => "very strong",
        }
    }
}

impl fmt::Display for PasswordStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Calculates the base-2 logarithm of the number of distinct passwords of
/// `length` that can be assembled from character pools of the given sizes.
///
/// `pool_sizes` contains one entry per character pool, giving the number of
/// that pool's characters present in the alphabet. The pools must be disjoint.
///
/// When `require_each_pool` is `false`, every password over the combined
/// alphabet is permitted, giving `length * log2(alphabet_size)` bits of
/// entropy. When it is `true`, only passwords containing at least one character
/// from every pool are permitted.
///
/// The arguments must describe a password space containing at least one
/// password:
///
/// - `length` must be greater than zero.
/// - `pool_sizes` must contain at least one entry, and every entry must be
///   greater than zero.
/// - When `require_each_pool` is `true`, `length` must be at least the number
///   of pools, since every pool must contribute at least one character.
///
/// This function is an internal implementation used to calculate the entropy of
/// a [`PasswordPolicy`](crate::PasswordPolicy). The first two follow from its
/// length and character-class bounds. The third follows from the compile-time
/// assertion in `policy.rs`, which ensures that the minimum permitted password
/// length can accommodate every character class. Since constructing a policy
/// guarantees that these preconditions are satisfied, there is no need to
/// return a [`Result`].
pub(crate) fn bits(pool_sizes: &[usize], length: usize, require_each_pool: bool) -> f64 {
    debug_assert!(length > 0, "password length must be greater than zero");
    debug_assert!(
        !pool_sizes.is_empty(),
        "at least one character pool is required"
    );
    debug_assert!(
        pool_sizes.iter().all(|&size| size > 0),
        "every character pool must contain at least one character: {pool_sizes:?}"
    );

    let alphabet_size: usize = pool_sizes.iter().sum();
    let unconstrained = exact(length) * exact(alphabet_size).log2();

    if !require_each_pool {
        return unconstrained;
    }

    // Adding the logarithm of the fraction avoids computing the number of valid
    // passwords directly, which can exceed the range of `f64`.
    unconstrained + fraction_of_passwords_using_all_pools(pool_sizes, length).log2()
}

/// Guarantees that one bit per character class fits in the subset mask used by
/// [`fraction_of_passwords_using_all_pools`].
///
/// The mask is a `u32`, which leaves room for far more classes than the crate
/// currently has. Reaching this limit is highly unlikely, but adding classes
/// beyond it would break the build rather than silently produce a wrong figure.
const _: () = assert!(CharClass::ALL.len() < u32::BITS as usize);

/// Calculates the fraction of passwords of the specified `length` that contain
/// at least one character from every character pool.
///
/// `pool_sizes` contains one entry per character pool, giving the number of
/// that pool's characters present in the alphabet. The pools must be disjoint.
///
/// It is assumed that each character position is selected independently and
/// uniformly from the combined alphabet. The fraction is calculated using the
/// inclusion-exclusion principle.
///
/// This function is called by [`bits`] when every pool must be represented in
/// the password. Its argument preconditions, and why they are satisfied in this
/// crate, are documented for [`bits`].
fn fraction_of_passwords_using_all_pools(pool_sizes: &[usize], length: usize) -> f64 {
    debug_assert!(
        pool_sizes.len() <= length,
        "password length ({length}) is shorter than the number of character pools ({})",
        pool_sizes.len()
    );

    let alphabet_size: usize = pool_sizes.iter().sum();

    // Start at zero. The empty subset is included in the loop and contributes the
    // initial +1 term of the inclusion-exclusion formula.
    let mut fraction = 0.0;
    let exponent = exact(length);

    // Enumerate every subset of excluded character pools. Each bit in `subset`
    // indicates whether the corresponding pool is excluded. With n pools, there are
    // 2^n possible subsets, including the empty subset.
    for subset in 0..(1_u32 << pool_sizes.len()) {
        // Calculate the total number of characters belonging to the excluded pools.
        let excluded: usize = pool_sizes
            .iter()
            .enumerate()
            .filter(|(index, _)| subset & (1 << index) != 0)
            .map(|(_, size)| size)
            .sum();

        // Calculate the proportion of the original alphabet that remains after
        // excluding the selected pools.
        let share = exact(alphabet_size - excluded) / exact(alphabet_size);

        // Calculate the fraction of passwords whose characters all belong to the
        // remaining alphabet. Since each position is selected independently, the
        // fractions for individual positions are multiplied.
        let term = share.powf(exponent);

        // Apply the inclusion-exclusion principle:
        // - Add terms when an even number of pools is excluded.
        // - Subtract terms when an odd number of pools is excluded.
        if subset.count_ones() % 2 == 0 {
            fraction += term;
        } else {
            fraction -= term;
        }
    }

    fraction
}

/// Converts a count to the `f64` representing the same value.
///
/// Every count reaching this function is a password length or a number of
/// characters in an alphabet. Both are bounded by
/// [`PasswordPolicy::MAX_LENGTH`](crate::PasswordPolicy::MAX_LENGTH) and the
/// size of the crate's alphabet respectively, which are far below the 2^53
/// limit of exact integer representation in an `f64`.
#[expect(
    clippy::cast_precision_loss,
    reason = "counts are far below the exactly representable range"
)]
const fn exact(count: usize) -> f64 {
    count as f64
}

#[cfg(test)]
mod tests {
    use std::iter;

    use super::{PasswordStrength, bits};

    /// How close two entropy figures have to be to count as equal.
    const EPSILON: f64 = 1e-9;

    /// Counts the number of passwords of the specified `length` that contain at
    /// least one character from every character pool.
    ///
    /// This brute-force implementation serves as a reference for testing the
    /// inclusion-exclusion calculation. Only suitable for tiny alphabets and
    /// lengths.
    fn brute_force_count(pool_sizes: &[usize], length: usize) -> usize {
        // Build an artificial alphabet where each entry identifies the pool to which
        // one character belongs. Actual character values are irrelevant. For example,
        // [2, 3] produces [0, 0, 1, 1, 1]: two characters belong to pool 0 and three
        // belong to pool 1.
        let alphabet: Vec<usize> = pool_sizes
            .iter()
            .enumerate()
            .flat_map(|(pool, &size)| iter::repeat_n(pool, size))
            .collect();

        // A password is a sequence of `length` alphabet indices. Since each position
        // has `alphabet.len()` possibilities, there are `alphabet.len()^length`
        // possible passwords.
        //
        // We can represent each sequence as a number with `length` digits in base
        // `alphabet.len()`. Each digit is an alphabet index. This gives a one-to-one
        // correspondence between passwords and the numbers in the range
        // `0..alphabet.len()^length`.
        //
        // For example, with 5 alphabet entries and a password length of 4, the range is
        // `0..625`. The number 7 is `0012` in base 5, representing the alphabet indices
        // [0, 0, 1, 2]. In our example alphabet, these indices belong to pools
        // [0, 0, 0, 1].
        (0..alphabet.len().pow(u32::try_from(length).unwrap()))
            .filter(|&password| {
                let mut remaining = password;
                let mut used = vec![false; pool_sizes.len()];

                // Decode the password one digit at a time, starting with its rightmost
                // base-`alphabet.len()` digit.
                for _ in 0..length {
                    // Extract the next digit, which identifies an alphabet entry.
                    let character = remaining % alphabet.len();

                    // Record the pool to which that character belongs.
                    used[alphabet[character]] = true;

                    // Remove the digit just processed to get the next one.
                    remaining /= alphabet.len();
                }

                // A password is permitted only if it contains a character from every pool.
                used.iter().all(|&pool| pool)
            })
            .count()
    }

    /// Tests the preconditions of `bits` and verifies that invalid password spaces
    /// are rejected. Since the preconditions are enforced by debug assertions,
    /// tests for invalid inputs only run in debug builds.
    mod contract {
        use super::bits;

        #[test]
        #[cfg(debug_assertions)]
        #[should_panic(expected = "password length must be greater than zero")]
        fn zero_length_password_is_rejected() {
            let _ = bits(&[26, 10], 0, true);
        }

        #[test]
        #[cfg(debug_assertions)]
        #[should_panic(expected = "at least one character pool is required")]
        fn an_empty_set_of_pools_is_rejected() {
            let _ = bits(&[], 16, true);
        }

        #[test]
        #[cfg(debug_assertions)]
        #[should_panic(expected = "every character pool must contain at least one character")]
        fn an_empty_pool_is_rejected() {
            let _ = bits(&[26, 0], 16, true);
        }

        #[test]
        #[cfg(debug_assertions)]
        #[should_panic(
            expected = "password length (2) is shorter than the number of character pools (3)"
        )]
        fn password_shorter_than_number_of_pools_is_rejected() {
            let _ = bits(&[26, 26, 10], 2, true);
        }
    }

    #[test]
    fn entropy_without_required_pools_is_length_times_the_log2_of_the_alphabet_size() {
        // Six-digit PINs: 10^6 possible passwords.
        assert!((bits(&[10], 6, false) - 19.931_568_569).abs() < EPSILON);

        // 128 characters from a 70-character alphabet: 70^128 possible passwords. This
        // is the largest password space supported by the crate.
        assert!((bits(&[26, 26, 10, 8], 128, false) - 784.548_226_169).abs() < EPSILON);
    }

    #[test]
    fn entropy_with_required_pools_matches_brute_force_count() {
        for (pool_sizes, length) in [
            (&[2, 3][..], 4),
            (&[2, 3][..], 5),
            (&[1, 1][..], 2),
            (&[2, 2, 2][..], 3),
            (&[1, 2, 3][..], 4),
        ] {
            let counted = brute_force_count(pool_sizes, length);

            #[expect(clippy::cast_precision_loss, reason = "the counts are small")]
            let expected = (counted as f64).log2();

            assert!((bits(pool_sizes, length, true) - expected).abs() < EPSILON);
        }
    }

    #[test]
    fn requiring_every_pool_reduces_entropy() {
        let relaxed = bits(&[26, 26, 10, 8], 16, false);
        let strict = bits(&[26, 26, 10, 8], 16, true);

        assert!(strict < relaxed);
        assert!((relaxed - 98.068_528_271).abs() < EPSILON);
        assert!((strict - 97.708_483_848).abs() < EPSILON);
    }

    #[test]
    fn requiring_a_single_pool_does_not_reduce_entropy() {
        for length in [6, 32, 128] {
            assert!((bits(&[10], length, true) - bits(&[10], length, false)).abs() < EPSILON);
        }
    }

    #[test]
    fn reducing_pool_sizes_reduces_entropy() {
        let full = bits(&[26, 26, 10, 8], 16, true);
        let reduced = bits(&[24, 25, 8, 8], 16, true);

        assert!(reduced < full);
        assert!((reduced - 95.972_006_345).abs() < EPSILON);
    }

    #[test]
    fn entropy_grows_with_length() {
        let pool_sizes = [26, 26, 10, 8];

        for length in 6..128 {
            assert!(bits(&pool_sizes, length, true) < bits(&pool_sizes, length + 1, true));
        }
    }

    #[test]
    fn each_rating_covers_the_band_of_entropy_it_documents() {
        let cases = [
            (f64::NEG_INFINITY, PasswordStrength::Weak),
            (0.0, PasswordStrength::Weak),
            (19.93, PasswordStrength::Weak),
            (59.999, PasswordStrength::Weak),
            (60.0, PasswordStrength::Moderate),
            (79.999, PasswordStrength::Moderate),
            (80.0, PasswordStrength::Strong),
            (97.71, PasswordStrength::Strong),
            (127.999, PasswordStrength::Strong),
            (128.0, PasswordStrength::VeryStrong),
            (f64::INFINITY, PasswordStrength::VeryStrong),
        ];

        for (bits, expected) in cases {
            assert_eq!(PasswordStrength::from_bits(bits), expected);
        }
    }

    #[test]
    fn an_uninterpretable_figure_is_rated_weak() {
        assert_eq!(
            PasswordStrength::from_bits(f64::NAN),
            PasswordStrength::Weak
        );
    }

    #[test]
    fn ratings_are_ordered_from_weak_to_very_strong() {
        assert!(PasswordStrength::Weak < PasswordStrength::Moderate);
        assert!(PasswordStrength::Moderate < PasswordStrength::Strong);
        assert!(PasswordStrength::Strong < PasswordStrength::VeryStrong);
    }

    #[test]
    fn display_matches_rating_name() {
        let names = [
            (PasswordStrength::Weak, "weak"),
            (PasswordStrength::Moderate, "moderate"),
            (PasswordStrength::Strong, "strong"),
            (PasswordStrength::VeryStrong, "very strong"),
        ];

        for (rating, name) in names {
            assert_eq!(rating.name(), name);
            assert_eq!(rating.to_string(), name);
        }
    }
}
