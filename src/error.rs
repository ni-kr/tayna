//! Errors returned when a password policy cannot be built.

use crate::policy::PasswordPolicy;

/// The reason a [`PasswordPolicyBuilder`](crate::PasswordPolicyBuilder) could
/// not produce a valid [`PasswordPolicy`].
///
/// Each variant represents a condition that must be met to create a valid
/// policy. Because these are checked once, in
/// [`PasswordPolicyBuilder::build`](crate::PasswordPolicyBuilder::build),
/// holding a [`PasswordPolicy`] is proof that all of them hold, and generation
/// itself cannot fail.
///
/// # Examples
/// ```
/// use tayna::{PasswordPolicy, PolicyError};
///
/// let error = PasswordPolicy::builder().length(4).build().unwrap_err();
///
/// assert_eq!(error, PolicyError::InvalidLength(4));
/// assert_eq!(
///     error.to_string(),
///     "password length 4 is invalid; must be between 6 and 128",
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum PolicyError {
    /// No length was given to the builder.
    ///
    /// There is no sensible default password length, so it must be stated
    /// explicitly via
    /// [`PasswordPolicyBuilder::length`](crate::PasswordPolicyBuilder::length).
    #[error("no password length was set")]
    MissingLength,

    /// The requested length is outside the allowed range.
    #[error(
        "password length {0} is invalid; must be between {min} and {max}",
        min=PasswordPolicy::MIN_LENGTH,
        max=PasswordPolicy::MAX_LENGTH
    )]
    InvalidLength(usize),

    /// Every character class was disabled, leaving nothing to draw from.
    #[error("at least one character class must be enabled")]
    NoCharacterClasses,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_correct() {
        assert_eq!(
            PolicyError::MissingLength.to_string(),
            "no password length was set"
        );

        assert_eq!(
            PolicyError::InvalidLength(200).to_string(),
            format!(
                "password length 200 is invalid; must be between {} and {}",
                PasswordPolicy::MIN_LENGTH,
                PasswordPolicy::MAX_LENGTH
            )
        );

        assert_eq!(
            PolicyError::NoCharacterClasses.to_string(),
            "at least one character class must be enabled"
        );
    }
}
