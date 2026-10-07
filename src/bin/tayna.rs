//! The `tayna` command-line password generator.
//!
//! A thin adapter over the library: it translates flags into a
//! [`PasswordPolicy`] and renders any [`PolicyError`] as a `clap` usage error.
//! All rules live in the library, so the CLI cannot drift from it.

use std::io::{self, Write as _};
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};
use tayna::{PasswordPolicy, PolicyError};

/// Exit code used when generated output cannot be written.
const EXIT_IO_ERROR: u8 = 1;

/// Generate secure random passwords.
///
/// Passwords are built from upper-case letters, lower-case letters, digits, and
/// symbols. Each character class can be disabled individually, but at least one
/// class must remain enabled.
#[derive(Debug, Parser)]
#[command(name = "tayna", version)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent command-line flag"
)]
struct Cli {
    /// Length of the generated password (6-128)
    #[arg(value_parser = parse_length)]
    length: usize,

    /// Exclude upper-case letters (A-Z)
    #[arg(short = 'U', long)]
    no_uppercase: bool,

    /// Exclude lower-case letters (a-z)
    #[arg(short = 'L', long)]
    no_lowercase: bool,

    /// Exclude digits (0-9)
    #[arg(short = 'D', long)]
    no_digits: bool,

    /// Exclude symbols (!@#$%^&*)
    #[arg(short = 'S', long)]
    no_symbols: bool,

    /// Do not force each enabled character class to appear
    #[arg(long)]
    allow_missing_classes: bool,

    /// Number of passwords to generate
    #[arg(
        short = 'n',
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u32).range(1..),
    )]
    count: u32,
}

impl Cli {
    /// Translates the parsed flags into a validated policy.
    fn policy(&self) -> Result<PasswordPolicy, PolicyError> {
        PasswordPolicy::builder()
            .length(self.length)
            .uppercase(!self.no_uppercase)
            .lowercase(!self.no_lowercase)
            .digits(!self.no_digits)
            .symbols(!self.no_symbols)
            .require_each_enabled_class(!self.allow_missing_classes)
            .build()
    }
}

/// Parses a password length.
///
/// This only parses the input as an unsigned integer. The allowed range is
/// deliberately left to [`PasswordPolicy`], so that the CLI and the library can
/// never disagree about what is valid. An out-of-range number reaches
/// [`Cli::policy`] and comes back as a [`PolicyError`].
fn parse_length(input: &str) -> Result<usize, String> {
    input
        .parse::<usize>()
        .map_err(|_| "input must be an unsigned integer".to_owned())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // `clap` cannot express "not all four of these flags at once" as an
    // argument group, so the library's own rule is reused and reported in
    // clap's format.
    let policy = cli.policy().unwrap_or_else(|error| usage_error(&error));

    match write_passwords(&policy, cli.count) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tayna: {error}");
            ExitCode::from(EXIT_IO_ERROR)
        }
    }
}

/// Writes `count` freshly generated passwords to stdout, one per line.
fn write_passwords(policy: &PasswordPolicy, count: u32) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for _ in 0..count {
        let password = policy.generate();
        match writeln!(out, "{}", password.as_str()) {
            Ok(()) => {}
            // A closed pipe (`tayna 20 -n 100 | head -1`) is a normal ending, not a
            // failure.
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
            Err(error) => return Err(error),
        }
    }

    out.flush()
}

/// Reports a policy error the way `clap` reports its own usage errors, then
/// exits with clap's usage exit code.
fn usage_error(error: &PolicyError) -> ! {
    let kind = match error {
        PolicyError::NoCharacterClasses => ErrorKind::ArgumentConflict,
        PolicyError::MissingLength => ErrorKind::MissingRequiredArgument,
        PolicyError::InvalidLength(_) => ErrorKind::InvalidValue,
    };

    let message = match error {
        PolicyError::NoCharacterClasses => {
            "cannot disable all character classes; at least one must remain enabled".to_owned()
        }
        other => other.to_string(),
    };

    Cli::command().error(kind, message).exit()
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory as _, Parser as _};

    use super::{Cli, parse_length};
    use tayna::{CharClass, CharClassSet, PasswordPolicy, PolicyError};

    #[test]
    fn parse_length_parses_whole_numbers() {
        assert_eq!(parse_length("123"), Ok(123));
    }

    #[test]
    fn parse_length_rejects_invalid_input() {
        for input in ["4.5", "twelve", "-1"] {
            assert_eq!(
                parse_length(input),
                Err("input must be an unsigned integer".to_owned())
            );
        }
    }

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn length_is_translated_to_the_policy() {
        let cli = Cli::try_parse_from(["tayna", "42"]).unwrap();
        let policy = cli.policy().unwrap();

        assert_eq!(policy.length(), 42);
    }

    #[test]
    fn length_outside_library_bounds_is_rejected() {
        for length in [
            PasswordPolicy::MIN_LENGTH - 1,
            PasswordPolicy::MAX_LENGTH + 1,
        ] {
            let cli = Cli::try_parse_from(["tayna", &length.to_string()]).unwrap();
            let policy_error = cli.policy().unwrap_err();

            assert_eq!(policy_error, PolicyError::InvalidLength(length));
        }
    }

    #[test]
    fn default_enables_all_classes_and_requires_each() {
        let cli = Cli::try_parse_from(["tayna", "12"]).unwrap();
        let policy = cli.policy().unwrap();

        assert_eq!(policy.classes(), CharClassSet::ALL);
        assert!(policy.requires_each_enabled_class());
    }

    #[test]
    fn character_class_flags_configure_the_policy() {
        let cli = Cli::try_parse_from(["tayna", "12", "--no-symbols", "-D"]).unwrap();
        let policy = cli.policy().unwrap();

        assert_eq!(
            policy.classes(),
            CharClassSet::ALL
                .without(CharClass::Symbols)
                .without(CharClass::Digits)
        );
        assert!(policy.requires_each_enabled_class());
    }

    #[test]
    fn disabling_every_class_is_rejected_by_the_policy() {
        let cli = Cli::try_parse_from(["tayna", "12", "-U", "-L", "-D", "-S"]).unwrap();
        let policy_error = cli.policy().unwrap_err();

        assert_eq!(policy_error, PolicyError::NoCharacterClasses);
    }

    #[test]
    fn allow_missing_classes_relaxes_the_policy() {
        let cli = Cli::try_parse_from(["tayna", "12", "--allow-missing-classes"]).unwrap();
        let policy = cli.policy().unwrap();

        assert!(!policy.requires_each_enabled_class());
    }

    #[test]
    fn default_count_is_one() {
        let cli = Cli::try_parse_from(["tayna", "12"]).unwrap();

        assert_eq!(cli.count, 1);
    }
}
