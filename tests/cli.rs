//! Integration tests for the `tayna` binary.
#![cfg(feature = "cli")]

use assert_cmd::Command;
use predicates::prelude::*;

// Taken from the library rather than written out again, so these tests cannot
// drift from the alphabet the binary actually uses.
const UPPERCASE: &str = tayna::CharClass::Uppercase.chars();
const LOWERCASE: &str = tayna::CharClass::Lowercase.chars();
const DIGITS: &str = tayna::CharClass::Digits.chars();
const SYMBOLS: &str = tayna::CharClass::Symbols.chars();

/// The binary under test.
fn tayna() -> Command {
    Command::cargo_bin("tayna").expect("the `tayna` binary should be built")
}

/// Runs a successful invocation and returns the generated lines, trimmed of the
/// trailing newline.
fn passwords(args: &[&str]) -> Vec<String> {
    let output = tayna()
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    String::from_utf8(output)
        .expect("output should be UTF-8")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Runs an invocation expected to fail and returns its stderr.
fn usage_error(args: &[&str]) -> String {
    let output = tayna()
        .args(args)
        .assert()
        .failure()
        // Policy errors are translated into clap usage errors, which exit with code 2.
        .code(2)
        .get_output()
        .stderr
        .clone();

    String::from_utf8(output).expect("stderr should be UTF-8")
}

#[test]
fn a_length_is_required() {
    assert!(usage_error(&[]).contains("<LENGTH>"));
}

#[test]
fn a_non_numeric_length_is_rejected() {
    assert!(usage_error(&["twenty"]).contains("input must be an unsigned integer"));
}

#[test]
fn a_length_outside_the_library_bounds_is_reported_as_a_usage_error() {
    assert!(usage_error(&["5"]).contains("must be between 6 and 128"));
    assert!(usage_error(&["129"]).contains("must be between 6 and 128"));
}

#[test]
fn one_password_of_the_requested_length_is_printed_by_default() {
    let passwords = passwords(&["20"]);

    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0].chars().count(), 20);
}

#[test]
fn count_prints_that_many_distinct_passwords() {
    for args in [["24", "--count", "5"], ["24", "-n", "5"]] {
        let passwords = passwords(&args);

        assert_eq!(passwords.len(), 5);
        assert!(passwords.iter().all(|line| line.chars().count() == 24));

        let unique: std::collections::HashSet<_> = passwords.iter().collect();
        assert_eq!(unique.len(), 5, "passwords should differ");
    }
}

#[test]
fn a_zero_count_is_rejected() {
    assert!(usage_error(&["8", "--count", "0"]).contains("invalid value"));
}

#[test]
fn all_four_classes_are_used_by_default() {
    let password = passwords(&["6"]).remove(0);

    assert!(password.chars().any(|c| UPPERCASE.contains(c)));
    assert!(password.chars().any(|c| LOWERCASE.contains(c)));
    assert!(password.chars().any(|c| DIGITS.contains(c)));
    assert!(password.chars().any(|c| SYMBOLS.contains(c)));
}

#[test]
fn each_class_can_be_disabled_individually() {
    // A flag is paired with a check for the class it disables.
    type ExclusionCase = (&'static str, fn(char) -> bool);

    // The long and short spellings are separate clap attributes, so each is
    // exercised instead of assuming the pair shares one code path.
    let cases: [ExclusionCase; 8] = [
        ("--no-uppercase", |c| UPPERCASE.contains(c)),
        ("--no-lowercase", |c| LOWERCASE.contains(c)),
        ("--no-digits", |c| DIGITS.contains(c)),
        ("--no-symbols", |c| SYMBOLS.contains(c)),
        ("-U", |c| UPPERCASE.contains(c)),
        ("-L", |c| LOWERCASE.contains(c)),
        ("-D", |c| DIGITS.contains(c)),
        ("-S", |c| SYMBOLS.contains(c)),
    ];

    for (flag, is_excluded) in cases {
        let password = passwords(&["128", flag]).remove(0);

        assert_eq!(password.chars().count(), 128);
        assert!(
            !password.chars().any(is_excluded),
            "{flag} did not exclude its class from {password}"
        );
    }
}

#[test]
fn multiple_classes_can_be_disabled_at_the_same_time() {
    let password = passwords(&["128", "--no-uppercase", "--no-digits"]).remove(0);

    assert!(
        !password.chars().any(|c| UPPERCASE.contains(c)),
        "--no-uppercase did not exclude its class from {password}"
    );

    assert!(
        !password.chars().any(|c| DIGITS.contains(c)),
        "--no-digits did not exclude its class from {password}"
    );
}

#[test]
fn disabling_all_four_classes_is_rejected() {
    let stderr = usage_error(&["32", "-U", "-L", "-D", "-S"]);

    assert!(stderr.contains("cannot disable all character classes;"));
    assert!(stderr.contains("at least one must remain enabled"));
}

#[test]
fn allow_missing_classes_is_accepted() {
    let password = passwords(&["8", "--allow-missing-classes"]).remove(0);

    assert_eq!(password.chars().count(), 8);
}

#[test]
fn help_lists_all_options() {
    tayna()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("<LENGTH>"))
        .stdout(predicate::str::contains("--no-uppercase"))
        .stdout(predicate::str::contains("--no-lowercase"))
        .stdout(predicate::str::contains("--no-digits"))
        .stdout(predicate::str::contains("--no-symbols"))
        .stdout(predicate::str::contains("--allow-missing-classes"))
        .stdout(predicate::str::contains("--count"))
        .stdout(predicate::str::contains("--help"))
        .stdout(predicate::str::contains("--version"));
}

#[test]
fn version_reports_the_crate_version() {
    tayna()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn consecutive_runs_produce_different_passwords() {
    let first = passwords(&["32"]).remove(0);
    let second = passwords(&["32"]).remove(0);

    assert_ne!(first, second);
}
