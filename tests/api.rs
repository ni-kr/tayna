//! Integration tests for the public API of the `tayna` crate.

use std::collections::HashSet;

use rand::SeedableRng as _;
use rand::rngs::StdRng;
use tayna::{
    CharClass, CharClassSet, Password, PasswordPolicy, PasswordPolicyBuilder, PolicyError,
};

#[test]
fn public_types_are_reachable_from_the_crate_root() {
    let _: CharClass = CharClass::Digits;
    let builder: PasswordPolicyBuilder = PasswordPolicy::builder();
    let policy: PasswordPolicy = builder.length(16).build().expect("valid policy");
    let _: Password = policy.generate();
    let _: CharClassSet = policy.classes();
    let _: PolicyError = PasswordPolicy::builder().build().unwrap_err();
}

#[test]
fn public_constants_are_reachable_from_the_crate_root() {
    let _: [CharClass; 4] = CharClass::ALL;
    let _: CharClassSet = CharClassSet::EMPTY;
    let _: CharClassSet = CharClassSet::ALL;
}

#[test]
fn builder_methods_compose() {
    // Different class-selection methods can be combined, and later settings
    // override earlier ones.
    let policy = PasswordPolicy::builder()
        .length(16)
        .classes(CharClass::Uppercase)
        .with_class(CharClass::Symbols)
        .without_class(CharClass::Symbols)
        .digits(true)
        .lowercase(true)
        .lowercase(false)
        .require_each_enabled_class(true)
        .exclude_ambiguous(true)
        .exclude_ambiguous(false)
        .build()
        .expect("valid policy");

    assert_eq!(policy.classes(), CharClass::Uppercase | CharClass::Digits);
    assert_eq!(policy.length(), 16);
    assert!(policy.requires_each_enabled_class());
    assert!(!policy.excludes_ambiguous());
}

#[test]
fn a_policy_needs_nothing_but_a_length() {
    let policy = PasswordPolicy::builder()
        .length(64)
        .build()
        .expect("valid policy");

    assert_eq!(policy.classes(), CharClassSet::ALL);
    assert_eq!(
        policy.alphabet(),
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    );
}

#[test]
fn a_policy_without_ambiguous_characters_only_drops_confusable_ones() {
    let readable = PasswordPolicy::builder()
        .length(32)
        .exclude_ambiguous(true)
        .build()
        .expect("valid policy");

    assert!(readable.excludes_ambiguous());
    assert_eq!(
        readable.alphabet(),
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"
    );

    let password = readable.generate();

    assert!(!password.as_str().chars().any(|c| "0O1Il".contains(c)));

    // Digits alone hold nothing that can be mistaken for a `0` or a `1`.
    let pin = PasswordPolicy::builder()
        .length(6)
        .classes(CharClass::Digits)
        .exclude_ambiguous(true)
        .build()
        .expect("valid policy");

    assert_eq!(pin.alphabet(), "0123456789");
}

#[test]
fn a_policy_can_be_reused_for_multiple_passwords() {
    let policy = PasswordPolicy::builder()
        .length(24)
        .build()
        .expect("valid policy");

    let passwords: HashSet<String> = (0..64).map(|_| policy.generate().into_string()).collect();

    assert_eq!(passwords.len(), 64, "generated passwords should not repeat");
    assert!(passwords.iter().all(|password| password.len() == 24));
}

#[test]
fn a_caller_can_supply_a_random_number_generator() {
    let policy = PasswordPolicy::builder()
        .length(48)
        .build()
        .expect("valid policy");

    let first = policy
        .generate_with(&mut StdRng::seed_from_u64(99))
        .into_string();
    let second = policy
        .generate_with(&mut StdRng::seed_from_u64(99))
        .into_string();
    let third = policy
        .generate_with(&mut StdRng::seed_from_u64(100))
        .into_string();

    assert_eq!(first, second);
    assert_ne!(first, third);
}

#[test]
fn a_password_supports_string_conversions() {
    let policy = PasswordPolicy::builder()
        .length(12)
        .build()
        .expect("valid policy");

    let password = policy.generate();

    let borrowed: &str = password.as_str();
    let as_ref: &str = password.as_ref();

    assert_eq!(as_ref, borrowed);

    let _: String = policy.generate().into();
}

#[test]
fn a_password_does_not_leak_through_debug() {
    // Debug output may end up in logs, so the password must remain redacted.
    let policy = PasswordPolicy::builder()
        .length(32)
        .build()
        .expect("valid policy");
    let password = policy.generate();

    let rendered = format!("{password:?}");
    let nested = format!("{:?}", Some(&password));

    assert_eq!(rendered, "Password(<redacted>)");
    assert!(!rendered.contains(password.as_str()));
    assert!(!nested.contains(password.as_str()));
}

#[test]
fn character_classes_expose_their_properties() {
    let class = CharClass::Symbols;

    assert_eq!(class.chars(), "!@#$%^&*");
    assert_eq!(class.size(), 8);
    assert_eq!(class.name(), "symbols");
    assert_eq!(class.to_string(), "symbols");
}

#[test]
fn character_class_sets_expose_their_properties() {
    let set = CharClass::Lowercase | CharClass::Digits;

    assert_eq!(set.len(), 2);
    assert!(set.contains(CharClass::Lowercase));
    assert!(!set.contains(CharClass::Symbols));
    assert_eq!(set.to_string(), "lowercase+digits");
    assert_eq!(set.alphabet(), "abcdefghijklmnopqrstuvwxyz0123456789");
}

#[test]
fn character_class_sets_resolve_ambiguous_characters_against_their_members() {
    let digits_and_letters = CharClass::Digits | CharClass::Uppercase;

    assert_eq!(digits_and_letters.ambiguous_chars(), "IO01");
    assert!(!digits_and_letters.unambiguous_alphabet().contains('0'));
    assert!(!digits_and_letters.unambiguous_alphabet().contains('O'));

    // Without upper-case letters there is no `O` to mistake a `0` for.
    let digits_only = CharClassSet::from(CharClass::Digits);

    assert_eq!(digits_only.ambiguous_chars(), "");
    assert_eq!(digits_only.unambiguous_alphabet(), digits_only.alphabet());
}
