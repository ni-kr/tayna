//! Property-based tests: invariants that must hold for every policy and class set.

use proptest::prelude::*;
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use tayna::{CharClass, CharClassSet, PasswordPolicy};

/// Any non-empty set of the four character classes.
///
/// The masks `1..16` enumerate exactly the fifteen non-empty subsets, and
/// proptest shrinks a failing mask towards smaller sets, so a counter-example
/// arrives with as few classes as possible.
fn class_sets() -> impl Strategy<Value = CharClassSet> {
    (1u8..16).prop_map(|mask| {
        CharClass::ALL
            .into_iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, class)| class)
            .collect()
    })
}

/// Any single character class.
fn classes() -> impl Strategy<Value = CharClass> {
    prop::sample::select(CharClass::ALL.as_slice())
}

mod password_policy {
    use super::*;

    /// Any length the crate accepts.
    fn lengths() -> impl Strategy<Value = usize> {
        PasswordPolicy::MIN_LENGTH..=PasswordPolicy::MAX_LENGTH
    }

    /// Builds a valid password policy from the given values.
    fn policy(length: usize, class_set: CharClassSet, require_each: bool) -> PasswordPolicy {
        PasswordPolicy::builder()
            .length(length)
            .classes(class_set)
            .require_each_enabled_class(require_each)
            .build()
            .expect("a non-empty class set with an in-range length is always valid")
    }

    proptest! {
        #[test]
        fn a_policy_exposes_all_its_values(
            length in lengths(),
            class_set in class_sets(),
            require_each in any::<bool>(),
        ) {
            // This also implicitly verifies that every valid combination of inputs builds
            // successfully.
            let policy = policy(length, class_set, require_each);

            prop_assert_eq!(policy.length(), length);
            prop_assert_eq!(policy.classes(), class_set);
            prop_assert_eq!(policy.requires_each_enabled_class(), require_each);
            prop_assert_eq!(policy.alphabet(), class_set.alphabet());
        }

        #[test]
        fn lengths_outside_the_bounds_are_always_rejected(
            length in (0usize..PasswordPolicy::MIN_LENGTH)
                .prop_union(PasswordPolicy::MAX_LENGTH + 1..10_000),
        ) {
            prop_assert!(PasswordPolicy::builder().length(length).build().is_err());
        }

        #[test]
        fn generated_passwords_match_their_policy(
            length in lengths(),
            class_set in class_sets(),
            seed: u64,
            require_each in any::<bool>(),
        ) {
            let policy = policy(length, class_set, require_each);

            let password = policy.generate_with(&mut StdRng::seed_from_u64(seed));

            prop_assert_eq!(password.len(), length);
            for character in password.as_str().chars() {
                prop_assert!(
                    policy.alphabet().contains(character),
                    "{:?} is outside the alphabet of {}", character, class_set
                );
            }
        }

        #[test]
        fn required_classes_always_appear(
            length in lengths(),
            class_set in class_sets(),
            seed: u64,
        ) {
            let policy = policy(length, class_set, true);

            let password = policy.generate_with(&mut StdRng::seed_from_u64(seed));

            for class in class_set {
                prop_assert!(
                    password.as_str().chars().any(|c| class.chars().contains(c)),
                    "{} is missing from a password generated with {}", class, class_set
                );
            }
        }

        #[test]
        fn the_same_seed_yields_the_same_password(
            length in lengths(),
            class_set in class_sets(),
            seed: u64,
            require_each in any::<bool>(),
        ) {
            let policy = policy(length, class_set, require_each);

            let first = policy.generate_with(&mut StdRng::seed_from_u64(seed)).into_string();
            let second = policy.generate_with(&mut StdRng::seed_from_u64(seed)).into_string();

            prop_assert_eq!(first, second);
        }

        #[test]
        fn password_length_agrees_with_the_characters_it_holds(
            length in lengths(),
            class_set in class_sets(),
            seed: u64,
            require_each in any::<bool>(),
        ) {
            let password = policy(length, class_set, require_each)
                .generate_with(&mut StdRng::seed_from_u64(seed));

            prop_assert_eq!(password.len(), password.as_str().chars().count());
        }
    }
}

mod char_class_set {
    use super::*;

    proptest! {
        #[test]
        fn alphabet_matches_its_member_classes(class_set in class_sets()) {
            let expected_size: usize = class_set.iter().map(CharClass::size).sum();

            prop_assert_eq!(class_set.alphabet().len(), expected_size);
            for class in class_set {
                prop_assert!(class_set.alphabet().contains(class.chars()));
            }
        }

        #[test]
        fn iteration_yields_exactly_the_member_classes(class_set in class_sets()) {
            let rebuilt: CharClassSet = class_set.iter().collect();

            prop_assert_eq!(rebuilt, class_set);
            prop_assert_eq!(class_set.iter().count(), class_set.len());
        }

        #[test]
        fn iteration_is_always_in_canonical_order(class_set in class_sets()) {
            let collected: Vec<_> = class_set.iter().collect();
            let mut canonical = collected.clone();
            canonical.sort_unstable();

            prop_assert_eq!(collected, canonical);
        }

        #[test]
        fn with_and_without_are_inverses(class_set in class_sets(), class in classes()) {
            prop_assert!(class_set.with(class).contains(class));
            prop_assert!(!class_set.without(class).contains(class));
            prop_assert_eq!(class_set.without(class).with(class), class_set.with(class));
            prop_assert_eq!(class_set.with(class).without(class), class_set.without(class));
        }

        #[test]
        fn with_and_without_are_idempotent(class_set in class_sets(), class in classes()) {
            prop_assert_eq!(class_set.with(class).with(class), class_set.with(class));
            prop_assert_eq!(class_set.without(class).without(class), class_set.without(class));
        }

        #[test]
        fn union_contains_exactly_the_members_of_both_sides(
            first in class_sets(),
            second in class_sets(),
        ) {
            let union = first | second;

            for class in CharClass::ALL {
                prop_assert_eq!(
                    union.contains(class),
                    first.contains(class) || second.contains(class)
                );
            }
        }

        #[test]
        fn union_of_two_classes_contains_exactly_the_members_of_both_sides(
            first in classes(),
            second in classes(),
        ) {
            let union = first | second;

            for member in CharClass::ALL {
                prop_assert_eq!(
                    union.contains(member),
                    member == first || member == second
                );
            }
        }

        #[test]
        fn union_of_a_set_and_a_class_contains_exactly_the_members_of_both_sides(
            class_set in class_sets(),
            class in classes(),
        ) {
            let union = class_set | class;

            for member in CharClass::ALL {
                prop_assert_eq!(
                    union.contains(member),
                    class_set.contains(member) || member == class
                );
            }
        }

        #[test]
        fn union_is_commutative_associative_and_idempotent(
            first in class_sets(),
            second in class_sets(),
            third in class_sets(),
        ) {
            prop_assert_eq!(first | second, second | first);
            prop_assert_eq!((first | second) | third, first | (second | third));
            prop_assert_eq!(first | first, first);
        }

        #[test]
        fn union_of_classes_is_commutative_associative_and_idempotent(
            first in classes(),
            second in classes(),
            third in classes(),
        ) {
            prop_assert_eq!(first | second, second | first);
            // The intermediate union is a set, so this also asserts that a union of a set
            // and a class is commutative.
            prop_assert_eq!((first | second) | third, first | (second | third));
            prop_assert_eq!(first | first, CharClassSet::from(first));
        }
    }
}
