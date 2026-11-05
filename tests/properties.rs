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
    fn policy(
        length: usize,
        class_set: CharClassSet,
        require_each: bool,
        exclude_ambiguous: bool,
    ) -> PasswordPolicy {
        PasswordPolicy::builder()
            .length(length)
            .classes(class_set)
            .require_each_enabled_class(require_each)
            .exclude_ambiguous(exclude_ambiguous)
            .build()
            .expect("a non-empty class set with an in-range length is always valid")
    }

    proptest! {
        #[test]
        fn a_policy_exposes_all_its_values(
            length in lengths(),
            class_set in class_sets(),
            require_each in any::<bool>(),
            exclude_ambiguous in any::<bool>(),
        ) {
            // This also implicitly verifies that every valid combination of inputs builds
            // successfully.
            let policy = policy(length, class_set, require_each, exclude_ambiguous);

            prop_assert_eq!(policy.length(), length);
            prop_assert_eq!(policy.classes(), class_set);
            prop_assert_eq!(policy.requires_each_enabled_class(), require_each);
            prop_assert_eq!(policy.excludes_ambiguous(), exclude_ambiguous);
            prop_assert_eq!(
                policy.alphabet(),
                if exclude_ambiguous {
                    class_set.unambiguous_alphabet()
                } else {
                    class_set.alphabet()
                }
            );
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
            exclude_ambiguous in any::<bool>(),
        ) {
            let policy = policy(length, class_set, require_each, exclude_ambiguous);

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
            exclude_ambiguous in any::<bool>(),
        ) {
            let policy = policy(length, class_set, true, exclude_ambiguous);

            let password = policy.generate_with(&mut StdRng::seed_from_u64(seed));

            for class in class_set {
                prop_assert!(
                    password.as_str().chars().any(|c| class.chars().contains(c)),
                    "{} is missing from a password generated with {}", class, class_set
                );
            }
        }

        #[test]
        fn excluded_characters_never_appear_in_a_password(
            length in lengths(),
            class_set in class_sets(),
            seed: u64,
            require_each in any::<bool>(),
        ) {
            let policy = policy(length, class_set, require_each, true);
            let excluded = class_set.ambiguous_chars();

            let password = policy.generate_with(&mut StdRng::seed_from_u64(seed));

            for character in password.as_str().chars() {
                prop_assert!(
                    !excluded.contains(character),
                    "{:?} should have been excluded from {}", character, class_set
                );
            }
        }

        #[test]
        fn the_same_seed_yields_the_same_password(
            length in lengths(),
            class_set in class_sets(),
            seed: u64,
            require_each in any::<bool>(),
            exclude_ambiguous in any::<bool>(),
        ) {
            let policy = policy(length, class_set, require_each, exclude_ambiguous);

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
            exclude_ambiguous in any::<bool>(),
        ) {
            let password = policy(length, class_set, require_each, exclude_ambiguous)
                .generate_with(&mut StdRng::seed_from_u64(seed));

            prop_assert_eq!(password.len(), password.as_str().chars().count());
        }
    }
}

mod char_class_set {
    use super::*;

    /// How each visually ambiguous character is read: `0` and `O` as zero, and
    /// `1`, `I`, and `l` as one.
    ///
    /// The library determines ambiguity from the character classes an alphabet
    /// draws on. Deciding it here from the characters the alphabet ends up holding
    /// keeps the property below an independent check of that rule.
    fn look_alike(character: char) -> Option<char> {
        match character {
            '0' | 'O' => Some('0'),
            '1' | 'I' | 'l' => Some('1'),
            _ => None,
        }
    }

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
        fn ambiguous_characters_are_those_with_a_confusable_partner(
            class_set in class_sets(),
        ) {
            let alphabet = class_set.alphabet();

            let expected: String = alphabet
                .chars()
                .filter(|&character| {
                    look_alike(character).is_some_and(|shape| {
                        alphabet
                            .chars()
                            .any(|other| other != character && look_alike(other) == Some(shape))
                    })
                })
                .collect();

            prop_assert_eq!(class_set.ambiguous_chars(), expected);
        }

        #[test]
        fn the_unambiguous_alphabet_keeps_everything_that_is_not_ambiguous(
            class_set in class_sets(),
        ) {
            let ambiguous = class_set.ambiguous_chars();
            let unambiguous = class_set.unambiguous_alphabet();

            prop_assert_eq!(
                unambiguous.chars().count() + ambiguous.chars().count(),
                class_set.alphabet().chars().count()
            );
            for character in class_set.alphabet().chars() {
                prop_assert_eq!(unambiguous.contains(character), !ambiguous.contains(character));
            }
        }

        #[test]
        fn no_enabled_class_is_emptied_by_removing_ambiguous_characters(
            class_set in class_sets(),
        ) {
            let unambiguous = class_set.unambiguous_alphabet();

            prop_assert!(!unambiguous.is_empty());
            for class in class_set {
                prop_assert!(class.chars().chars().any(|c| unambiguous.contains(c)));
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
