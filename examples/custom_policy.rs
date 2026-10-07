//! Builds a few policies with the builder API.
//!
//! Run with `cargo run --example custom_policy`.

use rand::SeedableRng as _;
use rand::rngs::StdRng;
use tayna::{CharClass, PasswordPolicy, PolicyError};

fn main() -> Result<(), PolicyError> {
    // The default policy enables all character classes and guarantees that a
    // character from each class appears at least once. Only the length has to be
    // supplied.
    let strong = PasswordPolicy::builder().length(24).build()?;
    report("Default policy (all four classes)", &strong);

    // Individual character classes can be disabled to build a policy with a
    // narrower alphabet, such as one that excludes symbols.
    let alphanumeric = PasswordPolicy::builder()
        .length(24)
        .symbols(false)
        .build()?;
    report("Alphanumeric policy", &alphanumeric);

    // `classes` replaces the entire set of enabled classes, making it convenient
    // to restrict a policy to a single class such as digits.
    let pin = PasswordPolicy::builder()
        .length(6)
        .classes(CharClass::Digits)
        .build()?;
    report("Numeric policy", &pin);

    // A policy is validated once and can then be reused cheaply.
    let batch: Vec<String> = (0..3).map(|_| strong.generate().into_string()).collect();
    println!("A batch of {} passwords:", batch.len());
    for password in &batch {
        println!("  {password}");
    }

    // Supplying the generator makes the output reproducible, which is handy in
    // tests and for demos like this one.
    let seeded = strong.generate_with(&mut StdRng::seed_from_u64(1234));
    println!("\nPassword seeded with 1234: {}", seeded.as_str());

    // Invalid combinations are rejected when the policy is built, never when the
    // password is generated from the policy.
    let no_length = PasswordPolicy::builder().build().unwrap_err();
    println!("\nRejected policy: {no_length}");
    let too_short = PasswordPolicy::builder().length(4).build().unwrap_err();
    println!("Rejected policy: {too_short}");
    let nothing_left = PasswordPolicy::builder()
        .length(12)
        .uppercase(false)
        .lowercase(false)
        .digits(false)
        .symbols(false)
        .build()
        .unwrap_err();
    println!("Rejected policy: {nothing_left}");

    Ok(())
}

/// Prints a policy and one password generated from it.
fn report(label: &str, policy: &PasswordPolicy) {
    println!(
        "{label}:\n  {} chars from {} (alphabet of {}):\n  {}\n",
        policy.length(),
        policy.classes(),
        policy.alphabet().len(),
        policy.generate().as_str(),
    );
}
