# tayna

Policy-driven password generation for Rust, with a builder API and a thin
command-line wrapper.

A builder collects the desired password constraints and checks every one of 
them. If they all hold, it yields a `PasswordPolicy`. Holding a `PasswordPolicy`
is therefore proof that it can produce passwords, which makes generation
infallible: it hands back a `Password`, never a `Result`.

Passwords can be composed from four character classes, all enabled by default:

| Class | Characters |
| --- | --- |
| `uppercase` | `A`–`Z` |
| `lowercase` | `a`–`z` |
| `digits` | `0`–`9` |
| `symbols` | `!@#$%^&*` |

## 1. Highlights

- **The domain is modelled with types:** Character classes are `CharClass`
  values collected in a `CharClassSet`, not a handful of booleans; a generated
  secret is a `Password`, not a `String`; and every way a policy can be invalid
  has its own `PolicyError` variant, so callers match on the cause instead of
  parsing a message.

- **Errors are caught when a password policy is constructed:** The builder
  validates the policy and returns an error if its constraints are invalid.
  Generating passwords from a valid policy is infallible.

- **Secrets are deliberately awkward to leak.** `Password` redacts its `Debug`
  output, has no `Display`, and, with the default `zeroize` feature, wipes its
  buffer when dropped.

- **Generation is cryptographically secure by default:** `generate` draws from
  a cryptographically secure generator, while `generate_with` takes one from the
  caller, which makes output reproducible in tests and demos.

- **No unsafe code:** the crate sets `unsafe_code = "forbid"`, so neither the
  library nor the binary can opt back in.

- **The CLI cannot drift from the library:** The binary is a thin wrapper. The
  bounds, rules, and error messages all come from the library.

- **The CLI is optional:** The library can be used without enabling the `cli`
  feature or pulling in `clap`. That leaves the dependencies `rand` and
  `thiserror`, plus `zeroize` for as long as the default `zeroize` feature stays
  enabled.


## 2. Quick start

### 2.1. Library

```console
$ cargo add tayna
```

```rust
use tayna::PasswordPolicy;

// Every rule is checked here, exactly once.
let policy = PasswordPolicy::builder().length(20).build()?;

// Infallible: there is no `Result` to unwrap.
let password = policy.generate();

assert_eq!(password.len(), 20);
println!("{}", password.as_str());
# Ok::<(), tayna::PolicyError>(())
```

### 2.2. Command line

```console
$ cargo install tayna
$ tayna 32
qF7w&x!SjHTrekIY&Oiuh1h8#xlAQHV3
```

## 3. Installation

### 3.1. As a dependency

```console
$ cargo add tayna
```

The dependency can also be declared directly in `Cargo.toml`:

```toml
[dependencies]
tayna = "0.1"
```

Both features below are enabled by default.

| Feature | Default | Effect |
| --- | --- | --- |
| `cli` | yes | Builds the `tayna` binary. Pulls in `clap`. |
| `zeroize` | yes | Wipes a `Password`'s buffer when it is dropped. |

Library-only consumers should disable `cli` to avoid pulling in `clap`:

```toml
[dependencies]
tayna = { version = "0.1", default-features = false, features = ["zeroize"] }
```

### 3.2. As a command-line tool

```console
$ cargo install tayna
```

## 4. How it works

A couple of types carry the whole model.

**`CharClass`** represents one of four character classes: `Uppercase`,
`Lowercase`, `Digits`, or `Symbols`. Classes can be combined with `|` into a
**`CharClassSet`**, which represents the character classes enabled by a policy
and determines its alphabet.

```rust
use tayna::{CharClass, PasswordPolicy};

let policy = PasswordPolicy::builder()
    .length(12)
    .classes(CharClass::Lowercase | CharClass::Digits)
    .build()?;

assert_eq!(policy.classes().to_string(), "lowercase+digits");
assert_eq!(policy.alphabet().len(), 36);
# Ok::<(), tayna::PolicyError>(())
```

**`PasswordPolicy`** holds a validated policy, reachable only through the
builder. One policy generates as many passwords as needed, and because it was
validated, none of those calls can fail:

```rust
use tayna::PasswordPolicy;

let policy = PasswordPolicy::builder().length(16).build()?;
let batch: Vec<_> = (0..10).map(|_| policy.generate()).collect();

assert_eq!(batch.len(), 10);
# Ok::<(), tayna::PolicyError>(())
```

By default every enabled class is guaranteed to appear at least once. This
requirement can be disabled to draw freely from the combined alphabet:

```rust
use tayna::PasswordPolicy;

let policy = PasswordPolicy::builder()
    .length(6)
    .require_each_enabled_class(false)
    .build()?;

assert!(!policy.requires_each_enabled_class());
# Ok::<(), tayna::PolicyError>(())
```

**`PolicyError`** names each way a policy can be invalid, so callers match on
the cause instead of parsing a message:

```rust
use tayna::{PasswordPolicy, PolicyError};

assert_eq!(
    PasswordPolicy::builder().build(),
    Err(PolicyError::MissingLength),
);

assert_eq!(
    PasswordPolicy::builder().length(5).build(),
    Err(PolicyError::InvalidLength(5)),
);

assert_eq!(
    PasswordPolicy::builder()
        .length(12)
        .uppercase(false)
        .lowercase(false)
        .digits(false)
        .symbols(false)
        .build(),
    Err(PolicyError::NoCharacterClasses),
);
```

Generation draws from a cryptographically secure generator by default, so
`generate` needs nothing from the caller. Supplying a generator to
`generate_with` makes the result reproducible, which is useful for tests and
demos:

```rust
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use tayna::PasswordPolicy;

let policy = PasswordPolicy::builder().length(16).build()?;

let a = policy.generate_with(&mut StdRng::seed_from_u64(528_491));
let b = policy.generate_with(&mut StdRng::seed_from_u64(528_491));

assert_eq!(a.as_str(), b.as_str());
# Ok::<(), tayna::PolicyError>(())
```

A runnable collection of examples lives in
[`examples/custom_policy.rs`](https://github.com/ni-kr/tayna/blob/main/examples/custom_policy.rs),
which builds a default, an alphanumeric, and a numeric-PIN policy, generates a
batch from a reused policy, and shows the errors a rejected policy produces.

The full API documentation, including every builder method, can be viewed
without generating documentation for the crate's dependencies:

```console
$ cargo doc --no-deps --open
```

## 5. Command line

Length is the only required argument. Optional flags can be added as needed:

```console
$ tayna 20 --no-uppercase --no-symbols
d5oms5klyy66r0ueg99p
```

The `--no-*` flags combine freely, except that disabling all character classes
is a usage error: nothing would be left to draw from. Length must be between 6
and 128, which are the same bounds the library enforces.

The binary describes every flag, along with its short form and default, in its
own help output:

```console
$ tayna --help
```

Passwords are written to stdout, one per line.

Exit codes are `0` on success, `2` for a usage error, such as an out-of-range
length or disabling every character class, and `1` if the output cannot be
written.

## 6. Limitations

The following outlines tayna's deliberate omissions and helps determine whether
it fits a particular use case.

- **The alphabet is fixed.** Character classes can be enabled and disabled, but
  a custom character set cannot be supplied, nor can visually ambiguous
  characters such as `l`, `1`, `O`, and `0` be excluded.

- **Length is capped at 6 to 128 characters.** Six is a common size of a numeric
  PIN. The 128-character upper bound allows long passwords while keeping the
  supported range bounded.

- **No passphrases.** tayna produces random character strings, not word-based
  passphrases.

- **No strength estimation.** There is no entropy score or strength meter,
  though `length()` and `alphabet()` are public and can be used to compute one.

- **No storage integration.** Generating passwords is the whole scope.

Zeroisation has a separate caveat: **Zeroising is best effort.** It reduces the
lifetime of secret data in memory, but cannot guarantee that every copy is
erased. The buffer is overwritten on drop, but the value may already have been
copied by the allocator or kept alive by the caller.

## 7. License

MIT. See the [`LICENSE`](https://github.com/ni-kr/tayna/blob/main/LICENSE) file
in the repository.
