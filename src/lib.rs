#![doc = include_str!("../README.md")]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod char_class;
mod error;
mod password;
mod policy;

pub use crate::char_class::{CharClass, CharClassIter, CharClassSet};
pub use crate::error::PolicyError;
pub use crate::password::Password;
pub use crate::policy::{PasswordPolicy, PasswordPolicyBuilder};
