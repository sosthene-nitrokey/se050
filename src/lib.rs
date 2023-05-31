#![no_std]

extern crate delog;
delog::generate_macros!();

mod se050;
mod t1;
mod types;

pub use crate::se050::{Se050, Se050Device};
pub use t1::T1overI2C;
pub use types::{DelayWrapper, ObjectId};

#[cfg(test)]
mod tests;
