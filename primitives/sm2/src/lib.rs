#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc_error_handler))]

pub mod sm2;
pub mod rt_sig;
pub mod io;


pub use self::sm2::{Public, Signature};
pub use self::rt_sig::{MultiSignature, MultiSigner};