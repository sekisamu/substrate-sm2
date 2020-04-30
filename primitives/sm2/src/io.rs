
use sp_std::vec::Vec;

#[cfg(feature = "std")]
use sp_std::ops::Deref;
use codec::{Encode, Decode};
#[cfg(feature = "std")]
use sp_core::crypto::{Pair, Public};
use sp_runtime_interface::{runtime_interface, Pointer};
#[cfg(feature = "std")]
use crate::sm2::{Pair as Sm2Pair, Public as Sm2Public};
use crate::sm2::Signature;

#[runtime_interface]
pub trait SCA {
	fn sm2_verify(
		sig: &Signature,
		msg: &[u8],
		pubkey: &[u8]
	) -> bool {
		let pk = Sm2Public::from_slice(&sig.into_sm2_pk());
		Sm2Pair::verify(&sig, msg, &pk)
	}
}
