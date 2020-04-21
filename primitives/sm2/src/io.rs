
use sp_std::vec::Vec;

#[cfg(feature = "std")]
use sp_std::ops::Deref;
use codec::{Encode, Decode};
#[cfg(feature = "std")]
use sp_core::crypto::{Pair, Public};
use sp_runtime_interface::{runtime_interface, Pointer};
#[cfg(feature = "std")]
use crate::sm2::{Pair as Sm2Pair, Signature, Public as Sm2Public};

#[runtime_interface]
pub trait SCA {
	fn sm2_verify(
		sig: &[u8; 64],
		msg: &[u8],
		pubkey: &[u8]
	) -> bool {
		let sig = Signature::from_raw(*sig);
		let pk = Sm2Public::from_slice(pubkey);
		Sm2Pair::verify(&sig, msg, &pk)
	}
}
