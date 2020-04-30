
/// a wrap-up Signature for runtime
use sp_std::prelude::*;
use sp_std::convert::{Into, TryFrom};
pub use sp_core::{TypeId, crypto::{key_types, KeyTypeId, CryptoType, AccountId32}};
pub use sp_application_crypto::{RuntimeAppPublic, BoundToRuntimeAppPublic};
pub use sp_core::{crypto::{self, Public}, ed25519, sr25519, ecdsa, hash::{H256, H512}};
pub use sp_core::RuntimeDebug;
use crate::sm2;
use codec::{Encode, Decode};
use sp_runtime::traits::{Verify, Lazy, IdentifyAccount};

#[cfg(feature = "std")]
pub use serde::{Serialize, Deserialize, de::DeserializeOwned};

/// Signature verify that can work with any known signature types..
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Eq, PartialEq, Clone, Encode, Decode, RuntimeDebug)]
pub enum MultiSignature {
	/// An Ed25519 signature.
	Ed25519(ed25519::Signature),
	/// An Sr25519 signature.
	Sr25519(sr25519::Signature),
	/// An ECDSA/SECP256k1 signature.
	Ecdsa(ecdsa::Signature),
	/// An SCA-256 signature
	Sm2(sm2::Signature),
}

impl From<ed25519::Signature> for MultiSignature {
	fn from(x: ed25519::Signature) -> Self {
		MultiSignature::Ed25519(x)
	}
}

impl From<sr25519::Signature> for MultiSignature {
	fn from(x: sr25519::Signature) -> Self {
		MultiSignature::Sr25519(x)
	}
}

impl From<ecdsa::Signature> for MultiSignature {
	fn from(x: ecdsa::Signature) -> Self {
		MultiSignature::Ecdsa(x)
	}
}

impl From<sm2::Signature> for MultiSignature {
	fn from(x: sm2::Signature) -> Self { MultiSignature::Sm2(x)}
}

impl Default for MultiSignature {
	fn default() -> Self {
		MultiSignature::Sm2(Default::default())
	}
}

/// Public key for any known crypto algorithm.
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Encode, Decode, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum MultiSigner {
	/// An Ed25519 identity.
	Ed25519(ed25519::Public),
	/// An Sr25519 identity.
	Sr25519(sr25519::Public),
	/// An SECP256k1/ECDSA identity (actually, the Blake2 hash of the compressed pub key).
	Ecdsa(ecdsa::Public),
	/// An SCA-256 identity (the Blake2 hash of the compressed pub key)
	Sm2(sm2::Public),
}

impl Default for MultiSigner {
	fn default() -> Self {
		MultiSigner::Sm2(Default::default())
	}
}

/// NOTE: This implementations is required by `SimpleAddressDeterminer`,
/// we convert the hash into some AccountId, it's fine to use any scheme.
impl<T: Into<H256>> crypto::UncheckedFrom<T> for MultiSigner {
	fn unchecked_from(x: T) -> Self {
		ed25519::Public::unchecked_from(x.into()).into()
	}
}

impl AsRef<[u8]> for MultiSigner {
	fn as_ref(&self) -> &[u8] {
		match *self {
			MultiSigner::Ed25519(ref who) => who.as_ref(),
			MultiSigner::Sr25519(ref who) => who.as_ref(),
			MultiSigner::Ecdsa(ref who) => who.as_ref(),
			MultiSigner::Sm2(ref who) => who.as_ref(),
		}
	}
}

impl IdentifyAccount for MultiSigner {
	type AccountId = AccountId32;
	fn into_account(self) -> AccountId32 {
		match self {
			MultiSigner::Ed25519(who) => <[u8; 32]>::from(who).into(),
			MultiSigner::Sr25519(who) => <[u8; 32]>::from(who).into(),
			MultiSigner::Ecdsa(who) => sp_io::hashing::blake2_256(&who.as_ref()[..]).into(),
			// ugly hacking
			MultiSigner::Sm2(who) => sp_io::hashing::blake2_256(&who.as_ref()[..]).into(),
		}
	}
}

impl From<ed25519::Public> for MultiSigner {
	fn from(x: ed25519::Public) -> Self {
		MultiSigner::Ed25519(x)
	}
}

impl TryFrom<MultiSigner> for ed25519::Public {
	type Error = ();
	fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
		if let MultiSigner::Ed25519(x) = m { Ok(x) } else { Err(()) }
	}
}

impl From<sr25519::Public> for MultiSigner {
	fn from(x: sr25519::Public) -> Self {
		MultiSigner::Sr25519(x)
	}
}

impl TryFrom<MultiSigner> for sr25519::Public {
	type Error = ();
	fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
		if let MultiSigner::Sr25519(x) = m { Ok(x) } else { Err(()) }
	}
}

impl From<ecdsa::Public> for MultiSigner {
	fn from(x: ecdsa::Public) -> Self {
		MultiSigner::Ecdsa(x)
	}
}

impl TryFrom<MultiSigner> for ecdsa::Public {
	type Error = ();
	fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
		if let MultiSigner::Ecdsa(x) = m { Ok(x) } else { Err(()) }
	}
}

impl From<sm2::Public> for MultiSigner {
	fn from(x: sm2::Public) -> Self { MultiSigner::Sm2(x)}
}

impl TryFrom<MultiSigner> for sm2::Public {
	type Error = ();
	fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
		if let MultiSigner::Sm2(x) = m { Ok(x) } else { Err(()) }
	}
}

#[cfg(feature = "std")]
impl std::fmt::Display for MultiSigner {
	fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
		match *self {
			MultiSigner::Ed25519(ref who) => write!(fmt, "ed25519: {}", who),
			MultiSigner::Sr25519(ref who) => write!(fmt, "sr25519: {}", who),
			MultiSigner::Ecdsa(ref who) => write!(fmt, "ecdsa: {}", who),
			MultiSigner::Sm2(ref who) => write!(fmt, "sm2: {}", who),
		}
	}
}

impl Verify for MultiSignature {
	type Signer = MultiSigner;
	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId32) -> bool {
		match (self, signer) {
			(MultiSignature::Ed25519(ref sig), who) => sig.verify(msg, &ed25519::Public::from_slice(who.as_ref())),
			(MultiSignature::Sr25519(ref sig), who) => sig.verify(msg, &sr25519::Public::from_slice(who.as_ref())),
			(MultiSignature::Ecdsa(ref sig), who) => {
				let m = sp_io::hashing::blake2_256(msg.get());
				match sp_io::crypto::secp256k1_ecdsa_recover_compressed(sig.as_ref(), &m) {
					Ok(pubkey) =>
						&sp_io::hashing::blake2_256(pubkey.as_ref())
							== <dyn AsRef<[u8; 32]>>::as_ref(who),
					_ => false,
				}
			},
			(MultiSignature::Sm2(ref sig), who) => {
				let pk = sig.into_sm2_pk();
				let r = sig.verify(msg.get(), &sm2::Public::from_raw(pk));
				let eq = &sp_io::hashing::blake2_256(pk.as_ref()) == <dyn AsRef<[u8; 32]>>::as_ref(who);
				r && eq

			}
		}
	}
}

