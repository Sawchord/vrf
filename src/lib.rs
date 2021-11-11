use lucius_curves::{Curve, KeyPair, PublicKey};

mod edwards25519;

pub struct VrfVerificationError;

pub struct VrfSerializationError;

pub trait VrfProof: Sized {
    type Curve: Curve;
    type Hash;
    type BytesType;

    fn generate(
        key_pair: &KeyPair<Self::Curve>,
        alpha_string: impl AsRef<[u8]>,
    ) -> (Self, Self::Hash);

    fn verify(
        &self,
        public_key: &PublicKey<Self::Curve>,
        alpha_string: impl AsRef<[u8]>,
    ) -> Result<Self::Hash, VrfVerificationError>;

    fn to_bytes(&self) -> Self::BytesType;

    fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self, VrfSerializationError>;
}
