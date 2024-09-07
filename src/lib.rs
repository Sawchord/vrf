#![no_std]

pub mod edwards25519;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfVerificationError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfSerializationError;

pub trait VrfSecretKey: Sized {
    const LENGTH: usize;
    type BytesType: AsRef<[u8]>;

    fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self>;
    fn to_bytes(&self) -> Self::BytesType;
}

pub trait VrfPublicKey: Sized {
    const LENGTH: usize;
    type BytesType: AsRef<[u8]>;

    fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self>;
    fn to_bytes(&self) -> Self::BytesType;
}

pub trait VrfProof: Sized {
    type SecretKey: VrfSecretKey;
    type PublicKey: VrfPublicKey;

    type Hash;
    type BytesType: AsRef<[u8]>;

    fn generate(
        public_key: &Self::PublicKey,
        secret_key: &Self::SecretKey,
        alpha_string: impl AsRef<[u8]>,
    ) -> (Self, Self::Hash);

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        alpha_string: impl AsRef<[u8]>,
    ) -> Result<Self::Hash, VrfVerificationError>;

    fn to_bytes(&self) -> Self::BytesType;

    fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self, VrfSerializationError>;
}
