mod edwards25519;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfVerificationError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfSerializationError;

pub trait VrfSecretKey: Sized {
    const LENGTH: usize;

    fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait VrfPublicKey: Sized {
    const LENGTH: usize;

    fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait VrfProof: Sized {
    type SecretKey: VrfSecretKey;
    type PublicKey: VrfPublicKey;

    type Hash;
    type BytesType;

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
