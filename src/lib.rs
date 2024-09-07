#![no_std]

pub mod edwards25519;

/// Generic error during Vrf verification
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfVerificationError;

/// Generic error during Vrf serialization
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

/// A generated [`VrfProof`]
pub trait VrfProof: Sized {
    type SecretKey: VrfSecretKey;
    type PublicKey: VrfPublicKey;

    /// The type of the hash output
    type Hash;

    /// The type of the serialized form of this proof
    type BytesType: AsRef<[u8]>;

    /// Generate a VRF proof
    ///
    /// # Arguments
    ///
    /// - `public_key`: the [`VrfPublicKey`] to generate this [`VrfProof`] for
    /// - `secret_key`: the [`VrfSecretKey`] to generate this [`VrfProof`] for
    /// - `alpha_string`: an arbitrary context string, needs to be the same one as used for [`VrfProof::verify`]
    ///
    /// # Returns
    ///
    /// `(proof, randomness)` where:
    /// - `proof` is the VRF proof that can be sent to the verifiers
    /// - `randomness` is the randomness produced by the VRF
    ///
    fn generate(
        public_key: &Self::PublicKey,
        secret_key: &Self::SecretKey,
        alpha_string: impl AsRef<[u8]>,
    ) -> (Self, Self::Hash);

    /// Validate a VRF proof
    ///
    /// # Arguments
    ///
    /// - `public_key`: the [`VrfPublicKey`] to validate this [`VrfProof`] against
    /// - `alpha_string`: an arbitrary context string, needs to be the same one as used for [`VrfProof::generate`]
    ///
    /// # Returns
    ///
    /// The generated randomness (on success)
    fn verify(
        &self,
        public_key: &Self::PublicKey,
        alpha_string: impl AsRef<[u8]>,
    ) -> Result<Self::Hash, VrfVerificationError>;

    /// Serialize this proof to [RFC9831](https://www.rfc-editor.org/rfc/rfc9381.html) compliant form
    fn to_bytes(&self) -> Self::BytesType;

    /// Deserialize this proof from [RFC9831](https://www.rfc-editor.org/rfc/rfc9381.html) compliant form
    fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self, VrfSerializationError>;
}
