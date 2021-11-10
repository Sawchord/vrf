use lucius_curves::{Curve, PublicKey, SecretKey};

mod edwards25519;

pub type VfrHash = [u8; 32];

pub trait VrfProof: Sized {
    type Curve: Curve;

    fn generate(secret_key: &SecretKey<Self::Curve>, data: impl AsRef<[u8]>) -> (Self, VfrHash);

    fn verify(&self, public_key: &PublicKey<Self::Curve>) -> Result<VfrHash, ()>;
}
