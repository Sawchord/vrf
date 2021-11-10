use lucius_curves::edwards25519::{Edwards25519, PublicKey, SecretKey};

pub struct VrfProof {}

impl crate::VrfProof for VrfProof {
    type Curve = Edwards25519;

    fn generate(secret_key: &SecretKey, data: impl AsRef<[u8]>) -> (Self, crate::VfrHash) {
        todo!()
    }

    fn verify(&self, public_key: &PublicKey) -> Result<crate::VfrHash, ()> {
        todo!()
    }
}
