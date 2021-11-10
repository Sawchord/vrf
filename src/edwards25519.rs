use lucius_curves::edwards25519::{Edwards25519, KeyPair, PublicKey};

pub struct VrfProof {}

impl crate::VrfProof for VrfProof {
    type Curve = Edwards25519;

    fn generate(key_pair: &KeyPair, data: impl AsRef<[u8]>) -> (Self, crate::VfrHash) {
        todo!()
    }

    fn verify(&self, public_key: &PublicKey) -> Result<crate::VfrHash, ()> {
        todo!()
    }
}
