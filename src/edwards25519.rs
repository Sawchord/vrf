// TODO: Remove
#![allow(dead_code, unused_variables)]

use lucius_curves::{
    edwards25519::{Edwards25519, KeyPair, PublicKey, SecretKey},
    Curve,
};

use crate::{VrfSerializationError, VrfVerificationError};

pub struct VrfProof {
    gamma: <Edwards25519 as Curve>::Point,
    c: <Edwards25519 as Curve>::Scalar,
    s: <Edwards25519 as Curve>::Scalar,
}

impl crate::VrfProof for VrfProof {
    type Curve = Edwards25519;
    type Hash = ();
    type BytesType = ();

    fn generate(key_pair: &KeyPair, alpha_string: impl AsRef<[u8]>) -> (Self, Self::Hash) {
        // 2. H = ECVRF_hash_to_curve(Y, alpha_string)
        // 3. h_string = point_to_string(H)
        // 4. Gamma = x*H
        // 5. k = ECVRF_nonce_generation(SK, h_string)
        // 6. c = ECVRF_hash_points(H, Gamma, k*B, k*H) (see Section 5.4.3)
        // 7. s = (k + c*x) mod q
        todo!()
    }

    fn verify(&self, public_key: &PublicKey) -> Result<Self::Hash, VrfVerificationError> {
        // 4. H = ECVRF_hash_to_curve(Y, alpha_string)
        // 5. U = s*B - c*Y
        // 6. V = s*H - c*Gamma
        // 7. c' = ECVRF_hash_points(H, Gamma, U, V) (see Section 5.4.3)
        // 8. If c and c' are equal, output ("VALID",ECVRF_proof_to_hash(pi_string)); else output "INVALID"
        todo!()
    }

    fn to_bytes(&self) -> Self::BytesType {
        // point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
        todo!()
    }

    fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self, VrfSerializationError> {
        // Decode_proof
        todo!()
    }
}

impl VrfProof {
    fn proof_to_hash(&self) -> <Self as crate::VrfProof>::Hash {
        // 4. three_string = 0x03 = int_to_string(3, 1), a single octet with value 3
        // 5. zero_string = 0x00 = int_to_string(0, 1), a single octet with value 0
        // 6. beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma) || zero_string)
        // 7. Output beta_string
        todo!()
    }

    fn hash_to_curve_try_and_increment(
        y: &PublicKey,
        alpha_string: impl AsRef<[u8]>,
    ) -> <Edwards25519 as Curve>::Point {
        // 1. ctr = 0
        // 2. PK_string = point_to_string(Y)
        // 3. one_string = 0x01 = int_to_string(1, 1), a single octet with value 1
        // 4. zero_string = 0x00 = int_to_string(0, 1), a single octet with value 0
        // 5. H = "INVALID"
        // 6. While H is "INVALID" or H is the identity element of the elliptic curve group:
        //    A. ctr_string = int_to_string(ctr, 1)
        //    B. hash_string = Hash(suite_string || one_string || PK_string || alpha_string || ctr_string || zero_string)
        //    C.  H = arbitrary_string_to_point(hash_string)
        //    D.  If H is not "INVALID" and cofactor > 1, set H = cofactor * H
        //    E.  ctr = ctr + 1
        // 7. Output H
        todo!()
    }

    fn nonce_generation(
        secret_key: &SecretKey,
        h_string: impl AsRef<[u8]>,
    ) -> <Edwards25519 as Curve>::Scalar {
        // 1. hashed_sk_string = Hash(SK)
        // 2. truncated_hashed_sk_string = hashed_sk_string[32]...hashed_sk_string[63]
        // 3. k_string = Hash(truncated_hashed_sk_string || h_string)
        // 4. k = string_to_int(k_string) mod q
        todo!()
    }
}
