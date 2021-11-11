// TODO: Remove
#![allow(dead_code, unused_variables)]

use crate::{VrfPublicKey, VrfSecretKey, VrfSerializationError, VrfVerificationError};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

pub struct SecretKey([u8; 32]);

impl VrfSecretKey for SecretKey {
    const LENGTH: usize = 32;

    fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self> {
        if data.as_ref().len() != Self::LENGTH {
            return None;
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&data.as_ref()[0..32]);

        Some(Self(bits))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl SecretKey {
    fn expand(&self) -> (Scalar, [u8; 32]) {
        todo!()
    }
}

pub struct PublicKey(EdwardsPoint);

impl VrfPublicKey for PublicKey {
    const LENGTH: usize = 32;

    fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self> {
        Some(Self(
            CompressedEdwardsY::from_slice(data.as_ref()).decompress()?,
        ))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.compress().to_bytes().to_vec()
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> Self {
        let hash: [u8; 64] = Sha512::digest(&secret_key.0).as_slice().try_into().unwrap();

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&hash[0..32]);

        bits[0] &= 248;
        bits[31] &= 127;
        bits[31] |= 64;

        PublicKey(Scalar::from_bits(bits) * ED25519_BASEPOINT_POINT)
    }
}

pub struct VrfProof {
    gamma: EdwardsPoint,
    c: Scalar,
    s: Scalar,
}

impl crate::VrfProof for VrfProof {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Hash = [u8; 64];
    type BytesType = ();

    fn generate(
        public_key: &Self::PublicKey,
        secret_key: &Self::SecretKey,
        alpha_string: impl AsRef<[u8]>,
    ) -> (Self, Self::Hash) {
        let (exp_secret_key, _) = secret_key.expand();

        // 2. H = ECVRF_hash_to_curve(Y, alpha_string)
        let h = Self::hash_to_curve(public_key, alpha_string);

        // 3. h_string = point_to_string(H)
        let h_string = h.compress().to_bytes();

        // 4. Gamma = x*H
        let gamma = exp_secret_key * h;

        // 5. k = ECVRF_nonce_generation(SK, h_string)
        let k = Self::nonce_generation(secret_key, h_string);

        // 6. c = ECVRF_hash_points(H, Gamma, k*B, k*H) (see Section 5.4.3)
        let c = Self::hash_points(&[h, gamma, k * ED25519_BASEPOINT_POINT, k * h]);

        // 7. s = (k + c*x) mod q
        let s = k + c * exp_secret_key;

        // Return proof and hash
        let proof = Self { gamma, s, c };
        let hash = proof.proof_to_hash();
        (proof, hash)
    }

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        alpha_string: impl AsRef<[u8]>,
    ) -> Result<Self::Hash, VrfVerificationError> {
        // 4. H = ECVRF_hash_to_curve(Y, alpha_string)
        let h = Self::hash_to_curve(public_key, alpha_string);

        // 5. U = s*B - c*Y
        let u = self.s * ED25519_BASEPOINT_POINT - self.c * public_key.0;

        // 6. V = s*H - c*Gamma
        let v = self.s * h - self.c * self.gamma;

        // 7. c' = ECVRF_hash_points(H, Gamma, U, V) (see Section 5.4.3)
        let c_tick = Self::hash_points(&[h, self.gamma, u, v]);

        // 8. If c and c' are equal, output ("VALID",ECVRF_proof_to_hash(pi_string)); else output "INVALID"
        match self.c == c_tick {
            false => Err(VrfVerificationError),
            true => Ok(self.proof_to_hash()),
        }
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
        // 6. beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma) || zero_string)
        let beta_string: [u8; 64] = Sha512::new()
            .chain(&[0x03]) // Suite string for EDWARDS25519-SHA512-TAI
            .chain(&[0x03])
            .chain((Scalar::from(8u8) * self.gamma).compress().to_bytes())
            .chain(&[0x00])
            .finalize()
            .as_slice()
            .try_into()
            .unwrap();

        // 7. Output beta_string
        beta_string
    }

    fn hash_points(points: impl AsRef<[EdwardsPoint]>) -> Scalar {
        // 2. Initialize str = suite_string || two_string
        let str = Sha512::new().chain(&[0x03]).chain([0x02]);

        // 3. for PJ in [P1, P2, ... PM]:str = str || point_to_string(PJ)
        let str = points
            .as_ref()
            .iter()
            .fold(str, |acc, point| acc.chain(point.compress().to_bytes()));

        // 4. zero_string = 0x00 = int_to_string(0, 1), a single octet with value 0
        // 5. str = str || zero_string
        // 6. c_string = Hash(str)
        let c_string: [u8; 64] = str.chain(&[0x00]).finalize().as_slice().try_into().unwrap();

        // 7. truncated_c_string = c_string[0]...c_string[n-1]
        let truncated_c_string: [u8; 32] = c_string[0..32].try_into().unwrap();

        // 8. c = string_to_int(truncated_c_string)
        let c = Scalar::from_bytes_mod_order(truncated_c_string);

        // 9. Output c
        c
    }

    fn hash_to_curve(y: &PublicKey, alpha_string: impl AsRef<[u8]>) -> EdwardsPoint {
        // 1. ctr = 0
        let mut ctr: u8 = 0;
        // 2. PK_string = point_to_string(Y)
        let pk_string = y.0.compress().to_bytes();

        // 6. While H is "INVALID" or H is the identity element of the elliptic curve group:
        let h = loop {
            // A. ctr_string = int_to_string(ctr, 1)
            let ctr_string: &[u8] = &[ctr];

            // B. hash_string = Hash(suite_string || one_string || PK_string || alpha_string || ctr_string || zero_string)
            let hash_string: [u8; 64] = Sha512::new()
                .chain(&[0x03]) // Suite string
                .chain(&[0x01])
                .chain(&pk_string)
                .chain(alpha_string.as_ref())
                .chain(ctr_string)
                .chain(&[0x00])
                .finalize()
                .as_slice()
                .try_into()
                .unwrap();

            // C.  H = arbitrary_string_to_point(hash_string)
            match CompressedEdwardsY::from_slice(&hash_string[0..32]).decompress() {
                // D.  If H is not "INVALID" and cofactor > 1, set H = cofactor * H
                Some(point) => break point,
                // E.  ctr = ctr + 1
                None => ctr += 1,
            }
        };

        // 7. Output H
        h
    }

    fn nonce_generation(secret_key: &SecretKey, h_string: impl AsRef<[u8]>) -> Scalar {
        // 1. hashed_sk_string = Hash(SK)
        let hashed_sk_string: [u8; 64] =
            Sha512::digest(&secret_key.0).as_slice().try_into().unwrap();

        // 2. truncated_hashed_sk_string = hashed_sk_string[32]...hashed_sk_string[63]
        let truncated_hashed_sk_string = &hashed_sk_string[32..64];

        // 3. k_string = Hash(truncated_hashed_sk_string || h_string)
        let k_string: [u8; 64] = Sha512::new()
            .chain(truncated_hashed_sk_string)
            .chain(h_string)
            .finalize()
            .as_slice()
            .try_into()
            .unwrap();

        // 4. k = string_to_int(k_string) mod q
        Scalar::from_bytes_mod_order_wide(&k_string)
    }
}

#[cfg(test)]
//#[cfg(feature = "none")]
mod tests {
    use crate::VrfProof;

    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_case1() {
        const SK: [u8; 32] =
            hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        const PK: [u8; 32] =
            hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        const ALPHA: [u8; 0] = [];
        const BETHA: [u8; 64] = hex!(
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876
            ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"
        );

        let sk = SecretKey::from_bytes(&SK).unwrap();
        let pk = PublicKey::from(&sk);

        assert_eq!(&pk.to_bytes(), &PK);

        let (proof, gen_hash) = super::VrfProof::generate(&pk, &sk, &ALPHA);
        assert_eq!(&gen_hash, &BETHA);

        assert!(proof.verify(&pk, &ALPHA).is_ok());
    }
}
