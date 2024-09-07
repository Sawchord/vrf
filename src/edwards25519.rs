use crate::{VrfPublicKey, VrfSecretKey, VrfSerializationError, VrfVerificationError};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    digest::Update,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

#[derive(Zeroize, Serialize, Deserialize)]
pub struct SecretKey([u8; 32]);

impl VrfSecretKey for SecretKey {
    const LENGTH: usize = 32;
    type BytesType = [u8; 32];

    fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self> {
        if data.as_ref().len() != Self::LENGTH {
            return None;
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&data.as_ref()[0..32]);

        Some(Self(bits))
    }

    fn to_bytes(&self) -> Self::BytesType {
        self.0
    }
}

impl SecretKey {
    fn expand(&self) -> (Scalar, [u8; 32]) {
        let hash: [u8; 64] = Sha512::digest(self.0).as_slice().try_into().unwrap();

        let mut lower: [u8; 32] = hash[0..32].try_into().unwrap();
        let upper: [u8; 32] = hash[32..64].try_into().unwrap();

        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        (Scalar::from_bytes_mod_order(lower), upper)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(EdwardsPoint);

impl VrfPublicKey for PublicKey {
    const LENGTH: usize = 32;
    type BytesType = [u8; 32];

    fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self> {
        Some(Self(
            CompressedEdwardsY::from_slice(data.as_ref())
                .unwrap()
                .decompress()?,
        ))
    }

    fn to_bytes(&self) -> Self::BytesType {
        self.0.compress().to_bytes()
    }
}

impl From<&ed25519_dalek::VerifyingKey> for PublicKey {
    fn from(pk: &ed25519_dalek::VerifyingKey) -> Self {
        Self::from_bytes(pk.as_bytes()).unwrap()
    }
}

// NOTE: This is copied from ed25519-dalek implementation.
impl From<&SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> Self {
        let hash: [u8; 64] = Sha512::digest(secret_key.0).as_slice().try_into().unwrap();

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&hash[0..32]);

        bits[0] &= 248;
        bits[31] &= 127;
        bits[31] |= 64;

        PublicKey(Scalar::from_bytes_mod_order(bits) * ED25519_BASEPOINT_POINT)
    }
}

impl From<&ed25519_dalek::SecretKey> for SecretKey {
    fn from(sk: &ed25519_dalek::SecretKey) -> Self {
        Self::from_bytes(sk).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfProof {
    gamma: EdwardsPoint,
    c: Scalar,
    s: Scalar,
}

impl crate::VrfProof for VrfProof {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Hash = [u8; 64];
    type BytesType = [u8; 80];

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
        let c = Self::hash_points([h, gamma, k * ED25519_BASEPOINT_POINT, k * h]);

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
        let c_tick = Self::hash_points([h, self.gamma, u, v]);

        // 8. If c and c' are equal, output ("VALID",ECVRF_proof_to_hash(pi_string)); else output "INVALID"
        match self.c == c_tick {
            false => Err(VrfVerificationError),
            true => Ok(self.proof_to_hash()),
        }
    }

    fn to_bytes(&self) -> Self::BytesType {
        // point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
        let mut output = [0; 80];
        output[0..32].copy_from_slice(&self.gamma.compress().to_bytes());
        output[32..48].copy_from_slice(&self.c.to_bytes()[0..16]);
        output[48..80].copy_from_slice(&self.s.to_bytes());

        output
    }

    fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self, VrfSerializationError> {
        // Decode_proof
        Ok(Self {
            gamma: CompressedEdwardsY::from_slice(&data.as_ref()[0..32])
                .unwrap()
                .decompress()
                .ok_or(VrfSerializationError)?,
            c: {
                let mut c = [0; 32];
                c[0..16].copy_from_slice(&data.as_ref()[32..48]);
                Scalar::from_bytes_mod_order(c)
            },
            s: Scalar::from_bytes_mod_order(data.as_ref()[48..80].try_into().unwrap()),
        })
    }
}

impl VrfProof {
    fn proof_to_hash(&self) -> <Self as crate::VrfProof>::Hash {
        // 6. beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma) || zero_string)
        let beta_string: [u8; 64] = Sha512::new()
            .chain([0x03]) // Suite string for EDWARDS25519-SHA512-TAI
            .chain([0x03])
            .chain((Scalar::from(8u8) * self.gamma).compress().to_bytes())
            .chain([0x00])
            .finalize()
            .as_slice()
            .try_into()
            .unwrap();

        // 7. Output beta_string
        beta_string
    }

    fn hash_points(points: impl AsRef<[EdwardsPoint]>) -> Scalar {
        // 2. Initialize str = suite_string || two_string
        let str = Sha512::new().chain([0x03]).chain([0x02]);

        // 3. for PJ in [P1, P2, ... PM]:str = str || point_to_string(PJ)
        let str = points
            .as_ref()
            .iter()
            .fold(str, |acc, point| acc.chain(point.compress().to_bytes()));

        // 4. zero_string = 0x00 = int_to_string(0, 1), a single octet with value 0
        // 5. str = str || zero_string
        // 6. c_string = Hash(str)
        let c_string: [u8; 64] = str.chain([0x00]).finalize().as_slice().try_into().unwrap();

        // 7. truncated_c_string = c_string[0]...c_string[n-1]
        let mut truncated_c_string: [u8; 32] = c_string[0..32].try_into().unwrap();
        truncated_c_string[16..32].copy_from_slice(&[0; 16]);

        // 8. c = string_to_int(truncated_c_string)
        // 9. Output c
        Scalar::from_bytes_mod_order(truncated_c_string)
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
                .chain([0x03]) // Suite string
                .chain([0x01])
                .chain(pk_string)
                .chain(alpha_string.as_ref())
                .chain(ctr_string)
                .chain([0x00])
                .finalize()
                .as_slice()
                .try_into()
                .unwrap();

            // C.  H = arbitrary_string_to_point(hash_string)
            match CompressedEdwardsY::from_slice(&hash_string[0..32])
                .unwrap()
                .decompress()
            {
                // D.  If H is not "INVALID" and cofactor > 1, set H = cofactor * H
                Some(point) => break Scalar::from(8u8) * point,
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
            Sha512::digest(secret_key.0).as_slice().try_into().unwrap();

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
mod tests {
    use super::*;
    use crate::VrfProof;
    use assert_matches::assert_matches;
    use hex_literal::hex;

    #[allow(unused_variables)]
    fn run_test_case(sk: &[u8; 32], pk: &[u8; 32], alpha: &[u8], beta: &[u8; 64], pi: &[u8; 80]) {
        let sk = SecretKey::from_bytes(sk).unwrap();

        // Generate proof
        let (proof, gen_hash) = super::VrfProof::generate(&PublicKey::from(&sk), &sk, alpha);

        // Serialize
        let proof_string = proof.to_bytes();

        // Check that hash of proof works
        assert_eq!(&gen_hash, beta);

        // Check that verification passes and generates same test
        assert_matches!(
            proof.verify(&PublicKey::from_bytes(pk).unwrap(), alpha),
            Ok(beta)
        );

        // Check the proof string
        assert_eq!(&proof_string, pi);

        // Check that serialization works
        assert_eq!(super::VrfProof::from_bytes(pi).unwrap(), proof);
    }

    /// Example 16
    #[test]
    fn test_case1() {
        const SK: [u8; 32] =
            hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        const PK: [u8; 32] =
            hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        const ALPHA: [u8; 0] = [];
        const BETA: [u8; 64] = hex!(
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876
            ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"
        );
        const PI: [u8; 80] = hex!(
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f
            5e8bd1839b414219e8626d393787a192241fc442e6569e96c462f62b8079b9ed83ff2
            ee21c90c7c398802fdeebea4001"
        );
        run_test_case(&SK, &PK, &ALPHA, &BETA, &PI);
    }

    /// Example 17
    #[test]
    fn test_case2() {
        const SK: [u8; 32] =
            hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        const PK: [u8; 32] =
            hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        const ALPHA: [u8; 1] = hex!("72");
        const BETA: [u8; 64] = hex!(
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310
            eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"
        );
        const PI: [u8; 80] = hex!(
            "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593
            f7eaf3eb2f1a968cba3f6e23b386aeeaab7b1ea44a256e811892e13eeae7c9f6ea899
            2557453eac11c4d5476b1f35a08"
        );
        run_test_case(&SK, &PK, &ALPHA, &BETA, &PI);
    }

    /// Example 18
    #[test]
    fn test_case3() {
        const SK: [u8; 32] =
            hex!("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        const PK: [u8; 32] =
            hex!("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        const ALPHA: [u8; 2] = hex!("af82");
        const BETA: [u8; 64] = hex!(
            "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c
            452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"
        );
        const PI: [u8; 80] = hex!(
            "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80
            e29dc513c01c3a980e0e545bcd848222d08a6c3e3665ff5a4cab13a643bef812e284c
            6b2ee063a2cb4f456794723ad0a"
        );
        run_test_case(&SK, &PK, &ALPHA, &BETA, &PI);
    }
}
