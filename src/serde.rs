use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
// TODO: Need to implement this functionality without ByteBuf
use serde_bytes::ByteBuf;

use crate::{
    edwards25519::{PublicKey, SecretKey, VrfProof},
    VrfProof as Proof, VrfPublicKey, VrfSecretKey,
};

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <ByteBuf>::deserialize(deserializer)?;
        PublicKey::from_bytes(bytes.as_ref()).ok_or(Error::custom("Failed to parse the public key"))
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <ByteBuf>::deserialize(deserializer)?;
        SecretKey::from_bytes(bytes.as_ref()).ok_or(Error::custom("Failed to parse the secret key"))
    }
}

impl Serialize for VrfProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for VrfProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <ByteBuf>::deserialize(deserializer)?;
        VrfProof::from_bytes(bytes.as_ref()).map_err(|err| Error::custom(format!("{:?}", err)))
    }
}

// TODO: Test re-serialization
