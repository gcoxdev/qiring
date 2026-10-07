use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const MIN_MEMORY_COST_KIB: u32 = 8 * 1024;
pub const MAX_MEMORY_COST_KIB: u32 = 256 * 1024;
pub const MIN_ITERATIONS: u32 = 1;
pub const MAX_ITERATIONS: u32 = 10;
pub const MIN_PARALLELISM: u32 = 1;
pub const MAX_PARALLELISM: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_cost_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_cost_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfParams {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(MIN_MEMORY_COST_KIB..=MAX_MEMORY_COST_KIB).contains(&self.memory_cost_kib)
            || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations)
            || !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism)
        {
            anyhow::bail!("KDF parameters are outside supported resource bounds");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherBlob {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failure")]
    Encrypt,
    #[error("decryption failure")]
    Decrypt,
    #[error("invalid length")]
    InvalidLength,
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn derive_kek(
    master_password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> anyhow::Result<Zeroizing<[u8; KEY_LEN]>> {
    if salt.len() != SALT_LEN {
        anyhow::bail!("salt must be {SALT_LEN} bytes");
    }
    params.validate()?;

    let p = Params::new(
        params.memory_cost_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| anyhow::anyhow!("invalid argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);

    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(master_password.as_bytes(), salt, out.as_mut())
        .map_err(|e| anyhow::anyhow!("argon2 derivation failed: {e}"))?;
    Ok(out)
}

pub fn derive_recovery_kek(
    recovery_key: &str,
    salt: &[u8],
    params: &KdfParams,
) -> anyhow::Result<Zeroizing<[u8; KEY_LEN]>> {
    derive_kek(recovery_key, salt, params)
}

pub fn generate_recovery_key() -> String {
    let entropy = random_bytes(24);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, entropy)
}

pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<CipherBlob, CryptoError> {
    encrypt_with_aad(key, plaintext, &[])
}

pub fn encrypt_with_aad(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<CipherBlob, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    let nonce = random_bytes(NONCE_LEN);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(CipherBlob { nonce, ciphertext })
}

pub fn decrypt(key: &[u8], blob: &CipherBlob) -> Result<Vec<u8>, CryptoError> {
    decrypt_with_aad(key, blob, &[])
}

pub fn decrypt_with_aad(key: &[u8], blob: &CipherBlob, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_LEN || blob.nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidLength);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    cipher
        .decrypt(
            XNonce::from_slice(&blob.nonce),
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

pub fn wrap_dek(kek: &[u8], dek: &[u8; KEY_LEN]) -> Result<CipherBlob, CryptoError> {
    encrypt(kek, dek)
}

pub fn wrap_dek_with_aad(kek: &[u8], dek: &[u8; KEY_LEN], aad: &[u8]) -> Result<CipherBlob, CryptoError> {
    encrypt_with_aad(kek, dek, aad)
}

pub fn unwrap_dek(kek: &[u8], wrapped: &CipherBlob) -> Result<[u8; KEY_LEN], CryptoError> {
    unwrap_dek_with_aad(kek, wrapped, &[])
}

pub fn unwrap_dek_with_aad(
    kek: &[u8],
    wrapped: &CipherBlob,
    aad: &[u8],
) -> Result<[u8; KEY_LEN], CryptoError> {
    let plain = Zeroizing::new(decrypt_with_aad(kek, wrapped, aad)?);
    if plain.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength);
    }

    let mut dek = [0u8; KEY_LEN];
    dek.copy_from_slice(&plain);
    Ok(dek)
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn random_dek() -> [u8; KEY_LEN] {
    let mut dek = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut dek);
    dek
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_round_trip() {
        let key = random_dek();
        let msg = b"qiring-secret";
        let blob = encrypt(&key, msg).expect("encrypt");
        let plain = decrypt(&key, &blob).expect("decrypt");
        assert_eq!(plain, msg);
    }

    #[test]
    fn authenticated_context_cannot_be_changed() {
        let key = random_dek();
        let blob = encrypt_with_aad(&key, b"secret", b"vault:one").expect("encrypt");
        assert!(decrypt_with_aad(&key, &blob, b"vault:two").is_err());
        assert_eq!(
            decrypt_with_aad(&key, &blob, b"vault:one").expect("decrypt"),
            b"secret"
        );
    }

    #[test]
    fn ciphertext_tampering_is_rejected() {
        let key = random_dek();
        let mut blob = encrypt_with_aad(&key, b"secret", b"vault").expect("encrypt");
        blob.ciphertext[0] ^= 0x80;
        assert!(decrypt_with_aad(&key, &blob, b"vault").is_err());
    }

    #[test]
    fn nonce_tampering_and_truncation_are_rejected() {
        let key = random_dek();
        let mut changed = encrypt_with_aad(&key, b"secret", b"vault").expect("encrypt");
        changed.nonce[0] ^= 0x80;
        assert!(decrypt_with_aad(&key, &changed, b"vault").is_err());

        let mut truncated = encrypt_with_aad(&key, b"secret", b"vault").expect("encrypt");
        truncated.nonce.pop();
        assert!(decrypt_with_aad(&key, &truncated, b"vault").is_err());
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let kek = random_dek();
        let dek = random_dek();
        let wrapped = wrap_dek(&kek, &dek).expect("wrap");
        let unwrapped = unwrap_dek(&kek, &wrapped).expect("unwrap");
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn kdf_is_deterministic_for_same_input() {
        let params = KdfParams::default();
        let salt = random_salt();
        let one = derive_kek("master", &salt, &params).expect("kdf1");
        let two = derive_kek("master", &salt, &params).expect("kdf2");
        assert_eq!(one.as_slice(), two.as_slice());
    }

    #[test]
    fn kdf_preserves_existing_vault_keys() {
        // Captured with argon2 0.5.3 and QiRing's existing vault parameters.
        let key = derive_kek(
            "QiRing compatibility password",
            b"qiring-test-salt",
            &KdfParams::default(),
        )
        .expect("derive compatible key");
        assert_eq!(
            key.as_slice(),
            &[
                0xf8, 0xc6, 0x01, 0xba, 0xc1, 0xb3, 0x41, 0xf8, 0xa5, 0xda, 0x49, 0x48, 0x0f, 0x15, 0x0c,
                0x34, 0xab, 0x37, 0x2c, 0x41, 0x75, 0xb6, 0xe8, 0xa5, 0x7c, 0x2a, 0xd9, 0xae, 0xb4, 0x47,
                0x9c, 0x4d,
            ]
        );
    }

    #[test]
    fn kdf_rejects_untrusted_resource_exhaustion_values() {
        let salt = random_salt();
        let params = KdfParams {
            memory_cost_kib: MAX_MEMORY_COST_KIB + 1,
            ..Default::default()
        };
        assert!(derive_kek("master", &salt, &params).is_err());
    }
}
