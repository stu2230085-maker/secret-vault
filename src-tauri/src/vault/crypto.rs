use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

use super::format::{SLOT_CIPHERTEXT_LEN, SLOT_LEN};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SLOT_AAD: &[u8] = b"VLT1 key slot";

fn argon2id() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, None).expect("fixed Argon2 parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub(super) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub(super) fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let nonce = random_bytes::<NONCE_LEN>();
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .ok()?;
    let mut record = Vec::with_capacity(NONCE_LEN + encrypted.len());
    record.extend_from_slice(&nonce);
    record.extend_from_slice(&encrypted);
    Some(record)
}

pub(super) fn decrypt(key: &[u8; 32], record: &[u8], aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if record.len() < NONCE_LEN + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&record[..NONCE_LEN]),
            Payload {
                msg: &record[NONCE_LEN..],
                aad,
            },
        )
        .ok()?;
    Some(Zeroizing::new(plaintext))
}

pub(super) fn make_slot(
    password: &str,
    role: u8,
    mode: u8,
    master_key: &[u8; 32],
) -> [u8; SLOT_LEN] {
    let salt = random_bytes::<SALT_LEN>();
    let nonce = random_bytes::<NONCE_LEN>();
    let mut wrapping_key = Zeroizing::new([0; 32]);
    argon2id()
        .hash_password_into(password.as_bytes(), &salt, &mut *wrapping_key)
        .expect("fixed Argon2 parameters are valid");

    let mut payload = Zeroizing::new([0; 34]);
    payload[0] = role;
    payload[1] = mode;
    payload[2..].copy_from_slice(master_key);

    let cipher = Aes256Gcm::new_from_slice(&*wrapping_key).expect("AES-256 key length is fixed");
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &*payload,
                aad: SLOT_AAD,
            },
        )
        .expect("key slot encryption should succeed");

    let mut slot = [0; SLOT_LEN];
    slot[..SALT_LEN].copy_from_slice(&salt);
    slot[SALT_LEN..SALT_LEN + NONCE_LEN].copy_from_slice(&nonce);
    slot[SALT_LEN + NONCE_LEN..].copy_from_slice(&encrypted);
    debug_assert_eq!(encrypted.len(), SLOT_CIPHERTEXT_LEN);
    slot
}

pub(super) fn open_slot(password: &str, slot: &[u8; SLOT_LEN]) -> Option<Zeroizing<Vec<u8>>> {
    let salt = &slot[..SALT_LEN];
    let nonce = &slot[SALT_LEN..SALT_LEN + NONCE_LEN];
    let encrypted = &slot[SALT_LEN + NONCE_LEN..];
    let mut wrapping_key = Zeroizing::new([0; 32]);
    argon2id()
        .hash_password_into(password.as_bytes(), salt, &mut *wrapping_key)
        .ok()?;
    let cipher = Aes256Gcm::new_from_slice(&*wrapping_key).ok()?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: encrypted,
                aad: SLOT_AAD,
            },
        )
        .ok()
        .map(Zeroizing::new)
}
