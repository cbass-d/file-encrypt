use anyhow::{anyhow, Result};
use argon2::PasswordHash;
use base64::prelude::*;
use chacha20poly1305::{
    aead::{Aead, AeadCore},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use rand_core::OsRng;
use std::{ffi::OsString, fs, path::PathBuf};

use crate::hash_algos::argon_hash;

pub fn encrypt_file(
    file_path: String,
    passphrase: String,
    output_file: String,
) -> Result<(OsString, String)> {
    // Hash passphrase
    let argon_pch: String = argon_hash::hash_passphrase(passphrase);
    let hash = PasswordHash::new(&argon_pch).unwrap();
    let hash = match hash.hash {
        Some(hash) => hash.to_string(),
        None => {
            eprintln!("[-] Error with argon2 hash");
            return Err(anyhow!("Unable to get hash from Argon2 PCH"));
        }
    };

    // Argon2 hash is encoded in base64
    let hash = BASE64_STANDARD_NO_PAD.decode(hash)?;

    // Generate iv, cipher, and key for encryption
    let key = Key::from_slice(&hash);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);

    let file_data = fs::read(file_path.clone())?;
    let mut enc_data = match cipher.encrypt(&nonce, file_data.as_ref()) {
        Ok(enc_data) => enc_data,
        Err(e) => {
            let e = e.to_string();
            return Err(anyhow!("Unable to encrypt data: {e}"));
        }
    };

    let mut nonce_and_data = nonce.to_vec();
    nonce_and_data.append(&mut enc_data);

    let new_file = PathBuf::from(output_file);
    fs::write(new_file.clone(), nonce_and_data)?;

    Ok((new_file.into(), argon_pch))
}

pub fn decrypt_file(
    file_path: String,
    passphrase: String,
    expected_pch: String,
    output_file: String,
) -> Result<()> {
    let (res, hash_opt) = argon_hash::check_hash(passphrase, expected_pch);
    if res == false {
        eprintln!("[-] Invalid passphrase provided");
        return Err(anyhow!("Invalid passphrase"));
    }

    let hash = hash_opt.unwrap();
    let hash = PasswordHash::new(&hash).unwrap();
    let hash = hash.hash.unwrap().to_string();

    let hash = BASE64_STANDARD_NO_PAD.decode(hash)?;

    // Generate iv, cipher, and key for encryption
    let key = Key::from_slice(&hash);
    let cipher = ChaCha20Poly1305::new(&key);

    // Get nonce from encrypted data
    let mut nonce_and_data = fs::read(file_path.clone())?;
    let data = nonce_and_data.split_off(12);
    let nonce = nonce_and_data;
    let nonce = Nonce::from_slice(&nonce);

    let plain_data = match cipher.decrypt(nonce, data.as_ref()) {
        Ok(data) => data,
        Err(e) => {
            let e = e.to_string();
            return Err(anyhow!("Unable to decrypt file: {e}"));
        }
    };

    let new_file = PathBuf::from(output_file);

    fs::write(new_file, plain_data)?;

    Ok(())
}
