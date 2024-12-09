use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::PasswordHash;
use base64::prelude::*;
use rand_core::OsRng;
use std::{ffi::OsString, fs, path::PathBuf};

use crate::hash_algos::argon_hash;

pub fn encrypt_file(file_path: String, passphrase: String) -> (OsString, String) {
    let argon_pch: String = argon_hash::hash_passphrase(passphrase);
    let hash = PasswordHash::new(&argon_pch).unwrap();
    let hash = hash.hash.unwrap().to_string();

    // Argon2 hash is encoded in base64
    let hash = BASE64_STANDARD_NO_PAD.decode(hash).unwrap();

    // Generate iv, cipher, and key for encryption
    let key = Key::<Aes256Gcm>::from_slice(&hash);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);

    let file_data = fs::read(file_path.clone()).unwrap();
    let mut enc_data = cipher.encrypt(&nonce, file_data.as_ref()).unwrap();
    let mut nonce_and_data = nonce.to_vec();
    nonce_and_data.append(&mut enc_data);

    let new_file = file_path + ".enc";
    let new_file = PathBuf::from(new_file).into_os_string();

    let _ = fs::write(new_file.clone(), nonce_and_data);

    (new_file, argon_pch)
}

pub fn decrypt_file(file_path: String, passphrase: String, expected_pch: String) {
    let (res, hash_opt) = argon_hash::check_hash(passphrase, expected_pch);
    if res == false {
        eprintln!("[-] Invalid passphrase provided");
        panic!();
    }

    let hash = hash_opt.unwrap();
    let hash = PasswordHash::new(&hash).unwrap();
    let hash = hash.hash.unwrap().to_string();

    // Argon2 hash is encoded in base64
    let hash = BASE64_STANDARD_NO_PAD.decode(hash).unwrap();

    // Generate iv, cipher, and key for encryption
    let key = Key::<Aes256Gcm>::from_slice(&hash);
    let cipher = Aes256Gcm::new(&key);

    // Get nonce from encrypted data
    let mut nonce_and_data = fs::read(file_path.clone()).unwrap();
    let data = nonce_and_data.split_off(12);
    let nonce = nonce_and_data;
    let nonce = Nonce::from_slice(&nonce);

    let plain_data = match cipher.decrypt(nonce, data.as_ref()) {
        Ok(data) => data,
        Err(e) => {
            let e = e.to_string();
            println!("[-] Failed decrypting file: {e}");
            panic!();
        }
    };
    let plain = String::from_utf8(plain_data).unwrap();

    let new_file = file_path.replace(".enc", "");
    let new_file = PathBuf::from(new_file).into_os_string();

    let _ = fs::write(new_file, plain);
}
