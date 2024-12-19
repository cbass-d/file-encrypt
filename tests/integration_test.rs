use file_encrypt::encryption_algos;
use std::ffi::OsString;
use std::fs;

#[test]
fn test_aes256_gcm() {
    let _ = fs::write("plain_text", b"Hello World 123456789:$");
    let file = String::from("plain_text");
    let passphrase = String::from("secret_key");
    let out_file = String::from("aes_cipher_text");
    let out_file_os_string = OsString::from(out_file.clone());
    let argon_pch: String;

    match encryption_algos::aes256_gcm::encrypt_file(file, passphrase.clone(), out_file.clone()) {
        Ok((new_file, hash)) => {
            argon_pch = hash;
            assert_eq!(out_file_os_string, new_file);
        }
        Err(e) => {
            panic!("{}", e.to_string());
        }
    }

    let file = out_file;
    let out_file = String::from("new_plain_text");
    match encryption_algos::aes256_gcm::decrypt_file(file, passphrase, argon_pch, out_file.clone())
    {
        Ok(()) => {
            let content: Vec<u8> = fs::read(out_file).unwrap();
            assert_eq!(content, b"Hello World 123456789:$");
        }
        Err(e) => {
            panic!("{}", e.to_string());
        }
    }

    let _ = fs::remove_file("plain_text");
    let _ = fs::remove_file("new_plain_text");
    let _ = fs::remove_file("aes_cipher_text");
}

#[test]
fn test_chacha20() {
    let _ = fs::write("plain_text", b"Hello World 123456789:$");
    let file = String::from("plain_text");
    let passphrase = String::from("secret_key");
    let out_file = String::from("chacha_cipher_text");
    let out_file_os_string = OsString::from(out_file.clone());
    let argon_pch: String;

    match encryption_algos::chacha20_poly::encrypt_file(file, passphrase.clone(), out_file.clone())
    {
        Ok((new_file, hash)) => {
            argon_pch = hash;
            assert_eq!(out_file_os_string, new_file);
        }
        Err(e) => {
            panic!("{}", e.to_string());
        }
    }

    let file = out_file;
    let out_file = String::from("new_plain_text");
    match encryption_algos::chacha20_poly::decrypt_file(
        file,
        passphrase,
        argon_pch,
        out_file.clone(),
    ) {
        Ok(()) => {
            let content: Vec<u8> = fs::read(out_file).unwrap();
            assert_eq!(content, b"Hello World 123456789:$");
        }
        Err(e) => {
            panic!("{}", e.to_string());
        }
    }

    let _ = fs::remove_file("plain_text");
    let _ = fs::remove_file("new_plain_text");
    let _ = fs::remove_file("chacha_cipher_text");
}
