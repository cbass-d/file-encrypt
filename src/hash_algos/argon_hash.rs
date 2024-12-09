use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, PasswordVerifier,
};

pub fn hash_passphrase(passphrase: String) -> String {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    let hash = argon2.hash_password(passphrase.as_bytes(), &salt).unwrap();
    let hash = hash.to_string();

    hash
}

pub fn check_hash(passphrase: String, expected_pch: String) -> (bool, Option<String>) {
    let expected_pch: PasswordHash = PasswordHash::new(&expected_pch).unwrap();

    match Argon2::default().verify_password(passphrase.as_bytes(), &expected_pch) {
        Ok(_) => {
            return (true, Some(expected_pch.to_string()));
        }
        Err(_) => {
            return (false, None);
        }
    }
}
