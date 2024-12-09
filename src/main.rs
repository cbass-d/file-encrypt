use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, PasswordVerifier,
};
use base64::prelude::*;
use clap::{Parser, Subcommand, ValueEnum};
use dirs::{data_local_dir, home_dir};
use rusqlite::{params, Connection, OpenFlags, RowIndex};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Subcommand, Debug)]
enum Command {
    Encrypt,
    Decrypt,
}

#[derive(ValueEnum, Debug, Clone)]
enum Algorithm {
    AES256Gcm,
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    // Command to run: Encryption, Decryption
    #[command(subcommand)]
    command: Command,

    // File name
    #[arg(short, long)]
    file: String,

    // Cryptographic algorithm to use
    #[arg(value_enum)]
    algorithm: Algorithm,

    // Passphrase to use for key derivation
    #[arg(short, long)]
    passphrase: String,
}

pub fn get_phrase_hash(passphrase: String) -> String {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    let hash = argon2.hash_password(passphrase.as_bytes(), &salt).unwrap();
    let hash = hash.to_string();

    hash
}

pub fn encrypt_file(file_path: String, algo: Algorithm, passphrase: String) {
    let pch_hash = get_phrase_hash(passphrase);
    let hash = PasswordHash::new(&pch_hash).unwrap();
    let hash = hash.hash.unwrap().to_string();

    // Argon2 hash is encoded in base64
    let hash = BASE64_STANDARD_NO_PAD.decode(hash).unwrap();

    // Generate iv, cipher, and key for encryption
    let key = Key::<Aes256Gcm>::from_slice(&hash);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);

    let file_data = fs::read(file_path).unwrap();
    let mut enc_data = cipher.encrypt(&nonce, file_data.as_ref()).unwrap();
    let mut nonce_data = nonce.to_vec();
    nonce_data.append(&mut enc_data);

    fs::write("test.enc", nonce_data).unwrap();

    // Store passhprhase/encrypted file pair in database
    match open_db() {
        Ok(conn) => {
            conn.execute(
                "insert into passphrases (file, pch) values (?1, ?2)",
                params!["test.enc", pch_hash],
            )
            .unwrap();
        }
        Err(e) => {
            eprintln!("[-] Unable to open database: {}", e);
            return;
        }
    }
}

pub fn decrypt_file(file_path: String, alog: Algorithm, passphrase: String) {
    let (res, hash_opt) = check_passphrase_hash(passphrase.clone(), file_path.clone());
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
    let enc_data = fs::read(file_path.clone()).unwrap();
    let nonce = &enc_data[0..12];
    let nonce = Nonce::from_slice(nonce);
    let enc_data = enc_data[12..].to_owned();

    let plain_data = match cipher.decrypt(nonce, enc_data.as_ref()) {
        Ok(data) => data,
        Err(e) => {
            let e = e.to_string();
            println!("[-] Failed decrypting file: {e}");
            panic!();
        }
    };
    let plain = String::from_utf8(plain_data).unwrap();

    let mut file_path: PathBuf = PathBuf::from(file_path);
    file_path.set_extension("txt");

    fs::write(file_path, plain);
}

pub fn create_db() -> Result<PathBuf, rusqlite::Error> {
    let db_path = match data_local_dir() {
        Some(data_dir) => {
            let mut db_path = data_dir;
            db_path.push("lockbox_data");
            db_path
        }
        None => PathBuf::from("../lockbox_data"),
    };

    let conn = Connection::open(&db_path)?;

    conn.execute(
        "create table if not exists passphrases (
            file text primary key,
            pch text not null
        )",
        [],
    )?;

    // Return path of DB for logging purposes
    Ok(db_path)
}

pub fn open_db() -> Result<Connection, rusqlite::Error> {
    let db_path = match data_local_dir() {
        Some(data_dir) => {
            let mut db_path = data_dir;
            db_path.push("lockbox_data");
            db_path
        }
        None => PathBuf::from("../lockbox_data"),
    };

    let conn = Connection::open(&db_path)?;

    Ok(conn)
}

pub fn check_passphrase_hash(passphrase: String, file: String) -> (bool, Option<String>) {
    let hash = match get_passphrase(file) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("[-] Unable to find passphrase: {e}");
            panic!();
        }
    };

    let expected_hash: PasswordHash = PasswordHash::new(&hash).unwrap();
    match Argon2::default().verify_password(passphrase.as_bytes(), &expected_hash) {
        Ok(_) => {
            return (true, Some(expected_hash.to_string()));
        }
        Err(_) => {
            return (false, None);
        }
    }
}

pub fn get_passphrase(file: String) -> Result<String, rusqlite::Error> {
    let conn = match open_db() {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("[-] Unable to open DB: {e}");
            panic!();
        }
    };

    let file = PathBuf::from(file);
    let file = file.file_name().unwrap().to_str().to_owned().unwrap();

    let row = conn.query_row(
        "select pch from passphrases where file = ?1",
        params![file],
        |row| row.get(0),
    );

    row
}

pub fn check_for_db() -> bool {
    let db_path = match data_local_dir() {
        Some(data_dir) => {
            let mut db_path = data_dir;
            db_path.push("lockbox_data");
            db_path
        }
        None => PathBuf::from("../lockbox_data"),
    };

    match Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(_) => true,
        Err(e) if e.sqlite_error_code().unwrap() == rusqlite::ErrorCode::CannotOpen => false,
        Err(_) => true,
    }
}

fn main() {
    let args = Args::parse();

    // If database does not exit already, create it
    if !check_for_db() {
        println!("[*] Creating lockbox database...");
        match create_db() {
            Ok(db_path) => {
                println!("[+] Databse created at {0:?}", db_path);
            }
            Err(e) => {
                eprintln!("[-] Failed at creating database: {e}");
                return;
            }
        }
    }

    match args.command {
        Command::Encrypt => encrypt_file(args.file, args.algorithm, args.passphrase),
        Command::Decrypt => decrypt_file(args.file, args.algorithm, args.passphrase),
    }
}
