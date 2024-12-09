use clap::{Parser, ValueEnum};
use dirs::data_local_dir;
use rusqlite::{params, Connection, OpenFlags};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use encryption_algos::aes256_gcm;

mod encryption_algos;
mod hash_algos;

#[derive(ValueEnum, Clone, Debug)]
enum Command {
    Encrypt,
    Decrypt,
}

#[derive(ValueEnum, Debug, Clone)]
enum Algorithm {
    AES256Gcm,
}

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    // Command to run: Encryption, Decryption
    #[arg(value_enum)]
    command: Command,

    // File name
    file: String,

    // Cryptographic algorithm to use
    #[arg(value_enum)]
    algorithm: Algorithm,

    // Passphrase to use for key derivation
    passphrase: String,
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

pub fn store_entry(file: OsString, argon_pch: String) {
    match open_db() {
        Ok(conn) => {
            conn.execute(
                "insert into passphrases (file, pch) values (?1, ?2)",
                params![file.to_string_lossy(), argon_pch],
            )
            .unwrap();
        }
        Err(e) => {
            eprintln!("[-] Unable to open database: {}", e);
            return;
        }
    }
}

pub fn remove_entry(file: String) {
    match open_db() {
        Ok(conn) => {
            conn.execute("delete from passphrases where file = ?1", params![file])
                .unwrap();
        }
        Err(e) => {
            eprintln!("[-] Unable to open database: {}", e);
            return;
        }
    }
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
        Command::Encrypt => {
            let (file_path, argon_pch) = aes256_gcm::encrypt_file(args.file, args.passphrase);
            store_entry(file_path, argon_pch);
        }
        Command::Decrypt => {
            let expected_hash = get_passphrase(args.file.clone()).unwrap();
            aes256_gcm::decrypt_file(args.file.clone(), args.passphrase, expected_hash);
            remove_entry(args.file);
        }
    }
}
