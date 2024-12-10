use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use dirs::data_local_dir;
use rusqlite::{params, Connection, OpenFlags};
use std::{ffi::OsString, path::PathBuf};

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

pub fn create_db() -> Result<String> {
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
    let db_path: String = db_path.to_string_lossy().to_string();
    Ok(db_path)
}

pub fn open_db() -> Result<Connection> {
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

pub fn get_passphrase(file: String) -> Result<String> {
    let conn = open_db()?;

    let file = PathBuf::from(file);
    let file = file.file_name().unwrap().to_str().to_owned().unwrap();

    let row = conn.query_row(
        "select pch from passphrases where file = ?1",
        params![file],
        |row| row.get(0),
    );

    Ok(row?)
}

pub fn store_entry(file: OsString, argon_pch: String) -> Result<()> {
    match open_db() {
        Ok(conn) => {
            conn.execute(
                "insert into passphrases (file, pch) values (?1, ?2)",
                params![file.to_string_lossy(), argon_pch],
            )?;
        }
        Err(e) => {
            eprintln!("[-] Unable to open database: {e}");
            return Err(e);
        }
    }

    Ok(())
}

pub fn remove_entry(file: String) -> Result<()> {
    match open_db() {
        Ok(conn) => {
            conn.execute("delete from passphrases where file = ?1", params![file])?;
        }
        Err(e) => {
            eprintln!("[-] Unable to open database: {}", e);
            return Err(e);
        }
    }

    Ok(())
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
        Err(e) => {
            eprintln!("[-] Error while checking for existence of database: {e}");
            panic!();
        }
    }
}

fn main() -> Result<()> {
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
                return Err(anyhow!("Database error"));
            }
        }
    }

    match args.command {
        Command::Encrypt => {
            let (file_path, argon_pch) = match aes256_gcm::encrypt_file(args.file, args.passphrase)
            {
                Ok((path, argon_pch)) => {
                    println!("[+] Encrypted file written to {path:?}");
                    (path, argon_pch)
                }
                Err(e) => {
                    eprintln!("[-] Error while encrypting: {e}");
                    return Err(anyhow!("Encryption error"));
                }
            };
            match store_entry(file_path, argon_pch) {
                Ok(_) => {
                    println!("[+] Successfully stored file/passphrase pair in database");
                }
                Err(e) => {
                    eprintln!("[-] Error while storing file/passphrase: {e}");
                    panic!();
                }
            }
        }
        Command::Decrypt => {
            let expected_hash = match get_passphrase(args.file.clone()) {
                Ok(expected_hash) => expected_hash,
                Err(e) => {
                    eprintln!("[-] Unable to get hash from database: {e}");
                    return Err(anyhow!("Hash retrieval error"));
                }
            };
            match aes256_gcm::decrypt_file(args.file.clone(), args.passphrase, expected_hash) {
                Ok(_) => {
                    println!("[+] {} has been successfully decrypted", args.file.clone());
                }
                Err(e) => {
                    eprintln!("[-] Unable to decrypt file: {e}");
                    return Err(anyhow!("Decryption error"));
                }
            }
            match remove_entry(args.file) {
                Ok(_) => {
                    println!("[+] Used up file/passphrase pair removed from database");
                }
                Err(e) => {
                    eprintln!("[-] Unable to remove file/passphrase pair from database: {e}");
                    panic!();
                }
            }
        }
    }

    Ok(())
}
