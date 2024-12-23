use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use dirs::data_local_dir;
use log::{error, info};
use rusqlite::{params, Connection, OpenFlags};
use std::{ffi::OsString, path::PathBuf};

use file_encrypt::encryption_algos::{aes256_gcm, chacha20_poly};

#[derive(ValueEnum, Clone, Debug)]
enum Command {
    Encrypt,
    Decrypt,
}

#[derive(ValueEnum, Debug, Clone)]
enum Algorithm {
    AES256Gcm,
    Chacha20Poly,
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

    // Name of output file
    #[arg(short)]
    output: String,
}

fn create_db() -> Result<String> {
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

    let _ = conn.close();

    // Return path of DB for logging purposes
    let db_path: String = db_path.to_string_lossy().to_string();
    Ok(db_path)
}

fn open_db() -> Result<Connection> {
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

fn get_passphrase(file: String) -> Result<String> {
    let conn = open_db()?;

    let file = PathBuf::from(file);
    let file = file.file_name().unwrap().to_str().to_owned().unwrap();

    let row = conn.query_row(
        "select pch from passphrases where file = ?1",
        params![file],
        |row| row.get(0),
    );

    let _ = conn.close();

    Ok(row?)
}

fn store_entry(file: OsString, argon_pch: String) -> Result<()> {
    match open_db() {
        Ok(conn) => {
            conn.execute(
                "insert into passphrases (file, pch) values (?1, ?2)",
                params![file.to_string_lossy(), argon_pch],
            )?;

            let _ = conn.close();
        }
        Err(e) => {
            info!("[-] Unable to open database");
            error!("{e}");
            return Err(e);
        }
    }

    Ok(())
}

fn remove_entry(file: String) -> Result<()> {
    match open_db() {
        Ok(conn) => {
            conn.execute("delete from passphrases where file = ?1", params![file])?;

            let _ = conn.close();
        }
        Err(e) => {
            info!("[-] Unable to open database");
            error!("{e}");
            return Err(e);
        }
    }

    Ok(())
}

fn check_for_db() -> bool {
    let db_path = match data_local_dir() {
        Some(data_dir) => {
            let mut db_path = data_dir;
            db_path.push("lockbox_data");
            db_path
        }
        None => PathBuf::from("../lockbox_data"),
    };

    // Must specify flag so rusqlite does not create DB if it does not exist
    // Creation of DB is done elsewhere
    match Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(_) => true,
        Err(e) if e.sqlite_error_code().unwrap() == rusqlite::ErrorCode::CannotOpen => false,
        Err(e) => {
            info!("[-] Error while checking for existence of database");
            error!("{e}");
            panic!();
        }
    }
}

fn encryption(
    algorithm: Algorithm,
    file_path: String,
    passphrase: String,
    output_file: String,
) -> Result<(OsString, String)> {
    match algorithm {
        Algorithm::AES256Gcm => aes256_gcm::encrypt_file(file_path, passphrase, output_file),
        Algorithm::Chacha20Poly => chacha20_poly::encrypt_file(file_path, passphrase, output_file),
    }
}

fn decryption(
    algorithm: Algorithm,
    file_path: String,
    passphrase: String,
    output_file: String,
) -> Result<()> {
    let expected_hash = match get_passphrase(file_path.clone()) {
        Ok(expected_hash) => expected_hash,
        Err(e) => {
            info!("[-] Unable to get hash from database");
            return Err(e);
        }
    };

    match algorithm {
        Algorithm::AES256Gcm => {
            aes256_gcm::decrypt_file(file_path, passphrase, expected_hash, output_file)
        }
        Algorithm::Chacha20Poly => {
            chacha20_poly::decrypt_file(file_path, passphrase, expected_hash, output_file)
        }
    }
}

fn main() -> Result<()> {
    // Set RUST_LOG if not already set
    match std::env::var("RUST_LOG") {
        Ok(_) => {}
        Err(_) => {
            std::env::set_var("RUST_LOG", "info");
        }
    };
    env_logger::init();

    let args = Args::parse();

    // If database does not exit already, create it
    if !check_for_db() {
        info!("[*] Creating lockbox database...");
        match create_db() {
            Ok(db_path) => {
                info!("[+] Databse created at {0:?}", db_path);
            }
            Err(e) => {
                info!("[-] Failed at creating database");
                error!("Database error: {e}");
                return Err(anyhow!("Database error"));
            }
        }
    }

    match args.command {
        Command::Encrypt => {
            info!("[*] Encrypting file...");
            let (new_file, argon_pch) =
                match encryption(args.algorithm, args.file, args.passphrase, args.output) {
                    Ok((new_file, argon_pch)) => (new_file, argon_pch),
                    Err(e) => {
                        info!("[-] Unable to encrypt file");
                        error!("{e}");
                        return Err(anyhow!(e));
                    }
                };
            info!("[+] File encrypted at {0:?}", new_file);

            info!("[*] Storing passphrase has in database...");
            store_entry(new_file, argon_pch)?;
            info!("[+] Passhprase stored");
        }
        Command::Decrypt => {
            info!("[*] Decrypting file...");
            match decryption(
                args.algorithm,
                args.file.clone(),
                args.passphrase,
                args.output,
            ) {
                Ok(()) => {}
                Err(e) => {
                    info!("[-] Failed to decrypt file");
                    error!("{e}");
                    return Err(e);
                }
            }
            info!("[+] File decrypted");

            info!("[*] Removing entry from database...");
            remove_entry(args.file)?;
            info!("[+] Entry removed");
        }
    }

    Ok(())
}
