mod binary_pads;
mod encrypt;
mod logging;
mod permutation_tables;
use clap::Parser;
use encrypt::{des_decrypt, des_encrypt};

/// Simple program to encrypt plaintext, and then show processes and, decrpyt to validate.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// 64 bit plaintext in hexdigit (16 hex digits)
    #[arg(short, long)]
    plaintext: String,

    /// key for encryption and decryption in hexdigit
    #[arg(short, long)]
    key: String,
}

fn check_string_is_ascii_hexdigit(s: String) -> bool {
    return s.chars().all(|c| c.is_ascii_hexdigit());
}

fn main() {
    let args = Args::parse();
    let plaintext_input = args.plaintext;
    let key_input = args.key;

    if !check_string_is_ascii_hexdigit(plaintext_input.clone()) {
        panic!("plaintext is not hexdigit");
    }
    if !check_string_is_ascii_hexdigit(key_input.clone()) {
        panic!("key is not hexdigit");
    }

    let plaintext_blocks = plaintext_input
        .as_bytes()
        .chunks(16)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap();

    for index in 0..plaintext_blocks.len() {
        let plaintext = format!("{:0<16}", plaintext_blocks[index]);
        let ciphertext = des_encrypt(plaintext.to_string(), key_input.clone());
        let ciphertext_string: String = format!("{:016x}", ciphertext);
        println!("✅ ciphertext: {}\n", ciphertext_string);

        let decrypted = des_decrypt(ciphertext_string.clone(), key_input.clone());
        let decrypted_string: String = format!("{:016x}", decrypted);
        println!("✅ decrypted: {}", decrypted_string);
    }
}
