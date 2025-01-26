use clap::Parser;

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

const INITIAL_PERMUTATION_TABLE: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const INVERSE_PERMUTATION_TABLE: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

fn get_permutated_block(plaintext_u64_block: u64, permutation_table: [u8; 64]) -> u64 {
    let mut permutated_block: u64 = 0;
    for index in 0..64 {
        let target_bit_index = permutation_table[index] - 1;
        let bit = plaintext_u64_block >> target_bit_index & 1;
        let new_block_with_bit = bit << index;
        permutated_block |= new_block_with_bit;
    }
    return permutated_block;
}

fn main() {
    let args = Args::parse();
    let plaintext_input = args.plaintext;
    let key_input = args.key;

    plaintext_input.chars().for_each(|c| {
        if !c.is_ascii_hexdigit() {
            panic!("is not hex digit");
        }
    });

    key_input.chars().for_each(|c| {
        if !c.is_ascii_hexdigit() {
            panic!("is not hex digit");
        }
    });

    let plaintext_u64_block = u64::from_str_radix(&plaintext_input, 16).ok().unwrap();
    println! {"plaintext binary:\n{}", format!("{:064b}", plaintext_u64_block)};
    let permutated_block = get_permutated_block(plaintext_u64_block, INITIAL_PERMUTATION_TABLE);
    println! {"permutated binary\n{}", format!("{:064b}", permutated_block)};
    println! {"permutated hex\n{}", format!("{:X}", permutated_block)};
}
