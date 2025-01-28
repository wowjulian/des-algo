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

// const INVERSE_PERMUTATION_TABLE: [u8; 64] = [
//     40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
//     37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
//     34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
// ];

const PC_1_TABLE: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC_2_TABLE: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

fn check_string_is_ascii_hexdigit(s: String) -> bool {
    return s.chars().all(|c| c.is_ascii_hexdigit());
}

fn get_permutated_block<const N: usize>(
    u64_block: u64,
    permutation_table: [u8; N],
    // u64_block empty bit count from left
    right_shift_offset: u8,
) -> u64 {
    let mut permutated_block: u64 = 0;
    for index in 0..N {
        let target_bit_index: u8 = permutation_table[index] - 1;
        let right_shift: u8 = 63 - target_bit_index;
        let bit = (u64_block >> right_shift - right_shift_offset) & 1;
        let new_block_with_bit: u64 = bit << (63 - index - (64 - N));
        permutated_block |= new_block_with_bit;
    }
    return permutated_block;
}

// let left_split_key_pad: u64 = u64::from_str_radix(
//     &"0000000011111111111111111111111111110000000000000000000000000000",
//     2,
// )
// .unwrap();
const LEFT_SPLIT_KEY_PAD: u64 = 72057593769492480;
// let right_split_key_pad: u64 = u64::from_str_radix(
//     &"0000000000000000000000000000000000001111111111111111111111111111",
//     2,
// )
// .unwrap();
const RIGHT_SPLIT_KEY_PAD: u64 = 268435455;
fn split_permutated_key(key: u64, chunk_size: usize) -> (u64, u64) {
    let left_split_block: u64 = (key & LEFT_SPLIT_KEY_PAD) >> chunk_size;
    let right_split_block: u64 = key & RIGHT_SPLIT_KEY_PAD;
    return (left_split_block, right_split_block);
}

const BIT_PAD_28: u64 = 268435455;
fn left_shift_28_bit_pair(left_key: u64, right_key: u64, shift_size: usize) -> (u64, u64) {
    let mut mutated_left_key = left_key;
    let mut mutated_right_key = right_key;

    for _index in 0..shift_size {
        let left_key_left_most_bit = (1 << 27) & mutated_left_key;
        let right_key_left_most_bit = (1 << 27) & mutated_right_key;

        let left_key_bit = (left_key_left_most_bit >> 27) & 1;
        let right_key_bit = (right_key_left_most_bit >> 27) & 1;
        mutated_left_key = ((mutated_left_key << 1) | left_key_bit) & BIT_PAD_28;
        mutated_right_key = ((mutated_right_key << 1) | right_key_bit) & BIT_PAD_28;
    }
    return (mutated_left_key, mutated_right_key);
}

const PC1_SHIGT_SIZES: [usize; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
fn get_pc1_shifted_keys(left_key: u64, right_key: u64) -> [(u64, u64); 16] {
    let mut pairs: [(u64, u64); 16] = [(0, 0); 16];
    let mut prev_left = left_key;
    let mut prev_right = right_key;
    for i in 0..16 {
        pairs[i] = left_shift_28_bit_pair(prev_left, prev_right, PC1_SHIGT_SIZES[i]);
        prev_left = pairs[i].0;
        prev_right = pairs[i].1;
    }
    return pairs;
}

fn get_pc2_permuted_keys(pc_1_keys: [(u64, u64); 16]) {
    for i in 0..16 {
        let (left, right) = pc_1_keys[i];
        let left_shifted = left << 28;
        let combined_block = left_shifted | right;
        let key = get_permutated_block(combined_block, PC_2_TABLE, 8);
        println!("K{} in 64 - [{}] ", i + 1, format!("{:064b}", key));
        println!("K{} in 48 - [{}] ", i + 1, format!("{:048b}", key));
    }
}

fn des_encrypt(plaintext_input: String, key_input: String) {
    let plaintext_u64_block = u64::from_str_radix(&plaintext_input, 16).ok().unwrap();
    println! {"plaintext binary:\n{}", format!("{:064b}", plaintext_u64_block)};
    let plaintext_after_init_permutation_block =
        get_permutated_block(plaintext_u64_block, INITIAL_PERMUTATION_TABLE, 0);
    // expected to be 1100110000000000110011001111111111110000101010101111000010101010
    println!(
        "plaintext after initaial permutation:\n{}",
        format!("{:064b}", plaintext_after_init_permutation_block)
    );

    let key_block: u64 = u64::from_str_radix(&key_input, 16).ok().unwrap();
    let permutated_key_block: u64 = get_permutated_block(key_block, PC_1_TABLE, 0);
    // expected to be 0000000011110000110011001010101011110101010101100110011110001111
    println! {"permutated key binary is (64):\n{}", format!("{:064b}", permutated_key_block)};

    let (left, right) = split_permutated_key(permutated_key_block, 28);
    println!("C{} - LEFT [{}] ", 0, format!("{:064b}", left));
    println!("D{} - RIGHT[{}]", 0, format!("{:064b}", right));

    let permuted_pc1_keys = get_pc1_shifted_keys(left, right);
    for i in 0..16 {
        let (left, right) = permuted_pc1_keys[i];
        println!("C{} - LEFT [{}] ", i + 1, format!("{:064b}", left));
        println!("D{} - RIGHT[{}]", i + 1, format!("{:064b}", right));
    }

    let permuted_pc2_keys = get_pc2_permuted_keys(permuted_pc1_keys);
}

fn main() {
    let args = Args::parse();
    let plaintext_input = args.plaintext;
    let key_input = args.key;

    if !check_string_is_ascii_hexdigit(plaintext_input.clone()) {
        panic!("plaintext is not hexdigit");
    }
    if plaintext_input.len() % 16 != 0 {
        panic!(
            "plaintext is not divisible by 16 hexdigit, 64 bits. Your plaintext length: {}",
            plaintext_input.len()
        );
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
        let plaintext_input_block = plaintext_blocks[index];
        println!("{}", plaintext_input_block);
        des_encrypt(plaintext_input_block.to_string(), key_input.clone());
    }
}
