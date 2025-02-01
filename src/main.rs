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

const E_BIT_SELECTION_TABLE: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const P_TABLE: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const PC_1_TABLE: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC_2_TABLE: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const S1_TABLE: [u64; 64] = [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11,
    9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5,
    11, 3, 14, 10, 0, 6, 13,
];

const S2_TABLE: [u64; 64] = [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10,
    6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2,
    11, 6, 7, 12, 0, 5, 14, 9,
];

const S3_TABLE: [u64; 64] = [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14,
    12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7,
    4, 15, 14, 3, 11, 5, 2, 12,
];

const S4_TABLE: [u64; 64] = [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12,
    1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8,
    9, 4, 5, 11, 12, 7, 2, 14,
];

const S5_TABLE: [u64; 64] = [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10,
    3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13,
    6, 15, 0, 9, 10, 4, 5, 3,
];

const S6_TABLE: [u64; 64] = [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14,
    0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10,
    11, 14, 1, 7, 6, 0, 8, 13,
];

const S7_TABLE: [u64; 64] = [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12,
    2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7,
    9, 5, 0, 15, 14, 2, 3, 12,
];

const S8_TABLE: [u64; 64] = [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11,
    0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13,
    15, 12, 9, 0, 3, 5, 6, 11,
];

fn check_string_is_ascii_hexdigit(s: String) -> bool {
    return s.chars().all(|c| c.is_ascii_hexdigit());
}

fn print_u64(label: &str, block: u64) {
    println!("{}{}", label, format!("{:064b}", block));
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
const LEFT_SPLIT_KEY_PAD_56: u64 = 72057593769492480;
// let right_split_key_pad: u64 = u64::from_str_radix(
//     &"0000000000000000000000000000000000001111111111111111111111111111",
//     2,
// )
// .unwrap();
const RIGHT_SPLIT_KEY_PAD_56: u64 = 268435455;
fn split_permutated_key_56(key_56: u64) -> (u64, u64) {
    let left_split_block: u64 = (key_56 & LEFT_SPLIT_KEY_PAD_56) >> 28;
    let right_split_block: u64 = key_56 & RIGHT_SPLIT_KEY_PAD_56;
    return (left_split_block, right_split_block);
}

// 1111111111111111111111111111111100000000000000000000000000000000
const LEFT_SPLIT_KEY_PAD_64: u64 = 18446744069414584320;
// 0000000000000000000000000000000011111111111111111111111111111111
const RIGHT_SPLIT_KEY_PAD_64: u64 = 4294967295;
fn split_permutated_key_64(key_64: u64) -> (u64, u64) {
    let left_split_block: u64 = (key_64 & LEFT_SPLIT_KEY_PAD_64) >> 32;
    let right_split_block: u64 = key_64 & RIGHT_SPLIT_KEY_PAD_64;
    return (left_split_block, right_split_block);
}

fn merge_32_block_in_reverse_order(left_64: u64, right_64: u64) -> u64 {
    return (right_64 << 32) + left_64;
}
// 0000 000000 000000 111111 000000 000000 000000 000000 000000 000000 000000
const FIRST_6BIT_IN_48: u64 = 277076930199552;
// 0000 000000 000000 000000 111111 000000 000000 000000 000000 000000 000000
const SECOND_6BIT_IN_48: u64 = 4329327034368;
// 0000 000000 000000 000000 000000 111111 000000 000000 000000 000000 000000
const THIRD_6BIT_IN_48: u64 = 67645734912;
// 0000 000000 000000 000000 000000 000000 111111 000000 000000 000000 000000
const FORTH_6BIT_IN_48: u64 = 1056964608;
// 0000 000000 000000 000000 000000 000000 000000 111111 000000 000000 000000
const FIFTH_6BIT_IN_48: u64 = 16515072;
// 0000 000000 000000 000000 000000 000000 000000 000000 111111 000000 000000
const SIXTH_6BIT_IN_48: u64 = 258048;
// 0000 000000 000000 000000 000000 000000 000000 000000 000000 111111 000000
const SEVENTH_6BIT_IN_48: u64 = 4032;
// 0000 000000 000000 000000 000000 000000 000000 000000 000000 000000 111111
const EIGHTH_6BIT_IN_48: u64 = 63;

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

fn get_pc2_permuted_keys(pc_1_keys: [(u64, u64); 16]) -> [u64; 16] {
    let mut pc_2_keys: [u64; 16] = [0; 16];
    for i in 0..16 {
        let (left, right) = pc_1_keys[i];
        let left_shifted = left << 28;
        let combined_block = left_shifted | right;
        let key = get_permutated_block(combined_block, PC_2_TABLE, 8);
        pc_2_keys[i] = key;
        println!("K{} in 64 - [{}] ", i + 1, format!("{:064b}", key));
        println!("K{} in 48 - [{}] ", i + 1, format!("{:048b}", key));
    }
    return pc_2_keys;
}

fn get_s_box_row_col(bit_6_block: u64) -> usize {
    let first_bit = (bit_6_block >> 4) & 2;
    let last_bit = bit_6_block & 1;
    let middle_4_bits = (bit_6_block >> 1) & 15;
    let row = first_bit | last_bit;
    let col = middle_4_bits;
    return (row * 16 + col) as usize;
}

fn some_function(block_32: u64, key: u64) -> u64 {
    let expanded_block = get_permutated_block(block_32, E_BIT_SELECTION_TABLE, 32);
    println! {"ER0:\n{}", format!("{:064b}", expanded_block)};
    println! {"K1:\n{}", format!("{:064b}", key)};
    let key_xor_expanded_block = key ^ expanded_block;
    println! {"K1+E(R0):\n{}", format!("{:064b}", key_xor_expanded_block)};

    let b1 = (key_xor_expanded_block & FIRST_6BIT_IN_48) >> 42;
    let b1_sub = S1_TABLE[get_s_box_row_col(b1)];

    let b2 = (key_xor_expanded_block & SECOND_6BIT_IN_48) >> 36;
    let b2_sub = S2_TABLE[get_s_box_row_col(b2)];
    print_u64("B2\n", b2);

    let b3 = (key_xor_expanded_block & THIRD_6BIT_IN_48) >> 30;
    let b3_sub = S3_TABLE[get_s_box_row_col(b3)];
    print_u64("B3\n", b3);

    let b4 = (key_xor_expanded_block & FORTH_6BIT_IN_48) >> 24;
    let b4_sub = S4_TABLE[get_s_box_row_col(b4)];
    print_u64("B4\n", b4);

    let b5 = (key_xor_expanded_block & FIFTH_6BIT_IN_48) >> 18;
    let b5_sub = S5_TABLE[get_s_box_row_col(b5)];
    print_u64("B5\n", b5);

    let b6: u64 = (key_xor_expanded_block & SIXTH_6BIT_IN_48) >> 12;
    let b6_sub = S6_TABLE[get_s_box_row_col(b6)];
    print_u64("B6\n", b6);

    let b7 = (key_xor_expanded_block & SEVENTH_6BIT_IN_48) >> 6;
    let b7_sub = S7_TABLE[get_s_box_row_col(b7)];
    print_u64("B7\n", b7);

    let b8: u64 = key_xor_expanded_block & EIGHTH_6BIT_IN_48;
    let b8_sub = S8_TABLE[get_s_box_row_col(b8)];
    print_u64("B8\n", b8);

    let sub = (b1_sub << 28)
        | (b2_sub << 24)
        | (b3_sub << 20)
        | (b4_sub << 16)
        | (b5_sub << 12)
        | (b6_sub << 8)
        | (b7_sub << 4)
        | (b8_sub);
    // Expecting 01011100100000101011010110010111
    println!("SUB: {}", sub);
    print_u64("SUB: ", sub);
    let permutated_block_after_p_table = get_permutated_block(sub, P_TABLE, 32);
    print_u64(
        "permutated_block_after_p_table: ",
        permutated_block_after_p_table,
    );
    return permutated_block_after_p_table;
}

fn run_16_rounds(plaintext_after_init_permutation_block: u64, permuted_pc2_keys: [u64; 16]) -> u64 {
    let (left_split, right_split) = split_permutated_key_64(plaintext_after_init_permutation_block);
    println!("left_split - [{}]", format!("{:064b}", left_split));
    println!("right_split - [{}]", format!("{:064b}", right_split));

    let mut prev_left_permuted_block = left_split;
    let mut prev_right_permutated_block = right_split;
    let mut current_left_permutated_block = 0;
    println!("L1:{}", format!("{:064b}", current_left_permutated_block));
    let mut current_right_permutated_block = 0;

    for index in 0..16 {
        current_left_permutated_block = prev_right_permutated_block;
        current_right_permutated_block = prev_left_permuted_block
            ^ some_function(prev_right_permutated_block, permuted_pc2_keys[index]);
        prev_left_permuted_block = current_left_permutated_block;
        prev_right_permutated_block = current_right_permutated_block;
    }

    print_u64("L16: ", current_left_permutated_block);
    print_u64("R16: ", current_right_permutated_block);

    return merge_32_block_in_reverse_order(
        current_left_permutated_block,
        current_right_permutated_block,
    );
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

    let (left, right) = split_permutated_key_56(permutated_key_block);
    println!("C{} - LEFT [{}] ", 0, format!("{:064b}", left));
    println!("D{} - RIGHT[{}]", 0, format!("{:064b}", right));

    let permuted_pc1_keys = get_pc1_shifted_keys(left, right);
    for i in 0..16 {
        let (left, right) = permuted_pc1_keys[i];
        println!("C{} - LEFT [{}] ", i + 1, format!("{:064b}", left));
        println!("D{} - RIGHT[{}]", i + 1, format!("{:064b}", right));
    }
    let permuted_pc2_keys = get_pc2_permuted_keys(permuted_pc1_keys);
    let (left_split, right_split) = split_permutated_key_64(plaintext_after_init_permutation_block);
    println!("left_split - [{}]", format!("{:064b}", left_split));
    println!("right_split - [{}]", format!("{:064b}", right_split));

    let reversed_block = run_16_rounds(plaintext_after_init_permutation_block, permuted_pc2_keys);
    let final_permutated_block = get_permutated_block(reversed_block, INVERSE_PERMUTATION_TABLE, 0);
    print_u64("final permutation block: ", final_permutated_block);
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
        des_encrypt(plaintext_blocks[index].to_string(), key_input.clone());
    }
}
