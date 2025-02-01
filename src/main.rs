mod binary_pads;
mod tables;

use binary_pads::{
    BIT_PAD_28, EIGHTH_6BIT_IN_48, FIFTH_6BIT_IN_48, FIRST_6BIT_IN_48, FORTH_6BIT_IN_48,
    LEFT_SPLIT_KEY_PAD_56, LEFT_SPLIT_KEY_PAD_64, RIGHT_SPLIT_KEY_PAD_56, RIGHT_SPLIT_KEY_PAD_64,
    SECOND_6BIT_IN_48, SEVENTH_6BIT_IN_48, SIXTH_6BIT_IN_48, THIRD_6BIT_IN_48,
};
use clap::Parser;
use tables::{
    E_BIT_SELECTION_TABLE, INITIAL_PERMUTATION_TABLE, INVERSE_PERMUTATION_TABLE, PC1_SHIFT_SIZES,
    PC_1_TABLE, PC_2_TABLE, P_TABLE, S1_TABLE, S2_TABLE, S3_TABLE, S4_TABLE, S5_TABLE, S6_TABLE,
    S7_TABLE, S8_TABLE,
};

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

fn print_u64(label: &str, block: u64) {
    // println!("{}{}", label, format!("{:064b}", block));
    println!("{}{}", label, format!("{:x}", block));
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
        let new_block_with_bit: u64 = bit << (N - index - 1);
        permutated_block |= new_block_with_bit;
    }
    return permutated_block;
}

fn split_permutated_key_56(key_56: u64) -> (u64, u64) {
    let left_split_block: u64 = (key_56 & LEFT_SPLIT_KEY_PAD_56) >> 28;
    let right_split_block: u64 = key_56 & RIGHT_SPLIT_KEY_PAD_56;
    return (left_split_block, right_split_block);
}

fn split_permutated_key_64(key_64: u64) -> (u64, u64) {
    let left_split_block: u64 = (key_64 & LEFT_SPLIT_KEY_PAD_64) >> 32;
    let right_split_block: u64 = key_64 & RIGHT_SPLIT_KEY_PAD_64;
    return (left_split_block, right_split_block);
}

fn merge_32_block_in_reverse_order(left_64: u64, right_64: u64) -> u64 {
    return (right_64 << 32) + left_64;
}

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

fn get_pc1_shifted_keys(left_key: u64, right_key: u64) -> [(u64, u64); 16] {
    let mut pairs: [(u64, u64); 16] = [(0, 0); 16];
    let mut prev_left = left_key;
    let mut prev_right = right_key;
    for i in 0..16 {
        pairs[i] = left_shift_28_bit_pair(prev_left, prev_right, PC1_SHIFT_SIZES[i]);
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
        print_u64(&format!("K[{}]: ", i + 1), key);
    }
    return pc_2_keys;
}

fn get_s_box_index(bit_6_block: u64) -> usize {
    let first_bit = (bit_6_block >> 4) & 2;
    let last_bit = bit_6_block & 1;
    let middle_4_bits = (bit_6_block >> 1) & 15;
    let row = first_bit | last_bit;
    let col = middle_4_bits;
    return (row * 16 + col) as usize;
}

fn f_function(block_32: u64, key: u64) -> u64 {
    let expanded_block = get_permutated_block(block_32, E_BIT_SELECTION_TABLE, 32);
    let key_xor_expanded_block = key ^ expanded_block;
    let b1 = (key_xor_expanded_block & FIRST_6BIT_IN_48) >> 42;
    let b1_sub = S1_TABLE[get_s_box_index(b1)];
    let b2 = (key_xor_expanded_block & SECOND_6BIT_IN_48) >> 36;
    let b2_sub = S2_TABLE[get_s_box_index(b2)];
    let b3 = (key_xor_expanded_block & THIRD_6BIT_IN_48) >> 30;
    let b3_sub = S3_TABLE[get_s_box_index(b3)];
    let b4 = (key_xor_expanded_block & FORTH_6BIT_IN_48) >> 24;
    let b4_sub = S4_TABLE[get_s_box_index(b4)];
    let b5 = (key_xor_expanded_block & FIFTH_6BIT_IN_48) >> 18;
    let b5_sub = S5_TABLE[get_s_box_index(b5)];
    let b6: u64 = (key_xor_expanded_block & SIXTH_6BIT_IN_48) >> 12;
    let b6_sub = S6_TABLE[get_s_box_index(b6)];
    let b7 = (key_xor_expanded_block & SEVENTH_6BIT_IN_48) >> 6;
    let b7_sub = S7_TABLE[get_s_box_index(b7)];
    let b8: u64 = key_xor_expanded_block & EIGHTH_6BIT_IN_48;
    let b8_sub = S8_TABLE[get_s_box_index(b8)];
    let sub = (b1_sub << 28)
        | (b2_sub << 24)
        | (b3_sub << 20)
        | (b4_sub << 16)
        | (b5_sub << 12)
        | (b6_sub << 8)
        | (b7_sub << 4)
        | (b8_sub);
    let permutated_block_after_p_table = get_permutated_block(sub, P_TABLE, 32);
    return permutated_block_after_p_table;
}

fn run_16_rounds(plaintext_after_init_permutation_block: u64, permuted_pc2_keys: [u64; 16]) -> u64 {
    let (left_split, right_split) = split_permutated_key_64(plaintext_after_init_permutation_block);
    let mut prev_left_permuted_block = left_split;
    let mut prev_right_permutated_block = right_split;
    let mut current_left_permutated_block = 0;
    let mut current_right_permutated_block = 0;

    for index in 0..16 {
        current_left_permutated_block = prev_right_permutated_block;
        current_right_permutated_block = prev_left_permuted_block
            ^ f_function(prev_right_permutated_block, permuted_pc2_keys[index]);
        prev_left_permuted_block = current_left_permutated_block;
        prev_right_permutated_block = current_right_permutated_block;
        let non_zero_index = index + 1;
        print_u64(
            &format!("L[{non_zero_index}]: "),
            current_left_permutated_block,
        );
        print_u64(
            &format!("R[{non_zero_index}]: "),
            current_right_permutated_block,
        );
    }

    return merge_32_block_in_reverse_order(
        current_left_permutated_block,
        current_right_permutated_block,
    );
}

fn des_encrypt(plaintext_input: String, key_input: String) {
    let plaintext_u64_block = u64::from_str_radix(&plaintext_input, 16).ok().unwrap();
    print_u64("plaintext: ", plaintext_u64_block);
    let plaintext_after_init_permutation_block =
        get_permutated_block(plaintext_u64_block, INITIAL_PERMUTATION_TABLE, 0);
    print_u64(
        "plaintext after initaial permutation: ",
        plaintext_after_init_permutation_block,
    );
    let key_block: u64 = u64::from_str_radix(&key_input, 16).ok().unwrap();
    let permutated_key_block: u64 = get_permutated_block(key_block, PC_1_TABLE, 0);
    print_u64("permutated key binary: ", permutated_key_block);

    let (left, right) = split_permutated_key_56(permutated_key_block);
    let permuted_pc1_keys = get_pc1_shifted_keys(left, right);
    for i in 0..16 {
        let (left, right) = permuted_pc1_keys[i];
        print_u64(&format!("C[{}]: ", i + 1), left);
        print_u64(&format!("D[{}]: ", i + 1), right);
    }
    let permuted_pc2_keys = get_pc2_permuted_keys(permuted_pc1_keys);
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
