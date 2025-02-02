use crate::{binary_pads, permutation_tables};
use tabled::{Table, Tabled};

#[derive(Tabled)]
struct DesLog {
    round: String,
    subkey: String,
    l: String,
    r: String,
    value: String,
}

use binary_pads::{
    BIT_PAD_28, EIGHTH_6BIT_IN_48, FIFTH_6BIT_IN_48, FIRST_6BIT_IN_48, FORTH_6BIT_IN_48,
    LEFT_SPLIT_KEY_PAD_56, LEFT_SPLIT_KEY_PAD_64, RIGHT_SPLIT_KEY_PAD_56, RIGHT_SPLIT_KEY_PAD_64,
    SECOND_6BIT_IN_48, SEVENTH_6BIT_IN_48, SIXTH_6BIT_IN_48, THIRD_6BIT_IN_48,
};
use permutation_tables::{
    E_BIT_SELECTION_TABLE, INITIAL_PERMUTATION_TABLE, INVERSE_PERMUTATION_TABLE, PC1_SHIFT_SIZES,
    PC_1_TABLE, PC_2_TABLE, P_TABLE, S1_TABLE, S2_TABLE, S3_TABLE, S4_TABLE, S5_TABLE, S6_TABLE,
    S7_TABLE, S8_TABLE,
};

pub fn print_u64(label: &str, block: u64) {
    // println!("{}{}", label, format!("{:064b}", block));
    println!("{}{}", label, format!("{:016x}", block));
}

pub fn get_permutated_block<const N: usize>(
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

pub fn split_permutated_key_56(key_56: u64) -> (u64, u64) {
    let left_split_block: u64 = (key_56 & LEFT_SPLIT_KEY_PAD_56) >> 28;
    let right_split_block: u64 = key_56 & RIGHT_SPLIT_KEY_PAD_56;
    return (left_split_block, right_split_block);
}

pub fn split_permutated_key_64(key_64: u64) -> (u64, u64) {
    let left_split_block: u64 = (key_64 & LEFT_SPLIT_KEY_PAD_64) >> 32;
    let right_split_block: u64 = key_64 & RIGHT_SPLIT_KEY_PAD_64;
    return (left_split_block, right_split_block);
}

pub fn merge_32_block_in_reverse_order(left_64: u64, right_64: u64) -> u64 {
    return (right_64 << 32) + left_64;
}

pub fn left_shift_28_bit_pair(left_key: u64, right_key: u64, shift_size: usize) -> (u64, u64) {
    let mut mutated_left_key = left_key;
    let mut mutated_right_key: u64 = right_key;
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

pub fn get_pc1_shifted_keys(left_key: u64, right_key: u64) -> [(u64, u64); 16] {
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

pub fn get_pc2_permuted_keys(pc_1_keys: [(u64, u64); 16]) -> [u64; 16] {
    let mut pc_2_keys: [u64; 16] = [0; 16];
    for i in 0..16 {
        let (left, right) = pc_1_keys[i];
        let left_shifted = left << 28;
        let combined_block = left_shifted | right;
        let key = get_permutated_block(combined_block, PC_2_TABLE, 8);
        pc_2_keys[i] = key;
    }
    return pc_2_keys;
}

pub fn get_s_box_index(bit_6_block: u64) -> usize {
    let first_bit = (bit_6_block >> 4) & 2;
    let last_bit = bit_6_block & 1;
    let middle_4_bits = (bit_6_block >> 1) & 15;
    let row = first_bit | last_bit;
    let col = middle_4_bits;
    return (row * 16 + col) as usize;
}

pub fn f_function(block_32: u64, key: u64) -> u64 {
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

fn run_16_rounds(
    plaintext_after_init_permutation_block: u64,
    subkeys: [u64; 16],
    des_log_table: &mut Vec<DesLog>,
) -> u64 {
    let (left_split, right_split) = split_permutated_key_64(plaintext_after_init_permutation_block);
    let mut prev_left_block = left_split;
    let mut prev_right_block = right_split;
    let mut left_block = 0;
    let mut right_block = 0;
    for index in 0..16 {
        left_block = prev_right_block;
        right_block = prev_left_block ^ f_function(prev_right_block, subkeys[index]);
        prev_left_block = left_block;
        prev_right_block = right_block;
        populate_round_log_table(
            des_log_table,
            index + 1,
            subkeys[index],
            left_block,
            right_block,
        );
    }
    return merge_32_block_in_reverse_order(left_block, right_block);
}

fn get_subkeys(key_input: String) -> [u64; 16] {
    let key_block: u64 = u64::from_str_radix(&key_input, 16).ok().unwrap();
    let permutated_key_block: u64 = get_permutated_block(key_block, PC_1_TABLE, 0);
    print_u64("permutated key binary: ", permutated_key_block);
    let (left, right) = split_permutated_key_56(permutated_key_block);
    let permuted_pc1_keys = get_pc1_shifted_keys(left, right);
    return get_pc2_permuted_keys(permuted_pc1_keys);
}

fn populate_ip_log_table(
    des_log_table: &mut Vec<DesLog>,
    plaintext_after_init_permutation_block: u64,
) {
    let (left, right) = split_permutated_key_64(plaintext_after_init_permutation_block);
    let left_ip = format!("{:016x}", left);
    let right_ip = format!("{:016x}", right);
    des_log_table.push(DesLog {
        round: "IP".to_string(),
        subkey: "".to_string(),
        l: left_ip,
        r: right_ip,
        value: format!("{:016x}", (left << 32) | right),
    });
}

fn populate_round_log_table(
    des_log_table: &mut Vec<DesLog>,
    round: usize,
    subkey: u64,
    left_block: u64,
    right_block: u64,
) {
    des_log_table.push(DesLog {
        round: format!("{}", round),
        subkey: format!("{:016x}", subkey),
        l: format!("{:016x}", left_block),
        r: format!("{:016x}", right_block),
        value: format!("{:016x}", (left_block << 32) | right_block),
    });
}

fn populate_inverse_ip_log_table(des_log_table: &mut Vec<DesLog>, final_permutated_block: u64) {
    let (left_final_permutated_block, right_final_permutated_block) =
        split_permutated_key_64(final_permutated_block);
    des_log_table.push(DesLog {
        round: "IP-1".to_string(),
        subkey: "".to_string(),
        l: format!("{:016x}", left_final_permutated_block),
        r: format!("{:016x}", right_final_permutated_block),
        value: format!(
            "{:016x}",
            (left_final_permutated_block << 32) | right_final_permutated_block
        ),
    });
}

pub fn des_encrypt(plaintext_input: String, key_input: String) -> u64 {
    let mut des_log_table: Vec<DesLog> = vec![];
    let plaintext_u64_block = u64::from_str_radix(&plaintext_input, 16).ok().unwrap();
    println!(
        "+----- 🔐 ENCRYPTING: {} ------+",
        format!("{:016x}", plaintext_u64_block)
    );

    let plaintext_after_init_permutation_block =
        get_permutated_block(plaintext_u64_block, INITIAL_PERMUTATION_TABLE, 0);
    populate_ip_log_table(&mut des_log_table, plaintext_after_init_permutation_block);
    let subkeys: [u64; 16] = get_subkeys(key_input).clone();
    let reversed_block = run_16_rounds(
        plaintext_after_init_permutation_block,
        subkeys,
        &mut des_log_table,
    );
    let final_permutated_block = get_permutated_block(reversed_block, INVERSE_PERMUTATION_TABLE, 0);
    populate_inverse_ip_log_table(&mut des_log_table, final_permutated_block);
    let table: String = Table::new(&des_log_table).to_string();
    println!("{}", table);

    return final_permutated_block;
}

pub fn des_decrypt(ciphertext: String, key_input: String) -> u64 {
    let mut des_log_table: Vec<DesLog> = vec![];
    let ciphertext_u64_block = u64::from_str_radix(&ciphertext, 16).ok().unwrap();
    println!(
        "+----- 🔓 DECRYPTING: {} ------+",
        format!("{:016x}", ciphertext_u64_block)
    );
    let plaintext_after_init_permutation_block: u64 =
        get_permutated_block(ciphertext_u64_block, INITIAL_PERMUTATION_TABLE, 0);
    print_u64(
        "after initaial permutation: ",
        plaintext_after_init_permutation_block,
    );
    populate_ip_log_table(&mut des_log_table, plaintext_after_init_permutation_block);
    let mut subkeys: [u64; 16] = get_subkeys(key_input).clone();
    subkeys.reverse();
    let reversed_block = run_16_rounds(
        plaintext_after_init_permutation_block,
        subkeys,
        &mut des_log_table,
    );
    let final_permutated_block: u64 =
        get_permutated_block(reversed_block, INVERSE_PERMUTATION_TABLE, 0);
    populate_inverse_ip_log_table(&mut des_log_table, final_permutated_block);
    let table: String = Table::new(&des_log_table).to_string();
    println!("{}", table);

    return final_permutated_block;
}

#[cfg(test)]
mod tests {
    use crate::encrypt::{des_decrypt, des_encrypt};

    #[test]
    fn encrypt_02468aceeca86420_with_0f1571c947d9e859() {
        let ciphertext = des_encrypt(
            "0123456789ABCDEF".to_string(),
            "133457799BBCDFF1".to_string(),
        );
        let expected: u64 = u64::from_str_radix(&"85e813540f0ab405", 16).ok().unwrap();
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn encrypt_0123456789abcdef_with_133457799_bbcdff1() {
        let ciphertext = des_encrypt(
            "02468aceeca86420".to_string(),
            "0f1571c947d9e859".to_string(),
        );
        let expected: u64 = u64::from_str_radix(&"da02ce3a89ecac3b", 16).ok().unwrap();
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn decrpyt_02468aceeca86420_with_0f1571c947d9e859() {
        let ciphertext = des_encrypt(
            "0123456789ABCDEF".to_string(),
            "133457799BBCDFF1".to_string(),
        );
        let decrypted = des_decrypt(
            "85e813540f0ab405".to_string(),
            "133457799BBCDFF1".to_string(),
        );
        let expected_ciphertext: u64 = u64::from_str_radix(&"85e813540f0ab405", 16).ok().unwrap();
        let expected_decrypted: u64 = u64::from_str_radix(&"0123456789ABCDEF", 16).ok().unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(decrypted, expected_decrypted);
    }

    #[test]
    fn decrpyt_0123456789abcdef_with_133457799_bbcdff1() {
        let ciphertext = des_encrypt(
            "02468aceeca86420".to_string(),
            "0f1571c947d9e859".to_string(),
        );
        let decrypted = des_decrypt(
            "da02ce3a89ecac3b".to_string(),
            "0f1571c947d9e859".to_string(),
        );
        let expected_ciphertext: u64 = u64::from_str_radix(&"da02ce3a89ecac3b", 16).ok().unwrap();
        let expected_decrypted: u64 = u64::from_str_radix(&"02468aceeca86420", 16).ok().unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(decrypted, expected_decrypted);
    }

    #[test]
    fn decrpyt_7772a5dc17cc382c_with_e31d1b22f059933e() {
        let ciphertext = des_encrypt(
            "7772A5DC17CC382C".to_string(),
            "E31D1B22F059933E".to_string(),
        );
        let decrypted = des_decrypt(
            "7C7EE7162E820D1C".to_string(),
            "E31D1B22F059933E".to_string(),
        );
        let expected_ciphertext: u64 = u64::from_str_radix(&"7C7EE7162E820D1C", 16).ok().unwrap();
        let expected_decrypted: u64 = u64::from_str_radix(&"7772A5DC17CC382C", 16).ok().unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(decrypted, expected_decrypted);
    }

    #[test]
    fn decrpyt_b268ed282a85a2ad_with_07511c6c9929cd75() {
        let ciphertext = des_encrypt(
            "b268ed282a85a2ad".to_string(),
            "07511c6c9929cd75".to_string(),
        );
        let decrypted = des_decrypt(
            "34B57D714D88E29C".to_string(),
            "07511c6c9929cd75".to_string(),
        );
        let expected_ciphertext: u64 = u64::from_str_radix(&"34B57D714D88E29C", 16).ok().unwrap();
        let expected_decrypted: u64 = u64::from_str_radix(&"b268ed282a85a2ad", 16).ok().unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(decrypted, expected_decrypted);
    }

    #[test]
    fn decrpyt_7e9591c91639ee65_with_c37ac5759520cd15() {
        let ciphertext = des_encrypt(
            "7e9591c91639ee65".to_string(),
            "c37ac5759520cd15".to_string(),
        );
        let decrypted = des_decrypt(
            "DC3C688EE9C561E6".to_string(),
            "c37ac5759520cd15".to_string(),
        );
        let expected_ciphertext: u64 = u64::from_str_radix(&"DC3C688EE9C561E6", 16).ok().unwrap();
        let expected_decrypted: u64 = u64::from_str_radix(&"7e9591c91639ee65", 16).ok().unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(decrypted, expected_decrypted);
    }
}
