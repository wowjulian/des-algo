use tabled::Tabled;

use crate::encrypt::split_permutated_key_64;

#[derive(Tabled)]
pub struct DesLog {
    round: String,
    subkey: String,
    l: String,
    r: String,
    value: String,
}

pub fn print_u64(label: &str, block: u64) {
    // println!("{}{}", label, format!("{:064b}", block));
    println!("{}{}", label, format!("{:016x}", block));
}

pub fn populate_ip_log_table(
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

pub fn populate_round_log_table(
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

pub fn populate_inverse_ip_log_table(des_log_table: &mut Vec<DesLog>, final_permutated_block: u64) {
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
