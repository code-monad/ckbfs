use ckb_hash::blake2b_256;
use std::{env, fs};

fn compute_code_hash(binary_name: &str, build_mode: &str) -> [u8; 32] {
    let binary_path = env::current_dir()
        .unwrap()
        .join("../../build")
        .join(build_mode)
        .join(binary_name);
    println!("path: {}", binary_path.to_string_lossy());
    let binary = std::fs::read(binary_path).expect("load {binary_name}");
    blake2b_256(binary)
}

// export encoded code hashes to public const value with name
pub fn export_code_hash(var: &str, code_hash: &[u8; 32]) -> String {
    format!("pub const {var}: [u8; 32] = {code_hash:?};\n")
}

pub fn main() {
    let build_mode = env::var("PROFILE").unwrap();
    let ckb_adler32_code_hash = compute_code_hash("ckb-adler32", &build_mode);

    let content = export_code_hash("CKB_ADLER32_CODE_HASH", &ckb_adler32_code_hash);
    fs::write("./src/hash.rs", content).unwrap();
}
