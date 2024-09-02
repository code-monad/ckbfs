pub fn strip_prefix_0x(content_str: &str) -> &str {
    content_str.strip_prefix("0x").unwrap_or(content_str)
}

use alloc::{vec, vec::Vec};
use ckb_std::{ckb_constants::Source, error::SysError, high_level::load_witness};

pub fn map_u64_to_source(value: u64) -> Source {
    match value {
        1 => Source::Input,
        2 => Source::Output,
        3 => Source::CellDep,
        4 => Source::HeaderDep,
        0x0100000000000001 => Source::GroupInput,
        0x0100000000000002 => Source::GroupOutput,
        _ => panic!("{value} is not a valid source"),
    }
}

#[no_mangle]
pub fn checksum(raw_content: &[u8]) -> u32 {
    adler::adler32_slice(raw_content)
}

#[no_mangle]
// recover from a u32 bytes arr
pub fn recover(raw_hash: &[u8]) -> Result<adler::Adler32, SysError> {
    let raw_hash_le_bytes = raw_hash
        .try_into()
        .map_err(|_| SysError::Unknown(raw_hash.len() as u64))?;
    Ok(adler::Adler32::from_checksum(u32::from_le_bytes(
        raw_hash_le_bytes,
    )))
}

#[no_mangle]
// recover from a hex str
pub fn recover_from_checksum_str(hash_str: &str) -> Result<adler::Adler32, SysError> {
    // strip 0x for decode purpose
    let hash_str = strip_prefix_0x(hash_str);
    let mut hash_bytes = vec![0u8; 4];
    faster_hex::hex_decode(hash_str.as_bytes(), &mut hash_bytes).map_err(|_| SysError::Encoding)?;
    recover(&hash_bytes)
}

// recovery direc from u32 checksum
pub fn recover_from_checksum(hash_u32: u32) -> adler::Adler32 {
    adler::Adler32::from_checksum(hash_u32)
}

pub fn load_witnesses_with_offset(
    index: usize,
    offset: usize,
    source: Source,
) -> Result<Vec<u8>, SysError> {
    load_witness(index, source).and_then(|mut witness| {
        if witness.len() < offset {
            return Err(SysError::LengthNotEnough(witness.len()));
        }
        Ok(witness.split_off(offset))
    })
}

#[no_mangle]
pub fn validate(raw_content: &[u8], checksum_: u32) -> bool {
    let target_checksum = checksum(raw_content);
    ckb_std::debug!("target_checksum: {target_checksum}, input_checksum: {checksum_}");
    target_checksum == checksum_
}
