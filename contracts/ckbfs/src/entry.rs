use alloc::{ffi::CString, format, vec, vec::Vec};
use blake2b_ref::Blake2bBuilder;
use ckb_std::high_level::{encode_hex, load_input_out_point, load_witness};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::core::ScriptHashType,
    high_level::{
        load_cell_data, load_cell_data_hash, load_cell_type, load_cell_type_hash, load_input,
        load_script, load_script_hash, QueryIter,
    },
};
use core::fmt::Write;

use molecule::prelude::Entity;

use crate::{error::CKBFSError, hash};
use ckbfs_types::CKBFSData;

pub fn encode_hex_0x(data: &[u8]) -> CString {
    let mut s = alloc::string::String::with_capacity(data.len() * 2 + 2);
    write!(&mut s, "0x").unwrap();
    for &b in data {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    CString::new(s).unwrap()
}

pub fn u8_to_cstring(number: u8) -> CString {
    let s = format!("0x{}", encode_hex(&number.to_le_bytes()).to_str().unwrap());
    CString::new(s).unwrap()
}

fn load_ckbfs_raw_data(index: usize, source: Source) -> Result<CKBFSData, CKBFSError> {
    CKBFSData::from_compatible_slice(
        load_cell_data(index, source)
            .map_err(|_| CKBFSError::ItemMissing)? // can not load data
            .as_slice(),
    )
    .map_err(|_| CKBFSError::Encoding)
}

pub fn load_type_args(index: usize, source: Source) -> molecule::bytes::Bytes {
    load_cell_type(index, source)
        .unwrap_or(None)
        .unwrap_or_default()
        .args()
        .raw_data()
}

pub fn calc_type_id(tx_first_input: &[u8], output_index: usize) -> [u8; 32] {
    let mut blake2b = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    blake2b.update(tx_first_input);
    blake2b.update(&(output_index as u64).to_le_bytes());
    let mut verify_id = [0; 32];
    blake2b.finalize(&mut verify_id);
    verify_id
}

pub fn validate_type_id(type_id: &[u8; 32], output_index: usize) -> bool {
    if let Ok(first_input) = load_input(0, Source::Input) {
        let expected_id = calc_type_id(first_input.as_slice(), output_index);
        return type_id[..] == expected_id[..];
    } else {
        false
    }
}

pub fn validate_by_spawn_v3(
    witness_index: u32,
    checksum: u32,
    code_hash: Option<&[u8; 32]>,
) -> Result<bool, CKBFSError> {
    let code_hash = code_hash.unwrap_or(&hash::CKB_ADLER32_CODE_HASH);
    let hasher_index = QueryIter::new(load_cell_data_hash, Source::CellDep)
        .position(|data_hash| data_hash.as_slice() == code_hash);
    if hasher_index.is_none() {
        return Err(CKBFSError::NoChecksumHasherFound);
    }

    let mode = u8_to_cstring(3u8);
    let witness_index_arg = encode_hex_0x(&witness_index.to_le_bytes());
    let checksum_arg = encode_hex_0x(&checksum.to_le_bytes());
    let exec_args = vec![
        mode.as_c_str(),
        witness_index_arg.as_c_str(),
        checksum_arg.as_c_str(),
    ];

    match ckb_std::high_level::exec_cell(code_hash, ScriptHashType::Data1, &exec_args) {
        Ok(_) => Ok(true),
        Err(_) => Err(CKBFSError::ChecksumMismatch),
    }
}

fn validate_by_spawn_v3_with_recover(
    witness_index: u32,
    checksum: u32,
    recover: u32,
    code_hash: Option<&[u8; 32]>,
) -> Result<bool, CKBFSError> {
    let code_hash = code_hash.unwrap_or(&hash::CKB_ADLER32_CODE_HASH);
    let hasher_index = QueryIter::new(load_cell_data_hash, Source::CellDep)
        .position(|data_hash| data_hash.as_slice() == code_hash);
    if hasher_index.is_none() {
        return Err(CKBFSError::NoChecksumHasherFound);
    }

    let mode = u8_to_cstring(3u8);
    let witness_index_arg = encode_hex_0x(&witness_index.to_le_bytes());
    let checksum_arg = encode_hex_0x(&checksum.to_le_bytes());
    let recover_arg = encode_hex_0x(&recover.to_le_bytes());
    let exec_args = vec![
        mode.as_c_str(),
        witness_index_arg.as_c_str(),
        checksum_arg.as_c_str(),
        recover_arg.as_c_str(),
    ];

    match ckb_std::high_level::exec_cell(code_hash, ScriptHashType::Data1, &exec_args) {
        Ok(_) => Ok(true),
        Err(_) => Err(CKBFSError::ChecksumMismatch),
    }
}

fn unpack_type_args(args: &[u8]) -> Result<([u8; 32], Option<&[u8; 32]>), CKBFSError> {
    if args.len() < 32 {
        return Err(CKBFSError::LengthNotEnough);
    }
    let type_id: [u8; 32] = args[0..32].try_into().unwrap();
    let mut checksum_code_hash = None;
    if args.len() >= 64 {
        checksum_code_hash = Some(args[32..64].try_into().unwrap());
    }
    return Ok((type_id, checksum_code_hash));
}

fn validate_witness_previous_position(
    witness_index: usize,
    expected_tx_hash: &[u8],
    expected_witness_index: u32,
) -> Result<(), CKBFSError> {
    let head_witness = load_witness(witness_index, Source::Output)?;
    
    // Parse Head Witness according to RFC v3 specification
    if head_witness.len() < 50 {
        return Err(CKBFSError::LengthNotEnough);
    }
    
    // Extract previous TX hash (bytes 6-37) and witness index (bytes 38-41)
    let witness_previous_tx_hash: [u8; 32] = head_witness[6..38].try_into().unwrap();
    let witness_previous_index = u32::from_le_bytes(head_witness[38..42].try_into().unwrap());
    
    // Validate previous position matches expected values
    if witness_previous_tx_hash != expected_tx_hash || witness_previous_index != expected_witness_index {
        return Err(CKBFSError::InvalidPreviousPosition);
    }
    
    Ok(())
}

fn process_creation(index: usize) -> Result<(), CKBFSError> {
    let data = load_ckbfs_raw_data(index, Source::Output)?;

    let type_script_args = load_type_args(index, Source::Output);
    let (type_id, checksum_code_hash) = unpack_type_args(&type_script_args)?;

    // validate unique id
    if !validate_type_id(&type_id, index) {
        return Err(CKBFSError::InvalidTypeId);
    }

    let checksum = u32::from_le_bytes(data.checksum().as_slice().try_into().unwrap());
    let witness_index = u32::from_le_bytes(data.index().as_slice().try_into().unwrap());

    // For creation, previous position should be all zeros
    validate_witness_previous_position(witness_index as usize, &[0u8; 32], 0)?;

    if !validate_by_spawn_v3(witness_index, checksum, checksum_code_hash)? {
        return Err(CKBFSError::ChecksumMismatch);
    }

    Ok(())
}

fn process_update(input_index: usize, output_index: usize) -> Result<(), CKBFSError> {
    let input_data = load_ckbfs_raw_data(input_index, Source::Input)?;
    let output_data = load_ckbfs_raw_data(output_index, Source::Output)?;

    let previous_output = load_input_out_point(input_index, Source::Input)?;

    // Rule 14: content-type, filename, and Type args cannot be changed
    if input_data.content_type().as_slice() != output_data.content_type().as_slice() {
        return Err(CKBFSError::InvalidFieldUpdate);
    }

    if input_data.filename().as_slice() != output_data.filename().as_slice() {
        return Err(CKBFSError::InvalidFieldUpdate);
    }

    // Validate that Type script args (including TypeID) are unchanged
    let input_type_args = load_type_args(input_index, Source::Input);
    let output_type_args = load_type_args(output_index, Source::Output);
    if input_type_args != output_type_args {
        return Err(CKBFSError::InvalidFieldUpdate);
    }

    let previous_tx_hash = previous_output.tx_hash();
    let previous_witness_index = u32::from_le_bytes(input_data.index().as_slice().try_into().unwrap());
    let output_witness_index = u32::from_le_bytes(output_data.index().as_slice().try_into().unwrap());

    // Validate witness previous position
    validate_witness_previous_position(output_witness_index as usize, previous_tx_hash.as_slice(), previous_witness_index)?;

    let type_script_args = load_script()?.args();
    let (_, checksum_code_hash) = unpack_type_args(type_script_args.as_slice())?;
    
    let input_checksum = u32::from_le_bytes(input_data.checksum().as_slice().try_into().unwrap());
    let output_checksum = u32::from_le_bytes(output_data.checksum().as_slice().try_into().unwrap());

    // Check if this is a transfer operation
    if input_checksum == output_checksum {
        // Transfer operation: Rule 16 - checksum cannot be updated
        // Rule 15: Head witness should not contain content part bytes (only backlink info)
        return process_transfer(output_witness_index, output_checksum, checksum_code_hash);
    }

    // Append operation: Rule 13 - new checksum should be hasher.recover_from(previous_checksum).update(new_content_bytes)
    process_append(output_witness_index, output_checksum, input_checksum, checksum_code_hash)
}

fn process_transfer(witness_index: u32, checksum: u32, checksum_code_hash: Option<&[u8; 32]>) -> Result<(), CKBFSError> {
    // For transfer, we validate that the witness structure is correct but no content is added
    // The hasher will validate the witness structure according to RFC v3 transfer rules
    if !validate_by_spawn_v3(witness_index, checksum, checksum_code_hash)? {
        return Err(CKBFSError::ChecksumMismatch);
    }
    Ok(())
}

fn process_append(witness_index: u32, checksum: u32, recover_checksum: u32, checksum_code_hash: Option<&[u8; 32]>) -> Result<(), CKBFSError> {
    // For append, we validate with recovery from previous checksum
    if !validate_by_spawn_v3_with_recover(witness_index, checksum, recover_checksum, checksum_code_hash)? {
        return Err(CKBFSError::ChecksumMismatch);
    }
    Ok(())
}

pub fn main() -> Result<(), CKBFSError> {
    let ckbfs_cell_type_hash = load_script_hash()?;

    // this in output:
    let ckbfs_in_output = QueryIter::new(load_cell_type_hash, Source::Output)
        .enumerate()
        .filter(|(_, type_hash)| type_hash.is_some_and(|x| x == ckbfs_cell_type_hash))
        .map(|(index, _)| index)
        .collect::<Vec<usize>>();

    let ckbfs_in_input = QueryIter::new(load_cell_type_hash, Source::Input)
        .position(|type_hash| type_hash.is_some_and(|x| x == ckbfs_cell_type_hash));

    // can not create two exact same ckbfs cell
    if ckbfs_in_output.len() > 1 {
        return Err(CKBFSError::DuplicatedOutputs);
    }

    match (ckbfs_in_input, ckbfs_in_output.len()) {
        (None, 1) => {
            // creation
            process_creation(ckbfs_in_output[0])?
        }
        (Some(_), 0) => {
            // destroy, forbidden
            return Err(CKBFSError::DeletionForbidden);
        }
        (Some(index), 1) => {
            // append or transfer
            process_update(index, ckbfs_in_output[0])?
        }

        _ => unreachable!(),
    }

    Ok(())
}
