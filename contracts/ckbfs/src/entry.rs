use alloc::{ffi::CString, string::String, vec, vec::Vec};
use blake2b_ref::Blake2bBuilder;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::core::ScriptHashType,
    debug,
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
    let mut s = String::with_capacity(data.len() * 2);
    write!(&mut s, "0x").unwrap();
    for &b in data {
        write!(&mut s, "{:02x}", b).unwrap();
    }
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

pub fn validate_by_spawn(
    witness_index: usize,
    checksum: u32,
    code_hash: Option<&[u8; 32]>,
) -> Result<bool, CKBFSError> {
    let code_hash = code_hash.unwrap_or(&hash::CKB_ADLER32_CODE_HASH);
    let hasher_index = QueryIter::new(load_cell_data_hash, Source::CellDep)
        .position(|data_hash| data_hash.as_slice() == code_hash);
    if hasher_index.is_none() {
        return Err(CKBFSError::NoChecksumHasherFound);
    }

    let mode = vec![b'1', 0];
    let witnesses_index_arg = vec![b'0' + witness_index as u8, 0];
    let checksum_arg = encode_hex_0x(&checksum.to_be_bytes());
    let exec_args = vec![
        core::ffi::CStr::from_bytes_with_nul(mode.as_slice()).unwrap(),
        core::ffi::CStr::from_bytes_with_nul(witnesses_index_arg.as_slice()).unwrap(),
        checksum_arg.as_c_str(),
    ];

    match ckb_std::high_level::exec_cell(code_hash, ScriptHashType::Data1, &exec_args) {
        Ok(_) => Ok(true),
        Err(_) => Err(CKBFSError::ChecksumMismatch),
    }
}

fn validate_by_spawn_with_recover(
    witness_index: usize,
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

    let mode = vec![b'1', 0];
    let witnesses_index_arg = vec![b'0' + witness_index as u8, 0];
    let checksum_arg = encode_hex_0x(&checksum.to_be_bytes());
    let recover_arg = encode_hex_0x(&recover.to_be_bytes());
    let exec_args = vec![
        core::ffi::CStr::from_bytes_with_nul(mode.as_slice()).unwrap(),
        core::ffi::CStr::from_bytes_with_nul(witnesses_index_arg.as_slice()).unwrap(),
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

fn process_creation(index: usize) -> Result<(), CKBFSError> {
    let data = load_ckbfs_raw_data(index, Source::Output)?;
    let type_script_args = load_type_args(index, Source::Output);
    let (type_id, checksum_code_hash) = unpack_type_args(&type_script_args)?;

    // vallidate unique id
    if !validate_type_id(&type_id, index) {
        return Err(CKBFSError::InvalidTypeId);
    }

    let mut recover = None;

    // if initial backlink is not empty, then it must
    if data.backlinks().len() != 0 {
        let ref_cell_index = QueryIter::new(load_cell_type, Source::CellDep)
            .enumerate()
            .position(|(_, cell_type)| {
                if let Ok(current_script_code_hash) = load_script() {
                    return cell_type.unwrap_or_default().code_hash().as_slice()
                        == current_script_code_hash.as_slice();
                }
                false
            });
        if ref_cell_index.is_none() {
            return Err(CKBFSError::InvalidInitialData);
        }
        let ref_data = load_ckbfs_raw_data(index, Source::CellDep)?;

        // should always be one size longer
        if data.backlinks().len() != (ref_data.backlinks().len() + 1) {
            return Err(CKBFSError::InvalidInitialData);
        }

        recover = Some(u32::from_le_bytes(
            ref_data.checksum().as_slice().try_into().unwrap(),
        ));

        // check backlink equality
        for i in 0..ref_data.backlinks().len() {
            if data
                .backlinks()
                .get(i)
                .ok_or(CKBFSError::IndexOutOfBound)?
                .as_slice()
                != ref_data
                    .backlinks()
                    .get(i)
                    .ok_or(CKBFSError::IndexOutOfBound)?
                    .as_slice()
            {
                return Err(CKBFSError::InvalidInitialData);
            }
        }

        debug!("Initial reference passed!");
    }

    let checksum = u32::from_le_bytes(data.checksum().as_slice().try_into().unwrap());
    let witness_index = u32::from_le_bytes(data.index().as_slice().try_into().unwrap());

    match recover {
        Some(recover) => {
            if !validate_by_spawn_with_recover(
                witness_index as usize,
                checksum,
                recover,
                checksum_code_hash,
            )? {
                return Err(CKBFSError::ChecksumMismatch);
            }
        }
        None => {
            if !validate_by_spawn(witness_index as usize, checksum, checksum_code_hash)? {
                return Err(CKBFSError::ChecksumMismatch);
            }
        }
    }

    Ok(())
}

fn process_update(input_index: usize, output_index: usize) -> Result<(), CKBFSError> {
    let input_data = load_ckbfs_raw_data(input_index, Source::Input)?;
    let output_data = load_ckbfs_raw_data(output_index, Source::Output)?;

    let type_script_args = load_script()?.args();
    let (_, checksum_code_hash) = unpack_type_args(type_script_args.as_slice())?;

    // transfer, pass if no data was modified
    if input_data.as_slice() == output_data.as_slice() {
        return Ok(()); // since we are only dealing with unique type scripts(script args can not modified, this is okay)
    }

    // verify append op

    // content-type can not be changed
    if input_data.content_type().as_slice()[..] != output_data.content_type().as_slice()[..] {
        return Err(CKBFSError::InvalidFieldUpdate);
    }

    // filename can not be changed
    if input_data.filename().as_slice()[..] != output_data.filename().as_slice()[..] {
        return Err(CKBFSError::InvalidFieldUpdate);
    }

    let recover = u32::from_le_bytes(output_data.checksum().as_slice().try_into().unwrap());

    // should always be one size longer
    if output_data.backlinks().len() != (input_data.backlinks().len() + 1) {
        return Err(CKBFSError::InvalidInitialData);
    }

    // check backlink equality
    for i in 0..input_data.backlinks().len() {
        if output_data
            .backlinks()
            .get(i)
            .ok_or(CKBFSError::IndexOutOfBound)?
            .as_slice()
            != input_data
                .backlinks()
                .get(i)
                .ok_or(CKBFSError::IndexOutOfBound)?
                .as_slice()
        {
            return Err(CKBFSError::InvalidAppend);
        }
    }

    let checksum = u32::from_le_bytes(output_data.checksum().as_slice().try_into().unwrap());
    let witness_index = u32::from_le_bytes(output_data.index().as_slice().try_into().unwrap());

    if !validate_by_spawn_with_recover(
        witness_index as usize,
        checksum,
        recover,
        checksum_code_hash,
    )? {
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
            process_creation(2)?
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
