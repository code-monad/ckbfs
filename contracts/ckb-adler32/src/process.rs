use core::borrow::Borrow;

use alloc::{vec, vec::Vec};
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::packed::Uint32Vec;
use ckb_std::ckb_types::prelude::{Entity, Unpack};
use ckb_std::error::SysError;
use ckb_std::high_level::{encode_hex, load_cell_data, load_witness};

use crate::error::CKBFSError;
use crate::utils::*;
use crate::{ckb_arg_to_num, ckb_arg_to_vec_u8};

pub const CKBFS_WITNESSES_OFFSET: usize = 6;

#[no_mangle]
pub fn load_witnesses_for_ckbfs(index: usize, source: Source) -> Result<Vec<u8>, SysError> {
    load_witnesses_with_offset(index, CKBFS_WITNESSES_OFFSET, source)
}

pub enum CKBFS_V3_WITNESSES_INDEX {
    HeadWitness(u32),
    MiddleWitness(u32),
    TailWitness(u32),
}

// Head witness structure: CKBFS(5) + version(1) + prev_position(36) + prev_checksum(4) + next_index(4) + content
// Middle/Tail witness structure: next_index(4) + content

// content part offset
pub const CKBFS_V3_HEAD_WITNESS_OFFSET: usize = 50; // 5 + 1 + 36 + 4 + 4 = 50
pub const CKBFS_V3_MIDDLE_WITNESS_OFFSET: usize = 4; // 4 bytes for next_index
pub const CKBFS_V3_TAIL_WITNESS_OFFSET: usize = 4; // 4 bytes for next_index

// recover checksum offset (only in head witness)
pub const CKBFS_V3_HEAD_RECOVER_CHECKSUM_OFFSET: usize = 42; // 5 + 1 + 36 = 42

// next index offset
pub const CKBFS_V3_HEAD_NEXT_INDEX_OFFSET: usize = 46; // 5 + 1 + 32 + 4 + 4 = 46
pub const CKBFS_V3_MIDDLE_NEXT_INDEX_OFFSET: usize = 0; // starts at beginning
pub const CKBFS_V3_TAIL_NEXT_INDEX_OFFSET: usize = 0; // starts at beginning

pub struct CKBFSV3WintessWithMeta {
    data: Vec<u8>,
    next_index: Option<u32>,
    recover_checksum: Option<u32>,
}

pub fn load_witnesses_for_ckbfs_v3(
    index: CKBFS_V3_WITNESSES_INDEX,
    source: Source,
) -> Result<CKBFSV3WintessWithMeta, SysError> {
    let witness_index = match index {
        CKBFS_V3_WITNESSES_INDEX::HeadWitness(index) => index,
        CKBFS_V3_WITNESSES_INDEX::MiddleWitness(index) => index,
        CKBFS_V3_WITNESSES_INDEX::TailWitness(index) => index,
    };

    let witness = load_witness(witness_index as usize, source)?;

    let extract_u32 = |offset: usize| -> Result<u32, SysError> {
        if witness.len() >= offset + 4 {
            Ok(u32::from_le_bytes(
                witness[offset..offset + 4].try_into().unwrap(),
            ))
        } else {
            Err(SysError::LengthNotEnough(witness.len()))
        }
    };

    match index {
        CKBFS_V3_WITNESSES_INDEX::HeadWitness(_) => {
            // Validate head witness structure: CKBFS + 0x03 + prev_position + prev_checksum + next_index + content
            if witness.len() < 50 {
                return Err(SysError::LengthNotEnough(witness.len()));
            }

            // Validate version
            if witness[5] != 0x03 {
                return Err(SysError::LengthNotEnough(witness.len()));
            }

            let recover_checksum = extract_u32(CKBFS_V3_HEAD_RECOVER_CHECKSUM_OFFSET)?;
            let next_index = extract_u32(CKBFS_V3_HEAD_NEXT_INDEX_OFFSET)?;

            let data = witness[CKBFS_V3_HEAD_WITNESS_OFFSET..].to_vec();

            Ok(CKBFSV3WintessWithMeta {
                data,
                next_index: if next_index == 0 {
                    None
                } else {
                    Some(next_index)
                },
                recover_checksum: Some(recover_checksum),
            })
        }
        CKBFS_V3_WITNESSES_INDEX::MiddleWitness(_) | CKBFS_V3_WITNESSES_INDEX::TailWitness(_) => {
            // Middle/Tail witness structure: next_index + content
            if witness.len() < 4 {
                return Err(SysError::LengthNotEnough(witness.len()));
            }

            let next_index = extract_u32(0)?;
            let data = witness[4..].to_vec();

            Ok(CKBFSV3WintessWithMeta {
                data,
                next_index: if next_index == 0 {
                    None
                } else {
                    Some(next_index)
                },
                recover_checksum: None,
            })
        }
    }
}

pub fn validate_checksum(expected_checksum: u32, data: &[u8], recover_checksum: Option<u32>) -> i8 {
    // recover if recover hash provided
    let checksum_ = match recover_checksum {
        Some(recover_checksum) => {
            let mut adler = recover_from_checksum(recover_checksum);
            adler.write_slice(data);
            adler.checksum()
        }
        None => checksum(data),
    };

    if checksum_ != expected_checksum {
        ckb_std::debug!(
            "CKB-Adler32: ValidateFailure, 0x{} != 0x{}",
            encode_hex(&checksum_.to_le_bytes()).to_string_lossy(),
            encode_hex(&expected_checksum.to_le_bytes()).to_string_lossy()
        );
        return CKBFSError::ValidateFailure as i8;
    }

    0
}

pub fn process_plain_validate(args: &[ckb_std::env::Arg]) -> i8 {
    if args.len() < 3 {
        ckb_std::debug!("CKB-Adler32: Arg LengthNotEnough");
        return CKBFSError::LengthNotEnough as i8;
    }

    let data = args[1].to_bytes();
    let expected_checksum = ckb_arg_to_num!(args[2].borrow(), u32);
    let recover_checksum = if args.len() > 3 {
        Some(ckb_arg_to_num!(args[3].borrow(), u32))
    } else {
        None
    };

    validate_checksum(expected_checksum, &data, recover_checksum)
}

pub fn process_ckbfs_validate(args: &[ckb_std::env::Arg]) -> i8 {
    if args.len() < 3 {
        ckb_std::debug!("CKB-Adler32: Arg LengthNotEnough");
        return CKBFSError::LengthNotEnough as i8;
    }

    let witnesses_indexes_vec = ckb_arg_to_vec_u8!(args[1].borrow());
    let witnesses_indexes = Uint32Vec::from_compatible_slice(&witnesses_indexes_vec)
        .expect("Failed to unpack witnesses indexes!");

    let witnesses_indexes = witnesses_indexes
        .into_iter()
        .map(|x| x.unpack())
        .collect::<Vec<u32>>();

    let expected_checksum = ckb_arg_to_num!(args[2].borrow(), u32);

    let recover_checksum = if args.len() > 3 {
        Some(ckb_arg_to_num!(args[3].borrow(), u32))
    } else {
        None
    };

    let mut final_checksum = recover_checksum;

    for witnesses_index in witnesses_indexes {
        let witnesses_part = load_witnesses_for_ckbfs(witnesses_index as usize, Source::Output)
            .expect(&alloc::format!(
                "CKB-Adler32: Failed to load witness {witnesses_index}"
            ));
        final_checksum = match final_checksum {
            None => Some(checksum(&witnesses_part)),
            Some(recover) => {
                let mut adler = recover_from_checksum(recover);
                adler.write_slice(&witnesses_part);
                Some(adler.checksum())
            }
        }
    }

    if final_checksum.unwrap_or_default() != expected_checksum {
        return CKBFSError::ValidateFailure as i8;
    }

    0
}

pub fn process_ckbfs_validate_v3(args: &[ckb_std::env::Arg]) -> i8 {
    if args.len() < 3 {
        ckb_std::debug!("CKB-Adler32: Arg LengthNotEnough");
        return CKBFSError::LengthNotEnough as i8;
    }

    let first_witness_index = ckb_arg_to_num!(args[1].borrow(), u32);
    let expected_checksum = ckb_arg_to_num!(args[2].borrow(), u32);

    // Load head witness first
    let head_witness = match load_witnesses_for_ckbfs_v3(
        CKBFS_V3_WITNESSES_INDEX::HeadWitness(first_witness_index),
        Source::Output,
    ) {
        Ok(witness) => witness,
        Err(_) => {
            ckb_std::debug!(
                "CKB-Adler32: Failed to load head witness {}",
                first_witness_index
            );
            return CKBFSError::ValidateFailure as i8;
        }
    };

    // Collect all witness content parts
    let mut all_content = head_witness.data;
    let mut current_index = head_witness.next_index;

    // Follow the witness chain
    while let Some(next_idx) = current_index {
        let witness = if next_idx == 0 {
            match load_witnesses_for_ckbfs_v3(
                CKBFS_V3_WITNESSES_INDEX::TailWitness(next_idx),
                Source::Output,
            ) {
                Ok(witness) => witness,
                Err(_) => {
                    ckb_std::debug!("CKB-Adler32: Failed to load witness {}", next_idx);
                    return CKBFSError::ValidateFailure as i8;
                }
            }
        } else {
            match load_witnesses_for_ckbfs_v3(
                CKBFS_V3_WITNESSES_INDEX::MiddleWitness(next_idx),
                Source::Output,
            ) {
                Ok(witness) => witness,
                Err(_) => {
                    ckb_std::debug!("CKB-Adler32: Failed to load witness {}", next_idx);
                    return CKBFSError::ValidateFailure as i8;
                }
            }
        };

        all_content.extend_from_slice(&witness.data);
        current_index = witness.next_index;
    }

    // Validate the final checksum
    validate_checksum(
        expected_checksum,
        &all_content,
        head_witness.recover_checksum,
    )
}

pub fn process_manual_validate(args: &[ckb_std::env::Arg]) -> i8 {
    if args.len() < 5 {
        ckb_std::debug!("CKB-Adler32: Arg LengthNotEnough");
        return CKBFSError::LengthNotEnough as i8;
    }

    let source = map_u64_to_source(ckb_arg_to_num!(&args[1], u64));
    let index = ckb_arg_to_num!(&args[2], u8);
    let offset = ckb_arg_to_num!(&args[3], u32);
    let content = load_cell_data(index as usize, source)
        .expect(&alloc::format!(
            "CKB-Adler32: Failed to load Data from {:?}[{index}]",
            source
        ))
        .split_off(offset as usize);

    let expected_checksum = ckb_arg_to_num!(args[4].borrow(), u32);
    let recover_checksum = if args.len() > 5 {
        Some(ckb_arg_to_num!(args[5].borrow(), u32))
    } else {
        None
    };

    validate_checksum(expected_checksum, &content, recover_checksum)
}
