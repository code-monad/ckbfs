use core::borrow::Borrow;

use alloc::{vec, vec::Vec};
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::packed::Uint32Vec;
use ckb_std::ckb_types::prelude::{Entity, Unpack};
use ckb_std::error::SysError;
use ckb_std::high_level::{encode_hex, load_cell_data};

use crate::error::CKBFSError;
use crate::utils::*;
use crate::{ckb_arg_to_num, ckb_arg_to_vec_u8};

pub const CKBFS_WITNESSES_OFFSET: usize = 6;

#[no_mangle]
pub fn load_witnesses_for_ckbfs(index: usize, source: Source) -> Result<Vec<u8>, SysError> {
    load_witnesses_with_offset(index, CKBFS_WITNESSES_OFFSET, source)
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
