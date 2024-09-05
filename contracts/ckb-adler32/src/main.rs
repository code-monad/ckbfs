#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
extern crate alloc;

#[cfg(not(test))]
use ckb_std::default_alloc;

#[cfg(not(test))]
ckb_std::entry!(program_entry);

#[cfg(not(test))]
default_alloc!();

mod error;
mod macros;
mod process;
mod utils;

use crate::error::CKBFSError;
use crate::process::*;
use crate::utils::*;
use alloc::vec;
use ckb_std::high_level::encode_hex;

pub fn program_entry() -> i8 {
    let args = ckb_std::env::argv();

    match args.len() {
        // different execution mode
        0 => {} // do nothing if no args provided
        1 => {
            let checksum_ = checksum(args[0].to_bytes());
            ckb_std::debug!(
                "0x{}",
                encode_hex(&checksum_.to_le_bytes()).to_string_lossy()
            );
            return 0; // return 0 as success
        } // only do hash if one arg exist

        // complex && mode specify mode
        _ => {
            // check arg count first
            let mode_arg = ckb_arg_to_num!(args[0], u8);
            // arg rules should be like:
            // [<MODE>, ...<OTHER ARGS>]
            // which means, first arg should always be mode

            return match mode_arg {
                // modes are defined as below:
                // 0 - plain validate mode; args should be: [CONTENT, EXPECT_CHECKSUM, RECOVER_CHECKSUM(OPTIONAL)]
                0 => process_plain_validate(args),

                // 1 - (for contract) ckbfs validate mode; args should be: [WITNESSES_INDEX, EXPECT_CHECKSUM, RECOVER_CHECKSUM(OPTIONAL)]
                1 => process_ckbfs_validate(args),

                // 2 - (for contract) manual validate mode; load data from where you want; args should be: [SOURCE, INDEX, OFFSET, EXPECTED_CHECKSUM, RECOVER_CHECKSUM(OPTIONAL)]
                2 => process_manual_validate(args),

                _ => return CKBFSError::Unknown as i8, // unknown args
            };
        }
    }
    0
}
