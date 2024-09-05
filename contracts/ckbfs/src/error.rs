use ckb_std::error::SysError;

/// Error
#[repr(i8)]
pub enum CKBFSError {
    IndexOutOfBound = -1,
    ItemMissing = -2,
    LengthNotEnough = -3,
    Encoding = -4,
    Unknown = -100,
    InvalidInitialData = 101,
    InvalidTypeId = 102,
    DeletionForbidden = 103,     // we can  not delete a CKBFS cell
    ChecksumMismatch = 104,      // mismatching while append
    InvalidFieldUpdate = 105,    // only backlinks is able to append, others are immutable
    NoChecksumHasherFound = 106, // no valid checksum binary founded in deps
    DuplicatedOutputs = 107,     // there can not be two same ckbfs cell in output
    InvalidAppend = 108,         // append data updates not meet
}

impl From<SysError> for CKBFSError {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            _ => Self::Unknown,
        }
    }
}
