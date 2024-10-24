#[macro_export]
macro_rules! ckb_arg_to_num {
    ($arg:expr, $type:ty) => {{
        let arg_str = $arg.to_str().expect("CKB-Adler32:Failed to extract arg!");
        if arg_str.starts_with("0x") {
            let arg_str = arg_str.strip_prefix("0x").unwrap();
            let mut buffer = vec![0; core::mem::size_of::<$type>()];
            faster_hex::hex_decode(arg_str.as_bytes(), &mut buffer)
                .expect("CKB-Adler32:Failed to extract arg as little endian hex!");
            <$type>::from_le_bytes(buffer.try_into().expect("Buffer size mismatch!"))
        } else {
            arg_str
                .parse::<$type>()
                .expect("CKB-Adler32:Failed to parse arg as number!")
        }
    }};
}

#[macro_export]
macro_rules! ckb_arg_to_vec_u8 {
    ($arg:expr) => {{
        let arg_str = $arg.to_str().expect("CKB-Adler32: Failed to extract arg!");
        if arg_str.starts_with("0x") {
            let arg_str = arg_str.strip_prefix("0x").unwrap();
            let mut buffer = vec![0u8; arg_str.len() / 2];
            faster_hex::hex_decode(arg_str.as_bytes(), &mut buffer)
                .expect("CKB-Adler32: Failed to decode hex into Vec<u8>!");
            buffer // Return the decoded Vec<u8>
        } else {
            panic!("CKB-Adler32: Input must start with '0x' to decode into Vec<u8>!");
        }
    }};
}
