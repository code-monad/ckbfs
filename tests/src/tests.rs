use crate::Loader;
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_hash::Blake2bBuilder;
use ckb_testtool::ckb_types::core::DepType;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use ckbfs_types::{CKBFSData, CKBFSDataNative, };
// Include your tests here
// See https://github.com/xxuejie/ckb-native-build-sample/blob/main/tests/src/tests.rs for more examples


pub fn build_type_id(first_input: &CellInput, out_index: usize) -> [u8; 32] {
    let mut blake2b = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    blake2b.update(first_input.as_slice());
    blake2b.update(&(out_index as u64).to_le_bytes());
    let mut verify_id = [0; 32];
    blake2b.finalize(&mut verify_id);
    verify_id
}


// generated unit test for contract ckbfs
#[test]
fn test_ckbfs() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckbfs");
    let adler32_bin: Bytes = Loader::default().load_binary("ckb-adler32");
    let always_success = ALWAYS_SUCCESS.clone();
    let always_success_outpoint = context.deploy_cell(always_success);
    let out_point = context.deploy_cell(contract_bin);
    let adler32_outpoint = context.deploy_cell(adler32_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&always_success_outpoint, Bytes::from(vec![42]))
        .expect("script");
    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let type_id = build_type_id(&input, 0);


    let type_script = context
    .build_script(&out_point, type_id.to_vec().into())
    .expect("script");
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .type_(ScriptOpt::new_builder().set(Some(type_script)).build())
            .build(),
    ];

    let outputs_data = CKBFSDataNative{
        index: 0,
        checksum: 0x11ea02fe,
        content_type: "plain/text".to_string(),
        filename: "Hello.txt".to_string(),
    };

    let ckbfs_data : CKBFSData = outputs_data.into(); 
    let content = "HELLO CKBFS";
    
    // Create Head Witness according to RFC v3 specification
    let mut head_witness = Vec::new();
    
    // 1. "CKBFS" string (5 bytes): 0x434b424653
    head_witness.extend_from_slice(b"CKBFS");
    
    // 2. Version (1 byte): 0x03
    head_witness.push(0x03);
    
    // 3. Previous Position (36 bytes): 32 bytes TX hash + 4 bytes witness index (all zeros for Publish)
    head_witness.extend_from_slice(&[0u8; 32]); // Previous TX hash (32 bytes of zeros)
    head_witness.extend_from_slice(&[0u8; 4]);  // Previous witness index (4 bytes of zeros)
    
    // 4. Previous Checksum (4 bytes): 0x00000000 for Publish operation
    head_witness.extend_from_slice(&[0u8; 4]);
    
    // 5. Next Index (4 bytes): 0x00000000 since this is the tail witness
    head_witness.extend_from_slice(&[0u8; 4]);
    
    // 6. Content bytes: "HELLO CKBFS"
    head_witness.extend_from_slice(content.as_bytes());

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .cell_dep(CellDep::new_builder().out_point(adler32_outpoint).dep_type(DepType::Code.into()).build())
        .outputs_data(vec![ckbfs_data.as_slice().pack()])
        .witness(Bytes::from(head_witness).pack())
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, 10_000_000)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

// generated unit test for contract ckb-alder32
#[test]
fn test_ckb_adler32() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-adler32");
    let out_point = context.deploy_cell(contract_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, Bytes::from(vec![42]))
        .expect("script");

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, 10_000_000)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}
