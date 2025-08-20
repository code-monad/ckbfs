# CKBFS Protocol V3

This is a next generation for CKBFS Protocol, aimed to provide a more affordable storage price -- comparing to similar solutions like IPFS.

The most important change of V3 is that there's no longer `Backlinks` inside the Cell data. Instead, it was moved into witnesses.


## Protocol Standard

### Data Structure

#### CKBFS v3 Cell

CKBFS Cell is a cell that stores metadata of the file:

```yaml
Data:
  content_type: Bytes # String Bytes
  filename: Bytes # String Bytes
  index: Uint32 # Reference of the first witnesses index.
  checksum: Uint32 # Adler32 checksum

Type:
  hash_type: "data1"
  code_hash: CKBFS_V3_TYPE_DATA_HASH
  args: <TypeID, 32 bytes>,[<hasher_code_hash>, optional]
Lock:
  <user_defined>
```

The following rules should be met in a CKBFS cell:

- Rule 1: data structure of a CKBFS cell is molecule encoded. See [Molecule](https://github.com/nervosnetwork/molecule) definitions below.
- Rule 2: checksum must match with specified witnesses. Default checksum algorithm will be Alder32 if not specify `hasher_code_hash` in Type script args.
- Rule 3: if `hasher_code_hash` is specified, then it will use hasher binary from CellDeps that matches `code_hash`, with same input parameter.
- Rule 4: Once created, a CKBFS cell can only be updated/transfered, which means it can not be destroyed.
- Rule 5: **`index` is the first witness index of the stored CKBFS structured contents in splited witnesses.**


### Witnesses

File contents are stored in witnesses. In a single transaction, witnesses can be splitted into multiple parts and concat together while verification. 

```yaml
Witnesses:
  <"CKBFS"> <0x03> <PREVIOUS_POSITION(TX_HASH, Witness_index)> <PREVIOUS_CHECKSUM(4 bytes) | 0x00000000> <NEXT_INDEX | 0x00000000> [CONTENT_BYTES_PART_1]
  <NEXT_INDEX | 0x00000000> <CONTENT_BYTES_PART_2>
  <NEXT_INDEX | 0x00000000> <CONTENT_BYTES_PART_3> ...
  <0x00000000> <CONTENT_BYTES_PART_N>
```

The following rules should be met for witnesses used in CKBFS:
- Rule 6: Witnesses are different in `Head Witness`, `Middle Witnesses`, and `Tail Witness`, their form should follow bellow's rules
- Rule 7: The first 5 bytes of `Head Witness` must be UTF8 coded string bytes of `CKBFS`, which should be: `0x434b424653`
- Rule 8: The 6th byte of `Head Witness` must be the version of CKBFS protocol, which should be: `0x03`.
- Rule 9: Previous position of this CKBFS content stores from 7th bytes to 42th bytes in `Head Witness`. it should be previous transaction hash(H256) and previous Head Witness index(Uint32).
- Rule 10: Previous checksum value must stored in `Head Witness`, position from 43rd to 46th bytes. If there's no previous status, then it should be `0x00000000`.
- Rule 10: File contents bytes are stored from:
    - 51st byte from the Head Witness.
    - 5th byte from the `Middle Witnesses` and `Tail Witness`

----

### Operations

This section describes operations and restrictions in CKBFS v3 implementation.

#### Publish

Publish operation creates one or more new CKBFS v3 cell.

```yaml
Witnesses:
  <...>
  <0x434b424653, 0x03, 32bytes 0x00, 0x00000000, 0x00000000, 0x00000002,CKBFS_CONTENT_BYTES_PART_1>
  <0x00000003, CKBFS_CONTENT_BYTES_PART_2>
  <...>
  <0x00000000, CKBFS_CONTENT_BYTES_PART_TAIL>
  <...>
Inputs:
  <...>
Outputs:
  <vec> CKBFS_V3_CELL
    Data:
      content-type: string
      filename: string
      indexes: uint32
      checksum: uint32
    Type:
      code_hash: ckbfs v3 type script
      args: 32 bytes type_id, (...)
  <...>
```

Publish operation must satisfy following rule:

- Rule 11: in a publish operation, checksum in cell data must be equal with `hash(Witnesses[ALL_CONTENT_PARTS])`.
- Rule 12: Previous position value, previous checksum value should be all zero in `Head Witnesses`


---

#### Append

Append operation updates exist live CKBFS v3 cell, validates the latest checksum.

```yaml
// Append
Witnesses:
  <...>
  <0x434b424653, 0x03, PREVIOUS_TX_HASH_VALUE, PREVIOUS_INDEX_IN_CKBFS_V3_CELL, PREIVOUS_CHECKSUM, 0x00000002,CKBFS_CONTENT_BYTES_PART_1>
  <0x00000003, CKBFS_CONTENT_BYTES_PART_2>
  <...>
  <0x00000000, CKBFS_CONTENT_BYTES_PART_TAIL>
  <...>
Inputs:
  <...>
  CKBFS_V3_CELL
    Data:
      content-type: string
      filename: string
      index: uint32
      checksum: uint32 # previous checksum
    Type:
      code_hash: ckbfs v3 type script
      args: 32 bytes type_id, (...)
  <...>
Outputs:
  <...>
  CKBFS_V3_CELL:
    Data:
      content-type: string
      filename: string
      index: uint32
      checksum: uint32 # updated checksum
    Type:
      code_hash: ckbfs v3 type script
      args: 32 bytes type_id, (...)
```

- Rule 13: new checksum of updated CKBFS cell should be equal to:  `hasher.recover_from(previous_checksum).update(new_content_bytes)`
- Rule 14: `content-type`, `filename`, and Type args of a CKBFS cell CAN NOT be updated in ANY condition


---

#### Transfer

Transfer operation transfers ownership of a CKBFS cell, and ensure it did not lost tracking of backlinks.

```yaml
// Transfer
Witnesses:
  <...>
  <0x434b424653, 0x03, PREVIOUS_TX_HASH_VALUE, PREVIOUS_INDEX_IN_CKBFS_V3_CELL, PREIVOUS_CHECKSUM, 0x00000000>
  <...>

Inputs:
  <...>
  CKBFS_V3_CELL
    Data:
      content-type: string
      filename: string
      index: uint32
      checksum: uint32
    Type:
      code_hash: ckbfs type script
      args: 32 bytes type_id, (...)
    Lock:
      <USER_DEFINED>
  <...>
Outputs:
  <...>
  CKBFS_V3_CELL:
    Data:
      content-type: string
      filename: string
      index: uint32
      checksum: uint32
    Type:
      code_hash: ckbfs type script
      args: 32 bytes type_id, (...)
    Lock:
      <USER_DEFINED>
```

- Rule 15: The `Head Witness` should not contain any content part bytes
- Rule 16: in a transfer operation, `checksum` CAN NOT be updated


---

## Other Notes

### Molecule Definitions:

Here’s molecule definitions of CKBFS data structures

```jsx
vector Bytes <byte>;
option BytesOpt (Bytes);
option Uint32Opt (Uint32);

table CKBFSData {
  index: Uint32,
  checksum: Uint32,
  content_type: Bytes,
  filename: Bytes,
}
```