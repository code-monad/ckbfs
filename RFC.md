# CKBFS Protocol

`CKBFS` is a protocol defined in order to describe a witnesses based file storage system. With CKBFS, one can:

- Store files on Nervos CKB Network
- Publish large files that may exceed block size limitation(~500kb), across multiple blocks, while still keep the index and retrieve action simple and straight

It contains:

- A hasher binary that uses [Adler-32 checksum algorithm](https://en.wikipedia.org/wiki/Adler-32)
- A type script contract that applies restrictions to avoid invalid file publication

## Core Concepts

Core concepts of  CKBFS is:

- One single cell(called CKBFS cell) to index one file, even multi-part file that split across blocks.
- **Permanent** storage. Deletion is **forbidden** through contract, which means the file metadata will never lost. Which also means you will need to lock some CKB capacity **FOREVER** in order to create it.
- Simple cell structure, encoded with molecule.
- Built-in checksum provided, both on-chain and off-chain side.

# The Protocol - or, the standard

## Data Structure

### CKBFS Cell

CKBFS Cell is a cell that stores:

A CKBFS cell in should looks like following:

```yaml
Data:
  content_type: Bytes # String Bytes
  filename: Bytes # String Bytes
  indexes: Vec<Uint32> # referenced witnesses index.
  checksum: Uint32 # Adler32 checksum
  backlinks: Vec<BackLink>

Type:
  hash_type: "data1"
  code_hash: CKBFS_TYPE_DATA_HASH
  args: <TypeID, 32 bytes>,[<hasher_code_hash>, optional]
Lock:
  <user_defined>
```

The following rules should be met in a CKBFS cell:

- Rule 1: data structure of a CKBFS cell is molecule encoded. See [Molecule](https://github.com/nervosnetwork/molecule) definitions below.
- Rule 2: checksum must match with specified witnesses. Default checksum algorithm will be Alder32 if not specify `hasher_code_hash` in Type script args.
- Rule 3: if backlinks(see definition below) of a CKBFS cell is not empty, it means file was stored across blocks.
- Rule 4: if `hasher_code_hash` is specified, then it will use hasher binary from CellDeps that matches `code_hash`, with same input parameter.
- Rule 5: Once created, a CKBFS cell can only be updated/transfered, which means it can not be destroyed.
- UPDATES IN VERSION 2: `indexes` is a vector of witness indexes, stored CKBFS structured contents in splited witnesses.

---

### BackLink

BackLink stands for the prefix part of a living CKBFS cell.  The strategy of CKBFS is similar to a linked list:

[backlink]←[backlink]←[…]←[CKBFS cell]

```yaml
BackLink:
  tx_hash: Bytes,
  indexes: Vec<Uint32>,
  checksum: Uint32,
```

---

### Witnesses

File contents are stored in witnesses. In a single transaction, witnesses can be splitted into multiple parts and concat together while verification. 

```yaml
Witnesses:
  <"CKBFS"><0x00><CONTENT_BYTES>
```

The following rules should be met for witnesses used in CKBFS:

- Rule 6: The first 5 bytes must be UTF8 coded string bytes of `CKBFS`, which should be: `0x434b424653`
- Rule 7: The 6th byte of witnesses must be the version of CKBFS protocol, which should be: `0x00`.
- Rule 8: File contents bytes are stored from 7th byte. Checksum hasher should also take bytes from `[7…]`.
- UPDATES IN VERSION 2: Every parts of the splitted content stored in witnesses must follow Rule 6 to Rule 8.

---

## Operations

This section describes operations and restrictions in CKBFS implementation

### Publish

Publish operation creates one or more new CKBFS cell.

```yaml
// Publish
Witnesses:
  <...>
  <0x434b424653, 0x0, CKBFS_CONTENT_BYTES>
  <...>
Inputs:
  <...>
Outputs:
  <vec> CKBFS_CELL
    Data:
      content-type: string
      filename: string
      indexes: vec<uint32>
      checksum: uint32
      backlinks: empty_vec
    Type:
      code_hash: ckbfs type script
      args: 32 bytes type_id, (...)
  <...>
```

Publish operation must satisfy following rule:

- Rule 9: in a publish operation, checksum must be equal with `hash(Witnesses[index])`.

---

### Append

Append operation updates exist live CKBFS cell, validates the latest checksum.

```yaml
// Append
Witnesses:
  <...>
  <CKBFS_CONTENT_BYTES>
  <...>
Inputs:
  <...>
  CKBFS_CELL
    Data:
      content-type: string
      filename: string
      indexes: vec<uint32>
      checksum: uint32
      backlinks: empty_vec
    Type:
      code_hash: ckbfs type script
      args: 32 bytes type_id, (...)
  <...>
Outputs:
  <...>
  CKBFS_CELL:
    Data:
      content-type: string
      filename: string
      indexes: vec<uint32>
      checksum: uint32 # updated checksum
      backlinks: vec<BackLink>
    Type:
      code_hash: ckbfs type script
      args: 32 bytes type_id, (...)
```

- Rule 10: backlinks field of a CKBFS cell can only be appended. Once allocated, all records in the vector can not be modified.
- Rule 11: new checksum of updated CKBFS cell should be equal to:  `hasher.recover_from(old_checksum).update(new_content_bytes)`
- Rule 12: `content-type`, `filename`, and Type args of a CKBFS cell CAN NOT be updated in ANY condition
- Rule 13: in an append operation, Output CKBFS Cell’s `indexes` can not be `empty`

---

### Transfer

Transfer operation transfers ownership of a CKBFS cell, and ensure it did not lost tracking of backlinks.

```yaml
// Transfer
Witnesses:
  <...>
Inputs:
  <...>
  CKBFS_CELL
    Data:
      content-type: string
      filename: string
      index: uint32
      checksum: uint32
      backlinks: empty_vec
    Type:
      code_hash: ckbfs type script
      args: 32 bytes type_id, (...)
    Lock:
      <USER_DEFINED>
  <...>
Outputs:
  <...>
  CKBFS_CELL:
    Data:
      content-type: string
      filename: string
      index: null
      checksum: uint32 # updated checksum
      backlinks: vec<BackLink>
    Type:
      code_hash: ckbfs type script
      args: 32 bytes type_id, (...)
    Lock:
      <USER_DEFINED>
```

- Rule 14: in a transfer operation, Output CKBFS Cell’s `indexes` must be empty
- Rule 15: if Input CKBFS Cell’s backlinks is empty, then output’s backlink should be append following Rule 10. Otherwise, the backlinks should not be updated
- Rule 16: in a transfer operation, `checksum` CAN NOT be updated

---

## Other Notes

### Molecule Definitions:

Here’s molecule definitions of CKBFS data structures

```jsx
vector Bytes <byte>;
option BytesOpt (Bytes);
option Uint32Opt (Uint32);
vector Indexes <index>;

table BackLink {
  tx_hash: Bytes,
  index: Indexes,
  checksum: Uint32,
}

vector BackLinks <BackLink>;

table CKBFSData {
  index: Indexes,
  checksum: Uint32,
  content_type: Bytes,
  filename: Bytes,
  backlinks: BackLinks,
}
```

### Checksum Validator Procedure:

Bellow is pseudocodes shows how one can validates the checksum:

```pascal
function validate_checksum(witness, expected_checksum, backlinks);
var
  hasher: thasher;
  computed_checksum: uint32;
  content_bytes: bytes;
  last_backlink: backlink;
begin
  // If backlinks is not empty, recover hasher state from the last backlink's checksum
  if length(backlinks) > 0 then
  begin
    last_backlink := backlinks[length(backlinks) - 1];
    hasher.recover(last_backlink.checksum);
  end;

  // Extract the content bytes from the witness starting from the 7th byte
  content_bytes := copy(witness, 7, length(witness) - 6);
  
  // Update the hasher with the content bytes
  hasher.update(content_bytes);

  // Finalize and compute the checksum
  computed_checksum := hasher.finalize;
  
  // Compare the computed checksum with the expected checksum
  if computed_checksum = expected_checksum then
    validate_checksum := true
  else
    validate_checksum := false;
end;

```

### Advanced Usage - Branch Forking File Appendix

Assuming that we have created a CKBFS Cell:

```yaml
CKBFS_CELL:
  Data:
    content-type: string
    filename: string
    indexes: [0x0]
    checksum: 0xFE02EA11
    backlinks: [BACKLINK_1, BACKLINK_2, ...]
  Type:
    code_hash: CKBFS_CODE_HASH
    args: TYPE_ID_A
  Lock:
    <USER_DEFINED>
```

It is able to creating a forking of this CKBFS by a special publish, similar to append but put the referenced CKBFS Cell in CellDeps:

```yaml
CellDeps:
  <...>
  CKBFS_CELL:
	  Data:
	    content-type: string
	    filename: string
	    indexes: [0x0]
	    checksum: 0xFE02EA11
	    backlinks: [BACKLINK_1, BACKLINK_2, ...]
	  Type:
	    code_hash: CKBFS_CODE_HASH
	    args: TYPE_ID_A
	  Lock:
	    <USER_DEFINED>
	<...>
Witnesses:
  <...>
  <CKBFS_CONTENT_BYTES>
  <...>
Inputs:
  <...>
Outputs:
  <...>
  CKBFS_CELL
    Data:
      content-type: string
      filename: string
      indexes: [uint32]
      checksum: UPDATED_CHECKSUM
      backlinks: [BACKLINK_1, BACKLINK_2, ...]
    Type:
      code_hash: ckbfs type script
      args: TYPE_ID_B
  <...>
```

And we are able to create a variant versions from a same reference data, allowing us to achieve something like git branching, shared-header data, etc.
