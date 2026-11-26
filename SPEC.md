# Secret Vault `.vlt` format and Phase 1 behavior

## Container layout

All integers in the container are unsigned little-endian values.

| Region | Length | Contents |
| --- | ---: | --- |
| Header | 8 bytes | `VLT1`, version `u16` (currently 1), flags `u16` |
| Key slots | 4 × 78 bytes | Four equal-size password slots |
| Data | Variable | Append-only `[12-byte nonce][AES-256-GCM ciphertext and 16-byte tag]` records |
| Encrypted index | Variable | AES-256-GCM encrypted JSON `VaultEntry[]` |
| Footer | 20 bytes | Index offset `u64`, index length `u64`, `1TLV` |

The fixed header and slot region is 320 bytes. A slot contains a 16-byte Argon2 salt, a 12-byte AES-GCM nonce, and 50 bytes of authenticated ciphertext. Its plaintext is a two-byte role/mode discriminator and the 32-byte random master key. Slot roles and disguise modes are confidential because they are inside the authenticated ciphertext. The main password occupies one slot; an optional self-destruct password occupies one; all remaining slots are generated with the operating-system CSPRNG. Dummy slots are indistinguishable random bytes and have the same size.

The index contains relative entry names and the offset and total length of each encrypted record. The index and content records use the master key and distinct fixed associated-data labels. Entries are appended before a fresh encrypted index and footer; older index copies and deleted content remain encrypted until compaction. Opening reads the header, fixed slots, and current index only. Reading a selected entry decrypts it into a zeroizing memory buffer and never writes plaintext to a temporary file.

## Cryptographic parameters

- Content and metadata: AES-256-GCM; each record has a fresh 96-bit nonce.
- Password wrapping: Argon2id v=19.3, 19 MiB memory, two iterations, one lane, with a fresh 128-bit salt per populated slot.
- Master/wrapping keys and decrypted buffers are held in zeroizing buffers.
- Unsupported versions, malformed offsets, authentication failures, and invalid index references are rejected.
- Authentication failures wait at least 500 ms. A valid self-destruct password overwrites the 320-byte header/slot prefix with operating-system random bytes, calls `sync_all`, then unlinks the container. Error-disguise mode returns the same generic invalid-password error; decoy mode returns an empty, read-only in-memory vault.
- Main and self-destruct passwords are rejected when their trimmed, lowercased forms are identical or within one edit operation.

Secure overwrite is best-effort on storage that remaps writes, uses journaling, snapshots, backups, or copy-on-write. Removing a vault does not guarantee erasure of older filesystem or device-level copies.

## Browser preview and mock

The browser-only client is selected when `window.__TAURI_INTERNALS__` is absent. It keeps demo content in memory (`test` opens the sample Markdown and HTML; `burn` exercises the selected self-destruct response). Tauri commands are accessed only through `src/vaultClient.ts`.

HTML and Markdown are displayed in an iframe with an empty `sandbox` attribute. The preview document also applies a restrictive CSP (`default-src 'none'`, no connections, forms, nested frames, or objects); Markdown text is HTML-escaped before formatting. The iframe has no script or same-origin permissions.

## Phase 1 scope

The initial UI supports opening/creating a vault, adding and deleting text files, searching names, isolated previews, locking, and compacting. The index supports hierarchical relative names; drag/drop, binary file handling, folder-management actions, password rotation, and recovery are outside Phase 1.
