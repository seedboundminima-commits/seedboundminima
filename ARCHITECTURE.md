# MinimaCrypto v1 — Encryption Architecture

## Overview

MinimaCrypto v1 is a MiniDapp for the Minima blockchain that implements quantum-resistant file encryption. Protection is based on the node's seed phrase: without it, decryption is impossible even if the `.minima` file is available.

**Principle:** only the 32-byte `challenge` is visible in the encrypted file. All other data (encryption key, signature, IV, tag, address, public key) is encrypted and accessible only to the owner of the seed phrase.

---

## Cryptographic Primitives Used

| Primitive | Purpose | Parameters |
|---|---|---|
| **AES-256-GCM** | Symmetric file encryption | 256-bit key, 128-bit IV, 128-bit Auth Tag |
| **PBKDF2-SHA512** | KEK derivation from seedHash | 250,000 iterations, 128-bit salt, context string |
| **W-OTS+** (Winternitz One-Time Signature) | Quantum-resistant file signature | ~4125 bytes signature, one-time address |
| **seedrandom** (Minima) | Deterministic hash generation from seed phrase + modifier | SHA-256 hash, depends on node's seed phrase |
| **SHA-256** | Hashing data before signing | 256-bit hash |
| **Web Crypto API** | All cryptographic operations in the browser | Native implementation, no JS libraries |

---

## Security Layers

### Layer 1: Data Encryption (AES-256-GCM)
- The file is encrypted with a random 256-bit AES key
- GCM mode provides confidentiality + data integrity
- 128-bit Authentication Tag guarantees detection of any modifications
- Without the AES key, brute-force requires: 2^256 operations

### Layer 2: Key Protection (seedrandom + PBKDF2-SHA512)
- AES key is wrapped via KEK_key
- `KEK_key = PBKDF2-SHA512(seedHash, "qcrypto-kek-v1" + salt, 250k)`
- `seedHash` is the result of `seedrandom(challenge)` on the Minima node
- Without seed phrase → different seedHash → different KEK → AES key cannot be extracted
- PBKDF2-SHA512 with 250k iterations slows brute-force + provides ~256 bits of quantum security

### Layer 3: Hidden Metadata (full zero-knowledge)
- Address, public key, signature, FileIV and FileTag are encrypted via KEK_meta
- `KEK_meta = PBKDF2-SHA512(seedHash, "qcrypto-meta-v1" + salt, 250k)`
- Context strings `"qcrypto-kek-v1"` and `"qcrypto-meta-v1"` guarantee KEK_key ≠ KEK_meta even with matching salt
- The `.minima` file reveals nothing about which address/key/IV/tag was used
- Without seed phrase, metadata is inaccessible

### Layer 4: Quantum-Resistant Signature (W-OTS+)
- Each file is signed with a one-time W-OTS+ key via Minima
- The signature is bound to the specific ciphertext + address
- During decryption the signature is verified — guarantees the file has not been modified
- W-OTS+ is resistant to quantum computer attacks (hash-based signature)
- One-time key usage — each file gets a new address

### Layer 5: Node Binding
- During decryption, `checkaddress` is checked — the address must belong to the node
- The file can only be decrypted on a node with the same seed phrase
- Backing up the seed phrase = backing up access to all files

---

## Encryption Process (7 steps)

```
File → .minima (2 approvals in node)
```

| Step | Operation | Details |
|---|---|---|
| 1 | `newaddress` | A new one-time W-OTS+ address is created (address + publickey) |
| 2 | AES key generation | `crypto.subtle.generateKey("AES-GCM", 256)` + random IV (16 bytes) |
| 3 | File encryption | `AES-256-GCM(aesKey, IV, file)` → ciphertext + tag (16 bytes) |
| 4 | W-OTS+ signature | `sign(SHA-256(ciphertext + address), publickey)` → signature (~4125 bytes). **Approve 1** |
| 5 | seedrandom | Generate 32 random bytes (challenge). `seedrandom(challenge)` → seedHash (32 bytes). **Approve 2** |
| 6 | Key wrapping | `PBKDF2-SHA512(seedHash, "qcrypto-kek-v1" + salt, 250k)` → KEK_key. `AES-GCM-wrap(KEK_key, aesKey)` → encKeyData |
| 6.5 | Metadata encryption | `PBKDF2-SHA512(seedHash, "qcrypto-meta-v1" + salt2, 250k)` → KEK_meta. `AES-GCM(KEK_meta, address + publickey + signature + fileIV + fileTag)` → encMeta |
| 7 | File assembly | All components are assembled into the binary `.minima` v1 format |

---

## Decryption Process (5 steps)

```
.minima → File (1 approval in node)
```

| Step | Operation | Details |
|---|---|---|
| 1 | Parsing | Extract challenge, encKeyData, encMeta, ciphertext |
| 2 | seedrandom | `seedrandom(challenge)` → same seedHash. **Approve 1** |
| 3 | Metadata decryption | KEK_meta from seedHash → decrypt → address, publickey, signature, fileIV, fileTag |
| 3.5 | Address verification | `checkaddress(address)` → `relevant: true` (address belongs to node) |
| 3.6 | Signature verification | `verify(SHA-256(ciphertext + address), publickey, signature)` → "Signature valid" |
| 4 | Key decryption | KEK_key from seedHash → unwrap AES key |
| 5 | File decryption | `AES-256-GCM-decrypt(aesKey, fileIV, fileTag, ciphertext)` → original file |

---

## .minima v1 File Format

```
Offset  Size     Field             Contents
──────  ───────  ────────────────  ──────────────────────────
0       4        MAGIC             0x4D 0x49 0x4E 0x00 ("MIN\0")
4       1        VERSION           0x01
5       32       Challenge         Random 32 bytes (the only visible data)
37      2        EncKeyLen         Length of encKeyData (LE uint16)
39      ~76      EncKeyData        salt(16) + iv(12) + wrappedAESKey(48)
~115    4        EncMetaLen        Length of encMeta (LE uint32)
~119    ~4340    EncMeta           salt(16) + iv(12) + AES-GCM(addr + pk + sig + IV + tag)
~4459   *        Ciphertext        AES-256-GCM encrypted file data
```

**What is visible without seed phrase:** MAGIC, VERSION, Challenge (32 bytes of random data), block lengths, encrypted blobs. No useful information.

**What is hidden:** AES key, FileIV, FileTag, W-OTS+ signature (~4125 bytes), address (66 characters), public key (66 characters), file contents.

---

## Threat Model

| Threat | Protection | Outcome |
|---|---|---|
| Interception of `.minima` file | AES-256-GCM + seedrandom-locked KEK | Without seed phrase, data cannot be extracted |
| File tampering | W-OTS+ signature + AES-GCM auth tag | Any modification is detected |
| Brute-force AES key | 256-bit key (2^256 space) | Computationally infeasible |
| Brute-force KEK | PBKDF2-SHA512 250k + seedrandom + context | Slows attack + requires seed phrase |
| Quantum computer (Grover) | SHA-512 in PBKDF2 → ~256 bits of quantum security | Resistant |
| Quantum computer (Shor) | W-OTS+ (hash-based, quantum-resistant) | Resistant |
| Metadata analysis | addr + pk + sig + IV + tag are encrypted | Full zero-knowledge |
| KEK_key and KEK_meta collision | Context strings `"qcrypto-kek-v1"` / `"qcrypto-meta-v1"` | Impossible even theoretically |
| Node loss | Recovery via seed phrase | All addresses and seedrandom are reproducible |

---

## Dependencies

- **Minima Node** — blockchain node with W-OTS+ signatures and `seedrandom`
- **MDS (MiniDapp System)** — WebSocket API for interacting with the node
- **Web Crypto API** — native cryptographic primitives of the browser (AES, SHA-512, PBKDF2)
- **No external libraries** — all cryptography via standard APIs

---

## Minima Commands

| Command | When | Requires approve |
|---|---|---|
| `newaddress` | Creating a one-time W-OTS+ address | No |
| `sign data:HASH publickey:PK` | Signing the file hash | Yes |
| `seedrandom modifier:"CHALLENGE"` | Deriving hash from seed phrase | Yes |
| `checkaddress address:ADDR` | Checking that address belongs to node | No |
| `verify data:HASH publickey:PK signature:SIG` | Verifying W-OTS+ signature | No |

---

## Summary

- **Encryption:** 2 confirmations in node (sign + seedrandom)
- **Decryption:** 1 confirmation in node (seedrandom)
- **Quantum resistance:** W-OTS+ signature (hash-based) + PBKDF2-SHA512 (~256 bits of quantum security)
- **Node binding:** seedrandom is deterministic from seed phrase
- **Zero-knowledge:** only 32 random bytes (challenge) are visible in the file — no IV, no tag, no metadata
- **Key separation:** context strings guarantee KEK_key ≠ KEK_meta
