# Seedbound — Encryption Architecture

## Overview

Seedbound is a MiniDapp for the Minima blockchain that implements quantum-resistant file encryption. Security is rooted in the node's seed phrase: without it, decryption is impossible even if the `.minima` file is obtained.

**Core principle:** only a 32-byte random `challenge` is visible in the encrypted file. All other data — encryption key, signature, IV, auth tag, address, public key — is encrypted and accessible only to the owner of the seed phrase.

---

## Cryptographic Primitives

| Primitive | Purpose | Parameters |
|-----------|---------|------------|
| **AES-256-GCM** | Symmetric file encryption | 256-bit key, 12-byte IV, 16-byte Auth Tag |
| **PBKDF2-SHA512** | Key Encryption Key (KEK) derivation | 250,000 iterations, 16-byte salt, context string |
| **W-OTS+** | Quantum-resistant file signature | ~4125-byte signature, one-time address |
| **seedrandom** (Minima) | Deterministic hash from node seed phrase | SHA-256, node-bound |
| **Web Crypto API** | All cryptographic operations | Native browser implementation, no JS libraries |

---

## 5 Security Layers

| Layer | Mechanism | What it protects |
|-------|-----------|-----------------|
| 1 — File encryption | AES-256-GCM | Content confidentiality + integrity |
| 2 — Key protection | PBKDF2-SHA512(seedHash) + AES-KW | Offline key recovery |
| 3 — Hidden metadata | All metadata encrypted under KEK_meta | Address, public key, IV, tag leakage |
| 4 — Quantum-resistant signature | W-OTS+ via Minima `sign` | File tampering + quantum attacks |
| 5 — Node binding | `seedrandom` — key derived inside node only | Offline brute-force of stolen files |

**Key separation:** two context strings — `"qcrypto-kek-v1"` and `"qcrypto-meta-v1"` — ensure KEK_key ≠ KEK_meta even with identical salt.

**Zero-knowledge:** a stolen `.minima` file reveals only 32 random bytes (the challenge) and block lengths. File type, owner identity, and all cryptographic parameters are hidden.

---

## Encryption Flow (2 node approvals)

| Step | Operation | Details |
|------|-----------|---------|
| 1 | `newaddress` | New one-time W-OTS+ address |
| 2 | Generate AES key | `crypto.subtle.generateKey("AES-GCM", 256)` + random IV |
| 3 | Encrypt file | `AES-256-GCM(aesKey, IV, file)` → ciphertext + tag |
| 4 | Sign | `sign(SHA-256(ciphertext + address))` → signature **[Approve 1]** |
| 5 | seedrandom | `getRandomValues(32)` → challenge; `seedrandom(challenge)` → seedHash **[Approve 2]** |
| 6 | Wrap key | `PBKDF2(seedHash, "qcrypto-kek-v1")` → KEK_key; `AES-KW(KEK_key, aesKey)` → encKeyData |
| 7 | Encrypt metadata | `PBKDF2(seedHash, "qcrypto-meta-v1")` → KEK_meta; `AES-GCM(KEK_meta, addr+pk+sig+IV+tag)` → encMeta |
| 8 | Assemble | Binary `.minima` v1 file |

## Decryption Flow (1 node approval)

| Step | Operation | Details |
|------|-----------|---------|
| 1 | Parse | Extract challenge, encKeyData, encMeta, ciphertext |
| 2 | seedrandom | `seedrandom(challenge)` → seedHash **[Approve 1]** |
| 3 | Decrypt metadata | KEK_meta → address, publickey, signature, fileIV, fileTag |
| 4 | Verify | `checkaddress(address)` → relevant; `verify(ciphertext, signature)` → valid |
| 5 | Decrypt key | KEK_key → unwrap aesKey |
| 6 | Decrypt file | `AES-256-GCM-decrypt(aesKey, fileIV, fileTag, ciphertext)` → original file |

---

## .minima v1 File Format

```
Offset   Size    Field         Contents
───────  ──────  ────────────  ──────────────────────────────────
0        4       MAGIC         0x4D 0x49 0x4E 0x00  ("MIN\0")
4        1       VERSION       0x01
5        32      Challenge     Random 32 bytes (only visible data)
37       2       EncKeyLen     LE uint16
39       ~76     EncKeyData    salt(16) + iv(12) + wrappedAESKey(48)
~115     4       EncMetaLen    LE uint32
~119     ~4340   EncMeta       salt(16) + iv(12) + AES-GCM(addr+pk+sig+IV+tag)
~4459    *       Ciphertext    AES-256-GCM encrypted file data
```

---

## Threat Model

| Threat | Protection | Result |
|--------|-----------|--------|
| Stolen `.minima` file | AES-256-GCM + seedrandom-locked KEK | Unreadable without seed phrase |
| File tampering | W-OTS+ signature + AES-GCM auth tag | Any modification detected |
| Brute-force AES key | 256-bit key space | 2^256 operations — infeasible |
| Brute-force KEK | PBKDF2-SHA512 × 250k + node-bound seedHash | Requires seed phrase + massive compute |
| Quantum (Grover) | SHA-512 in PBKDF2 | ~256-bit post-quantum security |
| Quantum (Shor) | W-OTS+ hash-based signature | Quantum-resistant by design |
| Metadata analysis | addr + pk + sig + IV + tag encrypted | Full zero-knowledge |
| Node loss | Deterministic recovery via seed phrase | All keys reproducible |

---

## Minima Node Commands

| Command | Purpose | Requires approval |
|---------|---------|------------------|
| `newaddress` | One-time W-OTS+ address | No |
| `sign data:HASH publickey:PK` | Sign file hash | **Yes** |
| `seedrandom modifier:"CHALLENGE"` | Derive hash from seed phrase | **Yes** |
| `checkaddress address:ADDR` | Verify address belongs to node | No |
| `verify data:HASH publickey:PK signature:SIG` | Verify W-OTS+ signature | No |
