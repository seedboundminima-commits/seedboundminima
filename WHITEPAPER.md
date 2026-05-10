# Seedbound

**Quantum-Resistant File Encryption with Multi-Node Access Grants for Minima Blockchain**

White Paper — v1.0 (May 2026)

Author: Pavel Shatia · License: MIT
Repository: https://github.com/seedboundminima-commits/seedboundminima

---

## Abstract

Seedbound is a MiniDapp for the Minima Blockchain that delivers quantum-resistant file encryption with a property no traditional encryption tool offers: **the decryption key never exists outside an active node**. Files are encrypted with AES-256-GCM and signed with W-OTS+ — Minima's native post-quantum signature — while the AES key itself is derived deterministically from the user's seed phrase via Minima's `seedrandom` primitive. The user never creates, stores, or transmits a key.

The project's signature feature is **Multi-Bound Access**: a single encrypted file can carry multiple independent grant blocks, each cryptographically tied to a different recipient's Minima node. Grants are delivered peer-to-peer over Maxima, the network's encrypted P2P transport. Sharing access does not mean sharing a key — it means issuing a cryptographic permission. The same ciphertext can be unlocked independently by sender, recipient, family member, lawyer, or backup node — each with their own key wrap and signature.

A working browser MiniDapp (v1.0.1) was publicly released on April 6, 2026, validated against a 50+ case manual test plan, and is fully open-source under the MIT license. This document describes the system in technical depth — its cryptographic foundation, file format, threat model, and roadmap toward a polished desktop product distributed via the official Minima MiniDapp Store.

---

## 1. Introduction

### 1.1 The Problem with Today's Encryption Tools

Existing encryption tools (VeraCrypt, GPG, age, OpenSSL) share three structural weaknesses:

1. **Manual key management.** Users must generate, store, back up, and transfer keys themselves. One lost key permanently destroys access; one leaked key permanently exposes content. Most users are not equipped to do this safely.

2. **The quantum horizon.** RSA-2048 and ECC P-256 — the asymmetric primitives underlying GPG, TLS, and most file-sharing systems — are vulnerable to Shor's algorithm. The transition timeline is uncertain, but data encrypted today and harvested for "decrypt later" attacks may be readable within a decade.

3. **Sharing is painful and risky.** Sending an encrypted file to a colleague typically means sending the key over a separate channel — email, messenger, password manager, or cloud share. Each of those channels is a leak surface. Most "secure file sharing" workflows degrade to "trust the channel."

The result: strong cryptography exists but is unreachable for the people who need it most — non-experts handling sensitive data.

### 1.2 What Seedbound Changes

Seedbound makes three structural moves at once:

- **Replaces user-managed keys with seed-bound derivation.** The encryption key is reproducible from the user's Minima seed phrase via the node's `seedrandom` primitive. There is no key file to lose, store, or steal.

- **Adopts a quantum-resistant primitive set.** AES-256-GCM (post-quantum-safe under Grover's algorithm), PBKDF2-SHA512 with 250 000 iterations, and W-OTS+ — a hash-based one-time signature unaffected by Shor's algorithm.

- **Replaces key sharing with grant issuing.** Instead of transmitting a key, the sender mints a grant block — an independent cryptographic envelope tied to the recipient's seed phrase. The recipient binds the grant to their own node; afterwards both parties decrypt the same file independently. The AES key is briefly transmitted over Maxima's E2E-encrypted channel and immediately re-encrypted under the recipient's seedHash on arrival; it never persists in plaintext on either end.

The result: strong cryptography that requires no key management from the user, hardened against quantum attacks, and shareable without channel risk.

---

## 2. Cryptographic Foundation

### 2.1 Primitive Set

| Primitive | Purpose | Parameters |
|-----------|---------|------------|
| AES-256-GCM | Symmetric file encryption | 256-bit key, 12-byte IV, 16-byte auth tag |
| AES-KW (RFC 3394) | Wrapping the AES file key | 256-bit KEK |
| PBKDF2-SHA512 | Deriving the KEK from seedHash | 250 000 iterations, 16-byte salt, context string |
| W-OTS+ | Quantum-resistant file signature | Native Minima `sign` primitive |
| seedrandom (Minima) | Deterministic hash from seed phrase | SHA-256, node-bound, requires user approval |
| SHA-256 | File hash for grant matching | Web Crypto |

All operations use the browser's native Web Crypto API. No third-party JavaScript cryptography is loaded.

### 2.2 The Five Security Layers

| Layer | Mechanism | Protects against |
|-------|-----------|-----------------|
| 1 — File encryption | AES-256-GCM | Content disclosure + tampering of payload |
| 2 — Key protection | PBKDF2-SHA512(seedHash) → AES-KW | Offline brute-force of stolen file |
| 3 — Hidden metadata | All metadata encrypted under separate KEK_meta | Leaking address, public key, IV, tag |
| 4 — Quantum-resistant signature | W-OTS+ via Minima `sign` | File tampering + future quantum attacks |
| 5 — Node binding | seedrandom — derivable only inside an active node | Offline decryption of stolen file even with seed phrase but no node |

**Key separation.** Two distinct context strings — `"qcrypto-kek-v1"` (for wrapping the AES key) and `"qcrypto-meta-v1"` (for encrypting metadata) — guarantee that the file-key KEK and the metadata KEK are different even when derived from the same salt and seedHash.

**Zero-knowledge property.** A stolen `.minima` file reveals only:
- 4 bytes of magic constant (`MIN\0`)
- 1 byte of version number
- 32 bytes of random challenge per grant block
- The number of grant blocks (a `uint16` count)
- The lengths of encrypted blobs

Everything else — file type, owner identity, public key, signature, IV, auth tag, recipient identities — is encrypted. An adversary cannot even tell whether two `.minima` files were created by the same user.

### 2.3 Why W-OTS+

W-OTS+ (Winternitz One-Time Signature Plus) is a hash-based signature scheme. Its security reduces to the collision-resistance of the underlying hash function (SHA-256 in Minima), making it **provably resistant to both classical and quantum adversaries** — Shor's algorithm does not threaten hash-based signatures, and Grover's algorithm only halves the effective security level (256-bit hash → ~128-bit post-quantum security).

Each Seedbound encryption uses a **fresh one-time W-OTS+ address** derived via Minima's `newaddress` command. The signature covers `SHA-256(ciphertext || address)`, so any tampering with the ciphertext is detectable at decryption time.

---

## 3. System Architecture

### 3.1 Component Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         BROWSER (MiniDapp iframe)                │
│                                                                  │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────────────┐   │
│  │  index.html │───→│   app.js (UI)    │←──→│  IndexedDB     │   │
│  │  + app.css  │    │  router, modals  │    │  (grant hints) │   │
│  └─────────────┘    └────────┬─────────┘    └────────────────┘   │
│                              │                                   │
│           ┌──────────────────┴────────────────┐                  │
│           ↓                                   ↓                  │
│  ┌────────────────────┐         ┌────────────────────────┐       │
│  │  MinimaCrypto.js   │         │    MultiBound.js       │       │
│  │ ─────────────────  │         │ ─────────────────────  │       │
│  │ AES-GCM, AES-KW,   │←────────│ v2 file format,        │       │
│  │ PBKDF2-SHA512,     │  uses   │ grant blocks, Maxima   │       │
│  │ Web Crypto, LE     │         │ messaging, IndexedDB   │       │
│  │ helpers, zeroFill  │         │ hints                  │       │
│  └─────────┬──────────┘         └──────────┬─────────────┘       │
│            │                               │                     │
│            └───────────────┬───────────────┘                     │
│                            ↓                                     │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                 mds.js (WebSocket client)                │    │
│  └──────────────────────────┬───────────────────────────────┘    │
└─────────────────────────────┼────────────────────────────────────┘
                              │ WebSocket
                              ↓
                  ┌────────────────────────────┐
                  │    LOCAL MINIMA NODE       │
                  │  ─────────────────────     │
                  │  newaddress, sign,         │
                  │  seedrandom, verify,       │
                  │  checkaddress, maxima,     │
                  │  H2 SQL (grant hint cache) │
                  └────────────────┬───────────┘
                                   │ Maxima P2P
                                   ↓
                  ┌────────────────────────────┐
                  │  RECIPIENT'S MINIMA NODE   │
                  └────────────────────────────┘
```

### 3.2 Layering Discipline

`MultiBound.js` consumes `MinimaCrypto.js` through `window.MinimaCrypto` and **never modifies it**. New cryptographic primitives are added to `MinimaCrypto.js`; multi-bound logic remains in `MultiBound.js`. This separation means that an external auditor reviewing the cryptographic core has a clearly bounded surface to inspect.

`mds.js` is an unmodified vendor library (Minima MDS WebSocket client v2.1.0). All node interaction flows through it.

### 3.3 No Server, No External Dependencies

Seedbound is a static MiniDapp. It runs entirely in the browser of the local Minima node. There is no backend, no external API, no external CDN. All cryptography uses the browser's native Web Crypto API. The result: nothing to host, nothing to monitor, nothing to compromise upstream.

---

## 4. File Format Specification

### 4.1 v1 (Single-Owner)

```
Offset   Size    Field          Contents
───────  ──────  ─────────────  ─────────────────────────────────────
0        4       MAGIC          0x4D 0x49 0x4E 0x00  ("MIN\0")
4        1       VERSION        0x01
5        32      Challenge      Random 32 bytes
37       2       EncKeyLen      LE uint16
39       ~76     EncKeyData     salt(16) + iv(12) + wrappedAESKey(48)
~115     4       EncMetaLen     LE uint32
~119     ~4340   EncMeta        salt(16) + iv(12) +
                                AES-GCM(addr + pubkey + sig + IV + tag)
~4459    *       Ciphertext     AES-256-GCM-encrypted file (to EOF)
```

All multi-byte integers are little-endian.

### 4.2 v2 (Multi-Bound)

```
Section        Field           Size    Contents
─────────────  ──────────────  ──────  ────────────────────────────────
HEADER         MAGIC           4       "MIN\0"
               VERSION         1       0x02

PRIMARY BLOCK  Challenge       32      Owner's random challenge
               EncKeyLen       2       LE uint16
               EncKeyData      ~76     salt + iv + wrappedAESKey
               EncMetaLen      4       LE uint32
               EncMeta         ~4340   AES-GCM(addr + pk + sig + IV + tag)

CIPHERTEXT     CiphertextLen   4       LE uint32  ← NEW IN v2
               Ciphertext      N       AES-256-GCM ciphertext

GRANT SECTION  GrantCount      2       LE uint16  (number of recipients)
               [GrantBlock × GrantCount]:
               GrantBlockLen   4       LE uint32
               GrantChallenge  32      Recipient's random challenge
               GrantEncKeyLen  2       LE uint16
               GrantEncKeyData ~76     Recipient's wrapped AES key
               GrantEncMetaLen 4       LE uint32
               GrantEncMeta    ~4340   Recipient's encrypted metadata
```

**Compatibility.** A v2 parser handles v1 files transparently (VERSION=1 → GrantCount=0). A v1 parser refuses v2 files with `Unsupported version: 2`. Files only ever upgrade in one direction (v1 → v2 by appending grant blocks); v2 → v1 is neither possible nor needed.

**Observability.** A passive observer of a v2 `.minima` file learns: it is a Seedbound file (magic), it is multi-bound (version 2), how many grants it carries (`GrantCount`). Nothing else — every other byte is random or pseudorandom under AES-GCM.

---

## 5. Multi-Bound Grant System

### 5.1 Three Components

**Maxima — transport.** Minima's built-in P2P protocol with automatic E2E encryption. Delivers the grant packet from sender to recipient. Maxima provides privacy (E2E), latency (instant), and zero cost — properties the public blockchain cannot match for ephemeral key exchange.

**`.minima` file — grant storage.** Grant blocks are embedded directly in the file. The file becomes fully portable — USB, email, cloud storage. A recipient with the right seed phrase running on a Minima node can decrypt the file with no additional data.

**IndexedDB — hint cache.** A local SQL table (Minima's H2 engine) maps `fileHash → grantIndex`. On subsequent decryptions the correct grant block is tried first, reducing user approvals from N to 1. The hint is a performance cache only — losing it does not lose access.

### 5.2 Grant Packet (over Maxima)

```json
{
  "type":      "seedbound_grant",
  "version":   1,
  "fileHash":  "<hex SHA-256(ciphertext)>",
  "aesKey":    "<base64 32-byte AES key>",
  "fileIV":    "<base64 12-byte IV>",
  "fileTag":   "<base64 16-byte auth tag>"
}
```

The packet contains only the data the recipient cannot compute themselves. The recipient generates their own W-OTS+ address, signature, challenge, and KEK on their own node. The AES key travels in plaintext **inside** the Maxima envelope — this is intentional and safe: Maxima's transport is end-to-end encrypted between nodes. On receipt the AES key is immediately re-encrypted under the recipient's seedHash and zero-filled in JS memory.

### 5.3 Sharing Flow (1 sender approval)

1. Parse `.minima` file → ciphertext, encKeyData, encMeta
2. `seedrandom(challenge)` → seedHash **[user approval]**
3. Decrypt sender's metadata → fileIV, fileTag
4. Decrypt AES key
5. Compute `fileHash = SHA-256(ciphertext)`
6. Send grant packet over Maxima: `maxima action:send publickey:<recipient> application:seedbound data:<json>`
7. Zero-fill: aesKey, seedHash, fileIV, fileTag

### 5.4 Binding Flow (2 recipient approvals)

1. Receive grant packet via Maxima listener (`event=MAXIMA, application=seedbound`)
2. Load `.minima` file; verify `SHA-256(ciphertext) === grantPacket.fileHash`
3. `newaddress` → recipient's W-OTS+ address, public key
4. `sign(SHA-256(ciphertext || address))` → recipient's signature **[approval 1]**
5. `getRandomValues(32)` → challenge; `seedrandom(challenge)` → recipient's seedHash **[approval 2]**
6. Derive KEK_key, KEK_meta from seedHash
7. Wrap AES key → grantEncKeyData; encrypt metadata → grantEncMeta
8. Append grant block to file (v1 → v2 or v2 → v2 + 1 block)
9. Save hint to IndexedDB: `fileHash → grantIndex`
10. Zero-fill: aesKey, seedHash, signature, fileIV, fileTag

The recipient signs the ciphertext themselves rather than relying on the sender's signature: the grant block's address must belong to the recipient's node (`checkaddress` validation). Using the sender's address would fail on the recipient's node.

### 5.5 Decryption of a v2 File (1 to N approvals)

1. Parse file → primary block + grantBlocks[]
2. Look up IndexedDB hint (`fileHash → grantIndex`); if found, try that block first
3. For each block (in hint-first order):
   - `seedrandom(challenge)` **[approval]**
   - Attempt metadata decryption under derived KEK_meta
   - AES-GCM auth-tag success → this is our block; continue
   - AES-GCM error → not our block; try next
4. `checkaddress(address)` → confirms the address is ours
5. `verify(ciphertext, signature, publicKey)` → confirms file integrity
6. Unwrap AES key under KEK_key
7. AES-256-GCM-decrypt(aesKey, fileIV, fileTag, ciphertext) → original file

With a hint, decryption requires 1 approval. Without a hint (e.g., after a node restore from seed phrase), it requires up to N approvals — but the file is still fully recoverable.

---

## 6. Threat Model

| Threat | Defence | Outcome |
|--------|---------|---------|
| Stolen `.minima` file | AES-256-GCM, key wrapped under seed-bound KEK | Unreadable without seed phrase + active node |
| File tampering | W-OTS+ signature + AES-GCM auth tag | Any modification rejected at decryption |
| Brute-force AES key | 256-bit key space | 2^256 — infeasible |
| Brute-force KEK | PBKDF2-SHA512 × 250 000, salted | Massive compute even with seed phrase |
| Quantum (Grover) | SHA-512 in PBKDF2, AES-256 | ~256/128-bit post-quantum margin |
| Quantum (Shor) | W-OTS+ hash-based signature; no RSA/ECC | Quantum-resistant by primitive choice |
| Metadata leak | Address, public key, signature, IV, tag all encrypted | Only random-looking bytes visible |
| Node loss | Deterministic regeneration from seed phrase | All keys reproducible on a fresh node |
| Recipient compromise | Trust model: granted = revealed | Revocation planned in M2 |
| MITM on grant transport | Maxima E2E encryption | Grant packet protected in transit |

**Operational hygiene.** All sensitive material — seedHash, raw AES keys, signatures, IVs, auth tags — is overwritten via `_zeroFill` in `finally` blocks. Even if the JS engine retains process memory, the sensitive byte ranges are scrubbed deterministically after use.

---

## 7. Use Cases

| User | Need | How Seedbound delivers |
|------|------|------------------------|
| Lawyer ↔ client | Confidential documents with court-grade integrity | Encrypted contract; grant block to client's node; W-OTS+ signature proves no tampering |
| Journalist ↔ source | Off-the-record material; cannot leak even if device seized | File only decryptable on journalist's node; seed phrase never written down |
| Medical practice | Patient records with regulatory archival | Multi-bound grants for the doctor + secondary backup node |
| Crypto holder | Long-term storage of sensitive recovery data | Self-grant a backup-node block; recover from any of N nodes |
| SMB co-founders | Shared secrets (cap table, contracts, keys) | Single ciphertext, N grants — each founder unlocks independently |
| Family | Wills, estate documents, sensitive memorabilia | Add grants for family members' nodes; no key handover, no centralized vault |

---

## 8. Why Minima Specifically

Three properties of the Minima blockchain make Seedbound viable and make Minima the only blockchain platform on which it could be built today at this level of accessibility:

1. **Always-on, lightweight nodes.** Minima nodes run on phones and laptops. The "node must be online" requirement is realistic, not a barrier.

2. **Native quantum-resistant primitives.** W-OTS+ signatures are built into the protocol. No external library, no parameter tuning, no version drift.

3. **Maxima — built-in P2P transport.** E2E encrypted, free, instant. The grant packet does not need to traverse SMTP, Slack, or any third-party messaging service. Privacy and reliability come from the protocol itself.

A traditional blockchain (Ethereum, Bitcoin) cannot deliver the same architecture: state is public, transactions cost money, and there is no built-in encrypted P2P layer. The seedrandom primitive that anchors Seedbound's whole "key never leaves the node" property has no equivalent on other chains.

---

## 9. Token Model & Future Monetization

**Today (v1.0.1):** No token. The MiniDapp is fully free, MIT-licensed, and self-hostable. Users only need a Minima node — which they already run — to use it.

**Growth phase (post-grant):** A planned NFT-based licensing model will mint per-seat licenses on Minima itself. NFTs will gate **advanced features** — bulk encryption, multi-account management, enterprise audit logs — while leaving the core encrypt/decrypt/share flow free forever. License NFTs are tradable on Minima, creating direct token activity within the ecosystem and providing sustainable funding for ongoing development.

This separation — free core + paid advanced tier — keeps Seedbound accessible to individual users (the privacy-conscious demographic the project most wants to serve) while creating a real on-chain revenue model that grows with adoption.

The Kickstarter grant requested in this proposal does **not** depend on the licensing model and does not fund any tokenomics work. NFT licensing belongs to a future Growth-phase grant proposal once the desktop product is in market.

---

## 10. Roadmap

**Six months, three milestones.**

| Phase | Period | Deliverables |
|-------|--------|--------------|
| **M1 — Core Stabilization & UX** | Months 0–2 | Enhanced UI/UX, batch file encryption, demo video, full documentation, cryptographic unit-test suite (binary parser roundtrip v1+v2, LE helpers, encrypt/decrypt cycle, grant block append, malformed-input handling) targeting ≥80% line coverage in `MinimaCrypto.js` and `MultiBound.js` |
| **M2 — Advanced Multi-Bound Features** | Months 2–4 | Improved grant management UI, access revocation, time-limited grants, backup-node setup wizard (one-click grant to a user's own secondary node), large-file optimizations |
| **M3 — Desktop MVP + Store Publication** | Months 4–6 | Standalone Tauri desktop app (removes ~100 MB browser memory limit; direct filesystem integration), official publication on the Minima MiniDapp Store |

Each milestone is independently shippable. M1 delivers a polished, well-tested v1.x browser MiniDapp; M2 expands the multi-bound feature set; M3 brings Seedbound into the official Store and onto the desktop.

---

## 11. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Browser memory caps file size at ~100 MB | M3 desktop (Tauri) removes the limit |
| User loses seed phrase + all bound nodes → unrecoverable file | M2 backup-node wizard; documentation emphasizes self-grant for recovery |
| Maxima delivery delay if recipient is offline | Grants are persistent in the file once bound; not time-sensitive after delivery |
| Silent regression in binary file format = lost user data | M1 unit-test suite locks parser/serializer behaviour, including malformed-input cases |
| No external security audit yet | Planned in Growth-phase grant; codebase fully open-source for community review now |

---

## 12. Comparison with Existing Solutions

| Property | VeraCrypt | GPG | age | **Seedbound** |
|----------|-----------|-----|-----|--------------|
| Quantum-resistant signatures | ✗ | ✗ (RSA/ECC) | ✗ | **✓ (W-OTS+)** |
| Key never leaves the user | partial | ✗ (private key file) | ✗ (private key file) | **✓ (seed-derived, node-bound)** |
| Multi-recipient without key sharing | ✗ | partial (re-encrypt per recipient) | partial | **✓ (independent grant blocks)** |
| P2P encrypted key delivery | ✗ | ✗ (manual transport) | ✗ | **✓ (Maxima)** |
| Zero-knowledge file format | ✗ | leaks recipient list | leaks recipient count | **near-total** (only grant count visible) |
| User-managed key files | ✓ (the problem) | ✓ | ✓ | **✗** (no key files exist) |
| Open source | ✓ | ✓ | ✓ | **✓** |

---

## 13. Conclusion

Seedbound is a working browser MiniDapp today (v1.0.1, April 2026) that demonstrates a different way of doing file encryption: one where the user manages no keys, the underlying primitives are quantum-resistant by construction, and sharing access does not mean sharing a key. The Multi-Bound grant system — enabled by Minima's seedrandom primitive and Maxima's encrypted P2P transport — has no direct equivalent on any other blockchain platform.

The Kickstarter grant funds a six-month effort to take v1.0.1 from a working proof-of-concept to a production-quality desktop product distributed through the official Minima MiniDapp Store, with the testing rigor and feature completeness required for non-technical users to safely entrust their sensitive data to it.

The codebase is MIT-licensed and openly auditable. The architecture is documented in detail. The cryptographic primitives are standard and reviewable. There is nothing hidden, nothing proprietary, and no centralized service to compromise — by design.

---

## References & Resources

- **Repository**: https://github.com/seedboundminima-commits/seedboundminima
- **MiniDapp Store JSON**: https://raw.githubusercontent.com/seedboundminima-commits/seedboundminima/master/seedbound-store.json
- **Architecture document**: ARCHITECTURE.md
- **Multi-Bound specification**: MULTI-BOUND-SPEC.md
- **Test plan**: TESTING.md (50+ manual test cases)
- **Demo video**: _(to be linked once published)_

**External references:**
- Minima MDS documentation: https://docs.minima.global/
- W-OTS+ specification: Hülsing, "W-OTS+ — Shorter Signatures for Hash-Based Signature Schemes" (PQCrypto 2013)
- AES-KW (RFC 3394): https://www.rfc-editor.org/rfc/rfc3394
- PBKDF2 (RFC 8018): https://www.rfc-editor.org/rfc/rfc8018
