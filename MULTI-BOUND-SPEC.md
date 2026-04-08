# Multi-Bound: Shared Access to Encrypted Files

## 1. What and Why

In v1, a `.minima` file is bound to a single node — only the owner of the encrypting seed phrase can decrypt it.

**Multi-Bound (v2)** adds the ability to share access. Each recipient binds the file to their own node. Afterwards, both sender and recipient can decrypt the same file independently, on their own nodes.

**Key principle:** the file is encrypted once. The ciphertext never changes. What changes is the number of "locks" — each authorized owner holds a separate grant block for the same content.

---

## 2. Three Components

### Maxima — Transport
Built-in Minima P2P protocol with automatic E2E encryption. Delivers the grant packet (AES key + parameters) from sender to recipient.

| Criterion | Maxima | Blockchain |
|-----------|--------|-----------|
| Privacy | E2E encrypted, no one sees it | State variables are public |
| Speed | Instant | Wait for block inclusion |
| Cost | Free | Requires Minima coins |

### `.minima` File — Grant Storage
Grant blocks are embedded at the end of the file. The file becomes fully portable — USB drive, email, cloud storage. Any authorized owner decrypts it on their node with no additional data.

IndexedDB is used only as a hint cache (which block index belongs to this node) to minimize node approval requests.

### Blockchain — Optional Notary (Phase 5)
Stores only SHA-256(grantId). Used for grant revocation (SB_REVOKE). On-chain data is public, so only the hash is stored — 32 random bytes with no context.

---

## 3. v2 Binary File Format

```
Section        Field           Size     Contents
─────────────  ──────────────  ──────   ──────────────────────────────
HEADER         MAGIC           4        "MIN\0"
               VERSION         1        0x02

PRIMARY BLOCK  Challenge       32       Random bytes
               EncKeyLen       2        LE uint16
               EncKeyData      ~76      salt+iv+wrappedAESKey
               EncMetaLen      4        LE uint32
               EncMeta         ~4340    AES-GCM(addr+pk+sig+IV+tag)

CIPHERTEXT     CiphertextLen   4        LE uint32  ← new in v2
               Ciphertext      N        AES-256-GCM encrypted data

GRANT SECTION  GrantCount      2        LE uint16
               [per block]
               GrantBlockLen   4        LE uint32
               GrantChallenge  32       Recipient's random challenge
               GrantEncKeyLen  2        LE uint16
               GrantEncKeyData ~76      Recipient's wrapped AES key
               GrantEncMetaLen 4        LE uint32
               GrantEncMeta    ~4340    Recipient's encrypted metadata
```

**Changes vs v1:** `CiphertextLen` field added (v1 ciphertext extended to EOF); `GrantCount` + grant block array appended after ciphertext.

**Backward compatibility:** v2 parser reads v1 files (VERSION=1 → GrantCount=0). v1 parser rejects v2 files with "Unsupported version: 2".

**What an attacker sees:** MAGIC, VERSION, `GrantCount` (number of recipients — the only metadata leak), and encrypted blobs indistinguishable from random data.

---

## 4. Grant Packet (transmitted via Maxima)

```json
{
  "type":      "seedbound_grant",
  "version":   1,
  "fileHash":  "<SHA-256(ciphertext), hex>",
  "aesKey":    "<32-byte AES key, base64>",
  "fileIV":    "<12 bytes, base64>",
  "fileTag":   "<16 bytes, base64>"
}
```

The packet contains only what the recipient cannot derive themselves — the AES key, IV, and tag. The recipient creates their own address, signature, challenge, and KEK on their own node.

The AES key is transmitted in plaintext inside the Maxima message — this is intentional and safe: Maxima provides E2E encryption. The key is immediately re-encrypted under the recipient's seedHash after receipt.

---

## 5. Sharing Flow (Sender)

**1 node approval.**

1. Parse `.minima` file → extract ciphertext, encKeyData, encMeta
2. `seedrandom(challenge)` → seedHash **[Approve]**
3. Decrypt metadata → fileIV, fileTag
4. Decrypt AES key
5. Compute `SHA-256(ciphertext)` → fileHash
6. Send grant packet via Maxima: `maxima action:send contact:<id> application:seedbound data:<json>`
7. Zero out: aesKey, seedHash, fileIV, fileTag

---

## 6. Binding Flow (Recipient)

**2 node approvals.**

1. Receive grant packet via Maxima listener (`event === "MAXIMA"`, `application === "seedbound"`)
2. Load `.minima` file; verify `SHA-256(ciphertext) === grantPacket.fileHash`
3. `newaddress` → address, publickey
4. `sign(SHA-256(ciphertext + address))` → signature **[Approve 1]**
5. `getRandomValues(32)` → challenge; `seedrandom(challenge)` → seedHash **[Approve 2]**
6. Derive KEK_key and KEK_meta from seedHash
7. Wrap AES key → grantEncKeyData; encrypt metadata → grantEncMeta
8. Embed grant block into file (v1→v2 or v2→v2+1)
9. Download updated file
10. Zero out: aesKey, seedHash, signature, fileIV, fileTag
11. Save hint to IndexedDB: `fileHash → grantIndex`

**Why the recipient signs the ciphertext themselves:** the grant block's address must belong to the decrypting node (`checkaddress` check). Using the sender's address would fail on the recipient's node.

---

## 7. Decryption of a v2 File

1. Parse file → primaryBlock + grantBlocks[]
2. Check IndexedDB for a hint (`fileHash → index`) → try that block first
3. For each block: `seedrandom(challenge)` **[Approve]** → attempt metadata decryption
   - AES-GCM success → our block → continue
   - AES-GCM error → not our block → try next
4. `checkaddress(address)` + `verify(signature)` → pass
5. Decrypt AES key → decrypt ciphertext → original file

**Approvals:** 1 with IndexedDB hint; N (number of blocks) without hint (e.g. after node restore from seed phrase).

---

## 8. Security

| Requirement | Implementation |
|------------|---------------|
| AES key never stored in plaintext | Zeroed after use; stored in file only as encKeyData under KEK |
| AES key transmitted only via Maxima | E2E encrypted; never appears in blockchain, localStorage, or logs |
| File integrity verified at binding | `SHA-256(ciphertext) === grantPacket.fileHash` |
| Each grant block independently secured | Own W-OTS+ signature, own challenge, own KEK |
| Zero-knowledge preserved | Only challenges + GrantCount visible in file |
| Sensitive data zeroed | `_zeroFill` in `finally` blocks: aesKey, seedHash, signature, fileIV, fileTag |

**Trust model:** the sender trusts the recipient. Once a grant is issued, the recipient holds the AES key and can re-share access. This is analogous to any shared-access system (Google Drive, Dropbox). Cryptographic revocation is planned for Phase 5.

---

## 9. Development Phases

| Phase | Timeline | Deliverable |
|-------|----------|-------------|
| 1 — Maxima transport | M1 | Send/receive grant packet via Maxima; no file format changes |
| 2 — Grant binding | M1 | Recipient re-encrypts AES key under their seedHash; grant block created |
| 3 — v2 file format | M2 | Grant blocks embedded in file; fully portable `.minima` v2 |
| 4 — v2 decryption | M2 | Block iteration + IndexedDB hint; full multi-node access |
| 5 — Revocation *(future)* | Growth grant | SHA-256(grantId) on-chain; SB_REVOKE; fake-block padding to hide recipient count |
