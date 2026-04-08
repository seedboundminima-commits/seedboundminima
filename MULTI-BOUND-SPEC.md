# Multi-Bound: Shared Access to Encrypted Files

## Technical Specification and Development Plan

---

## 1. What We Are Building and Why

Currently (v1), a `.minima` file is bound to a single node. Only the owner of the seed phrase that encrypted the file can decrypt it. There is no way to grant access to another person.

Multi-Bound (v2) adds the ability to grant file access to other people. Each recipient binds the file to their own node — after that, both the sender and the recipient can decrypt the same file independently, each on their own node.

**Key principle:** the file is encrypted once. The ciphertext does not change. What changes is only the number of "locks" — each owner has their own lock (grant block) for the same content.

---

## 2. Three Components of the System

### 2.1. Maxima — the Transport Layer

**What it is:** a P2P messaging protocol built into Minima. It encrypts messages end-to-end automatically.

**Role in the system:** delivers the grant packet (AES key + parameters) from the sender to the recipient.

**Why Maxima, not a blockchain transaction:**

| Criterion | Maxima | Blockchain (state vars) |
|-----------|--------|------------------------|
| Privacy | E2E encryption, nobody sees it | State variables are public, visible to all |
| Speed | Instant | Must wait for block inclusion |
| Cost | Free | Requires Minima coins as input |
| Data size | Sufficient for a grant packet | 256 variables with length constraints |
| Online | Recipient must be online (or message waits) | Data is in the blockchain forever |

**Decision:** Maxima. Privacy and speed outweigh permanent storage. Permanent storage is provided by the file itself (grant blocks embedded in the file).

### 2.2. The `.minima` File — Grant Block Storage

**Role in the system:** grant blocks are embedded at the end of the file. The file becomes fully portable — it can be copied to a USB drive, emailed, or uploaded to the cloud. Any authorized owner can decrypt it on their node without any additional data.

**Why in the file, not in the browser's IndexedDB:**

| Criterion | In the file | IndexedDB |
|-----------|------------|-----------|
| Portability | File = everything needed | Grant is lost when changing devices |
| Reliability | File can be backed up | Clearing the browser = losing the grant |
| Simplicity | One file, one format | File ↔ DB synchronization required |
| Recovery | Seed phrase + file = access | Seed phrase + file + IndexedDB = access |

**Decision:** grant blocks live in the file. IndexedDB is used only as a cache hint (which block is ours) to optimize the number of approve requests.

### 2.3. Blockchain — Notary (Optional, Phase 5)

**Role in the system:** stores only the SHA-256 hash of the grantId. This allows:
- Proving that a grant existed on a specific date
- Revoking a grant (SB_REVOKE record)

**Why only the hash, not the data:**

On-chain data is public. If the full encrypted grant were stored, the fact that "address X gave someone access to something" would be visible. This reveals user behavior. A hash reveals nothing — 32 random bytes with no context.

**Decision:** blockchain = optional notary only for revocation. Implemented last.

---

## 3. Binary File Format v2

### 3.1. Why Binary, Not JSON

The input specification proposed a JSON format. Rejected for three reasons:

1. **Zero-knowledge.** JSON keys (`"aesKey"`, `"signature"`, `"address"`) are readable in a hex editor. Even if the values are encrypted, the structure reveals what is inside. The binary format is a sequence of bytes with no labels.

2. **Compactness.** JSON with base64 increases file size by ~37% due to encoding. Binary format stores bytes as-is.

3. **Compatibility.** v1 is already binary. Switching to JSON breaks backward compatibility of the parser and requires a complete rewrite of `_assembleMinima` / `_parseMinima`.

### 3.2. v2 File Structure

```
Section             Offset    Size         Field             Contents
──────────────────  ──────    ──────       ────              ──────────

HEADER              0         4            MAGIC             0x4D 0x49 0x4E 0x00 ("MIN\0")
                    4         1            VERSION           0x02

PRIMARY BLOCK       5         32           Challenge         32 random bytes
                    37        2            EncKeyLen         Length of encKeyData (LE uint16)
                    39        ~76          EncKeyData        salt(16) + iv(12) + wrappedAESKey(48)
                    ~115      4            EncMetaLen        Length of encMeta (LE uint32)
                    ~119      ~4340        EncMeta           AES-GCM(addr + pk + sig + IV + tag)

CIPHERTEXT          ~4459     4            CiphertextLen     Length of ciphertext (LE uint32)
                    ~4463     N            Ciphertext        AES-256-GCM encrypted file data

GRANT SECTION       ~4463+N   2            GrantCount        Number of grant blocks (LE uint16)

                    [for each grant block]:
                              4            GrantBlockLen     Full size of this block (LE uint32)
                              32           GrantChallenge    Recipient's challenge
                              2            GrantEncKeyLen    Length of recipient's encKeyData (LE uint16)
                              ~76          GrantEncKeyData   salt + iv + wrappedAESKey (under recipient's KEK)
                              4            GrantEncMetaLen   Length of recipient's encMeta (LE uint32)
                              ~4340        GrantEncMeta      AES-GCM(addr + pk + sig + IV + tag of recipient)
```

### 3.3. What Changed Compared to v1

| Change | Reason |
|--------|--------|
| VERSION = 2 (instead of 1) | The parser distinguishes formats: v1 = no grants, v2 = with grants |
| CiphertextLen (4 bytes) before ciphertext | In v1, ciphertext occupied everything to the end of the file. In v2, grant blocks follow the ciphertext, so we need to know where the ciphertext ends |
| GrantCount + array of grant blocks | The actual grant storage |

### 3.4. Backward Compatibility

The v2 parser reads v1 files: if VERSION = 1, ciphertext = everything to the end of the file, GrantCount = 0.

The v1 parser does NOT read v2 files: it will throw an error "Unsupported version: 2". This is expected behavior — an older version of the application is unaware of grants.

### 3.5. What an Attacker Sees

```
MIN\0                         ← file format
0x02                          ← version 2 (grants present)
[32 random bytes]             ← primary challenge
[encrypted blob]              ← encKeyData (unreadable)
[encrypted blob]              ← encMeta (unreadable)
[encrypted blob]              ← ciphertext (unreadable)
0x0001                        ← 1 grant block (number of recipients visible)
[32 random bytes]             ← grant challenge
[encrypted blob]              ← grant encKeyData (unreadable)
[encrypted blob]              ← grant encMeta (unreadable)
```

**Information leak:** the attacker learns the number of grant blocks (= how many people have access). All other data is encrypted noise.

**If leaking the count is critical** (phase 5+): padding can be added — fake grant blocks with random data, always up to a fixed number (e.g., 8). During decryption, fake blocks fail the AES-GCM check and are skipped. This increases file size by ~35 KB but completely hides the number of recipients. This is left for the future — it is excessive for the first version.

---

## 4. Grant Packet: What Is Transmitted via Maxima

### 4.1. Contents

```
grantPacket = {
    type:      "seedbound_grant",
    version:   1,
    fileHash:  <SHA-256(ciphertext), 32 bytes, hex>,
    aesKey:    <256-bit AES key, 32 bytes, base64>,
    fileIV:    <12 bytes, base64>,
    fileTag:   <16 bytes, base64>
}
```

### 4.2. What Is NOT Included and Why

| Field | Why not included |
|-------|----------------|
| `originalChallenge` | Not needed by the recipient. The recipient creates their own challenge |
| `originalWOTSSignature` | Not needed. The recipient creates their own signature on their own node |
| `senderAddress` / `senderPublicKey` | Not needed. The recipient does not verify the sender's signature — they sign the file themselves |
| `senderMaximaContact` | The recipient already knows who sent the message (Maxima identifies the sender) |
| `recipientMaximaPubKey` | The recipient's public key should not appear in plaintext anywhere except at the moment of sending |
| `grantTimestamp` | Timestamp serves no cryptographic purpose and adds metadata |
| `grantSignature` (W-OTS+ signature of the grant) | Maxima already authenticates the sender E2E. An additional signature = an extra approve + 4 KB of data. Will be added in the future if verification of the grant outside Maxima is needed |

### 4.3. Why the Grant Is Minimal

Principle: transmit via Maxima exactly what the recipient cannot create themselves. The recipient cannot create:
- The AES key (only the sender knows it)
- The fileIV and fileTag (only the sender knows them)
- The fileHash (the recipient can compute it, but the file may still be in transit)

Everything else (address, public key, signature, challenge, KEK) the recipient creates themselves on their own node.

---

## 5. Process: Sender Shares Access

### 5.1. User Scenario

1. The sender opens the application
2. Clicks "Share" on the encrypted file
3. Loads the `.minima` file
4. Selects a recipient from the Maxima contacts list
5. Confirms the send
6. Sees: "Grant sent"

### 5.2. Technical Steps

```
1. Load and parse the .minima file
   └─ _parseMinima(file) → { challenge, encKeyData, encMeta, ciphertext }

2. Decrypt on the sender's node (standard flow)
   ├─ seedrandom(challenge) → seedHash                    [APPROVE 1]
   ├─ _deriveKEK(seedHash, "qcrypto-kek-v1") → KEK_key
   ├─ _decryptAESKey(encKeyData, seedHash) → aesKey
   ├─ _deriveKEK(seedHash, "qcrypto-meta-v1") → KEK_meta
   └─ _decryptMetadata(encMeta, seedHash) → { fileIV, fileTag, ... }

3. Compute fileHash
   └─ SHA-256(ciphertext) → fileHash

4. Assemble grant packet
   └─ { type, version, fileHash, aesKey, fileIV, fileTag }

5. Send via Maxima
   └─ MDS.cmd('maxima action:send contact:<id> application:seedbound data:<json>')

6. Zero out sensitive data from memory
   └─ _zeroFill(aesKey), _zeroFill(seedHash), etc.
```

**Number of approves:** 1 (seedrandom to decrypt your own file).

### 5.3. Maxima Command

```javascript
const msg = JSON.stringify({
    type: "seedbound_grant",
    version: 1,
    fileHash: fileHashHex,
    aesKey: aesKeyBase64,
    fileIV: fileIVBase64,
    fileTag: fileTagBase64
});

MDS.cmd('maxima action:send contact:' + contactId + ' application:seedbound data:' + msg, callback);
```

The `application:seedbound` parameter is a filter. The recipient only listens for messages where `application === "seedbound"`.

### 5.4. New MDS Commands

| Command | Purpose | Approve |
|---------|---------|---------|
| `maxcontacts` | Get the contacts list for the UI | No |
| `maxima action:send` | Send the grant | No |

---

## 6. Process: Recipient Binds the Grant

### 6.1. User Scenario

1. The recipient sees a notification: "You have been granted access to a file"
2. Loads the `.minima` file (the sender delivered it separately — via email, messenger, USB drive)
3. Clicks "Bind to my node"
4. Confirms 2 operations in the node (sign + seedrandom)
5. Downloads the updated file with the grant block embedded

### 6.2. Technical Steps

```
1. Receive grant packet via Maxima listener
   └─ MDS.init → event "MAXIMA" → data.application === "seedbound"

2. Load the .minima file
   └─ _parseMinima(file) → { ciphertext, ... }

3. Verify fileHash
   └─ SHA-256(ciphertext) === grantPacket.fileHash?
      ├─ Yes → continue
      └─ No → error: "This grant does not match this file"

4. Create a one-time address on the recipient's node
   └─ newaddress → { address, publickey }

5. Sign the ciphertext with the recipient's key
   └─ sign(SHA-256(ciphertext + address), publickey)              [APPROVE 1]
   └─ → signature (~4125 bytes)

6. Generate challenge and seedHash for the recipient
   ├─ challenge = crypto.getRandomValues(32 bytes)
   └─ seedrandom(challenge) → seedHash                            [APPROVE 2]

7. Encrypt the AES key under the recipient's KEK
   ├─ PBKDF2-SHA512(seedHash, "qcrypto-kek-v1" + salt, 250k) → KEK_key
   └─ AES-GCM-wrap(KEK_key, aesKey) → grantEncKeyData

8. Encrypt metadata under the recipient's KEK_meta
   ├─ PBKDF2-SHA512(seedHash, "qcrypto-meta-v1" + salt, 250k) → KEK_meta
   └─ AES-GCM(KEK_meta, address + publickey + signature + fileIV + fileTag) → grantEncMeta

9. Assemble the grant block
   └─ { challenge, grantEncKeyData, grantEncMeta }

10. Embed the grant block into the file
    ├─ If file is v1 → convert to v2 (add CiphertextLen, GrantCount=1)
    └─ If file is v2 → GrantCount++ and append the block

11. Download the updated file

12. Zero out all sensitive data
    └─ _zeroFill(aesKey, seedHash, signature, fileIV, fileTag)

13. Save hint to IndexedDB
    └─ { fileHash → grantIndex }
```

**Number of approves:** 2 (sign + seedrandom). Identical to encrypting a new file.

### 6.3. Why the Recipient Creates Their Own Signature

The grant packet does not contain the sender's signature. The recipient signs the ciphertext with their own W-OTS+ key. Reasons:

1. **checkaddress:** during decryption, `checkaddress(address)` is verified. If the grant block contained the sender's address, the check would fail on the recipient's node (`relevant: false`). The address must belong to the node that is decrypting.

2. **Integrity:** the recipient personally verifies that the ciphertext has not been altered since it was received. Their signature is their guarantee.

3. **Independence:** each grant block is completely self-contained. Decryption requires no data from the primary block or from other grants.

---

## 7. Process: Decrypting a Multi-Bound File

### 7.1. Algorithm

```
1. _parseMinima(file)
   ├─ If VERSION = 1 → standard v1 flow (no grants)
   └─ If VERSION = 2 → extract primaryBlock + grantBlocks[]

2. Determine which block is ours
   ├─ Check IndexedDB: is there a hint for this fileHash?
   │   ├─ Yes → try the indicated block first
   │   └─ No → iterate through all blocks in order
   └─ blocks = [primaryBlock, ...grantBlocks]

3. For each block:
   a) seedrandom(block.challenge) → seedHash                      [APPROVE]
   b) Try: _decryptMetadata(block.encMeta, seedHash)
      ├─ Success → this is our block → continue decryption
      └─ AES-GCM error → not our block → try next

4. If our block is found:
   ├─ Extract address, publickey, signature, fileIV, fileTag
   ├─ checkaddress(address) → relevant: true
   ├─ verify(ciphertext, signature, publickey) → valid
   ├─ _decryptAESKey(block.encKeyData, seedHash) → aesKey
   └─ AES-GCM-decrypt(aesKey, fileIV, fileTag, ciphertext) → file

5. If no block matched:
   └─ Error: "You do not have access to this file"
```

### 7.2. The Multiple-Approves Problem

Each `seedrandom` attempt = 1 approve in the node. If a file has 5 blocks and ours is the fifth, the user must confirm 5 times in the node.

**Solution 1: IndexedDB hint (primary)**

When binding a grant (step 6.2, item 13), the application remembers: `fileHash → grantIndex`. During decryption, IndexedDB is checked first. If a hint exists — only one block is tried (1 approve).

Works on the device where the grant was bound. On a new device (restored from seed phrase), there is no hint → iteration.

**Solution 2: Check all challenges in one approve (optimization)**

Instead of N calls to `seedrandom`, you can:
1. Collect all challenges from the file
2. Call `seedrandom` for the first challenge
3. Try to decrypt that block's metadata
4. If it fails — call for the next one
5. Stop on the first success

Worst case: N approves. On average: N/2. With IndexedDB: always 1.

**Solution 3: Open hint (rejected)**

Store the first 4 bytes of SHA-256(seedHash) in plaintext in each block. The application calls seedrandom once, compares the hint, and decrypts the correct block.

Rejected: the hint links the challenge to the seedHash. Theoretically an attacker who knows the hint can narrow the search space for the seed phrase. A minor risk, but it violates zero-knowledge.

**Final decision:** IndexedDB hint + sequential iteration as fallback. For files with 1–3 recipients (typical scenario), iteration requires 1–3 approves — acceptable.

---

## 8. Code Architecture: Two Files

### 8.1. Separation Principle

```
MinimaCrypto.js    →  encryption / decryption (v1, unchanged)
MultiBound.js      →  grant creation / binding / Maxima / v2 format
index.html         →  <script src="MinimaCrypto.js">
                      <script src="MultiBound.js">
```

**Why two files, not one:**
- `MinimaCrypto.js` is already tested and stable. Any change to it risks breaking working encryption/decryption
- Grant logic is separate functionality with its own UI and its own flow
- Two files can be developed and tested independently
- If MultiBound.js has a bug, core encryption continues to work

**How MultiBound.js uses MinimaCrypto.js:**

`MultiBound.js` accesses `window.MinimaCrypto` (the global instance, already created in MinimaCrypto.js) and calls its public and internal methods:

```javascript
const mc = window.MinimaCrypto;

mc.decryptFile(blob)          // decryption when creating a grant
mc._deriveKEK(seedHash, ctx)  // creating KEK for a grant block
mc._encryptAESKey(...)        // wrapping the AES key
mc._encryptMetadata(...)      // encrypting metadata
mc._createNewAddress()        // one-time address for the recipient
mc._signWithMinima(...)       // W-OTS+ signature
mc._getSeedRandom(...)        // seedrandom for the recipient
mc._uint16ToLE(...)           // utilities for binary format
mc._uint32ToLE(...)
mc._uint32FromLE(...)
mc._bufferToHex(...)
mc._hexToBuffer(...)
mc._zeroFill(...)
```

No changes to MinimaCrypto.js are required. All needed methods already exist and are accessible through the class instance.

### 8.2. MinimaCrypto.js — No Changes

| Function | Status |
|----------|--------|
| `encryptFile` | Unchanged. Creates v1 file |
| `decryptFile` | Unchanged. Reads v1 file |
| `_parseMinima` | Unchanged. Parses v1 format |
| `_assembleMinima` | Unchanged. Assembles v1 format |
| All internal methods | Unchanged. Used by MultiBound.js via window.MinimaCrypto |

### 8.3. MultiBound.js — New File

| Function | What it does |
|----------|-------------|
| `createGrant(minimaBlob)` | Decrypts the sender's file, extracts AES key + fileIV + fileTag, returns the grant packet |
| `sendGrant(contactId, grantPacket)` | Sends the grant via Maxima |
| `onGrantReceived(callback)` | Listener for incoming grants via Maxima |
| `bindGrant(minimaBlob, grantPacket)` | Grant binding: newaddress → sign → seedrandom → encrypt → grant block |
| `addGrantToFile(minimaBlob, grantBlock)` | Embeds a grant block into the file (v1→v2 or v2→v2+) |
| `decryptMultiBound(minimaBlob)` | Decryption of a v2 file: iterate through blocks, fall back to grants |
| `_parseMinima_v2(fileBlob)` | v2 parser: reads primary block + grant section |
| `_assembleMinima_v2(primaryData, grantBlocks, ciphertext)` | Assembles v2 file |
| `_getGrantHint(fileHash)` | Reads the IndexedDB hint |
| `_saveGrantHint(fileHash, index)` | Writes the IndexedDB hint |

### 8.4. How Does decryptFile Know About v2?

In `index.html`, decryption logic checks the file version before calling:

```javascript
async function decryptFile() {
    const file = currentDecryptFile;
    const header = new Uint8Array(await file.slice(0, 5).arrayBuffer());
    const version = header[4];

    if (version === 1) {
        await window.MinimaCrypto.decryptFile(file, { onProgress: updateStep });
    } else if (version === 2) {
        await window.MultiBound.decryptMultiBound(file, { onProgress: updateStep });
    }
}
```

MinimaCrypto.js knows nothing about v2. MultiBound.js parses v2, extracts the relevant block, and uses MinimaCrypto methods for the final AES data decryption.

### 8.5. index.html — Changes

| Change | What to do |
|--------|-----------|
| Include MultiBound.js | `<script src="MultiBound.js"></script>` after MinimaCrypto.js |
| "Share" section (sidebar) | Replace placeholder with working UI: file selection, contact selection, send button |
| Incoming grant notification | Toast notification on MAXIMA event |
| "Bind" modal window | File upload, binding progress (7 steps), download button |
| decryptFile() function | Check version before calling: v1 → MinimaCrypto, v2 → MultiBound |

### 8.6. Project File Structure

```
seedbound/
├── index.html              UI (sidebar + pages + modals)
├── MinimaCrypto.js         Encryption/decryption v1 (unchanged)
├── MultiBound.js           Grant logic + v2 format
├── mds.js                  Minima MDS library
├── dapp.conf               MiniDapp manifest
└── favicon.ico             Icon
```

### 8.7. New MDS Commands

| Command | Where used |
|---------|-----------|
| `maxcontacts` | UI: loading the contacts list |
| `maxima action:send contact:ID application:seedbound data:JSON` | Sending the grant packet |
| MDS.init → `event === "MAXIMA"` | Receiving the grant packet |

### 8.8. IndexedDB

| Key | Value | When written |
|-----|-------|-------------|
| `grant:<fileHash>` | `{ grantIndex: N, timestamp: Date }` | After binding the grant |

---

## 9. Security

### 9.1. Mandatory Requirements

| Requirement | Implementation |
|------------|---------------|
| AES key not stored in plaintext | After binding the grant, aesKey is zeroed from memory (`_zeroFill`). In the file it is stored only inside encKeyData, encrypted by the KEK |
| AES key transmitted only via Maxima | Maxima encrypts E2E. The key does not appear in the blockchain, localStorage, or logs |
| fileHash verified during binding | SHA-256(ciphertext) === grantPacket.fileHash. Protection against file substitution |
| Each grant block has its own W-OTS+ signature | The recipient signs the ciphertext with their one-time key |
| Each grant block has its own challenge and seedHash | Compromising one grant does not reveal others |
| Zero-knowledge is preserved | Only challenges (32 random bytes each) + GrantCount are visible in the file |
| Sensitive data is zeroed | `_zeroFill` on aesKey, seedHash, signature, fileIV, fileTag in finally blocks |

### 9.2. Threat Model (Extension to v1)

| Threat | Protection |
|--------|-----------|
| Interception of grant packet in Maxima | Maxima encrypts E2E. Without the recipient's private key, the grant is unreadable |
| Grant packet substitution (MITM) | Maxima authenticates the sender. Substitution is impossible without control over the sender's node |
| Sender wants to revoke a grant | Phase 5: SB_REVOKE on the blockchain. Before phase 5: impossible — the recipient already has the grant block in the file |
| Recipient forwards the file to a third party | A third party without a grant cannot decrypt it. But the recipient can create a grant for the third party. This is by design |
| Number of recipients is revealed | GrantCount is visible. Solution: padding with fake blocks (phase 5+) |

### 9.3. Trust Model

**The sender trusts the recipient.** This is a fundamental assumption. The sender voluntarily transmits the AES key. After that, the recipient can technically decrypt the file, create a grant for someone else, or save the AES key. This is analogous to how any shared access system works (Google Drive, Dropbox). Technical forwarding restriction (DRM) is not a goal of this project.

---

## 10. Error Handling

| Situation | User message | Technical cause |
|-----------|-------------|----------------|
| Grant not for this file | "This access key does not match the uploaded file" | SHA-256(ciphertext) ≠ grantPacket.fileHash |
| Recipient is not online | "The recipient is currently offline. The message will be delivered when they connect" | Maxima behavior with offline recipient |
| No contacts in Maxima | "Add a contact in the Minima node to share the file" | `maxcontacts` returned an empty list |
| No block matched | "You do not have access to this file. Ask the owner to grant you access" | All decryption attempts of encMeta returned an AES-GCM error |
| Grant already bound (re-binding) | "This file is already bound to your node" | fileHash already exists in IndexedDB |
| Node disconnected during binding | "Connection to node lost. Please try again" | MDS_DISCONNECTED / MDS_LOGGING_OUT |
| User rejected approve | "Operation cancelled" | MDS_PENDING accept: false |

---

## 11. Development Phases

### Phase 1: Maxima Transport
Send and receive a grant via Maxima. No file format changes.

### Phase 2: Grant Binding
Recipient re-encrypts the AES key under their own seedHash. Grant block created in memory.

### Phase 3: v2 File Format
Grant blocks embedded in the file. File is fully portable.

### Phase 4: Decryption with Block Iteration
Decryption of a v2 file by any authorized owner. IndexedDB hint + sequential fallback.

### Phase 5: On-Chain Revoke and Improvements (Future)
SHA-256(grantId) on blockchain, SB_REVOKE, padding with fake grant blocks, TTL for grant packets.

---

## 12. Test Plan

| Test | What we verify |
|------|---------------|
| Encrypt v1 → decrypt v1 | Backward compatibility not broken |
| Encrypt v1 → add grant → decrypt primary (v2) | Primary block works in v2 |
| Encrypt v1 → add grant → decrypt grant (v2) | Grant block works on recipient's node |
| Decrypt v2 on node without access | Error "You do not have access" |
| Send grant → Maxima delivery | Grant is delivered to recipient |
| Bind grant with wrong fileHash | Error "Grant does not match this file" |
| Two grants in one file | Both recipients can decrypt |
| Restore node from seed phrase + v2 file (without IndexedDB) | Block iteration, decryption works |
| v2 file opened in v1 application | Error "Unsupported version" |
| Concurrent: two files encrypting simultaneously | pendinguid filtering works |

---

## 13. Scope Estimate

| Phase | MultiBound.js (new) | MinimaCrypto.js | index.html |
|-------|---------------------|-----------------|------------|
| 1. Maxima transport | ~150 lines | Unchanged | ~50 lines |
| 2. Binding | ~200 lines | Unchanged | ~60 lines |
| 3. v2 format | ~150 lines | Unchanged | ~10 lines |
| 4. v2 decryption | ~100 lines | Unchanged | ~20 lines |
| 5. Revoke | ~100 lines | Unchanged | ~30 lines |

**Total phases 1–4:**
- `MultiBound.js`: ~600 lines (new file)
- `MinimaCrypto.js`: 0 changes
- `index.html`: ~140 lines of changes
