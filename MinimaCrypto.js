/**
 * Quantum Crypto v1 — Quantum-Resistant File Encryption for Minima
 *
 * В файле виден ТОЛЬКО challenge (32 байт). Всё остальное зашифровано.
 *
 * Формат .minima (Standard):
 *   MAGIC(4) | VERSION(1)=1 | Challenge(32)
 *   | EncKeyLen(2) | EncKeyData(~76) | EncMetaLen(4) | EncMeta(~4340) | Ciphertext
 *
 * EncMeta = AES-GCM(KEK_meta, address + publickey + signature + fileIV + fileTag)
 * EncKeyData = AES-GCM-wrap(KEK_key, AES-ключ файла)
 * KEK_key  = PBKDF2-SHA512(seedHash, "qcrypto-kek-v1"  + salt, 250k)
 * KEK_meta = PBKDF2-SHA512(seedHash, "qcrypto-meta-v1" + salt, 250k)
 */

class MinimaCryptoEnhancedClass {
    constructor() {
        this.MAGIC = new Uint8Array([0x4D, 0x49, 0x4E, 0x00]); // "MIN\0"
        this.VERSION = 1;
        this.CTX_KEK  = new TextEncoder().encode('qcrypto-kek-v1');
        this.CTX_META = new TextEncoder().encode('qcrypto-meta-v1');
        console.log('[QC] Quantum Crypto v1 инициализирован');
    }

    // ─── ENCRYPTION ─────────────────────────────────────────────

    _wait(ms) { return new Promise(r => setTimeout(r, ms)); }

    async encryptFile(fileBlob, options = {}) {
        console.log('[MC] === ENCRYPT START ===', fileBlob.name || 'файл', formatBytes(fileBlob.size));
        const p = options.onProgress || (() => {});
        let seedHash = null;
        let signature = null;

        try {
            p(0, 'active');
            const { address, publickey } = await this._createNewAddress();
            await this._wait(400);
            p(0, 'done');

            await this._wait(300);
            p(1, 'active');
            const aesKey = await this._generateAESKey();
            const fileIV = crypto.getRandomValues(new Uint8Array(12));
            await this._wait(400);
            p(1, 'done');

            await this._wait(300);
            p(2, 'active');
            const fileData = await fileBlob.arrayBuffer();
            const encrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: fileIV, tagLength: 128 }, aesKey, fileData
            );
            const encryptedArray = new Uint8Array(encrypted);
            const ciphertext = encryptedArray.slice(0, -16);
            const fileTag = encryptedArray.slice(-16);
            await this._wait(500);
            p(2, 'done');

            await this._wait(300);
            p(3, 'pending');
            signature = await this._signWithMinima(ciphertext, publickey, address);
            p(3, 'done');

            await this._wait(300);
            p(4, 'pending');
            const challenge = crypto.getRandomValues(new Uint8Array(32));
            const challengeHex = this._bufferToHex(challenge);
            seedHash = await this._getSeedRandom(challengeHex);
            p(4, 'done');

            await this._wait(300);
            p(5, 'active');
            const encryptedKeyData = await this._encryptAESKey(aesKey, seedHash);
            const encryptedMeta = await this._encryptMetadata(
                { address, publickey, signature, fileIV, fileTag }, seedHash
            );
            await this._wait(500);
            p(5, 'done');

            await this._wait(300);
            p(6, 'active');
            const minimaFile = this._assembleMinima(challenge, encryptedKeyData, encryptedMeta, ciphertext);
            console.log('[MC] === ENCRYPT DONE === size:', formatBytes(minimaFile.size));
            await this._wait(400);
            p(6, 'done');

            return { file: minimaFile, address: address };

        } catch (error) {
            console.error('[MC] === ENCRYPT FAIL ===', error.message);
            throw error;
        } finally {
            this._zeroFill(seedHash);
            this._zeroFill(signature);
        }
    }

    // ─── DECRYPTION ─────────────────────────────────────────────

    async decryptFile(minimaBlob, options = {}) {
        console.log('[MC] === DECRYPT START ===', formatBytes(minimaBlob.size));
        const p = options.onProgress || (() => {});
        let seedHash = null;
        let meta = null;

        try {
            p(0, 'active');
            const parsed = await this._parseMinima(minimaBlob);
            const { challenge, encryptedKeyData, encryptedMeta, ciphertext } = parsed;
            await this._wait(500);
            p(0, 'done');

            await this._wait(300);
            p(1, 'pending');
            const challengeHex = this._bufferToHex(challenge);
            seedHash = await this._getSeedRandom(challengeHex);
            p(1, 'done');

            await this._wait(300);
            p(2, 'active');
            meta = await this._decryptMetadata(encryptedMeta, seedHash);
            await this._wait(500);
            p(2, 'done');

            await this._wait(300);
            p(3, 'active');
            await this._verifyAddressExists(meta.address);
            const isValid = await this._verifySignature(ciphertext, meta.signature, meta.address, meta.publickey);
            if (!isValid) throw new Error('Invalid signature: the file may have been tampered with');
            await this._wait(400);
            p(3, 'done');

            await this._wait(300);
            p(4, 'active');
            const aesKey = await this._decryptAESKey(encryptedKeyData, seedHash);
            const encryptedWithTag = new Uint8Array(ciphertext.length + 16);
            encryptedWithTag.set(ciphertext, 0);
            encryptedWithTag.set(meta.fileTag, ciphertext.length);

            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: meta.fileIV, tagLength: 128 }, aesKey, encryptedWithTag
            );
            await this._wait(400);
            p(4, 'done');

            console.log('[MC] === DECRYPT DONE ===', formatBytes(decrypted.byteLength));
            return { file: new Blob([decrypted]), fileSize: decrypted.byteLength, address: meta.address };

        } catch (error) {
            console.error('[MC] === DECRYPT FAIL ===', error.message);
            throw error;
        } finally {
            this._zeroFill(seedHash);
            if (meta) {
                this._zeroFill(meta.signature);
                this._zeroFill(meta.fileIV);
                this._zeroFill(meta.fileTag);
            }
        }
    }

    // ─── FILE FORMAT v1 ─────────────────────────────────────────

    /**
     * MAGIC(4) | VERSION(1)=1 | Challenge(32)
     * | EncKeyLen(2) | EncKeyData | EncMetaLen(4) | EncMeta | Ciphertext
     */
    _assembleMinima(challenge, encryptedKeyData, encryptedMeta, ciphertext) {
        if (challenge.length !== 32) throw new Error('Challenge must be 32 bytes');

        console.log('[MC] _assembleMinima: encKey=' + encryptedKeyData.length + ' encMeta=' + encryptedMeta.length + ' ciphertext=' + ciphertext.length);

        const parts = [
            this.MAGIC,
            new Uint8Array([this.VERSION]),
            challenge,
            this._uint16ToLE(encryptedKeyData.length), encryptedKeyData,
            this._uint32ToLE(encryptedMeta.length), encryptedMeta,
            ciphertext
        ];

        return new Blob(parts, { type: 'application/x-minima' });
    }

    async _parseMinima(fileBlob) {
        const buffer = await fileBlob.arrayBuffer();
        const view = new Uint8Array(buffer);

        if (view.length < 50) throw new Error('File is too small');

        const magic = view.slice(0, 4);
        if (!this._arrayEquals(magic, this.MAGIC)) throw new Error('Invalid file format');

        const version = view[4];
        console.log('[MC] _parseMinima: version =', version);
        if (version !== 1) throw new Error(`Неподдерживаемая версия: ${version}. Требуется формат Standard (1).`);

        let o = 5;

        const challenge = view.slice(o, o + 32); o += 32;

        const encKeyLen = this._uint16FromLE(view, o); o += 2;
        const encryptedKeyData = view.slice(o, o + encKeyLen); o += encKeyLen;

        const encMetaLen = this._uint32FromLE(view, o); o += 4;
        if (o + encMetaLen > view.length) throw new Error('Invalid structure: metadata exceeds file bounds');
        const encryptedMeta = view.slice(o, o + encMetaLen); o += encMetaLen;

        const ciphertext = view.slice(o);

        console.log('[MC] _parseMinima: encKey=' + encKeyLen + ' encMeta=' + encMetaLen + ' ciphertext=' + ciphertext.length);

        return { challenge, encryptedKeyData, encryptedMeta, ciphertext };
    }

    // ─── KEY MANAGEMENT ─────────────────────────────────────────

    async _generateAESKey() {
        return await crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
        );
    }

    /** KEK = PBKDF2-SHA512(seedHash, context + salt, 250k) */
    async _deriveKEK(keyMaterial, salt, context, usages = ["wrapKey", "unwrapKey"]) {
        const contextedSalt = new Uint8Array(context.length + salt.length);
        contextedSalt.set(context, 0);
        contextedSalt.set(salt, context.length);

        const imported = await crypto.subtle.importKey(
            "raw", keyMaterial, { name: "PBKDF2" }, false, ["deriveKey"]
        );
        return await crypto.subtle.deriveKey(
            { name: "PBKDF2", hash: "SHA-512", salt: contextedSalt, iterations: 250000 },
            imported,
            { name: "AES-GCM", length: 256 },
            false,
            usages
        );
    }

    async _encryptAESKey(aesKey, seedHash) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const kek = await this._deriveKEK(seedHash, salt, this.CTX_KEK);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const wrappedKey = await crypto.subtle.wrapKey(
            "raw", aesKey, kek, { name: "AES-GCM", iv: iv, tagLength: 128 }
        );
        const result = new Uint8Array(16 + 12 + wrappedKey.byteLength);
        result.set(salt, 0);
        result.set(iv, 16);
        result.set(new Uint8Array(wrappedKey), 28);
        return result;
    }

    async _decryptAESKey(encryptedKeyData, seedHash) {
        const salt = encryptedKeyData.slice(0, 16);
        const iv = encryptedKeyData.slice(16, 28);
        const wrappedKey = encryptedKeyData.slice(28);
        const kek = await this._deriveKEK(seedHash, salt, this.CTX_KEK);
        try {
            return await crypto.subtle.unwrapKey(
                "raw", wrappedKey, kek,
                { name: "AES-GCM", iv: iv, tagLength: 128 },
                { name: "AES-GCM", length: 256 },
                true, ["encrypt", "decrypt"]
            );
        } catch (error) {
            throw new Error('Failed to decrypt AES key. Invalid seed phrase.');
        }
    }

    // ─── METADATA ───────────────────────────────────────────────

    /**
     * Бинарная структура plaintext метаданных:
     *   AddrLen(2) | Address | PubkeyLen(2) | Publickey | FileIV(12) | FileTag(16) | Signature(остаток)
     */
    async _encryptMetadata({ address, publickey, signature, fileIV, fileTag }, seedHash) {
        const encoder = new TextEncoder();
        const addrBytes = encoder.encode(address);
        const pkBytes = encoder.encode(publickey);

        const plainLen = 2 + addrBytes.length + 2 + pkBytes.length + 12 + 16 + signature.length;
        const plain = new Uint8Array(plainLen);
        let o = 0;

        plain.set(this._uint16ToLE(addrBytes.length), o); o += 2;
        plain.set(addrBytes, o); o += addrBytes.length;
        plain.set(this._uint16ToLE(pkBytes.length), o); o += 2;
        plain.set(pkBytes, o); o += pkBytes.length;
        plain.set(fileIV, o); o += 12;
        plain.set(fileTag, o); o += 16;
        plain.set(signature, o);

        console.log('[MC] _encryptMetadata: plain:', plainLen, 'байт');

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const kek = await this._deriveKEK(seedHash, salt, this.CTX_META, ["encrypt", "decrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv, tagLength: 128 }, kek, plain
        );
        plain.fill(0);

        const result = new Uint8Array(16 + 12 + encrypted.byteLength);
        result.set(salt, 0);
        result.set(iv, 16);
        result.set(new Uint8Array(encrypted), 28);
        return result;
    }

    async _decryptMetadata(encryptedMeta, seedHash) {
        const salt = encryptedMeta.slice(0, 16);
        const iv = encryptedMeta.slice(16, 28);
        const encData = encryptedMeta.slice(28);

        const kek = await this._deriveKEK(seedHash, salt, this.CTX_META, ["encrypt", "decrypt"]);

        let plain;
        try {
            plain = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv, tagLength: 128 }, kek, encData
            ));
        } catch (error) {
            throw new Error('Failed to decrypt metadata. Invalid seed phrase.');
        }

        const decoder = new TextDecoder();
        let o = 0;

        const addrLen = this._uint16FromLE(plain, o); o += 2;
        const address = decoder.decode(plain.slice(o, o + addrLen)); o += addrLen;

        const pkLen = this._uint16FromLE(plain, o); o += 2;
        const publickey = decoder.decode(plain.slice(o, o + pkLen)); o += pkLen;

        const fileIV = plain.slice(o, o + 12); o += 12;
        const fileTag = plain.slice(o, o + 16); o += 16;

        const signature = plain.slice(o);
        plain.fill(0);

        console.log('[MC] _decryptMetadata: addr=' + addrLen + ' pk=' + pkLen + ' iv=12 tag=16 sig=' + signature.length);
        return { address, publickey, fileIV, fileTag, signature };
    }

    // ─── MINIMA NODE COMMANDS ───────────────────────────────────

    async _createNewAddress() {
        console.log('[MC] _createNewAddress: запрос...');
        if (typeof MDS === 'undefined' || !MDS.cmd) throw new Error('MDS unavailable');

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Timeout: newaddress')), 10000);

            MDS.cmd('newaddress', (response) => {
                clearTimeout(timeout);
                console.log('[MC] _createNewAddress: ответ:', JSON.stringify(response).substring(0, 200));

                if (response && response.status && response.response) {
                    resolve({
                        address: response.response.address,
                        publickey: response.response.publickey
                    });
                } else {
                    reject(new Error('Ошибка создания адреса'));
                }
            });
        });
    }

    async _verifyAddressExists(addressToVerify) {
        console.log('[MC] _verifyAddressExists:', addressToVerify);
        if (typeof MDS === 'undefined' || !MDS.cmd) throw new Error('MDS unavailable');

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Timeout: checkaddress')), 10000);

            MDS.cmd(`checkaddress address:${addressToVerify}`, (response) => {
                clearTimeout(timeout);
                console.log('[MC] _verifyAddressExists: ответ:', JSON.stringify(response).substring(0, 300));

                if (response && response.status && response.response) {
                    if (response.response.relevant === true) {
                        console.log('[MC] _verifyAddressExists: relevant = true');
                        resolve(true);
                    } else {
                        reject(new Error('ADDRESS не принадлежит этой ноде.'));
                    }
                } else {
                    reject(new Error('Ошибка checkaddress: ' + (response?.error || '?')));
                }
            });
        });
    }

    async _getSeedRandom(modifier) {
        console.log('[MC] _getSeedRandom: modifier длина', modifier.length);
        if (typeof MDS === 'undefined' || !MDS.cmd) throw new Error('MDS unavailable');

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Timeout: seedrandom')), 10000);

            MDS.cmd(`seedrandom modifier:"${modifier}"`, (response) => {
                console.log('[MC] _getSeedRandom: ответ:', JSON.stringify(response).substring(0, 300));

                if (response && response.status === true && response.response) {
                    clearTimeout(timeout);
                    const hash = response.response.seedrandom || response.response;
                    if (hash && typeof hash === 'string') {
                        console.log('[MC] _getSeedRandom: OK, длина:', hash.length);
                        resolve(this._hexToBuffer(hash));
                    } else {
                        reject(new Error('seedrandom: некорректный ответ'));
                    }
                    return;
                }

                if (response && response.pending === true) {
                    clearTimeout(timeout);
                    const expectedUid = response.pendinguid;
                    console.log('[MC] _getSeedRandom: PENDING, pendinguid:', expectedUid);

                    const cleanup = () => {
                        window.removeEventListener('minimaPendingResolved', onAccept);
                        window.removeEventListener('minimaPendingDenied', onDeny);
                        window.removeEventListener('minimaDisconnected', onDisconnect);
                    };

                    const onAccept = (event) => {
                        if (event.detail.uid !== expectedUid) return;
                        const result = event.detail.result;
                        const hash = result.seedrandom
                            || result.response?.seedrandom
                            || (typeof result.response === 'string' ? result.response : null);
                        if (hash && typeof hash === 'string') {
                            cleanup();
                            console.log('[MC] _getSeedRandom: RESOLVED via pending');
                            resolve(this._hexToBuffer(hash));
                        }
                    };

                    const onDeny = (event) => {
                        if (event.detail.uid !== expectedUid) return;
                        cleanup();
                        reject(new Error('DENIED'));
                    };

                    const onDisconnect = () => {
                        cleanup();
                        reject(new Error('DISCONNECTED'));
                    };

                    window.addEventListener('minimaPendingResolved', onAccept);
                    window.addEventListener('minimaPendingDenied', onDeny);
                    window.addEventListener('minimaDisconnected', onDisconnect);
                    setTimeout(() => {
                        cleanup();
                        reject(new Error('TIMEOUT'));
                    }, 120000);
                } else {
                    clearTimeout(timeout);
                    reject(new Error('seedrandom: ' + (response?.error || 'неизвестная ошибка')));
                }
            });
        });
    }

    async _signWithMinima(ciphertext, publickey, address) {
        console.log('[MC] _signWithMinima: подписываю...');
        if (typeof MDS === 'undefined' || !MDS.cmd) throw new Error('MDS unavailable');

        const encoder = new TextEncoder();
        const addrBytes = encoder.encode(address);
        const combined = new Uint8Array(ciphertext.length + addrBytes.length);
        combined.set(ciphertext);
        combined.set(addrBytes, ciphertext.length);

        const hash = await crypto.subtle.digest('SHA-256', combined);
        const hashHex = this._bufferToHex(hash);
        console.log('[MC] _signWithMinima: dataHash:', hashHex.substring(0, 16) + '...');

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Timeout: sign')), 10000);

            MDS.cmd(`sign data:${hashHex} publickey:${publickey}`, (response) => {
                console.log('[MC] _signWithMinima: ответ:', JSON.stringify(response).substring(0, 300));

                if (response && response.status === true && response.response) {
                    clearTimeout(timeout);
                    const sig = response.response.signature || response.response;
                    if (sig && typeof sig === 'string') {
                        console.log('[MC] _signWithMinima: OK, длина:', sig.length);
                        resolve(this._hexToBuffer(sig));
                        return;
                    }
                }

                if (response && response.pending === true) {
                    clearTimeout(timeout);
                    const expectedUid = response.pendinguid;
                    console.log('[MC] _signWithMinima: PENDING, pendinguid:', expectedUid);

                    const cleanup = () => {
                        window.removeEventListener('minimaPendingResolved', onAccept);
                        window.removeEventListener('minimaPendingDenied', onDeny);
                        window.removeEventListener('minimaDisconnected', onDisconnect);
                    };

                    const onAccept = (event) => {
                        if (event.detail.uid !== expectedUid) return;
                        const result = event.detail.result;
                        const sig = result.signature || result.response;
                        if (sig && typeof sig === 'string') {
                            cleanup();
                            console.log('[MC] _signWithMinima: RESOLVED via pending, длина:', sig.length);
                            resolve(this._hexToBuffer(sig));
                        }
                    };

                    const onDeny = (event) => {
                        if (event.detail.uid !== expectedUid) return;
                        cleanup();
                        reject(new Error('DENIED'));
                    };

                    const onDisconnect = () => {
                        cleanup();
                        reject(new Error('DISCONNECTED'));
                    };

                    window.addEventListener('minimaPendingResolved', onAccept);
                    window.addEventListener('minimaPendingDenied', onDeny);
                    window.addEventListener('minimaDisconnected', onDisconnect);
                    setTimeout(() => {
                        cleanup();
                        reject(new Error('TIMEOUT'));
                    }, 120000);
                } else {
                    clearTimeout(timeout);
                    reject(new Error('sign: не удалось получить подпись'));
                }
            });
        });
    }

    async _verifySignature(ciphertext, signature, address, publickey) {
        console.log('[MC] _verifySignature: publickey:', publickey.substring(0, 16) + '...');
        if (typeof MDS === 'undefined' || !MDS.cmd) throw new Error('MDS unavailable');
        if (!publickey) throw new Error('Public key is missing');

        const encoder = new TextEncoder();
        const addrBytes = encoder.encode(address);
        const combined = new Uint8Array(ciphertext.length + addrBytes.length);
        combined.set(ciphertext);
        combined.set(addrBytes, ciphertext.length);

        const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
        const dataHex = this._bufferToHex(hashBuffer);
        const sigHex = '0x' + this._bufferToHex(signature);

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Таймаут verify')), 10000);

            console.log('[MC] _verifySignature: verify...');
            MDS.cmd(`verify data:${dataHex} publickey:${publickey} signature:${sigHex}`, (resp) => {
                clearTimeout(timeout);
                console.log('[MC] _verifySignature: response:', resp?.response);

                if (resp && resp.status) {
                    const r = resp.response;
                    const valid = r === true || r?.valid === true || r === 'Signature valid';
                    console.log('[MC] _verifySignature:', valid ? 'ВАЛИДНА' : 'НЕВАЛИДНА');
                    resolve(valid);
                } else {
                    reject(new Error('verify: ' + (resp?.error || 'ошибка')));
                }
            });
        });
    }

    // ─── UTILS ──────────────────────────────────────────────────

    _bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    }

    _hexToBuffer(hex) {
        if (hex.startsWith('0x') || hex.startsWith('0X')) hex = hex.slice(2);
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    _arrayEquals(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) return false; }
        return true;
    }

    _uint16ToLE(v) { return new Uint8Array([v & 0xFF, (v >> 8) & 0xFF]); }
    _uint16FromLE(view, o) { return view[o] | (view[o + 1] << 8); }

    _uint32ToLE(v) {
        return new Uint8Array([v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF]);
    }
    _uint32FromLE(view, o) {
        return (view[o] | (view[o + 1] << 8) | (view[o + 2] << 16) | (view[o + 3] << 24)) >>> 0;
    }

    _zeroFill(buf) { if (buf && buf instanceof Uint8Array) buf.fill(0); }

    downloadFile(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename || 'file.minima';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(2) + ' MB';
}

if (typeof window !== 'undefined') {
    const instance = new MinimaCryptoEnhancedClass();
    window.MinimaCryptoEnhanced = instance;
    window.MinimaCrypto = instance;
    console.log('[MC] MinimaCrypto v1 готова');
}

if (typeof MDS !== 'undefined' && MDS.init && !window.__minimaPendingListenerRegistered) {
    window.__minimaPendingListenerRegistered = true;
    const originalInit = MDS.init;

    MDS.init = function(callback) {
        originalInit(function(msg) {
            if (msg.event === 'MDS_PENDING') {
                console.log('[MC] MDS_PENDING:', JSON.stringify(msg.data).substring(0, 400));
                const r = msg.data;
                if (r && r.accept === true && r.result) {
                    console.log('[MC] MDS_PENDING ACCEPTED, uid:', r.uid);
                    window.dispatchEvent(new CustomEvent('minimaPendingResolved', {
                        detail: { uid: r.uid, result: r.result }
                    }));
                } else if (r && r.accept === false) {
                    console.log('[MC] MDS_PENDING DENIED, uid:', r.uid);
                    window.dispatchEvent(new CustomEvent('minimaPendingDenied', {
                        detail: { uid: r.uid }
                    }));
                }
            }

            if (msg.event === 'MDS_LOGGING_OUT' || msg.event === 'MDS_DISCONNECTED') {
                console.log('[MC] NODE DISCONNECTED:', msg.event);
                window.dispatchEvent(new CustomEvent('minimaDisconnected'));
            }

            if (callback) callback(msg);
        });
    };
    console.log('[MC] MDS_PENDING listener зарегистрирован');
}
