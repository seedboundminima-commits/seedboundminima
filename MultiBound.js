/**
 * MultiBound — Multi-bound grant system for MinimaCrypto
 *
 * Зависит от MinimaCrypto.js (window.MinimaCrypto).
 * Не изменяет MinimaCrypto.js — только использует его методы.
 *
 * Формат .minima Multi-Bound (расширение Standard):
 *   MAGIC(4) | VERSION(1)=4 | PrimaryChallenge(32)
 *   | EncKeyLen(2) | EncKeyData | EncMetaLen(4) | EncMeta
 *   | CiphertextLen(4) | Ciphertext
 *   | GrantCount(2) | [GrantBlock...]
 *
 * GrantBlock:
 *   BlockLen(4) | Challenge(32) | EncKeyLen(2) | EncKeyData | EncMetaLen(4) | EncMeta
 */

const MB_DB_NAME  = 'seedbound_grants';
const MB_DB_STORE = 'hints';

class MultiBoundClass {
    constructor() {
        this.VERSION_MULTI = 4;
        this._maximaCallbacks = [];
        this._sqlReady = false;
        console.log('[MB] MultiBound инициализирован');
    }

    _mc() {
        const mc = window.MinimaCrypto;
        if (!mc) throw new Error('MinimaCrypto is not loaded');
        return mc;
    }

    // ─── CREATE GRANT (отправитель) ──────────────────────────────

    /**
     * Расшифровывает свой файл и извлекает grant-пакет для отправки через Maxima.
     * Требует 1 approve (seedrandom).
     *
     * @param {Blob} minimaBlob — файл .minima (v3 или v4)
     * @param {Object} options — { onProgress }
     * @returns {{ aesKeyB64, fileIVB64, fileTagB64, fileHash }}
     */
    async createGrant(minimaBlob, options = {}) {
        const mc = this._mc();
        const p = options.onProgress || (() => {});
        let seedHash = null;
        let aesKeyRaw = null;
        let meta = null;

        try {
            p(0, 'active');
            const parsed = await this._parseAny(minimaBlob);
            await mc._wait(400);
            p(0, 'done');

            await mc._wait(300);
            p(1, 'pending');
            const challengeHex = mc._bufferToHex(parsed.primaryBlock.challenge);
            seedHash = await mc._getSeedRandom(challengeHex);
            p(1, 'done');

            await mc._wait(300);
            p(2, 'active');
            meta = await mc._decryptMetadata(parsed.primaryBlock.encryptedMeta, seedHash);
            const aesKey = await mc._decryptAESKey(parsed.primaryBlock.encryptedKeyData, seedHash);
            aesKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', aesKey));

            const fileHashBuf = await crypto.subtle.digest('SHA-256', parsed.ciphertext);
            const fileHash = mc._bufferToHex(fileHashBuf);
            await mc._wait(400);
            p(2, 'done');

            const grant = {
                type: 'seedbound_grant',
                version: 1,
                fileHash: fileHash,
                aesKeyB64: this._toBase64(aesKeyRaw),
                fileIVB64: this._toBase64(meta.fileIV),
                fileTagB64: this._toBase64(meta.fileTag)
            };

            console.log('[MB] createGrant: OK, fileHash:', fileHash.substring(0, 16) + '...');
            return grant;

        } catch (error) {
            console.error('[MB] createGrant FAIL:', error.message);
            throw error;
        } finally {
            mc._zeroFill(seedHash);
            mc._zeroFill(aesKeyRaw);
            if (meta) {
                mc._zeroFill(meta.signature);
                mc._zeroFill(meta.fileIV);
                mc._zeroFill(meta.fileTag);
            }
        }
    }

    // ─── BIND GRANT (получатель) ─────────────────────────────────

    /**
     * Привязывает grant к своей ноде: newaddress → sign → seedrandom → encrypt → add to file.
     * Требует 2 approve (sign + seedrandom).
     *
     * @param {Blob} minimaBlob — файл .minima
     * @param {Object} grantPacket — { aesKeyB64, fileIVB64, fileTagB64, fileHash }
     * @param {Object} options — { onProgress }
     * @returns {{ file: Blob }} — обновлённый файл с grant-блоком
     */
    async bindGrant(minimaBlob, grantPacket, options = {}) {
        const mc = this._mc();
        const p = options.onProgress || (() => {});
        let seedHash = null;
        let signature = null;
        let aesKeyRaw = null;

        try {
            p(0, 'active');
            const parsed = await this._parseAny(minimaBlob);

            const fileHashBuf = await crypto.subtle.digest('SHA-256', parsed.ciphertext);
            const fileHash = mc._bufferToHex(fileHashBuf);

            if (fileHash !== grantPacket.fileHash) {
                throw new Error('Grant does not match the file: fileHash mismatch');
            }
            await mc._wait(400);
            p(0, 'done');

            await mc._wait(300);
            p(1, 'active');
            const { address, publickey } = await mc._createNewAddress();
            await mc._wait(400);
            p(1, 'done');

            await mc._wait(300);
            p(2, 'pending');
            signature = await mc._signWithMinima(parsed.ciphertext, publickey, address);
            p(2, 'done');

            await mc._wait(300);
            p(3, 'pending');
            const challenge = crypto.getRandomValues(new Uint8Array(32));
            const challengeHex = mc._bufferToHex(challenge);
            seedHash = await mc._getSeedRandom(challengeHex);
            p(3, 'done');

            await mc._wait(300);
            p(4, 'active');
            aesKeyRaw = this._fromBase64(grantPacket.aesKeyB64);
            const fileIV = this._fromBase64(grantPacket.fileIVB64);
            const fileTag = this._fromBase64(grantPacket.fileTagB64);

            const aesKey = await crypto.subtle.importKey(
                'raw', aesKeyRaw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
            );

            const encryptedKeyData = await mc._encryptAESKey(aesKey, seedHash);
            const encryptedMeta = await mc._encryptMetadata(
                { address, publickey, signature, fileIV, fileTag }, seedHash
            );
            await mc._wait(500);
            p(4, 'done');

            await mc._wait(300);
            p(5, 'active');
            const grantBlock = { challenge, encryptedKeyData, encryptedMeta };
            const updatedFile = this._addGrantToFile(parsed, grantBlock);

            // allBlocks = [primaryBlock, ...grantBlocks] — новый грант идёт последним
            const grantIndex = parsed.grantBlocks.length + 1;
            await this._saveHint(fileHash, grantIndex);

            console.log('[MB] bindGrant: OK, grant #' + grantIndex);
            await mc._wait(400);
            p(5, 'done');

            return { file: updatedFile };

        } catch (error) {
            console.error('[MB] bindGrant FAIL:', error.message);
            throw error;
        } finally {
            mc._zeroFill(seedHash);
            mc._zeroFill(signature);
            mc._zeroFill(aesKeyRaw);
        }
    }

    // ─── DECRYPT WITH GRANT (прямая расшифровка по гранту) ──────

    /**
     * Расшифровывает файл напрямую по grant-пакету — без привязки, без approve.
     * Работает с v3 и v4 файлами.
     *
     * @param {Blob} minimaBlob — оригинальный файл .minima
     * @param {Object} grantPacket — { aesKeyB64, fileIVB64, fileTagB64, fileHash }
     * @param {Object} options — { onProgress }
     * @returns {{ file: Blob, fileSize }}
     */
    async decryptWithGrant(minimaBlob, grantPacket, options = {}) {
        const mc = this._mc();
        const p = options.onProgress || (() => {});
        let aesKeyRaw = null;

        try {
            p(0, 'active');
            const parsed = await this._parseAny(minimaBlob);

            const fileHashBuf = await crypto.subtle.digest('SHA-256', parsed.ciphertext);
            const fileHash = mc._bufferToHex(fileHashBuf);

            if (fileHash !== grantPacket.fileHash) {
                throw new Error('File does not match the grant: fileHash mismatch');
            }
            await mc._wait(400);
            p(0, 'done');

            await mc._wait(300);
            p(1, 'active');
            aesKeyRaw = this._fromBase64(grantPacket.aesKeyB64);
            const fileIV  = this._fromBase64(grantPacket.fileIVB64);
            const fileTag = this._fromBase64(grantPacket.fileTagB64);

            const aesKey = await crypto.subtle.importKey(
                'raw', aesKeyRaw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
            );

            const encryptedWithTag = new Uint8Array(parsed.ciphertext.length + 16);
            encryptedWithTag.set(parsed.ciphertext, 0);
            encryptedWithTag.set(fileTag, parsed.ciphertext.length);

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: fileIV, tagLength: 128 }, aesKey, encryptedWithTag
            );
            await mc._wait(400);
            p(1, 'done');

            console.log('[MB] decryptWithGrant: OK,', decrypted.byteLength, 'байт');
            return { file: new Blob([decrypted]), fileSize: decrypted.byteLength };

        } catch (error) {
            console.error('[MB] decryptWithGrant FAIL:', error.message);
            throw error;
        } finally {
            mc._zeroFill(aesKeyRaw);
        }
    }

    // ─── DECRYPT MULTI-BOUND (v4) ───────────────────────────────

    /**
     * Расшифровка файла v4: перебирает primary-блок и grant-блоки.
     * Использует IndexedDB-подсказку для минимизации approve.
     *
     * @param {Blob} minimaBlob — файл .minima v4
     * @param {Object} options — { onProgress }
     * @returns {{ file: Blob, fileSize, address }}
     */
    async decryptMultiBound(minimaBlob, options = {}) {
        const mc = this._mc();
        const p = options.onProgress || (() => {});
        let seedHash = null;
        let meta = null;

        try {
            p(0, 'active');
            const parsed = await this._parseAny(minimaBlob);
            const allBlocks = [parsed.primaryBlock, ...parsed.grantBlocks];

            const fileHashBuf = await crypto.subtle.digest('SHA-256', parsed.ciphertext);
            const fileHash = mc._bufferToHex(fileHashBuf);
            await mc._wait(400);
            p(0, 'done');

            const hint = await this._getHint(fileHash);
            if (hint !== null && hint >= 0 && hint < allBlocks.length) {
                const reordered = [allBlocks[hint], ...allBlocks.filter((_, i) => i !== hint)];
                allBlocks.length = 0;
                allBlocks.push(...reordered);
            }

            await mc._wait(300);
            p(1, 'pending');
            let foundBlock = null;

            for (let i = 0; i < allBlocks.length; i++) {
                const block = allBlocks[i];
                const challengeHex = mc._bufferToHex(block.challenge);

                try {
                    seedHash = await mc._getSeedRandom(challengeHex);
                    meta = await mc._decryptMetadata(block.encryptedMeta, seedHash);
                    foundBlock = block;
                    console.log('[MB] decryptMultiBound: блок #' + i + ' подошёл');
                    break;
                } catch (e) {
                    console.log('[MB] decryptMultiBound: блок #' + i + ' не подошёл:', e.message);
                    mc._zeroFill(seedHash);
                    seedHash = null;
                    meta = null;
                }
            }

            if (!foundBlock || !seedHash || !meta) {
                throw new Error('You do not have access to this file');
            }
            p(1, 'done');

            await mc._wait(300);
            p(2, 'active');
            await mc._verifyAddressExists(meta.address);
            const isValid = await mc._verifySignature(
                parsed.ciphertext, meta.signature, meta.address, meta.publickey
            );
            if (!isValid) throw new Error('Invalid signature: the file may have been tampered with');
            await mc._wait(400);
            p(2, 'done');

            await mc._wait(300);
            p(3, 'active');
            const aesKey = await mc._decryptAESKey(foundBlock.encryptedKeyData, seedHash);

            const encryptedWithTag = new Uint8Array(parsed.ciphertext.length + 16);
            encryptedWithTag.set(parsed.ciphertext, 0);
            encryptedWithTag.set(meta.fileTag, parsed.ciphertext.length);

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: meta.fileIV, tagLength: 128 }, aesKey, encryptedWithTag
            );
            await mc._wait(400);
            p(3, 'done');

            console.log('[MB] decryptMultiBound: OK,', formatBytes(decrypted.byteLength));
            return { file: new Blob([decrypted]), fileSize: decrypted.byteLength, address: meta.address };

        } catch (error) {
            console.error('[MB] decryptMultiBound FAIL:', error.message);
            throw error;
        } finally {
            mc._zeroFill(seedHash);
            if (meta) {
                mc._zeroFill(meta.signature);
                mc._zeroFill(meta.fileIV);
                mc._zeroFill(meta.fileTag);
            }
        }
    }

    // ─── FILE FORMAT v4 ──────────────────────────────────────────

    /**
     * Парсит файл v3 или v4. Возвращает единую структуру.
     * @returns {{ primaryBlock, ciphertext, grantBlocks[] }}
     */
    async _parseAny(fileBlob) {
        const mc = this._mc();
        const buffer = await fileBlob.arrayBuffer();
        const view = new Uint8Array(buffer);

        if (view.length < 50) throw new Error('Файл слишком маленький');

        const magic = view.slice(0, 4);
        if (!mc._arrayEquals(magic, mc.MAGIC)) throw new Error('Invalid file format');

        const version = view[4];
        console.log('[MB] _parseAny: version =', version);

        if (version === 3) {
            return this._parseStandard(view);
        } else if (version === this.VERSION_MULTI) {
            return this._parseMultiBound(view);
        } else {
            throw new Error('Unsupported format version: ' + version);
        }
    }

    _parseStandard(view) {
        const mc = this._mc();
        let o = 5;

        const challenge = view.slice(o, o + 32); o += 32;
        const encKeyLen = mc._uint16FromLE(view, o); o += 2;
        const encryptedKeyData = view.slice(o, o + encKeyLen); o += encKeyLen;
        const encMetaLen = mc._uint32FromLE(view, o); o += 4;
        if (o + encMetaLen > view.length) throw new Error('Invalid file structure');
        const encryptedMeta = view.slice(o, o + encMetaLen); o += encMetaLen;
        const ciphertext = view.slice(o);

        console.log('[MB] _parseStandard: encKey=' + encKeyLen + ' encMeta=' + encMetaLen + ' ct=' + ciphertext.length);

        return {
            version: 3,
            primaryBlock: { challenge, encryptedKeyData, encryptedMeta },
            ciphertext,
            grantBlocks: []
        };
    }

    _parseMultiBound(view) {
        const mc = this._mc();
        let o = 5;

        const challenge = view.slice(o, o + 32); o += 32;
        const encKeyLen = mc._uint16FromLE(view, o); o += 2;
        const encryptedKeyData = view.slice(o, o + encKeyLen); o += encKeyLen;
        const encMetaLen = mc._uint32FromLE(view, o); o += 4;
        if (o + encMetaLen > view.length) throw new Error('Invalid file structure');
        const encryptedMeta = view.slice(o, o + encMetaLen); o += encMetaLen;

        const ciphertextLen = mc._uint32FromLE(view, o); o += 4;
        if (o + ciphertextLen > view.length) throw new Error('Ciphertext exceeds file bounds');
        const ciphertext = view.slice(o, o + ciphertextLen); o += ciphertextLen;

        const grantCount = mc._uint16FromLE(view, o); o += 2;
        console.log('[MB] _parseMultiBound: grantCount=' + grantCount);

        const grantBlocks = [];
        for (let i = 0; i < grantCount; i++) {
            if (o + 4 > view.length) throw new Error('Grant block #' + i + ' is truncated');
            const blockLen = mc._uint32FromLE(view, o); o += 4;
            if (o + blockLen > view.length) throw new Error('Grant block #' + i + ' exceeds file bounds');

            const blockStart = o;
            const gChallenge = view.slice(o, o + 32); o += 32;
            const gEncKeyLen = mc._uint16FromLE(view, o); o += 2;
            const gEncKeyData = view.slice(o, o + gEncKeyLen); o += gEncKeyLen;
            const gEncMetaLen = mc._uint32FromLE(view, o); o += 4;
            const gEncMeta = view.slice(o, o + gEncMetaLen); o += gEncMetaLen;

            if (o - blockStart !== blockLen) {
                console.warn('[MB] grant #' + i + ' blockLen мисматч:', o - blockStart, '!=', blockLen);
            }

            grantBlocks.push({
                challenge: gChallenge,
                encryptedKeyData: gEncKeyData,
                encryptedMeta: gEncMeta
            });
        }

        console.log('[MB] _parseMultiBound: encKey=' + encKeyLen + ' encMeta=' + encMetaLen
            + ' ct=' + ciphertext.length + ' grants=' + grantBlocks.length);

        return {
            version: 4,
            primaryBlock: { challenge, encryptedKeyData, encryptedMeta },
            ciphertext,
            grantBlocks
        };
    }

    /**
     * Добавляет grant-блок в файл. Если v3 — конвертирует в v4.
     * @returns {Blob}
     */
    _addGrantToFile(parsed, newGrantBlock) {
        const mc = this._mc();

        const allGrants = [...parsed.grantBlocks, newGrantBlock];

        const grantBuffers = allGrants.map(g => {
            const blockParts = [
                g.challenge,
                mc._uint16ToLE(g.encryptedKeyData.length), g.encryptedKeyData,
                mc._uint32ToLE(g.encryptedMeta.length), g.encryptedMeta
            ];
            let blockLen = 0;
            blockParts.forEach(p => blockLen += p.length);

            return { lenBytes: mc._uint32ToLE(blockLen), parts: blockParts };
        });

        const pb = parsed.primaryBlock;
        const parts = [
            mc.MAGIC,
            new Uint8Array([this.VERSION_MULTI]),
            pb.challenge,
            mc._uint16ToLE(pb.encryptedKeyData.length), pb.encryptedKeyData,
            mc._uint32ToLE(pb.encryptedMeta.length), pb.encryptedMeta,
            mc._uint32ToLE(parsed.ciphertext.length), parsed.ciphertext,
            mc._uint16ToLE(allGrants.length)
        ];

        grantBuffers.forEach(gb => {
            parts.push(gb.lenBytes);
            gb.parts.forEach(p => parts.push(p));
        });

        console.log('[MB] _addGrantToFile: v4, grants=' + allGrants.length);
        return new Blob(parts, { type: 'application/x-minima' });
    }

    // ─── MAXIMA ──────────────────────────────────────────────────

    /**
     * Отправляет grant-пакет через Maxima.
     * Сохраняет в SQL для повторной отправки если получатель офлайн.
     */
    async sendGrant(contactPublickey, grantPacket, fileName) {
        if (typeof MDS === 'undefined' || !MDS.cmd) throw new Error('MDS unavailable');

        const message = { ...grantPacket, fileName: fileName || 'файл' };
        const dataStr = JSON.stringify(message);
        const dataHex = this._strToHex(dataStr);
        console.log('[MB] sendGrant: отправка на', contactPublickey.substring(0, 16) + '...', 'данные:', dataStr.length, 'байт');

        await this._sqlInit();
        const pendingId = await this._sqlSavePending(contactPublickey, dataHex, fileName || 'файл', grantPacket.fileHash);

        return new Promise((resolve) => {
            const timeout = setTimeout(() => {
                console.warn('[MB] sendGrant: timeout, грант сохранён для повторной отправки (id=' + pendingId + ')');
                resolve({ queued: true });
            }, 15000);

            MDS.cmd('maxima action:send publickey:' + contactPublickey
                + ' application:seedbound data:' + dataHex + ' poll:true', (resp) => {
                clearTimeout(timeout);

                if (resp && resp.status === true) {
                    console.log('[MB] sendGrant: OK, помечаем доставленным');
                    if (pendingId !== null) this._sqlMarkDelivered(pendingId);
                    resolve({ queued: false });
                } else {
                    console.warn('[MB] sendGrant: не доставлен сейчас, сохранён для повторной отправки');
                    resolve({ queued: true });
                }
            });
        });
    }

    /**
     * Повторяет отправку всех незадоставленных грантов из SQL.
     * Вызывать при старте приложения.
     */
    async retryPendingGrants() {
        await this._sqlInit();
        const rows = await this._sqlGetPending();
        if (rows.length === 0) return;
        console.log('[MB] retryPendingGrants:', rows.length, 'в очереди');
        for (const row of rows) {
            this._sendRetry(row.id, row.recipient_pk, row.grant_hex);
        }
    }

    _sendRetry(id, recipientPK, grantHex) {
        if (typeof MDS === 'undefined' || !MDS.cmd) return;
        console.log('[MB] _sendRetry: id=' + id + ' pk=' + recipientPK.substring(0, 16) + '...');
        MDS.cmd('maxima action:send publickey:' + recipientPK
            + ' application:seedbound data:' + grantHex + ' poll:true', (resp) => {
            if (resp && resp.status === true) {
                console.log('[MB] _sendRetry: доставлен id=' + id);
                this._sqlMarkDelivered(id);
            } else {
                console.log('[MB] _sendRetry: получатель всё ещё недоступен, id=' + id);
            }
        });
    }

    /**
     * Загружает список Maxima-контактов.
     * @returns {Array<{ id, name }>}
     */
    async getContacts() {
        if (typeof MDS === 'undefined' || !MDS.cmd) throw new Error('MDS unavailable');

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Timeout: maxcontacts')), 10000);

            MDS.cmd('maxcontacts', (resp) => {
                clearTimeout(timeout);

                if (resp && resp.status === true && resp.response) {
                    const raw = Array.isArray(resp.response)
                        ? resp.response
                        : (resp.response.contacts || resp.response.maxcontacts || []);
                    const contacts = raw.map(c => ({
                        id: c.id || c.publickey,
                        publickey: c.publickey,
                        name: c.name || c.extradata?.name || c.publickey?.substring(0, 12) + '...'
                    }));
                    console.log('[MB] getContacts:', contacts.length, 'контактов');
                    resolve(contacts);
                } else {
                    resolve([]);
                }
            });
        });
    }

    /**
     * Регистрирует callback на входящие grant-пакеты через Maxima.
     * Вызывать один раз при инициализации.
     */
    onGrantReceived(callback) {
        this._maximaCallbacks.push(callback);
    }

    /**
     * Вызывается из MDS.init при событии MAXIMA.
     * @param {Object} data — msg.data из MDS
     */
    async _handleMaximaMessage(data) {
        try {
            if (!data || !data.data) return;

            let parsed;
            if (typeof data.data === 'string') {
                let raw = data.data;
                if (raw.startsWith('0x') || raw.startsWith('0X')) {
                    raw = this._hexToStr(raw);
                }
                parsed = JSON.parse(raw);
            } else {
                parsed = data.data;
            }

            if (data.application !== 'seedbound' || parsed?.type !== 'seedbound_grant') return;

            console.log('[MB] Grant получен от:', data.from?.substring(0, 16) || '?');

            await this._sqlInit();
            await this._sqlSaveReceivedGrant(parsed, data.from || '');

            this._maximaCallbacks.forEach(cb => {
                try { cb(parsed, data.from); } catch (e) {
                    console.error('[MB] Grant callback error:', e);
                }
            });
        } catch (e) {
            console.error('[MB] _handleMaximaMessage parse error:', e);
        }
    }

    // ─── SQL PERSISTENT QUEUE ────────────────────────────────────

    _sql(query) {
        return new Promise((resolve) => {
            if (typeof MDS === 'undefined' || !MDS.sql) { resolve(null); return; }
            MDS.sql(query, (resp) => {
                if (resp && resp.status === true) resolve(resp);
                else { console.warn('[MB] SQL error:', resp?.error || resp, '| query:', query); resolve(null); }
            });
        });
    }

    async _sqlInit() {
        if (this._sqlReady) return;
        await this._sql(
            'CREATE TABLE IF NOT EXISTS pending_grants (' +
            'id INTEGER AUTO_INCREMENT PRIMARY KEY,' +
            'recipient_pk VARCHAR(1024) NOT NULL,' +
            'grant_hex CLOB NOT NULL,' +
            'file_name VARCHAR(512),' +
            'file_hash VARCHAR(128),' +
            'delivered INTEGER DEFAULT 0,' +
            'created_at BIGINT)'
        );
        await this._sql(
            'CREATE TABLE IF NOT EXISTS received_grants (' +
            'id INTEGER AUTO_INCREMENT PRIMARY KEY,' +
            'file_hash VARCHAR(128) NOT NULL,' +
            'file_name VARCHAR(512),' +
            'sender_pk VARCHAR(1024),' +
            'grant_json CLOB NOT NULL,' +
            'bound INTEGER DEFAULT 0,' +
            'received_at BIGINT)'
        );
        this._sqlReady = true;
    }

    async _sqlSaveReceivedGrant(grant, senderPK) {
        const safeHash = (grant.fileHash || '').replace(/'/g, "''");
        const existing = await this._sql(
            "SELECT id FROM received_grants WHERE file_hash='" + safeHash + "' AND bound=0 LIMIT 1"
        );
        if (existing?.rows?.length > 0) {
            console.log('[MB] Грант уже есть в received_grants, пропускаем');
            return existing.rows[0].ID;
        }
        const safeJson = JSON.stringify(grant).replace(/'/g, "''");
        const safeName = (grant.fileName || 'файл').replace(/'/g, "''");
        const safePK   = (senderPK || '').replace(/'/g, "''");
        await this._sql(
            "INSERT INTO received_grants (file_hash, file_name, sender_pk, grant_json, received_at) VALUES ('" +
            safeHash + "','" + safeName + "','" + safePK + "','" + safeJson + "'," + Date.now() + ")"
        );
        const res = await this._sql('SELECT IDENTITY() as id');
        const id = res?.rows?.[0]?.ID ?? null;
        console.log('[MB] Грант сохранён в received_grants, id=' + id);
        return id;
    }

    async _sqlGetReceivedGrants() {
        const res = await this._sql('SELECT * FROM received_grants WHERE bound=0 ORDER BY received_at DESC');
        return (res?.rows || []).map(r => ({
            id:          r.ID,
            file_hash:   r.FILE_HASH,
            file_name:   r.FILE_NAME,
            sender_pk:   r.SENDER_PK,
            grant_json:  r.GRANT_JSON,
            bound:       r.BOUND,
            received_at: r.RECEIVED_AT,
            grant: (() => { try { return JSON.parse(r.GRANT_JSON); } catch(e) { return null; } })()
        }));
    }

    async _sqlMarkBound(id) {
        await this._sql('UPDATE received_grants SET bound=1 WHERE id=' + id);
        console.log('[MB] received_grants id=' + id + ' помечен bound');
    }

    async _sqlDeleteGrant(id) {
        await this._sql('DELETE FROM received_grants WHERE id=' + id);
        console.log('[MB] received_grants id=' + id + ' удалён');
    }

    async _sqlSavePending(recipientPK, grantHex, fileName, fileHash) {
        const safePK   = (recipientPK || '').replace(/'/g, "''");
        const safeHex  = (grantHex || '').replace(/'/g, "''");
        const safeName = (fileName || '').replace(/'/g, "''");
        const safeHash = (fileHash || '').replace(/'/g, "''");
        await this._sql(
            "INSERT INTO pending_grants (recipient_pk, grant_hex, file_name, file_hash, created_at) VALUES ('" +
            safePK + "','" + safeHex + "','" + safeName + "','" + safeHash + "'," + Date.now() + ")"
        );
        const res = await this._sql('SELECT IDENTITY() as id');
        return res?.rows?.[0]?.ID ?? null;
    }

    async _sqlMarkDelivered(id) {
        await this._sql('UPDATE pending_grants SET delivered=1 WHERE id=' + id);
        console.log('[MB] SQL: грант id=' + id + ' помечен доставленным');
    }

    async _sqlGetPending() {
        // Только гранты за последние 30 дней — защита от бесконечного накопления
        const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
        const res = await this._sql('SELECT * FROM pending_grants WHERE delivered=0 AND created_at>' + cutoff + ' ORDER BY created_at ASC');
        return (res?.rows || []).map(r => ({
            id:           r.ID,
            recipient_pk: r.RECIPIENT_PK,
            grant_hex:    r.GRANT_HEX,
            file_name:    r.FILE_NAME,
            file_hash:    r.FILE_HASH,
            delivered:    r.DELIVERED,
            created_at:   r.CREATED_AT
        }));
    }

    // ─── INDEXEDDB HINTS ─────────────────────────────────────────

    async _openDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(MB_DB_NAME, 1);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains(MB_DB_STORE)) {
                    db.createObjectStore(MB_DB_STORE, { keyPath: 'fileHash' });
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => {
                console.warn('[MB] IndexedDB недоступна');
                resolve(null);
            };
        });
    }

    async _saveHint(fileHash, grantIndex) {
        try {
            const db = await this._openDB();
            if (!db) return;
            const tx = db.transaction(MB_DB_STORE, 'readwrite');
            tx.objectStore(MB_DB_STORE).put({
                fileHash,
                grantIndex,
                timestamp: Date.now()
            });
            await new Promise(r => { tx.oncomplete = r; });
            db.close();
            console.log('[MB] Hint сохранён: hash=' + fileHash.substring(0, 16) + '... index=' + grantIndex);
        } catch (e) {
            console.warn('[MB] _saveHint error:', e);
        }
    }

    async _getHint(fileHash) {
        try {
            const db = await this._openDB();
            if (!db) return null;
            const tx = db.transaction(MB_DB_STORE, 'readonly');
            const req = tx.objectStore(MB_DB_STORE).get(fileHash);
            const result = await new Promise(r => { req.onsuccess = () => r(req.result); });
            db.close();
            if (result) {
                console.log('[MB] Hint найден: index=' + result.grantIndex);
                return result.grantIndex;
            }
            return null;
        } catch (e) {
            console.warn('[MB] _getHint error:', e);
            return null;
        }
    }

    // ─── UTILS ───────────────────────────────────────────────────

    _strToHex(str) {
        const bytes = new TextEncoder().encode(str);
        const parts = ['0x'];
        for (let i = 0; i < bytes.length; i++) parts.push(bytes[i].toString(16).padStart(2, '0'));
        return parts.join('');
    }

    _hexToStr(hex) {
        let clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
        if (clean.length % 2 !== 0) clean = '0' + clean; // выравнивание нечётной длины
        const bytes = new Uint8Array(clean.match(/.{2}/g).map(b => parseInt(b, 16)));
        return new TextDecoder().decode(bytes);
    }

    _toBase64(buf) {
        const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    }

    _fromBase64(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }

    /**
     * Проверяет версию файла по первым 5 байтам (не загружая весь файл).
     * @returns {number} — 3 или 4
     */
    async getFileVersion(fileBlob) {
        const header = new Uint8Array(await fileBlob.slice(0, 5).arrayBuffer());
        return header[4];
    }
}

if (typeof window !== 'undefined') {
    window.MultiBound = new MultiBoundClass();
    console.log('[MB] MultiBound готова');
}
