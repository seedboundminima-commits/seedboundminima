'use strict';

let currentEncryptFile = null;
let currentDecryptFile = null;
let currentShareFile   = null;
let currentBindFile    = null;
let pendingGrant       = null;
let selectedGrantId    = null;
let operationInProgress = false;

const MAX_FILE_SIZE = 100 * 1024 * 1024;

/* ─── UTILS ─────────────────────────────────── */

function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/* ─── INIT ──────────────────────────────────── */

MDS.init(function(msg) {
    if (msg.event === 'MAXIMA' && window.MultiBound) {
        window.MultiBound._handleMaximaMessage(msg.data);
    }
    if (msg.event === 'inited' && window.MultiBound) {
        window.MultiBound.retryPendingGrants();
        loadReceivedGrants();
    }
});

if (window.MultiBound) {
    window.MultiBound.onGrantReceived(function(grant, from) {
        pendingGrant = grant;
        showGrantNotification(grant.fileName || 'file', from);
    });
}

if (!window.crypto || !window.crypto.subtle) {
    document.querySelector('.main').innerHTML =
        '<div class="card"><div class="error-box">' +
        '<strong>Browser not supported.</strong><br>' +
        'A modern browser with Web Crypto API support is required.' +
        '</div></div>';
}

window.addEventListener('beforeunload', function(e) {
    if (operationInProgress) {
        e.preventDefault();
        e.returnValue = '';
    }
});

/* ─── NAVIGATION ────────────────────────────── */

function navigateTo(pageId, btn) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('page-' + pageId).classList.add('active');
    btn.classList.add('active');
    if (pageId === 'share') { loadContacts(); loadReceivedGrants(); }
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('collapsed');
}

function switchShareTab(tabName, btn) {
    document.querySelectorAll('#page-share .tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('#page-share .tab').forEach(t => t.classList.remove('active'));
    document.getElementById('share-' + tabName + '-tab').classList.add('active');
    btn.classList.add('active');
}

/* ─── MODAL ─────────────────────────────────── */

const ENCRYPT_STEPS = [
    'Creating one-time key',
    'Preparing encryption',
    'Encrypting file',
    'Signing file',
    'Binding to your node',
    'Protecting keys',
    'Assembling encrypted file'
];

const DECRYPT_STEPS = [
    'Reading file',
    'Verifying node access',
    'Extracting metadata',
    'Verifying integrity',
    'Decrypting file'
];

const SEND_GRANT_STEPS = [
    'Reading file',
    'Verifying node access',
    'Extracting keys'
];

const BIND_GRANT_STEPS = [
    'Verifying file',
    'Decrypting'
];

const DECRYPT_V4_STEPS = [
    'Reading file',
    'Locating your access grant',
    'Verifying integrity',
    'Decrypting file'
];

function openModal(title, steps) {
    const modal     = document.getElementById('progress-modal');
    const titleEl   = document.getElementById('modal-title');
    const listEl    = document.getElementById('modal-steps');
    const actionsEl = document.getElementById('modal-actions');
    const errorEl   = document.getElementById('modal-error');

    titleEl.textContent = title;
    actionsEl.innerHTML = '';
    actionsEl.classList.remove('visible');
    errorEl.style.display = 'none';
    errorEl.textContent = '';
    listEl.innerHTML = '';

    steps.forEach((label, i) => {
        const li = document.createElement('li');
        li.className = 'step-item';
        li.id = 'step-' + i;
        li.innerHTML =
            '<div class="step-icon">' + (i + 1) + '</div>' +
            '<div class="step-label">' +
                '<div>' + escapeHtml(label) + '</div>' +
                '<div class="step-hint" id="step-hint-' + i + '"></div>' +
            '</div>';
        listEl.appendChild(li);
    });

    modal.classList.add('open');
}

function updateStep(index, state) {
    const el   = document.getElementById('step-' + index);
    const hint = document.getElementById('step-hint-' + index);
    if (!el) return;

    el.className = 'step-item ' + state;

    const icon = el.querySelector('.step-icon');
    if (state === 'done')  icon.innerHTML = '&#10003;';
    else if (state === 'error') icon.innerHTML = '&#10007;';

    hint.textContent = state === 'pending' ? 'Open Pending Actions in your node and approve' : '';
}

function showModalError(message) {
    const errorEl   = document.getElementById('modal-error');
    errorEl.textContent = message;
    errorEl.style.display = 'block';

    const actionsEl = document.getElementById('modal-actions');
    actionsEl.innerHTML = '<button class="button" onclick="closeModal()">Close</button>';
    requestAnimationFrame(() => actionsEl.classList.add('visible'));
}

function showModalDownload(blob, filename, hint) {
    const actionsEl = document.getElementById('modal-actions');
    actionsEl.innerHTML = '';

    if (hint) {
        const hintEl = document.createElement('p');
        hintEl.style.cssText = 'color:#8B949E;font-size:12px;margin:0 0 12px;line-height:1.5;';
        hintEl.textContent = hint;
        actionsEl.appendChild(hintEl);
    }

    const btn = document.createElement('button');
    btn.className = 'button button-green';
    btn.textContent = 'Download ' + filename;
    btn.onclick = function() { window.MinimaCrypto.downloadFile(blob, filename); };
    actionsEl.appendChild(btn);

    const closeBtn = document.createElement('button');
    closeBtn.className = 'button';
    closeBtn.textContent = 'Close';
    closeBtn.style.background = '#1C1C1C';
    closeBtn.style.marginLeft = '8px';
    closeBtn.onclick = closeModal;
    actionsEl.appendChild(closeBtn);

    requestAnimationFrame(() => actionsEl.classList.add('visible'));
}

function closeModal() {
    document.getElementById('progress-modal').classList.remove('open');
}

/* ─── ERROR HANDLING ────────────────────────── */

function friendlyError(msg) {
    if (msg === 'DENIED') return 'Action denied. You clicked Deny in Pending Actions.';
    if (msg === 'DISCONNECTED') return 'Connection to node lost. Make sure Minima is running.';
    if (msg === 'TIMEOUT') return 'Request timed out. Approve the action in Pending Actions and try again.';
    if (msg.includes('MDS unavailable')) return 'Minima node is unavailable. Check your connection.';
    if (msg.includes('Invalid file format')) return 'This file is not a valid encrypted .minima file.';
    if (msg.includes('Unsupported format version')) return 'This file was created with a different version of the app.';
    if (msg.includes('Failed to decrypt')) return 'Decryption failed. The file was encrypted on a different node.';
    if (msg.includes('does not belong')) return 'File was encrypted on a different node. The same seed phrase is required.';
    if (msg.includes('Invalid signature') || msg.includes('tampered')) return 'The file is corrupted or has been modified after encryption.';
    if (msg.includes('Timeout')) return 'Node did not respond. Check your connection and try again.';
    if (msg.includes('fileHash mismatch')) return 'This grant does not match the file. Make sure you selected the correct file.';
    if (msg.includes('do not have access')) return 'You do not have access to this file. Request a grant from the file owner.';
    if (msg.includes('Maxima')) return 'Maxima error. Check that the contact is online.';
    return msg;
}

function markActiveStepsAsError() {
    document.querySelectorAll('.step-item.active, .step-item.pending').forEach(s => {
        s.className = 'step-item error';
        s.querySelector('.step-icon').innerHTML = '&#10007;';
        s.querySelector('.step-hint').textContent = '';
    });
}

/* ─── FILE HANDLING ─────────────────────────── */

function checkFileSize(file, type) {
    const infoEl = document.getElementById(type + '-file-info');
    const btnEl  = document.getElementById(type + '-button');

    document.getElementById(type + '-filename').textContent = file.name;
    document.getElementById(type + '-filesize').textContent = formatFileSize(file.size);
    infoEl.style.display = 'block';

    if (file.size > MAX_FILE_SIZE) {
        infoEl.innerHTML =
            '<strong style="color:#EF4444;">File too large:</strong> ' + escapeHtml(formatFileSize(file.size)) +
            '<div style="margin-top:6px;color:#888888;font-size:0.85em;">Maximum file size is 100 MB</div>';
        btnEl.disabled = true;
        return false;
    }

    btnEl.disabled = false;
    return true;
}

function handleEncryptFile(event) {
    const file = event.target.files[0];
    if (file) { currentEncryptFile = file; checkFileSize(file, 'encrypt'); }
}

function handleDecryptFile(event) {
    const file = event.target.files[0];
    if (file) { currentDecryptFile = file; checkFileSize(file, 'decrypt'); }
}

/* ─── SHARE / GRANT ─────────────────────────── */

function handleShareFile(event) {
    const file = event.target.files[0];
    if (file) {
        currentShareFile = file;
        document.getElementById('share-filename').textContent = file.name;
        document.getElementById('share-filesize').textContent = formatFileSize(file.size);
        document.getElementById('share-file-info').style.display = 'block';
        updateShareSendButton();
    }
}

function handleBindFile(event) {
    const file = event.target.files[0];
    if (file) {
        currentBindFile = file;
        document.getElementById('bind-filename').textContent = file.name;
        document.getElementById('bind-filesize').textContent = formatFileSize(file.size);
        document.getElementById('bind-file-info').style.display = 'block';
        document.getElementById('bind-button').disabled = !pendingGrant;
    }
}

function updateShareSendButton() {
    const sel = document.getElementById('share-contact-select');
    const btn = document.getElementById('share-send-button');
    btn.disabled = !currentShareFile || !sel.value;
}

async function loadContacts() {
    if (!window.MultiBound) return;
    const sel = document.getElementById('share-contact-select');
    sel.innerHTML = '<option value="">Loading...</option>';
    sel.disabled = true;

    try {
        const contacts = await window.MultiBound.getContacts();
        sel.innerHTML = '';
        if (contacts.length === 0) {
            sel.innerHTML = '<option value="">No Maxima contacts found</option>';
        } else {
            sel.innerHTML = '<option value="">Select a contact</option>';
            contacts.forEach(c => {
                const opt = document.createElement('option');
                opt.value = c.publickey || c.id;
                opt.textContent = c.name;
                sel.appendChild(opt);
            });
            sel.disabled = false;
        }
    } catch (e) {
        sel.innerHTML = '<option value="">Failed to load contacts</option>';
    }

    sel.onchange = updateShareSendButton;
}

async function sendGrant() {
    if (!currentShareFile || !window.MultiBound) return;
    const contactId = document.getElementById('share-contact-select').value;
    if (!contactId) return;

    operationInProgress = true;
    setButtonsDisabled(true);
    openModal('Sending access: ' + currentShareFile.name, SEND_GRANT_STEPS);

    try {
        const oneTime = document.getElementById('share-onetime-check').checked;
        const grant = await window.MultiBound.createGrant(currentShareFile, { onProgress: updateStep });
        if (oneTime) grant.oneTime = true;

        const result = await window.MultiBound.sendGrant(contactId, grant, currentShareFile.name);

        const actionsEl = document.getElementById('modal-actions');
        if (result && result.queued) {
            actionsEl.innerHTML =
                '<p style="color:#8B949E;font-size:12px;margin:0 0 12px;line-height:1.5;">' +
                'The recipient is currently offline. The grant has been saved and will be delivered automatically when they come online.</p>' +
                '<button class="button" onclick="closeModal()">Got it</button>';
        } else {
            actionsEl.innerHTML = '<button class="button" onclick="closeModal()">Done</button>';
        }
        requestAnimationFrame(() => actionsEl.classList.add('visible'));

    } catch (error) {
        markActiveStepsAsError();
        showModalError(friendlyError(error.message));
    } finally {
        operationInProgress = false;
        setButtonsDisabled(false);
        updateShareSendButton();
    }
}

async function loadReceivedGrants() {
    if (!window.MultiBound) return;
    await window.MultiBound._sqlInit();
    const grants = await window.MultiBound._sqlGetReceivedGrants();
    const list    = document.getElementById('bind-grants-list');
    const noGrant = document.getElementById('bind-no-grant');

    if (grants.length === 0) {
        list.innerHTML = '';
        noGrant.style.display = 'block';
        document.getElementById('share-badge').classList.remove('show');
        return;
    }

    noGrant.style.display = 'none';
    document.getElementById('share-badge').classList.add('show');

    const items = grants.map(g => {
        const date     = new Date(parseInt(g.received_at)).toLocaleString();
        const from     = g.sender_pk ? escapeHtml(g.sender_pk.substring(0, 20)) + '...' : 'unknown';
        const fileName = escapeHtml(g.file_name || 'file');
        const oneTimeLabel = g.grant && g.grant.oneTime
            ? '<span style="color:#F85149;font-size:11px;margin-left:6px;border:1px solid #F85149;border-radius:3px;padding:1px 4px;">1×</span>'
            : '';

        const id = parseInt(g.id);
        return '<div class="file-info" style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">' +
            '<div>' +
            '<strong style="color:#E6EDF3;">' + fileName + '</strong>' + oneTimeLabel +
            '<div style="font-size:11px;color:#888888;margin-top:2px;">Received: ' + escapeHtml(date) + ' · from ' + from + '</div>' +
            '</div>' +
            '<div style="display:flex;gap:6px;flex-shrink:0;">' +
            '<button class="button" style="background:#FF6B00;padding:6px 14px;font-size:12px;white-space:nowrap;" onclick="selectGrant(' + id + ')">Select</button>' +
            '<button class="button" style="background:#1C1C1C;padding:6px 10px;font-size:12px;" title="Delete grant" onclick="deleteGrant(' + id + ')">✕</button>' +
            '</div>' +
            '</div>';
    });

    list.innerHTML = items.join('');
}

function selectGrant(id) {
    if (!window.MultiBound) return;
    window.MultiBound._sqlGetReceivedGrants().then(grants => {
        const row = grants.find(g => g.id == id);
        if (!row || !row.grant) return;
        pendingGrant    = row.grant;
        selectedGrantId = row.id;
        currentBindFile = null;
        document.getElementById('bind-file-info').style.display    = 'none';
        document.getElementById('bind-selected-name').textContent  = row.file_name || 'file';
        document.getElementById('bind-file-section').style.display = 'block';
        document.getElementById('bind-button').disabled = true;
    });
}

function clearSelectedGrant() {
    pendingGrant    = null;
    selectedGrantId = null;
    currentBindFile = null;
    document.getElementById('bind-file-section').style.display = 'none';
    document.getElementById('bind-file-info').style.display    = 'none';
}

async function deleteGrant(id) {
    if (!window.MultiBound) return;
    if (!confirm('Delete this grant? This action cannot be undone.')) return;
    await window.MultiBound._sqlDeleteGrant(id);
    // if the deleted grant was selected — clear the selection
    if (selectedGrantId === id) clearSelectedGrant();
    loadReceivedGrants();
}

async function bindGrant() {
    if (!currentBindFile || !pendingGrant || !window.MultiBound) return;

    operationInProgress = true;
    setButtonsDisabled(true);
    openModal('Decrypting: ' + currentBindFile.name, BIND_GRANT_STEPS);

    try {
        const result  = await window.MultiBound.decryptWithGrant(currentBindFile, pendingGrant, { onProgress: updateStep });
        const outName = currentBindFile.name.replace(/\.v\d+\.minima$/i, '').replace(/\.minima$/i, '');
        showModalDownload(result.file, outName);

        if (pendingGrant?.oneTime && selectedGrantId !== null) {
            await window.MultiBound._sqlMarkBound(selectedGrantId);
        }

        pendingGrant    = null;
        selectedGrantId = null;
        currentBindFile = null;
        document.getElementById('bind-file-section').style.display = 'none';
        document.getElementById('bind-file-info').style.display    = 'none';
        loadReceivedGrants();

    } catch (error) {
        markActiveStepsAsError();
        showModalError(friendlyError(error.message));
    } finally {
        operationInProgress = false;
        setButtonsDisabled(false);
    }
}

function showGrantNotification(fileName, from) {
    const notif = document.getElementById('grant-notification');
    const text  = document.getElementById('grant-notification-text');
    text.textContent = 'You have been granted access to "' + fileName + '"';
    notif.classList.add('show');
    document.getElementById('share-badge').classList.add('show');
    loadReceivedGrants();
}

function acceptGrantNotification() {
    dismissGrantNotification();
    const shareBtn = document.getElementById('nav-share');
    navigateTo('share', shareBtn);
    const bindTab = document.querySelector('#page-share .tab:nth-child(2)');
    switchShareTab('bind', bindTab);
}

function dismissGrantNotification() {
    document.getElementById('grant-notification').classList.remove('show');
}

async function pasteGrantManual() {
    const text = document.getElementById('bind-manual-input').value.trim();
    if (!text) return;
    try {
        const grant = JSON.parse(text);
        if (grant.type !== 'seedbound_grant' || !grant.aesKeyB64 || !grant.fileHash) {
            alert('Invalid format. Expected JSON with fields: type, fileHash, aesKeyB64, fileIVB64, fileTagB64.');
            return;
        }
        if (window.MultiBound) {
            await window.MultiBound._sqlInit();
            await window.MultiBound._sqlSaveReceivedGrant(grant, '');
        }
        document.getElementById('bind-manual-input').value = '';
        loadReceivedGrants();
    } catch (e) {
        alert('JSON parse error: ' + e.message);
    }
}

/* ─── ENCRYPT / DECRYPT ─────────────────────── */

function setButtonsDisabled(disabled) {
    document.getElementById('encrypt-button').disabled   = disabled;
    document.getElementById('decrypt-button').disabled   = disabled;
    document.getElementById('share-send-button').disabled = disabled;
    document.getElementById('bind-button').disabled      = disabled;
}

async function encryptFile() {
    if (!currentEncryptFile || !window.MinimaCrypto) return;

    operationInProgress = true;
    setButtonsDisabled(true);
    openModal('Encrypting: ' + currentEncryptFile.name, ENCRYPT_STEPS);

    try {
        const result  = await window.MinimaCrypto.encryptFile(currentEncryptFile, { onProgress: updateStep });
        const outName = currentEncryptFile.name + '.minima';
        showModalDownload(result.file, outName);
    } catch (error) {
        markActiveStepsAsError();
        showModalError(friendlyError(error.message));
    } finally {
        operationInProgress = false;
        setButtonsDisabled(false);
        if (currentEncryptFile) document.getElementById('encrypt-button').disabled = false;
        if (currentDecryptFile) document.getElementById('decrypt-button').disabled = false;
    }
}

async function decryptFile() {
    if (!currentDecryptFile || !window.MinimaCrypto) return;

    operationInProgress = true;
    setButtonsDisabled(true);

    let version = 1;
    try {
        if (window.MultiBound) version = await window.MultiBound.getFileVersion(currentDecryptFile);
    } catch (e) { /* fallback to v3 */ }

    const isMultiBound = version === 2;
    const steps = isMultiBound ? DECRYPT_V4_STEPS : DECRYPT_STEPS;
    openModal('Decrypting: ' + currentDecryptFile.name, steps);

    try {
        let result;
        if (isMultiBound && window.MultiBound) {
            result = await window.MultiBound.decryptMultiBound(currentDecryptFile, { onProgress: updateStep });
        } else {
            result = await window.MinimaCrypto.decryptFile(currentDecryptFile, { onProgress: updateStep });
        }

        const outName = currentDecryptFile.name.replace(/\.v\d+\.minima$/i, '').replace(/\.minima$/i, '');
        showModalDownload(result.file, outName);
    } catch (error) {
        markActiveStepsAsError();
        showModalError(friendlyError(error.message));
    } finally {
        operationInProgress = false;
        setButtonsDisabled(false);
        if (currentEncryptFile) document.getElementById('encrypt-button').disabled = false;
        if (currentDecryptFile) document.getElementById('decrypt-button').disabled = false;
    }
}

/* ─── DRAG & DROP ───────────────────────────── */

['encrypt', 'decrypt', 'share', 'bind'].forEach(type => {
    const area = document.getElementById(type + '-upload-area');
    if (!area) return;

    area.addEventListener('dragover', (e) => {
        e.preventDefault();
        area.classList.add('dragover');
    });

    area.addEventListener('dragleave', () => {
        area.classList.remove('dragover');
    });

    area.addEventListener('drop', (e) => {
        e.preventDefault();
        area.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length === 0) return;
        const file = files[0];
        if      (type === 'encrypt') { currentEncryptFile = file; checkFileSize(file, type); }
        else if (type === 'decrypt') { currentDecryptFile = file; checkFileSize(file, type); }
        else if (type === 'share')   { handleShareFile({ target: { files: [file] } }); }
        else if (type === 'bind')    { handleBindFile({ target: { files: [file] } }); }
    });
});
