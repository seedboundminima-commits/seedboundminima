# CLAUDE.md — SeedBound / Minima Quantum Crypto

## Что это за проект

MiniDapp (децентрализованное приложение) для сети Minima Blockchain.
Квантово-устойчивое шифрование файлов + система многопользовательского доступа через гранты.

**Ключевая идея**: файл шифруется один раз, но к нему можно добавить несколько «замков» (grant-блоков), каждый из которых привязан к отдельной Minima-ноде. Расшифровать может любой владелец одного из замков — на своей ноде.

---

## Файловая структура

```
seedboundminima/
├── index.html            — весь UI (одностраничное приложение)
├── mds.js                — WebSocket-клиент к Minima-ноде (MDS v2.1.0, не трогаем)
├── MinimaCrypto.js       — шифрование v3, ядро криптографии
├── MultiBound.js         — система грантов, формат v4 (ОСНОВНОЙ ФАЙЛ ДЛЯ РАБОТЫ)
├── dapp.conf             — манифест MiniDapp (name, version, icon)
├── favicon.ico
├── README.md             — пользовательская документация
├── ARCHITECTURE.md       — техническая архитектура
├── MULTI-BOUND-SPEC.md   — спецификация формата v4 и системы грантов (подробно)
└── TESTING.md            — план ручного тестирования (50+ тест-кейсов)
```

---

## Архитектура

```
index.html  (UI)
    │
    ├── MinimaCrypto.js  (window.MinimaCrypto)
    │       └── шифрование/расшифровка v3
    │
    └── MultiBound.js    (window.MultiBound)
            └── зависит от MinimaCrypto, никогда не изменяет его
                └── гранты, формат v4, Maxima P2P, IndexedDB
                        │
                    mds.js  (window.MDS)
                        └── WebSocket → Minima Node
```

**Правило**: `MultiBound.js` использует `MinimaCrypto.js` через `window.MinimaCrypto`, но **никогда не изменяет** его. Если нужна новая криптографическая операция — она добавляется в `MinimaCrypto.js`, а вызывается из `MultiBound.js`.

---

## Бинарный формат файлов .minima

### Standard / v1 (только свой узел)
```
MAGIC(4)="MIN\0" | VERSION(1)=0x01 | Challenge(32)
| EncKeyLen(2/LE) | EncKeyData(~76)
| EncMetaLen(4/LE) | EncMeta(~4340)
| Ciphertext(*)
```

### Multi-Bound / v2 (несколько получателей)
```
MAGIC(4)="MIN\0" | VERSION(1)=0x02 | PrimaryChallenge(32)
| EncKeyLen(2/LE) | EncKeyData
| EncMetaLen(4/LE) | EncMeta
| CiphertextLen(4/LE) | Ciphertext(CiphertextLen)
| GrantCount(2/LE)
| [GrantBlock * GrantCount]
```

### GrantBlock
```
BlockLen(4/LE) | Challenge(32) | EncKeyLen(2/LE) | EncKeyData | EncMetaLen(4/LE) | EncMeta
```

**Важно**: все многобайтовые числа — **little-endian**. Методы: `_uint16FromLE`, `_uint32FromLE`, `_uint16ToLE`, `_uint32ToLE` — в `MinimaCrypto.js`.

---

## Криптографические примитивы

| Что | Алгоритм | Где |
|-----|----------|-----|
| Шифрование файла | AES-256-GCM | `crypto.subtle` |
| Обёртывание AES-ключа | AES-KW 256 | `crypto.subtle` |
| Деривация KEK | PBKDF2-SHA512, 250 000 итераций | `crypto.subtle` |
| Подпись | W-OTS+ (через `sign` команду Minima) | MDS → Minima Node |
| Seed binding | `seedrandom(challenge)` → 64-byte seedHash | MDS → Minima Node (требует approve) |
| Хэш файла | SHA-256 от ciphertext | `crypto.subtle` |
| IV файла | 12 байт случайных | `crypto.getRandomValues` |
| Auth tag | 16 байт, часть AES-GCM | отдельно в метаданных |

---

## Команды Minima Node (через MDS)

| Команда | Назначение | Требует approve |
|---------|-----------|----------------|
| `newaddress` | Создаёт W-OTS+ адрес | нет |
| `sign data:HASH publickey:PK` | Подпись данных | **да** |
| `seedrandom modifier:"CHALLENGE"` | Детерминированный хэш от seed-фразы | **да** |
| `checkaddress address:ADDR` | Проверка принадлежности адреса ноде | нет |
| `verify data:HASH publickey:PK signature:SIG` | Проверка подписи | нет |
| `maxcontacts` | Список P2P-контактов | нет |
| `maxima action:send publickey:PK application:seedbound data:JSON` | P2P отправка гранта (3 варианта: `id:N`, `to:MxAddr`, `publickey:PK`) | нет |

**Approve**: когда Minima запрашивает подтверждение у пользователя — в MDS-ответе приходит `pending:true`. Нужно ждать следующего события с `status:true`. Это обработано в `mc._getSeedRandom()` и `mc._signWithMinima()`.

---

## Grant Packet (передаётся через Maxima)

```json
{
  "type": "seedbound_grant",
  "version": 1,
  "fileHash": "<hex SHA-256 от ciphertext>",
  "aesKeyB64": "<base64 32-байт AES-ключ>",
  "fileIVB64": "<base64 12-байт IV>",
  "fileTagB64": "<base64 16-байт auth tag>"
}
```

**Внимание**: пакет содержит сырой AES-ключ в открытом виде внутри Maxima-сообщения. Это намеренно — безопасность обеспечивается Maxima-шифрованием (E2E). После получения ключ немедленно шифруется под seedHash получателя.

---

## Потоки операций

### Шифрование (v3) — 2 approve
1. `newaddress` → адрес + публичный ключ
2. Генерация AES-ключа, IV, шифрование файла → ciphertext + tag
3. `sign(ciphertext)` → подпись *(approve #1)*
4. `getRandomValues(32)` → challenge
5. `seedrandom(challenge)` → seedHash *(approve #2)*
6. Деривация KEK через PBKDF2, обёртывание AES-ключа
7. Шифрование метаданных (адрес, ключ, подпись, IV, tag) отдельным KEK_meta
8. Сборка бинарного файла v3

### Создание гранта (createGrant) — 1 approve
1. Парсинг файла
2. `seedrandom(challenge)` → seedHash *(approve #1)*
3. Расшифровка метаданных → получение fileIV, fileTag
4. Расшифровка AES-ключа
5. Возврат grant-пакета (fileHash, aesKeyB64, fileIVB64, fileTagB64)

### Привязка гранта (bindGrant) — 2 approve
1. Парсинг файла, проверка fileHash
2. `newaddress` → адрес получателя
3. `sign(ciphertext)` → подпись получателя *(approve #1)*
4. `getRandomValues(32)` → challenge
5. `seedrandom(challenge)` → seedHash получателя *(approve #2)*
6. Шифрование AES-ключа + метаданных под seedHash получателя
7. Добавление grant-блока в файл (v3→v4 или v4+1 блок)
8. Сохранение подсказки в IndexedDB

### Расшифровка v4 — 1..N approve (оптимизировано IndexedDB)
1. Парсинг файла, вычисление fileHash
2. Поиск подсказки в IndexedDB (если есть — нужный блок первым)
3. Для каждого блока: `seedrandom(challenge)` *(approve)* → попытка расшифровки метаданных
4. При успехе: проверка адреса, проверка подписи
5. Расшифровка AES-ключа → расшифровка ciphertext

---

## IndexedDB

- **SQL движок**: H2 (не SQLite!) — `AUTO_INCREMENT` не `AUTOINCREMENT`, типы `VARCHAR`, `CLOB`, `BIGINT`, колонки в ответе **UPPERCASE**
- **SQL API**: `MDS.sql(query, callback)` — не `MDS.cmd('sql ...')`
- **База**: `seedbound_grants`
- **Хранилище**: `hints`
- **Схема**: `{ fileHash: string, grantIndex: number, timestamp: number }`
- **Назначение**: запоминает, какой grant-блок (индекс) принадлежит данной ноде, чтобы при следующей расшифровке сразу пробовать нужный блок и не делать лишних approve.
- **Индекс 0** = primary block (владелец файла), **1+** = grant-блоки.

---

## Zero-fill (безопасное затирание памяти)

После использования чувствительных данных всегда вызывается `mc._zeroFill(data)`:
- `seedHash` — всегда в `finally`
- `aesKeyRaw` — всегда в `finally`
- `signature` — в `finally`
- `meta.fileIV`, `meta.fileTag` — в `finally`

**Никогда не убирать** zero-fill из `finally`-блоков — это защита от утечки ключей в памяти.

---

## UI (index.html)

Одностраничное приложение, четыре страницы:
1. **Encrypt** — загрузка файла → шифрование → скачать .minima
2. **Decrypt** — загрузка .minima → расшифровка → скачать оригинал
3. **Share** — две вкладки:
   - *Send Grant*: загрузка файла → выбор Maxima-контакта → отправить грант
   - *Bind Grant*: получение уведомления о гранте → загрузка файла → привязать → скачать v4
4. **About** — информация о безопасности

**Grant-уведомления**: входящие гранты через Maxima отображаются как бейджи в сайдбаре и всплывают в углу. Хранятся в `window._pendingGrants`.

---

## Конфигурация dapp.conf

```json
{
  "name": "Quantum Crypto",
  "version": "3.0.0",
  "description": "Quantum-resistant file encryption using Minima blockchain",
  "icon": "favicon.ico",
  "category": "Security"
}
```

При изменении версии — обновлять здесь.

---

## Важные ограничения и особенности

- **Размер файла**: рекомендовано до 100 МБ (браузерная память)
- **v3 → v4**: `_parseAny` поддерживает оба формата; `_addGrantToFile` всегда пишет v4
- **v4 → v3**: невозможно и не нужно
- **Кросс-нодовая защита**: файл, зашифрованный на ноде А, не расшифруется на ноде Б — если только не добавлен grant-блок для Б
- **Нет серверов**: всё работает в браузере + Minima-нода локально
- **`mds.js` не трогаем**: это внешняя библиотека Minima

---

## Типичные паттерны кода

```javascript
// Получить MinimaCrypto
const mc = this._mc(); // бросит Error если не загружена

// Прогресс-колбэк
const p = options.onProgress || (() => {});
p(stepIndex, 'active' | 'pending' | 'done');

// Буфер ↔ hex
mc._bufferToHex(buffer)
mc._hexToBuffer(hex)

// Base64 (в MultiBound.js, не в MinimaCrypto)
this._toBase64(uint8array)
this._fromBase64(base64string)

// LE числа
mc._uint16FromLE(view, offset)
mc._uint32FromLE(view, offset)
mc._uint16ToLE(value)   // → Uint8Array(2)
mc._uint32ToLE(value)   // → Uint8Array(4)

// Пауза между шагами (для UX)
await mc._wait(milliseconds)

// Безопасное затирание
mc._zeroFill(sensitiveData) // принимает Uint8Array | null | undefined
```

---

## Что НЕ делать

- Не изменять `mds.js` — внешняя библиотека
- Не добавлять серверную логику — dapp работает полностью локально
- Не менять формат grant-пакета без версионирования (`version: 1` → `version: 2`)
- Не убирать `finally { mc._zeroFill(...) }` блоки
- Не кешировать seedHash между вызовами — он должен запрашиваться каждый раз
- Не трогать `MAGIC` и версионные константы без обновления обоих парсеров

---

## Тестирование

Ручной план тестирования: `TESTING.md` (50+ тест-кейсов).
Автоматических тестов нет — добавить при необходимости.

Для тестирования нужны минимум 2 запущенные Minima-ноды.
