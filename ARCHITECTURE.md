# MinimaCrypto v1 — Архитектура шифрования

## Обзор

MinimaCrypto v1 — MiniDapp для блокчейна Minima, реализующий квантово-устойчивое шифрование файлов. Защита основана на seed phrase ноды: без неё расшифровка невозможна, даже при наличии файла `.minima`.

**Принцип:** в зашифрованном файле виден только 32-байтный `challenge`. Все остальные данные (ключ шифрования, подпись, IV, tag, адрес, публичный ключ) зашифрованы и доступны только владельцу seed phrase.

---

## Используемые криптографические примитивы

| Примитив | Назначение | Параметры |
|---|---|---|
| **AES-256-GCM** | Симметричное шифрование файла | 256-бит ключ, 128-бит IV, 128-бит Auth Tag |
| **PBKDF2-SHA512** | Деривация KEK из seedHash | 250 000 итераций, 128-бит salt, контекстная строка |
| **W-OTS+** (Winternitz One-Time Signature) | Квантово-устойчивая подпись файла | ~4125 байт подпись, одноразовый адрес |
| **seedrandom** (Minima) | Детерминированная генерация хеша из seed phrase + modifier | SHA-256 хеш, зависит от seed фразы ноды |
| **SHA-256** | Хеширование данных перед подписью | 256-бит хеш |
| **Web Crypto API** | Все криптографические операции в браузере | Нативная реализация, без JS-библиотек |

---

## Уровни защиты

### Уровень 1: Шифрование данных (AES-256-GCM)
- Файл шифруется случайным 256-битным AES ключом
- GCM режим обеспечивает конфиденциальность + целостность данных
- 128-бит Authentication Tag гарантирует обнаружение любых изменений
- Без AES ключа brute-force: 2^256 операций

### Уровень 2: Защита ключа (seedrandom + PBKDF2-SHA512)
- AES ключ обёрнут (wrapped) через KEK_key
- `KEK_key = PBKDF2-SHA512(seedHash, "qcrypto-kek-v1" + salt, 250k)`
- `seedHash` — результат `seedrandom(challenge)` на ноде Minima
- Без seed phrase → другой seedHash → другой KEK → AES ключ не извлечь
- PBKDF2-SHA512 с 250k итерациями замедляет brute-force + даёт ~256 бит квантовой стойкости

### Уровень 3: Скрытые метаданные (полный zero-knowledge)
- Адрес, публичный ключ, подпись, FileIV и FileTag зашифрованы через KEK_meta
- `KEK_meta = PBKDF2-SHA512(seedHash, "qcrypto-meta-v1" + salt, 250k)`
- Контекстные строки `"qcrypto-kek-v1"` и `"qcrypto-meta-v1"` гарантируют что KEK_key ≠ KEK_meta даже при совпадении salt
- В файле `.minima` невозможно определить какой адрес/ключ/IV/tag использовался
- Без seed phrase метаданные недоступны

### Уровень 4: Квантово-устойчивая подпись (W-OTS+)
- Каждый файл подписывается одноразовым W-OTS+ ключом через Minima
- Подпись привязана к конкретному ciphertext + address
- При расшифровке подпись верифицируется — гарантирует что файл не изменён
- W-OTS+ устойчив к атакам квантовых компьютеров (hash-based signature)
- Одноразовое использование ключа — каждый файл получает новый адрес

### Уровень 5: Привязка к ноде
- При расшифровке проверяется `checkaddress` — адрес должен принадлежать ноде
- Файл можно расшифровать только на ноде с тем же seed phrase
- Резервное копирование seed phrase = резервное копирование доступа ко всем файлам

---

## Процесс шифрования (7 шагов)

```
Файл → .minima (2 approve в ноде)
```

| Шаг | Операция | Детали |
|---|---|---|
| 1 | `newaddress` | Создаётся новый одноразовый W-OTS+ адрес (address + publickey) |
| 2 | Генерация AES ключа | `crypto.subtle.generateKey("AES-GCM", 256)` + случайный IV (16 байт) |
| 3 | Шифрование файла | `AES-256-GCM(aesKey, IV, файл)` → ciphertext + tag (16 байт) |
| 4 | W-OTS+ подпись | `sign(SHA-256(ciphertext + address), publickey)` → signature (~4125 байт). **Approve 1** |
| 5 | seedrandom | Генерация 32 случайных байт (challenge). `seedrandom(challenge)` → seedHash (32 байт). **Approve 2** |
| 6 | Обёртка ключа | `PBKDF2-SHA512(seedHash, "qcrypto-kek-v1" + salt, 250k)` → KEK_key. `AES-GCM-wrap(KEK_key, aesKey)` → encKeyData |
| 6.5 | Шифрование метаданных | `PBKDF2-SHA512(seedHash, "qcrypto-meta-v1" + salt2, 250k)` → KEK_meta. `AES-GCM(KEK_meta, address + publickey + signature + fileIV + fileTag)` → encMeta |
| 7 | Сборка файла | Все компоненты собираются в бинарный формат `.minima` v1 |

---

## Процесс расшифровки (5 шагов)

```
.minima → Файл (1 approve в ноде)
```

| Шаг | Операция | Детали |
|---|---|---|
| 1 | Парсинг | Извлечение challenge, encKeyData, encMeta, ciphertext |
| 2 | seedrandom | `seedrandom(challenge)` → тот же seedHash. **Approve 1** |
| 3 | Расшифровка метаданных | KEK_meta из seedHash → расшифровка → address, publickey, signature, fileIV, fileTag |
| 3.5 | Верификация адреса | `checkaddress(address)` → `relevant: true` (адрес принадлежит ноде) |
| 3.6 | Верификация подписи | `verify(SHA-256(ciphertext + address), publickey, signature)` → "Signature valid" |
| 4 | Расшифровка ключа | KEK_key из seedHash → unwrap AES ключ |
| 5 | Расшифровка файла | `AES-256-GCM-decrypt(aesKey, fileIV, fileTag, ciphertext)` → исходный файл |

---

## Формат файла .minima v1

```
Offset  Size     Поле              Содержимое
──────  ───────  ────────────────  ──────────────────────────
0       4        MAGIC             0x4D 0x49 0x4E 0x00 ("MIN\0")
4       1        VERSION           0x01
5       32       Challenge         Случайные 32 байт (единственные открытые данные)
37      2        EncKeyLen         Длина encKeyData (LE uint16)
39      ~76      EncKeyData        salt(16) + iv(12) + wrappedAESKey(48)
~115    4        EncMetaLen        Длина encMeta (LE uint32)
~119    ~4340    EncMeta           salt(16) + iv(12) + AES-GCM(addr + pk + sig + IV + tag)
~4459   *        Ciphertext        AES-256-GCM зашифрованные данные файла
```

**Что видно без seed phrase:** MAGIC, VERSION, Challenge (32 байт случайных данных), длины блоков, зашифрованные блобы. Никакой полезной информации.

**Что скрыто:** AES ключ, FileIV, FileTag, W-OTS+ подпись (~4125 байт), адрес (66 символов), публичный ключ (66 символов), содержимое файла.

---

## Модель угроз

| Угроза | Защита | Результат |
|---|---|---|
| Перехват файла `.minima` | AES-256-GCM + seedrandom-locked KEK | Без seed phrase данные не извлечь |
| Подмена файла | W-OTS+ подпись + AES-GCM auth tag | Любое изменение обнаруживается |
| Brute-force AES ключа | 256-бит ключ (2^256 пространство) | Вычислительно невозможно |
| Brute-force KEK | PBKDF2-SHA512 250k + seedrandom + контекст | Замедляет атаку + требует seed phrase |
| Квантовый компьютер (Гровер) | SHA-512 в PBKDF2 → ~256 бит квантовой стойкости | Устойчив |
| Квантовый компьютер (Шор) | W-OTS+ (hash-based, quantum-resistant) | Устойчив |
| Анализ метаданных | addr + pk + sig + IV + tag зашифрованы | Полный zero-knowledge |
| Совпадение KEK_key и KEK_meta | Контекстные строки `"qcrypto-kek-v1"` / `"qcrypto-meta-v1"` | Невозможно даже теоретически |
| Потеря ноды | Восстановление через seed phrase | Все адреса и seedrandom воспроизводимы |

---

## Зависимости

- **Minima Node** — блокчейн-нода с W-OTS+ подписями и `seedrandom`
- **MDS (MiniDapp System)** — WebSocket API для взаимодействия с нодой
- **Web Crypto API** — нативные криптографические примитивы браузера (AES, SHA-512, PBKDF2)
- **Без внешних библиотек** — вся криптография через стандартные API

---

## Команды Minima

| Команда | Когда | Требует approve |
|---|---|---|
| `newaddress` | Создание одноразового W-OTS+ адреса | Нет |
| `sign data:HASH publickey:PK` | Подпись хеша файла | Да |
| `seedrandom modifier:"CHALLENGE"` | Деривация хеша из seed phrase | Да |
| `checkaddress address:ADDR` | Проверка принадлежности адреса ноде | Нет |
| `verify data:HASH publickey:PK signature:SIG` | Верификация W-OTS+ подписи | Нет |

---

## Итого

- **Шифрование:** 2 подтверждения в ноде (sign + seedrandom)
- **Расшифровка:** 1 подтверждение в ноде (seedrandom)
- **Квантовая устойчивость:** W-OTS+ подпись (hash-based) + PBKDF2-SHA512 (~256 бит квантовой стойкости)
- **Привязка к ноде:** seedrandom детерминирован от seed phrase
- **Zero-knowledge:** в файле видны только 32 случайных байт (challenge) — ни IV, ни tag, ни метаданные
- **Разделение ключей:** контекстные строки гарантируют KEK_key ≠ KEK_meta
