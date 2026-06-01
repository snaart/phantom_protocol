# Phantom Core Rust → Production-Ready: дорожная карта

> ⚠ **Historical baseline (pre-implementation, 2026).** This document is the
> original gap-analysis roadmap that motivated the Phase 0–7 effort. Most
> items framed below as "to-do" or "future work" have since been
> **implemented and shipped** — see [`PROGRESS.md`](PROGRESS.md) for the
> live status tracker, updated alongside every feature commit with
> `file:line` evidence and commit SHAs. Phases 0–7 are now closed:
> Phase 3 (11 of 11 ✅), Phase 4 (6 of 6 ✅), Phase 5 (code-side ✅,
> external CMVP lab validation remains), Phase 6 (code-side ✅, formal
> verification audit-driven), Phase 7 (8 of 8 ✅). The cryptographic
> primitives referenced as `pqcrypto-kyber` / `pqcrypto-dilithium`
> throughout this doc were swapped to `ml-kem` (FIPS 203) / `ml-dsa`
> (FIPS 204) in Phase 5.1. Use this file as historical context + design
> rationale; use `PROGRESS.md` for current state.

## Context

**Что есть сейчас.** Phantom Core (0.2.0, ~11.8 KLOC) — это пост-квантово-безопасный L4/L6 транспорт на Rust с гибридной криптографией (X25519+Kyber768 KEM, Ed25519+Dilithium3 signatures), AEAD (ring AES-256-GCM или ChaCha20-Poly1305), мульти-leg транспортом (TCP, KCP-over-UDP, FakeTLS) и публичным API через UniFFI. Архитектурный фундамент крепкий: три HIGH-severity уязвимости из security review мая 2026 закрыты, инварианты соблюдены (pin server-key, ENCRYPTED-flag enforcement, FakeTLS per-record counter nonces), 122 unit-теста проходят, бенчи существуют.

**Чего не хватает для production.** Конкретные пробелы, обнаруженные при exhaustive code-сканировании:

1. **Security:** timing-leak в cookie comparison (`handshake.rs:136`), `CryptoState::session_key` без `Zeroize`, `.unwrap()` на пути handshake (3 места), нет mid-session key rotation (нет PFS в пределах сессии), `ReplayProtection` и `SessionCache` определены но не подключены, `_ephemeral_kem_secret` (`handshake.rs:167`) — phantom-limb от незавершённого 0-RTT.
2. **Производительность:** per-packet `vec![0u8; len]` (`tcp_transport.rs:70`), `.clone()` plaintext в recv-цикле (`api/session.rs:427`), 10ms polling-interval вместо event-driven (`api/session.rs:444`), `BufferPool` / `Pacer` / `PacketCoalescer` / `BandwidthEstimator` определены, но в hot path не задействованы. `[profile.release].opt-level = "s"` — оптимизация под размер, а не под скорость.
3. **Portability:** жёсткая привязка к `tokio` (`full` features), `tokio::net::*` блокирует WASM, `pqcrypto-*` требует std, `zstd` из git master (нестабильно), `std::time::SystemTime` не работает в WASM из коробки.
4. **Аудит/Compliance:** не FIPS-совместимы blake3 / ChaCha20Poly1305 / pqcrypto-kyber|dilithium (нужны ML-KEM / ML-DSA), нет threat model, SECURITY.md, протокольной спецификации, нет cargo-deny / audit / fuzz / proptest / loom / miri.
5. **Operations:** нет CI/CD (нет `.github/`), нет `LICENSE` / `README` / `CHANGELOG`, девять `log::` вызовов на всю кодовую базу, ноль `tracing` инструментации, ноль metrics, нет MSRV, нет `rust-toolchain.toml` / `rustfmt.toml` / `clippy.toml` / `deny.toml`.
6. **API/FFI:** unwraps достижимы из FFI (`api/session.rs:244`, `api/listener.rs:25`), только Python bindings реально тестируются, нет cross-language interop тестов.

**Цель.** Привести библиотеку к состоянию, в котором она (а) проходит внешний security audit и пригодна для FIPS 140-3 / Common Criteria certification, (б) обеспечивает максимальную производительность на актуальных hot path, (в) работает на любой платформе (server / mobile / embedded / WASM-браузер), (г) имеет полноценный operations/release/governance pipeline.

**Подход.** Восемь параллельно-сопрягаемых фаз. Phase 0 (Foundation) обязательно первая, потому что меняет CI и lint-правила, на которые завязаны все последующие изменения. Phases 1-5 — основная работа, частично параллельная. Phases 6-7 — закрепляющие. План трассирует каждый пункт к `file:line` существующего кода и существующим утилитам, которые надо переиспользовать или включить в hot path.

**Размерность.** При оценках использую T-shirt sizes: S = ≤1 неделя на одного инженера, M = 1-3 недели, L = 1-3 месяца, XL = 3+ месяцев. Сводная оценка в конце документа.

---

## Phase 0 — Foundation: Governance, CI, Tooling

**Goal:** установить guard-rails (CI, форматирование, lint, supply-chain) до того, как начинать менять код. Без CI любое следующее изменение — это работа вслепую.

**Effort: M.** Параллелизация: один инженер за 2-3 недели.

### 0.1 Governance & lice​nsing
- `LICENSE` (рекомендую Apache-2.0; альтернатива — dual MIT/Apache-2.0 как стандарт Rust-крейтов).
- `README.md` — vision, quickstart (10 строк client + 10 строк server), архитектурная диаграмма, link map к остальным docs.
- `CHANGELOG.md` — формат Keep a Changelog.
- `SECURITY.md` — disclosure policy, supported primitives matrix, GPG-key для приватных репортов, временные SLA для ответа.
- `CONTRIBUTING.md` — стиль, test workflow, fmt/clippy/deny требования, sign-off.
- `Cargo.toml`: заполнить `repository`, `license`, `keywords`, `categories`, `documentation` для всех крейтов (`core/`, `cli/`).
- Codeowners для security-критичных директорий (`core/src/crypto/`, `core/src/transport/handshake.rs`, `core/src/transport/legs/faketls.rs`).

### 0.2 Toolchain pinning
- `rust-toolchain.toml` с pinned stable (рекомендую 1.75+; `async-trait` встроен с 1.75).
- `.rustfmt.toml` — `edition = "2021"`, `max_width = 100`, `imports_granularity = "Crate"`, `group_imports = "StdExternalCrate"`.
- `.clippy.toml` — `msrv = "1.75"`, `disallowed-methods`, `cognitive-complexity-threshold = 30`.
- MSRV-policy: документировать в `README.md` и проверять в CI matrix.

### 0.3 Supply-chain hygiene
- `deny.toml` (cargo-deny): запрет copyleft (LGPL/GPL без exception), запрет yanked / unmaintained, allowlist crypto-крейтов.
- `cargo-audit` job в CI с RustSec database checks.
- Pin `zstd = { git = "..." }` → `zstd = "0.13"` release. Лучше: убрать `zstd` совсем, оставить `lz4_flex` (pure-Rust, no_std-friendly). zstd подключить опционально через feature.
- Pin `tokio = "1.36"` → актуальная patch-version (1.40+) для security fixes.
- `cargo-vet` или `cargo-crev` review для зависимостей с unsafe (особенно `ring`, `kcp-tokio`, `pqcrypto-*`).
- SBOM генерация (`cargo-cyclonedx`) — артефакт релиза.

### 0.4 CI/CD pipeline
Создать `.github/workflows/` с jobs:
- **`ci.yml`** — на каждый PR: build, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo doc --no-deps --workspace`.
- **`cross.yml`** — matrix билдов: `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc`, `wasm32-unknown-unknown`, `wasm32-wasi`.
- **`fuzz.yml`** — короткие fuzz-runs (1-2 минуты) на каждый PR для парсеров; nightly длинные runs (8 часов) через cron schedule.
- **`audit.yml`** — `cargo audit`, `cargo deny`.
- **`bench.yml`** — criterion-baseline сравнение с main (использовать `criterion-compare-action`), threshold по регрессиям ≥5%.
- **`miri.yml`** — nightly run `cargo +nightly miri test` для memory safety checks.
- **`loom.yml`** — loom-тесты концurrency invariants (новые тесты см. Phase 6).
- **`release.yml`** — на git tag: `cargo publish --dry-run`, GPG-sign артефакта, GitHub Release, опционально `cargo dist`.
- Все jobs кешируют `~/.cargo`, `target/`.

### 0.5 Pre-commit hooks
- `.pre-commit-config.yaml` или `lefthook.yml`: fmt, clippy, type-check.
- `cargo-husky` для автоустановки hooks при `cargo build`.

### 0.6 Performance baseline
- Зафиксировать текущие numbers по `core/benches/transport_bench.rs`, `protocol_comparison.rs`, `buffer_pool_bench.rs`, `syn_flood_bench.rs` в `BENCHMARKS.md`.
- Сохранить criterion JSON в репо в `bench-baseline/` для будущего сравнения.

### 0.7 Релизные настройки
- **Исправить `[profile.release]`** в `core/Cargo.toml:94-99`: 
  - `opt-level = 3` (текущее `"s"` оптимизирует под размер — анти-performance).
  - Оставить `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`.
  - Добавить отдельный `[profile.release-size]` с `opt-level = "z"` для embedded.
  - Добавить `[profile.bench]` с `inherits = "release"` + `debug = true` для profiling.
- Добавить `[profile.dist]` для финальных артефактов c PGO instrumentation.
- Включить `target-cpu=native` через optional CI matrix (отдельная сборка с native intrinsics).

### Deliverables Phase 0
| Артефакт | Файл | Status |
|---|---|---|
| Лицензия | `LICENSE` | new |
| Project docs | `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md` | new |
| Toolchain pin | `rust-toolchain.toml`, `.rustfmt.toml`, `.clippy.toml` | new |
| Supply-chain | `deny.toml`, `audit.toml` | new |
| CI | `.github/workflows/{ci,cross,fuzz,audit,bench,miri,loom,release}.yml` | new |
| Release profile fix | `core/Cargo.toml:94` | edit |
| Dependency pinning | `core/Cargo.toml:13,47` | edit |

---

## Phase 1 — Security Hardening (P0, аудит-блокер)

**Goal:** ликвидировать каждый конкретный security gap, найденный в inventory, и установить инварианты, которые будут проверяться в CI.

**Effort: L.** Один-два инженера за 2-3 месяца. Каждый пункт защищён тестом.

### 1.1 Constant-time где есть сравнения секретов
**Проблема:** `handshake.rs:136` — `client_hello.cookie.map(|c| c == expected_cookie)` использует обычное `==` для 32-байтового cookie → timing-leak позволяет brute-force за O(256) запросов вместо O(2^256).

- Добавить зависимость `subtle = "2"`.
- Заменить все `==` на секретах на `ConstantTimeEq::ct_eq(...)`:
  - `core/src/transport/handshake.rs:136` — cookie comparison.
  - Аудит `core/src/transport/handshake.rs:263-266` — `expected != &server_hello.server_verify_key` использует derive'd `PartialEq` на `HybridVerifyingKey`; проверить, что Ed25519/Dilithium derive используют CT (или обернуть в `ct_eq`).
  - Аудит `core/src/security/replay_protection.rs` — все сравнения nonce.
- Добавить `clippy::disallowed-methods` правило, блокирующее `PartialEq::eq` на типах, помеченных как secret (через newtype).
- Тесты: статистический timing-test (constant-time-eq-tests pattern).

### 1.2 Zeroize всех session secrets
**Проблема:** `CryptoState` (`transport/session.rs:36-42`) содержит `session_key: [u8; 32]`, но **нет** `Drop` или `Zeroize` impl. Ключ остаётся в памяти.

- Добавить `#[derive(Zeroize, ZeroizeOnDrop)]` на:
  - `CryptoState` (`core/src/transport/session.rs:36`).
  - `Session::resumption_secret` (`core/src/transport/session.rs:97`).
  - `HandshakeServer::pow_secret` (`core/src/transport/handshake.rs:106`).
  - `HandshakeClient::nonce` (`core/src/transport/handshake.rs:221`).
- Для `CryptoSession` / `CryptoSessionInner` (`core/src/crypto/adaptive_crypto.rs`): добавить `Zeroize` на `nonce_prefix` и обёрнутые `LessSafeKey` (ring ключи — но ring не expose mutable bytes; потребуется обёртка с manual Drop, что зануляет окружающую структуру, не сами ring keys).
- Audit: запрос ко всем модулям — если структура держит «sensitive material», она ДОЛЖНА иметь `ZeroizeOnDrop`. Список через grep / lint.
- Тест: `proptest`-test, проверяющий, что после `drop()` место в памяти зачищено (через `MaybeUninit` ловушку или allocator hook).

### 1.3 Уничтожение `.unwrap()` на security-sensitive путях
**Проблема:** список panic-источников в production коде:
- `core/src/transport/handshake.rs:97` — `borsh::to_vec(transcript).unwrap()` в `compute_transcript_hash`.
- `core/src/transport/handshake.rs:231` — `getrandom::getrandom(&mut nonce).unwrap()` в `HandshakeClient::new`.
- `core/src/transport/handshake.rs:326-327` — `SystemTime::now()...unwrap()` и `Hmac::new_from_slice().unwrap()` в `generate_cookie`.
- `core/src/api/session.rs:244` — `borsh::to_vec(&hello).unwrap()` в `background_task`.
- `core/src/transport/legs/faketls.rs:131-132` — `UnboundKey::new().unwrap()` в FakeTLS keying.
- `core/src/transport/compression.rs:146` — `unreachable!()` в `decompress` (исследовать reachability).

Действия:
- Все `borsh::to_vec` → `borsh::to_vec(...).map_err(SerializationError::from)?` с типизированной ошибкой.
- `HandshakeServer::new()`, `HandshakeClient::new()` → возвращать `Result<Self, HandshakeError>`, чтобы getrandom failures корректно поднимались.
- `generate_cookie`: `SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| HandshakeError::ClockBackwards)?`; HMAC key 32 bytes — длина известна, замени `.unwrap()` на `.expect("...")` с инвариантом, либо безопасный конструктор.
- UnboundKey: key length known at compile time — заменить на typed constructor, гарантирующий длину, или вернуть error.
- Добавить `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unreachable, clippy::unimplemented, clippy::todo)]` в `core/src/lib.rs`. Исключения только через `#[allow(...)]` с обоснованием.

### 1.4 Replay protection wired into data plane
**Проблема:** `core/src/security/replay_protection.rs` определён и тестирован, но в основном recv-пути (`core/src/api/session.rs:365-438`) **не вызывается**.

- Подключить sliding-window replay check после `decrypt_packet` (`api/session.rs:395`):
  - Per-session sliding window (стандарт IPsec ESP RFC 4303 § 3.4.3) на основе sequence number из `PacketHeader.sequence`.
  - Window size: 1024 (стандартный размер).
  - Использовать существующий `security/replay_protection.rs`, либо переписать на bitmap (быстрее `HashMap<u32, Instant>`).
- Реджектить duplicate / out-of-window пакеты — добавить counter в metrics (`replay_rejected_total`).
- Тест: переотправить тот же пакет дважды → второй должен дропнуться.

### 1.5 Mid-session key rotation (PFS for long sessions)
**Проблема:** session использует один derived key всю жизнь сессии. Компрометация ключа → leak всех сообщений.

- Спроектировать rekey-schedule:
  - **Time-based:** каждые N минут (config-настройка, по умолчанию 30 min).
  - **Volume-based:** перед достижением 2^48 пакетов (NIST SP 800-38D AES-GCM safety limit). Сейчас `AtomicU64`-counter в `crypto/adaptive_crypto.rs:200` — добавить watermark check.
  - **Triggered:** explicit API `rekey()` для приложения.
- KDF chain: `next_key = HKDF-Expand(current_key || "phantom-rekey-v1", 32)`. Хранить ratchet state в `Session::resumption_secret`.
- Wire-протокол: добавить `PacketFlags::REKEY` flag (новый bit). Получатель при REKEY-flag запускает derive нового ключа на следующий пакет.
- Sync: первый пакет после rekey содержит `epoch: u8` чтобы receiver знал, какой ключ применять.
- Тест: long-running session → rekey происходит → старые ключи не работают.

### 1.6 Session ID entropy
**Проблема:** `core/src/api/session.rs:165,202,583` использует `rand::random::<u32>()` для session ID — всего 32 бита, weak source (thread_rng не cryptographic).

- Заменить на `let mut id = [0u8; 16]; getrandom::getrandom(&mut id)?;` → 128-bit case-insensitive id.
- Применить ко всем местам генерации session ID.
- Тест: проверить отсутствие коллизий после 10^6 generations.

### 1.7 AEAD nonce safety limit
**Проблема:** `AtomicU64` send/recv counter теоретически переполняется через 2^64 пакетов. На реальных пропускных это не угроза, но AES-GCM ломается раньше — после 2^32 пакетов с одним ключом риск multi-target attacks.

- Hard limit: AEAD counter > 2^48 → принудительный rekey (см. 1.5).
- Soft warning: counter > 2^32 → emit warning metric.
- Тест: моки с предзаведённым counter → rekey срабатывает.

### 1.8 Wire format & version negotiation
**Проблема:** `handshake.rs:130` — `if client_hello.version != 1 { return Fail }`. Нет downgrade-resistance: атакующий не может downgrade'нуть, но и нет графа поддерживаемых версий.

- Превратить `version: u8` в `Vec<u8>` (offered versions) + один `chosen_version`.
- В transcript подписи включать **весь** offered list — это classical downgrade-resistance из TLS 1.3 RFC 8446 § 4.1.3.
- Документировать политику version bumping в `PROTOCOL.md` (Phase 7).

### 1.9 Strict ENCRYPTED-flag invariant (defense in depth)
Уже частично есть (`api/session.rs:402-406`). Усилить:
- Заменить `log::warn!` на metric `unencrypted_post_handshake_dropped_total` + структурированный tracing event.
- Добавить опциональный strict mode: на N dropped packets → принудительный close. Config-настройка `strict_downgrade_response: u32`.
- Тест: explicit "attacker strip flag" — packet с empty payload и stripped flag отбрасывается (уже есть в test_phantom_session_handshake_via_transport, формализовать).

### 1.10 Cookie freshness
**Проблема:** `generate_cookie` использует `timestamp_min` (текущая минута) как salt — `handshake.rs:325-331`. Слабая freshness: cookies валидны до 60 секунд.

- Расширить salt: `timestamp_min || rotating_secret_id`. Sec ID меняется каждый час, скользящее окно из двух accepted secrets (текущий + предыдущий).
- Альтернатива: `[u8; 64]` cookie с 32 байтами случайного challenge + 32 байта HMAC.

### 1.11 PoW secret rotation
- `HandshakeServer::pow_secret` (`handshake.rs:106`) генерируется один раз. Добавить rotation API (каждый час) с graceful overlap.

### 1.12 Phantom-limb cleanup
- `HandshakeServer::process_client_hello` (`handshake.rs:167`) создаёт `ephemeral_kem_secret`, использует только `ephemeral_kem_public` в `ServerHello`. Либо использовать секрет (для реального PQC roundtrip), либо удалить (упрощает code-audit). Решение зависит от Phase 4 / 0-RTT design.
- `HandshakeClient::take_early_data` (`handshake.rs:307`) — проверить call-sites. Если не вызывается — удалить.
- `core/src/networks/tls.rs:34` log warning "DEBUG MODE ONLY" — формализовать: должно быть отдельным `tls-debug` feature, выключенным в release-builds.

### 1.13 Audit-friendly invariants в коде
- Добавить module-level `#![forbid(unsafe_code)]` ко всем модулям, кроме `core/src/crypto/keys.rs` и `core/src/transport/udp_transport.rs` (где unsafe оправдан и документирован).
- Каждый `unsafe { }` блок: SAFETY-комментарий с инвариантами.
- Аннотировать каждую crypto-функцию `#[inline(never)]` для предотвращения compiler-cheating с timing.

### 1.14 PoW и DoS resistance
- Документировать threat model для DoS (Phase 6).
- Adaptive PoW difficulty: cookie + PoW сейчас опциональны (`difficulty: 0`). Под нагрузкой автоматически повышать difficulty (см. `core/src/transport/half_open.rs`).
- Limit unique IPs in flight на handshake (rate limit per-IP).

### Deliverables Phase 1
| Артефакт | Where | Effort |
|---|---|---|
| `subtle::ConstantTimeEq` повсеместно для секретов | `core/src/transport/handshake.rs`, `core/src/security/replay_protection.rs` | S |
| `ZeroizeOnDrop` на всех session-secret structs | `core/src/transport/session.rs:36`, `:97`, `core/src/transport/handshake.rs:106,221`, `core/src/crypto/adaptive_crypto.rs` | M |
| Удаление `.unwrap()` в production crypto path | списки см. 1.3 | M |
| `#![deny(clippy::unwrap_used,...)]` в `lib.rs` | `core/src/lib.rs` | S |
| Replay protection wired | `core/src/api/session.rs:395`, `core/src/security/replay_protection.rs` | M |
| Mid-session key rotation | `core/src/transport/session.rs`, `core/src/crypto/adaptive_crypto.rs`, `core/src/transport/types.rs` (PacketFlags::REKEY) | L |
| Session ID 128-bit | `core/src/api/session.rs:165,202,583` | S |
| Version-list negotiation | `core/src/transport/handshake.rs:35` (ClientHello), `:71` (ServerHello), transcript | M |
| Cookie freshness | `core/src/transport/handshake.rs:325` | S |
| Phantom-limb cleanup | `core/src/transport/handshake.rs:167,307`, `core/src/networks/tls.rs:34` | S |
| Negative tests | `core/tests/` — new file `security_invariants.rs` | M |

**Verification:** все 12 пунктов закрыты тестами; clippy без warnings; aud​i​t-friendly: каждый pub crypto function имеет doc-comment с invariants; нет unwrap в production paths кроме явно-разрешённых.

---

## Phase 2 — Performance Critical Path

**Goal:** убрать аллокации с hot path, подключить уже-написанную, но disconnected infrastructure (BufferPool, Pacer, Coalescer, BandwidthEstimator), переход на event-driven там, где сейчас polling.

**Effort: L.** Один-два инженера за 2-3 месяца.

### 2.1 Eliminate per-packet allocations в TCP transport
**Проблема:** `core/src/api/tcp_transport.rs:70` — `vec![0u8; len]` каждый incoming packet. На 1M pkt/s это 1M mallocs/s.

- Wire `core/src/transport/buffer_pool.rs::BufferPool` в `TcpSessionTransport::recv_bytes`.
  - `BufferPool` уже thread-local + global fallback, с `RAII` return (`PooledBuffer` Drop). Используется в benches, но не в runtime — это и есть phantom infrastructure.
- Изменить сигнатуру `SessionTransport::recv_bytes(&self) -> Result<Vec<u8>, _>` → `Result<PooledBuffer, _>` (или `Bytes` поверх `BufferPool` через `Arc`).
- Обновить call-sites в `api/session.rs:367,372`.
- Тест: `criterion` regression — `recv_bytes` allocation count ≈ 0 после warmup.

### 2.2 Eliminate plaintext clone в recv path
**Проблема:** `core/src/api/session.rs:427` — `Bytes::from(plaintext.clone())` копирует payload, чтобы отправить и в demux и в `recv_tx`.

- `plaintext` уже `Vec<u8>` → конвертировать в `Bytes::from(plaintext)` без клона (one move).
- Route в demux: `demux.route_data_async(stream_id, bytes.clone()).await` — `Bytes::clone()` это refcount bump, не копия.
- Сам `recv_tx.send(bytes_or_vec)` — channel принимает `Vec<u8>` сейчас. Изменить тип канала на `mpsc::Sender<Bytes>` чтобы избежать обратной конверсии.

### 2.3 Stack-buffer для small-packet serialization
**Проблема:** `core/src/api/session.rs:420,560` — `Vec::new()` per ACK / per send.

- Использовать `smallvec::SmallVec<[u8; 256]>` или просто `[u8; 256]` (большинство пакетов ≤ MTU=1300, малые ACK помещаются в 64 байта).
- Малые пакеты: писать `PacketHeader::to_wire` в стековый буфер на горячем пути (кодек уже ручной big-endian, без аллокаций для заголовка).
- Бенч `core/benches/transport_bench.rs` показывает baseline; добавить bench именно на small-packet serialization.

### 2.4 Event-driven send loop вместо polling
**Проблема:** `core/src/api/session.rs:444` — `tokio::time::interval(Duration::from_millis(10))` пробуждает send-loop каждые 10 ms даже если делать нечего. Hot streams страдают latency, idle streams тратят CPU.

- Заменить interval-poll на `Notify` или `mpsc::Sender<StreamReady>`:
  - Каждый stream при `send_reliable / send_unreliable` сигнализирует `stream.send_notifier.notify_one()`.
  - Главный select! ждёт `cmd_rx`, `stream_ready_rx`, `recv_handle` — без 10 ms tick.
- Альтернатива: переписать data-pump на per-stream task (одна task на stream), что лучше масштабируется на cores.
- Тест: latency-bench показывает <100µs от user-`send` до wire vs текущие ≤10ms tail.

### 2.5 Wire PacketCoalescer in send path
**Проблема:** `core/src/transport/packet_coalescer.rs` определён (4 теста), но в hot loop **не подключён**. Каждый stream-send делает отдельный transport-call → syscall amplification.

- В `run_data_pump` (`api/session.rs`) аккумулировать готовые-к-отправке packets за один tick / Notify-batch, передавать в Coalescer, отправлять одним `transport.send_bytes`.
- Coalescer уже знает MTU (TRANSPORT_MTU = 1300 на `api/session.rs:443`).
- Win: ~10-20% throughput на multi-stream workloads (меньше syscalls + меньше framing overhead).

### 2.6 Wire Pacer / BandwidthEstimator in send path
**Проблема:** `core/src/transport/pacer.rs` — token-bucket pacer, `core/src/transport/bandwidth_estimator.rs` — EMA bandwidth tracking. Оба определены и протестированы, но **disconnected**.

- Connect pacer перед `transport.send_bytes`: если tokens < packet size → подождать `pacer.next_token_at()`.
- Connect bandwidth estimator на recv-side: каждый ACK обновляет EMA.
- Connect estimator → pacer.rate: pacer держит actual link bandwidth × utilization target.
- Это **fundament** для Phase 4 congestion control.

### 2.7 Lock-free reads on crypto state
**Проблема:** `core/src/transport/session.rs:87` — `crypto: RwLock<CryptoState>`. На каждый encrypt/decrypt — read-lock acquire. `parking_lot::RwLock` fast, но всё равно атомарная операция.

- Заменить на `arc_swap::ArcSwap<Arc<CryptoState>>`. Read = atomic load, без блокировки. Write (rekey) = atomic swap.
- Применимо только если CryptoState immutable-after-derive. Counter внутри `CryptoSessionInner` — это `AtomicU64`, отдельный от `CryptoState`. То есть CryptoState immutable вне rekey.

### 2.8 Direct Bytes routing everywhere
- Внутри transport-layer всё уже использует `bytes::Bytes` (legs/tcp.rs, faketls.rs).
- В `SessionTransport` trait и API layer — `Vec<u8>`. Заменить на `Bytes` чтобы убрать конверсию на boundary.
- Эффект: ~5% reduction в memcpy на full pipeline.

### 2.9 SO_REUSEPORT / multi-accept для server
- На server side: бинать N tokio listeners на тот же port (SO_REUSEPORT), каждый на свой core. Multi-accept без contention.
- TLS / FakeTLS leg бенефицирует наиболее (handshake — самая дорогая операция).
- Linux only; за feature flag.

### 2.10 GSO / GRO для UDP leg
- `core/src/transport/udp_transport.rs:154,331` уже использует `recvmmsg`. Добавить `sendmmsg` для batch UDP send.
- UDP segmentation offload (`UDP_SEGMENT` socket option) — Linux 4.18+. Снижает per-packet syscall overhead.
- За feature flag `linux-perf-extensions`.

### 2.11 Per-CPU work-stealing
- Если data-pump переписан на per-stream task (см. 2.4), tokio runtime сам распределяет. Иначе — explicit `LocalSet` per-core с work-stealing affinity.
- Возможно overkill для phase 2; отложить до Phase 4 multi-path.

### 2.12 Release-profile + PGO + native intrinsics
- Phase 0 уже починила `opt-level = 3`. Phase 2 добавляет:
  - **PGO**: `cargo pgo build` → profile run → `cargo pgo optimize build`. CI-job для генерации.
  - **Native CPU build**: `RUSTFLAGS="-C target-cpu=native"` для on-prem deployments. CI sample build с current GitHub-runner CPU.
  - **`cargo-bloat`** report в CI — отслеживать binary size regressions.

### 2.13 Async/`select!` cancel-safety audit
- `transport/stream.rs:152` — 500 ms timeout в `poll_send` может вызывать HOL blocking. Replace на event-driven (см. 2.4).
- Все `select!` ветки cancel-safe? Audit:
  - `api/session.rs:447-531` — `cmd_rx.recv()`, `recv_handle.await`, `poll_interval.tick()` — все cancel-safe.
  - Lock holding across await — audit (`send_queue.lock().await` на 336 удерживается через drain — короткий, OK).

### Deliverables Phase 2
| Опт | Где | Эффект |
|---|---|---|
| Wire BufferPool | `core/src/api/tcp_transport.rs:70`, `core/src/transport/buffer_pool.rs` | -50%+ alloc/s на recv path |
| No plaintext clone | `core/src/api/session.rs:427` | -1 копия размером packet |
| Stack-buf serialization | `core/src/api/session.rs:420,560` | -2 mallocs/packet |
| Event-driven send | `core/src/api/session.rs:444`, новый `Notify` | -10 ms tail latency |
| Wire Coalescer | `core/src/transport/packet_coalescer.rs` + `core/src/api/session.rs` | +10-20% throughput multi-stream |
| Wire Pacer + Estimator | `core/src/transport/pacer.rs`, `core/src/transport/bandwidth_estimator.rs` | foundation для congestion control |
| ArcSwap on crypto state | `core/src/transport/session.rs:87` | -1 atomic / packet |
| Bytes throughout API | `SessionTransport` trait + adapters | -5% memcpy |
| GSO/sendmmsg UDP | `core/src/transport/udp_transport.rs` | +20-30% UDP throughput Linux |
| PGO + native CPU | `core/Cargo.toml` profile + CI | +5-15% throughput |

**Verification:** новые benchmarks показывают targeted improvements; criterion-baseline в CI; latency P50/P99 measured.

---

## Phase 3 — Architecture for Portability (WASM, embedded, mobile)

**Goal:** decouple core API from concrete tokio types, enable WASM/embedded/mobile targets, sustain существующий server use-case.

**Effort: XL.** Два-три инженера за 3-6 месяцев.

### 3.1 Runtime abstraction
**Проблема:** `core/src/api/session.rs` напрямую использует `tokio::spawn`, `tokio::time::interval`, `tokio::sync::Mutex`. Это блокирует WASM (нет multi-threaded tokio в WASM) и embedded (нет tokio в no_std).

- Ввести `pub trait Runtime`:
  ```rust
  pub trait Runtime: Send + Sync + 'static {
      fn spawn(&self, fut: impl Future + Send + 'static);
      fn now(&self) -> Instant;     // monotonic
      fn sleep(&self, d: Duration) -> impl Future;
      type Notify: Notify;          // event signal
  }
  ```
- Implement `TokioRuntime`, `WasmRuntime` (через `wasm-bindgen-futures`), `EmbeddedRuntime` (через `embassy` или custom).
- Replace `tokio::spawn(...)` → `runtime.spawn(...)` в `api/session.rs:177,215,365`.
- Это серьёзная архитектурная работа — все ~10 spawn-sites нужно перевести.

### 3.2 Clock abstraction
**Проблема:** `std::time::SystemTime` (`handshake.rs:326`, `crypto/pow.rs`) не работает в WASM без shim. `std::time::Instant` иначе в WASM.

- `pub trait Clock { fn now_wall_clock(&self) -> SystemTime; fn now_monotonic(&self) -> Instant; }` — feature-gated.
- На server: passthrough к `std::time::*`.
- На WASM: `js_sys::Date::now()` → SystemTime; `js_sys::performance::now()` → monotonic Instant.
- На embedded: устройство-specific RTC + tickcount.

### 3.3 Transport leg для WASM (browser)
- Новый `core/src/transport/legs/websocket.rs::WebSocketLeg`.
- Использует `web-sys::WebSocket` + `wasm-bindgen-futures`.
- Implements `TransportLeg` trait (`core/src/transport/legs/mod.rs:16-37`).
- Использует MTU=64 KB (WebSocket frame), framing уже встроенный.
- Browser deployment: client-side только (никакой listener в браузере). PhantomListener — server-side артефакт.

### 3.4 Transport leg для embedded (serial, UART, CAN, custom IO)
- Generic `EmbeddedLeg<RW: AsyncRead + AsyncWrite>` через `embedded-io-async` traits.
- Frame-format совместим с `tcp.rs` length-prefix.
- Используется на устройствах без TCP stack.

### 3.5 Conditional compilation matrix
- Features в `core/Cargo.toml`:
  - `std` (default): full tokio + tokio::net.
  - `wasm`: wasm-bindgen, web-sys, no tokio::net.
  - `embedded`: no_std + alloc, embassy executor optional.
  - `pqc-standard` (existing).
  - `pqc-ml-kem-mldsa` (Phase 5): FIPS-стандартные PQC.
  - `fips`: FIPS-compliant build (Phase 5).
  - `linux-perf-extensions`: GSO/recvmmsg/sendmmsg.
  - `tracing` / `metrics` (Phase 4).
- Каждая фича: separate CI job, проверка билда + минимальный smoke-test.

### 3.6 No_std + alloc для embedded — **DESCOPED for 1.0 (framing-only on bare-metal)**
**Decision:** running the PQ handshake on bare-metal `thumbv7em` is a multi-month
sub-project (no-std crypto, an Embassy/RTIC runtime, a QEMU-hosted handshake test),
not a 1.0 blocker. For 1.0, embedded is **framing-only**: `thumbv7em` ships
`EmbeddedLeg` + its length-prefix codec, and a bare-metal embedder brings its own
crypto/handshake driver over the leg. The README, the `Status & limitations`
section, and the embedded section now say so; the PQ-on-bare-metal claim is gone.
The build plan below is retained as the future-widening recipe if it is ever
picked up — promoting modules out of the `std`-gated region can land
module-by-module without re-touching the Phase 3.6 gating infrastructure.

**Проблема (build path, not pursued for 1.0):** `pqcrypto-*` требует std. `tokio` весь требует std. `zstd` C-bindings.

- `pqcrypto-*` → `ml-kem` crate (no_std + alloc support) для embedded path.
- Замена `tokio::sync::Mutex` на `embassy-sync::Mutex` или `spin::Mutex` под `embedded` feature.
- Drop `tokio::time` → `embassy::time` или generic abstraction (Phase 3.2).
- `std::collections::HashMap` → `hashbrown::HashMap` (no_std + alloc).
- `std::sync::Arc` → `alloc::sync::Arc`.

### 3.7 Pure-Rust compression
- Drop `zstd` (C-bindings блокируют embedded/WASM). Оставить `lz4_flex`.
- Опционально: `zstd-rs` pure-Rust port (`ruzstd`) под `std-compression` feature.

### 3.8 RNG abstraction
- `getrandom` поддерживает WASM (`getrandom_backend = "wasm_js"`) — но требует feature.
- Embedded: hardware RNG чип. `RngCore` trait + crate-specific impl.
- Audit: каждое использование `OsRng` / `getrandom::getrandom` — за feature gate.

### 3.9 FFI binding generation
- Сейчас UniFFI генерирует только Python (`tests/bindings/`). Добавить:
  - Swift (через `uniffi-bindgen swift`) — для iOS.
  - Kotlin (через `uniffi-bindgen kotlin`) — для Android.
  - C-header (`uniffi-bindgen-cpp` или manual) — для прочих.
- `tests/run_test.py` расширить на:
  - Python (existing).
  - Swift (через `swift run` на macOS CI).
  - Kotlin (через `kotlinc + java` на Linux CI).

### 3.10 WASM-specific tweaks
- Drop `tokio = "full"` → minimal feature set for WASM.
- Build `wasm32-unknown-unknown` (browser) + `wasm32-wasi` (server-WASM).
- `wasm-pack` integration: `examples/wasm_client/` собирается в `npm` пакет.
- Reproducible WASM build (no wall-clock, no random unless via crypto API).

### 3.11 Cross-platform CI matrix
Уже частично в Phase 0. Здесь расширить:
- `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl` (Android NDK).
- `x86_64-apple-darwin`, `aarch64-apple-darwin`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`.
- `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`.
- `wasm32-unknown-unknown`, `wasm32-wasi`.
- `thumbv7em-none-eabihf` (Cortex-M4 embedded — smoke build only).

### Deliverables Phase 3
| Артефакт | Где | Effort |
|---|---|---|
| Runtime trait | `core/src/runtime/mod.rs` (new) | M |
| TokioRuntime / WasmRuntime / EmbeddedRuntime | `core/src/runtime/{tokio,wasm,embedded}.rs` | L |
| Clock trait | `core/src/runtime/clock.rs` | S |
| WebSocketLeg | `core/src/transport/legs/websocket.rs` | M |
| EmbeddedLeg | `core/src/transport/legs/embedded.rs` | M |
| Conditional compilation matrix | `core/Cargo.toml` | M |
| pqcrypto → ml-kem migration plan | Phase 5 overlap | L |
| Pure-Rust compression | drop zstd | S |
| FFI binding gen | Swift/Kotlin/C | M |
| Cross-platform CI | `.github/workflows/cross.yml` | M |

**Verification:** WASM example в браузере (Chrome/Firefox) подключается к Linux server; embedded example собирается на `thumbv7em`; iOS/Android FFI smoke-test проходит.

---

## Phase 4 — New Subsystems

**Goal:** добавить производственно-критичные подсистемы (0-RTT, multi-path failover, multiplexing finalization, congestion control, telemetry), используя уже-заложенный фундамент.

**Effort: XL.** Несколько инженеров за 4-6 месяцев. Подсистемы относительно независимы.

### 4.1 0-RTT resumption (PSK-based early data)
**Что уже есть:** `core/src/transport/session_cache.rs` (тикет-кеш), `core/src/transport/session.rs:144` (`Session::resume`), `core/src/transport/handshake.rs:49` (`resume_session_id`), `:201` (resumption_secret HKDF).

**Что нужно достроить:**
- Server-side: tickets в `SessionCache` (LRU, default 10K, TTL 24h). Encrypt ticket payload session-master-key чтобы был stateless.
- Client-side: после успешного handshake клиент сохраняет (server_pk, ticket, master_secret) в local cache.
- При следующем connect: client отправляет ticket в `ClientHello.resume_session_id`. Server lookup → если valid → respond без full hybrid roundtrip.
- Early-data path: client пишет данные в `early_data: Vec<Vec<u8>>` (`handshake.rs:222`), шифрует под `resumption_secret`-derived key, отправляет в первом потоке после ClientHello.
- **Anti-replay:** early data inherently replayable. Document: пользовательский protocol должен делать operations idempotent OR использовать replay window only for early-data.
- Wire-protocol: новый `PacketFlags::EARLY_DATA` bit. Server проверяет replay window для early-data отдельно.
- Тест: round-trip "first connect → close → reconnect with resume" → measure handshake bytes & latency saved.

### 4.2 Multi-path failover + connection migration
**Что уже есть:** `core/src/transport/legs/{tcp,kcp,faketls}.rs`, `core/src/transport/virtual_socket.rs`, `core/src/transport/fallback.rs`, `core/src/transport/scheduler.rs`.

**Что нужно достроить:**
- `VirtualSocket` должен parallel-keep-alive все доступные legs.
- Per-packet path selection (по health + RTT + loss); пометить leg-id в `PacketHeader.path_id` (уже поле единого `PacketHeader`).
- Path validation: при появлении нового path (другой IP/leg) — challenge-response (random 32-byte) до полного switch.
- Mobility / migration: session ID stable, IP/leg меняется. Это эквивалент QUIC connection migration (RFC 9000 § 9). Сервер реджектит migration без path validation.
- Per-path congestion state (packet number space — каждый path считает loss/RTT отдельно, плюс global stream layer).
- Fast failover: timer на каждом path; если N акций нет ACK за RTO → demote leg, продолжить на другом. Цель: <50 ms switchover.
- `Scheduler` (`transport/scheduler.rs`) — заменить ad-hoc на explicit policies: LowLatency / HighThroughput / Reliability / Multipath (round-robin / weighted).
- Тесты: TCP leg dies → KCP continues; добавление WebSocket leg → используется при наличии.

### 4.3 Multi-stream finalization
**Что уже есть:** `core/src/transport/stream.rs`, `core/src/transport/multiplexer.rs`, `core/src/api/stream.rs::PhantomStream`.

**Что нужно достроить:**
- Stream priority scheduling: `AtomicU32` priority уже есть, но в schedule-loop не используется. Реализовать priority queue.
- Per-stream flow control window (TCP-style sliding window). Currently — `Semaphore` (MAX_PENDING_PACKETS=1024) без backpressure feedback к peer. Добавить WINDOW_UPDATE frames.
- HOL-blocking elimination: текущий `run_data_pump` (`api/session.rs:444-468`) итерирует все streams последовательно. Заменить на per-stream tasks с независимыми очередями.
- Reliable + unreliable семантика на одном stream: уже есть (`send_reliable / send_unreliable`), но retransmit для reliable не реализован end-to-end. Wire retransmit timer + selective ACK.

### 4.4 Congestion control (BBRv2-inspired)
**Что уже есть:** `transport/pacer.rs` (token bucket), `transport/bandwidth_estimator.rs` (EMA).

**Что нужно достроить:**
- BBRv2 state machine: Startup / Drain / ProbeBW / ProbeRTT.
- Estimator inputs: ACK rate (delivery_rate), min_rtt (windowed min).
- Pacer rate: `bw_estimate * pacing_gain`.
- Loss signal: per-path loss rate → multiplicative decrease.
- ECN support (optional): RFC 3168 + Hop ECN field в `PacketHeader`.
- Tests: simulated bottleneck (через `core/src/test_harness/`) — convergence к 80%+ link bandwidth.

### 4.5 Telemetry & observability
**Что уже есть:** 9 `log::` calls, `transport/metrics.rs` (минимально).

**Что нужно достроить:**
- **`tracing`**: добавить как dependency. Инструментировать:
  - `#[tracing::instrument]` на `connect_with_transport`, `accept`, `send_app_data`, `decrypt_packet`, `process_client_hello`, `process_server_hello`.
  - Span fields: `session_id`, `stream_id`, `path_id`, `peer_addr`.
  - Levels: TRACE для per-packet, DEBUG для per-handshake, INFO для session lifecycle, WARN для drops/replays, ERROR для failures.
- **`metrics`**: counters, gauges, histograms.
  - Counters: `sessions_total{state="connected|failed|closed"}`, `packets_total{direction, encrypted}`, `bytes_total{...}`, `replay_rejected_total`, `unencrypted_dropped_total`, `aead_decrypt_failed_total`, `handshakes_total{stage}`, `migrations_total`.
  - Gauges: `active_sessions`, `active_streams`, `cpu_aead_throughput_bps`.
  - Histograms: `handshake_latency_seconds`, `packet_processing_latency_seconds`, `rtt_seconds`, `payload_size_bytes`.
- **Exporters**:
  - Prometheus (`metrics-exporter-prometheus`) — server-side HTTP endpoint.
  - OpenTelemetry (OTel SDK + OTLP exporter) — гибкая распределённая trace pipeline.
  - JSON-line logs (для shipping в Loki/Elastic).
- **Operational dashboards**:
  - Grafana dashboard JSON (commit в `docs/operations/grafana/`).
  - Prometheus alert rules (`docs/operations/prometheus/alerts.yml`).
- **Health endpoints**:
  - `pub fn health(&self) -> HealthStatus` на `PhantomListener` (active sessions count, handshake error rate).
  - Optional HTTP `/health` endpoint в example app.

### 4.6 Graceful shutdown & signal handling
- `PhantomListener::shutdown(timeout)` — stop accepting, drain current sessions.
- На server-binary level: ловить SIGTERM/SIGINT, инициировать graceful close.
- Документировать в `docs/operations/deployment.md`.

### Deliverables Phase 4
| Подсистема | Файлы | Effort |
|---|---|---|
| 0-RTT resumption | `core/src/transport/session_cache.rs`, `core/src/transport/handshake.rs`, `core/src/api/session.rs` | L |
| Multi-path failover | `core/src/transport/virtual_socket.rs`, `core/src/transport/scheduler.rs`, `core/src/transport/fallback.rs`, `core/src/transport/types.rs` | XL |
| Connection migration | `core/src/transport/migration.rs` (new) | L |
| Stream priority scheduling | `core/src/transport/stream.rs`, `core/src/api/session.rs` | M |
| Per-stream flow control | `core/src/transport/stream.rs`, new wire frame | M |
| BBRv2 congestion control | `core/src/transport/cc.rs` (new), `core/src/transport/pacer.rs`, `core/src/transport/bandwidth_estimator.rs` | L |
| Tracing instrumentation | везде в hot path | M |
| Metrics + Prometheus exporter | `core/src/observability/` (new) | M |
| Health endpoints | `core/src/api/listener.rs`, `core/src/api/session.rs` | S |
| Graceful shutdown | `core/src/api/listener.rs` | S |

**Verification:** 0-RTT measured ≥2× faster reconnect; multi-path failover <50 ms; congestion control converges (CC simulator); metrics scrape работает; Grafana dashboard загружается.

---

## Phase 5 — FIPS 140-3 / Common Criteria Compliance Track

**Goal:** опциональная FIPS-compliant сборка с certified primitives и подготовка к Common Criteria evaluation.

**Effort: XL.** Параллельный track. Лабораторная часть требует внешнего CMVP-laboratory (бюджет $80K-$300K), что вне scope этого плана, но code-changes — внутри.

### 5.1 FIPS-approved primitive selection
**Где сейчас НЕ FIPS:**
- `blake3` — не FIPS (нужно SHA-256 / SHA-3).
- `chacha20poly1305` — не FIPS (нужно AES-GCM, что уже есть через `ring`).
- `pqcrypto-kyber` — Kyber768 не FIPS; FIPS 203 утвердил ML-KEM-768 (тот же алгоритм, иная сериализация).
- `pqcrypto-dilithium` — Dilithium3 не FIPS; FIPS 204 утвердил ML-DSA-65.
- `x25519-dalek` — X25519 не FIPS-approved KEM (как классический). Возможные альтернативы: ECDH P-256/P-384 (FIPS 186-4), но это reduce'ит post-quantum hybridness.

**Действия:**
- Feature `fips`: при включении переключает на:
  - hash/KDF: SHA-256 (через `ring::digest::SHA256` или `sha2`).
  - AEAD: AES-256-GCM (уже есть через `ring`), но требует FIPS-validated build of `ring` (или `aws-lc-rs`).
  - PQ-KEM: `ml-kem` crate (FIPS 203) вместо `pqcrypto-kyber`.
  - PQ-SIG: `ml-dsa` crate (FIPS 204) вместо `pqcrypto-dilithium`.
  - Signing: Ed25519 остаётся (FIPS 186-5 утвердил EdDSA с Ed25519).
  - Classical KEM: X25519 заменить на ECDH P-256 в FIPS-feature, либо drop classical leg и оставить только PQ.
- Backend для symmetric crypto: switch на `aws-lc-rs` (Amazon's FIPS-validated fork of BoringSSL).
- Feature combinatorics:
  - `default`: текущее (PQC standard, X25519, ChaCha + AES, blake3).
  - `fips`: ML-KEM/ML-DSA + Ed25519 + AES-256-GCM + SHA-256, нет ChaCha, нет blake3, нет X25519.
  - `fips-hybrid`: ML-KEM/ML-DSA + ECDH P-256 + Ed25519 + AES-256-GCM + SHA-256.

### 5.2 Constant-time audit & SIDE-channel resistance
- Audit каждой ветки на public-secret mix:
  - Все ветви по результатам decrypt: `match crypto.decrypt(...)` — handle equally на success vs fail.
  - Все ветви по длине секретов.
  - Все ветви по signature verification.
- Compile-time guarantees: `subtle` уже подключён в Phase 1.
- Аудит на cache-timing: AES-NI — constant-time на современных CPUs. Documented requirement в `SECURITY.md`.

### 5.3 RNG audit & DRBG path
- FIPS требует SP 800-90A DRBG.
- `getrandom` на Linux → `/dev/urandom` (FIPS-validated на certified kernels).
- В FIPS mode: использовать `aws-lc-rs::rand` (CTR_DRBG / HMAC_DRBG из BoringSSL).
- Документировать "approved RNG sources" в `SECURITY.md` для каждой платформы.

### 5.4 CAVP test vectors
- Cryptographic Algorithm Validation Program (CAVP) — proof, что наша implementation matches NIST test vectors.
- Добавить `tests/cavp/` с:
  - ML-KEM-768 KAT (Known Answer Test) vectors.
  - ML-DSA-65 KAT vectors.
  - Ed25519 RFC 8032 vectors.
  - AES-256-GCM NIST KAT.
  - SHA-256 NIST KAT.
  - HKDF RFC 5869 test vectors.
- CI job `cavp.yml` запускает все KATs.

### 5.5 Documentation для CMVP
- `docs/compliance/fips-security-policy.md` — boundary, modes of operation, approved security functions.
- `docs/compliance/key-management.md` — generation, storage, destruction, key lifecycle.
- `docs/compliance/self-tests.md` — power-on self-tests (POST), conditional self-tests, on-demand self-tests.
- Implement self-tests:
  - POST: run a known-answer test for each algorithm at module init.
  - Conditional: pairwise consistency test on key pair generation.
  - On-demand: API `phantom_core::fips::run_self_tests() -> Result<(), FipsError>`.

### 5.6 Common Criteria (CC) targeting
- Determine target Protection Profile (PP):
  - **PP-Mobile Device VPN Client** (NIAP) — likely match для mobile use case.
  - **collaborative Protection Profile for Network Devices** (NDcPP) — для server.
- Map our security functional requirements (SFRs) → PP requirements.
- Document Security Target (ST) — это итерационный документ с CC evaluator.

### 5.7 Validation pathway
- FIPS 140-3 CMVP queue: $80-150K, 6-12 months.
- CC evaluation: $150-300K, 12-24 months.
- Это решения бизнеса. Code-changes делаются first, validation — потом.

### Deliverables Phase 5
| Артефакт | Где | Effort |
|---|---|---|
| `fips` feature flag | `core/Cargo.toml`, conditional code paths | L |
| ML-KEM / ML-DSA migration | `core/src/crypto/hybrid_kem.rs`, `core/src/crypto/hybrid_sign.rs` | L |
| aws-lc-rs backend | `core/src/crypto/adaptive_crypto.rs`, `core/src/crypto/aes_session.rs` | M |
| SHA-256 KDF (non-blake3) | `core/src/crypto/adaptive_crypto.rs:175`, `core/src/crypto/aes_session.rs:57`, `core/src/transport/legs/faketls.rs:118` | S |
| CAVP test vectors | `tests/cavp/` | M |
| Self-tests (POST + conditional) | `core/src/crypto/self_tests.rs` (new) | M |
| Compliance docs | `docs/compliance/` | M |
| CC Protection Profile mapping | `docs/compliance/cc-st.md` | L |

**Verification:** `cargo build --features fips` собирается; CAVP KATs все green; self-tests passes; примитивы dependency-tree содержит только FIPS-approved crates.

---

## Phase 6 — Audit Readiness: Fuzzing, Property Tests, Loom, Documentation

**Goal:** подготовить артефакты, которые ожидает внешний security auditor.

**Effort: L.** Один-два инженера 2-3 месяца.

### 6.1 Threat model document
- `docs/security/threat-model.md` (STRIDE + LINDDUN methodology):
  - **Spoofing**: protected by `expected_server_key` pinning (Phase 1.1, already enforced).
  - **Tampering**: AEAD AAD на каждый packet (`PacketHeader`).
  - **Repudiation**: out of scope; not designed for non-repudiation (would require persistent transcript signing).
  - **Information disclosure**: AEAD, FakeTLS obfuscation, no plaintext leaks via error messages (Phase 1.13).
  - **Denial of service**: cookie + PoW (`transport/half_open.rs`), per-IP rate limit (Phase 1.14).
  - **Elevation of privilege**: out of scope; library не has privileged operations.
- LINDDUN privacy threats: linkability, identifiability, non-repudiation (here: undesired), detectability, disclosure, unawareness, non-compliance.
- **Out-of-scope** explicitly stated: traffic analysis (timing/size), compromise of endpoints, compromise of server long-lived signing key.

### 6.2 Protocol specification
- `docs/protocol/PROTOCOL.md`:
  - Wire format: every field of `PhantomPacket`, `PacketHeader`, `ClientHello`, `ServerHello` with byte offset and width.
  - State machine: handshake stages (Initial → ClassicalReady → PqcReady → Established / Failed).
  - Handshake message flow (ASCII diagram).
  - AEAD construction: nonce = `nonce_prefix[4] || counter[8]`, AAD = serialized PacketHeader.
  - Key derivation: HKDF inputs, info strings, labels.
  - Cookie/PoW: HMAC-SHA-256 details.
  - 0-RTT semantics + anti-replay caveat.
  - Multi-path migration: validation challenge format.
  - Versioning policy.

### 6.3 Architecture document
- `docs/architecture/ARCHITECTURE.md`:
  - Module diagram (mermaid / svg).
  - Data flow (recv path / send path).
  - Trust boundaries (FFI, network).
  - Concurrency model.

### 6.4 Fuzzing harnesses (cargo-fuzz)
- `fuzz/` directory с `cargo-fuzz init`. Targets:
  - `fuzz_targets/fuzz_client_hello.rs` — fuzz `borsh::from_slice::<ClientHello>(input)` + `process_client_hello`.
  - `fuzz_targets/fuzz_server_hello.rs` — fuzz client side.
  - `fuzz_targets/fuzz_packet_parse.rs` — fuzz `PhantomPacket::from_wire(input)`.
  - `fuzz_targets/fuzz_aead_decrypt.rs` — fuzz `Session::decrypt_packet` with random AAD + ciphertext.
  - `fuzz_targets/fuzz_faketls_record.rs` — fuzz FakeTLS record parsing (`legs/faketls.rs:669-689`).
  - `fuzz_targets/fuzz_tcp_framing.rs` — fuzz length-prefix parsing.
- OSS-Fuzz integration: бесплатно для open-source, 24/7 continuous fuzzing.
- Corpus seeded from real-world packet captures (when available).

### 6.5 Property tests (proptest)
- Add `proptest = "1"` as dev-dependency.
- `core/tests/property/` directory:
  - AEAD round-trip: `forall (key, nonce, aad, plaintext): decrypt(encrypt(plaintext, key, nonce, aad), key, nonce, aad) == Ok(plaintext)`.
  - Handshake: `forall (client_seed, server_seed): handshake(client, server) -> client.session.shared_secret == server.session.shared_secret`.
  - Wire-format round-trip: `forall packet: PhantomPacket::from_wire(packet.to_wire()) == Ok(packet)`.
  - Replay window: `forall stream of nonces: replay-protected.accept(...).count == count_after_dedup(stream)`.
- Run 100K iterations per property; failures saved to corpus.

### 6.6 Loom tests (concurrency invariants)
- Add `loom = "0.7"` as dev-dependency.
- `core/tests/loom/`:
  - DashMap stream insertions/removals + concurrent reads.
  - Atomic counter monotonicity на rekey trigger.
  - Send queue under contention.
- Run loom-tests in CI (separate job, slow).

### 6.7 Miri test runs (memory safety)
- CI job `miri.yml`: `cargo +nightly miri test --workspace`.
- Catches UB, leaks, unaligned access.
- Some tokio operations не support miri — изолировать pure unit tests от async io.

### 6.8 Negative security tests (formal)
- `core/tests/negative_security.rs`:
  - Bad server identity → `ConnectionState::Failed`.
  - Stripped ENCRYPTED flag with non-empty payload → packet dropped.
  - Malformed PacketHeader (random bytes) → parse failure, не panic.
  - FakeTLS replay (same record twice) → second rejected.
  - Tampered ciphertext (single bit flip) → AEAD verification fails.
  - Replay window exceeded → rejected.
  - Cookie tampered → handshake fails.
  - Version downgrade attempt → rejected по version-list check.

### 6.9 Coverage measurement
- `cargo-llvm-cov` или `tarpaulin` для line + branch coverage.
- Target: ≥85% line coverage, ≥75% branch coverage в `core/src/crypto/`, `core/src/transport/handshake.rs`.
- CI job + Codecov / Coveralls upload.

### 6.10 Formal verification (optional, advanced)
- Symbolic model в `ProVerif` или `Tamarin`:
  - Model handshake as message-passing protocol.
  - Prove authentication, key agreement, forward secrecy under specified adversary.
- Effort XL, skip unless required by audit.

### 6.11 Code-level invariants documented
- Each `unsafe { }` block: `// SAFETY: <invariant>` comment.
- Each `panic!`, `unwrap`, `expect` (those that remain): `// PANIC-SAFETY: <invariant>` comment + лист в `docs/security/panic-sites.md`.
- Each public crypto API: doc-comment with what it guarantees and what it doesn't.

### Deliverables Phase 6
| Артефакт | Где | Effort |
|---|---|---|
| Threat model | `docs/security/threat-model.md` | M |
| Protocol spec | `docs/protocol/PROTOCOL.md` | M |
| Architecture doc | `docs/architecture/ARCHITECTURE.md` | M |
| Fuzz harnesses | `fuzz/` directory | M |
| OSS-Fuzz integration | `oss-fuzz/projects/phantom-core/` (separate repo) | S |
| Property tests | `core/tests/property/` | M |
| Loom tests | `core/tests/loom/` | M |
| Miri CI | `.github/workflows/miri.yml` | S |
| Negative tests | `core/tests/negative_security.rs` | M |
| Coverage | CI + thresholds | S |
| Code-invariant docs | inline comments + `docs/security/panic-sites.md` | M |

**Verification:** fuzz runs 24+ hours без panic; loom tests pass; coverage ≥85%; threat model peer-reviewed (internally).

---

## Phase 7 — Operations & Release

**Goal:** довести до состояния, в котором другая команда может deploy и operate без помощи authors.

**Effort: M.** Один инженер 1-2 месяца.

### 7.1 End-to-end examples
- `core/examples/simple_client.rs` — connect, send/recv, close.
- `core/examples/simple_server.rs` — listen, accept, handle session.
- `core/examples/multi_stream.rs` — открыть N parallel streams, send concurrent data.
- `core/examples/with_kcp.rs` — KCP-only client/server.
- `core/examples/with_faketls.rs` — FakeTLS-only.
- `core/examples/auto_failover.rs` — multi-leg setup, simulate primary leg failure.
- `core/examples/wasm_client/` — WASM-bundled пример, npm пакет.
- `core/examples/mobile_ios/` — Swift example using `PhantomSession`.
- `core/examples/mobile_android/` — Kotlin example.
- `core/examples/embedded_demo.rs` — `EmbeddedLeg` framing over a mock byte stream, **run on a host** (the full PQ session is std-only; a `thumbv7em` "Phantom-secured uplink" is descoped — see §3.6).
- Каждый example в README + комментарии в коде.

### 7.2 Deployment guides
- `docs/operations/docker.md` + `Dockerfile` для server binary.
- `docs/operations/kubernetes.md` + sample manifests (`deployments/k8s/`).
- `docs/operations/systemd.md` + `phantom-server.service` unit file.
- `docs/operations/mobile-integration.md` — XCFramework / AAR build & integration.
- `docs/operations/wasm-bundling.md` — wasm-pack workflow.

### 7.3 Versioning policy
- `docs/policy/versioning.md`:
  - Public Rust API: SemVer strict.
  - Wire format: single `PhantomPacket` with a pinned `WIRE_VERSION` header byte — bumped deliberately on a breaking change.
  - FFI ABI: track separately в `tests/bindings/CHANGELOG.md`.
- `cargo-semver-checks` в CI: detect breaking changes pre-merge.

### 7.4 Release process
- `cargo-release` or `cargo-dist` for binary releases.
- GPG-signed git tags + release artifacts.
- crates.io publication workflow.
- SLSA-level 3 attestation (provenance proof via GitHub OIDC).
- Reproducible builds (`cargo config` lockdown + container-pinned toolchain).

### 7.5 Incident response & disclosure
- `SECURITY.md` (in Phase 0) с GPG key + email.
- Embargo SLA: 90 days from receipt to public disclosure.
- CVE process: GitHub Security Advisories.

### 7.6 Operational dashboards & alerts
- `docs/operations/grafana/phantom-dashboard.json` — Grafana dashboard (sessions, handshakes, throughput, latency, errors).
- `docs/operations/prometheus/alerts.yml` — alerts: handshake failure rate, AEAD failure rate, migration rate spike.
- Reference deployment patterns.

### 7.7 Performance tuning guide
- `docs/operations/perf-tuning.md`:
  - OS settings (sysctl, fs.file-max, net.core.rmem_max).
  - Build-time choices (target-cpu=native, PGO).
  - Config tuning (`PhantomConfig.server()` vs `.mobile()`).
  - Profiling tips (perf, flamegraph).

### 7.8 Migration guides
- Migration notes recorded in `CHANGELOG.md` per breaking-change release (the
  per-version `docs/migration/` dir was removed when the three version axes
  collapsed into one wire protocol).
- Wire-version compatibility matrix.

### Deliverables Phase 7
| Артефакт | Где |
|---|---|
| End-to-end examples (server, client, mobile, WASM, embedded) | `core/examples/` |
| Deployment guides | `docs/operations/` |
| Versioning policy + cargo-semver-checks | `docs/policy/`, CI |
| Release pipeline | GitHub Actions, cargo-release |
| Incident response playbook | `docs/security/incident-response.md` |
| Grafana dashboards, Prometheus alerts | `docs/operations/grafana/`, `docs/operations/prometheus/` |
| Performance tuning guide | `docs/operations/perf-tuning.md` |

---

## Sequencing & Dependencies

```
Phase 0  ────►  Phase 1  ──┐
   │            Phase 2  ──┼──►  Phase 4  ──►  Phase 7
   │            Phase 3  ──┤
   └─────────►  Phase 5  ──┴──►  Phase 6  ──►  Phase 7
```

- **Phase 0** (Foundation) — обязательная первая.
- **Phases 1, 2, 3, 5** могут идти параллельно после Phase 0:
  - 1 (Security) — независим, кроме нужды в CI из 0.
  - 2 (Performance) — независим.
  - 3 (Portability) — может конфликтовать с 1/2 в одних файлах; рекомендуется сначала 1, потом 3.
  - 5 (FIPS) — параллельный track, независим от 1/2/3 архитектурно, но в 5.1 swap primitives → conflicts с 1 если оба меняют тот же файл.
- **Phase 4** (New subsystems) зависит от 2 (Pacer/Estimator wired) и 3 (Runtime abstraction для multi-path).
- **Phase 6** (Audit readiness) зависит от 1+5 (хочется audit стабилизированной security model).
- **Phase 7** (Operations) последний — закрепляет.

**Минимальный MVP-путь к "production":** Phase 0 → 1 → 2 (без всех XL пунктов) → 6 (минимум: fuzzing + protocol spec + threat model) → 7. Это 4-6 месяцев для focused team. WASM, FIPS, congestion control добавляются позже.

**Полный путь:** все 8 фаз, 12-18 месяцев для команды 2-3 инженеров, 6-9 месяцев для 5+ инженеров.

---

## Effort Summary

| Phase | Topic | Effort | Crit |
|---|---|---|---|
| 0 | Foundation (CI, tooling, gov) | M | P0 |
| 1 | Security hardening | L | P0 |
| 2 | Performance | L | P1 |
| 3 | Portability (WASM/embedded) | XL | P1 |
| 4 | New subsystems (0-RTT/multi-path/CC/telemetry) | XL | P1 |
| 5 | FIPS/CC compliance | XL | P1 |
| 6 | Audit readiness (fuzz/proptest/loom/docs) | L | P0 |
| 7 | Operations & release | M | P1 |

**Total: ~13-18 person-months** для full plan.

---

## Open Decisions (требуют user input до старта)

1. **WASM target scope:** только client (WebSocket leg в браузере) или также server-side WASI (для serverless deploy)?  Plan currently assumes both; client browser — приоритет.
2. **Embedded target scope:** какой класс устройств (Cortex-M, Cortex-A, ESP32, RISC-V)? Plan предполагает Cortex-M уровень для smoke build.
3. **FIPS implementation strategy:** `aws-lc-rs` (BoringSSL FIPS module) vs `ring` + standalone ML-KEM/ML-DSA crates vs внешний liboqs FFI? Plan recommends aws-lc-rs.
4. **License:** Apache-2.0 / dual MIT+Apache (Rust standard) / commercial? Plan recommends Apache-2.0.
5. **CMVP/CC laboratory choice:** влияет на форматы документов в Phase 5/6.
6. **Crates.io publication timing:** до или после security audit?
7. **Bug bounty program:** включать или нет? Если да — через HackerOne/Bugcrowd или self-hosted?
8. **Mobile SDK distribution:** ship как XCFramework + AAR, или users собирают сами из Rust source?
9. **Phasing strategy:** sequential phases (predictable, slower) или parallel tracks (faster, more conflicts)?
10. **Performance targets:** есть ли конкретные numbers, к которым стремимся (throughput Gbps, latency µs)?

---

## Verification Plan

Каждая фаза проверяется конкретным набором critериев:

**Phase 0:** CI green on sample PR; `cargo deny check` clean; `cargo audit` clean; `cargo doc --no-deps` без warnings; криты ​​erion baseline сохранён.

**Phase 1:**
- Все 12 пунктов hardening закрыты PR'ами с тестами.
- `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used -D clippy::expect_used` clean.
- New file `core/tests/security_invariants.rs` со всеми negative tests passes.
- Long-running session test (24h) → key rotation срабатывает.

**Phase 2:**
- Criterion bench show:
  - `recv_bytes`: allocs ≈ 0 per packet после warmup.
  - Send latency P50 < 100 µs, P99 < 1 ms.
  - Throughput +20-30% от baseline.
- Flamegraph не показывает hot frames в Vec::new или Clone.

**Phase 3:**
- CI matrix: всё зелёное на 8+ target triples.
- `examples/wasm_client/` собирается → запускается в Chrome → connects to Linux server, exchanges data.
- `examples/embedded/` собирается на `thumbv7em-none-eabihf`.
- iOS/Android FFI smoke-test passes (XCFramework load + simple connect).

**Phase 4:**
- 0-RTT measured: second connect → handshake bytes ≤ 50% of full PQ handshake, latency ≤ 50% of full.
- Multi-path failover: kill primary TCP leg, KCP takes over в <50 ms (measured via packet trace).
- Congestion control: simulator (bottleneck 100 Mbps, 50ms RTT) → converges к 80%+ utilization без packet loss spikes.
- Tracing: `RUST_LOG=phantom_core=trace` показывает spans с session_id, stream_id.
- Prometheus scrape returns valid metrics; Grafana dashboard loads.

**Phase 5:**
- `cargo build --features fips --no-default-features` собирается.
- CAVP KAT tests все passes.
- `phantom_core::fips::run_self_tests()` returns Ok.
- Dependency tree (`cargo tree --features fips`) содержит только FIPS-approved или non-cryptographic crates.

**Phase 6:**
- Fuzz runs 24+ hours без panics (на каждом fuzz target).
- Loom tests все passes.
- Coverage ≥85% line / ≥75% branch.
- Threat model peer-reviewed (internal).
- Protocol spec validates с реальным wire trace (PCAP анализ).

**Phase 7:**
- Все examples собираются и запускаются.
- `cargo publish --dry-run` clean.
- Release pipeline на test tag создаёт signed артефакт.
- Grafana dashboard import + Prometheus alerts validate.

---

## Critical Files Reference

Файлы, упоминаемые в плане многократно (для быстрой ориентации):

| Файл | Роль |
|---|---|
| `core/Cargo.toml` | Workspace, features, profile (Phase 0.7) |
| `core/src/lib.rs` | Module declarations + UniFFI scaffolding |
| `core/src/api/session.rs` | Public client API + run_data_pump (hot path) |
| `core/src/api/listener.rs` | Public server API |
| `core/src/api/stream.rs` | PhantomStream FFI surface |
| `core/src/api/tcp_transport.rs` | TCP framing (Phase 2.1 BufferPool) |
| `core/src/transport/handshake.rs` | Hybrid handshake — большая часть Phase 1 |
| `core/src/transport/session.rs` | Session + CryptoState (Phase 1.2 Zeroize) |
| `core/src/transport/types.rs` | Wire format — single `PhantomPacket`, pinned `WIRE_VERSION` |
| `core/src/transport/buffer_pool.rs` | Готов, не подключён (Phase 2.1) |
| `core/src/transport/pacer.rs` | Готов, не подключён (Phase 2.6) |
| `core/src/transport/packet_coalescer.rs` | Готов, не подключён (Phase 2.5) |
| `core/src/transport/bandwidth_estimator.rs` | Готов, не подключён (Phase 2.6, Phase 4.4) |
| `core/src/transport/virtual_socket.rs` | Multi-leg orchestrator (Phase 4.2) |
| `core/src/transport/scheduler.rs` | Path policies (Phase 4.2) |
| `core/src/transport/session_cache.rs` | Готов, не подключён (Phase 4.1) |
| `core/src/transport/legs/tcp.rs` | TCP leg |
| `core/src/transport/legs/kcp.rs` | KCP leg |
| `core/src/transport/legs/faketls.rs` | FakeTLS leg (uses AES-GCM via ring) |
| `core/src/transport/legs/websocket.rs` | NEW в Phase 3.3 |
| `core/src/transport/legs/embedded.rs` | NEW в Phase 3.4 |
| `core/src/crypto/hybrid_kem.rs` | X25519+Kyber768 — Phase 5.1 swap |
| `core/src/crypto/hybrid_sign.rs` | Ed25519+Dilithium3 — Phase 5.1 swap |
| `core/src/crypto/adaptive_crypto.rs` | AEAD core (Phase 1.2 Zeroize, Phase 5.1 backend) |
| `core/src/crypto/aes_session.rs` | Reference AEAD pattern |
| `core/src/security/replay_protection.rs` | Готов, не подключён (Phase 1.4) |
| `core/src/runtime/` | NEW в Phase 3.1 (TokioRuntime, WasmRuntime, EmbeddedRuntime) |
| `core/src/observability/` | NEW в Phase 4.5 (metrics exporters) |
| `core/src/crypto/self_tests.rs` | NEW в Phase 5.5 (POST + conditional) |
| `core/tests/security_invariants.rs` | NEW в Phase 1 (negative tests) |
| `core/tests/property/` | NEW в Phase 6.5 |
| `core/tests/loom/` | NEW в Phase 6.6 |
| `core/tests/negative_security.rs` | NEW в Phase 6.8 |
| `fuzz/fuzz_targets/` | NEW в Phase 6.4 |
| `docs/security/threat-model.md` | NEW в Phase 6.1 |
| `docs/protocol/PROTOCOL.md` | NEW в Phase 6.2 |
| `docs/architecture/ARCHITECTURE.md` | NEW в Phase 6.3 |
| `docs/compliance/fips-security-policy.md` | NEW в Phase 5.5 |
| `docs/operations/` | NEW в Phase 7 |
| `.github/workflows/` | NEW в Phase 0.4 |
