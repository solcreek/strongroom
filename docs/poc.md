# Strongroom: Rust / TypeScript POC

比較 BYOK API key 的 envelope encryption：TypeScript / Web Crypto、Rust / Wasm，以及同一個 Rust 核心的原生執行檔。

**這是效能與相容性 POC，不是可儲存真實 API key 的服務。** 包裝資料金鑰的「KMS」使用公開、固定的本機測試金鑰。沒有串接 AWS KMS、Google Cloud KMS、Vault 或 OpenBao；沒有正式租戶授權、憑證管理或稽核設施。HTTP 入口預設關閉，只應在本機使用合成資料測試。

## 內容

| 實作 | 加密與密文格式 | 執行方式 |
|---|---|---|
| TypeScript | Web Crypto AES-256-GCM | Node.js；Cloudflare Workers |
| Rust / Wasm | RustCrypto AES-256-GCM；Rust 負責 JSON、驗證、加解密、base64 | 小型 JS HTTP host + Wasm；Node.js 與本機 workerd |
| Rust native | 與 Wasm 相同的 Rust 核心；ARM 原生版啟用 AES / PMULL 硬體加速 | CLI，用於核心效能與整個程序記憶體的基準 |

Rust / Wasm POC 不是完整的 workers-rs 伺服器。共用的 JS host 處理 HTTP、請求限制、POC token、CSPRNG 與模擬網路等待；Rust 核心處理密文。此拆分刻意保留一樣的 HTTP 行為，避免框架差異混入核心比較。原生版目前沒有 HTTP server 或容器部署測試。

## 重現

需求：Node.js 24+、Rust 1.98.1、`wasm32-unknown-unknown` target、wasm-bindgen CLI 0.2.105。

```sh
rustup toolchain install 1.98.1 --profile minimal --target wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.105 --locked
npm ci
npm run build
npm run check
npm test
npm run bench
npm run bench:workerd
npm run report
# 允許本機 TCP listener 的環境，可額外執行：
npm run bench:workers
```

不要同時執行多個 benchmark，以免互相干擾。建置會先執行 Rust 的標準測試向量與竄改測試。Node 測試會檢查三個引擎的九種交叉解密組合，以及 unicode、空字串、64 KiB 上限、錯誤 context、密文竄改與 HTTP 防護。這次環境禁止 TCP listen，故 HTTP 壓測未完成；改以 workerd 自帶的無 socket test 入口驗證實際 runtime 的相容性與 handler 效能。

此工作區原本只有 Homebrew Rust、沒有 Wasm target，因此 `.cache/` 內另放官方 Rust 工具鏈、wasm-bindgen 及 Cargo 下載快取。`scripts/build.mjs` 在它們存在時使用；一般 rustup 安裝不需要這些本機快取。全域工具鏈不受影響。Cargo.lock 與 package-lock.json 記錄依賴版本。

## 執行 POC

TypeScript 的 Node HTTP server 只綁定 loopback：

```sh
POC_ONLY=true POC_TOKEN=synthetic-local-token-at-least-24-chars npm run start:ts
```

```sh
curl http://127.0.0.1:8787/encrypt \
  -H 'Authorization: Bearer synthetic-local-token-at-least-24-chars' \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"synthetic-api-key","context":{"tenantId":"t1","recordId":"r1","purpose":"api-key"}}'
```

將回傳的整個 envelope 與相同 context 送到 `POST /decrypt` 即回傳 `{"plaintext":"synthetic-api-key"}`。HTTP API 不接受外部指定的 entropy。

兩份 Workers 設定：`wrangler.ts.jsonc`、`wrangler.rust.jsonc`。本機啟動可使用：

```sh
npx wrangler dev --config wrangler.ts.jsonc --local \
  --var POC_ONLY:true --var POC_TOKEN:synthetic-local-token-at-least-24-chars
# 或將 config 換成 wrangler.rust.jsonc（先 npm run build）
```

預設 `workers_dev: false`、`POC_ONLY: false`；沒有發布到任何帳號。Workers 部署需要編譯後的 Wasm、JS glue 與 Worker 入口，不能直接上傳任意 WASI 執行檔。一般容器平台則應選 Rust 原生 HTTP 程式或 Node.js 服務；Wasm 並不會自動消除各平台的網路、身分驗證與部署差異。

## 密文契約

每次加密產生 56 bytes CSPRNG：32-byte DEK、12-byte data nonce、12-byte wrapping nonce。AES-256-GCM 使用 128-bit tag。DEK 每次寫入更新，沒有明文 DEK cache。

AAD 為 UTF-8 JSON array：`["strongroom-poc",1,tenantId,recordId,purpose]`。資料加密與 DEK 包裝皆綁定相同 AAD；解密者必須提供預期的 context，不能只信任資料庫內的租戶欄位。context 是完整性綁定，不是呼叫者授權，且不得放秘密。

Envelope 包含 `version`、`algorithm`、`keyId`、`nonce`、`wrappedKey`、`ciphertext`。Binary 欄位使用 canonical base64url without padding；GCM tag 附在 ciphertext 尾端；wrappedKey 是 wrapping nonce + encrypted DEK + tag。格式目前僅供 POC，不是既有公開標準。

Rust 使用 Zeroizing 保護暫存 DEK，TS 清除可控制的 byte buffers；兩者仍有 JSON 字串、host/Wasm 資料複製及 runtime 管理的記憶體，不能保證所有明文副本立即被抹除。

## 量測方法與限制

- 核心測試：128 B、1 KiB、16 KiB；每份樣本為一次 encrypt + decrypt，包含 RNG、JSON、base64、兩次模擬 KMS wrap/unwrap。三次獨立程序重複，輪替測試順序。
- 無延遲情境先暖機 100 次；每次模擬 KMS 呼叫等待 10 ms 或 50 ms 的情境先暖機 5 次。延遲是計時器，沒有 DNS、TLS、雲端驗證、限流或真正 KMS 費用。
- 本機 workerd：已完成無 socket 的 handler 測試；每個 roundtrip 包含 encrypt / decrypt 的 Request/Response，整個 batch 量測含結尾的 1 ms timer，以配合 Workers 時鐘行為。沒有 HTTP transport，數字是 batch 平均，非逐請求 p50/p95。
- 額外 HTTP 腳本：Miniflare/workerd、loopback HTTP、128 B，並行度 1 與 8，每個 roundtrip 包含兩次 HTTP request。這次執行因 sandbox 禁止 listen 而未完成。
- 延遲提供每次 run 的 p50/p95；報告表格取三次 run 的中位數，沒有把它當成全球服務 SLO。
- 記憶體是整個程序的峰值 RSS：Wasm 在 Node 裡量測，包含 V8；Rust 原生 CLI 不需要 V8。這不能證明 Workers isolate 會按相同比例節省記憶體。Wasm linear memory 另列原始資料，不能替代總記憶體。
- CPU 是程序資源計數，包含啟動與暖機；不是 Cloudflare 帳單 CPU 時間。Node 內 module 初始化與啟動本機 workerd 也不是正式環境 cold start。
- 此結果比較的是這兩份實作與所用函式庫。Web Crypto 由宿主實作；Wasm 的 RustCrypto 使用可攜實作。Rust / Wasm 也可以改為呼叫宿主 Web Crypto，那是另一種待測設計。
- 產物大小分別列 JS bundle、Wasm 與原生 binary，不把壓縮 Wasm 大小和未壓縮 JS 相比。
- 沒有測正式 Cloudflare、GCP、GKE、AWS、Render、Railway 的部署或跨雲網路；沒有用真實 KMS 做端到端驗證。

結果見 [POC 比較報告](../results/REPORT.md)、[核心原始資料](../results/benchmark.json)、[workerd 原始資料](../results/workerd.json)、[HTTP 測試狀態](../results/workers.json)。兩份 Workers 設定都已通過 Wrangler deploy --dry-run。

## 正式產品下一步

保留可共用的 Rust domain core，但把 KMS 抽象成非同步 wrap/unwrap provider，再分別實作 AWS SigV4、Google OAuth / workload identity、Vault / OpenBao 認證與 HTTP transport。原生與 Workers 的 HTTP、計時器和憑證取得不同；雲端 SDK 能在原生 Rust 編譯不代表能在 `wasm32-unknown-unknown` 使用。

正式驗收還需要：租戶授權、可輪替的服務身分、禁止敏感資料進日誌、KMS timeout / retry / rate limit、稽核持久化、版本化 key routing、舊資料與備份的復原流程，以及每個部署平台與 KMS 組合的實際整合測試。先用 AWS sandbox KMS 完成一條真實流程，再擴充供應商。

參考：[Workers Rust](https://developers.cloudflare.com/workers/languages/rust/)、[workers-rs](https://github.com/cloudflare/workers-rs)、[Workers Wasm](https://developers.cloudflare.com/workers/runtime-apis/webassembly/javascript/)、[Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)、[RustCrypto AES-GCM](https://docs.rs/aes-gcm/0.10.3/aes_gcm/)、[envelope encryption](https://docs.cloud.google.com/kms/docs/envelope-encryption)。
