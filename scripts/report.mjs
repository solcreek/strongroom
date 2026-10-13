import { readFileSync, writeFileSync } from 'node:fs';
const core = JSON.parse(readFileSync('results/benchmark.json'));
const workers = JSON.parse(readFileSync('results/workerd.json'));
const validation = JSON.parse(readFileSync('results/validation.json'));
const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
const engines = ['typescript', 'rust-wasm', 'rust-native'];
const names = { typescript: 'TypeScript / Web Crypto', 'rust-wasm': 'Rust / Wasm', 'rust-native': 'Rust native CLI' };
const pick = (engine, size, delay = 0) => core.measurements.filter(x => x.engine === engine && x.size === size && x.delayMsPerKmsCall === delay);
const metric = (engine, size, key, delay = 0) => median(pick(engine, size, delay).map(x => x[key]));
const coreRows = [128, 1024, 16384].map(size => `| ${size} B | ${engines.map(e => metric(e, size, 'p50Ms').toFixed(3)).join(' | ')} |`).join('\n');
const p95Rows = [128, 1024, 16384].map(size => `| ${size} B | ${engines.map(e => metric(e, size, 'p95Ms').toFixed(3)).join(' | ')} |`).join('\n');
const resourceRows = engines.map(e => `| ${names[e]} | ${(metric(e, 128, 'processMaxRssBytes') / 1048576).toFixed(2)} | ${metric(e, 128, 'processCpuSeconds').toFixed(3)} |`).join('\n');
const delayRows = [10, 50].map(delay => `| ${delay} ms × 2 | ${engines.map(e => metric(e, 128, 'p50Ms', delay).toFixed(3)).join(' | ')} |`).join('\n');
const workerValue = (engine, size, delay) => median(workers.results.filter(r => r.engine === engine && r.size === size && r.delayMsPerKmsCall === delay).map(r => r.averageRoundtripMs));
const workerRows = [[128, 0], [1024, 0], [16384, 0], [128, 10]].map(([size, delay]) =>
  `| ${size} B | ${delay} ms × 2 | ${workerValue('typescript', size, delay).toFixed(3)} | ${workerValue('rust-wasm', size, delay).toFixed(3)} |`).join('\n');
const artifacts = core.artifacts.map(a => `| ${a.path} | ${(a.bytes / 1024).toFixed(2)} | ${(a.gzipBytes / 1024).toFixed(2)} |`).join('\n');
const speedup = workerValue('typescript', 128, 0) / workerValue('rust-wasm', 128, 0);
const text = `# Rust / TypeScript POC 比較

Rust 可行。這份 POC 的 Rust 核心已成功編成原生 binary 與 Wasm；Rust / Wasm 與 TypeScript 都通過本機 workerd 驗證及 Wrangler deploy --dry-run。

對 128-byte API key，本機 workerd 的 Rust / Wasm handler 約為 TypeScript 的 ${speedup.toFixed(2)} 倍速度，但一次加密＋解密只差 ${(workerValue('typescript', 128, 0) - workerValue('rust-wasm', 128, 0)).toFixed(3)} ms。模擬每次 KMS 等待 10 ms 後，兩者都約 24 ms。這支持 Rust 核心的選擇，但不能推論正式服務會同比例加速或節省 Workers 費用。

建議 Strongroom 採 Rust 共用核心：Workers 用 Wasm + 薄 host，容器平台用原生 HTTP adapter。若第一版只針對 Workers，TypeScript 的建置流程與產物更簡單，效能也足以處理小型 API key；Rust 的主要額外價值是共用核心及原生部署的資源效率。下一個決策關卡是相同區域、真實 sandbox KMS 的端到端量測。

## 環境與方法

- 核心量測時間：${core.createdAt}。
- 機器：${core.cpu}，${core.arch} / ${core.platform}；Node ${core.versions.node}；${core.versions.rust}。
- Workers runtime：${workers.workerdVersion}，compatibility date 2026-07-01。
- 一次 roundtrip = encrypt + decrypt，包括 RNG、JSON、base64、每次產生新的 DEK，以及本機模擬的 wrap / unwrap；不是單獨 AES throughput。
- 每個情境重複三次。核心表是三次 run 的 p50 或 p95 中位數；workerd 表是三個 batch 平均值的中位數。兩種統計不能當成同一測試直接相除。
- Rust native 在 ARM 上啟用 aes_armv8 / polyval_armv8；Wasm 使用 portable RustCrypto；TypeScript 使用 runtime Web Crypto。沒有 DEK cache。

## 核心處理延遲

單位 ms，無人工 KMS 延遲，p50。TypeScript 與 Wasm 在 Node 執行；Rust native 是 CLI。

| 資料大小 | TypeScript | Rust / Wasm | Rust native |
|---|---:|---:|---:|
${coreRows}

p95，仍是三個 run 的中位數：

| 資料大小 | TypeScript | Rust / Wasm | Rust native |
|---|---:|---:|---:|
${p95Rows}

## 本機 workerd handler

單位 ms，batch 平均值的三次中位數。測試執行 Request/Response handler，**沒有 TCP / HTTP transport**。Workers 的時鐘在 I/O 邊界才前進，因此使用整批量測及最後一個 1 ms timer；timer 開銷包含在數值內。這不是逐請求 p50/p95，也不是正式 Cloudflare 的 CPU 計費時間。

| 資料大小 | 每次 KMS 的模擬等待 | TypeScript | Rust / Wasm |
|---|---|---:|---:|
${workerRows}

完整 loopback HTTP 壓測因 sandbox 禁止 listen 而未量測。保留 npm run bench:workers，可在允許本機 TCP 的環境執行，包括並行度 1 / 8。這次相容性與 handler 測試透過 workerd 自帶的無 socket test 入口完成。

## 原生與 Node 程序資源

128 B、1500 次量測＋100 次暖機；表格取三個程序的中位數。

| 程序 | 峰值 RSS（MiB） | 整個程序 CPU 秒數 |
|---|---:|---:|
${resourceRows}

RSS / CPU 包含 runtime、初始化與暖機。Rust CLI 沒有 HTTP server、TLS 或 KMS SDK；它的數字不是正式容器服務容量。Wasm 這列包含 Node / V8，不能將它解讀成 Workers isolate 的總記憶體或直接推估費用。Wasm linear memory 的原始數字另存 JSON，它只是總記憶體的一部分。

## 模擬 KMS 等待

128 B 的核心 roundtrip，p50，ms：

| 模擬等待 | TypeScript | Rust / Wasm | Rust native |
|---|---:|---:|---:|
${delayRows}

只有人工等待，沒有實際 KMS 呼叫。Rust native 使用 thread sleep、Node 使用 timer，在 macOS 上的喚醒精度不同；native 在這張表的差距不是網路效能結論。這些數字只能展示數十毫秒等待會淹沒數十微秒核心差距，不能作為雲端 KMS latency 預測。

## 產物大小

以下是 benchmark 使用的 minified bundle 與 binary，KiB：

| 產物 | 未壓縮 | gzip |
|---|---:|---:|
${artifacts}

Rust Worker 需要 JS host + Wasm，必須加總兩者；Web Crypto 本身位於宿主 runtime，不需要放進 TypeScript bundle。

另以兩份實際 Wrangler 設定進行 dry-run，Wrangler ${validation.wranglerDryRun.version} 回報：TypeScript 上傳 ${validation.wranglerDryRun.typescript.uploadKiB} KiB / gzip ${validation.wranglerDryRun.typescript.gzipKiB.toFixed(2)} KiB；Rust / Wasm 上傳 ${validation.wranglerDryRun.rustWasm.uploadKiB} KiB / gzip ${validation.wranglerDryRun.rustWasm.gzipKiB} KiB。Wrangler 預設建置與 benchmark 的 minification 不同，因此數字略異。兩者均成功打包，沒有發布。

## 驗證與尚未驗證

- 2 項 Rust 測試通過，包括 AES-256-GCM 標準向量。
- 17 項 Node 測試通過，包括九種交叉解密組合、邊界、context 與竄改拒絕。
- TypeScript typecheck 通過。
- 本機 workerd：雙向交叉解密、錯誤租戶 context、竄改密文拒絕通過。
- 兩份 Wrangler deploy --dry-run 通過。
- 沒有實際 Cloudflare 發布、cloud cold-start、CPU billing、Workers 總記憶體或容器平台部署測試。
- 沒有 AWS / Google / Vault / OpenBao 實際整合；KMS 模擬使用公開固定金鑰，POC 不能保護真實使用者 API key。
- Rust / Wasm 使用 JS host，不是完整 workers-rs 伺服器。原生 Rust 目前只有 CLI baseline。

原始資料：[核心](benchmark.json)、[workerd](workerd.json)、[HTTP 測試狀態](workers.json)、[驗證紀錄](validation.json)。重現指令及契約見 [README](../README.md)。
`;
writeFileSync('results/REPORT.md', text);
console.log('Wrote results/REPORT.md');
