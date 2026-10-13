# Strongroom

以 managed KMS 保護使用者提供的 API key。你的資料庫只儲存加密 envelope，需要呼叫第三方服務時，才透過授權的 Strongroom 服務解密。

目前為 **0.1.0-alpha.1 開發版**。Rust 負責 AES-256-GCM 與密文格式，Cloudflare Workers 優先；容器使用 Node 24 host 執行同一份 Rust Wasm 和 HTTP handler。npm 公開版本仍是佔名用的 `0.0.0`；以下指令使用本地建置，不會發布或部署。

- KMS：AWS KMS、Google Cloud KMS、Vault、OpenBao Transit。
- HTTP：`POST /v1/encrypt`、`POST /v1/decrypt`，固定 tenant、操作與 key 授權。
- Agent 介面：TypeScript SDK、JSON CLI、OpenAPI 3.1、離線 JSON Schema、明確錯誤碼與 retryable 欄位。
- 部署：Workers、Docker、Cloud Run／GKE、AWS ECS／App Runner、Render、Railway。

## 本機啟動

需要 Node 24、Rust 1.98.1、Wasm target 與 wasm-bindgen CLI 0.2.105。

```sh
rustup toolchain install 1.98.1 --profile minimal --target wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.105 --locked
npm ci
npm run build
npm run dev:init
npm run dev
```

`dev:init` 建立 `.strongroom/`，使用 CSPRNG 產生本機 KEK 和 API token；目錄權限 0700、檔案 0600，不覆寫既有設定。`dev` 在 `127.0.0.1:8787` 啟動真正的 workerd，TypeScript 修改後自動重建並 reload。Rust 修改後執行 `npm run build` 並重啟 dev。Node host 可用 `npm run dev:node` 啟動。

另一個終端執行完整 SDK 範例：

```sh
node --env-file=.strongroom/client.env examples/byok.mjs
```

或讓 agent 先讀取 schema，再透過 stdin 使用 CLI：

```sh
node packages/strongroom/dist/cli.js schema encrypt
printf '%s' '{"key":"primary","plaintext":"demo-api-key","context":{"tenantId":"development","recordId":"user-123/openai","purpose":"provider-api-key"}}' |
  node --env-file=.strongroom/client.env packages/strongroom/dist/cli.js encrypt --output .strongroom/envelope.json
```

明文、token 不需要出現在 CLI flags。`--output` 建立 0600 檔案並拒絕覆寫；不指定時輸出單一 JSON 到 stdout。錯誤輸出單一 JSON 到 stderr，以 exit code 區分輸入、授權、拒絕及暫時性失敗。

## 應用程式整合

```ts
import { Strongroom } from 'strongroom'; // 使用本地 npm pack 產生的套件

const strongroom = new Strongroom({
  url: process.env.STRONGROOM_URL!,
  token: process.env.STRONGROOM_TOKEN!,
});
const context = {
  tenantId: authenticatedTenant.id,
  recordId: credential.id,
  purpose: 'provider-api-key',
};
const envelope = await strongroom.encrypt({ key: 'primary', plaintext: userSuppliedApiKey, context });
await database.credentials.update(credential.id, { envelope });

// 使用時重新從可信的授權資料建立 context。
const stored = await database.credentials.find(credential.id);
const apiKey = await strongroom.decrypt({ envelope: stored.envelope, context });
// 將 apiKey 傳給第三方 API；不要記錄到 log。
```

一個 Strongroom token 綁定一個 tenant。你的應用仍須驗證使用者是否能存取指定 credential。Context 不是密碼，也不是授權替代品；不要把 API key 放進 context。

## 開發與驗證

```sh
npm run verify           # build、TypeScript、Rust tests、service/SDK/CLI/runtime tests、coverage gate
npm run test:fast        # 初次 build 後的快速測試
npm run build:host       # 只重建 HTTP host 與 SDK/CLI
npm run deploy:check     # Wrangler dry-run，不部署
npm run test:package     # 真正打包、安裝並驗證 SDK types 與 CLI
TRANSIT_BIN=/path/to/bao npm run test:transit
```

Coverage gate：共享 service 與 SDK／CLI 的 lines、statements、functions ≥90%，branches ≥80%。Rust 使用獨立測試；Workers／Node host 用實際 runtime 與 loopback HTTP 驗證，不灌入共享程式碼的 coverage 百分比。

本機已驗證 OpenBao 2.7.1 的真實 Transit roundtrip、context 拒絕、金鑰輪替與 token 撤銷。AWS／GCP 目前是協定測試，尚未用雲端帳戶驗證。Docker daemon 在目前環境未啟動，因此本機未完成 image build；CI 會執行 Docker build。

詳細文件：[架構](docs/architecture.md)、[設定](docs/configuration.md)、[部署](docs/deployment.md)、[安全邊界](docs/security.md)、[Agent 使用指南](docs/agents.md)。歷史 POC 保留在 `poc/` 與 [benchmark 報告](results/REPORT.md)，其固定 mock key 與密文格式不相容於正式核心。
