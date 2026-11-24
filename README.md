# SSRF 靜態檢查

三個套件與 GitHub Action 只讀你自己的原始碼，標出可能的 SSRF，並給修復建議。它們不會對任何網址送出請求。結果是啟發式判斷，需要人工確認。

檢查看的是這幾類寫法：

- 不可信輸入進到 HTTP client 的目的地。
- 只以少數字面主機名稱做封鎖。
- 用子字串比對 allowlist。
- 重新導向沒有再檢查目的地。
- 管理功能只因為連線來自 loopback 就放行。

修復方向是：使用者只傳 `productId` 或 `storeId`，由程式決定固定上游。若業務一定要收 URL，請嚴格解析、限制 scheme、對 host 做精確相等比對、檢查每個解析後的 IP，並對重新導向與重試套用同一政策。同時限制 egress，管理功能使用獨立認證。

## 套件

```bash
# Go
cd packages/go
go run ./cmd/ssrfscan --path ../.. --rules ../../rules/ssrf-rules.json --md-out ../../ssrf-report.md

# JavaScript / TypeScript
cd packages/js
npm ci && npm run build
node dist/cli.js --path ../.. --rules ../../rules/ssrf-rules.json --json-out ../../ssrf-report.json

# Rust
cargo run --manifest-path packages/rust/Cargo.toml -- \
  --path . --rules rules/ssrf-rules.json --json-out ssrf-report.json --md-out ssrf-report.md
```

共用規則在 [rules/ssrf-rules.json](rules/ssrf-rules.json)。報告格式見 [rules/report.schema.json](rules/report.schema.json)。

## GitHub Action

Action 沒有目標網址參數。呼叫端需要先 checkout。倉庫裡沒有的語言會略過。

```yaml
name: ssrf
on: [pull_request]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./
        with:
          path: .
          fail_on: high
```

`fail_on` 可以是 `high`、`medium` 或 `none`。報告會寫到 `ssrf-report.json`、`ssrf-report.md`，並上傳 artifact。

## 測試

```bash
cd packages/go && go test ./...
cd packages/js && npm ci && npm test
cd packages/rust && cargo test
```

`testdata` 與 `tests/fixtures` 裡有故意寫成有風險的範例。把整個倉庫掃進去時，這些範例會出現在報告裡。
