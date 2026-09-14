# GitHub Action 使用指南

AgentWarden Action 在 CI 中扫描 Skill、Tool 和 MCP 配置，把结果写入 SARIF，并让存在风险的构建直接失败。

## 安装方式

GitHub Marketplace 发布后可直接从 Marketplace 添加。仓库内也可以显式引用：

```yaml
- uses: juangh123/AgentWarden@v0.3.1
```

版本选择建议：

| 引用方式 | 适用场景 |
| :--- | :--- |
| `@v0.3.1` | 推荐；版本固定，升级可控 |
| `@v0` | 自动接收兼容的 v0.x 修复；执行前应检查 Release Notes |
| `@<commit-sha>` | 高安全环境；最严格的可重复与防篡改方式 |

不要在受保护的生产仓库中长期使用 `@main`。

Action 直接从固定版本中运行 `src/cli.ts`，不执行 `npm install`，也不要求
`agentwarden-cli` 已发布到 npm。`node-version` 必须为 22.6 或更高版本。

## 最小示例

```yaml
name: Agent Skill Security

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: juangh123/AgentWarden@v0.3.1
        with:
          path: skills/
          profile: strict
          config: .agentwarden/policy.json
```

Action 以扫描退出码作为门禁：有阻断级发现时返回 `1`，参数或配置错误时返回 `2`。

## SARIF 与 Code Scanning

Action 默认把 SARIF 写入 `agentwarden-results.sarif`。若要上传到 GitHub Security Tab：

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7

  - name: Run AgentWarden
    uses: juangh123/AgentWarden@v0.3.1
    with:
      path: .
      profile: strict
      sarif: agentwarden.sarif

  - name: Upload SARIF
    if: always() && hashFiles('agentwarden.sarif') != ''
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: agentwarden.sarif
```

上传步骤使用 `if: always()`，这样即使扫描因风险失败，开发者仍能在 Security Tab 查看具体条目。

## 增量扫描

增量扫描可以避免大型仓库在每个 PR 上重复审计全部资产：

```yaml
- uses: actions/checkout@v7
  with:
    fetch-depth: 0

- uses: juangh123/AgentWarden@v0.3.1
  with:
    path: .
    changed: 'true'
    changed-from: ${{ github.event.pull_request.base.sha }}
```

`changed` 使用自动检测的 Git 基线，`changed-from` 使用显式 ref 或 commit SHA。GitHub checkout 必须包含比较所需的历史；增量模式下推荐 `fetch-depth: 0`。

## Baseline 与到期治理

对已经审核并接受的历史发现，可以保存稳定指纹基线，并强制所有例外在指定日期前重新检查：

```yaml
- uses: juangh123/AgentWarden@v0.3.1
  with:
    path: skills/
    baseline: .agentwarden-baseline.json
    baseline-status: 'true'
    baseline-expiring-within: '14'
    baseline-fail-on-expiring: 'true'
    baseline-fail-on-unmatched: 'true'
```

基线只保存稳定指纹和审核元数据，不保存原始敏感片段。`baseline-status` 要求同时提供 `baseline`。过期基线始终失败，不会永久静默豁免。

## 策略与规则覆盖

| 输入 | 作用 |
| :--- | :--- |
| `profile` | `legacy`、`balanced` 或 `strict` 策略档位 |
| `config` | 仓库内 JSON 策略文件，可继承或覆盖默认值 |
| `fail-on` | 显式覆盖失败严重级别 |
| `min-score` | 显式覆盖最低安全得分 |
| `include` / `exclude` | 换行分隔的路径 glob |
| `ignore-rules` | 换行分隔的规则 ID |
| `severity-overrides` | 换行分隔的 `RULE_ID=severity`，例如 `SEC-CRED-003=medium` |

推荐把策略文件提交到 `.agentwarden/policy.json`，让本地扫描和 CI 使用同一门禁。

## 安全建议

- 固定 Action 版本，生产环境优先使用 commit SHA。
- 只授予 `contents: read` 和必要的 `security-events: write`。
- 不要把 Token、私钥或完整敏感内容写入仓库策略、基线或 Issue。
- SARIF 和 JSON 默认脱敏；仅在受信任本地调试时使用 `--no-redact`。
- 对可信发布者启用 `publishers.requireSignature`、`trustedKeys` 和 `revokedKeys`。
