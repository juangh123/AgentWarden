# 🛡️ AgentWarden (formerly SkillGuard)

> **Zero-Dependency Security Package Manager & Audit CLI for Agent Skills (Codex, MCP, OpenAI Tools, etc.)**

AgentWarden（命令别名 `warden` / `agentwarden` / `skillguard`）是专为 AI Agent 技能生态（Skills / Tools）打造的企业级供应链安全与审计工具。它在 Skill 安装前执行静态安全扫描与提示词越狱审查，并通过 `skills.lock` 指纹锁定防范本地代码篡改与配置漂移。

---

## ✨ 核心特性

- ⚡ **零运行时依赖 (Zero Runtime Dependency)**：纯原生 Node.js 22+ 实现，开箱即用；TypeScript 仅作为开发依赖用于构建。
- 🔍 **多维度安全审计 (SAST & Prompt Injection)**：
  - 敏感凭证与密钥泄露检测（`~/.ssh`、`~/.aws`、API Key、环境变量、硬编码 Token、内嵌私钥）
  - 破坏性命令执行检测（`rm -rf`、反弹 Shell、无头脚本下载执行 `curl | sh`、`eval`/`base64 -d | bash` 解码执行链）
  - 提示词越狱检测（系统角色覆盖、Jailbreak 词库、编码混淆载荷）
  - 隐蔽数据偷放与反向链接识别（Raw IP 外带、webhook.site 等数据收集端点、本地文件上传）
- 🔒 **完整性指纹锁定 (`skills.lock`)**：类比 `package-lock.json`，记录 SHA-256 签名与安全得分，一键审计本地文件篡改；锁文件损坏或字段缺失会直接报错，不会静默降级为空。
- 📊 **企业级报告格式**：控制台彩色展示、**JSON** 导出以及 **SARIF 2.1.0**（可直接接入 GitHub Code Scanning / CI）。
- 🎛️ **策略化配置**：内置 `legacy` / `balanced` / `strict` 策略档位，支持配置继承、自定义 `failOn`、`minScore`、规则忽略清单与 `allowedDomains` 白名单。
- 🔎 **策略可观测性**：`policy` 命令展示最终生效配置，`policy diff` 可在升档或配置变更前生成结构化差异，JSON 输出可纳入审计流水线。
- 🧭 **统一资产发现**：目录扫描自动发现 Markdown Skills 与常见 MCP 配置，并可通过 `include` / `exclude` glob 精确限定审计范围。
- ⚡ **Git 增量扫描**：按 PR 或指定 Git ref 只审计实际变化的 Skill/MCP 文件，减少大型仓库的 CI 扫描时间。
- 🧱 **可审计基线**：用稳定指纹接受既有告警，支持责任人、审核备注和过期时间；过期后自动恢复阻断，基线不保存原始敏感片段。
- 🕶️ **默认安全报告**：JSON、SARIF 与终端输出自动隐藏密钥、认证头、私钥、敏感配置值和原始文件内容。
- 🧩 **规则治理**：查看完整规则目录，并按规则覆盖有效严重级别，无需修改源码或直接关闭规则。

---

## 🚀 快速上手

需要 Node.js ≥ 22.6。

```bash
# 安装开发依赖（构建与类型检查所需）
npm install

# 运行单元测试
npm test

# 构建发行产物（生成 dist/cli.js）
npm run build

# 端到端冒烟测试（构建 + CLI 全流程）
npm run smoke
```

## 📖 命令用法

```bash
# 扫描单个 Skill 文件或整个目录（支持多个路径）
node dist/cli.js scan fixtures/malicious-skill.md
node dist/cli.js scan fixtures/ --format sarif
node dist/cli.js scan . --json
node dist/cli.js scan a.md b.md --json
node dist/cli.js scan . --profile strict --include "skills/**" --exclude "skills/vendor/**"
node dist/cli.js scan . --changed --json
node dist/cli.js scan . --changed-from origin/main --json

# 以 JSON / SARIF 导出（适配 CI/CD 与 GitHub Code Scanning）
node dist/cli.js scan fixtures/ --sarif
node dist/cli.js scan fixtures/safe-skill.md --json

# 安装并锁定安全技能（存在高危风险将自动阻断安装）
node dist/cli.js install fixtures/safe-skill.md
node dist/cli.js install fixtures/safe-skill.md --force   # 跳过阻断，强制锁定

# 校验单个技能文件是否与 lockfile 匹配
node dist/cli.js verify fixtures/safe-skill.md

# 审计所有已安装技能的本地完整性，并按当前策略重新扫描
node dist/cli.js audit

# 查看已安装列表 / 卸载
node dist/cli.js list
node dist/cli.js uninstall safe-weather-reporter

# 查看规则与有效严重级别
node dist/cli.js rules
node dist/cli.js rules --json
node dist/cli.js scan skills/ --severity-override SEC-CRED-003=medium

# 查看最终生效策略与扫描范围
node dist/cli.js policy
node dist/cli.js policy --profile strict --include "skills/**" --json
node dist/cli.js policy --config .agentwarden/policy.json --json
node dist/cli.js policy diff legacy strict
node dist/cli.js policy diff current .agentwarden/policy.json --fail-on-diff --json
node dist/cli.js scan . --config .agentwarden/policy.json

# 生成或应用已接受发现的基线
node dist/cli.js baseline create skills/ --output .agentwarden-baseline.json
node dist/cli.js baseline create skills/ --owner security-platform --expires-in 30 --note "Migration tracked in SEC-142"
node dist/cli.js baseline status skills/ --baseline .agentwarden-baseline.json --json
node dist/cli.js baseline status skills/ --baseline .agentwarden-baseline.json --expiring-within 14 --fail-on-expiring --fail-on-unmatched
node dist/cli.js baseline prune skills/ --baseline .agentwarden-baseline.json --json
node dist/cli.js baseline prune skills/ --baseline .agentwarden-baseline.json --force
node dist/cli.js baseline update skills/ --baseline .agentwarden-baseline.json --force
node dist/cli.js scan skills/ --baseline .agentwarden-baseline.json

# 帮助与版本
node dist/cli.js help
node dist/cli.js --version
```

### 常用选项

| 选项 | 说明 |
| :--- | :--- |
| `-f, --force` | 跳过高危阻断，或确认写入基线的新建与维护变更 |
| `--format pretty\|json\|sarif` | 输出格式（也支持 `--json` / `--sarif` 简写） |
| `--config <file>` | 显式加载 JSON 策略文件；缺失或格式错误时退出码为 `2` |
| `--profile <name>` | 策略档位：`legacy`/`balanced`/`strict`（默认 `legacy`） |
| `--fail-on <sev>` | 判定失败的严重级别阈值：`critical`/`high`/`medium`/`low`/`info` |
| `--min-score <0-100>` | 最低安全得分 |
| `--ignore-rule <id>` | 跳过指定规则，可重复传入 |
| `--severity-override <rule=sev>` | 覆盖指定规则的有效严重级别，可重复传入 |
| `--include <glob>` | 将目录扫描限定到匹配路径，可重复传入 |
| `--exclude <glob>` | 从目录扫描中排除匹配路径，可重复传入 |
| `--changed` | 仅扫描相对自动检测 Git 基线发生变化的 Skill/MCP 文件 |
| `--changed-from <ref>` | 仅扫描相对指定 Git ref 或提交 SHA 发生变化的文件 |
| `--fail-on-diff` | `policy diff` 检测到差异时返回退出码 `1` |
| `--baseline <file>` | 仅抑制基线中精确匹配的既有发现 |
| `--output <file>` | `baseline` 命令输出路径（默认 `.agentwarden-baseline.json`） |
| `--owner <name>` | 基线责任人、团队或审核工单标识 |
| `--expires-in <days>` | 新建基线在指定天数后过期，范围 `1-3650` |
| `--expires-at <date>` | 使用 ISO 日期显式设置基线过期时间 |
| `--note <text>` | 保存简短审核备注，最多 500 字符 |
| `--expiring-within <days>` | `baseline status` 在基线剩余天数不超过该值时标记临近到期（默认 `30`） |
| `--fail-on-expiring` | `baseline status` 检测到临近到期时返回退出码 `1` |
| `--fail-on-unmatched` | `baseline status` 检测到未匹配项时返回退出码 `1` |
| `--dry-run` | 预览 `baseline prune/update` 的增删结果，不写入文件 |
| `--no-redact` | 在报告中保留原始片段和完整文件内容，仅用于受信任的本地调试 |
| `-C, --cwd <dir>` | 指定工作目录（lockfile 与相对路径均基于该目录解析） |
| `--no-color` | 关闭 ANSI 颜色（同时遵循 `NO_COLOR` 环境变量） |

### 退出码

| 退出码 | 含义 |
| :--- | :--- |
| `0` | 扫描通过 / 操作成功 |
| `1` | 存在安全风险（扫描未通过、校验篡改、当前策略失败、安装阻断） |
| `2` | 用法错误 / 文件不存在 / 非法参数 |

---

## ⚙️ 配置文件

在项目根目录放置 `.wardenrc.json / .skillguardrc.json`（或 `.skillguardrc` / `skillguard.config.json`）即可覆盖默认策略，也可以通过 `--config <file>` 显式指定：

```json
{
  "extends": "./base-security.json",
  "profile": "balanced",
  "failOn": "medium",
  "minScore": 75,
  "ignoreRules": ["SEC-INJ-002"],
  "allowedDomains": ["api.open-meteo.com", "company-internal.example"],
  "include": ["skills/**", "agents/**"],
  "exclude": ["skills/vendor/**", "**/fixtures/**"],
  "baseline": ".agentwarden-baseline.json",
  "severityOverrides": {
    "SEC-CRED-003": "medium"
  }
}
```

- `extends`：继承一个或多个父配置，字符串或字符串数组均可；路径相对于当前配置文件解析。数组按顺序合并，后面的父配置和当前文件中的标量字段优先。
- `profile`：策略档位。`legacy` 为 `failOn: high` / `minScore: 60`，`balanced` 为 `high` / `80`，`strict` 为 `medium` / `90`。
- `failOn`：命中该级别及以上的发现即判定失败。
- `minScore`：得分低于该值即失败（0-100，自动收敛）。
- `ignoreRules`：按规则 ID 忽略检测（例如误报豁免）。
- `allowedDomains`：网络类规则的域名白名单（含子域名匹配）；命中白名单的 URL 不会被 `SEC-EXFIL-002` 等外带规则标记。
- `include` / `exclude`：相对于工作目录的 glob，仅约束目录扫描；`exclude` 优先于 `include`。
- `baseline`：显式启用发现基线；不存在或格式损坏时会直接失败，不会静默忽略。
- `severityOverrides`：按规则 ID 调整有效严重级别；影响评分、失败阈值、基线和 SARIF 输出。

继承时 `ignoreRules`、`allowedDomains`、`include`、`exclude` 为追加合并，`severityOverrides` 按键合并，其他字段由子配置覆盖。缺失父配置或循环引用会终止加载；显式 `--config` 下返回退出码 `2`，隐式候选配置则继续兼容回退到默认策略。

命令行中的 `--profile` 会先采用该档位的默认阈值；仅当同时显式传入 `--fail-on` 或 `--min-score` 时，对应 CLI 值才会覆盖档位默认值。重复传入的 `--include` / `--exclude` 会追加到配置文件的路径范围内。

使用 `agentwarden policy --json` 可以检查合并配置文件、策略档位和 CLI 参数后的最终值，适合在 CI 中记录安全门禁的实际配置。

`policy --json` 的 `configSource` 字段会显示最终配置文件绝对路径，`configSources` 按父级到子级列出完整继承链；未加载配置文件时分别为 `null` 和空数组。显式传入的 `--config` 文件不存在、不是文件、JSON 根节点不是对象或继承关系损坏时会立即以退出码 `2` 失败。隐式发现候选文件时仍保持兼容行为：损坏文件会跳过并回退到 `legacy` 默认策略。

### 策略差异

使用 `policy diff <from> <to>` 比较两个最终生效策略。两侧均支持 `legacy` / `balanced` / `strict` 档位、`current`（当前工作目录配置与 CLI 覆盖），或任意显式 JSON 配置文件路径。

```bash
agentwarden policy diff legacy strict
agentwarden policy diff current .warden/policy.json --json
agentwarden policy diff current .warden/policy.json --fail-on-diff --json
```

差异覆盖档位、失败阈值、最低分、基线、允许域名、忽略规则、目录范围和规则严重级别覆盖。默认仅报告差异并返回 `0`；显式传入 `--fail-on-diff` 后，存在差异时返回 `1`，适合在策略变更 PR 中阻断未经审查的升级。

### 规则治理

使用 `agentwarden rules` 查看当前生效的规则目录。JSON 输出包含规则原始严重级别、有效严重级别、覆盖状态、忽略状态、说明和建议。

```bash
agentwarden rules --json
agentwarden scan skills/ --severity-override SEC-CRED-003=medium
```

严重级别覆盖会参与评分和 `failOn` 判断，因此修改级别或收敛基线前应经过代码审查。无效规则 ID 不会报错，但也不会出现在规则目录中；可通过 `rules --json` 检查目标规则是否显示 `overridden: true`，确认覆盖已实际生效。

配置文件非法或缺失字段时自动回退到 `legacy` 档位（`failOn: high`、`minScore: 60`），不会中断运行。

---

## 📋 规则体系

| 规则 ID | 类别 | 级别 | 描述 |
| :--- | :--- | :--- | :--- |
| `SEC-CRED-001` | 凭证安全 | CRITICAL | 访问私钥、SSH、AWS 等敏感本地文件 |
| `SEC-CRED-002` | 凭证安全 | CRITICAL | 脚本引用高特权环境变量密钥 |
| `SEC-CRED-003` | 凭证安全 | HIGH | 硬编码 API Token / 密钥（AWS AKIA、GitHub、OpenAI、Stripe、Slack、JWT 等） |
| `SEC-CRED-004` | 凭证安全 | CRITICAL | 内嵌完整私钥材料（SSH/RSA/EC/PGP） |
| `SEC-CMD-001` | 命令安全 | CRITICAL | 执行高危系统破坏指令（如 `rm -rf /`） |
| `SEC-CMD-002` | 命令安全 | HIGH | 动态脚本下载并执行（`curl \| bash`） |
| `SEC-CMD-003` | 命令安全 | HIGH | `eval` / `base64 -d \| bash` 等解码执行链 |
| `SEC-INJ-001` | 提示词安全 | CRITICAL | 间接提示词注入与系统角色覆盖 |
| `SEC-INJ-002` | 提示词安全 | HIGH | Jailbreak 词库 / 无限制模式请求 |
| `SEC-INJ-003` | 提示词安全 | MEDIUM | 编码 / 混淆载荷标记（atob、fromCharCode、hex 转义） |
| `SEC-EXFIL-001` | 网络安全 | CRITICAL | 异常数据外带或反弹连接尝试 |
| `SEC-EXFIL-002` | 网络安全 | HIGH | 数据收集端点（webhook.site 等）或本地文件上传外带 |
| `SEC-MCP-001` | MCP 配置 | CRITICAL | MCP Server 使用原始 shell、下载器或未固定版本包运行 |
| `SEC-MCP-002` | MCP 配置 | HIGH | MCP 配置在 `env` 中硬编码明文密钥 |
| `SEC-MCP-003` | MCP 配置 | HIGH | MCP JSON 无法解析或缺少有效 Server 映射 |
| `SEC-SUPPLY-001` | 供应链 | HIGH | 未校验哈希便下载并执行远程脚本 |
| `SEC-SUPPLY-002` | 供应链 | MEDIUM | 指向仿冒官方仓库或下载源的相似域名 |

目录扫描会跳过 `node_modules`、`dist`、`.git` 等构建/版本目录；除已列入白名单的 `.cursor`、`.vscode`、`.claude`、`.codex` 外，不会深入隐藏目录。`include` / `exclude` 只作用于目录发现，显式传入的文件无论扩展名或路径过滤规则如何都会被扫描。

`audit` 同时执行两层检查：锁文件 SHA-256 完整性，以及按当前配置重新扫描后的安全策略。即使用 `install --force` 锁定了高风险技能，只要内容未改但策略检查失败，`audit` 仍会返回退出码 `1`。

### 增量扫描

`scan --changed-from <ref>` 使用 Git 三方比较语义（`<ref>...HEAD`）计算提交变更，并合并当前工作区与未跟踪文件；删除或重命名前的旧路径不会进入扫描。`scan --changed` 会按 `AGENTWARDEN_BASE_REF`、`origin/$GITHUB_BASE_REF`、`$GITHUB_BASE_REF`、`HEAD~1` 的顺序选择可用基线。显式传入 `--changed-from` 时不会自动回退。

```bash
agentwarden scan . --changed --json
agentwarden scan . --changed-from origin/main --sarif
agentwarden scan skills/ --changed-from "$BASE_SHA" --include "skills/**"
```

变更集会与命令行路径、`include` 和 `exclude` 取交集，并只保留 Markdown Skill、MCP 配置或现有文件。没有相关变更时命令返回退出码 `0`，结构化报告中的 `totalScanned` 为 `0`。`baseline status` 和维护命令必须使用全量扫描范围，不接受 `--changed` / `--changed-from`，避免把范围外的基线条目误判为失效。

### 扫描基线

基线用于接受经过审查的既有发现，适合在已有大型 Skill 仓库中逐步接入安全门禁：

```bash
agentwarden baseline create skills/ --output .agentwarden-baseline.json
agentwarden baseline create skills/ --owner security-platform --expires-in 30 --note "SEC-142 migration"
agentwarden baseline status skills/ --baseline .agentwarden-baseline.json --json
agentwarden baseline prune skills/ --baseline .agentwarden-baseline.json
agentwarden baseline update skills/ --baseline .agentwarden-baseline.json --force
agentwarden scan skills/ --baseline .agentwarden-baseline.json
```

指纹由规则、类别、级别、规范化文件路径和规范化告警片段共同生成，因此普通行号移动不会导致基线失效，但规则内容、文件位置或匹配片段变化后必须重新审查。基线仅保存 SHA-256 指纹、规则 ID、文件、行号和级别，不保存原始敏感片段。

基线不会自动启用。必须通过 `--baseline <file>` 或配置项 `baseline` 显式指定；覆盖已有基线必须使用 `--force`。旧语法 `baseline [path...]` 仍然兼容，`baseline create [path...]` 是新语法的显式形式。

基线 v2 会在 `review` 中保存审核时间、`owner`、可选 `expiresAt` 和审核备注。超过 `expiresAt` 后，该基线不再抑制任何发现，所有当前告警重新进入策略判断，因此 CI 会自动恢复阻断。旧版 v1 基线仍可读取和应用，但不会过期。

`baseline status [path...]` 会重新扫描指定路径（默认当前目录），逐条报告基线匹配状态、接受时间、未匹配条目年龄，以及责任人、审核时间和到期状态。匹配基于稳定指纹：如果只扫描仓库子目录，基线中位于该扫描范围之外的条目会显示为 `unmatched`。基线已过期时命令返回退出码 `1`；`--fail-on-expiring` 和 `--fail-on-unmatched` 可分别把临近到期和未匹配项升级为 CI 失败。

`baseline prune [path...]` 只删除当前扫描中不再匹配的条目，适合代码删除、规则内容变化或扫描范围调整后的清理。`baseline update [path...]` 会执行同一清理，并把当前仍存在的发现重新接纳到基线；已有匹配条目的 `acceptedAt` 会保留，新条目使用本次维护时间。两个命令默认只输出预览，必须显式传入 `--force` 才会写回；`--dry-run` 可用于在强制模式下明确要求预览，两者不能同时使用。变更后的基线会更新 `reviewedAt`，并保留原有责任人、备注和到期时间；可通过 `--owner`、`--expires-in`、`--expires-at` 和 `--note` 在维护时同步更新审核元数据。旧版 v1 基线发生实际维护变更时会升级为 v2。

审核备注会原样写入基线文件，不应包含密钥、Token 或其他敏感数据。扫描和 status 报告只投影 `owner`、`expiresAt`、过期状态及条目元数据，不包含备注正文或原始敏感片段。v2 新建条目会记录 `acceptedAt` 并据此计算 `ageDays`，v1 基线没有接受时间时该字段为空。

### 报告脱敏

报告默认脱敏，避免安全扫描结果本身泄露凭证：

- API Key、GitHub/OpenAI/Slack/AWS/JWT 等常见 Token 会被替换为 `[REDACTED]`。
- `Authorization`、Bearer/Basic Token、URL 内嵌密码和敏感 key/value 会被隐藏。
- 私钥内容以及没有结束标记的私钥头会被替换。
- `rawContent`、`promptText` 和代码内容会经过脱敏后再进入 JSON/SARIF。

仅在受信任的本地调试环境下使用 `--no-redact`。CI 日志、Issue、SARIF 上传和共享终端输出不应关闭脱敏。

---

## 🔌 CI/CD 集成

### GitHub Actions（代码扫描）

```yaml
- name: SkillGuard Scan
  run: npm ci && npm run build && node dist/cli.js scan skills/ --sarif > skillguard.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skillguard.sarif
```

### 一般 CI（JSON + 退出码）

```bash
warden scan skills/ --json
echo "exit code: $?"   # 0=通过 1=存在风险 2=用法错误
```

本仓库已内置 `.github/workflows/ci.yml`，在 Node 22/24 上自动执行 typecheck、单测、构建与扫描冒烟测试。

---

## 🏗️ 开发说明

```text
src/
  cli.ts               CLI 入口与参数解析（命令、选项、退出码）
  baseline/            发现基线生成、校验、应用与稳定指纹
  git/                 Git 变更集解析与增量扫描范围
  scanner/             扫描编排与评分
  reporter/redaction.ts 报告脱敏与安全输出投影
  parser/              Markdown / Frontmatter 解析
  rules/               安全规则实现（credentials / commands / injection / exfiltration）
  manifest/            skills.lock 读写与路径解析
  config/              配置加载与校验
  reporter/            控制台 / JSON / SARIF 输出
scripts/
  clean.mjs            清理构建产物
  e2e-smoke.mjs        CLI 端到端冒烟测试
tests/                 单元测试（node:test，免框架）
fixtures/              安全 / 恶意 / 混淆 / 硬编码密钥样本
```

构建产物为真实编译的 CommonJS-free ESM JavaScript，`dist/cli.js` 直接可执行；源代码使用 Node 原生 TypeScript 支持，测试无需额外运行时。

## 📦 Programmatic SDK (Node.js & TypeScript)

AgentWarden also provides a fully-typed programmatic SDK for embedding security audits directly into your agent runtime or backend servers:

```typescript
import {
  POLICY_PROFILES,
  diffPolicyConfigs,
  scanSkillContent,
  scanSkillPaths,
  getChangedFiles,
  filterSkillFiles,
  createBaseline,
  applyBaseline,
  pruneBaseline,
  updateBaseline,
  buildSarifReport,
} from 'agentwarden';

// Scan arbitrary skill prompt or code in-memory
const result = scanSkillContent(`
\`\`\`bash
cat ~/.ssh/id_rsa
\`\`\`
`, 'virtual-skill.md');

console.log(result.passed); // false
console.log(result.findings);

// Discover and scan Markdown skills plus MCP JSON configs from disk
const results = scanSkillPaths('./skills', {
  profile: 'strict',
  include: ['skills/**'],
  exclude: ['skills/vendor/**'],
});
console.log(`Scanned ${results.length} assets`);
console.log(POLICY_PROFILES.strict); // { failOn: 'medium', minScore: 90 }

// Resolve an incremental scope for CI without shelling out yourself
const changed = getChangedFiles({ base: 'origin/main' });
const changedSkillFiles = filterSkillFiles(changed.files, process.cwd(), {
  include: ['skills/**'],
});
console.log(`${changedSkillFiles.length} changed skill files`);

// Compare effective policies before rolling a stricter gate into CI
const policyDelta = diffPolicyConfigs(POLICY_PROFILES.legacy, POLICY_PROFILES.strict);
console.log(policyDelta.changes);

// Build and apply a baseline in memory or persist it with writeBaseline()
const baseline = createBaseline(results, process.cwd(), {
  owner: 'security-platform',
  expiresAt: '2026-12-31T23:59:59.000Z',
  note: 'Temporary migration exemption',
});
const newResults = results.map((result) => applyBaseline(result, baseline));
const updated = updateBaseline(results, baseline, {
  owner: 'security-platform',
});
console.log(updated.summary);

// SARIF reports are redacted by default; pass { redact: false } only for trusted local tooling.
const sarif = buildSarifReport(newResults);
```

---

## 🤖 GitHub Action Integration

Add AgentWarden as a security gate in your CI/CD pipeline:

```yaml
- uses: actions/checkout@v5
  with:
    fetch-depth: 0

- name: Run AgentWarden Security Gate
  uses: juangh123/AgentWarden@main
  with:
    path: '.'
    config: '.agentwarden/policy.json'
    profile: 'strict'
    include: |
      skills/**
      agents/**
    exclude: |
      skills/vendor/**
    changed: 'true'
    changed-from: ${{ github.event.pull_request.base.sha }}
    baseline: '.agentwarden-baseline.json'
    baseline-status: 'true'
    baseline-expiring-within: '14'
    baseline-fail-on-expiring: 'true'
    baseline-fail-on-unmatched: 'true'
    ignore-rules: |
      SEC-INJ-002
    severity-overrides: |
      SEC-CRED-003=medium
    node-version: '22'
```

Action 的 `fail-on` 和 `min-score` 默认留空并使用 `profile`；显式设置时会覆盖档位默认值。`config` 可加载仓库中的策略文件，`include`、`exclude`、`ignore-rules` 和 `severity-overrides` 使用换行分隔。启用 `changed` / `changed-from` 前必须让 checkout 获取足够历史；PR 中推荐 `fetch-depth: 0`，或把 `github.event.pull_request.base.sha` 传给 `changed-from`。

设置 `baseline-status: 'true'` 后，Action 会先按全量配置范围执行基线状态检查，再运行增量扫描与 SARIF 输出；该选项要求同时提供 `baseline`。`baseline-expiring-within` 定义临近到期的提醒窗口（默认 `30` 天），`baseline-fail-on-expiring` 和 `baseline-fail-on-unmatched` 可分别让临近到期或未匹配条目阻断工作流。基线已过期时始终返回失败，避免过期豁免在 CI 中继续生效。

---

## 📄 License

MIT
