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
- 🎛️ **策略化配置**：内置 `legacy` / `balanced` / `strict` 策略档位，并支持自定义 `failOn`、`minScore`、规则忽略清单与 `allowedDomains` 白名单。
- 🔎 **策略可观测性**：`policy` 命令直接展示最终生效的配置来源、档位、阈值、基线、规则覆盖和目录范围，JSON 输出可纳入审计流水线。
- 🧭 **统一资产发现**：目录扫描自动发现 Markdown Skills 与常见 MCP 配置，并可通过 `include` / `exclude` glob 精确限定审计范围。
- 🧱 **可审计基线**：用稳定指纹接受既有告警，同时继续阻断新发现；基线不保存原始敏感片段。
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
node dist/cli.js scan . --config .agentwarden/policy.json

# 生成或应用已接受发现的基线
node dist/cli.js baseline skills/ --output .agentwarden-baseline.json
node dist/cli.js scan skills/ --baseline .agentwarden-baseline.json

# 帮助与版本
node dist/cli.js help
node dist/cli.js --version
```

### 常用选项

| 选项 | 说明 |
| :--- | :--- |
| `-f, --force` | 跳过高危阻断，强制写入 lockfile（仅 `install`） |
| `--format pretty\|json\|sarif` | 输出格式（也支持 `--json` / `--sarif` 简写） |
| `--config <file>` | 显式加载 JSON 策略文件；缺失或格式错误时退出码为 `2` |
| `--profile <name>` | 策略档位：`legacy`/`balanced`/`strict`（默认 `legacy`） |
| `--fail-on <sev>` | 判定失败的严重级别阈值：`critical`/`high`/`medium`/`low`/`info` |
| `--min-score <0-100>` | 最低安全得分 |
| `--ignore-rule <id>` | 跳过指定规则，可重复传入 |
| `--severity-override <rule=sev>` | 覆盖指定规则的有效严重级别，可重复传入 |
| `--include <glob>` | 将目录扫描限定到匹配路径，可重复传入 |
| `--exclude <glob>` | 从目录扫描中排除匹配路径，可重复传入 |
| `--baseline <file>` | 仅抑制基线中精确匹配的既有发现 |
| `--output <file>` | `baseline` 命令输出路径（默认 `.agentwarden-baseline.json`） |
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

- `profile`：策略档位。`legacy` 为 `failOn: high` / `minScore: 60`，`balanced` 为 `high` / `80`，`strict` 为 `medium` / `90`。
- `failOn`：命中该级别及以上的发现即判定失败。
- `minScore`：得分低于该值即失败（0-100，自动收敛）。
- `ignoreRules`：按规则 ID 忽略检测（例如误报豁免）。
- `allowedDomains`：网络类规则的域名白名单（含子域名匹配）；命中白名单的 URL 不会被 `SEC-EXFIL-002` 等外带规则标记。
- `include` / `exclude`：相对于工作目录的 glob，仅约束目录扫描；`exclude` 优先于 `include`。
- `baseline`：显式启用发现基线；不存在或格式损坏时会直接失败，不会静默忽略。
- `severityOverrides`：按规则 ID 调整有效严重级别；影响评分、失败阈值、基线和 SARIF 输出。

命令行中的 `--profile` 会先采用该档位的默认阈值；仅当同时显式传入 `--fail-on` 或 `--min-score` 时，对应 CLI 值才会覆盖档位默认值。重复传入的 `--include` / `--exclude` 会追加到配置文件的路径范围内。

使用 `agentwarden policy --json` 可以检查合并配置文件、策略档位和 CLI 参数后的最终值，适合在 CI 中记录安全门禁的实际配置。

`policy --json` 的 `configSource` 字段会显示实际加载的配置文件绝对路径；未加载配置文件时为 `null`。显式传入的 `--config` 文件不存在、不是文件或 JSON 根节点不是对象时会立即以退出码 `2` 失败。隐式发现候选文件时仍保持兼容行为：损坏文件会跳过并回退到 `legacy` 默认策略。

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

### 扫描基线

基线用于接受经过审查的既有发现，适合在已有大型 Skill 仓库中逐步接入安全门禁：

```bash
agentwarden baseline skills/ --output .agentwarden-baseline.json
agentwarden scan skills/ --baseline .agentwarden-baseline.json
```

指纹由规则、类别、级别、规范化文件路径和规范化告警片段共同生成，因此普通行号移动不会导致基线失效，但规则内容、文件位置或匹配片段变化后必须重新审查。基线仅保存 SHA-256 指纹、规则 ID、文件、行号和级别，不保存原始敏感片段。

基线不会自动启用。必须通过 `--baseline <file>` 或配置项 `baseline` 显式指定；覆盖已有基线必须使用 `--force`。

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
  scanSkillContent,
  scanSkillPaths,
  createBaseline,
  applyBaseline,
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

// Build and apply a baseline in memory or persist it with writeBaseline()
const baseline = createBaseline(results);
const newResults = results.map((result) => applyBaseline(result, baseline));

// SARIF reports are redacted by default; pass { redact: false } only for trusted local tooling.
const sarif = buildSarifReport(newResults);
```

---

## 🤖 GitHub Action Integration

Add AgentWarden as a security gate in your CI/CD pipeline:

```yaml
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
    baseline: '.agentwarden-baseline.json'
    ignore-rules: |
      SEC-INJ-002
    severity-overrides: |
      SEC-CRED-003=medium
    node-version: '22'
```

Action 的 `fail-on` 和 `min-score` 默认留空并使用 `profile`；显式设置时会覆盖档位默认值。`config` 可加载仓库中的策略文件，`include`、`exclude`、`ignore-rules` 和 `severity-overrides` 使用换行分隔。

---

## 📄 License

MIT
