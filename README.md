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
- 🔒 **完整性指纹锁定 (`skills.lock`)**：类比 `package-lock.json`，记录 SHA-256 签名与安全得分，一键审计本地文件篡改。
- 📊 **企业级报告格式**：控制台彩色展示、**JSON** 导出以及 **SARIF 2.1.0**（可直接接入 GitHub Code Scanning / CI）。
- 🎛️ **策略化配置**：`.wardenrc.json / .skillguardrc.json` 支持 `failOn` 阈值、`minScore`、规则忽略清单与 `allowedDomains` 白名单。

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
node dist/cli.js scan a.md b.md --json

# 以 JSON / SARIF 导出（适配 CI/CD 与 GitHub Code Scanning）
node dist/cli.js scan fixtures/ --sarif
node dist/cli.js scan fixtures/safe-skill.md --json

# 安装并锁定安全技能（存在高危风险将自动阻断安装）
node dist/cli.js install fixtures/safe-skill.md
node dist/cli.js install fixtures/safe-skill.md --force   # 跳过阻断，强制锁定

# 校验单个技能文件是否与 lockfile 匹配
node dist/cli.js verify fixtures/safe-skill.md

# 全局审计所有已安装技能的本地完整性
node dist/cli.js audit

# 查看已安装列表 / 卸载
node dist/cli.js list
node dist/cli.js uninstall safe-weather-reporter

# 帮助与版本
node dist/cli.js help
node dist/cli.js --version
```

### 常用选项

| 选项 | 说明 |
| :--- | :--- |
| `-f, --force` | 跳过高危阻断，强制写入 lockfile（仅 `install`） |
| `--format pretty\|json\|sarif` | 输出格式（也支持 `--json` / `--sarif` 简写） |
| `--fail-on <sev>` | 判定失败的严重级别阈值：`critical`/`high`/`medium`/`low`/`info`（默认 `high`） |
| `--min-score <0-100>` | 最低安全得分（默认 `60`） |
| `--ignore-rule <id>` | 跳过指定规则，可重复传入 |
| `-C, --cwd <dir>` | 指定工作目录（lockfile 与相对路径均基于该目录解析） |
| `--no-color` | 关闭 ANSI 颜色（同时遵循 `NO_COLOR` 环境变量） |

### 退出码

| 退出码 | 含义 |
| :--- | :--- |
| `0` | 扫描通过 / 操作成功 |
| `1` | 存在安全风险（扫描未通过、校验篡改、安装阻断） |
| `2` | 用法错误 / 文件不存在 / 非法参数 |

---

## ⚙️ 配置文件

在项目根目录放置 `.wardenrc.json / .skillguardrc.json`（或 `.skillguardrc` / `skillguard.config.json`）即可覆盖默认策略：

```json
{
  "failOn": "medium",
  "minScore": 75,
  "ignoreRules": ["SEC-INJ-002"],
  "allowedDomains": ["api.open-meteo.com", "company-internal.example"]
}
```

- `failOn`：命中该级别及以上的发现即判定失败。
- `minScore`：得分低于该值即失败（0-100，自动收敛）。
- `ignoreRules`：按规则 ID 忽略检测（例如误报豁免）。
- `allowedDomains`：网络类规则的域名白名单（含子域名匹配）；命中白名单的 URL 不会被 `SEC-EXFIL-002` 等外带规则标记。

配置文件非法或缺失字段时自动回退到默认值（`failOn: high`、`minScore: 60`），不会中断运行。

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
  scanner/             扫描编排与评分
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

## 📄 License

MIT
