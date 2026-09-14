# AgentWarden 冷启动执行清单

> 状态更新：`v0.3.1` 的 GitHub Action 已可不依赖 npm 包独立运行。npm 首次发布仍需配置短期 token 或 Trusted Publisher；本页其余内容保留为 v0.3.0 首发记录。

本清单用于 v0.3.0 首次公开发布。目标不是制造安全能力的错觉，而是让开发者能在五分钟内完成一次扫描、看到明确退出码，并在 CI 中复用同一策略。

## 当前定位

AgentWarden 是 AI Agent Skill / Tool / MCP 配置的静态安全门禁、完整性锁和发布者来源验证工具。当前能力包括：

- 静态扫描提示词注入、凭证访问、危险命令和数据外带模式
- 用 SHA-256 锁定单文件或多文件 Skill
- 用 Ed25519 签名和可信发布者策略验证来源
- 输出 Redacted JSON、SARIF 和 CycloneDX 1.5 SBOM
- 在 GitHub Action 中执行全量、增量或 baseline 扫描

当前不使用“完全防护”“保证安全”“万能 AI 防火墙”等表述。静态扫描会漏报，也可能误报；高风险执行仍需要最小权限、隔离运行和人工审核。

## 发布前检查

```bash
npm ci
npm run typecheck
npm test
npm run smoke
npm run test:package
npm pack --dry-run --json
```

确认 tarball：

- 包名为 `agentwarden-cli`
- 版本为 `0.3.0`
- 包含 `dist`、`README.md`、`LICENSE`
- 不包含仓库根目录的 `skills.lock`
- `agentwarden-cli --version` 输出 `agentwarden v0.3.0`

## npm 发布

包名 `agentwarden` 已被无关项目占用，禁止向该名称发布。本项目固定使用：

```text
agentwarden-cli
```

首次发布必须先把新包名写入 npm registry，Trusted Publisher 只能在包创建后配置。推荐使用短期 `NPM_TOKEN` 完成引导，由 GitHub Actions 生成 provenance：

```bash
gh variable set NPM_PUBLISH_ENABLED --repo juangh123/AgentWarden --body true
gh secret set NPM_TOKEN --repo juangh123/AgentWarden
gh run rerun <release-run-id> --repo juangh123/AgentWarden
```

`NPM_TOKEN` 应使用只对 `agentwarden-cli` 有写权限的 granular token。当前 `v0.3.0` Release run 的 ID 是 `34735455673`。

首次发布成功后，切换到 Trusted Publisher：

1. 在 npm 打开已创建的 `agentwarden-cli` 包设置。
2. 配置 Trusted Publisher：GitHub owner `juangh123`，repository `AgentWarden`，workflow `release.yml`。
3. 保留 GitHub Actions `id-token: write` 和仓库变量 `NPM_PUBLISH_ENABLED=true`。
4. 删除 `NPM_TOKEN`，后续版本推送完整 tag 即可由 OIDC 发布。

本地检查登录状态：

```bash
npm whoami
```

## GitHub Release

Release workflow 在 tag 推送后执行：

```bash
git switch main
git pull --ff-only
git tag -a v0.3.0 -m "AgentWarden v0.3.0"
git push origin v0.3.0
```

workflow 会再次验证 tag 与 package version 一致，然后创建 GitHub Release。发布后确认：

```bash
gh release view v0.3.0 --repo juangh123/AgentWarden
npm view agentwarden-cli version dist.integrity
```

## 仓库元数据

```bash
gh repo edit juangh123/AgentWarden \
  --description "Security gate, integrity lock, and provenance SBOM for AI Agent Skills and MCP tools" \
  --add-topic ai-security \
  --add-topic mcp-security \
  --add-topic prompt-injection \
  --add-topic supply-chain-security \
  --add-topic sbom \
  --add-topic cyclonedx \
  --add-topic codex-skills \
  --add-topic github-actions
```

建议同时完成：

- 启用 GitHub Discussions，承接用法问题而不污染 Issue
- 启用 Private vulnerability reporting
- 保护 `main`：要求 CI 通过，禁止 force push
- 创建 `v0.3.0` 的 GitHub Release，并把 `docs/release-notes-v0.3.0.md` 作为正文基础
- 确认 Action 在 Marketplace 元数据可见后发布为 Release

## 首发内容

### 英文短帖

```text
AgentWarden v0.3.0 is available as agentwarden-cli.

It scans AI Agent Skills and MCP configurations before execution, locks reviewed
assets with SHA-256, verifies Ed25519 publisher provenance, emits redacted SARIF,
and exports CycloneDX SBOMs.

Try an intentionally unsafe example:
curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.0/examples/malicious-skill.md
npx agentwarden-cli scan malicious-skill.md

It is a static gate, not a sandbox or a guarantee. Feedback and bypass reports
are welcome.
```

### 中文短帖

```text
AgentWarden v0.3.0 已发布，npm 包名为 agentwarden-cli。

它可在 Agent Skill / MCP 配置进入运行时前执行静态扫描，用 skills.lock 锁定
SHA-256 完整性，验证 Ed25519 发布者来源，并输出脱敏 SARIF 与 CycloneDX SBOM。

一条命令验证阻断行为：
curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.0/examples/malicious-skill.md
npx agentwarden-cli scan malicious-skill.md

它是静态安全门禁，不是沙箱，也不承诺“零风险”。欢迎提交绕过案例和真实工作流反馈。
```

### 技术长帖结构

1. 真实问题：Skill 安装缺乏 package lock、provenance 和 CI 门禁。
2. 30 秒演示：安全样例返回 `0`，恶意样例返回 `1`。
3. 设计边界：静态规则负责早期阻断，签名和摘要负责来源与完整性。
4. CI 示例：GitHub Action 输出 SARIF 并上传 Security Tab。
5. 可复现结果：npm、Release、测试矩阵和 SBOM 样例链接。
6. 明确邀请：规则绕过、误报、MCP 格式和发布者策略反馈。

## 目标社区

- MCP 与 Agent 工具开发者社区
- AI 安全、LLM 安全和提示词注入研究者
- DevSecOps、软件供应链与 SBOM 实践者
- GitHub Actions、Node.js CLI 和开源维护者社区
- Codex Skill、Agent Tool 和插件生态作者

不要在同一时间向大量社区重复投放同一内容。每个社区使用与其实际工作流相关的具体版本，并直接参与评论。

## 首批指标

按周记录：

| 指标 | 说明 |
| :--- | :--- |
| npm weekly downloads | 是否形成自然安装 |
| First-run success rate | `npx --yes agentwarden-cli --version` 与首次扫描成功率 |
| Time to first blocked finding | 从打开 README 到得到退出码 `1` 的时间 |
| Action adoption | 引用 Action 的公开仓库数 |
| Issue conversion | 用法、误报和规则请求分别有多少 |
| Bypass reports | 可复现的安全规则绕过数量 |
| Package install failures | Linux / macOS / Windows 失败分布 |

North-star 指标不是 star 数，而是“成功执行扫描并接入第二次运行”的开发者数量。

## 发布后 14 天

- 48 小时内修复安装失败、版本输出和 README 路径问题
- 一周内把高频误报整理成规则或策略改进，不在默认配置中静默忽略
- 为前三个真实使用仓库补充匿名案例
- 发布 `v0.3.x` patch，持续维护 `@v0` Action 标签
- 评估下一阶段优先级：更多 MCP 配置格式、规则证据质量、企业策略或运行时集成

## 外部依赖

仓库无法代替账号侧操作：

- npm 账号登录或 npm Trusted Publisher 配置
- GitHub Discussions、branch protection 和 Marketplace 发布确认
- 社区帖子发布与评论维护

在这些外部步骤完成前，仓库、Release workflow、发布文稿和验证入口都可以保持就绪。
