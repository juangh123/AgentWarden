# AgentWarden 冷启动执行清单

> 状态更新（2026-09-16）：`v0.3.2` GitHub Release 与 npm 首发均已完成，
> GitHub Action 已发布到
> [GitHub Marketplace](https://github.com/marketplace/actions/agentwarden-security-gate)，
> `npx agentwarden-cli@0.3.2` 也可用。本地发布门禁已复核：TypeScript 检查、
> 107 项单测、113 项端到端检查、安装包烟测和 19 项 MVP 验收全部通过；
> 在干净目录首次运行和恶意样例退出码 `1` 也已验证。npm 账号已启用 2FA，
> Trusted Publisher 已绑定 `juangh123/AgentWarden` 的 `release.yml`，后续
> tag 可通过 GitHub OIDC 自动发布 provenance。
>
> 如需绕过 npm，仍可从 GitHub 固定提交安装：
> `npm install --global "github:juangh123/AgentWarden#<commit-sha>"`。安装过程中会执行 `prepare` 构建 `dist/`，因此 `warden` / `agentwarden` 等命令可直接使用。

本清单用于当前公开版本的冷启动。目标不是制造安全能力的错觉，而是让开发者能在五分钟内完成一次扫描、看到明确退出码，并在 CI 中复用同一策略。

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
npm run test:mvp
```

`npm run test:mvp` 会生成并校验 `release/agentwarden-cli-<version>.tgz` 与
`release/SHA256SUMS`，再把 tarball 安装到干净目录并验证完整命令链。确认产物：

- 包名为 `agentwarden-cli`
- 版本与 `package.json` 一致
- 包含 `dist`、`README.md`、`LICENSE`
- 不包含仓库根目录的 `skills.lock`
- 四个命令别名均指向已安装的 `dist/cli.js`
- tarball 的 SHA-256 与 `SHA256SUMS` 一致

## npm 发布

包名 `agentwarden` 已被无关项目占用，禁止向该名称发布。本项目固定使用：

```text
agentwarden-cli
```

`agentwarden-cli@0.3.2` 首次发布已经完成。验证 registry 状态：

```bash
npm view agentwarden-cli@0.3.2 version dist.integrity
npx --yes agentwarden-cli@0.3.2 --version
```

首次 bootstrap 版本没有 provenance。GitHub Actions Trusted Publisher 已
通过 npm 官方 `trust` 命令完成配置：

- workflow：`release.yml`
- repository：`juangh123/AgentWarden`
- permissions：publish、stage publish

后续版本推送完整 tag 即可由 OIDC 发布，不再需要 `NPM_TOKEN`。

本地检查登录状态：

```bash
npm whoami
```

## GitHub Release

Release workflow 在 tag 推送后执行：

```bash
git switch main
git pull --ff-only
git tag -a v0.3.2 -m "AgentWarden v0.3.2"
git push origin v0.3.2
```

workflow 会再次验证 tag 与 package version 一致，校验 CI 产出的 tarball，
发布同一个已验收产物，并把 tarball 与 `SHA256SUMS` 附加到 GitHub Release。
发布后确认：

```bash
gh release view v0.3.2 --repo juangh123/AgentWarden
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

以下仓库侧设置已经完成：

- GitHub Discussions 已启用，用于承接用法问题
- Private vulnerability reporting 已启用
- `main` 已保护：8 项 CI 检查必须通过，禁止 force push 和删除
- Dependabot security updates 与 secret scanning push protection 已启用
- `v0.3.2` GitHub Release 已创建，并附带 tarball 与 `SHA256SUMS`
- GitHub Action 已发布为 `AgentWarden Security Gate`，主分类为 `Security`

仓库侧冷启动已无阻塞。接下来是首发内容分发、收集真实工作流反馈，并按周记录
首批指标。

## 首发内容

### 英文短帖

```text
AgentWarden v0.3.2 is available as agentwarden-cli.

It scans AI Agent Skills and MCP configurations before execution, locks reviewed
assets with SHA-256, verifies Ed25519 publisher provenance, emits redacted SARIF,
and exports CycloneDX SBOMs.

Try an intentionally unsafe example:
curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.2/examples/malicious-skill.md
npx agentwarden-cli@0.3.2 scan malicious-skill.md

It is a static gate, not a sandbox or a guarantee. Feedback and bypass reports
are welcome.
```

### 中文短帖

```text
AgentWarden v0.3.2 已发布，npm 包名为 agentwarden-cli。

它可在 Agent Skill / MCP 配置进入运行时前执行静态扫描，用 skills.lock 锁定
SHA-256 完整性，验证 Ed25519 发布者来源，并输出脱敏 SARIF 与 CycloneDX SBOM。

一条命令验证阻断行为：
curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.2/examples/malicious-skill.md
npx agentwarden-cli@0.3.2 scan malicious-skill.md

它是静态安全门禁，不是沙箱，也不承诺“零风险”。欢迎提交绕过案例和真实工作流反馈。
```

### 技术长帖结构

1. 真实问题：Skill 安装缺乏 package lock、provenance 和 CI 门禁。
2. 30 秒演示：安全样例返回 `0`，恶意样例返回 `1`。
3. 设计边界：静态规则负责早期阻断，签名和摘要负责来源与完整性。
4. CI 示例：GitHub Action 输出 SARIF 并上传 Security Tab。
5. 可复现结果：npm、Release、测试矩阵和 SBOM 样例链接。
6. 明确邀请：规则绕过、误报、MCP 格式和发布者策略反馈。

## 渠道账号状态

账号注册只是分发准备，不代表可以立即发帖。每个渠道都必须先完成邮箱验证、
阅读社区规则并积累正常参与记录。

| 渠道 | 公开账号 | 当前状态 | 下一门槛 |
| :--- | :--- | :--- | :--- |
| DEV | [`agentwarden`](https://dev.to/agentwarden) | 已注册并完成资料，公开主页已可访问，尚无文章 | 在 HN 首发之后准备 DEV 英文技术文章，由维护者本人复核并发布 |
| Discord | `agentwarden_cli` | 已注册 | 只加入 2 至 3 个 MCP、AI Agent 或 DevSecOps 社区；先参与讨论，不群发私信或立即贴链接 |
| Hacker News | `agentwarden` | 已注册，about 已完善，静置期已结束 | 按[事实清单](launch-hacker-news.md)由维护者本人撰写并发布 `Show HN`；不直接粘贴生成文本 |
| Reddit | [`u/Basic_Support_9438`](https://www.reddit.com/user/Basic_Support_9438/) | 已注册，公开主页已核对，2026-09-15 已在 `r/mcp` 发布首帖 | 监控并人工回复评论；不在多个社区重复投放；继续参与相关讨论后再扩展 |
| 掘金 | [`AgentWarden`](https://juejin.cn/user/252246275414937) | 已注册并完成资料；2026-09-16 发布中文长帖 | 监控阅读、收藏和评论；收到技术问题时由维护者本人回复 |
| V2EX | 待注册 | 注册页匿名请求返回 `403` | 在浏览器人工确认注册资格和邀请要求；在账号可用前暂缓 |
| 即刻 | 待注册 | 未注册，优先级低于掘金 | 掘金账号可用后再推进，按移动端社区习惯参与 |

不要把同一帖文在多个社区同时投放。公开帖子、评论、私信和主动邀请在提交前
都需要维护者本人确认；不请求点赞、评论或转发。
中文长帖在公开发布前由维护者本人复核；平台要求标注 AI 生成或辅助内容时，
按平台规则声明。

### 已发布渠道记录

| 日期 | 渠道 | 内容 | 状态 |
| :--- | :--- | :--- | :--- |
| 2026-09-15 | Reddit `r/mcp` | [AgentWarden: static security gate and integrity lock for MCP configs and agent skills](https://www.reddit.com/r/mcp/comments/1wh2kyb/agentwarden_static_security_gate_and_integrity/) | 公开可见；作者 `u/Basic_Support_9438`；等待真实评论和反馈 |
| 2026-09-16 | 掘金 `人工智能` | [Agent Skill 和 MCP 配置也需要安全门禁：从扫描到可验证的供应链](https://juejin.cn/post/7685966048847790114) | 公开可见；原创；9 月 19 日为阅读 12、点赞 1、收藏 1、评论 0 |

不要因为 Reddit 用户名与产品名不一致而创建重复账号。优先在现有账号的个人简介、
头像和后续正常参与中建立身份连续性。

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
| First-run success rate | `npx --yes agentwarden-cli@0.3.2 --version` 与首次扫描成功率 |
| Time to first blocked finding | 从打开 README 到得到退出码 `1` 的时间 |
| Action adoption | 引用 Action 的公开仓库数 |
| Issue conversion | 用法、误报和规则请求分别有多少 |
| Bypass reports | 可复现的安全规则绕过数量 |
| Package install failures | Linux / macOS / Windows 失败分布 |

North-star 指标不是 star 数，而是“成功执行扫描并接入第二次运行”的开发者数量。

### 2026-09-16 基线

| 指标 | 当前值 |
| :--- | :--- |
| Marketplace 状态 | 已发布，`Security` 分类 |
| GitHub 首发公告 | Discussion #21，1 条评论 |
| Stars / Watchers / Forks | 0 / 0 / 0 |
| Open Issues | 0 |
| GitHub Release 资产下载 | 0 |
| npm downloads | registry 尚未返回下载统计 |

该快照用于后续周度对比，不把短期互动量作为核心成功指标。

### 2026-09-19 快照

| 指标 | 当前值 |
| :--- | :--- |
| Stars / Watchers / Forks | 0 / 0 / 0 |
| Open Issues | 0 |
| GitHub Release 资产下载 | 0 |
| npm weekly downloads | 13（2026-09-12 至 2026-09-18） |
| DEV 主页 | 公开可访问；0 篇文章 |
| Reddit `r/mcp` | 公开可见；RSS 显示 0 条评论 |
| 掘金文章 | 阅读 12 / 点赞 1 / 收藏 1 / 评论 0 |
| Hacker News | 0 submissions / 0 comments；静置期已结束 |

第一周的主要信号是 npm 出现自然安装，以及掘金至少产生一次点赞和一次收藏。
GitHub Star、Fork 和 Release 下载仍未形成，下一阶段应继续争取可复现的
workflow 反馈，而不是追求一次性流量。

## 发布后 14 天

- 48 小时内修复安装失败、版本输出和 README 路径问题
- 一周内把高频误报整理成规则或策略改进，不在默认配置中静默忽略
- 为前三个真实使用仓库补充匿名案例
- 发布 `v0.3.x` patch，持续维护 `@v0` Action 标签
- 评估下一阶段优先级：更多 MCP 配置格式、规则证据质量、企业策略或运行时集成

## 外部依赖

仓库无法代替账号侧操作：

- npm 账号登录或 npm Trusted Publisher 配置
- GitHub Discussions、branch protection 和 Marketplace 后续版本维护
- 社区帖子发布与评论维护

仓库内的 Release workflow、发布文稿和验证入口已保持就绪；上述账号侧维护与
社区分发仍需维护者持续参与。
