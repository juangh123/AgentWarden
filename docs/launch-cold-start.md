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
| DEV | [`agentwarden`](https://dev.to/agentwarden) | 已注册并完成资料；2026-09-19 发布英文长帖，公开主页现有 1 篇文章 | 监控阅读、收藏、评论和转发；收到技术问题时由维护者本人回复 |
| Discord | `agentwarden_cli` | 2026-09-20 已加入 MCP Contributor Discord 并完成规则确认；已加入 Model Context Protocol 社区并通过 MEE6 验证；已在 `showcase` 发布项目主题；OpenAI 验证受地区限制不可用 | MCP Contributor 只由维护者本人参与，不发送 AI 生成内容；监控 `showcase` 回复，不重复发帖 |
| Hacker News | `agentwarden` | 已注册，about 已完善；2026-09-23 确认 `Show HN` 限制已解除 | 建议维护者选择能够持续跟进的时段（推荐工作日 20:00 至 22:00 UTC+8）按[事实清单](launch-hacker-news.md)亲自撰写并提交，预留 2 至 3 小时互动 |
| Reddit | [`u/Basic_Support_9438`](https://www.reddit.com/user/Basic_Support_9438/) | 已注册，公开主页已核对，2026-09-15 已在 `r/mcp` 发布首帖 | 监控并人工回复评论；不在多个社区重复投放；继续参与相关讨论后再扩展 |
| 掘金 | [`AgentWarden`](https://juejin.cn/user/252246275414937) | 已注册并完成资料；2026-09-16 发布中文长帖；2026-09-23 增至 20 阅读、1 点赞、1 收藏 | 监控阅读、收藏和评论；收到技术问题时由维护者本人回复 |
| V2EX | 待发布 | 已就绪[分享创造草稿](launch-v2ex.md)与技术事实清单 | 维护者在浏览器登录可用账号后，按规范在 `create` 节点发布并亲自跟进回复 |
| 即刻 | 待注册 | 未注册，优先级低于掘金 | 掘金账号可用后再推进，按移动端社区习惯参与 |

### Discord 目标社区

| 优先级 | 社区 | 入口 | 参与状态与边界 |
| :--- | :--- | :--- | :--- |
| 1 | OpenAI 官方社区 | https://discord.gg/openai | 已在服务器列表中，但账号验证返回 `unsupported_country_region_territory`，当前不可参与 |
| 2 | MCP Contributor Discord | https://discord.gg/6CSzBmMkjX | 已加入并完成 onboarding。只参与 Security IG、Skills over MCP 或工具链讨论；服务器禁止 AI 生成消息和产品营销 |
| 3 | Model Context Protocol 社区 | https://discord.com/invite/model-context-protocol-1312302100125843476 | 已加入并通过 MEE6 验证；2026-09-20 在 `showcase` 发布 [AgentWarden](https://discord.com/channels/1312302100125843476/1544674994423074867/threads/1550914398879486072)，使用 `Security`、`CLI` 标签，当前 0 条消息 |

`showcase` 当前可用标签为 `Server`、`Client`、`Security`、`WebMCP`、`CLI`、
`Library`、`Experiment`。本次发布使用 `Security` 和 `CLI`。每个项目只保留
一个主题；后续补充分享时更新原主题，不重复发帖。

不要把同一帖文在多个社区同时投放。公开帖子、评论、私信和主动邀请在提交前
都需要维护者本人确认；不请求点赞、评论或转发。
中文长帖在公开发布前由维护者本人复核；平台要求标注 AI 生成或辅助内容时，
按平台规则声明。

### 已发布渠道记录

| 日期 | 渠道 | 内容 | 状态 |
| :--- | :--- | :--- | :--- |
| 2026-09-15 | Reddit `r/mcp` | [AgentWarden: static security gate and integrity lock for MCP configs and agent skills](https://www.reddit.com/r/mcp/comments/1wh2kyb/agentwarden_static_security_gate_and_integrity/) | 公开可见；作者 `u/Basic_Support_9438`；等待真实评论和反馈 |
| 2026-09-16 | 掘金 `人工智能` | [Agent Skill 和 MCP 配置也需要安全门禁：从扫描到可验证的供应链](https://juejin.cn/post/7685966048847790114) | 公开可见；原创；2026-09-23 为阅读 20、点赞 1、收藏 1、评论 0 |
| 2026-09-19 | DEV | [Agent Skills and MCP Configs Need a Security Gate](https://dev.to/agentwarden/agent-skills-and-mcp-configs-need-a-security-gate-cdf) | 公开可见；作者 `AgentWarden`；已标注 `AI-assisted`；封面、四个标签、正文和链接已核对 |
| 2026-09-20 | Discord `Model Context Protocol > showcase` | [AgentWarden: a static security gate for Agent Skills and MCP configs](https://discord.com/channels/1312302100125843476/1544674994423074867/threads/1550914398879486072) | 公开可见；作者 `AgentWarden`；已使用 `Security`、`CLI` 标签；等待真实评论和反馈 |

### 开源目录收录 PR

| 日期 | 目录 | 收录项 | 状态 |
| :--- | :--- | :--- | :--- |
| 2026-09-19 | [Awesome MCP Security](https://github.com/Puliczek/awesome-mcp-security) | [Tools and code](https://github.com/Puliczek/awesome-mcp-security/pull/334) | PR #334 开放；提交内容可合并，等待维护者审核 |
| 2026-09-19 | [Awesome MCP DevTools](https://github.com/punkpeye/awesome-mcp-devtools) | [Testing Tools](https://github.com/punkpeye/awesome-mcp-devtools/pull/338) | PR #338 开放；提交内容可合并，等待维护者确认分类和收录 |
| 2026-09-19 | [Awesome Agent Skills Security](https://github.com/LLMSecurity/awesome-agent-skills-security) | [Tools & Frameworks](https://github.com/LLMSecurity/awesome-agent-skills-security/pull/67) | PR #67 已于 2026-09-20 合并；项目已正式收录至 Tools & Frameworks 分类 |
| 2026-09-23 | [Awesome-MCP-ZH](https://github.com/yzfly/Awesome-MCP-ZH) | [🔒 安全与分析](https://github.com/yzfly/Awesome-MCP-ZH/pull/603) | PR #603 开放；中文核心 MCP 资源精选，分类与表格规范已对齐，等待审核 |

每条收录只提交一次，不催审、不要求点赞或转发。维护者提出格式、分类或事实修正时，
优先在原 PR 中处理；PR 合并后再按目录影响力评估是否需要补充发布记录。

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
| DEV 主页 | 公开可访问；1 篇文章 |
| Reddit `r/mcp` | 公开可见；RSS 显示 0 条评论 |
| 掘金文章 | 阅读 12 / 点赞 1 / 收藏 1 / 评论 0 |
| Hacker News | 0 submissions / 0 comments；站点临时限制 `Show HN`，暂停提交 |

第一周的主要信号是 npm 出现自然安装，以及掘金至少产生一次点赞和一次收藏。
GitHub Star、Fork 和 Release 下载仍未形成，下一阶段应继续争取可复现的
workflow 反馈，而不是追求一次性流量。

### 2026-09-23 首周快照（Day 7）

| 指标 | 当前值 |
| :--- | :--- |
| Stars / Watchers / Forks | 0 / 0 / 0 |
| Open Issues | 0 |
| GitHub Release 资产下载 | 0 |
| npm weekly downloads | 22（较 9-19 快照增加 9 次，增幅 69%；日均均有自然下载） |
| Awesome 权威目录收录 | 1/3 已正式合并收录（Awesome Agent Skills Security PR #67） |
| DEV 文章 | 公开可访问；1 篇文章，4 个标签（ai, security, opensource, devops） |
| Reddit `r/mcp` | 公开可见；RSS 显示 0 条评论 |
| 掘金文章 | 阅读 20 / 点赞 1 / 收藏 1 / 评论 0（阅读量较 9-19 增加 67%） |
| Discord 社区 | 2 个核心社区（MCP Contributor, Model Context Protocol）；`showcase` 专帖已发布 |
| Hacker News | 0 submissions / 0 comments；`Show HN` 限制已解除，建议准备发布 |

发布满 7 天（完整首周）核心进展分析：

1. **自然安装持续验证有效性**：npm 周下载由首周初的 11 次稳步提升至 22 次，表明已有开发者通过 `npx agentwarden-cli` 尝试运行或引入本地测试链。
2. **权威开源目录取得首个实质收录**：成功合并进 `Awesome Agent Skills Security`（PR #67，分类为 `Tools & Frameworks`），形成了首个被外部安全组织与生态背书的固定索引链接。
3. **多平台分发基础已搭建完成**：中英文渠道（Reddit、掘金、DEV、Discord）均已完成首发落地与信息铺垫，形成了统一的脱敏扫描、退出码与 CI 门禁心智。
4. **下一阶段核心突破点**：
   - **Hacker News `Show HN`**：HN 限制解除且当前 Agent/MCP 工具安全讨论热烈，维护者在晚间亲自发布 `Show HN` 是激发海外深度技术开发者试用与 Star 转化的最高杠杆动作。
   - **跟进剩余 2 个 Awesome PR**：持续关注 `awesome-mcp-security` #334 与 `awesome-mcp-devtools` #338 的合并动态。
   - **真实工作流接入案例**：针对实际场景（如 Claude Code / Cursor / Codex Skill 工具链或本地 MCP 网关）产出最小验证示例，推动首个外部仓库接入 GitHub Action 门禁。

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
