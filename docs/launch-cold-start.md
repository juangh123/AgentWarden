# AgentWarden 冷启动执行清单

> 状态更新（2026-09-29）：`v0.3.4` 已正式发布。GitHub Release 与 npm
> `agentwarden-cli@0.3.4` 均已上线，provenance 由 Trusted Publisher 通过 OIDC 生成。
> 发布验收过程中发现并修复了一处发布产物完整性问题：仓库内提交的 tarball 与 CI
> 实际发布的字节不一致，根因是 Windows CRLF 检出与 Linux CI 的换行差异；现在
> Release workflow 校验并发布仓库内已提交的同一份产物，并新增 `npm run test:release`
> 发布门禁。本轮本地门禁：TypeScript、132/132 单测、127/127 端到端检查、20/20 MVP
> 打包验收通过；新增的发布产物验收校验仓库产物与校验值一致、可安装可用，并在
> 发布提交上与源码内容一致。
> 状态更新（2026-09-27）：当前公开版本仍为 `v0.3.3`，`v0.3.4` 发布候选已在
> `codex/release-v0.3.4` 分支准备，用于交付外部社区反馈驱动的 `policy guard`。
> npm 最近一周下载出现 183 次的短时增长，其中 2026-09-24 单日 138 次；由于
> Stars、Issue、评论和外部接入尚未同步增长，这批下载暂按发布与验证脉冲记录，
> 不能等同于持续采用。公开发布仍需推送 `v0.3.4` tag，由 Trusted Publisher
> 完成 npm provenance 与 GitHub Release。本地发布门禁已复核：TypeScript、
> 132/132 单测、127/127 端到端检查、安装包烟测和 20/20 MVP 验收全部通过。
>
> 状态更新（2026-09-24）：`v0.3.3` GitHub Release 与 npm 发布均已完成，
> GitHub Action 已发布到
> [GitHub Marketplace](https://github.com/marketplace/actions/agentwarden-security-gate)，
> `npx agentwarden-cli@0.3.3` 也可用。本地发布门禁已复核：TypeScript 检查、
> 128 项单测、121 项端到端检查、安装包烟测和 20 项 MVP 验收全部通过；
> 在仓库外干净目录验证版本号、安全样例退出码 `0`、恶意样例退出码 `1`，
> GitHub Release tarball 的 SHA-256 与 `SHA256SUMS` 一致。npm 账号已启用 2FA，
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
npm run test:release
```

`npm run test:mvp` 会生成并校验 `release/agentwarden-cli-<version>.tgz` 与
`release/SHA256SUMS`，再把 tarball 安装到干净目录并验证完整命令链。发布分支必须
一并提交重新生成的这两份文件。`npm run test:release` 校验仓库内已提交的产物与
`SHA256SUMS` 一致、可安装可用，并与当前源码重新打包出来的文件内容一致；Release
workflow 发布的就是这份已提交产物，不再在 runner 上重新打包，所以该检查只在发布
提交上必须全绿。确认产物：

> 验证已发布包时，必须在仓库目录之外的干净目录执行 `npx`。在包自身的仓库里
> 运行时，`npx` 会把请求解析到本地同名同版本包，出现
> `'agentwarden-cli' is not recognized` 之类与发布无关的假失败。

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

`agentwarden-cli@0.3.4` 是当前公开版本，发布于 2026-09-29。
发布完成后验证 registry 状态：

```bash
npm view agentwarden-cli@0.3.4 version dist.integrity
npx --yes agentwarden-cli@0.3.4 --version
```

最初的 bootstrap 版本 `0.3.2` 没有 provenance。GitHub Actions Trusted
Publisher 已通过 npm 官方 `trust` 命令完成配置：

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
git tag -a v0.3.4 -m "AgentWarden v0.3.4"
git push origin v0.3.4
```

workflow 会再次验证 tag 与 package version 一致，校验 CI 产出的 tarball，
发布同一个已验收产物，并把 tarball 与 `SHA256SUMS` 附加到 GitHub Release。
发布后确认：

```bash
gh release view v0.3.4 --repo juangh123/AgentWarden
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
- `v0.3.3` GitHub Release 已创建，并附带 tarball 与 `SHA256SUMS`
- GitHub Action 已发布为 `AgentWarden Security Gate`，主分类为 `Security`

仓库侧冷启动已无阻塞。接下来是首发内容分发、收集真实工作流反馈，并按周记录
首批指标。

## 首发内容

### 英文短帖

```text
AgentWarden v0.3.4 is available as agentwarden-cli.

It scans AI Agent Skills and MCP configurations before execution, locks reviewed
assets with SHA-256, verifies Ed25519 publisher provenance, emits redacted SARIF,
and exports CycloneDX SBOMs.

Try an intentionally unsafe example:
curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.4/examples/malicious-skill.md
npx agentwarden-cli@0.3.4 scan malicious-skill.md

It is a static gate, not a sandbox or a guarantee. Feedback and bypass reports
are welcome.
```

### 中文短帖

```text
AgentWarden v0.3.4 已发布，npm 包名为 agentwarden-cli。

它可在 Agent Skill / MCP 配置进入运行时前执行静态扫描，用 skills.lock 锁定
SHA-256 完整性，验证 Ed25519 发布者来源，并输出脱敏 SARIF 与 CycloneDX SBOM。

一条命令验证阻断行为：
curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.4/examples/malicious-skill.md
npx agentwarden-cli@0.3.4 scan malicious-skill.md

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
| First-run success rate | `npx --yes agentwarden-cli@0.3.4 --version` 与首次扫描成功率 |
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
| GitHub 首发公告 | Discussion #21（Day 9 为 2 条评论） |
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

同日复核的首发链路（Windows，干净临时目录）：

| 检查项 | 结果 |
| :--- | :--- |
| `npx --yes agentwarden-cli@0.3.2 --version` | 输出 `agentwarden v0.3.2`，退出码 `0` |
| `npx --yes agentwarden-cli@0.3.2 scan safe-skill.md` | 退出码 `0` |
| `npx --yes agentwarden-cli@0.3.2 scan malicious-skill.md` | 命中 5 条 CRITICAL，安全分 `0/100`，退出码 `1` |
| 示例链接 | `raw.githubusercontent.com/.../v0.3.2/examples/*.md` 均可下载 |

发布满 7 天（完整首周）核心进展分析：

1. **自然安装持续验证有效性**：npm 周下载由首周初的 11 次稳步提升至 22 次，表明已有开发者通过 `npx agentwarden-cli` 尝试运行或引入本地测试链。
2. **权威开源目录取得首个实质收录**：成功合并进 `Awesome Agent Skills Security`（PR #67，分类为 `Tools & Frameworks`），形成了首个被外部安全组织与生态背书的固定索引链接。
3. **多平台分发基础已搭建完成**：中英文渠道（Reddit、掘金、DEV、Discord）均已完成首发落地与信息铺垫，形成了统一的脱敏扫描、退出码与 CI 门禁心智。
4. **下一阶段核心突破点**：
   - **Hacker News `Show HN`**：HN 限制解除且当前 Agent/MCP 工具安全讨论热烈，维护者在晚间亲自发布 `Show HN` 是激发海外深度技术开发者试用与 Star 转化的最高杠杆动作。
   - **跟进剩余 2 个 Awesome PR**：持续关注 `awesome-mcp-security` #334 与 `awesome-mcp-devtools` #338 的合并动态。
   - **真实工作流接入案例**：已补充可复制的最小下游示例
     `examples/github-action-project`，并由 CI 通过本地 Action 实际执行；下一步推动首个外部仓库接入。

同日完成首轮产品迭代，回应最常见的“配置格式是否覆盖”问题：

- PR #44 增加 Cursor、VS Code、Copilot、Windsurf、Cline、Roo Code、Continue、Zed、Gemini、Qwen 和 Dev Container 的常见 MCP 配置位置，并支持 `mcp.servers`、`context_servers`、`customizations.vscode.mcp.servers`。
- PR #45 增加 Claude Code `~/.claude.json` 的用户级 `mcpServers` 与项目级 `projects.*.mcpServers` 扫描，并对同名 Server 保留独立条目。
- 两项改动均只扩展静态 JSON 发现与解析边界，不改变“不执行目标 Skill 或 MCP Server”的能力边界。

同日继续完成第二轮扫描与发布链路加固：

- PR #46 修正 `--profile` 帮助文本与 profile 默认值说明，并增加 smoke 回归，避免文档与 CLI 行为再次漂移。
- PR #47 修复 MCP Server 名为 `__proto__` 时被解析器丢弃、绝对路径 shell/downloader 绕过、scoped 包与 `@latest` 被误判为已固定版本，以及畸形 `.claude.json` 在目录扫描中 fail-open 的问题。
- PR #47 新增 `SEC-MCP-004`，检查远程 MCP 的 HTTP、无效 URL 和 URL 内嵌凭据；`SEC-MCP-002` 同时覆盖 `headers` 中的明文秘密。
- PR #47 还修复 Windows 原子替换失败时可能丢失旧文件、供应链规则行号偏移、SARIF schema 失效和 artifact URI 未编码的问题。
- 上述修复通过 124 项单元测试、114/114 端到端烟测、包安装烟测、19/19 MVP 打包验收，以及 Linux、Windows、macOS 三平台 CI。

### 2026-09-24 Day 8 快照

| 指标 | 当前值 |
| :--- | :--- |
| Stars / Watchers / Forks | 0 / 0 / 0 |
| 本仓库 Open Issues / Open PRs | 0 / 0 |
| GitHub Release 资产下载 | 0 |
| npm weekly downloads | 22（2026-09-15 至 2026-09-21，与 Day 7 快照相同） |
| npm 日粒度下载 | registry 在 2026-09-22 至 2026-09-24 暂记为 0；统计窗口尚未完整结算，不据此判断下降 |
| GitHub 仓库流量 | 近 14 天 27 次浏览 / 22 个独立访客（截至 2026-09-23） |
| Awesome 权威目录收录 | 1/4 已合并；`awesome-mcp-security` #334、`awesome-mcp-devtools` #338、`Awesome-MCP-ZH` #603 仍待审核 |
| DEV 文章 | 0 个公开反应 / 0 条评论 |
| Reddit `r/mcp` | RSS 显示 0 条评论 |
| 掘金文章 | 沿用 2026-09-23 可核验值：阅读 20 / 点赞 1 / 收藏 1 / 评论 0 |
| Hacker News | 0 submissions / 0 comments；账号自 2026-09-23 起已具备 `Show HN` 发布条件 |

2026-09-24 发布前复核的发布链路（Windows，仓库外临时目录）：

| 检查项 | 结果 |
| :--- | :--- |
| TypeScript 检查 | 通过 |
| 单元测试 | 124/124 通过 |
| 端到端烟测 | 114/114 通过 |
| npm tarball 安装烟测 | 通过 |
| MVP 打包验收 | 19/19 通过 |
| `npx --yes agentwarden-cli@0.3.2 --version` | 输出 `agentwarden v0.3.2`，退出码 `0` |
| 安全样例扫描 | 退出码 `0` |
| 恶意样例扫描 | 命中 5 条 CRITICAL，安全分 `0/100`，退出码 `1` |
| GitHub Release 附件 | 下载后 SHA-256 为 `e6038f16...a05d596`，与 `release/SHA256SUMS` 一致 |

Day 8 没有出现需要紧急发布补丁的新安装失败或安全反馈。主要瓶颈仍是分发而非
工程质量：HN 首发和 V2EX 发布依赖维护者本人撰写、提交并持续互动。今天
19:20（UTC+8）已进入 HN 建议发布窗口；若维护者能预留 2 至 3 小时亲自跟进，
应优先完成 `Show HN`，否则顺延到下一个可持续参与的晚间时段。仓库侧下一步优先
补一个真实工作流接入案例，而不是在缺少反馈时扩大版本范围。

### 2026-09-24 v0.3.3 发布验收

| 检查项 | 结果 |
| :--- | :--- |
| `main` CI | `09db93b` 全部通过（[run 35994066389](https://github.com/juangh123/AgentWarden/actions/runs/35994066389)） |
| Release workflow | verify 与 publish 均成功（[run 35994099639](https://github.com/juangh123/AgentWarden/actions/runs/35994099639)） |
| npm registry | `latest = 0.3.3`，[GitHub Release](https://github.com/juangh123/AgentWarden/releases/tag/v0.3.3) 已公开发布 |
| npm integrity | `sha512-Gdu28L6uWkonYJaFsmMXx1XpAh4+Pe1LxDw8SpSyguDO7UOoc7iW4GZO6n9K90/ieunhPFG/g5RjQBVuuDofbA==` |
| npm provenance | [SLSA provenance](https://registry.npmjs.org/-/npm/v1/attestations/agentwarden-cli@0.3.3) 已生成并通过 OIDC 签名 |
| 仓库外 `npx --version` | `agentwarden v0.3.3`，退出码 `0` |
| 安全样例扫描 | 安全分 `100/100`，退出码 `0` |
| 恶意样例扫描 | 命中 5 条 CRITICAL，安全分 `0/100`，退出码 `1` |
| Release tarball | 大小 85,756 bytes，SHA-256 `f1349c07dec659d3891d75c6198cd8c01082821edc5880e97acf495cb9e2aabf` |
| `SHA256SUMS` | 与下载后的 Release tarball SHA-256 一致，校验通过 |

### 2026-09-25 Day 9 快照与评论巡检

| 指标 | 当前值 |
| :--- | :--- |
| Stars / Watchers / Forks | 0 / 0 / 0 |
| 本仓库 Open Issues / Open PRs | 0 / 0 |
| GitHub Release 资产下载 | 2（v0.3.3 tarball 与 SHA256SUMS 各 1 次，较 Day 8 首次出现） |
| GitHub 仓库流量 | 近 14 天 27 次浏览 / 22 个独立访客；另 1,432 次 clone / 227 个独立 cloner |
| npm weekly downloads | 22（2026-09-15 至 2026-09-21，与 Day 7/8 相同） |
| npm 日粒度下载 | 2026-09-22 至 2026-09-25 仍记为 0，统计窗口尚未完整结算 |
| Awesome 权威目录收录 | 1/4 已合并；`awesome-mcp-security` #334、`awesome-mcp-devtools` #338、`Awesome-MCP-ZH` #603 仍待审核且无新评论 |
| GitHub Discussion #21 | 新增 1 条外部评论（2026-09-25），合计 2 条 |
| DEV 文章 | 0 个公开反应 / 0 条评论 |
| Reddit `r/mcp` | RSS 显示 0 条评论 |
| 掘金文章 | 公开页未返回可解析计数，沿用 2026-09-23 可核验值：阅读 20 / 点赞 1 / 收藏 1 / 评论 0 |
| Hacker News | 0 submissions / 0 comments；账号仍具备 `Show HN` 发布条件 |

本日最重要的评论来自 GitHub Discussion #21。外部开发者 `imMamdouhaboammar`
指出：Action 从工作区读取策略文件，因此 PR 可以在同一提交里加入凭证读取 Skill，
并同时通过 `ignoreRules` 或降低 `failOn` 放宽策略；仅靠 `changed: true` 时，
纯策略变更 PR 甚至没有可扫描的 Skill 文件。

该问题已复现并修复，而不是仅作说明：

- 新增 `agentwarden policy guard <base-ref>`：读取基线 ref 上已批准策略（含 `extends` 继承链），
  与工作区策略的有效值比较；任何差异返回退出码 `1`。
- Action 新增可选输入 `policy-guard` 与 `policy-guard-base`，默认关闭；启用后先执行策略守护，
  再执行基线状态检查、增量扫描与 SARIF 输出。
- 下游示例加入 `CODEOWNERS` 占位条目，把 `.agentwarden/` 与 `.github/workflows/` 交给安全审查者。
- 回归覆盖两种绕过：同一 PR 同时提交恶意 Skill 与策略放宽；纯策略变更且无 Skill 文件变化。

同日验证：TypeScript 检查通过，128/128 单元测试通过，121/121 端到端检查通过。
Day 9 的唯一高优先级工程缺口仍来自真实社区反馈，说明评论巡检已经产生实际安全收益。

### 2026-09-27 Day 11 快照与 v0.3.4 发布准备

| 指标 | 当前值 |
| :--- | :--- |
| Stars / Watchers / Forks | 0 / 0 / 0 |
| 本仓库 Open Issues / Open PRs | 0 / 0 |
| GitHub Release 资产下载 | 2（v0.3.3 tarball 与 SHA256SUMS 各 1 次） |
| npm weekly downloads | 183（2026-09-17 至 2026-09-26 API 窗口总计 190；截至巡检时 last-week 为 183） |
| npm 版本分布 | 最近一周 0.3.3 为 164 次、0.3.2 为 19 次 |
| Awesome 权威目录收录 | 1/4 已合并；`awesome-mcp-security` #334、`awesome-mcp-devtools` #338、`Awesome-MCP-ZH` #603 仍待审核 |
| GitHub Discussion #21 | 3 条评论；外部反馈已复现并完成代码修复 |
| DEV 文章 | 0 个公开反应 / 0 条评论 |
| Hacker News | 未检索到 AgentWarden 提交；仍需维护者在可持续互动的晚间时段亲自发布 |
| V2EX | 草稿就绪；仍需维护者登录后在 `分享创造` 节点发布 |

npm 日粒度下载为：09-18 两次、09-19 五次、09-20 两次、09-21 两次、
09-22 一次、09-23 两次、09-24 138 次、09-25 31 次、09-26 七次。
09-24 与 v0.3.3 发布时间重合，随后快速回落，且没有同时出现 Star、Issue、
评论或外部 Action 引用增长，因此当前把它记录为发布、镜像和验证行为造成的
短时脉冲。下一完整统计窗口若不能保持增长，不应把 183 次解释为稳定采用。

本轮把外部评论提出的策略绕过问题收口为 `v0.3.4` 发布候选：

- `agentwarden policy guard <base-ref>` 比较工作区与批准基线之间的有效策略。
- `policy-guard` 已接入 Action，并覆盖全部策略影响输入及发现基线。
- 新初始化的下游工作流默认在 PR 中启用守护，同时保留直接调用的兼容性。
- `examples/github-action-project` 提供可复制的下游接入、严格策略和
  `CODEOWNERS` 边界。
- `v0.3.4` 发布候选包含 Release Notes、版本引用、npm/API 文档和冷启动文案更新。

本地发布门禁结果：

| 检查项 | 结果 |
| :--- | :--- |
| TypeScript 检查 | 通过 |
| 单元测试 | 132/132 通过 |
| 端到端烟测 | 127/127 通过 |
| npm tarball 安装烟测 | 通过 |
| MVP 打包验收 | 20/20 通过 |
| Git 源码安装烟测 | 通过 |
| 发布产物 | `release/agentwarden-cli-0.3.4.tgz` 与 `release/SHA256SUMS` 已生成并核对；SHA-256 为 `da2894a2...e3c56136b` |

公开发布仍需维护者合并发布分支并推送 `v0.3.4` tag。仓库侧不再需要用
未发布命令继续扩展范围；发布后优先观察注册表披露、首次扫描反馈和首个
外部仓库接入，再决定下一项产品能力。

### 2026-09-29 Day 13 快照、v0.3.4 发布验收与发布产物修复

| 指标 | 当前值 |
| :--- | :--- |
| Stars / Watchers / Forks | 0 / 0 / 0 |
| 本仓库 Open Issues / Open PRs | 0 / 0 |
| GitHub Release 资产下载 | v0.3.4 tarball 与 `SHA256SUMS` 发布当天各 0 次 |
| npm 最近一周下载 | 183（2026-09-18 至 2026-09-26 窗口，沿用 Day 11 结算值） |
| npm 日粒度下载 | 09-18 两次、09-19 五次、09-20 两次、09-21 两次、09-22 一次、09-23 两次、09-24 138 次、09-25 31 次、09-26 七次、09-27 五次、09-28 零次 |
| npm 9-13 至 9-28 累计 | 206 次；脉冲回落后 09-27 为五次、09-28 为零次，仍不视为稳定采用 |
| Awesome 权威目录收录 | 1/4 已合并；`awesome-mcp-security` #334、`awesome-mcp-devtools` #338、`Awesome-MCP-ZH` #603 仍待审核且无新评论 |
| GitHub Discussion #21 | 3 条评论，无新增；外部反馈已在 v0.3.4 收口 |
| DEV 文章 | 0 个公开反应 / 0 条评论 |
| 掘金文章 | 沿用 2026-09-23 可核验值：阅读 20 / 点赞 1 / 收藏 1 / 评论 0 |
| Hacker News | 仍未检索到 AgentWarden 提交；`Show HN` 仍需维护者在可互动的晚间发布 |
| V2EX | 草稿就绪；仍需维护者登录后在 `分享创造` 节点发布 |

本轮把 Day 11 准备就绪的发布候选推送到公网：

- 合并 PR #59（`release: prepare v0.3.4`），推送 `v0.3.4` tag，由 Release workflow 完成发布。
- 发布后仓库不再保留未发布的 `policy guard` 能力，`v0.3.4` 的 Action 与 CLI 都包含策略守护。

发布验收（2026-09-29）：

| 检查项 | 结果 |
| :--- | :--- |
| `main` CI | `6519415` 全部通过（[run 36571858343](https://github.com/juangh123/AgentWarden/actions/runs/36571858343)） |
| Release workflow | verify 与 publish 均成功（[run 36572017608](https://github.com/juangh123/AgentWarden/actions/runs/36572017608)） |
| npm registry | `latest = 0.3.4`，发布时间 `2026-09-29T13:03:03Z` |
| npm integrity | `sha512-WTVhwliScHhVyciy60gd/gHzm6WYP32pNIOOpG7CeJccEyeIgWV8vyU18ROkz9tAN3lshllHqGBUY8wtINtMrg==` |
| npm provenance | [SLSA provenance](https://registry.npmjs.org/-/npm/v1/attestations/agentwarden-cli@0.3.4) 已生成并通过 OIDC 签名 |
| GitHub Release | [v0.3.4](https://github.com/juangh123/AgentWarden/releases/tag/v0.3.4) 已公开发布，附带 tarball 与 `SHA256SUMS` |
| Release tarball | 91,095 bytes，SHA-256 `6eb45e9c6073d327497b933c37385c95ddf9ac4ae2b9ddd39fe89c81394736ca` |
| 发布附件 `SHA256SUMS` | 与下载后的 Release tarball SHA-256 一致，校验通过 |
| 本地发布门禁 | TypeScript、132/132 单测、127/127 端到端检查、npm 安装烟测、20/20 MVP 打包验收全部通过；发布产物校验见下节 |

#### 发布产物完整性修复

发布后交叉核对发现：仓库内提交的 `release/agentwarden-cli-0.3.4.tgz`
（91,218 bytes，SHA-256 `da2894a2ebef1454c928c18fe8167cc8c445f4bfb7793d0614c8cf0e3c56136b`）
与 CI 实际发布到 npm 和 GitHub Release 的产物（91,095 bytes，SHA-256
`6eb45e9c6073d327497b933c37385c95ddf9ac4ae2b9ddd39fe89c81394736ca`）不一致。
根因是 Windows 检出把文本文件写成 CRLF、Linux CI 使用 LF，`npm pack` 因此在
两种环境下产生不同字节；而 Release workflow 只校验了 runner 上重新生成的
tarball 与 `SHA256SUMS`，没有校验仓库内已提交的那一份，用户按仓库记录校验
发布附件时会看到不匹配。

处理方式：

- 新增 `.gitattributes`（`* text=auto eol=lf`），让所有平台的文本检出统一为 LF。
- `release/` 中的 tarball 与 `SHA256SUMS` 已替换为实际发布的字节，仓库记录与 npm、GitHub Release 对齐。
- 新增 `npm run test:release`：校验仓库内 tarball 与 `SHA256SUMS` 一致，并对这份已提交产物执行 publish dry-run、干净安装与完整 CLI 生命周期验收。
- 该命令还用不依赖外部工具的 tar 内容比对，确认已提交产物与当前源码重新打包出来的文件内容一致；跨 npm 版本只比较文件名与内容，不比较压缩字节。
- Release workflow 的 verify 任务改用 `npm run test:release`，publish 任务发布的是仓库内已提交并经校验的同一份 tarball，不再在 runner 上重新打包。
- 已验证负例：把 `SHA256SUMS` 改成错误摘要后，`npm run test:release` 以 `FAIL: committed tarball matches release/SHA256SUMS`、退出码 `1` 失败。

发布门禁的语义：`npm run test:release` 只在发布提交上必须全绿。已发布版本在
`main` 上继续保留其实际发布字节；一旦包内会出现的文件（`dist/`、`README.md`、
`package.json`、`LICENSE`）发生变化，内容比对会报告差异，直到下一个版本重新
生成产物。因此 `main` 上出现该差异属于预期，不是回归。

已知残留：`v0.3.4` tag 指向的提交树中仍是修复前的 tarball 字节。已发布的 npm
与 GitHub Release 产物以发布附件中的 `SHA256SUMS` 为准；`main` 已对齐，后续版本
由新的发布门禁保证仓库记录与发布字节一致。

Day 13 的结论：仓库侧工程与发布链路已收口，当前瓶颈回到分发。`Show HN`、
V2EX 与 Reddit 评论维护都依赖维护者本人操作；仓库侧下一步优先争取首个外部
仓库接入 `policy-guard`，而不是在缺少反馈时扩大版本范围。

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
