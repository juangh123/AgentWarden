# Hacker News `Show HN` 准备

> Hacker News 明确禁止生成或 AI 编辑的评论。本文件只是维护者的事实清单，
> 不得直接复制到 HN。`Show HN` 标题、正文和所有评论必须由维护者本人撰写。

> 2026-09-23 更新：HN 的 `Show HN` 队列已恢复正常提交与展示，近期有多篇
> MCP 工具链与 Agent 运行时项目获得社区高关注度讨论。维护者可在能够预留
> 2 至 3 小时持续跟进并亲自回复的晚间时段（建议 20:00 至 22:00 UTC+8）启动发布。

## 发布目标

- 主链接：https://github.com/juangh123/AgentWarden
- 展示对象：仓库本身，不要链接掘金、Reddit 或短帖
- 建议标题方向：
  - `Show HN: AgentWarden – Scan and lock AI agent skills before execution`
  - `Show HN: AgentWarden – Static security gate and integrity lock for AI skills and MCP configs`
- 标题必须由维护者重新确认；不要使用“revolutionary”“fully secure”或
  “guaranteed protection”等营销表述。

## 推荐提交方式（HN 经典模式）

1. 在 `news.ycombinator.com/submit` 提交链接：
   - **title**: `Show HN: AgentWarden – Scan and lock AI agent skills before execution`
   - **url**: `https://github.com/juangh123/AgentWarden`
2. 提交后立即进入该 item 页面，在评论区发布首条技术自述（First Comment），
   说明做这个工具的背景、技术实现、直接复现命令和寻找的反馈类型。

## 可以验证的事实

- AgentWarden 是 Node.js CLI，要求 Node.js 22.6 或更高版本。
- 它在 Skill、Tool 和 MCP 配置进入 Agent 运行时前执行静态扫描。
- 当前规则覆盖凭证访问、危险命令、提示词注入、数据外带、MCP 配置和供应链风险。
- `skills.lock` 记录 SHA-256 完整性和文件清单。
- 远程安装可要求发布者提供的 SHA-256，并支持 Ed25519 分离签名。
- 报告支持脱敏 JSON、SARIF 2.1.0 和 CycloneDX 1.5 SBOM。
- GitHub Action 可用于 full、changed-file 和 baseline 扫描。
- 当前版本为 `agentwarden-cli@0.3.3`，GitHub Action 固定引用
  `juangh123/AgentWarden@v0.3.3`。

## 直接演示

维护者在本地运行并确认输出后再决定是否写进正文：

```bash
curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.3/examples/malicious-skill.md
npx --yes agentwarden-cli@0.3.3 scan malicious-skill.md
```

预期结果：命中高风险规则并返回退出码 `1`。正文只描述维护者亲自复现的结果。

## 建议首条评论（维护者自述参考）

> 维护者发布时应通读并根据个人口吻做微调，保持谦逊、技术直白、不使用营销辞藻：

```text
Hi HN, I built AgentWarden after noticing a gap in how AI agent skills and MCP configs are managed.

Today, an agent skill is usually distributed as a Markdown file copied into a repo or referenced by URL. But to a coding agent (like Claude Code, Codex, or Cursor), that file is effectively executable code: it can instruct the agent to inspect ~/.ssh or environment variables, execute destructive shell commands, send data to untrusted endpoints, or configure MCP servers with unpinned commands.

Unlike npm, cargo, or pip dependencies, skills rarely get:
1. A lockfile recording exact byte hashes (SHA-256)
2. Cryptographic publisher provenance verification (Ed25519)
3. A static CI gate returning exit code 1 to block PRs before merge

AgentWarden is a zero-runtime-dependency Node.js CLI (built on native Node 22.6+ features) designed to act as an early gate before an agent executes these files:
- Scans Markdown skills and MCP configurations for sensitive paths, destructive commands, prompt injection, data exfiltration, and raw shell execution in MCP definitions.
- Pins reviewed assets in `skills.lock` with SHA-256 and exports CycloneDX 1.5 SBOMs.
- Supports detached Ed25519 signatures for verified publisher workflows.
- Emits redacted SARIF for GitHub Code Scanning and runs as a GitHub Action.

You can test the exit codes from an empty directory:

  curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.3/examples/safe-skill.md
  npx --yes agentwarden-cli@0.3.3 scan safe-skill.md
  # exits 0

  curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.3/examples/malicious-skill.md
  npx --yes agentwarden-cli@0.3.3 scan malicious-skill.md
  # exits 1

It is strictly a static gate, not a runtime sandbox or policy engine. It can and will produce false positives and misses. I'm especially interested in feedback on:
- Real-world MCP configuration formats that fail discovery or parsing
- Rule bypasses and realistic false positives
- How your team currently reviews or isolates third-party skills and MCP servers

Repo: https://github.com/juangh123/AgentWarden
npm: https://www.npmjs.com/package/agentwarden-cli
Marketplace: https://github.com/marketplace/actions/agentwarden-security-gate
```

## 必须主动说明的边界

- 它是静态门禁，不是沙箱、杀毒软件或运行时策略引擎。
- 静态规则会漏报，也可能误报。
- 它不能替代最小权限、隔离、网络限制、代码审查和人工判断。
- 最有价值的反馈是可复现的 MCP 格式、误报、绕过、CI 集成和安装问题。

## 发布时机

- `Show HN` 限制已解除（2026-09-23 确认），可在下述时间条件下发布。
- 维护者必须能在发布后 2 至 3 小时持续查看并亲自回复。
- 若今天无法持续参与，改为次日或下个工作日的 `20:00` 至 `22:00`（UTC+8），
  以覆盖美国东部上午时段。
- 不要为了赶上某个时间点而让无人维护的帖子自行沉底。

## 发布前确认

- 标题和正文由维护者本人撰写，不直接粘贴本文件或任何生成文本。
- 同意 HN 社区规则，不使用投票请求、互赞、私信邀请或跨平台联动。
- 只提交一次。没有形成讨论时，不立即删除并重复提交。
- 发布后记录 item 链接，但评论回复必须由维护者本人完成。
