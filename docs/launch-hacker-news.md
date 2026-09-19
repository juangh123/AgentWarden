# Hacker News `Show HN` 准备

> Hacker News 明确禁止生成或 AI 编辑的评论。本文件只是维护者的事实清单，
> 不得直接复制到 HN。`Show HN` 标题、正文和所有评论必须由维护者本人撰写。

> 2026-09-19 更新：HN 正在临时限制 `Show HN`，原因是短时间内的提交量过大。
> 当前不要重复提交。先正常阅读和参与社区，等待限制解除后再说。

## 发布目标

- 主链接：https://github.com/juangh123/AgentWarden
- 展示对象：仓库本身，不要链接掘金、Reddit 或短帖
- 建议标题方向：
  - `Show HN: AgentWarden - static security gate for AI agent skills and MCP configs`
  - `Show HN: AgentWarden - scan and lock AI agent skills before execution`
- 标题必须由维护者重新确认；不要使用“revolutionary”“fully secure”或
  “guaranteed protection”等营销表述。

## 可以验证的事实

- AgentWarden 是 Node.js CLI，要求 Node.js 22.6 或更高版本。
- 它在 Skill、Tool 和 MCP 配置进入 Agent 运行时前执行静态扫描。
- 当前规则覆盖凭证访问、危险命令、提示词注入、数据外带、MCP 配置和供应链风险。
- `skills.lock` 记录 SHA-256 完整性和文件清单。
- 远程安装可要求发布者提供的 SHA-256，并支持 Ed25519 分离签名。
- 报告支持脱敏 JSON、SARIF 2.1.0 和 CycloneDX 1.5 SBOM。
- GitHub Action 可用于 full、changed-file 和 baseline 扫描。
- 当前版本为 `agentwarden-cli@0.3.2`，GitHub Action 固定引用
  `juangh123/AgentWarden@v0.3.2`。

## 直接演示

维护者在本地运行并确认输出后再决定是否写进正文：

```bash
curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.2/examples/malicious-skill.md
npx --yes agentwarden-cli@0.3.2 scan malicious-skill.md
```

预期结果：命中高风险规则并返回退出码 `1`。正文只描述维护者亲自复现的结果。

## 必须主动说明的边界

- 它是静态门禁，不是沙箱、杀毒软件或运行时策略引擎。
- 静态规则会漏报，也可能误报。
- 它不能替代最小权限、隔离、网络限制、代码审查和人工判断。
- 最有价值的反馈是可复现的 MCP 格式、误报、绕过、CI 集成和安装问题。

## 发布时机

- 在 HN 解除 `Show HN` 限制前，不执行本文件中的发布步骤。
- 维护者必须能在发布后 2 至 3 小时持续查看并亲自回复。
- 若今天无法持续参与，改为次日或下个工作日的 `20:00` 至 `22:00`（UTC+8），
  以覆盖美国东部上午时段。
- 不要为了赶上某个时间点而让无人维护的帖子自行沉底。

## 发布前确认

- 标题和正文由维护者本人撰写，不直接粘贴本文件或任何生成文本。
- 同意 HN 社区规则，不使用投票请求、互赞、私信邀请或跨平台联动。
- 只提交一次。没有形成讨论时，不立即删除并重复提交。
- 发布后记录 item 链接，但评论回复必须由维护者本人完成。
