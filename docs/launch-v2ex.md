# V2EX `分享创造` 发布准备

> 发布前说明：本文件只是维护者的事实清单与草稿，不能整段粘贴后直接发布。
> V2EX 社区对营销内容和跨站投放非常敏感，正文必须由维护者本人按自己的口吻改写。

> 2026-09-23 更新：V2EX 站点对匿名请求返回 `403`，当前无法从脚本侧确认节点状态
> 或注册资格。维护者需在浏览器中登录后自行核对节点名称、发帖规则与账号权重。

## 发布目标

- 节点：`分享创造`（`/go/create`），用于展示自己做的项目，不要在无关节点交叉发帖。
- 主链接：https://github.com/juangh123/AgentWarden
- 唯一发帖：同一项目只发一次。收到反馈时在原帖回复，不重复开新帖。

## 可以验证的事实

- AgentWarden 是 Node.js CLI，要求 Node.js 22.6 或更高版本，零运行时依赖。
- 它在 Skill、Tool 和 MCP 配置进入 Agent 运行时前执行静态扫描。
- 当前规则覆盖凭证泄露、危险命令、提示词注入、数据外带、MCP 配置和供应链风险。
- `skills.lock` 记录 SHA-256 完整性和文件清单；远程安装可要求发布者提供的摘要。
- 支持 Ed25519 分离签名验证发布者来源。
- 报告支持脱敏 JSON、SARIF 2.1.0 和 CycloneDX 1.5 SBOM。
- GitHub Action 支持 full、changed-file 和 baseline 扫描。
- 当前版本为 `agentwarden-cli@0.3.2`，Action 固定引用 `juangh123/AgentWarden@v0.3.2`。

## 标题方向

- `做了一个 Agent Skill / MCP 配置的静态安全门禁，可接入 CI`
- `Agent Skill 和 MCP 配置也在变成依赖，写了个扫描加锁的小工具`

不要使用“颠覆”“绝对安全”“一劳永逸”等表述，也不要写“求 star”。

## 直接演示（维护者先在本地复现）

```bash
mkdir agentwarden-demo && cd agentwarden-demo

curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.2/examples/safe-skill.md
npx --yes agentwarden-cli@0.3.2 scan safe-skill.md

curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.2/examples/malicious-skill.md
npx --yes agentwarden-cli@0.3.2 scan malicious-skill.md
```

安全样例返回 `0`，恶意样例返回 `1`。Windows 上把 `curl` 换成 `curl.exe`，
并用 `$LASTEXITCODE` 查看退出码。

## 正文结构建议（保持简短，V2EX 不喜欢长软文）

1. 一句话说清问题：Skill 和 MCP 配置当依赖用，但没有 lockfile、来源校验和 CI 门禁。
2. 一句话说清做法：进运行时之前静态扫描，`skills.lock` 锁 SHA-256，可选 Ed25519 验源。
3. 贴上面两条可复制命令和预期退出码。
4. 主动说明边界：静态门禁不是沙箱，会漏报也会误报，不能替代最小权限和隔离。
5. 给出真实邀请：希望看到真实工作流里没被识别的 MCP 配置格式、误报和绕过案例。

## 必须主动说明的边界

- 它是静态门禁，不是沙箱、杀毒软件或运行时策略引擎。
- 静态规则会漏报，也可能误报。
- 它不能替代最小权限、隔离、网络限制、代码审查和人工判断。

## 发布前确认

- 用浏览器登录后确认 `分享创造` 节点可用，账号没有发帖限制。
- 正文由维护者本人改写，不使用自动生成的长段落或营销句式。
- 不请求点赞、收藏、关注或转发，不与其他平台互推。
- 不在多个节点重复投放同一内容。
- 发布后记录主题链接；技术问题由维护者本人回复。
