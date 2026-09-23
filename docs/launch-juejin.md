# Agent Skill 和 MCP 配置也需要安全门禁：从扫描到可验证的供应链

> 发布前说明：这是维护者草稿，需要本人完成技术复核后再发布。若平台要求
> 标注 AI 生成或辅助内容，请按平台规则声明。不要在正文或评论中请求点赞、
> 转发或集中评论。

AI Agent 正在获得越来越多的本地能力：读取文件、执行命令、访问 API、连接
MCP Server，以及按自然语言指令组合这些工具。

但很多 Agent Skill 的安装方式仍然是“复制一个 Markdown 文件”或“把一个
GitHub 地址写进配置”。它们看起来像文档，实际却可能包含脚本、凭证访问逻辑
和外部网络请求。

这意味着 Skill 和 MCP 配置正在变成一种新的依赖项，却没有获得依赖管理应有的
基本保护：

- 没有 lockfile 记录安装内容；
- 没有稳定的内容摘要检测后续篡改；
- 没有发布者来源验证；
- 没有在 CI 中阻止高风险配置进入主分支的门禁。

我做的 AgentWarden 就是为了解决这几个具体问题。它不是运行时沙箱，也不承诺
“保证 Agent 安全”，而是一个在 Skill 和 MCP 配置进入运行时之前执行的静态
安全门禁、完整性锁和发布者来源验证工具。

## 先把问题跑出来

AgentWarden 需要 Node.js 22.6 或更高版本，不需要运行时依赖。可以直接通过
npm 临时运行：

```bash
mkdir agentwarden-demo
cd agentwarden-demo

curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.2/examples/safe-skill.md
npx --yes agentwarden-cli@0.3.2 scan safe-skill.md

curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.2/examples/malicious-skill.md
npx --yes agentwarden-cli@0.3.2 scan malicious-skill.md
```

安全样例返回退出码 `0`。恶意样例会命中凭证读取、危险命令、提示词注入或数据
外带相关规则，并返回退出码 `1`。

Windows PowerShell 用户可以把 `curl` 换成 `curl.exe`。查看最后一次退出码：

```powershell
npx --yes agentwarden-cli@0.3.2 scan malicious-skill.md
$LASTEXITCODE
```

退出码比终端颜色更重要，因为它可以让同一套检查直接进入 CI：

- `0`：扫描通过；
- `1`：存在安全风险、完整性不匹配或当前策略失败；
- `2`：命令用法、路径或配置错误。

## 它检查什么

当前规则覆盖以下类别：

- 凭证与密钥泄露，例如访问 SSH、AWS 等敏感路径，引用高特权环境变量，或把
  API Token 和私钥直接写入内容；
- 危险命令执行，例如系统破坏命令、下载后直接执行、`eval` 和编码解码执行链；
- 提示词注入和越狱模式，例如覆盖系统角色、诱导无限制行为或混淆载荷；
- 数据外带，例如连接异常收集端点、上传本地文件或建立反弹连接；
- MCP 配置风险，例如使用原始 shell、未固定版本包运行服务端，或在 `env` /
  `headers` 中
  写入明文密钥；
- 供应链风险，例如未校验摘要便下载执行远程脚本，或使用相似域名伪装来源。

AgentWarden 会自动发现 Markdown Skill 和常见 MCP 配置，也支持通过
`include` / `exclude` 限定扫描范围：

```bash
npx --yes agentwarden-cli@0.3.2 scan . \
  --profile strict \
  --include "skills/**" \
  --exclude "skills/vendor/**"
```

扫描报告默认脱敏。即使某个文件误把 Token 写进内容，JSON、SARIF 和终端输出
也不会把原始敏感值直接展示出来。

## 从扫描到 lockfile

一次性扫描只能说明“当前内容没有命中规则”，不能证明文件之后没有被修改。

AgentWarden 用 `skills.lock` 记录已审核内容的 SHA-256、文件清单、远程来源和
发布者来源信息。可以把它理解为 Skill 版本的 lockfile：

```bash
npx --yes agentwarden-cli@0.3.2 install ./skills/weather.md
npx --yes agentwarden-cli@0.3.2 verify .agentwarden/skills/weather.md
npx --yes agentwarden-cli@0.3.2 audit
npx --yes agentwarden-cli@0.3.2 sbom --output agentwarden.cdx.json
```

`verify` 检查本地内容是否仍与锁文件一致。`audit` 会同时检查完整性，并按照
当前策略重新扫描。`sbom` 则从锁文件导出 CycloneDX 1.5 清单，便于后续审计
和软件供应链系统消费。

远程安装必须提供发布者给出的 SHA-256：

```bash
npx --yes agentwarden-cli@0.3.2 install \
  https://publisher.example/skills/weather.md \
  --sha256 <64-char-sha256>
```

摘要不匹配、文件修改或包内清单异常都会导致非零退出码，不会把未通过检查的
内容静默写入锁文件。

如果不仅要确认“字节流没有被替换”，还要确认“是谁发布的”，可以加入 Ed25519
分离签名：

```bash
npx --yes agentwarden-cli@0.3.2 install \
  https://publisher.example/skills/weather.md \
  --sha256 <64-char-sha256> \
  --signature https://publisher.example/skills/weather.md.sig \
  --public-key ./trusted-publisher.pem
```

SHA-256 解决内容完整性，Ed25519 解决发布者身份，两者不能互相替代。

## 放进 CI

对于已有仓库，可以先生成策略文件和 GitHub Actions 工作流：

```bash
npx --yes agentwarden-cli@0.3.2 init --profile strict
```

也可以直接使用 GitHub Marketplace 中的 Action：

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7

  - uses: juangh123/AgentWarden@v0.3.2
    with:
      path: skills/
      profile: strict
      config: .agentwarden/policy.json
```

Action 输出 SARIF，可继续上传到 GitHub Code Scanning。大型仓库可以使用
`changed` 或 `changed-from` 只扫描 PR 中变化的 Skill 和 MCP 文件。

对于历史项目，基线功能可以暂时接受已经人工审核的旧发现，但每条例外都应记录
责任人、审核时间和到期时间。基线过期后会重新阻断，避免永久静默豁免。

## 边界比宣传更重要

AgentWarden 是静态门禁，不是沙箱、杀毒软件或运行时策略引擎。

它可能漏报新的攻击模式，也可能对合法项目产生误报。静态规则无法替代最小权限、
容器隔离、网络限制、代码审查和人工决策。

因此当前最有价值的反馈不是“看起来不错”，而是可以复现的真实问题：

- 没有被正确发现或解析的 MCP 配置格式；
- 在真实工作流中出现的误报；
- 可以复现的规则绕过；
- 大型仓库和 PR 中的 CI 集成缺口；
- 包安装、Node.js 版本或跨平台兼容性问题。

## 相关链接

- GitHub：https://github.com/juangh123/AgentWarden
- npm：https://www.npmjs.com/package/agentwarden-cli
- GitHub Marketplace：
  https://github.com/marketplace/actions/agentwarden-security-gate
- 使用问题与集成经验：
  https://github.com/juangh123/AgentWarden/discussions
- 可复现缺陷和误报：
  https://github.com/juangh123/AgentWarden/issues/new/choose

如果你正在维护 Agent Skill、MCP Server 或内部 Agent 工具链，我会更希望听到
你们当前的安装、审核和 CI 流程，而不是单纯的 Star。真实 workflow 的缺口，
才是下一版最值得修的东西。

## 发布前核对

- 使用 `docs/assets/juejin-cover.png` 作为掘金封面；
- 在 Node.js 22.6 或更高版本上重新执行正文中的扫描、锁文件和 SBOM 命令；
- 确认示例链接、Action 版本和 npm 版本均可访问；
- 根据平台要求补充 AI 辅助内容声明；
- 由维护者本人改写开头、结尾和评论，不使用自动评论。
