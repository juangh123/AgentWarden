# AgentWarden 分发环节操作指引

> 本文件是维护者可执行的操作手册：按渠道给出入口、步骤、可写内容与发布后动作。
> `Show HN` 标题与评论、V2EX 正文、Reddit 与 Discord 的回复都必须由维护者本人
> 撰写，本文件只提供事实、结构与边界，不能整段粘贴发布。

## 目标与边界

目标：让真实开发者在五分钟内完成一次扫描并看到明确退出码，而不是制造安全能力的
错觉或短期曝光。

所有渠道通用边界：

- 不请求点赞、收藏、关注、转发，不做互推和跨站联动。
- 同一内容不在同一时间投向多个社区；每个社区用与它实际工作流相关的说法。
- 不夸大能力：不使用“完全防护”“保证安全”“万能 AI 防火墙”等表述。
- 只描述维护者本人复现过的结果，不引用未验证的数字。

## 账号与登录清单

| 渠道 | 账号 | 入口 | 登录要求 |
| :--- | :--- | :--- | :--- |
| V2EX | 维护者账号 | https://www.v2ex.com/go/create | 必须登录；站内对脚本请求返回 `403`，只能在浏览器操作 |
| Hacker News | `agentwarden` | https://news.ycombinator.com/submit | 必须登录；`Show HN` 限制已解除 |
| Reddit | `u/Basic_Support_9438` | https://www.reddit.com/r/mcp/comments/1wh2kyb/ | 必须登录；本机网络对 `reddit.com` 直接返回 `403` |
| Discord | `agentwarden_cli` | https://discord.com/channels/1312302100125843476/1544674994423074867/threads/1550914398879486072 | 必须登录 |
| 掘金 | `AgentWarden` | https://juejin.cn/user/252246275414937 | 只需监控 |
| DEV | `agentwarden` | https://dev.to/agentwarden | 只需监控 |

本机无法替代账号操作：浏览器控制与第三方会话都不在手边，社区登录、发帖和评论
只能由维护者本人完成。这里的脚本只负责准备事实、复现命令和记录结果。

## 开始前一次性核对

在仓库目录之外的干净目录复现一次，确保文案里的命令与退出码成立：

```bash
mkdir agentwarden-demo
cd agentwarden-demo

curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.5/examples/safe-skill.md
npx --yes agentwarden-cli@0.3.5 scan safe-skill.md       # 期望退出码 0

curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.5/examples/malicious-skill.md
npx --yes agentwarden-cli@0.3.5 scan malicious-skill.md  # 期望退出码 1
```

Windows PowerShell 用户把 `curl` 换成 `curl.exe`，并用 `$LASTEXITCODE` 查看退出码。
任何一步的退出码与预期不符时，先不要发布，回到仓库排查。

## 渠道 A：V2EX `分享创造`

事实清单与建议结构见 [launch-v2ex.md](launch-v2ex.md)。

1. 浏览器登录 V2EX，打开 https://www.v2ex.com/go/create ，确认 `分享创造` 节点可用、
   账号没有发帖限制。
2. 新建主题，从 [launch-v2ex.md](launch-v2ex.md) 的标题方向里选一个，或按自己口吻
   改写。
3. 正文按下面五段结构，用本人语气写，保持简短：
   - 一句话说清问题：Skill 和 MCP 配置当依赖用，却没有 lockfile、来源校验和 CI 门禁。
   - 一句话说清做法：进运行时之前静态扫描，`skills.lock` 锁 SHA-256，可选 Ed25519 验源。
   - 贴可复制命令与预期退出码，来自上一步的复现结果。
   - 主动说明边界：静态门禁不是沙箱，会漏报也会误报。
   - 给出真实邀请：希望看到没被识别的 MCP 配置格式、误报和绕过案例。
4. 发布后把主题链接记入下方“发布后记录”。

发布后：技术问题在原帖回复，不重复开新帖，不在多个节点交叉发帖。

## 渠道 B：Hacker News `Show HN`

事实清单、标题方向与首评参考见 [launch-hacker-news.md](launch-hacker-news.md)。

1. 选择能持续跟进的时段（建议工作日 `20:00` 至 `22:00` UTC+8，覆盖美东上午），
   并预留 2 至 3 小时在线。
2. 登录后打开 https://news.ycombinator.com/submit ：
   - title：`Show HN: AgentWarden – Scan and lock AI agent skills before execution`
   - url：`https://github.com/juangh123/AgentWarden`
3. 提交后立即进入 item 页面，发布首条技术自述。参考结构（必须本人重写）：
   - 起因：Skill 以 Markdown 分发，但对 Agent 而言近乎可执行代码。
   - 缺口：没有 lockfile、没有发布者来源验证、没有 CI 门禁。
   - 实现：零运行时依赖、Node 22.6+、SHA-256 锁、Ed25519 分离签名、SARIF 与 CycloneDX SBOM。
   - 一条可复现命令与退出码。
   - 明确边界与希望得到的反馈类型。
4. 提交后记录 item 链接。

发布后：只提交一次；没人讨论时不要立刻删除重发；所有评论回复必须本人完成，
不使用 AI 生成内容。

## 渠道 C：Reddit `r/mcp` 维护

首帖：
https://www.reddit.com/r/mcp/comments/1wh2kyb/agentwarden_static_security_gate_and_integrity/

当前状态（2026-09-29 复核）：1 upvote / 0 comments。

1. 登录后打开首帖，看评论数是否大于 0。有评论则逐条人工回复；没有则不动作。
2. 帖子正文里的演示命令仍固定在旧版本，建议顺手编辑到当前版本：
   - `.../v0.3.2/examples/malicious-skill.md` → `.../v0.3.5/examples/malicious-skill.md`
   - `npx agentwarden-cli@0.3.2 scan ...` → `npx agentwarden-cli@0.3.5 scan ...`

   编辑方式：帖子下方的 `Edit` 按钮 → 改这两处版本号 → 保存。
3. 不在 `r/mcp` 或其他 subreddit 重复投放同一内容；先继续参与相关问题讨论。

## 渠道 D：Discord `showcase` 维护

主题：
https://discord.com/channels/1312302100125843476/1544674994423074867/threads/1550914398879486072

当前状态（2026-09-29）：脚本侧读不到消息（频道消息接口返回 `401`），需要维护者
登录后核对。

1. 登录 Discord，打开上面的主题链接，查看是否有新回复。
2. 有技术问题就在原主题里人工回复；补充信息时更新原主题，不新建重复主题。
3. MCP Contributor Discord 与 OpenAI 社区只由维护者本人参与，不发 AI 生成消息，
   也不做产品营销。

## 渠道 E：掘金与 DEV（已发布，仅维护）

- 掘金：https://juejin.cn/post/7685966048847790114 —— 监控阅读、点赞、收藏、评论，
  技术问题本人回复。
- DEV：https://dev.to/agentwarden/agent-skills-and-mcp-configs-need-a-security-gate-cdf
  —— 监控 reactions 与评论，保持 `AI-assisted` 声明。

两者当前都是 0 评论；没有评论时不必主动顶帖。

## 渠道 F：开源目录 PR 跟进

| 目录 | PR | 状态（2026-09-29） |
| :--- | :--- | :--- |
| [Awesome MCP Security](https://github.com/Puliczek/awesome-mcp-security) | [#334](https://github.com/Puliczek/awesome-mcp-security/pull/334) | 开放、可合并、0 条评论 |
| [Awesome MCP DevTools](https://github.com/punkpeye/awesome-mcp-devtools) | [#338](https://github.com/punkpeye/awesome-mcp-devtools/pull/338) | 开放、可合并、0 条评论 |
| [Awesome-MCP-ZH](https://github.com/yzfly/Awesome-MCP-ZH) | [#603](https://github.com/yzfly/Awesome-MCP-ZH/pull/603) | 开放、可合并、0 条评论 |

规则：每条只提交一次，不催审；维护者要求改格式或分类时在原 PR 中处理。

## 发布后记录

每次发布或重要维护后，把结果补进[冷启动清单](launch-cold-start.md)的“已发布渠道
记录”，格式沿用该表：

| 日期 | 渠道 | 链接 | 状态 |
| :--- | :--- | :--- | :--- |
| 待填 | 待填 | 待填 | 待填 |

## 回复与沟通原则

- 先复现再回应：对方给出可复现的问题，先在本地跑一遍再答。
- 承认边界：误报和漏报都直说，不辩解，也不承诺“下个版本一定解决”。
- 不索要 star、不引导点赞；把回复落在真实工作流的缺口上。
- 平台要求标注 AI 生成或辅助内容时，按平台规则声明。
