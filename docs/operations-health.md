# 运行健康巡检

本清单用于每次发布前、每周巡检和异常排查。它只执行只读检查或本地构建，
不会发布 npm 包、移动标签、修改分支保护或代表维护者向社区发言。

## 本地门禁

```bash
npm ci
npm run verify:local
```

`verify:local` 依次执行类型检查、单元测试、端到端烟测、包安装烟测、
依赖漏洞审计和 registry 签名校验。发布提交还必须通过：

```bash
npm run test:release
```

`test:release` 只应在准备发布的提交上全绿。当前版本发布后继续修改包内文件时，
它会报告当前源码与已提交 tarball 的差异，这是下一次版本发布前的预期状态。

## 性能

```bash
npm run bench:cold-start
npm run bench:cold-start:network:repeat
```

本地基准用于发现 CLI 回归；联网基准为每次采样使用独立 npm 缓存，避免把一次
registry 抖动当成稳定回归。不设置硬性网络阈值；p90 明显高于历史中位数或单次
请求超过一分钟时，先重测并检查 npm registry 连通性。

`Cold Start Benchmark` workflow 每周保存 JSON 报告，可在 GitHub Actions
Artifacts 中比较趋势。

## 线上发布

```bash
npm view agentwarden-cli version dist.integrity
gh release view v0.3.7 --repo juangh123/AgentWarden
gh run list --repo juangh123/AgentWarden --branch main --workflow CI --limit 1
git ls-remote --tags origin v0 v0.3 v0.3.7
```

核对：

- `main` 的最新 CI 与 8 项保护检查成功。
- npm `latest` 与固定版本命令输出一致。
- Release 资产、`SHA256SUMS` 和仓库内 tarball 的 SHA-256 一致。
- provenance 可查询，Release 不是 draft 或 prerelease。
- 旧浮动标签没有被文档推荐，且 `v0.3` 指向当前 minor 的最新发布提交。

新增的 `min-node` 与 CodeQL 检查合并到 `main` 后，需要维护者决定是否加入
分支保护的必需检查列表；修改保护规则属于仓库权限变更，不在本地巡检中自动执行。

## 安全配置

```bash
npm audit --audit-level=high
npm audit signatures
gh api repos/juangh123/AgentWarden/code-scanning/alerts?state=open
gh api repos/juangh123/AgentWarden/dependabot/alerts?state=open
gh api repos/juangh123/AgentWarden/branches/main/protection
```

CodeQL、Dependabot 或 Secret Scanning 告警出现后，先确认影响版本和可达性。
不要为了清空告警而降低规则等级或关闭检查。

## 分发指标

```bash
gh release view v0.3.7 --repo juangh123/AgentWarden --json assets
gh api repos/juangh123/AgentWarden
gh api repos/juangh123/AgentWarden/traffic/views
gh api repos/juangh123/AgentWarden/traffic/clones
```

下载、浏览和 clone 只是采用信号，不能单独证明持续使用。社区发布与编辑必须由
维护者确认，具体渠道和账号状态见
[分发操作指引](launch-distribution-runbook.md)。

## 判定

- **通过**：本地门禁全绿、最新 CI 全绿、npm/Release 制品一致、无高风险告警。
- **有风险**：主链路可用，但存在发布树不一致、性能异常、渠道阻塞或待处理依赖。
- **阻塞**：构建或测试失败、发布制品不一致且准备发布、关键凭据泄漏风险，
  或线上版本不可安装。
