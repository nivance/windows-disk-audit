# windows-disk-audit

> Windows 磁盘空间审计 —— 先搞清楚「空间去哪了、什么在偷偷变大」，再决定要不要删。

一个零依赖的 Windows 磁盘诊断 Skill。**只读扫描 + 规则库归因 + 时间序列增长对比**，清理只是可选尾巴，且清理的时候必须逐项确认、一律进回收站。

纯 PowerShell 5.1 实现，不装 Python、不装 Node、不需要任何第三方「清理大师」。

---

## 为什么需要它

C 盘从"还剩 50 GB"到"飘红"，通常是无声发生的。已有的工具各有短板：

| 工具 | 能回答 | 回答不了 |
|---|---|---|
| WizTree / TreeSize | 谁最大 | **为什么这周掉了 3 GB** |
| Windows 存储感知 | 大致分类 | 具体是谁、能不能删 |
| 各类「清理大师」 | 一键释放 | 它到底删了什么 |

本项目的答案是三段式：

1. **快照** —— 一次遍历把整盘体积按深度聚合（不做重复遍历）
2. **归因** —— 拿规则库匹配可清理项，按风险分级
3. **对比** —— 和上一次快照做差，直接给出**增长榜**

第 3 步才是关键。单次快照只能告诉你"谁占得多"，只有时间序列才能回答"为什么掉得这么快"。

## 速度：直读 NTFS 主文件表

默认走 `mft` 引擎 —— 直接解析 NTFS 的 `$MFT`，一次读到全部 139 万个文件的路径与大小。**有管理员权限时全盘 6 秒扫完，且是全量精确数据**（WizTree 的原理）。没有权限时自动降级为目录遍历，功能完全一致，只是慢。

实测（C 盘 152 GB / 1,388,727 文件 / 323,678 目录，同一台机器）：

| 阶段 | `mft` 引擎 | `walk` 引擎 | 倍数 |
|---|---|---|---|
| 采集（`scan.ps1 -Depth 3`） | **6.0 s** | 274 s | 46× |
| 归因测尺（`analyze.ps1`） | **8.2 s** | 93.8 s | 11× |
| 端到端 | **≈ 15 s** | ≈ 368 s | 25× |

归因阶段之所以也要提速，是因为它需要几十个规则路径的当前体积。逐目录遍历要 94 秒，其中 22 秒花在一条根本不需要实时遍历的 `never` 规则（`WinSxS`）上。现在 `dirsizes.ps1` 用**一次** `$MFT` 解析把 85 个路径全部量出来，任意深度都一样快。

两个引擎的一致性经过逐目录对账验证：`System32`、`WinSxS`、`npm-cache`、`Documents\Codex` 等 10 个目录的体积**与遍历法完全一致（偏差 0.0%）**。

| 引擎 | 原理 | 需要 |
|---|---|---|
| `mft` | 解析 NTFS 主文件表 | 管理员权限 + NTFS + 卷根（`-Root 'C:\'`） |
| `walk` | 逐目录遍历 | 无（任意文件系统、任意权限） |

`-Engine auto`（默认）优先 `mft`，失败时逐个 root 静默降级并把原因写进快照的 `engineNotes` —— **没权限也能用，只是慢，且降级原因可查**。

## 特性

| 特性 | 说明 |
|---|---|
| **只读优先** | `scan.ps1` 永不删除任何文件，采集阶段零风险 |
| **规则与代码分离** | 36 条目录规则 + 5 条文件名规则，全是 JSON；新增膨胀点只改数据、不改脚本 |
| **增长对比** | 与上一次快照做差，输出"谁在涨、涨了多少"；只比对同 root 同 depth 的快照，避免串味 |
| **引擎口径透明** | 快照记录自己由哪个引擎产生；跨引擎对比会打 `engineMismatch` 标记并说明 ~1% 口径差，绝不把口径差当成真实增长 |
| **异常膨胀检测** | 单个缓存类目录 > 5 GB 直接标红。**这是挖出"隐形大户"的关键** —— 纯看总量发现不了它 |
| **默认进回收站** | 用 `SHFileOperation` + `FOF_ALLOWUNDO`，误删可从回收站找回 |
| **零依赖** | 只需系统自带的 PowerShell 5.1+，无需任何运行时 |
| **自带回归测试** | 55 项断言，1 分钟跑完，全部在临时目录内运行，不碰真实数据；缺管理员权限时 MFT 断言报 SKIP 而非 FAIL |

## 快速开始

### 1. 安装

克隆到 Skill 目录即可，无需构建、无需安装依赖。

```bash
git clone https://github.com/nivance/windows-disk-audit.git

# WorkBuddy
mv windows-disk-audit "$USERPROFILE/.workbuddy/skills/"

# Claude Code
mv windows-disk-audit "$USERPROFILE/.claude/skills/"
```

### 2. 使用

对 AI 助手直接说人话就行，会按描述里的触发词自动命中：

> C 盘满了 / 磁盘空间不足 / 空间去哪了 / 哪个目录占空间 / 帮我看看什么在变大

也可以手动跑脚本：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$S = "$env:USERPROFILE\.workbuddy\skills\windows-disk-audit"

# Step 1 只读采集（mft 引擎约 6 秒；降级为遍历时 100 GB 量级约 4-5 分钟）
& "$S\scripts\scan.ps1" -Root 'C:\' -Depth 3
# 末行输出 RESULT <快照json路径> totalMB=... roots=1 engine=mft seconds=6.2

# Step 2 归因（不传 -Snapshot 时自动取最新快照）
& "$S\scripts\analyze.ps1"

# Step 3 预览清理方案，一行都不会删
& "$S\scripts\clean.ps1" -Analysis '<analysis.json>' -FindingIds 'chrome-service-worker','npm-cache' -DryRun

# Step 4 看过路径清单后再执行
& "$S\scripts\clean.ps1" -Analysis '<analysis.json>' -FindingIds 'chrome-service-worker','npm-cache' -Confirmed
```

常用开关：

```powershell
& "$S\scripts\scan.ps1" -Root 'C:\' -Engine walk     # 强制遍历引擎
& "$S\scripts\analyze.ps1" -SizeEngine walk          # 强制用遍历测尺做交叉验证
```

> 只有 `cleanMode` 为 `delete-dir` / `purge-contents` 的项能被脚本执行；`command` / `manual` 类型的只会打印操作指引，交给人做。

## 输出长什么样

`analyze.ps1` 产出一份 JSON，由 AI 助手在**对话内**渲染成中文报告（默认不生成 HTML 文件）：

```markdown
## 一、C 盘现状
C: 165 GB 总 / 已用 143 GB / 剩余 23 GB（87%）

| 顶层目录 | 占用 | 说明 |
|---|---|---|
| C:\Users | 104 GB | 绝对大头 |
| C:\Windows | 30.9 GB | WinSxS + System32，系统本体 |
| C:\Program Files | 11.6 GB | UWP 应用为主 |

## 二、为什么"掉得特别快"

| 增长源 | 当前体积 | 增长特征 |
|---|---|---|
| Chrome Service Worker 缓存 | 13.3 GB | 按月累积 1.9G → 2.5G → 3.7G，从不回收 |
| 包管理器缓存 | 14.3 GB | npm/pnpm/pip/uv/bun，只增不减 |
| AI 工具会话与日志 | ~15 GB | 对话历史与 trace，从不清理 |

## 三、可删清单（✅ 零风险）
| 目标 | 释放 | 操作 |
|---|---|---|
| Chrome Service Worker（须先完全退出 Chrome） | 13.3 GB | 删该目录 |
| AppData\Local\npm-cache | 8.5 GB | npm cache clean --force |
| 临时目录 + Windows 临时目录 | 1.6 GB | 直接清空 |

## 四、⛔ 别删清单
System32 / WinSxS（硬链接，手删会搞坏系统）/ Fonts / Program Files 下已安装程序 / 用户文档
```

分析 JSON 里的 `comparison` 字段说明本次能不能直接和上次比：

```json
"comparison": {
  "engine": "mft", "previousEngine": "walk",
  "engineMismatch": true, "noteCode": "engine-mismatch",
  "currentTotalMB": 151739, "previousTotalMB": 152068, "totalDeltaMB": -937
}
```

| `noteCode` | 含义 |
|---|---|
| `comparable` | 两次同引擎，数字可直接比 |
| `engine-mismatch` | 两次引擎不同，总量存在约 1% 口径差；目录级方向可信，2% 以内的 delta 视为噪声 |
| `no-previous` | 找不到可比的旧快照（首次运行）——**这不等于"没有变化"** |

## 安全设计

这个项目需要**删除能力**，所以安全约束是硬编码进脚本的，不是文档里的软建议：

1. **采集阶段永不删除** —— `scan.ps1` 只读，`analyze.ps1` 只读
2. **未传 `-Confirmed` 一定不动手** —— 光给 `-DryRun` 只会打印计划
3. **一律走回收站** —— 禁止 `rm` / `del` / `rmdir`
4. **红线目录直接拒绝** —— `never-touch.json` 三级结构（`exactPaths` 精确 / `paths` 前缀 / `depth1Allow` 盘符根白名单），外加拒绝盘符根与含受保护路径段的路径
5. **单批 ≤ 10 项** —— 超出直接报错退出
6. **不碰系统状态** —— 不调用第三方清理工具、不改注册表、不动服务和计划任务
7. **用户说"先别删"就只跑诊断** —— 绝不进入清理步骤

## 目录结构

```
windows-disk-audit/
├── SKILL.md               # Skill 主文档：触发词、流程、安全红线、扩展指南
├── scripts/
│   ├── scan.ps1           # 只读采集 → JSON 快照（-Engine mft|walk|auto）
│   ├── analyze.ps1        # 规则归因 + 分级 + 增长对比 + 异常检测
│   ├── dirsizes.ps1       # 规则路径定向测尺：一次 $MFT 解析量出几十个目录的体积
│   ├── MftScan.cs         # NTFS $MFT 解析器（C#，Add-Type 就地编译，无外部依赖）
│   ├── clean.ps1          # 移入回收站（需 -Confirmed）
│   └── selftest.ps1       # 55 项回归断言
├── rules/
│   ├── caches.json        # 可清理规则库（36 条目录规则 + 5 条文件名规则）
│   └── never-touch.json   # 红线目录，clean.ps1 的硬校验依据
├── references/
│   └── report-format.md   # 对话内中文报告模板
└── fixtures/
    ├── sample-history/    # 两份带时间差的假快照，用于回归增长对比
    └── test-rules.json    # 空规则集，让自检与真实磁盘内容解耦
```

数据与代码分离：skill 目录只放只读代码，运行期产物（快照 + 分析结果）写到数据根 `~/.disk-audit`，可用环境变量 `DISK_AUDIT_HOME` 覆盖。

## 扩展规则库

发现新的膨胀点，往 `rules/caches.json` 的 `rules` 数组加一条即可，无需改脚本：

```json
{
  "id": "my-cache",
  "label": "显示给用户的中文名称",
  "category": "app-cache",
  "risk": "safe",
  "cleanMode": "delete-dir",
  "paths": ["%LOCALAPPDATA%\\SomeApp\\Cache"],
  "cleanHint": "先退出 SomeApp 再删除",
  "why": "为什么会膨胀"
}
```

- `paths` 支持 `%ENVVAR%` 与单层通配符 `*`
- `cleanMode`：`delete-dir` 整目录删除｜`purge-contents` 清空内容保留目录｜`command` 需执行命令｜`manual` 需人工处理
- `risk`：`safe` 删了只是首次稍慢｜`caution` 可能是数据或影响功能｜`never` 禁止删除
- `fileRules` 用于按文件名匹配大文件（安装包残留、镜像、超大日志等）

规则路径可以任意深：`dirsizes.ps1` 一次 `$MFT` 解析就能给出任意深度目录的精确体积，加一条深层规则不会让归因变慢。

## 测试

```powershell
& "$S\scripts\selftest.ps1"     # 约 1 分钟
# 末行：SELFTEST pass=55 fail=0 skip=0 / RESULT-PASS
```

覆盖：增长对比与 root/depth 匹配、引擎一致性标记（同引擎 / 跨引擎 / 无历史三态）、首次运行无历史、体积计算正确性（对已知 3 MB 文件）、System32 必须被拒绝、盘符根子目录必须被拒绝、批量上限、dry-run 零删除、无 `-Confirmed` 不动手、规则通配符解析、文件名规则去重、随包规则文件结构校验、脚本纯 ASCII 校验、`MftScan.cs` 可编译、非卷根参数被拒、MFT 测尺对已知目录给出正确体积、`-Engine walk` 被尊重、两种测尺引擎不改变 findings 集合。

缺管理员权限时，MFT 相关断言报 `SKIP` 而不是 `FAIL` —— 换一台没有权限的机器也必须能跑通。

## 已知边界

- **仅支持 Windows**，依赖 PowerShell 5.1+（Windows 10 / 11 / Server 2016+ 均自带）
- **`mft` 引擎需要管理员权限 + NTFS 卷 + 卷根作为 `-Root`**，否则自动降级为遍历；降级原因记在快照的 `engineNotes`
- **`WinSxS` 显示体积远大于真实占用** —— 它与 System32 通过硬链接共享文件，而两个引擎都按**目录项**计数，所以共享文件被计两次（本机额外的目录项有 27.7 万个）。报告里必须说明，否则容易让人误以为删掉能省十几 GB
- **`$MFT` 解析的三个现实坑**（已在 2026-10 修复，勿回退）：
  - 基记录被长盘区表占满时，`$FILE_NAME` 会被挤到扩展记录里。"基记录没有 `$FILE_NAME`" 不等于文件不存在 —— 若直接跳过该记录，整棵子树上的文件名与体积会一起消失（本机实测因此漏掉过一个 1.1 GB 文件）
  - 一个记录里可能有多个 `$DATA`：最低 VCN 那个带真实大小，续段报 0。必须取最大值，否则真大小被 0 覆盖
  - `$DATA` 头里 `0x30` 是分配大小、`0x38` 是逻辑大小。walker 与资源管理器都用逻辑大小，取 `0x38` 两个引擎口径才一致（压缩 / 稀疏文件差异可达 40%）
- **无管理员权限时**，`System Volume Information`（系统还原点）等目录无法统计，会记入 `errorCount` 而非崩溃
- **超长路径**（> 260 字符）在回收站操作时可能失败，会记录在结果里
- 脚本固定使用 `\\?\` 前缀处理长路径，纯 ASCII 书写（PowerShell 5.1 会按 ANSI 代码页解析无 BOM 的 `.ps1`）

## English

**windows-disk-audit** is a zero-dependency Windows disk-space auditing skill written in pure PowerShell 5.1.

It answers the question most disk tools miss: *not just "what is big", but "what has been silently growing"*. It takes a read-only snapshot, attributes space using a rule library, and diffs against the previous snapshot to produce a growth ranking. Anomaly detection flags any cache directory above 5 GB — the usual culprit behind a mysteriously shrinking system drive.

On NTFS it parses the Master File Table directly, so a full-volume scan of 1.4 million files takes **6 seconds instead of 274** and returns exact data. Without administrator rights it falls back to a directory walk automatically, records why in `engineNotes`, and everything else works the same — just slower. A second pass over the same MFT measures the rule library's matched directories, which brings the attribution step from 94 seconds down to 8.

Cleanup is optional and deliberately conservative: nothing is ever deleted during collection, every single path must be confirmed explicitly (`-Confirmed`), deletions go to the Recycle Bin, at most 10 items per batch, and system-critical paths are refused outright.

Run `scripts/selftest.ps1` for the 55-assertion regression suite.
