---
name: windows-disk-audit
description: Windows 磁盘空间体检与清理建议。触发词：C盘满了、磁盘空间不足、C盘越来越小、空间去哪了、哪个目录占空间、磁盘占用分析、清理C盘、磁盘体检、disk space audit、free up disk space。流程：只读扫描（默认直读 NTFS $MFT，秒级；无管理员权限时自动退化为目录遍历）→ 规则库归因分级 → 与上次快照做增长对比 → 对话内输出中文报告 → （可选）经用户逐项确认后把可清理项移入回收站。纯 PowerShell 5.1 实现，零外部依赖。
agent_created: true
---

# 磁盘空间体检（Windows）

## Overview

诊断「磁盘为什么被占满、什么在快速变大、哪些能删」。核心是三段式：

1. **采集**（`scripts/scan.ps1`）—— 只读遍历，输出 JSON 快照，**永不删除任何文件**
2. **归因**（`scripts/analyze.ps1`）—— 用规则库匹配可清理项、分级、与上次快照对比出增长榜、标记异常膨胀
3. **报告** —— 由 agent 在**对话内**输出中文表格（不自动生成 HTML 文件）
4. **清理**（`scripts/clean.ps1`，可选）—— 仅在用户逐项确认后执行，走回收站

**设计原则一：规则与代码分离。** 可清理项是一张 JSON 规则表（`rules/caches.json`），新增膨胀点只改数据、不改脚本。

**设计原则二：两套引擎，同一份数据形状。** 采集与测尺都有 `mft` / `walk` 两条路径，输出的快照和分析结构完全一致：

| 引擎 | 原理 | 需要 | 全盘耗时（实测 1.39M 文件 / 152 GB） |
|---|---|---|---|
| `mft`（默认优先） | 直接解析 NTFS 主文件表 | Windows 管理员权限 + NTFS 卷 + 卷根作为 `-Root` | 采集 **6 秒**、规则测尺 **6 秒** |
| `walk`（兜底） | 逐目录遍历 | 无（任何文件系统、任何权限） | 采集 **274 秒**、规则测尺 **94 秒** |

`-Engine auto`（默认）会优先用 `mft`，失败时**逐个 root 静默降级**到 `walk` 并把原因写进快照的 `engineNotes`。所以：**没有管理员权限也能用，只是慢**。降级原因要如实告诉用户，不要隐瞒。

## 目录结构

```
windows-disk-audit/
├── SKILL.md
├── README.md              # 面向 GitHub 的项目说明
├── rules/
│   ├── caches.json        # 可清理规则库（含 risk / category / cleanHint）
│   └── never-touch.json   # 红线目录，clean.ps1 的硬校验依据
├── scripts/
│   ├── scan.ps1           # 只读采集（-Engine mft|walk|auto）
│   ├── analyze.ps1        # 归因 + 分级 + 增长对比 + 异常检测
│   ├── dirsizes.ps1       # 规则路径的定向测尺：一次 $MFT 解析给出几十个目录的体积
│   ├── MftScan.cs         # NTFS $MFT 解析器（C#，由 scan.ps1 / dirsizes.ps1 用 Add-Type 编译）
│   ├── clean.ps1          # 移入回收站（需 -Confirmed）
│   └── selftest.ps1       # 自检：59 项断言，全在临时目录里跑，不碰真实数据
├── references/
│   └── report-format.md   # 对话内报告模板
└── fixtures/
    ├── sample-history/    # 回归测试用的两份假快照（含时间差，用于验证增长对比）
    └── test-rules.json    # 空规则集，让自检与真实磁盘内容解耦
```

**代码与数据分离**：skill 目录只放只读代码；所有运行期产物写到数据根 `DISK_AUDIT_HOME`（默认 `~/.disk-audit`），快照存 `history/`。

## 运行前解析路径

不要把 skill 绝对路径写死。先解析一次：

```powershell
$S = if (Test-Path (Join-Path $env:USERPROFILE '.workbuddy\skills\windows-disk-audit')) {
       Join-Path $env:USERPROFILE '.workbuddy\skills\windows-disk-audit'
     } else { <实际所在目录> }
```

数据根同名环境变量可覆盖：`$env:DISK_AUDIT_HOME`。

## Workflow

### Step 1 — 采集（只读）

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& "$S\scripts\scan.ps1" -Root 'C:\' -Depth 3
```

- 不传 `-Root` 时扫描所有固定磁盘。
- `-Engine` 可强制 `mft` / `walk` / `auto`（默认）。**判断"能不能用 MFT"要让脚本自己做**，不要凭感觉传 `-Engine mft`：没有管理员权限时它会抛错并降级，白白多一步。
- 耗时预期：MFT 引擎全盘约 **6 秒**；退化为遍历时 100 GB 量级需 **4-5 分钟**，属正常 I/O 耗时。需要快速定位时先用 `-Root 'C:\Users'` 缩小范围。
- 输出末尾一行 `RESULT <json路径> totalMB=... roots=1 engine=mft seconds=6.2`，把该路径记下来给 Step 2。
- 快照默认落在 `$env:DISK_AUDIT_HOME\history\scan-<时间戳>.json`。
- 用 MFT 时快照里还会有 `engine`、`engineNotes`、`mftRecords`、`mftHardLinkEntries`、`mftOrphans` 字段，报告里可用于解释口径（见「已知边界」）。

### Step 2 — 归因

```powershell
& "$S\scripts\analyze.ps1" -Snapshot '<上一步的json路径>'
```

输出 `RESULT <analysis json> findings=... safeMB=... cautionMB=... growth=... anomalies=... engine=... sizeSource=...`。

把 analysis JSON 读进来，按 `findings` / `growth` / `anomalies` / `neverTouch` 组织报告。

**关于 `sizeSource`**：`mft` 表示各规则的目录体积来自一次 $MFT 解析（默认，快）；`walk` 表示逐目录遍历（慢约 10 倍，但同样准确）。降级原因在 `sizeNotes` 里，需要时如实告知用户。可用 `-SizeEngine walk` 强制走遍历做交叉验证。

**关于 `comparison`（跨引擎对比，必须遵守）**：

```json
"comparison": {
  "engine": "mft", "previousEngine": "walk",
  "engineMismatch": true, "noteCode": "engine-mismatch",
  "currentTotalMB": 151739, "previousTotalMB": 152068, "totalDeltaMB": -937,
  "note": "Previous snapshot used engine=walk but this one used engine=mft. ..."
}
```

| `noteCode` | 含义 | 报告写法 |
|---|---|---|
| `comparable` | 两次同引擎，数字可直接比 | 正常给增长榜 |
| `engine-mismatch` | 两次引擎不同，存在约 1% 的口径差 | **必须说明**："本次与上次用的采集引擎不同，总量差 ~1% 是口径差不是真实变化；目录级增长方向可信，2% 以内的 delta 视为噪声" |
| `no-previous` | 找不到可比的旧快照 | 明确说"本次为首次可比扫描，无增长数据"，**不要编造增长** |

`growth` 只会和**同 root、同 depth** 的上一次快照对比。所以扫过 `C:\` 之后再单独扫 `C:\Users`，不会污染前者的增长榜 —— 但报告里要说明本次没有可比快照。

### Step 3 — 报告（对话内）

严格按 `references/report-format.md` 的结构在对话中输出中文报告。**默认不生成 HTML 文件**，除非用户明确要求。

必须包含的四块：
1. **空间去向** —— 各顶层目录体积
2. **为什么变快** —— `growth` 里的增长榜（首次运行无历史时说明本次不适用）
3. **可删清单** —— 按 `risk` 分 safe / caution 两档，每项给出体积与清理方式
4. **别删清单** —— 用 `neverTouch` 说明哪些不能动

`anomalies` 里的条目要单独醒目提示（这是发现"隐形大户"的关键）。

### Step 4 — 清理（可选，需用户确认）

先给用户看清单，等其明确选择后再执行。**不超过 10 项一批。**

```powershell
# 预览，不删除
& "$S\scripts\clean.ps1" -Analysis '<analysis json>' -FindingIds 'chrome-service-worker','npm-cache' -DryRun

# 用户确认后
& "$S\scripts\clean.ps1" -Analysis '<analysis json>' -FindingIds 'chrome-service-worker','npm-cache' -Confirmed
```

- 只有 `cleanMode` 为 `delete-dir` / `purge-contents` 的项能自动执行；`command` / `manual` 只能给用户操作指引。用 `-Analysis -FindingIds` 时会自动跳过后两类。
- 也可改用计划文件：`-Plan <json>`，格式 `{"items":[{"path":"...","mode":"delete-dir|purge-contents","id":"..."}]}`。`mode` 只接受这两个值，其余一律拒绝。
- 清理后提醒用户：文件在**回收站**里，确认无误后再清空。

## 安全红线（硬约束，任何情况下不得放宽）

1. **采集阶段永不删除**，scan.ps1 只读。
2. 删除前必须**逐项列出具体路径**并取得用户明确同意；未传 `-Confirmed` 时 clean.ps1 一定不动手。
3. **一律走回收站**，禁止 `rm` / `del` / `rmdir`。
4. `rules/never-touch.json` 里的目录、盘符根目录、含受保护路径段的路径，clean.ps1 **直接拒绝执行**，包括 System32、WinSxS、Fonts、Program Files、用户文档目录等。
5. **单批不超过 10 项**，超出直接报错退出。
6. 不调用任何第三方「清理大师」，不修改注册表，不碰服务与计划任务。
7. 用户说"先别删"时，只跑 Step 1-3，绝不进入 Step 4。

## 扩展规则库

发现新的膨胀点后，往 `rules/caches.json` 的 `rules` 数组加一条即可，无需改脚本：

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

- `paths` 支持 `%ENVVAR%` 与单段通配符 `*`（只匹配一层目录名）。
- `cleanMode`：`delete-dir` 整目录删除｜`purge-contents` 清空内容保留目录｜`command` 需执行命令｜`manual` 需人工处理。
- `risk`：`safe` 删了只是首次稍慢｜`caution` 可能是数据或影响功能｜`never` 禁止删除。
- `fileRules` 用于按文件名规则匹配大文件（安装包残留、镜像、超大日志等）。

规则路径**不需要**在意深浅：`dirsizes.ps1` 会为任意深度的目录算出精确体积（一次 $MFT 解析，与深度无关），所以加一条深层缓存规则不会让 analyze 变慢。

## 环境约束（本机实测踩坑，务必遵守）

| 约束 | 说明 |
|---|---|
| 脚本必须纯 ASCII | PS 5.1 按 ANSI 代码页解析无 BOM 的 .ps1，中文注释会引发 ParseException。中文只放在 rules JSON、references 和对话报告里。**临时探针脚本同样适用** |
| 执行策略 | 运行前先 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` |
| 不要用 `du` 扫盘 | git-bash 的 `du` 会跟随 junction 无限递归，表现为长时间零输出 |
| 不要用 robocopy 算体积 | 中文版 Windows 的汇总行是本地化标签，正则解析会失败 |
| 一次遍历聚合 | 逐目录重复遍历是 O(n²)；walk 引擎用「一次遍历 + 哈希表按深度聚合」，mft 引擎用「一次解析 + 子树求和」 |
| 跳过 reparse point | walk 引擎必须跳过，否则会在 junction 上死循环 |
| 不要把宿主 stdout 交给子脚本 | 子脚本的 `RESULT` 行会污染调用方的输出（analyze 调 dirsizes 时用子进程 + 丢弃输出） |
| `@($genericList)` 是雷 | 在 `[pscustomobject]@{...}` 里用 `@($list)` 包住泛型 List 会让转换抛 `ArgumentException: 参数类型不匹配`（PS 5.1）。改用 `$list.ToArray()` |
| 不要用 `$home` 当普通变量 | `$home` 是只读自动变量，赋值会静默失败，导致路径写错地方 |
| 一条规则内的多个 pattern 可能命中同一目录 | `%TEMP%` 与 `%LOCALAPPDATA%\Temp` 在 Windows 上就是同一个目录。analyze 在**规则内**按规范化路径去重；不去重的话该 finding 的体积和 `matchCount` 都会翻倍（shipped 的 `user-temp` 曾把 1,596 MB 的 Temp 报成 3,192 MB）。规则文件保留两条是对的 —— `%TEMP%` 被重定向时二者确实是两个目录，所以要在代码里去重而不是删规则 |
| 数组字面量里的 `+` 会被逗号抢先 | `@($a, $b + '\x*')` 在 PowerShell 里解析成**三个**元素（`, ` 优先级高于 `+`），会静默多测一个父目录。拼接字符串先赋给变量再放进数组 |

## 验证方式

一键自检（约 1 分钟，全部在临时目录内运行，不碰真实数据）：

```powershell
& "$S\scripts\selftest.ps1"
```

末行输出 `SELFTEST pass=59 fail=0 skip=0` 或 `RESULT-FAIL`。缺管理员权限时 MFT 相关断言会报 `SKIP` 而不是 `FAIL`（这是刻意的：**换一台没有管理员权限的机器也必须能跑通**）。

覆盖范围：增长对比、增长对比的 root/depth 匹配、引擎一致性标记（同引擎 / 跨引擎 / 无历史三态）、首次运行无历史、体积计算正确性、System32 拒绝、盘符根子目录拒绝、批量上限、dry-run 不删除、无 `-Confirmed` 不执行、规则通配符解析、文件名规则匹配与去重、随包规则文件结构校验、脚本纯 ASCII 校验、`MftScan.cs` 可编译、非卷根参数被拒、MFT 测尺对已知目录给出正确体积、`-Engine walk` 被尊重、两种测尺引擎不改变 findings 集合、同一条规则内重叠 pattern 只计一次（T16）。

改动脚本后至少跑一次「全新环境」验证：

1. 换一个干净 cwd（如临时目录），不要用 skill 目录本身。
2. `$env:DISK_AUDIT_HOME` 指向空目录，模拟首次执行（无历史 → 增长对比应为空且不报错）。
3. **非管理员权限**运行，确认 `mft` 降级为 `walk`、`engineNotes` 有原因、权限失败计入 `errorCount` 而不是脚本崩溃。
4. 非 C 盘系统盘、用户名不是 Administrator 的机器上验证路径解析不依赖硬编码。

## 已知边界

- 仅支持 Windows。`mft` 引擎额外要求 NTFS + 管理员权限，否则自动降级为 `walk`。
- **两个引擎都按「目录项」计数**：一个文件若有 2 个硬链接（例如 WinSxS 与 System32 共享），会被计两次。因此 `WinSxS` 显示体积远大于真实占用，报告里必须说明，不能让用户以为删了能省 12 GB。快照里的 `mftHardLinkEntries` 就是超出基记录的额外目录项数量（本机 27.7 万）。
- **`$MFT` 解析的现实坑**（已在 2026-10 修复，勿回退）：
  - `$FILE_NAME` 可能被挤到扩展记录里（基记录被长盘区表占满时）。**基记录没有 `$FILE_NAME` 不等于文件不存在**，必须仍标记为存活节点，否则会丢掉整棵树上的文件名与体积（本机实测因此漏掉过一个 1.1 GB 文件）。
  - 一个记录里可能有多个 `$DATA`：最低 VCN 那个带真实大小，续段报 0。要取**最大值**，否则真大小会被 0 覆盖。
  - `$DATA` 的 `0x30` 是分配大小、`0x38` 是逻辑大小。walker 与资源管理器都用逻辑大小，取 `0x38` 才能两个引擎口径一致（压缩/稀疏文件差异可达 40%）。
- 无管理员权限时，`System Volume Information`（系统还原点）与部分系统目录无法统计，会体现在 `errorCount` 里。
- 回收站清理依赖 SHFileOperation，超长路径（>260 字符）可能失败，会记录在结果里。
