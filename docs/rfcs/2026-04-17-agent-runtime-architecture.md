# RFC: Cliq Agent Runtime Architecture

**Status:** Proposed  
**Author:** Architecture Draft  
**Date:** 2026-04-17  
**Decision Type:** Architecture  
**Audience:** Core maintainers and contributors

---

## 1. Summary

Cliq 已经完成了一个真实可运行的最小 agent 闭环，但当前实现仍属于单进程、本地优先的实验 harness，而不是可持续扩展的 agent runtime。

本 RFC 提议将 Cliq 的下一阶段目标明确为：

> 把 Cliq 演进成一个以 runtime 为中心的内核，  
> 让 CLI 只是第一个交互表面，而不是系统本身。

为达成这个目标，系统需要从当前的单体脚本结构，演进为由指令层、runtime/tool 层、策略层、会话层和 surface 层组成的分层架构。

---

## 2. Context

当前项目的优点很明确：

- 已有完整的 `user -> model -> action -> tool -> feedback -> final message` 闭环
- 使用 provider-agnostic 的 JSON-over-text 协议，便于调试和迁移
- 有本地 session 持久化与 replay
- 已有精确文本替换型 `edit` primitive，而不是把所有修改都压给 shell

但当前结构也存在明显瓶颈：

- 主要逻辑集中在单一入口文件
- 协议表达力有限，导致大量只读和辅助行为被迫走 `bash`
- 没有能力分发机制，新增功能会直接回写核心
- session 主要是线性记录，还不是工作流资产
- CLI 是唯一宿主，没有 headless / SDK / service 入口
- 策略、权限、沙箱没有独立挂载点
- 观测、审计、上下文治理不足

如果继续在现有结构上直接叠加 action、mode 或 UI，系统会快速演变成硬编码沼泽。

---

## 3. Problem Statement

Cliq 当前最大的问题不是“功能少”，而是“宿主结构没有为持续增长准备好”。

具体来说：

1. `protocol`、`tool execution`、`session`、`CLI`、`policy` 还没有明确边界。
2. 新增能力的主要方式仍然是修改核心源码，而不是接入外围模块。
3. inspection、mutation、approval、logging、resume 等运行时关注点被混在一个循环中。
4. 没有一套稳定的架构骨架来承载未来的 read-only tools、skills、extensions、automation、RPC 和 richer UX。

---

## 4. Goals

本 RFC 的目标是定义一个中期稳定的架构方向，而不是一次性实现全部能力。

### 4.1 Primary Goals

- 将当前单体 harness 重构为清晰分层的 runtime 内核
- 将 tool system 从当前的协议分支逻辑中抽离出来
- 为策略层、扩展层和多宿主表面预留稳定接口
- 将 session 从“线性聊天记录”逐步演进为“工作流上下文资产”
- 明确后续阶段的演进顺序，避免无序扩展

### 4.2 Non-Goals

本 RFC 不要求在本轮直接实现：

- 完整 TUI / workbench
- 多 agent 调度
- 完整 RPC/SDK 产品化
- 完整 permission/sandbox 系统
- 完整 session tree、fork UI、compaction 策略

这些能力属于后续阶段，但本 RFC 会为它们定义落点。

---

## 5. Design Principles

### 5.1 Runtime First

先稳定 runtime 边界，再增加新能力。  
任何新功能如果需要直接修改主循环的大量条件分支，都说明架构落点不正确。

### 5.2 Tool System Over Protocol Growth

优先建设 tool registry、schema、lifecycle、result model 和 policy hooks，  
而不是仅靠往 JSON 顶层继续加 key。

### 5.3 Policies Are Not Tools

工具只负责能力本身。  
是否允许执行、是否需要确认、是否允许访问某路径，应由独立策略层负责。

### 5.4 CLI Is A Surface, Not The Kernel

CLI 是当前首个宿主，但不是系统边界。  
后续的非交互执行、服务模式、UI 和自动化都应复用同一个 runtime。

### 5.5 Sessions Are Workflow Assets

session 不应只承担连续对话存档功能；它还应承担 resume、fork、compact、handoff、audit 和 workflow continuity。

### 5.6 Growth Should Happen At The Edges

新增 skill、hook、prompt、integration、tool package 时，应尽量发生在外围装配层，而不是回写核心。

---

## 6. Proposed Architecture

### 6.1 Layer Model

目标架构分为五层：

1. **Instruction Layer**
2. **Runtime and Tool Layer**
3. **Policy and Governance Layer**
4. **Session and Context Layer**
5. **Surface Layer**

### 6.2 Instruction Layer

这一层负责构造模型实际看到的指令上下文，至少应区分：

- system/product instruction
- user prompt
- repo instruction
- local or team memory
- skill prompt
- hook 注入上下文

这一层解决的是“agent 应该遵守什么”和“这些规则从哪里来”的问题。

### 6.3 Runtime and Tool Layer

这一层是系统核心，负责：

- turn runner
- model client abstraction
- action parsing
- tool registry
- tool execution lifecycle
- structured tool result
- event emission

在该层中，`bash` 和 `edit` 只是两个 tool definition，不再是主循环里的硬编码分支。

### 6.4 Policy and Governance Layer

这一层负责：

- permission mode
- read-only mode
- write confirmation
- command trust policy
- path access policy
- sandbox policy
- audit hooks

其职责是决定“能不能执行”，而不是“怎么执行”。

### 6.5 Session and Context Layer

这一层负责：

- session persistence
- replay model
- checkpoints
- fork/resume
- compaction records
- handoff artifacts
- context budget tracking

在短期内，session 仍可保持线性结构；但 record model 必须为 future fork/compact 预留演进空间。

### 6.6 Surface Layer

这一层负责：

- interactive CLI
- non-interactive exec
- future RPC or JSONL stream
- future app / UI / IDE integrations

不同 surface 共享同一个 runtime 内核，不应复制执行逻辑。

---

## 7. Target Runtime Boundaries

短期内建议将核心代码拆分为以下边界：

- `config`
- `prompt`
- `protocol`
- `model`
- `tools`
- `runtime`
- `session`
- `cli`

它们的职责如下：

- `protocol`: action schema、解析、版本兼容
- `model`: provider client 和 completion 接口
- `tools`: tool definitions、registry、tool contracts
- `runtime`: turn runner、hooks、event flow
- `session`: session types、store、migration、append/save/load
- `prompt`: system prompt 与后续 instruction composition
- `cli`: 参数解析、REPL、输出渲染

这一步的意义不在于“目录变多”，而在于把未来所有增长点放到正确的边界上。

---

## 8. Capability Gaps To Address

当前最需要补齐的不是更多 mutation 工具，而是结构化只读与系统治理能力。

### 8.1 Immediate Gaps

- structured read-only tools
- policy modes
- hook lifecycle
- instruction sources
- event stream

### 8.2 Medium-Term Gaps

- session checkpoint / fork / compact
- RPC / SDK / service mode
- richer execution telemetry
- extension and skill packaging

### 8.3 Later Gaps

- automation
- worktree-aware execution
- multi-agent orchestration
- richer workbench UX

---

## 9. Delivery Phases

### Phase 0: Runtime Kernel Foundation

**Purpose:** 停止单体入口继续膨胀，并建立最小可扩展内核。  
**Scope:** 只做边界重构，不主动增加新能力。

内容包括：

- 拆出 `session / protocol / model / tools / runtime / cli`
- 建立 tool registry
- 建立 runner 与 hook pipeline
- 让 CLI 依赖 runtime，而不是承载 runtime
- 为核心模块补最小测试

**Explicitly excluded from Phase 0:**

- 新的工具类型
- approval modes
- richer UI
- RPC/SDK
- session fork/compact 功能实现

### Phase 1: Structured Read Tools And Policy Modes

补齐 `read / ls / find / grep` 等只读工具，并建立最小策略模式：

- `auto`
- `confirm-write`
- `read-only`
- `confirm-bash`
- `confirm-all`

### Phase 2: Instruction, Hooks, Skills, Extensions

补 instruction composition、hook lifecycle、skill loading、extension discovery 与安装入口。

### Phase 3: Session As Workflow Asset

引入 checkpoint、fork、compact、handoff 等工作流能力。

### Phase 4: Headless Runtime Interfaces

提供非交互执行、结构化事件流和最小 RPC/JSONL 协议。

### Phase 5: Observability And Governance

补 event stream、cost/token tracking、audit、export、debug/replay。

### Phase 6: Automation, Worktrees, Rich UX

在 runtime 稳定后再补 automation、worktree isolation、multi-surface UX。

---

## 10. Phase 0 vs Execution Plan

本 RFC 中的 **Phase 0** 是一个**架构阶段定义**，回答的是：

- 为什么先做 runtime kernel foundation
- 这一阶段的边界是什么
- 哪些内容此时不做

而现有文件：

- [2026-04-17-runtime-kernel-foundation.md](../superpowers/plans/2026-04-17-runtime-kernel-foundation.md)

是 **Phase 0 的执行计划**，回答的是：

- 具体拆哪些文件
- 每一步先写什么测试
- 哪些命令验证通过
- 按什么顺序实施

两者不是冲突关系，而是：

- RFC 定义方向与边界
- Execution Plan 定义落地步骤

因此，在本 RFC 范围内，该执行计划仍然适用，不应删除；但应明确标注它是 Phase 0 的执行计划，而不是总路线图。

---

## 11. Risks

### 11.1 Over-Refactoring Risk

如果在 Phase 0 同时引入新工具、新 UI、新策略模式，重构范围会失控，验证成本也会显著上升。

### 11.2 False Modularity Risk

如果只是拆文件，但没有建立稳定接口和职责边界，系统会退化成“分文件的单体”。

### 11.3 Surface Coupling Risk

如果 CLI 仍然保留 runtime 决策逻辑，后续 headless 化和多宿主支持仍会受阻。

### 11.4 Policy Leakage Risk

如果 permission/path policy 直接写进 tool 逻辑，后续治理会非常难拆。

---

## 12. Acceptance Criteria

本 RFC 被认为收敛完成，需要满足：

- 有一个单一、明确的目标架构描述
- Phase 0 到 Phase 6 的边界清晰
- Phase 0 与执行计划的关系清楚，不重复、不冲突
- 文档不再依赖外部产品命名来解释自身方向
- 维护者可以据此继续写更细的 plan 或直接开始 Phase 0 实施

---

## 13. Decision

建议采纳本 RFC 作为当前架构演进的唯一基线文档。

同时采用以下配套整理原则：

- 保留 Phase 0 执行计划，并明确其从属于本 RFC
- 移除旧的路线图文档，避免“路线图”和“RFC”并行造成语义重复
- 后续所有实施计划都以本 RFC 的 phase 边界为准
