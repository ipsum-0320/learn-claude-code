#!/usr/bin/env python3
# Harness: all mechanisms combined -- the complete cockpit for the model.
"""
s_full.py - Full Reference Agent

Capstone implementation combining every mechanism from s01-s11.
Session s12 (task-aware worktree isolation) is taught separately.
NOT a teaching session -- this is the "put it all together" reference.

    +------------------------------------------------------------------+
    |                        FULL AGENT                                 |
    |                                                                   |
    |  System prompt (s05 skills, task-first + optional todo nag)      |
    |                                                                   |
    |  Before each LLM call:                                            |
    |  +--------------------+  +------------------+  +--------------+  |
    |  | Microcompact (s06) |  | Drain bg (s08)   |  | Check inbox  |  |
    |  | Auto-compact (s06) |  | notifications    |  | (s09)        |  |
    |  +--------------------+  +------------------+  +--------------+  |
    |                                                                   |
    |  Tool dispatch (s02 pattern):                                     |
    |  +--------+----------+----------+---------+-----------+          |
    |  | bash   | read     | write    | edit    | TodoWrite |          |
    |  | task   | load_sk  | compress | bg_run  | bg_check  |          |
    |  | t_crt  | t_get    | t_upd    | t_list  | spawn_tm  |          |
    |  | list_tm| send_msg | rd_inbox | bcast   | shutdown  |          |
    |  | plan   | idle     | claim    |         |           |          |
    |  +--------+----------+----------+---------+-----------+          |
    |                                                                   |
    |  Subagent (s04):  spawn -> work -> return summary                 |
    |  Teammate (s09):  spawn -> work -> idle -> auto-claim (s11)      |
    |  Shutdown (s10):  request_id handshake                            |
    |  Plan gate (s10): submit -> approve/reject                        |
    +------------------------------------------------------------------+

    REPL commands: /compact /tasks /team /inbox
"""

import json
import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path
from queue import Queue

from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv(override=True)
if os.getenv("ANTHROPIC_BASE_URL"):
    os.environ.pop("ANTHROPIC_AUTH_TOKEN", None)
# 从 .env 文件中读取 API 密钥、模型 ID 等敏感信息。

WORKDIR = Path.cwd()
# 获取当前 Python 脚本运行时的工作目录（Current Working Directory）。
# Agent 之后所有的文件操作（读写代码、创建 .tasks 文件夹、存放进度）都会以这个路径为基准。
client = Anthropic(base_url=os.getenv("ANTHROPIC_BASE_URL"))
MODEL = os.environ["MODEL_ID"]


TEAM_DIR = WORKDIR / ".team"
INBOX_DIR = TEAM_DIR / "inbox"
TASKS_DIR = WORKDIR / ".tasks"
SKILLS_DIR = WORKDIR / "skills"
TRANSCRIPT_DIR = WORKDIR / ".transcripts"
# TEAM_DIR & INBOX_DIR：Agent 之间的通讯中心。它们通过在磁盘上读写文件来互相发消息，而不是通过内存，这样更稳定且可追溯。
# TASKS_DIR：持久化存储任务状态的地方，确保 Agent 重启后还能记得没干完的活。
# SKILLS_DIR：存放 Agent 可以调用的工具脚本或自定义能力。
# TRANSCRIPT_DIR：记录 Agent 所有的聊天记录（Transcript），用于后续的“自我压缩”和回溯。

TOKEN_THRESHOLD = 100000 # 触发对话压缩的 Token 上限
POLL_INTERVAL = 5 # 检查新消息的时间间隔（5秒）
IDLE_TIMEOUT = 60 # 判定为闲置的超时时间


VALID_MSG_TYPES = {"message", "broadcast", "shutdown_request",
                   "shutdown_response", "plan_approval_response"}
# 通信协议的定义，用于 send_message tool，定义了消息总线中允许的消息类型。
#   │ message                │ 普通点对点消息         │
#   ├────────────────────────┼────────────────────────┤
#   │ broadcast              │ 广播消息（发给所有人） │
#   ├────────────────────────┼────────────────────────┤
#   │ shutdown_request       │ 关机请求               │
#   ├────────────────────────┼────────────────────────┤
#   │ shutdown_response      │ 关机响应               │
#   ├────────────────────────┼────────────────────────┤
#   │ plan_approval_response │ 计划审批结果           │
#   └────────────────────────┴────────────────────────┘
# 用途是发送消息时会验证类型必须在这个集合中，防止无效的消息类型。

# === SECTION: base_tools ===
def safe_path(p: str) -> Path:
    # 定义一个路径安全检查函数，输入字符串路径，返回 Path 对象。
    path = (WORKDIR / p).resolve()
    # 将相对路径 p 与工作目录 WORKDIR 拼接，并解析为绝对路径。
    if not path.is_relative_to(WORKDIR):
        raise ValueError(f"Path escapes workspace: {p}")
        # 检查路径是否在 WORKDIR 内，防止路径穿越攻击（如 ../../etc/passwd）。
    return path

def run_bash(command: str) -> str:
    # 定义 bash 命令执行函数。
    dangerous = ["rm -rf /", "sudo", "shutdown", "reboot", "> /dev/"]
    # 定义危险命令关键词黑名单。
    if any(d in command for d in dangerous):
        # 如果命令包含任一危险关键词，直接拒绝执行。
        return "Error: Dangerous command blocked"
    try:
        r = subprocess.run(command, shell=True, cwd=WORKDIR,
                           capture_output=True, text=True, timeout=120)
        # 执行命令，120 秒超时，捕获输出。
        out = (r.stdout + r.stderr).strip()
        # 合并 stdout/stderr，截断到 50000 字符，无输出返回 "(no output)"。
        return out[:50000] if out else "(no output)"
    except subprocess.TimeoutExpired:
        return "Error: Timeout (120s)"

def run_read(path: str, limit: int = None) -> str:
    # 定义文件读取函数。
    try:
        lines = safe_path(path).read_text().splitlines()
        # 安全读取文件，按行分割。
        if limit and limit < len(lines):
            lines = lines[:limit] + [f"... ({len(lines) - limit} more)"]
            # 如果限制了行数且文件更长，截断并显示剩余行数。
            # ⭐️⭐️⭐️⭐️⭐️ Agent 开发的核心就是把 Agent 当做协作者，有什么问题都通过自然语言及时暴露给它。
        return "\n".join(lines)[:50000]
        # 重新合并成字符串，截断到 50000 字符。 
    except Exception as e:
        return f"Error: {e}"

def run_write(path: str, content: str) -> str:
    # 定义文件写入函数。
    try:
        fp = safe_path(path)
        fp.parent.mkdir(parents=True, exist_ok=True)
        # 创建父目录（如不存在）。
        fp.write_text(content)
        return f"Wrote {len(content)} bytes to {path}"
        # 写入内容，返回字节数。
    except Exception as e:
        return f"Error: {e}"

def run_edit(path: str, old_text: str, new_text: str) -> str:
    # 定义文件编辑函数（字符串替换）。
    try:
        fp = safe_path(path)
        c = fp.read_text()
        if old_text not in c:
            # 读取文件内容，如果找不到 old_text 则报错。
            return f"Error: Text not found in {path}"
        fp.write_text(c.replace(old_text, new_text, 1))
        # 执行一次替换（replace(..., 1) 只替换第一个匹配），返回成功。
        return f"Edited {path}"
    except Exception as e:
        return f"Error: {e}"



class TodoManager:
    # 定义 Todo 管理器类，负责维护一个短期的任务清单，供 LLM 在单次对话中追踪进度。
    def __init__(self):
        self.items = []
        # 初始化一个空列表，用来存储所有 todo 项。每个项是一个字典，包含 content、status、activeForm 三个字段。

    def update(self, items: list) -> str:
        # 创建/更新整个 todo 列表，注意是全量替换，不是增量更新——LLM 每次调用都要传入完整的列表。
        validated, ip = [], 0
        # validated 是验证通过后的新列表；ip 是 in_progress 状态的计数器，用于后面检查是否有多个任务同时进行。
        for i, item in enumerate(items):
        # 遍历 LLM 传来的每个 todo 项，i 是索引，用于报错时定位是第几个出问题。
            content = str(item.get("content", "")).strip()      
            # 取出 content 字段，转字符串并去掉首尾空格。用 .get() 防止字段缺失时报错。      
            status = str(item.get("status", "pending")).lower()
            # 取出 status 字段，默认值是 "pending"，转小写统一格式。
            af = str(item.get("activeForm", "")).strip()
            # 取出 activeForm 字段，这是当前正在执行的具体动作描述，比如 "正在运行测试"。
            if not content: raise ValueError(f"Item {i}: content required")
            # content 不能为空，否则这个 todo 没有意义。
            if status not in ("pending", "in_progress", "completed"):
                raise ValueError(f"Item {i}: invalid status '{status}'")
            # status 只允许三个合法值，防止 LLM 传入非法状态。
            if not af: raise ValueError(f"Item {i}: activeForm required")
            # activeForm 也不能为空，强制 LLM 描述每个 todo 的具体行动形式。
            if status == "in_progress": ip += 1
            # 每发现一个 in_progress 的项就计数加一。
            validated.append({"content": content, "status": status, "activeForm": af})
            # 验证通过后把规范化的字典追加进 validated 列表。
        if len(validated) > 20: raise ValueError("Max 20 todos")
        # 限制最多 20 个 todo，防止列表过长占用太多 token。
        if ip > 1: raise ValueError("Only one in_progress allowed")
        # 同一时间只允许一个任务处于 in_progress 状态，强制 LLM 专注于一件事。
        self.items = validated
        # 验证全部通过后，用新列表替换旧列表，然后调用 render() 返回格式化的字符串给 LLM 看。
        return self.render()

    def render(self) -> str:
        if not self.items: return "No todos."
        lines = []
        # 准备一个空行列表，逐项生成显示文本。
        for item in self.items:
            m = {"completed": "[x]", "in_progress": "[>]", "pending": "[ ]"}.get(item["status"], "[?]")
            # 根据状态选择对应的标记符号。"[?]" 是兜底值，理论上不会出现（因为 update() 已经验证过状态）。
            suffix = f" <- {item['activeForm']}" if item["status"] == "in_progress" else ""
            # 只有 in_progress 的项才在后面追加 activeForm，标注正在执行的具体动作。其他状态不显示。
            lines.append(f"{m} {item['content']}{suffix}")
            # 把标记、内容、后缀拼成一行，比如 [>] 修复登录 bug <- 正在编辑 auth.py。
        done = sum(1 for t in self.items if t["status"] == "completed")
        lines.append(f"\n({done}/{len(self.items)} completed)")
        # 统计已完成数量，在列表末尾追加进度汇总，比如 (2/5 completed)。
        return "\n".join(lines)
        # 把所有行用换行符连接成一个字符串返回。


    def has_open_items(self) -> bool:
        # 只要有任意一个 todo 的状态不是 "completed"，就返回 True。供 agent_loop 判断是否需要发送"别忘了更新 todo"的提醒。
        return any(item.get("status") != "completed" for item in self.items)

# 下面编写一个例子说明 TodoManager 的流程。
# ===================== 第一步：Claude 调用 TodoWrite 工具，传入这个列表。
# items = [
#     {"content": "写计算器主体函数", "status": "in_progress", "activeForm": "正在编写 calculator.py"},
#     {"content": "写加法函数",       "status": "pending",     "activeForm": "待实现 add()"},
#     {"content": "写减法函数",       "status": "pending",     "activeForm": "待实现 subtract()"},
#     {"content": "写乘法函数",       "status": "pending",     "activeForm": "待实现 multiply()"},
#     {"content": "写除法函数",       "status": "pending",     "activeForm": "待实现 divide()"},
#     {"content": "写单元测试",       "status": "pending",     "activeForm": "待编写 test_calculator.py"},
# ]

# **`render()` 输出：**
# [>] 写计算器主体函数 <- 正在编写 calculator.py
# [ ] 写加法函数
# [ ] 写减法函数
# [ ] 写乘法函数
# [ ] 写除法函数
# [ ] 写单元测试
# (0/6 completed)

# ===================== 第二步：完成几个函数后，Claude 再次调用 TodoWrite。
# items = [
#     {"content": "写计算器主体函数", "status": "completed",   "activeForm": "已完成"},
#     {"content": "写加法函数",       "status": "completed",   "activeForm": "已完成"},
#     {"content": "写减法函数",       "status": "completed",   "activeForm": "已完成"},
#     {"content": "写乘法函数",       "status": "completed",   "activeForm": "已完成"},
#     {"content": "写除法函数",       "status": "in_progress", "activeForm": "正在处理除零异常"},
#     {"content": "写单元测试",       "status": "pending",     "activeForm": "待编写 test_calculator.py"},
# ]

# **`render()` 输出：**
# [x] 写计算器主体函数
# [x] 写加法函数
# [x] 写减法函数
# [x] 写乘法函数
# [>] 写除法函数 <- 正在处理除零异常
# [ ] 写单元测试

# (4/6 completed)

# ===================== 第三步：全部完成。
# items = [
#     {"content": "写计算器主体函数", "status": "completed", "activeForm": "已完成"},
#     {"content": "写加法函数",       "status": "completed", "activeForm": "已完成"},
#     {"content": "写减法函数",       "status": "completed", "activeForm": "已完成"},
#     {"content": "写乘法函数",       "status": "completed", "activeForm": "已完成"},
#     {"content": "写除法函数",       "status": "completed", "activeForm": "已完成"},
#     {"content": "写单元测试",       "status": "completed", "activeForm": "已完成"},
# ]

# **`render()` 输出：**
# [x] 写计算器主体函数
# [x] 写加法函数
# [x] 写减法函数
# [x] 写乘法函数
# [x] 写除法函数
# [x] 写单元测试

# (6/6 completed)

# 如何理解 activeForm？
# activeForm 本质上是**"当前正在做的事情的具体描述"**，是对 status 的补充说明。当 LLM 在下一轮对话读到这条 todo 时，activeForm 能帮它快速回忆起上一轮自己做到哪里了，相当于一个自我提示便签。
# 我们可以将 activeForm 理解为某个 todo 项的任务进度。每次更新 activeForm 都必须经过一次完整的 LLM 交互。
# ⭐️⭐️⭐️⭐️⭐️ 从这里的设计我们也可以知道 Agent 的微观范式是 ReAct 的。

# 如下所示 ===>
# # 第1轮
# {"content": "修复登录 bug", "status": "in_progress", "activeForm": "正在阅读 session.py"}

# # 第2轮，content 和 status 没变，只有 activeForm 变了
# {"content": "修复登录 bug", "status": "in_progress", "activeForm": "发现 token 在第42行过期"}

# # 第3轮
# {"content": "修复登录 bug", "status": "in_progress", "activeForm": "正在修改 refresh_token()"}

# # 第4轮
# {"content": "修复登录 bug", "status": "in_progress", "activeForm": "正在跑回归测试"}

# # 第5轮，任务完成，status 才变
# {"content": "修复登录 bug", "status": "completed", "activeForm": "已完成"}



# === SECTION: subagent (s04) ===
def run_subagent(prompt: str, agent_type: str = "Explore") -> str:
    # 这段代码实现了一个子 Agent，是主 Agent 派生出来执行独立任务的"助手"。
    sub_tools = [
        {"name": "bash", "description": "Run command.",
         "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
        {"name": "read_file", "description": "Read file.",
         "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    ]
    # 所有子 Agent 都有的基础工具，只能读取和执行命令，不能修改文件。

    if agent_type != "Explore":
        sub_tools += [
            {"name": "write_file", "description": "Write file.",
             "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
            {"name": "edit_file", "description": "Edit file.",
             "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "old_text": {"type": "string"}, "new_text": {"type": "string"}}, "required": ["path", "old_text", "new_text"]}},
        ]
    # 如果不是 "Explore" 模式，才追加写文件和编辑文件的工具。这是一个权限控制机制。
    # Explore 只能读、只能跑命令；general-purpose 读写都可以。

    sub_handlers = {
        "bash": lambda **kw: run_bash(kw["command"]),
        "read_file": lambda **kw: run_read(kw["path"]),
        "write_file": lambda **kw: run_write(kw["path"], kw["content"]),
        "edit_file": lambda **kw: run_edit(kw["path"], kw["old_text"], kw["new_text"]),
    }
    # 子 Agent 自己的工具分发表，和主 Agent 的 TOOL_HANDLERS 是独立的，只包含文件操作相关的工具，没有 todo、任务管理、队友通信等功能。

    sub_msgs = [{"role": "user", "content": prompt}]
    resp = None
    # 初始化子 Agent 自己独立的对话历史，只有一条用户消息作为起点。resp 先设为 None，用于最后的兜底判断。

    for _ in range(30):
        # 这里的循环是会话的循环。
        # 最多循环 30 轮，防止子 Agent 陷入死循环无限消耗 token。
        resp = client.messages.create(model=MODEL, messages=sub_msgs, tools=sub_tools, max_tokens=8000)
        # 调用 LLM，注意这里没有传 system 参数，子 Agent 没有系统提示，比主 Agent 更轻量。
        sub_msgs.append({"role": "assistant", "content": resp.content})
        # 把 LLM 回复追加进子 Agent 自己的对话历史。
        if resp.stop_reason != "tool_use":
            # 如果 LLM 不再调用工具，说明任务完成，跳出循环。
            break

        results = []
        for b in resp.content:
            if b.type == "tool_use":
                h = sub_handlers.get(b.name, lambda **kw: "Unknown tool")
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": str(h(**b.input))[:50000]})
        # 执行所有工具调用，收集结果，回传给 LLM，继续下一轮。和主 Agent 的工具执行逻辑一样，但没有 todo 提醒、没有背景通知、没有压缩机制，更加精简。
        sub_msgs.append({"role": "user", "content": results})
        # Anthropic 的标准要求将 tool result 作为 user input 写入上下文。

    if resp:
        # 循环结束后，把最后一轮 LLM 回复中所有文本块拼接起来作为任务总结返回给主 Agent。如果 resp 是 None（一次都没跑成功），返回失败提示。
        return "".join(b.text for b in resp.content if hasattr(b, "text")) or "(no summary)"
    return "(subagent failed)"

# 需要注意，这里的 run_subagent 是一个完全串行的过程，执行过程如下：
# 主 Agent
#   │
#   ├─ 调用 run_subagent()   ← 主 Agent 在这里停住了
#   │      │
#   │      ├─ 第1轮 LLM 调用
#   │      ├─ 执行工具
#   │      ├─ 第2轮 LLM 调用
#   │      ├─ 执行工具
#   │      ├─ ...
#   │      └─ 返回总结字符串
#   │
#   └─ 收到总结，继续往下走   ← 主 Agent 才恢复

# 子 Agent 可以和 background_run 对比一下。

#          run_subagent           background_run
# 执行方式  串行，主 Agent 等待      并行，主 Agent 不等待
# 适合场景  需要结果才能继续的任务     不需要立即拿结果的任务
# 实现机制  普通函数调用             开新线程
# 结果获取  直接返回通过             drain() 异步获取

# 如果想要并行执行多个子 Agent，这套代码本身不支持。 需要改造成类似 BackgroundManager 的方式。所以 run_subagent 更适合用于必须拿到结果才能继续的场景，比如"先让子 Agent 探索代码库，再根据探索结果决定下一步怎么做"。

class SkillLoader:
    # 这段代码实现了一个技能加载器，负责管理 LLM 可以调用的专项知识库。
    # 下面需要先给出 Skill 的
    def __init__(self, skills_dir: Path):
        self.skills = {}
        # 初始化一个空字典，用来存储所有加载好的技能，key 是技能名，value 是包含 meta 和 body 的字典。
        if skills_dir.exists():
            for f in sorted(skills_dir.rglob("SKILL.md")):
                # 如果技能目录存在，递归搜索所有子目录下的 SKILL.md 文件。sorted() 保证加载顺序一致，不受文件系统排序影响。
                text = f.read_text()
                match = re.match(r"^---\n(.*?)\n---\n(.*)", text, re.DOTALL)
                # 读取文件内容，用正则表达式尝试匹配 Front Matter 格式。re.DOTALL 让 . 可以匹配换行符，因为元数据和正文都是多行的。
                meta, body = {}, text
                # 先给 meta 和 body 设默认值——如果没有 Front Matter，meta 是空字典，body 是整个文件内容。
                if match:
                    for line in match.group(1).strip().splitlines():
                        if ":" in line:
                            k, v = line.split(":", 1)
                            meta[k.strip()] = v.strip()
                            # 如果匹配成功，解析 --- 之间的元数据。split(":", 1) 只切第一个冒号，防止值里有冒号时切错，比如 url: https://example.com。
                    body = match.group(2).strip()
                    # 提取 --- 之后的正文内容。
                name = meta.get("name", f.parent.name)
                # 技能名优先取 meta 里的 name 字段，如果没有就用文件所在的目录名作为兜底。比如 skills/git/SKILL.md 没有 name 字段，就用 "git" 作为技能名。
                self.skills[name] = {"meta": meta, "body": body}
                # 将获取的 skill 存储到内存中。

    def descriptions(self) -> str:
        if not self.skills: return "(no skills)"
        return "\n".join(f"  - {n}: {s['meta'].get('description', '-')}" for n, s in self.skills.items())
        # 生成所有技能的简短描述列表，注入到主 Agent 的系统提示里，下面是一个例子：
        # - git: Git 版本控制操作指南
        # - docker: Docker 容器管理指南
        # - testing: 单元测试编写规范
        # 这样 LLM 知道有哪些技能可以用，但还没有加载具体内容，节省 token。

    def load(self, name: str) -> str:
        # 按需加载某个技能的完整内容，用 `<skill>` 标签包裹返回给 LLM。如果技能名不存在，返回报错并列出所有可用技能名供 LLM 参考。
        s = self.skills.get(name)
        if not s: return f"Error: Unknown skill '{name}'. Available: {', '.join(self.skills.keys())}"
        return f"<skill name=\"{name}\">\n{s['body']}\n</skill>"
    # 整体设计思路是"懒加载" =>
    # 系统启动时，只加载技能名和描述      ← 轻量，几十个 token
    # LLM 需要时，调用 load_skill      ← 才加载完整内容，可能几千 token


# === SECTION: compression (s06) ===
def estimate_tokens(messages: list) -> int:
    # 将 messages 序列化为 JSON 字符串，除以 4 估算 token 数量。
    # 为什么除以 4：一个 token 大约等于 4 个字符（英文），所以字符数 / 4 是一个粗略的 token 估算。
    return len(json.dumps(messages, default=str)) // 4

def microcompact(messages: list):
    # 保留最近 3 个工具结果的完整内容，把更早的、超过 100 字符的工具结果替换成 "[cleared]"，以节省 token。
    indices = []
    for i, msg in enumerate(messages):
        if msg["role"] == "user" and isinstance(msg.get("content"), list):
            for part in msg["content"]:
                if isinstance(part, dict) and part.get("type") == "tool_result":
                    # 遍历整个对话历史，找出所有 tool_result，按时间顺序放入 indices 列表。
                    indices.append(part)
    if len(indices) <= 3:
        return
    for part in indices[:-3]:
        if isinstance(part.get("content"), str) and len(part["content"]) > 100:
            # indices[:-3] = 除最后 3 个以外的全部（即更早的工具结果）
            # 只清除 超过 100 字符 的（短结果如 "Edited main.py" 保留），替换为 "[cleared]"
            part["content"] = "[cleared]"

def auto_compact(messages: list) -> list:
    # 当对话太长时，把完整历史存到磁盘，然后让 LLM 生成摘要，用这个摘要替换掉整个 messages 列表。
    TRANSCRIPT_DIR.mkdir(exist_ok=True)
    path = TRANSCRIPT_DIR / f"transcript_{int(time.time())}.jsonl"
    with open(path, "w") as f:
        for msg in messages:
            f.write(json.dumps(msg, default=str) + "\n")
            # 把每条消息写成一行 JSON，存到文件。
            # 这是"备份"，压缩后原始对话仍可追溯。
    conv_text = json.dumps(messages, default=str)[:80000]
    # 把整个 messages 序列化成一个大字符串
    # 截取前 80000 个字符（约 20000 token）
    # 防止摘要请求本身也超 token 限制。
    resp = client.messages.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"Summarize for continuity:\n{conv_text}"}],
        max_tokens=2000,
    )
    # 发起一个独立的 LLM 调用（不是主对话）
    # 让模型阅读对话历史，生成一段延续性摘要
    # 限制摘要最多 2000 token
    summary = resp.content[0].text
    return [
        {"role": "user", "content": f"[Compressed. Transcript: {path}]\n{summary}"},
        # 第一条消息：告诉模型"对话已压缩"，附上原始记录路径和摘要。
        {"role": "assistant", "content": "Understood. Continuing with summary context."},
        # 第二条消息：模拟助手确认，保持 user/assistant 交替格式。
    ]

# 首先需要区别一下 Task 和 Todo。
# 1. Todo 是短期的，存储在内存中，结构比较简单，并且其只维持单次对话，不支持多 agent。
# 2. Task 是长期的，存储在磁盘文件中，结构比较完整，包括 id, subject, description, owner, blockedBy， blocks，其可以持久化，生命周期跨对话，并且支持多 Agent，支持认领（claim）、阻塞（blockedBy/blocks）。

# ⭐️⭐️⭐️⭐️⭐️
# Todo — 轻量级个人清单
# {
#     "content": "写单元测试",
#     "status": "in_progress",
#     "activeForm": "Writing unit tests"
# }
# - 保存在内存中，不持久化
# - 只是给 LLM 一个"待办事项"参考
# - 不支持多人、多 agent 协作

# Task — 重量级项目管理
# {
#     "id": 1,
#     "subject": "实现登录模块",
#     "description": "需要支持 OAuth",
#     "status": "pending",
#     "owner": "alice",          # 谁在做
#     "blockedBy": [],           # 被谁阻塞
#     "blocks": [2, 3]          # 阻塞了谁
# }
# - 每个任务一个文件，持久化到磁盘
# - 有完整的任务依赖管理（blockedBy/blocks）
# - 支持多 agent 认领
# - 可以被 claim_task 自动分配

# ⭐️⭐️⭐️⭐️⭐️ 用一个表格来梳理 TODO 和 Task 的区别

#               | TodoManager      | TaskManager |
#               |----------------- |------------|
# | **存储位置** | 内存 `self.items` | 磁盘 `.tasks/*.json` |
# | **生命周期** | 对话结束即消失      | 持久化，重启不丢失 |
# | **使用者**   | 只有主 Agent      | 主 Agent + 所有队友 |
# | **依赖关系** | 无                | blockedBy / blocks |
# | owner 概念  | 无                | 有，记录谁在负责 |
# | **粒度**     | 细，步骤级别       | 粗，里程碑级别 |
# | **适合场景** | 单次对话的短期步骤   | 多 Agent 协作的长期任务 |

# 两者可以结合起来完成任务，如下所示：

# TaskManager（宏观）：
# [ ] #1: 写前端页面  @alice
# [ ] #2: 写后端 API  @bob
# [ ] #3: 写测试      (blocked by: [1, 2])

# alice 的 TodoManager（微观，只有 alice 自己看）：
# [x] 搭建页面框架
# [>] 实现登录表单 <- 正在处理表单验证
# [ ] 对接后端接口
# [ ] 写样式

# ⭐️⭐️⭐️⭐️⭐️ 总得来说，TaskManager 是团队共享的任务板，TodoManager 是个人的执行清单。

class TaskManager:
    def __init__(self):
        TASKS_DIR.mkdir(exist_ok=True)
        # 确保 .tasks/ 目录存在，所有任务以独立 JSON 文件存储。

    def _next_id(self) -> int:
        # 给 Task 生成下一个 ID，
        # 扫描现有的任务文件，找最大的 ID，加 1 后返回。
        ids = [int(f.stem.split("_")[1]) for f in TASKS_DIR.glob("task_*.json")]
        return max(ids, default=0) + 1
        # 扫描所有 task_*.json，从文件名提取 ID 数字，返回最大值 +1。比如已有 task_1.json、task_3.json，下一个就是 4。

    def _load(self, tid: int) -> dict:
        p = TASKS_DIR / f"task_{tid}.json"
        if not p.exists(): raise ValueError(f"Task {tid} not found")
        return json.loads(p.read_text())

    def _save(self, task: dict):
        (TASKS_DIR / f"task_{task['id']}.json").write_text(json.dumps(task, indent=2))
    # 按 ID 读取/保存任务文件，是所有操作的基础。
    # 一个文件就是一个 task。

    def create(self, subject: str, description: str = "") -> str:
        task = {"id": self._next_id(), "subject": subject, "description": description,
                "status": "pending", "owner": None, "blockedBy": [], "blocks": []}
        self._save(task)
        return json.dumps(task, indent=2)
    # 创建新任务，初始状态固定是 pending，owner 为 None，依赖关系都是空列表。

    def get(self, tid: int) -> str:
        return json.dumps(self._load(tid), indent=2)
        # json.dumps 能够将 json dict 转成字符串，存在内存里。
        # 因此这里的 get 就是返回一个 json string。

    def update(self, tid: int, status: str = None,
               add_blocked_by: list = None, add_blocks: list = None) -> str:
        task = self._load(tid)
        if status:
            task["status"] = status
            # 更新状态。
            if status == "completed":
                # completed 时自动解除其他任务对自己的依赖。
                for f in TASKS_DIR.glob("task_*.json"):
                    t = json.loads(f.read_text())
                    if tid in t.get("blockedBy", []):
                        t["blockedBy"].remove(tid)
                        self._save(t)
            if status == "deleted":
                # deleted 时直接删文件。
                (TASKS_DIR / f"task_{tid}.json").unlink(missing_ok=True)
                return f"Task {tid} deleted"
        if add_blocked_by:
            # add_blocked_by，追加"谁阻塞了我"。
            task["blockedBy"] = list(set(task["blockedBy"] + add_blocked_by))
        if add_blocks:
            # add_blocks，追加"我阻塞了谁"，用 set() 去重防止重复。
            task["blocks"] = list(set(task["blocks"] + add_blocks))
        self._save(task)
        # 保存更新后的结果。
        return json.dumps(task, indent=2)
        # 返回最终的 task json string。 

    def list_all(self) -> str:
        tasks = [json.loads(f.read_text()) for f in sorted(TASKS_DIR.glob("task_*.json"))]
        if not tasks: return "No tasks."
        lines = []
        for t in tasks:
            m = {"pending": "[ ]", "in_progress": "[>]", "completed": "[x]"}.get(t["status"], "[?]")
            owner = f" @{t['owner']}" if t.get("owner") else ""
            blocked = f" (blocked by: {t['blockedBy']})" if t.get("blockedBy") else ""
            lines.append(f"{m} #{t['id']}: {t['subject']}{owner}{blocked}")
        return "\n".join(lines)
    # list_all 用于列出所有 task 的信息，最终的输出结果如下：
    #   [x] #1: 实现登录模块 @alice
    #   [>] #2: 写登录测试 @bob
    #   [ ] #3: 部署到服务器 (blocked by: [2])
    

    def claim(self, tid: int, owner: str) -> str:
        task = self._load(tid)
        task["owner"] = owner
        task["status"] = "in_progress"
        self._save(task)
        return f"Claimed task #{tid} for {owner}"
    # 认领任务，owner 由调用方传入，主 Agent 传 `"lead"`，队友传自己的名字。

# 一个完整的 Task 任务如下：

# 刚创建时 =>
# {
#   "id": 3,
#   "subject": "实现用户登录功能",
#   "description": "需要包含 JWT token 生成、session 管理、错误处理",
#   "status": "pending",
#   "owner": null,
#   "blockedBy": [1, 2],
#   "blocks": [4, 5]
# } 

# 被 bob 认领后 =>
# {
#   "id": 3,
#   "subject": "实现用户登录功能",
#   "description": "需要包含 JWT token 生成、session 管理、错误处理",
#   "status": "in_progress",
#   "owner": "bob",
#   "blockedBy": [1, 2],
#   "blocks": [4, 5]
# }

# 任务1和任务2完成后，blockedBy 自动清空 =>
# {
#   "id": 3,
#   "subject": "实现用户登录功能",
#   "description": "需要包含 JWT token 生成、session 管理、错误处理",
#   "status": "in_progress",
#   "owner": "bob",
#   "blockedBy": [],
#   "blocks": [4, 5]
# }

# bob 完成后 =>
# {
#   "id": 3,
#   "subject": "实现用户登录功能",
#   "description": "需要包含 JWT token 生成、session 管理、错误处理",
#   "status": "completed",
#   "owner": "bob",
#   "blockedBy": [],
#   "blocks": [4, 5]
# }

# 此时任务4和任务5的 `blockedBy` 里的 `3` 会被自动移除，它们就可以被认领了。
# 对应 list_all() 的输出：
# [ ] #1: 搭建数据库 schema @alice
# [ ] #2: 设计 API 接口文档 @carol
# [>] #3: 实现用户登录功能 @bob (blocked by: [1, 2])
# [ ] #4: 写登录页面前端 (blocked by: [3])
# [ ] #5: 写登录接口测试 (blocked by: [3])


# === SECTION: background (s08) ===
class BackgroundManager:
    def __init__(self):
        self.tasks = {}
        # 一个字典，key 是任务 ID，value 是任务的状态、命令、结果等信息。
        self.notifications = Queue()
        # 一个线程安全的队列，用于后台线程完成后向主线程"汇报"结果

    def run(self, command: str, timeout: int = 120) -> str:
        tid = str(uuid.uuid4())[:8]
        # 生成一个随机的 8 位任务 ID，比如 "a3f2c1b9"，用来唯一标识这个后台任务。
        self.tasks[tid] = {"status": "running", "command": command, "result": None}
        # 立即在 self.tasks 字典里注册这个任务，状态设为 "running"，result 暂时为 None。
        threading.Thread(target=self._exec, args=(tid, command, timeout), daemon=True).start()
        # 开一个守护线程（daemon=True 意味着主进程退出时这个线程会自动销毁），在后台执行 _exec 方法。主线程不阻塞，立即往下走。
        return f"Background task {tid} started: {command[:80]}"
        # 立刻返回给 LLM 一条确认消息，告知任务 ID 和命令前 80 个字符。

    def _exec(self, tid: str, command: str, timeout: int):
        try:
            # subprocess.run 是在当前线程同步执行命令，会阻塞直到命令完成（等待子进程退出）。它不创建新线程。threading.Thread 是创建一个新的操作系统线程。
            r = subprocess.run(command, shell=True, cwd=WORKDIR,
                               capture_output=True, text=True, timeout=timeout)
            # 调用 subprocess.run 执行命令：
            #   - shell=True — 用 shell 解析 command
            #   - cwd=WORKDIR — 在指定目录执行
            #   - capture_output=True — 捕获 stdout 和 stderr
            #   - text=True — 返回字符串而非字节
            #   - timeout=timeout — 超时控制

            output = (r.stdout + r.stderr).strip()[:50000]
            # 合并 stdout 和 stderr，去首尾空白，截断到 50000 字符。
            self.tasks[tid].update({"status": "completed", "result": output or "(no output)"})
            # 更新任务状态为 completed，结果设为 output（无输出则用 "(no output)"）。
            # dict 的 update 方法是一个用于原地合并或更新字典内容的核心工具。它的核心逻辑是将另一个字典或键值对可迭代对象中的内容添加到当前字典中，如果存在重复的键，新值会覆盖旧值。
        except Exception as e:
            # 出现异常，将更新任务状态为 error，结果为异常信息。
            self.tasks[tid].update({"status": "error", "result": str(e)})

        self.notifications.put({"task_id": tid, "status": self.tasks[tid]["status"],
                                "result": self.tasks[tid]["result"][:500]})
        # 将任务 ID、状态、和结果（前 500 字符）放入通知队列。注意：这一行在 try/except 之外，无论成功或失败都会执行。主线程的 agent_loop 会定期调用 BG.drain() 来消费这些通知。

    def check(self, tid: str = None) -> str:
        # 传入 tid：返回单个任务的状态和结果。
        # 不传 tid：列出所有任务的 ID、状态和命令前 60 字符，
        if tid:
            t = self.tasks.get(tid)
            return f"[{t['status']}] {t.get('result', '(running)')}" if t else f"Unknown: {tid}"
        return "\n".join(f"{k}: [{v['status']}] {v['command'][:60]}" for k, v in self.tasks.items()) or "No bg tasks."

    def drain(self) -> list:
        # 把 notifications 队列里所有待消费的通知一次性取出，返回一个列表，队列清空。agent_loop 在每次调用 LLM 之前都会先 drain() 一次，把后台结果注入对话，让 LLM 知道"后台发生了什么"。
        notifs = []
        while not self.notifications.empty():
            notifs.append(self.notifications.get_nowait())                                  
            # get_nowait() — 非阻塞获取，立即返回。
            #  - 有数据 → 返回数据。
            #  - 无数据 → 抛出 queue.Empty 异常
        return notifs


# === SECTION: messaging (s09) ===
class MessageBus:
    # 定义消息总线类。这是整个多 Agent 系统的"邮局"，负责 Agent 之间的所有通信。
    def __init__(self):
        INBOX_DIR.mkdir(parents=True, exist_ok=True)
        # 初始化时确保收件箱目录存在。parents=True 表示如果父目录也不存在就一并创建；exist_ok=True 表示目录已存在也不报错。

    def send(self, sender: str, to: str, content: str,
             msg_type: str = "message", extra: dict = None) -> str:
        # 发送消息的方法。参数：
        # sender：发件人名字
        # to：收件人名字
        # content：消息正文
        # msg_type：消息类型，默认是普通 "message"，也可以是 "broadcast"、"shutdown_request" 等
        # extra：附加字段的字典，比如 {"request_id": "abc123"}

        msg = {"type": msg_type, "from": sender, "content": content,
               "timestamp": time.time()}
        # 构造消息字典，包含类型、发件人、正文、时间戳四个基础字段。

        if extra: msg.update(extra)
        # 如果调用方传入了额外字段，就合并进 msg。比如关机请求需要附带 request_id。

        with open(INBOX_DIR / f"{to}.jsonl", "a") as f:
            f.write(json.dumps(msg) + "\n")
            # 以追加模式打开收件人的收件箱文件（比如 alice.jsonl），把消息序列化成一行 JSON 写入。每条消息占一行，这就是 .jsonl（JSON Lines）格式的含义。

        return f"Sent {msg_type} to {to}"
        # 返回确认字符串，供 LLM 知道发送成功。

    def read_inbox(self, name: str) -> list:
        path = INBOX_DIR / f"{name}.jsonl"
        # 构造该 Agent 的收件箱路径。如果文件不存在，说明没有消息，直接返回空列表。
        if not path.exists(): return []
        msgs = [json.loads(l) for l in path.read_text().strip().splitlines() if l]
        # 读取文件全部内容，按行分割，过滤空行，把每行 JSON 字符串反序列化成字典，组成列表。
        path.write_text("")
        # 读完之后清空文件。这实现了"已读即删"的语义，防止下次重复读到同一批消息。
        return msgs
        # 返回这批消息列表，供调用方（agent_loop 或队友线程）处理。


    def broadcast(self, sender: str, content: str, names: list) -> str:
        count = 0
        for n in names:
            if n != sender:
                # 遍历所有队友名字，跳过自己——不需要给自己发广播。
                self.send(sender, n, content, "broadcast")
                # 对每一个其他成员调用 send()，消息类型标记为 "broadcast"，并计数。
                count += 1
        return f"Broadcast to {count} teammates"
        # 返回实际广播到的人数。


# 主 Agent (agent_loop)
    # │
    # ├─ 串行工具：bash / read_file / subagent ...
    # │
    # └─ 并行队友：TeammateManager
    #                 │
    #                 ├─ alice 线程
    #                 ├─ bob 线程
    #                 └─ carol 线程
    #                      │
    #                      ├─ 从 TaskManager 认领任务
    #                      ├─ 通过 MessageBus 收发消息
    #                      └─ 完成后 idle，等待新任务
# 梳理顺序：    
# 1. TeammateManager — 队友怎么被创建、怎么工作、怎么 idle、怎么关闭
# 2. TaskManager — 队友怎么认领任务、依赖关系怎么解除（结合队友场景就清晰了）
# 3. MessageBus — 主 Agent 和队友怎么通信（你已经看过了，结合队友场景再回顾一遍）
# 4. agent_loop — 把所有机制串起来看主 Agent 怎么驱动整个系统

# ⭐️⭐️⭐️⭐️⭐️ 这里介绍一下 TeammateManager、run_subagent 和 BackgroundManager 的区别：
# 1. run_subagent — 一次性任务委托，特点是同步、一次性、阻塞等待结果。
#   - 主 agent 发起 → 等待子 agent 完成 → 拿到结果继续
#   - 只做一件事：发给 LLM，返回结果
#   - 子 agent 有独立循环。
#   - 工具只有 bash、read_file（Explore 模式）

# 2. BackgroundManager — 后台命令执行。特点是异步、不等待、结果通过队列通知
#   - 主 agent 发起 → 立刻返回 → 后台线程执行命令
#   - 结果通过 Queue 通知，注入到 messages 里告诉 LLM
#   - 不涉及 LLM，只是跑 shell 命令
#   - 类似于 "fire and forget"

# 3. TeammateManager — 长期运行的协作 Agent。特点是独立线程、持久运行、可通信、idle/resume 机制。
#   - 子 agent 有自己的 agent_loop，持续运行
#   - 可以 idle（暂停）→ 收到消息或任务时被唤醒
#   - 可以通过 BUS.send/read_inbox 与其他 agent 通信
#   - 生命周期：spawn → working → idle → (wakeup → working) 或 shutdown
#   - 工具比 subagent 丰富：有 send_message、claim_task、idle 等


class TeammateManager:
    # 这段代码实现了队友 Agent 的完整生命周期管理，是整个多 Agent 系统的核心。
    # 首先理解整体的状态机设计：
    # spawn() 创建
    #      │
    #      ▼
    #   working  ──────────────────────────────────┐
    #      │                                       │
    #      │ LLM 调用 idle，或完成当前任务            │
    #      ▼                                       │
    #    idle                                      │
    #      │                                       │
    #      ├─ 收到新消息  ──────────────────────────┤
    #      ├─ 发现未认领任务 ───────────────────────┘
    #      │
    #      └─ 超时无事可做
    #           │
    #           ▼
    #        shutdown
    def __init__(self, bus: MessageBus, task_mgr: TaskManager):
        # 初始化时注入 MessageBus 和 TaskManager 两个依赖，加载已有的队伍配置。self.threads 预留了线程引用字典，但这版代码实际没用上（用 daemon 线程代替了）。
        TEAM_DIR.mkdir(exist_ok=True)
        self.bus = bus
        self.task_mgr = task_mgr
        self.config_path = TEAM_DIR / "config.json"
        self.config = self._load()
        self.threads = {}
        

    def _load(self) -> dict:
        # 从磁盘中加载配置。
        if self.config_path.exists():
            return json.loads(self.config_path.read_text())
        return {"team_name": "default", "members": []}

    def _save(self):
        # 将配置保存到磁盘中。
        self.config_path.write_text(json.dumps(self.config, indent=2))

    def _find(self, name: str) -> dict:
        # 按照名字来查找协作者。
        for m in self.config["members"]:
            if m["name"] == name: return m
        return None
    
    # 上述的 _load、_save 和 _find 代码都是在维护配置文件，一个示例的配置文件如下 =>
    # {
    #     "team_name": "default",
    #     "members": [
    #         {"name": "alice", "role": "前端开发", "status": "working"},
    #         {"name": "bob",   "role": "后端开发", "status": "idle"}
    #     ]
    # }

    def spawn(self, name: str, role: str, prompt: str) -> str:
        # 派生队友。如果队友已存在且处于 idle 或 shutdown 状态才允许重新派生，working 状态直接拒绝防止重复创建。开一个 daemon 线程运行 _loop()，主进程退出时线程自动销毁。
        member = self._find(name) 
        # 从磁盘中找到协作 Agent 的信息。
        if member:
            if member["status"] not in ("idle", "shutdown"):
                return f"Error: '{name}' is currently {member['status']}"
            member["status"] = "working"
            member["role"] = role
            # 拉起协作 Agent。
        else:
            # 添加新的协作 Agent。
            member = {"name": name, "role": role, "status": "working"}
            self.config["members"].append(member)
        self._save()
        threading.Thread(target=self._loop, args=(name, role, prompt), daemon=True).start()
        # target=self._loop 是线程要执行的函数（_loop 方法）。
        # args=(name, role, prompt) 是传给 _loop 的三个参数。
        # daemon=True 守护线程——主进程退出时自动终止。

        # 子 agent 通过 daemon=True 启动，意味着：
        # - 如果主 agent 退出/崩溃，整个程序会立即退出
        # - 不会留下僵尸子 agent 继续运行
        # - 子 agent 的生命周期跟随主 agent

        # 如果 daemon=False：
        # - 主进程退出时，会等待所有子线程完成
        # - 可能导致程序无法退出（子 agent 死循环）

        return f"Spawned '{name}' (role: {role})"
        # spawn 的返回值会作为 tool result，作为 role user 返回给 LLM。

    def _set_status(self, name: str, status: str):
        member = self._find(name)
        if member:
            member["status"] = status
            self._save()
        # 更新队员状态并持久化到磁盘，让主 Agent 随时能通过 list_all 看到最新状态。

    def _loop(self, name: str, role: str, prompt: str):
        # _loop() 是核心，分两个阶段交替运行。
        # 这里的 Prompt 是 LLM 生成的,给子 Agent 的 Prompt，具体流程如下：
        
        # 1. 主 agent（lead）决定 spawn 一个子 agent。
        # 2. 主 agent 调用 spawn_teammate 工具，LLM 生成 name、role、prompt。
        # 3. 这三个参数传给子线程的 _loop。
        # 4. 子 agent 用这些参数初始化自己的对话上下文，然后开始工作。

        team_name = self.config["team_name"]
        sys_prompt = (f"You are '{name}', role: {role}, team: {team_name}, at {WORKDIR}. "
                      f"Use idle when done with current work. You may auto-claim tasks.")
        # 这不是两个独立字符串，而是 Python 的隐式字符串拼接，括号只是用于换行，其等价于 sys_prompt = f"You are '{name}', role: {role}, team: {team_name}, at {WORKDIR}. Use idle when done with current work. You may auto-claim tasks."

        messages = [{"role": "user", "content": prompt}] # 每个队友 Agent 有自己独立的系统提示和对话历史，互不干扰。

        tools = [
            {"name": "bash", "description": "Run command.", "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},

            {"name": "read_file", "description": "Read file.", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},

            {"name": "write_file", "description": "Write file.", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},

            {"name": "edit_file", "description": "Edit file.", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "old_text": {"type": "string"}, "new_text": {"type": "string"}}, "required": ["path", "old_text", "new_text"]}},

            {"name": "send_message", "description": "Send message.", "input_schema": {"type": "object", "properties": {"to": {"type": "string"}, "content": {"type": "string"}}, "required": ["to", "content"]}},
            # 给其他 Agent 发消息。
            {"name": "idle", "description": "Signal no more work.", "input_schema": {"type": "object", "properties": {}}},
            # 主动宣告空闲。
            {"name": "claim_task", "description": "Claim task by ID.", "input_schema": {"type": "object", "properties": {"task_id": {"type": "integer"}}, "required": ["task_id"]}}, 
            # 认领任务。
        ]
        # 队友的工具集比主 Agent 少，没有 todo 管理、没有派生子 Agent、没有广播等高级功能。

        # 下面是一些消息的例子。

        # 普通消息（主 Agent 给队友分配任务）。
        # {
        #     "type": "message",
        #     "from": "lead",
        #     "content": "请检查 auth.py 里的 token 验证逻辑，看看有没有安全漏洞",
        #     "timestamp": 1703123456.789
        # }

        # 广播消息（主 Agent 通知所有人）。
        # {
        #     "type": "broadcast",
        #     "from": "lead",
        #     "content": "注意：所有文件操作请在 /src 目录下进行，不要动 /config",
        #     "timestamp": 1703123460.123
        # }

        # 关机请求（主 Agent 让队友退出）。
        # {
        #     "type": "shutdown_request",
        #     "from": "lead",
        #     "content": "Please shut down.",
        #     "timestamp": 1703123480.456,
        #     "request_id": "a3f2c1b9"
        # }

        # 队友之间互发消息。
        # {
        #     "type": "message",
        #     "from": "alice",
        #     "content": "我已经完成了前端部分，接口文档在 docs/api.md，你可以开始写后端了",
        #     "timestamp": 1703123500.789
        # }

        # 计划审批回复（主 Agent 审批队友的计划）。
        # {
        #     "type": "plan_approval_response",
        #     "from": "lead",
        #     "content": "同意，但数据库设计需要加索引",
        #     "timestamp": 1703123520.000,
        #     "request_id": "b7d4e2f1",
        #     "approve": true,
        #     "feedback": "记得在 user_id 字段上加索引"
        # }

        while True:
            # -- WORK PHASE --
            for _ in range(50): # 最多 50 轮 LLM 调用，这也是 ⭐️⭐️⭐️⭐️⭐️ 这是单次会话的 agent loop。
                inbox = self.bus.read_inbox(name)
                # 每轮 LLM 调用前先检查收件箱（处理来自其他 agent 的消息），优先处理关机请求，其他消息注入对话历史。
                for msg in inbox:
                    if msg.get("type") == "shutdown_request":
                        self._set_status(name, "shutdown")
                        # 状态改为 shutdown，保存到磁盘，子 agent 的 _loop 退出。
                        # 之后主 Agent 可以通过 list_teammates 看到该子 agent 状态已经变成了 shutdown。
                        return # 收到关机请求，立即退出。
                    messages.append({"role": "user", "content": json.dumps(msg)})
                    # LLM history 必须要 user 和 assistant 交替出现。
                    # 因此这里其实会有一些问题。
                    # 那这里应该有问题吧 ，在 _loop 中，先写入了：
                    # messages = [{"role": "user", "content": prompt}]
                    # 然后在 while True 中，如果 inbox 中有消息，可能会写入：
                    # messages.append({"role": "user", "content": json.dumps(msg)})
                    # ⭐️⭐️⭐️⭐️⭐️，这应该算是代码里的一个 bug，在 inbox 同时收到多条消息，或者第一轮循环时 inbox 就有消息的情况下会触发。

                    # 如果不修改这个 BUG，那么 Anthropic API 会直接返回一个错误，然后被捕获。
                try:
                    # 调用 LLM，注意每个队友是独立的 LLM 调用，和主 Agent 完全并行。
                    response = client.messages.create(
                        model=MODEL, system=sys_prompt, messages=messages,
                        tools=tools, max_tokens=8000)
                except Exception:
                    self._set_status(name, "shutdown")
                    return
                # 将 LLM 的响应写入 messages。
                messages.append({"role": "assistant", "content": response.content})
                if response.stop_reason != "tool_use":
                    # ⭐️⭐️⭐️⭐️⭐️ 这里的设计和主 Agent 的流程设计是一样的。
                    # 如果不是 tool_use，那么说明已经拿到了最终 Response 了，之后就会进入到 idle 状态。
                    # 这里需要说一下 tool_use 的来源：
                    # 1. 训练会使得 LLM 理解工具的定义，决定何时去调用，生成正确的格式。
                    # 2. API 检测到工具调用，自动设置 stop_reason = "tool_use"
                    break
                results = []
                idle_requested = False
                # results 收集本轮所有工具的执行结果，idle_requested 标记 LLM 是否请求进入 idle，原因和之前一样——不能在循环中途就 break，要等所有工具执行完。
                for block in response.content:
                    if block.type == "tool_use":
                        # 遍历 LLM 回复，只处理工具调用块。
                        if block.name == "idle":
                            idle_requested = True
                            output = "Entering idle phase."
                            # LLM 调用 idle 时，只打标记，不做任何实际操作，返回一个确认字符串让 LLM 知道请求被接收了。
                        elif block.name == "claim_task":
                            # 认领任务，注意这里 name 是队友自己的名字，硬编码传入，LLM 无法冒充别人认领任务。
                            output = self.task_mgr.claim(block.input["task_id"], name)
                            # 这里会让协作 Agent 认领 task_id 任务。
                        elif block.name == "send_message":
                            output = self.bus.send(name, block.input["to"], block.input["content"])
                            # 发消息，发件人同样硬编码为 name，LLM 只能以自己的身份发消息。
                        else:
                            dispatch = {"bash": lambda **kw: run_bash(kw["command"]),
                                        "read_file": lambda **kw: run_read(kw["path"]),
                                        "write_file": lambda **kw: run_write(kw["path"], kw["content"]),
                                        "edit_file": lambda **kw: run_edit(kw["path"], kw["old_text"], kw["new_text"])}
                            # 其余工具走本地 dispatch 表执行。注意这个 dispatch 表是每次循环都重新创建的，和主 Agent 的全局 TOOL_HANDLERS 不同，这是一个轻微的性能浪费，但功能上没有问题。
                            output = dispatch.get(block.name, lambda **kw: "Unknown")(**block.input)
                        print(f"  [{name}] {block.name}: {str(output)[:120]}")
                        results.append({"type": "tool_result", "tool_use_id": block.id, "content": str(output)})
                        # 打印日志方便观察，然后把结果按 API 格式封装进 results。注意输出只截 120 字符用于显示，但存入 results 的是完整内容。
                messages.append({"role": "user", "content": results})
                # 把所有工具结果一次性打包成一条 user 消息回传给 LLM，保持交替格式。
                if idle_requested:
                    # 所有工具执行完之后，才检查 idle 标记，跳出当前会话的工作循环进入 idle 阶段。
                    break

                # 下面是一个完整的例子：
                # LLM 回复：
                # [text block]    "我来读取文件然后编辑它"
                # [tool_use]      bash(command="ls src/")
                # [tool_use]      read_file(path="src/auth.py")
                # [tool_use]      idle

                # 代码执行：
                # block1: text    → 跳过
                # block2: bash    → 执行，output = "auth.py config.py"
                # block3: read_file → 执行，output = "文件内容..."
                # block4: idle    → idle_requested = True，output = "Entering idle phase."

                # results = [
                # {tool_use_id: "id2", content: "auth.py config.py"},
                # {tool_use_id: "id3", content: "文件内容..."},
                # {tool_use_id: "id4", content: "Entering idle phase."},
                # ]

                # messages.append({"role": "user", "content": results})
                # if idle_requested: break  ← 跳出工作循环

            # -- IDLE PHASE: poll for messages and unclaimed tasks --
            # ⭐️⭐️⭐️⭐️⭐️ 首先需要回答一个问题，为什么要设立 idle status？队友 Agent 完成当前任务后，不应该立刻销毁，因为：
            # 没有 idle：
            # * 任务完成 → 线程退出 → 主 Agent 想分配新任务 → 必须重新 spawn → 重新开始对话历史
            # 有 idle：
            # * 任务完成 → 进入等待 → 收到新任务 → 直接继续 → 保留完整对话历史

            # 本质上，idle 阶段就是线程的"待机模式"，保持队友存活但不消耗 LLM token。
            # spawn() 时，threading.Thread(target=self._loop, ..., daemon=True).start()，这代表线程启动 → 状态 = "working"；_loop() 里所有的 return 都意味着线程结束。

            # 所有路径在 return 之前都必须先设置 shutdown 状态，原因是，如果不设置，线程退出后主 Agent 看到的还是 "working"；主 Agent 会以为队友还在干活，实际上线程已经没了。
            # shutdown 和 idle 状态下的协作 Agent 是允许重新 spawn 的。
            self._set_status(name, "idle")
            resume = False
            for _ in range(IDLE_TIMEOUT // max(POLL_INTERVAL, 1)):
                # 计算最多轮询多少次 => 60 // 5 = 12 次，每次间隔 5 秒，最多等待 60 秒。max(POLL_INTERVAL, 1) 防止除以零。每次轮询前先睡 5 秒，不消耗任何 LLM token。
                time.sleep(POLL_INTERVAL)
                inbox = self.bus.read_inbox(name)
                if inbox:
                    for msg in inbox:
                        if msg.get("type") == "shutdown_request":
                            self._set_status(name, "shutdown")
                            return
                        messages.append({"role": "user", "content": json.dumps(msg)})
                    resume = True
                    # 这里被唤醒应该是该子 Agent 做事情做到一半因阻塞停了下来，之后等到别人完成了阻塞任务之后，阻塞结束，子 Agent 继续执行，工作流程如下：
                    # 1. 子 agent 完成当前任务
                    # 2. 调用 idle 工具（或发消息告知 lead 自己 idle 了）
                    # 3. 停止主动调用 LLM，进入"睡眠"状态
                    # 4. 其他 agent 发来消息（通过 BUS.send）
                    # 5. 唤醒该子 agent
                    # 6. 子 agent 收到 inbox 中的消息
                    # 7. 设置 resume = True，break 出等待循环
                    # 8. 继续调用 LLM 处理新任务

                    # ⭐️⭐️⭐️⭐️⭐️ 当然，也可以是被主 Agent 直接指派了任务。
                    break 
                    # 跳出 idle，准备执行新的任务。

                # 收到消息时的处理：
                # 1. 如果是关机请求，直接退出线程。
                # 2. 其他消息注入对话历史，resume = True 跳出轮询，回到工作阶段。
                unclaimed = []
                for f in sorted(TASKS_DIR.glob("task_*.json")):
                    t = json.loads(f.read_text())
                    if t.get("status") == "pending" and not t.get("owner") and not t.get("blockedBy"):
                        unclaimed.append(t)
                # 扫描任务板，筛选条件必须同时满足三个：
                # 1. status == "pending"：还没开始。
                # 2. not owner：没有人认领。
                # 3. not blockedBy：没有被其他任务阻塞。

                if unclaimed:
                    # 取第一个符合条件的任务认领，sorted() 保证按文件名排序，即按 ID 从小到大，优先认领编号最小的任务。
                    task = unclaimed[0]
                    self.task_mgr.claim(task["id"], name)
                    # Identity re-injection for compressed contexts
                    if len(messages) <= 3:
                        # messages <= 3 说明对话历史被压缩过，只剩摘要。此时重新在最前面注入身份信息，防止 LLM 忘记自己是谁。成对插入保持交替格式。
                        messages.insert(0, {"role": "user", "content":
                            f"<identity>You are '{name}', role: {role}, team: {team_name}.</identity>"})
                        messages.insert(1, {"role": "assistant", "content": f"I am {name}. Continuing."})
                        # 逻辑链是这样的，消息数量很少时 => 历史被压缩 => 需要提醒 LLM 它是谁。
                    messages.append({"role": "user", "content":
                        f"<auto-claimed>Task #{task['id']}: {task['subject']}\n{task.get('description', '')}</auto-claimed>"})
                    # ⭐️⭐️⭐️⭐️⭐️ 类似于像 <auto-claimed> 这样的特殊前缀，是代码库自己的约定，用于在 <tag> 包裹的信息中向 LLM 传递结构化提示，如下所示：
                    # ├──────────────────────┼─────────────────────────┤
                    # │ <identity>           │ 重新注入 agent 身份信息 │
                    # ├──────────────────────┼─────────────────────────┤
                    # │ <auto-claimed>       │ 自动认领了某个任务      │
                    # ├──────────────────────┼─────────────────────────┤
                    # │ <background-results> │ 后台任务结果            │
                    # ├──────────────────────┼─────────────────────────┤
                    # │ <inbox>              │ 来自其他 agent 的消息   │
                    # ├──────────────────────┼─────────────────────────┤
                    # │ <reminder>           │ 提醒更新 TODO           │
                    # └──────────────────────┴─────────────────────────┘
                    messages.append({"role": "assistant", "content": f"Claimed task #{task['id']}. Working on it."})
                    resume = True
                    # 这是一个子 Agent 定时自我唤醒的流程，处于 idle 状态的子 Agent 会定期从 task 文件中获取 pending 的 task 来继续处理。
                    # ⭐️⭐️⭐️⭐️⭐️ 把认领的任务注入对话历史，assistant 的回复是硬编码的占位符，目的只是维持交替格式。resume = True 跳出轮询。
                    break
                    # 跳出 idle，准备执行新的任务。

            if not resume:
                self._set_status(name, "shutdown")
                return
            self._set_status(name, "working")
            # 轮询结束后检查结果：
            # - 60 秒内没有任何消息也没有任务 => 自然 shutdown，线程退出。
            # - 有消息或认领了任务 => 恢复 working 状态，回到外层 `while True` 继续工作。

    def list_all(self) -> str:
        # 用于列出所有协作 Agent 的状态。
        if not self.config["members"]: return "No teammates."
        # 如果没有队友成员，返回 "No teammates."。
        lines = [f"Team: {self.config['team_name']}"] # 给出团队名称。
        for m in self.config["members"]:
            lines.append(f"  {m['name']} ({m['role']}): {m['status']}")
            # 遍历每个成员，格式化为 => "名称（角色）: 状态"
        return "\n".join(lines)

    def member_names(self) -> list:
        return [m["name"] for m in self.config["members"]]
    # 列表推导式，遍历所有成员，提取每个成员的 name 组成列表。
    # 例如 => ["alice", "bob", "eve"]。


# 创建全局实例
TODO = TodoManager()
SKILLS = SkillLoader(SKILLS_DIR)
TASK_MGR = TaskManager()
BG = BackgroundManager()
BUS = MessageBus()
TEAM = TeammateManager(BUS, TASK_MGR)
#   - TODO — 任务清单管理
#   - SKILLS — 技能加载器
#   - TASK_MGR — 任务管理器
#   - BG — 后台任务管理器
#   - BUS — 消息总线（agent 间通信）
#   - TEAM — 队友管理器

# === SECTION: system_prompt ===
SYSTEM = f"""You are a coding agent at {WORKDIR}. Use tools to solve tasks.
Prefer task_create/task_update/task_list for multi-step work. Use TodoWrite for short checklists.
Use task for subagent delegation. Use load_skill for specialized knowledge.
Skills: {SKILLS.descriptions()}"""
#   这是主 agent 的 SYSTEM prompt，告诉它：
#   - 工作目录是哪
#   - 优先用什么工具管理任务（task_create/task_update/task_list）：多步骤的复杂工作，优先用 task_create（创建任务）、task_update（更新任务）、task_list（任务列表）这三类操作；简短的简易清单，才用 TodoWrite 功能。
#   - 可以委托子 agent
#   - 可以加载技能

shutdown_requests = {}
plan_requests = {}
# === SECTION: shutdown_protocol (s10) ===
def handle_shutdown_request(teammate: str) -> str:
    req_id = str(uuid.uuid4())[:8]
    # 生成唯一请求 ID。
    shutdown_requests[req_id] = {"target": teammate, "status": "pending"}
    # 记录到 shutdown_requests。
    # 在 shutdown_requests 字典中记录本次关机请求的状态，用于追踪和后续确认。为什么需要这个记录？
    # 1. 追踪：主 agent 发出去请求后，能查"我发出的关机请求状态"。
    # 2. 等待响应：队友收到后可能会回复 shutdown_response，主 agent 可以对照 request_id 找到对应请求并更新状态。
    # 3. 防止重复：如果收到重复的 shutdown_response，可以查到对应的是哪个请求。
    BUS.send("lead", teammate, "Please shut down.", "shutdown_request", {"request_id": req_id})
    # 通过 BUS 发消息给目标队友。
    return f"Shutdown request {req_id} sent to '{teammate}'"
    # 返回确认消息。

# ⭐️⭐️⭐️⭐️⭐️ 整个 agent 关机的流程如下：
#   1. 主 agent 发送 shutdown_request → shutdown_requests["a3f2c1b9"] = {"target": "alice", "status": "pending"}。
#   2. 队友 alice 收到，调用 handle_shutdown_request 返回 "Shutdown request a3f2c1b9 sent to 'alice'"。
#   3. 队友 alice 关机，发送 shutdown_response。
#   4. 主 agent 收到响应，查找 shutdown_requests["a3f2c1b9"]，确认状态更新。


def handle_plan_review(request_id: str, approve: bool, feedback: str = "") -> str:
    # 1. 根据 request_id 查找计划请求。
    req = plan_requests.get(request_id)
    # 2. 不存在则报错。
    if not req: return f"Error: Unknown plan request_id '{request_id}'"
    # 3. 更新状态为 approved 或 rejected。
    req["status"] = "approved" if approve else "rejected"
    # 4. 通过消息总线发回给请求者。
    BUS.send("lead", req["from"], feedback, "plan_approval_response",
             {"request_id": request_id, "approve": approve, "feedback": feedback})
    # 5. 返回结果。
    return f"Plan {req['status']} for '{req['from']}'"
# ⭐️⭐️⭐️⭐️⭐️ 这里是一个示例的流程：
#   ┌─────────────────────────────────────────────────────────────────┐
#   │  队友 alice                                                     │
#   │  plan_requests["abc123"] = {                                    │
#   │      "from": "alice",                                           │
#   │      "plan": "...",                                             │
#   │      "status": "pending"                                        │
#   │  }                                                              │
#   │  BUS.send("lead", "alice", plan_content, "plan_approval_request",│
#   │           {"request_id": "abc123", ...})                        │
#   └─────────────────────────────────────────────────────────────────┘
#                                 │
#                                 ▼
#   ┌─────────────────────────────────────────────────────────────────┐
#   │  主 agent (lead) 收到 plan_approval_request                      │
#   │                                                                  │
#   │  决定批准或拒绝后，调用：                                          │
#   │  handle_plan_review(request_id="abc123", approve=True,          │
#   │                      feedback="Good plan, proceed.")             │
#   └─────────────────────────────────────────────────────────────────┘
#                                 │
#                                 ▼
#   ┌─────────────────────────────────────────────────────────────────┐
#   │  handle_plan_review 执行：                                        │
#   │  1. req = plan_requests.get("abc123") → 找到 alice 的请求         │
#   │  2. req["status"] = "approved"                                   │
#   │  3. BUS.send("lead", "alice", "Good plan, proceed.",             │
#   │              "plan_approval_response", {...})                    │
#   │  4. 返回 "Plan approved for 'alice'"                             │
#   └─────────────────────────────────────────────────────────────────┘
#                                 │
#                                 ▼
#   ┌─────────────────────────────────────────────────────────────────┐
#   │  队友 alice 的 _loop 收到消息：                                    │
#   │  inbox = BUS.read_inbox("alice")                                 │
#   │  msg = {                                                        │
#   │      "type": "plan_approval_response",                           │
#   │      "request_id": "abc123",                                    │
#   │      "approve": True,                                           │
#   │      "feedback": "Good plan, proceed."                          │
#   │  }                                                              │
#   │  messages.append({"role": "user", "content": json.dumps(msg)})   │
#   │  → LLM 看到审批结果，决定是否继续执行计划                          │
#   └─────────────────────────────────────────────────────────────────┘
# 注意，这是一个自主多 Agent 系统，审批是由主 Agent（LLM）自动完成，不是人类审批。



# 这是一个工具注册表（TOOL_HANDLERS），将 LLM 可调用的工具名映射到对应的处理函数。
# 工具的调用流程为 => LLM 返回 tool_use → 遍历每个工具调用 → 从 TOOL_HANDLERS 找到对应 handler 执行 → 返回结果给 LLM。
# 下面是工具的分类 =>
#   ┌──────────┬─────────────────────────────────────────────────────────────────────┐
#   │   类别   │                                工具                                 │
#   ├──────────┼─────────────────────────────────────────────────────────────────────┤
#   │ 文件系统 │ bash, read_file, write_file, edit_file                              │
#   ├──────────┼─────────────────────────────────────────────────────────────────────┤
#   │ 任务管理 │ TodoWrite, task_create/get/update/list, claim_task                  │
#   ├──────────┼─────────────────────────────────────────────────────────────────────┤
#   │ 子 agent │ task (运行 Explore 等子 agent)                                      │
#   ├──────────┼─────────────────────────────────────────────────────────────────────┤
#   │ 团队协作 │ spawn_teammate, list_teammates, send_message, read_inbox, broadcast │
#   ├──────────┼─────────────────────────────────────────────────────────────────────┤
#   │ 后台任务 │ background_run, check_background                                    │
#   ├──────────┼─────────────────────────────────────────────────────────────────────┤
#   │ 其他     │ load_skill, compress, idle, shutdown_request, plan_approval         │
#   └──────────┴─────────────────────────────────────────────────────────────────────┘
TOOL_HANDLERS = {
    "bash":             lambda **kw: run_bash(kw["command"]),
    # 执行 shell 命令。把 LLM 传来的 command 参数传给 run_bash()。
    "read_file":        lambda **kw: run_read(kw["path"], kw.get("limit")),
    # 读取文件内容。limit 是可选参数（用 .get() 取），用于限制读取的行数。
    "write_file":       lambda **kw: run_write(kw["path"], kw["content"]),
    # 把内容写入文件，文件不存在则创建。
    "edit_file":        lambda **kw: run_edit(kw["path"], kw["old_text"], kw["new_text"]),
    # 在文件中找到 old_text 并替换为 new_text，精确修改文件的某一处。
    "TodoWrite":        lambda **kw: TODO.update(kw["items"]),
    # 更新 todo 列表，items 是包含所有 todo 项的数组。
    "task":             lambda **kw: run_subagent(kw["prompt"], kw.get("agent_type", "Explore")),
    # 派生一个子 Agent 去执行某个独立任务。agent_type 默认是 "Explore"（只读），也可以指定为 "general-purpose"（可读写）。
    "load_skill":       lambda **kw: SKILLS.load(kw["name"]),
    # 从 skills/ 目录加载指定技能的 SKILL.md 内容，注入给 LLM 作为专项知识。
    "compress":         lambda **kw: "Compressing...",
    # 这里故意只返回一个字符串，什么都不做。真正的压缩逻辑在 agent_loop 里检测 manual_compress 标记后执行，因为压缩需要在所有工具执行完之后才能进行。
    "background_run":   lambda **kw: BG.run(kw["command"], kw.get("timeout", 120)),
    # 在后台线程里执行命令，不阻塞主对话。timeout 默认 120 秒。
    "check_background": lambda **kw: BG.check(kw.get("task_id")),
    # 查询后台任务的状态和结果。不传 task_id 则列出所有后台任务。
    "task_create":      lambda **kw: TASK_MGR.create(kw["subject"], kw.get("description", "")),
    # 在 .tasks/ 目录创建一个持久化任务文件。description 是可选的详细说明。
    "task_get":         lambda **kw: TASK_MGR.get(kw["task_id"]),
    # 按 ID 读取某个任务的详细信息。
    "task_update":      lambda **kw: TASK_MGR.update(kw["task_id"], kw.get("status"), kw.get("add_blocked_by"), kw.get("add_blocks")),
    # 更新任务状态，或添加任务之间的依赖关系（谁阻塞谁）。三个参数都是可选的。
    "task_list":        lambda **kw: TASK_MGR.list_all(),
    # 列出所有任务，不需要任何参数。
    "spawn_teammate":   lambda **kw: TEAM.spawn(kw["name"], kw["role"], kw["prompt"]),
    # 派生一个持久化的队友 Agent，在独立线程里长期运行，可以接收消息和自动认领任务。
    "list_teammates":   lambda **kw: TEAM.list_all(),
    # 列出所有队友的名字、角色和当前状态（working/idle/shutdown）。
    "send_message":     lambda **kw: BUS.send("lead", kw["to"], kw["content"], kw.get("msg_type", "message")),
    # 以 "lead"（主 Agent）的身份给某个队友发消息。发件人固定是 lead。
    "read_inbox":       lambda **kw: json.dumps(BUS.read_inbox("lead"), indent=2),
    # 读取并清空 lead 自己的收件箱，返回格式化的 JSON 字符串。
    "broadcast":        lambda **kw: BUS.broadcast("lead", kw["content"], TEAM.member_names()),
    # 给所有队友广播同一条消息，自动跳过自己。
    "shutdown_request": lambda **kw: handle_shutdown_request(kw["teammate"]),
    # 向指定队友发送关机请求，队友收到后会在完成当前工作后退出线程。
    "plan_approval":    lambda **kw: handle_plan_review(kw["request_id"], kw["approve"], kw.get("feedback", "")),
    # 审批队友提交的计划，approve 为 True 或 False，可附带 feedback 说明原因。
    "idle":             lambda **kw: "Lead does not idle.",
    # 主 Agent（lead）不支持进入 idle 状态，直接返回拒绝提示。idle 只属于队友 Agent。
    "claim_task":       lambda **kw: TASK_MGR.claim(kw["task_id"], "lead"),
    # 主 Agent 认领某个任务，把任务的 owner 设为 "lead"，状态改为 in_progress。
}

# 这里描述了 tools 的用法，他会丢给 LLM，这里的定义是需要遵循 Anthropic 的标准的，并不是随便定义的，因此如果我们使用 Claude 模型，Tool Selection 效果会更好些。
TOOLS = [
    {"name": "bash", "description": "Run a shell command.",
     "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
    {"name": "read_file", "description": "Read file contents.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Write content to file.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
    {"name": "edit_file", "description": "Replace exact text in file.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "old_text": {"type": "string"}, "new_text": {"type": "string"}}, "required": ["path", "old_text", "new_text"]}},
    {"name": "TodoWrite", "description": "Update task tracking list.",
     "input_schema": {"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object", "properties": {"content": {"type": "string"}, "status": {"type": "string", "enum": ["pending", "in_progress", "completed"]}, "activeForm": {"type": "string"}}, "required": ["content", "status", "activeForm"]}}}, "required": ["items"]}},
    {"name": "task", "description": "Spawn a subagent for isolated exploration or work.",
     "input_schema": {"type": "object", "properties": {"prompt": {"type": "string"}, "agent_type": {"type": "string", "enum": ["Explore", "general-purpose"]}}, "required": ["prompt"]}},
    {"name": "load_skill", "description": "Load specialized knowledge by name.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "compress", "description": "Manually compress conversation context.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "background_run", "description": "Run command in background thread.",
     "input_schema": {"type": "object", "properties": {"command": {"type": "string"}, "timeout": {"type": "integer"}}, "required": ["command"]}},
    {"name": "check_background", "description": "Check background task status.",
     "input_schema": {"type": "object", "properties": {"task_id": {"type": "string"}}}},
    {"name": "task_create", "description": "Create a persistent file task.",
     "input_schema": {"type": "object", "properties": {"subject": {"type": "string"}, "description": {"type": "string"}}, "required": ["subject"]}},
    {"name": "task_get", "description": "Get task details by ID.",
     "input_schema": {"type": "object", "properties": {"task_id": {"type": "integer"}}, "required": ["task_id"]}},
    {"name": "task_update", "description": "Update task status or dependencies.",
     "input_schema": {"type": "object", "properties": {"task_id": {"type": "integer"}, "status": {"type": "string", "enum": ["pending", "in_progress", "completed", "deleted"]}, "add_blocked_by": {"type": "array", "items": {"type": "integer"}}, "add_blocks": {"type": "array", "items": {"type": "integer"}}}, "required": ["task_id"]}},
    {"name": "task_list", "description": "List all tasks.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "spawn_teammate", "description": "Spawn a persistent autonomous teammate.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}, "role": {"type": "string"}, "prompt": {"type": "string"}}, "required": ["name", "role", "prompt"]}},
    {"name": "list_teammates", "description": "List all teammates.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "send_message", "description": "Send a message to a teammate.",
     "input_schema": {"type": "object", "properties": {"to": {"type": "string"}, "content": {"type": "string"}, "msg_type": {"type": "string", "enum": list(VALID_MSG_TYPES)}}, "required": ["to", "content"]}},
    {"name": "read_inbox", "description": "Read and drain the lead's inbox.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "broadcast", "description": "Send message to all teammates.",
     "input_schema": {"type": "object", "properties": {"content": {"type": "string"}}, "required": ["content"]}},
    {"name": "shutdown_request", "description": "Request a teammate to shut down.",
     "input_schema": {"type": "object", "properties": {"teammate": {"type": "string"}}, "required": ["teammate"]}},
    {"name": "plan_approval", "description": "Approve or reject a teammate's plan.",
     "input_schema": {"type": "object", "properties": {"request_id": {"type": "string"}, "approve": {"type": "boolean"}, "feedback": {"type": "string"}}, "required": ["request_id", "approve"]}},
    {"name": "idle", "description": "Enter idle state.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "claim_task", "description": "Claim a task from the board.",
     "input_schema": {"type": "object", "properties": {"task_id": {"type": "integer"}}, "required": ["task_id"]}},
]

# 下面是一个 message 的例子。

# messages = [
#     # ──────────────────────────────────────────────
#     # 第 1 轮：用户输入
#     # ──────────────────────────────────────────────
#     {
#         "role": "user",
#         "content": "读取 main.py，找到 bug 并修复它"
#     },

#     # ──────────────────────────────────────────────
#     # 第 1 轮：Assistant 回复（请求调用工具 read_file）
#     # ──────────────────────────────────────────────
#     {
#         "role": "assistant",
#         "content": [
#             {
#                 "type": "text", ⭐️⭐️⭐️⭐️⭐️
#                 "text": "让我先读取 main.py 的内容。"
#             },
#             {
#                 "type": "tool_use", ⭐️⭐️⭐️⭐️⭐️
#                 "id": "toolu_01A2B3C4D5",
#                 "name": "read_file",
#                 "input": {"path": "main.py"}
#             }
#         ]
#     },

#     # ──────────────────────────────────────────────
#     # 第 1 轮：工具执行结果（由代码注入，role=user）
#     # ──────────────────────────────────────────────
#     {
#         "role": "user",
#         "content": [
#             {
#                 "type": "tool_result",
#                 "tool_use_id": "toolu_01A2B3C4D5",
#                 "content": "import os\n\ndef greet(name)\n    print(f'Hello, {name}!')\n\ngreet('World')"
#             }
#         ]
#     },

#     # ──────────────────────────────────────────────
#     # 第 2 轮：Assistant 发现 bug，请求调用 edit_file
#     # ──────────────────────────────────────────────
#     {
#         "role": "assistant",
#         "content": [
#             {
#                 "type": "text",
#                 "text": "找到了！第 3 行 `def greet(name)` 缺少冒号。让我修复。"
#             },
#             {
#                 "type": "tool_use",
#                 "id": "toolu_02E6F7G8H9",
#                 "name": "edit_file",
#                 "input": {
#                     "path": "main.py",
#                     "old_text": "def greet(name)",
#                     "new_text": "def greet(name):"
#                 }
#             }
#         ]
#     },

#     # ──────────────────────────────────────────────
#     # 第 2 轮：edit_file 的执行结果
#     # ──────────────────────────────────────────────
#     {
#         "role": "user",
#         "content": [
#             {
#                 "type": "tool_result",
#                 "tool_use_id": "toolu_02E6F7G8H9",
#                 "content": "Edited main.py"
#             }
#         ]
#     },

#     # ──────────────────────────────────────────────
#     # 第 3 轮：Assistant 用 bash 验证修复
#     # ──────────────────────────────────────────────
#     {
#         "role": "assistant",
#         "content": [
#             {
#                 "type": "text",
#                 "text": "已修复。运行一下确认没有其他问题。"
#             },
#             {
#                 "type": "tool_use",
#                 "id": "toolu_03I0J1K2L3",
#                 "name": "bash",
#                 "input": {"command": "python main.py"}
#             }
#         ]
#     },

#     # ──────────────────────────────────────────────
#     # 第 3 轮：bash 执行结果
#     # ──────────────────────────────────────────────
#     {
#         "role": "user",
#         "content": [
#             {
#                 "type": "tool_result",
#                 "tool_use_id": "toolu_03I0J1K2L3",
#                 "content": "Hello, World!"
#             }
#         ]
#     },

#     # ──────────────────────────────────────────────
#     # 第 3 轮：Assistant 最终回复（stop_reason="end_turn"，循环结束）
#     # ──────────────────────────────────────────────
#     {
#         "role": "assistant",
#         "content": [
#             {
#                 "type": "text",
#                 "text": "✅ 已修复！问题是 `def greet(name)` 缺少冒号。\n\n修改：`def greet(name)` → `def greet(name):`\n\n运行验证输出 `Hello, World!`，一切正常。"
#             }
#         ]
#     },
# ]

# === SECTION: agent_loop ===
# Agent 的核心循环：发消息给 LLM → 解析工具调用 → 执行工具 → 循环直到 LLM 返回普通回复
def agent_loop(messages: list):
    rounds_without_todo = 0
    while True: # ⭐️⭐️⭐️⭐️⭐️ 这是单次会话的 agent loop。
        microcompact(messages)
        # 保留最近 3 个工具结果的完整内容，把更早的、超过 100 字符的工具结果替换成 "[cleared]"，以节省 token。
        if estimate_tokens(messages) > TOKEN_THRESHOLD:
            # 如果当前 messages 中的 token 数已经超过了一个阈值，那么就需要进行 context 压缩。
            # TOKEN_THRESHOLD 是触发对话压缩的 Token 上限
            print("[auto-compact triggered]")
            messages[:] = auto_compact(messages)
            # 当对话太长时，把完整历史存到磁盘，然后让 LLM 生成摘要，用这个摘要替换掉整个 messages 列表。
            
        # 把后台线程已完成的任务结果，包装成对话消息注入到 messages 中，让 LLM 知道后台发生了什么。
        notifs = BG.drain()
        # 查看后台任务的执行结果。
        if notifs:
            txt = "\n".join(f"[bg:{n['task_id']}] {n['status']}: {n['result']}" for n in notifs)
            # 将每条通知格式化为 [bg:task_id] status: result，用换行连接成一段文本。
            messages.append({"role": "user", "content": f"<background-results>\n{txt}\n</background-results>"})
            # 以 user 消息插入，告诉 LLM 有后台任务完成了。
            messages.append({"role": "assistant", "content": "Noted background results."})
            # 再插入一条 assistant 消息，模拟 LLM 已确认收到，避免 LLM 重复询问后台结果。

        inbox = BUS.read_inbox("lead")
        # 处理来自其他 agent 的消息。
        # 从消息总线读取身份为 "lead" 的 agent 的收件箱（其他 agent 发给它的消息）。
        if inbox:
            messages.append({"role": "user", "content": f"<inbox>{json.dumps(inbox, indent=2)}</inbox>"})
            messages.append({"role": "assistant", "content": "Noted inbox messages."})
            # 如果 inbox 有内容，将其 JSON 序列化后包装成 <inbox> 标签的 user 消息注入，然后插入一条 assistant 确认消息。
            # ⭐️⭐️⭐️⭐️⭐️ 这是一个多 agent 协作架构，lead 是主 agent，它会接收其他 agent发来的消息（inbox）和后台任务结果（notifs），统一注入到对话上下文中，让 LLM 知道"有什么新消息"。

        # LLM call
        response = client.messages.create(
            model=MODEL, system=SYSTEM, messages=messages,
            tools=TOOLS, max_tokens=8000,
        )
        # 调用 LLM API，传入当前对话上下文（messages）、系统提示（SYSTEM）、可用工具（TOOLS），最大返回 8000 tokens。
        # ⭐️⭐️⭐️⭐️⭐️ 这是 Anthropic 官方 Python SDK（anthropic 包）提供的标准调用方式。这里除了需要传入 messages 之外，还需要传入 Tools，这里的 Tools 的定义需要遵循一定的规范，同时由于是 Anthropic 给出的标准，因此 Claude 模型对 Tools 的解析肯定是最好的，如果我们要换一套 LLM，那么 LLM 的解析就不一定精准了。
        
        messages.append({"role": "assistant", "content": response.content})
        # LLM 的回复追加到对话历史。
        if response.stop_reason != "tool_use":
            return
        # 如果 LLM 没有调用工具（只是普通回复），则退出 agent_loop，结束这一轮对话。
        # 如果 LLM 判断需要调用工具，那么就需要继续执行。

        # Tool execution
        results = []
        # 初始化一个空列表，用来收集本轮所有工具调用的执行结果，最后会一次性打包发回给 LLM。
        used_todo = False
        # 标记本轮是否调用了 TodoWrite。用于后面的"nag reminder"逻辑——如果连续几轮都没更新 todo，就提醒 LLM。
        manual_compress = False
        # 标记本轮是否调用了 compress 工具。因为压缩要等所有工具都执行完之后再做，所以先用一个 flag 记下来，不能在循环中途就压缩。
        for block in response.content:
            if block.type == "tool_use":
                # 只处理工具调用块，跳过纯文本块（文本块已经在前面追加进 messages 了）。
                if block.name == "compress":
                    # 如果 LLM 请求压缩对话，先打个标记，等循环结束后再统一处理，而不是立刻压缩——因为当前循环还在遍历 response，中途修改 messages 会造成混乱。
                    manual_compress = True
                handler = TOOL_HANDLERS.get(block.name)
                # 从 TOOL_HANDLERS 字典里查找对应工具名的处理函数。如果工具名不存在，返回 None。
                # TOOL_HANDLERS 是一个 dict，存储了各种各样的工具。
                try:
                    output = handler(**block.input) if handler else f"Unknown tool: {block.name}"
                    # 如果找到了 handler，就用 **block.input 把 LLM 传来的参数解包后调用它；如果没找到，返回一条错误提示字符串。**block.input 是字典解包，比如 {"command": "ls"} 会变成 handler(command="ls")。
                except Exception as e:
                    output = f"Error: {e}"
                    # 捕获工具执行过程中的任何异常，转成字符串返回给 LLM，而不是让整个程序崩溃。LLM 收到报错后可以自行决定下一步怎么办。
                print(f"> {block.name}: {str(output)[:200]}")
                # 在终端打印本次工具调用的名字和输出的前 200 个字符，方便开发者实时观察 Agent 在做什么。

                results.append({"type": "tool_result", "tool_use_id": block.id, "content": str(output)})
                # 把工具执行结果封装成 Anthropic API 要求的格式，追加进 results 列表。tool_use_id 必须与 LLM 请求时的 block.id 对应，API 靠这个 ID 把"请求"和"结果"配对起来。

                if block.name == "TodoWrite":
                    # 如果本次调用的是 TodoWrite，把标记置为 True，用于循环结束后重置"连续未更新 todo"的计数器。
                    # ⭐️⭐️⭐️⭐️⭐️ 从这里也可以看出来，整个的 Agent 的宏观范式是 Plan and Solve。
                    used_todo = True
        
        rounds_without_todo = 0 if used_todo else rounds_without_todo + 1
        # 三元表达式。如果本轮用了 TodoWrite，计数器归零；否则计数器加一。用来追踪"LLM 已经连续几轮没有更新 todo 了"。
        if TODO.has_open_items() and rounds_without_todo >= 3:
            # 两个条件同时满足才触发提醒：
            # * TODO.has_open_items()：todo 列表里还有未完成的项目
            # * rounds_without_todo >= 3：LLM 已经连续 3 轮没有更新 todo。
            results.insert(0, {"type": "text", "text": "<reminder>Update your todos.</reminder>"})
            # 在 results 列表的最前面插入一条提醒文本。用 insert(0, ...) 而不是 append 是为了让提醒出现在所有工具结果之前，确保 LLM 第一眼就看到它。
            # 这里有一个问题是——为什么这里需要提醒 Claude 要更新 TODO？首先我们需要了解代码的背景逻辑。
            # 1. 用户给 Claude 一个复杂任务
            # 2. Claude 应该先用 TodoWrite 工具把任务拆解成 todo 列表
            # 3. 然后逐步执行，每完成一步就更新 todo 状态
            # 4. 直到所有 todo 完成
            # Claude 在专注执行任务时（比如连续调用 bash、edit_file），很容易忘记回过头来更新 todo 状态。导致 =>
            # [>] 修复 bug        ← 明明已经修完了，状态还是 in_progress
            # [ ] 写测试
            # [ ] 提交代码
            # ⭐️⭐️⭐️⭐️⭐️ 所以这本质上这是一种"行为约束"机制，因为不能保证 Claude 每轮都自觉维护 todo，所以用代码强制提醒它。
        messages.append({"role": "user", "content": results})
        # 把本轮所有工具执行结果（以及可能的提醒）打包成一条 role: user 的消息追加进对话历史。这是 Anthropic API 的协议要求——工具结果必须以 user 角色回传。
    
        if manual_compress:
            print("[manual compact]")
            messages[:] = auto_compact(messages)
        # 如果本轮 LLM 调用了 compress 工具，现在才真正执行压缩。
        # messages[:] = auto_compact(messages) 是一个值得注意的写法——用切片赋值而不是 messages = auto_compact(messages)，区别是：
        # * messages = ...：创建一个新列表，外部持有的引用不受影响
        # * messages[:] = ...：原地修改同一个列表对象，agent_loop 外部（history）持有的引用也会同步更新



# === SECTION: repl ===
# 1. 打印 \033[36ms_full >> \033[0m 这个青色提示符等待输入
# 2. 用户输入 → 加入 history 列表 → 调用 agent_loop(history) 处理 → 打印结果 → 循环
# 3. 四个内置调试命令（无需 Agent，直接本地读取状态）：
# - /compact — 手动触发上下文压缩
# - /tasks — 打印任务管理器中所有任务
# - /team — 打印所有队友 Agent 状态
# - /inbox — 打印自己（lead）的收件箱消息
if __name__ == "__main__":
    history = []
    # 对话历史列表，这是发给模型的上下文。
    while True: # ⭐️⭐️⭐️⭐️⭐️ 这是整个 Agent 的循环。
        try:
            query = input("\033[36ms_full >> \033[0m")
            # 打印提示符等待输入 
        except (EOFError, KeyboardInterrupt):
            break # Ctrl+D / Ctrl+C 优雅退出
        if query.strip().lower() in ("q", "exit", ""):
            break # 输入空/q/exit 也退出
        if query.strip() == "/compact":
            # 手动触发上下文压缩
            if history:
                print("[manual compact via /compact]")
                history[:] = auto_compact(history)
            continue
        if query.strip() == "/tasks":
            # 查看所有任务状态
            print(TASK_MGR.list_all())
            continue
        if query.strip() == "/team":
            # 查看所有队友 Agent 状态
            print(TEAM.list_all())
            continue
        if query.strip() == "/inbox":
            # 查看收件箱消息
            print(json.dumps(BUS.read_inbox("lead"), indent=2))
            continue
        history.append({"role": "user", "content": query})
        # 把用户输入加入历史。
        agent_loop(history)
        # 发送给 Agent 处理
        print()
