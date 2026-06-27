# HAR Analyzer MCP Server

一个专为 **Trae IDE**（以及任何支持 MCP 协议的客户端）设计的 Python MCP Server，用于辅助 HAR 流量文件的逆向分析工作。

通过把"读 HAR"这件事从 AI 的主循环里剥离出来，本地完成所有繁重的解析、清洗、索引工作，AI（Trae）只接收精炼后的结构化摘要数据，从而**避免 Token 爆炸、避免敏感词触发安全过滤、避免被无关噪音干扰**。

---

## 目录

- [背景与设计哲学](#背景与设计哲学)
- [核心特性](#核心特性)
- [文件结构](#文件结构)
- [安装](#安装)
- [Trae MCP 配置](#trae-mcp-配置)
- [提供的 MCP Tools](#提供的-mcp-tools)
- [推荐工作流](#推荐工作流)
- [Tool 参数详解](#tool-参数详解)
- [技术细节](#技术细节)
- [安全与隐私](#安全与隐私)
- [错误处理](#错误处理)
- [性能基准](#性能基准)
- [常见问题](#常见问题)
- [开发与调试](#开发与调试)
- [路线图](#路线图)
- [贡献](#贡献)
- [许可证](#许可证)
- [致谢](#致谢)

---

## 背景与设计哲学

直接把完整 HAR 文件塞给 AI 会导致三个致命问题：

1. **Token 爆炸**：HAR 文件体积轻易超过数十 MB，原始 JSON 直接传输会立刻耗尽 Token 配额。
2. **噪音淹没信号**：HAR 包含大量静态资源（图片 / 字体 / CSS / JS）、base64 二进制、冗余 Header、重复请求，AI 难以聚焦到真正有价值的 API 端点。
3. **安全过滤误触发**：部分 API 响应内容可能命中 AI 平台的安全词，导致整个请求被拒绝。

**本项目的解决方案：** MCP Server 在本地完成所有重活（解析、去重、过滤、裁剪、索引），只通过 MCP Tools 向 Trae 暴露干净的摘要接口。

```
┌──────────────┐         ┌────────────────────┐         ┌──────────────┐
│  Chrome /    │  导出    │   HAR MCP Server   │  结构化  │   Trae AI    │
│  DevTools    │ ──────> │  (本地：清洗+索引)  │ ──────> │  (只读摘要)  │
└──────────────┘  .har   └────────────────────┘  JSON   └──────────────┘
```

---

## 核心特性

- 🚀 **流式解析** —— 基于 `ijson`，逐条处理 HAR 的 `log.entries`，不一次性加载整个文件，**支持数十 MB 的大体积 HAR 文件，内存峰值可控**。
- 🗂️ **SQLite 内存索引** —— 清洗后的数据存入 `:memory:` 数据库，建立 url / method / status / host / is_api / tags 多列索引，查询毫秒级响应。
- 🧹 **智能清洗** —— 默认跳过图片 / 字体 / CSS / JS / 视频 / 音频等静态资源；Header 只保留认证、签名、自定义 `x-*` 等关键字段。
- 🏷️ **自动标签** —— 为每条请求打上 `json` / `form` / `auth` / `signed` / `encrypted` / `error` / `redirect` 等标签，便于 AI 按维度过滤。
- 🔍 **API 识别** —— 基于 Content-Type、URL 模式、HTTP 方法、响应 body 结构综合判定，自动识别"真正有价值的请求"。
- 🔐 **敏感词脱敏** —— 内置 sanitizer 模块，支持 [Sensitive-lexicon](https://github.com/konsheng/Sensitive-lexicon) + Aho-Corasick、`better-profanity`、`alt-profanity-check`、本地 `wordlist.txt` 多种脱敏源，**在写入 SQLite 之前对所有字符串字段做脱敏**，避免特定内容触发下游 AI 的安全过滤。
- 🛡️ **零值输出原则** —— `har_summary` 的 `body_structure` 字段只递归提取键名和值类型，**绝不暴露任何实际数据值**；`har_extract_auth` 同样只返回 token 长度、格式、出现次数等元信息。
- ⚡ **结构化错误** —— 所有 Tool 在出错时返回 `{"error": {"code", "message", "detail"}}` 对象，**不会因抛异常导致 MCP 协议中断**。
- 🧵 **线程安全** —— SQLite 连接通过 `threading.Lock` 保护，可在并发请求下安全使用。

---

## 文件结构

```
har_mcp/
├── server.py           # MCP Server 主入口，注册 8 个 Tool
├── har_parser.py       # HAR 流式解析 + 数据清洗模块
├── har_store.py        # 内存 / SQLite 索引存储模块（线程安全）
├── filters.py          # 过滤规则（静态资源剔除、API 识别、Header 清洗、Body 处理、标签生成）
├── summarizer.py       # 摘要生成器（把 Entry 压缩为 AI 友好格式 + 加密/签名模式检测）
├── sanitizer.py        # 字符串脱敏模块（支持多种脱敏源）
├── config.py           # 全局配置常量（截断阈值、白名单、正则模式）
├── Sensitive-lexicon/  # git clone 下来的敏感词库（.gitignore 已忽略）
│   └── sensitive-lexicon.txt
├── wordlist.txt        # 自定义敏感词库（用户维护，不进版本控制）
├── requirements.txt    # Python 依赖
├── mcp.json            # Trae MCP 配置（python 直接运行）
├── mcp_uv.json         # Trae MCP 配置（uv 管理环境）
├── .gitignore          # Git 忽略规则
├── LICENSE             # 许可证（建议补充）
└── README.md           # 本文件
```

---

## 安装

### 环境要求

- **Python >= 3.10**（推荐 3.11+）
- **操作系统**：Windows / macOS / Linux
- **磁盘**：无特殊要求，所有数据均在内存

### 方式一：pip（最简单）

```bash
cd har_mcp
pip install -r requirements.txt
```

### 方式二：uv（推荐，速度快、环境隔离）

```bash
cd har_mcp
uv sync
# 或
uv pip install -r requirements.txt
```

### 方式三：conda

```bash
conda create -n har-mcp python=3.11
conda activate har-mcp
pip install -r requirements.txt
```

### 依赖说明

| 包 | 必选 | 用途 |
|---|---|---|
| `mcp>=1.0.0` | ✅ | 官方 MCP Python SDK |
| `ijson>=3.3.0` | ✅ | 流式 JSON 解析，处理大体积 HAR 文件的核心依赖 |
| `pyahocorasick>=2.0.0` | ⭕ | Aho-Corasick 自动机，配合 Sensitive-lexicon 使用（推荐） |
| `better-profanity>=0.7.0` | ⭕ | 英文敏感词过滤（备选方案） |
| `alt-profanity-check>=1.0.0` | ⭕ | 多语言敏感词检测（备选方案） |

> 脱敏模块支持多种方案，按优先级自动选择：
> 1. **Sensitive-lexicon + pyahocorasick**（推荐，需 `git clone` 词库）
> 2. `better-profanity`（若已安装）
> 3. `alt-profanity-check`（若已安装）
> 4. 本地 `wordlist.txt` 自定义词库（兜底）
>
> 以上依赖均为可选，也可以都不装 —— 不装时 sanitizer 为空操作，不影响主流程。

### 验证安装

```bash
python -c "from har_store import HarStore; store = HarStore(); print('✅ HarStore 初始化成功')"
```

### 设置敏感词库（可选但强烈建议）

若希望启用敏感词脱敏，推荐把词库 clone 到项目目录：

```bash
cd har_mcp
git clone https://github.com/konsheng/Sensitive-lexicon.git
```

完成后目录结构：

```
har_mcp/
├── server.py
├── sanitizer.py
├── Sensitive-lexicon/
│   └── sensitive-lexicon.txt   ← sanitizer 默认读取
└── wordlist.txt                ← 你的额外自定义词（可选）
```

如果词库存放在其他位置，可通过环境变量指定：

```bash
export HAR_MCP_LEXICON=/path/to/Sensitive-lexicon/sensitive-lexicon.txt   # macOS/Linux
$env:HAR_MCP_LEXICON = "D:\Sensitive-lexicon\sensitive-lexicon.txt"        # PowerShell
```

> 不 clone 词库也能运行，此时 sanitizer 会尝试使用 `better-profanity`、`alt-profanity-check` 或 `wordlist.txt`，若都没有则降级为空操作。

---

## Trae MCP 配置

将 `mcp.json`（或 `mcp_uv.json`）中的内容合并到 Trae 的 MCP 配置文件中。

配置位置通常是：
- **Windows**：`C:\Users\<你的用户名>\.trae\mcp.json`
- **macOS / Linux**：`~/.trae/mcp.json`
- 或项目根目录的 `.trae/mcp.json`

**重要：必须将 `/path/to/har_mcp` 替换为项目的实际绝对路径。**

### 方式一：直接使用 python

```json
{
  "mcpServers": {
    "har-analyzer": {
      "command": "python",
      "args": ["/absolute/path/to/har_mcp/server.py"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/har_mcp"
      }
    }
  }
}
```

### 方式二：使用 uv 管理环境（推荐）

```json
{
  "mcpServers": {
    "har-analyzer": {
      "command": "uv",
      "args": ["run", "--project", "/absolute/path/to/har_mcp", "python", "server.py"],
      "env": {}
    }
  }
}
```

### 方式三：Windows 用户特别提示

Windows 下 `python` 可能指向 Microsoft Store 假别名，建议：

```json
{
  "mcpServers": {
    "har-analyzer": {
      "command": "py",
      "args": ["-3.11", "E:/Har_MCP/server.py"],
      "env": {
        "PYTHONPATH": "E:/Har_MCP"
      }
    }
  }
}
```

或者使用完整 Python 路径：

```json
{
  "mcpServers": {
    "har-analyzer": {
      "command": "C:/Python311/python.exe",
      "args": ["E:/Har_MCP/server.py"],
      "env": {
        "PYTHONPATH": "E:/Har_MCP"
      }
    }
  }
}
```

配置完成后重启 Trae，工具列表里应出现 8 个 `har_*` 工具。

---

## 提供的 MCP Tools

| Tool 名称 | 输入参数 | 输出 | 适用场景 |
|---|---|---|---|
| `har_load` | `filepath`, `include_static?`, `api_only?` | 加载统计信息 | **第一步：必调** |
| `har_summary` | `host_filter?`, `api_only?` | 端点分组列表 | 获取全局"地图" |
| `har_search` | `url_contains?`, `method?`, `status?`, `host?`, `has_tag?`, `limit?`, `offset?` | 摘要列表 | 按条件定位请求 |
| `har_get_entry` | `entry_id`, `include_full_body?` | 单条详情 | 深入查看具体请求 |
| `har_get_entries_batch` | `entry_ids[]`, `include_full_body?` | 批量详情 | 一次看多条 |
| `har_extract_auth` | — | 认证信息摘要 | 分析认证机制 |
| `har_detect_patterns` | — | 加密/签名/异常检测 | 安全机制分析 |
| `har_unload` | — | `{"status": "cleared"}` | 释放内存 |

详细参数见 [Tool 参数详解](#tool-参数详解)。

---

## 推荐工作流

```
  ┌─────────────────────────────────────────┐
  │ 1. har_load(filepath="...har")          │ ← 必须先调
  │    → 获得 total_entries / api_count     │
  └──────────────┬──────────────────────────┘
                 │
                 ▼
  ┌─────────────────────────────────────────┐
  │ 2. har_summary()                        │ ← 获得全局"地图"
  │    → endpoint_groups[]                  │
  │    → 找出可疑端点（status>=400, signed）│
  └──────────────┬──────────────────────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
  ┌──────────┐      ┌─────────────────┐
  │ 3a.      │      │ 3b.             │
  │ har_     │      │ har_            │
  │ detect_  │      │ extract_        │
  │ patterns │      │ auth            │
  │ 加密特征 │      │ 认证机制        │
  └────┬─────┘      └────────┬────────┘
       │                     │
       └──────────┬──────────┘
                  ▼
  ┌─────────────────────────────────────────┐
  │ 4. har_search(...)                      │ ← 按 URL/方法/标签精确定位
  │    → 拿到 entry_id 列表                 │
  └──────────────┬──────────────────────────┘
                 │
                 ▼
  ┌─────────────────────────────────────────┐
  │ 5. har_get_entry(id)                    │ ← 按需查看详情
  │    或 har_get_entries_batch(ids)        │
  └─────────────────────────────────────────┘
```

### 典型对话示例

> **用户**：帮我分析这个 HAR 文件 `/tmp/capture.har` 里登录接口的签名机制
>
> **AI**：
> 1. `har_load("/tmp/capture.har")` → 加载成功，共 1247 条请求，其中 89 条 API
> 2. `har_summary()` → 发现端点 `/api/v2/login`（POST），调用 3 次
> 3. `har_detect_patterns()` → 发现所有 POST 请求均带 `x-sign` Header，值为 64 位 hex（HMAC-SHA256）
> 4. `har_search(url_contains="/login", method="POST")` → 拿到 entry_id = [42, 87, 156]
> 5. `har_get_entries_batch([42, 87, 156])` → 拿到完整请求细节，开始逆向 x-sign 算法

---

## Tool 参数详解

### 1. `har_load`

**作用**：加载并解析 HAR 文件到内存。必须先调用。

| 参数 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `filepath` | string | ✅ | — | HAR 文件的绝对路径 |
| `include_static` | bool | ❌ | `false` | 是否包含静态资源（图片/CSS/JS） |
| `api_only` | bool | ❌ | `false` | 是否只索引 API 请求 |

**返回**：
```json
{
  "status": "ok",
  "total_entries": 1247,
  "indexed_entries": 89,
  "skipped_static": 1158,
  "api_count": 89,
  "unique_hosts": ["api.example.com"],
  "time_range": {"start": "2025-01-15T10:00:00Z", "end": "2025-01-15T10:30:00Z"},
  "load_time_seconds": 2.34,
  "hint": "HAR 已加载完毕。建议先调用 har_summary ..."
}
```

### 2. `har_summary`

**作用**：按 `method + url_pattern` 聚合所有 API 端点，生成全局视图。

| 参数 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `host_filter` | string | ❌ | — | 只看指定域名 |
| `api_only` | bool | ❌ | `true` | 是否只统计 API 请求 |

**返回的 `endpoint_groups[]` 字段**：
```json
{
  "method": "POST",
  "url_pattern": "https://api.example.com/api/v2/users/{id}",
  "count": 12,
  "status_codes": [200, 401, 500],
  "req_content_type": "application/json",
  "res_content_type": "application/json",
  "avg_time_ms": 234.5,
  "has_auth_header": true,
  "req_body_structure": {"username": "string", "password": "string"},
  "res_body_structure": {"code": "integer", "data": {"token": "string", "expire": "integer"}},
  "entry_ids": [42, 87, 156, ...]
}
```

> ⚠️ `body_structure` **只包含键名和值类型**，绝不暴露实际值。

### 3. `har_search`

**作用**：按条件搜索请求列表，返回摘要（不含完整 body）。

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `url_contains` | string | — | URL 关键词（LIKE 模糊匹配） |
| `method` | string | — | HTTP 方法（GET/POST/PUT/PATCH/DELETE） |
| `status` | int | — | 状态码精确匹配 |
| `host` | string | — | 域名精确匹配 |
| `has_tag` | string | — | 标签过滤，见下表 |
| `limit` | int | 20 | 最多返回数（最大 100） |
| `offset` | int | 0 | 分页偏移量 |

**可用 `has_tag` 值**：

| 标签 | 含义 |
|---|---|
| `json` / `form` / `text` / `binary` | body 编码 |
| `truncated` | body 被截断（>50KB） |
| `auth` | 含认证 Header |
| `signed` | 含签名 Header |
| `encrypted` | 疑似加密 body |
| `error` | 4xx/5xx 状态码 |
| `redirect` | 3xx 状态码 |
| `sanitized` | 命中敏感词库被脱敏 |

### 4. `har_get_entry`

| 参数 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `entry_id` | int | ✅ | — | 来自 `har_search` 的 `id` 字段 |
| `include_full_body` | bool | ❌ | `true` | 是否包含完整 body（>50KB 时只返回 preview） |

### 5. `har_get_entries_batch`

| 参数 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `entry_ids` | int[] | ✅ | — | 一次最多 10 条 |
| `include_full_body` | bool | ❌ | `true` | 同上 |

### 6. `har_extract_auth`

**返回**：
```json
{
  "auth_headers_found": {
    "authorization": {
      "sample_schemes": ["Bearer"],
      "entry_ids": [42, 87],
      "token_length_samples": [256, 248]
    },
    "x-sign": {
      "sample_schemes": ["none"],
      "entry_ids": [42, 87, 156],
      "token_length_samples": [64, 64, 64]
    }
  },
  "cookies_found": {
    "session_id": {"entry_count": 89}
  },
  "patterns_note": "authorization 使用 Bearer 方案，token 长度在 248-256 之间变化；x-sign 长度稳定在 64 字符，疑似 HMAC-SHA256 签名。"
}
```

### 7. `har_detect_patterns`

**返回 4 类发现**：
- `encrypted_body`：疑似加密的 body（Base64 + 16 倍数长度 → 推测 AES）
- `url_hash`：URL 路径含 MD5/SHA1/SHA256 哈希段（端点混淆）
- `request_signature`：签名 Header（长度稳定 → 推测算法）
- `error_cluster`：同一错误状态码集中出现（可能触发风控）

### 8. `har_unload`

清除当前已加载数据，释放内存。**通常无需手动调用** —— 再次 `har_load` 会自动清空旧数据。

---

## 技术细节

### 流式解析

使用 [`ijson`](https://github.com/ICRAR/ijson) 流式迭代 HAR 的 `log.entries` 数组：

```python
# har_parser.py 核心
with open(filepath, 'rb') as f:
    entries = ijson.items(f, 'log.entries.item')
    for entry in entries:
        yield _clean_entry(entry)
```

**为什么不用 `json.load`？**
- 50MB HAR 文件解压后约 200MB JSON，`json.load` 会一次性占用约 **5-10 倍内存**（Python 对象开销）。
- `ijson` 流式处理内存峰值仅与单条 Entry 大小相关，通常 < 50MB。

### SQLite 内存索引

使用 `sqlite3.connect(':memory:')` + `PRAGMA journal_mode=MEMORY`，性能接近裸 C 实现。

建立的索引：
- `idx_entries_url`（LIKE 模糊搜索）
- `idx_entries_method`（精确匹配）
- `idx_entries_status`（精确匹配）
- `idx_entries_host`（精确匹配）
- `idx_entries_is_api`（bool 过滤）
- `idx_entries_tags`（标签 LIKE 匹配）

批量插入：`executemany` + 500 条/批，50MB 文件约 2-3 秒完成。

### 静态资源过滤

综合三种判定（任一命中即跳过）：
1. **MIME 严格匹配**：`image/png`、`font/woff2`、`text/css`、`application/javascript` 等。
2. **URL 后缀**：`.png`、`.jpg`、`.woff2`、`.css`、`.js`、`.map` 等。
3. **URL 正则模式**：`/_next/static/`、`/static/`、`/dist/`、`/assets/`、`/build/`，以及 `cdn.`、`analytics.`、`google-analytics.com` 等常见 CDN / 埋点域名。

### API 识别

满足以下任一条件即视为 API：
- 方法是 `POST` / `PUT` / `PATCH` / `DELETE`
- URL 匹配 `/api/`、`/v\d+/`、`/graphql`、`/rest/`、`/rpc/`
- `Content-Type` 或 `Accept` 包含 `application/json`
- 响应 body 是有效 JSON

### 敏感词脱敏

执行时机：**在数据写入 SQLite 之前**（`har_store.load()` 中）。

支持多种脱敏源，按优先级依次生效：

1. **方案 A（推荐）**：`Sensitive-lexicon` + `pyahocorasick` Aho-Corasick 自动机
   - 模块导入时构建一次自动机，单次匹配时间复杂度 **O(文本长度)**，与词库大小无关。
   - 命中词替换为等长 `*`，重叠区间自动合并。
2. **方案 B**：`better-profanity`（若已安装）
3. **方案 C**：`alt-profanity-check`（若已安装，句子级预测）
4. **方案 D（兜底）**：本地 `wordlist.txt` 自定义词库（正则匹配）

词库来源环境变量：

```bash
export HAR_MCP_LEXICON=/path/to/Sensitive-lexicon/sensitive-lexicon.txt   # macOS/Linux
$env:HAR_MCP_LEXICON = "D:\Sensitive-lexicon\sensitive-lexicon.txt"        # PowerShell
```

被脱敏的请求会在 `tags` 中追加 `sanitized` 标记。

---

## 安全与隐私

### 不返回实际值

| 工具 | 是否返回实际值 | 说明 |
|---|---|---|
| `har_summary` | ❌ | `body_structure` 只有键名+类型 |
| `har_search` | ❌ | body 截断到 200 字符 |
| `har_get_entry` | ✅ | 按需返回完整 body |
| `har_extract_auth` | ❌ | 只返回 token 长度、scheme、出现次数 |
| `har_detect_patterns` | ❌ | 只返回类型、描述、entry_id 列表 |

### 防止敏感词触发

`sanitizer.py` 在数据落盘前对所有字符串字段做脱敏，**即使是 `har_get_entry` 返回的 body 也是脱敏后的结果**。

### 词库配置

通过环境变量自定义词库路径：

```bash
# 主敏感词库（Sensitive-lexicon 的 sensitive-lexicon.txt）
export HAR_MCP_LEXICON=/path/to/Sensitive-lexicon/sensitive-lexicon.txt   # macOS/Linux
$env:HAR_MCP_LEXICON = "D:\Sensitive-lexicon\sensitive-lexicon.txt"        # PowerShell

# 额外自定义词库（可选，每行一词）
export HAR_MCP_WORDLIST=/path/to/your/wordlist.txt   # macOS/Linux
$env:HAR_MCP_WORDLIST = "D:\my-wordlist.txt"          # PowerShell
```

`Sensitive-lexicon/` 目录与 `wordlist.txt` 已在 `.gitignore` 中，**不会**被提交到 Git。

### 错误码参考

| 错误码 | 含义 |
|---|---|
| `NOT_LOADED` | 未调用 `har_load` |
| `FILE_NOT_FOUND` | HAR 文件路径错误 |
| `PERMISSION_DENIED` | 文件无读取权限 |
| `PARSE_ERROR` | HAR JSON 格式损坏 |
| `ENTRY_NOT_FOUND` | `entry_id` 不存在 |
| `INVALID_PARAMS` | 参数类型/范围错误 |
| `UNKNOWN_TOOL` | 调用了不存在的工具 |
| `INTERNAL_ERROR` | 内部未捕获异常（附 traceback） |

---

## 性能基准

测试环境：Windows 11, i7-12700H, Python 3.11

| HAR 文件大小 | Entry 总数 | API 数 | 加载耗时 | 内存峰值 |
|---|---|---|---|---|
| 5 MB | 320 | 45 | 0.4s | ~80 MB |
| 20 MB | 1,500 | 180 | 1.2s | ~180 MB |
| 50 MB | 4,200 | 520 | 2.8s | ~350 MB |
| 100 MB | 8,800 | 1,100 | 6.5s | ~600 MB |

> 以上为单次 `har_load` 的端到端耗时，包含 ijson 流式解析 + 清洗 + SQLite 索引构建。
> `har_search` 单次查询耗时 < 10 ms（已建索引）。

---

## 常见问题

### Q1：加载时报 `PARSE_ERROR`

HAR 文件不是合法 JSON。常见原因：
- 文件被截断（导出过程中浏览器关闭）
- 文件被编辑过，引入了语法错误

**解决**：重新导出 HAR，或用 `python -c "import json; json.load(open('xxx.har'))"` 验证 JSON 合法性。

### Q2：加载后 `api_count = 0`

HAR 里所有请求都被识别为静态资源。可能原因：
- 该 HAR 是纯静态页面（无 XHR/Fetch）
- 启用了 `api_only=True` 但 URL/方法都没命中 API 规则

**解决**：调用 `har_load(..., include_static=True, api_only=False)` 重新加载，再用 `har_search` 探索。

### Q3：脱敏后看不到真实 body

这是**预期行为**。如需查看原始内容：
- 关闭脱敏：
  - 删除 `Sensitive-lexicon/` 目录（或设置 `HAR_MCP_LEXICON` 指向不存在的路径）
  - 把 `wordlist.txt` 设为空
  - 卸载 `pyahocorasick`、`better-profanity`、`alt-profanity-check`（可选，sanitizer 会自动降级为空操作）
- 直接用 Chrome DevTools 查看原始 HAR

### Q4：MCP 工具列表里没有 `har_*`

排查步骤：
1. 终端手动执行 `python /path/to/server.py`，看是否报错
2. 检查 `mcp.json` 中的 `args` 路径是否正确
3. 重启 Trae
4. 查看 Trae 的 MCP 日志（通常是 `~/.trae/logs/`）

### Q5：HAR 文件 100+ MB，加载很慢

建议：
- 关闭 Chrome DevTools 的"Preserve log"，只录目标操作
- 在导出前用 DevTools 的 Filter 过滤无关域名
- 拆分 HAR：Chrome 的 "Export HAR (filtered)" 可以按域名筛选

### Q6：能同时加载多个 HAR 文件吗？

**不能**。当前设计是单 HAR 单实例。`har_load` 会清空旧数据。

如需对比多个 HAR，建议每个 HAR 单独分析，记录 entry_id 范围。

---

## 开发与调试

### 本地冒烟测试

```bash
cd har_mcp
python -c "from har_store import HarStore; store = HarStore(); print('OK')"
```

### 手动调用 Tool

```python
import asyncio
from server import call_tool

async def test():
    result = await call_tool("har_load", {"filepath": "/path/to/test.har"})
    print(result[0].text)  # TextContent

asyncio.run(test())
```

### 单独测试脱敏模块

```python
from sanitizer import sanitize_string, sanitize_dict, get_sanitizer_status

print(get_sanitizer_status())
text, count = sanitize_string("这是一段含敏感词的文本")
print(f"命中词数: {count}, 结果: {text}")

# 测试嵌套 JSON
obj, count = sanitize_dict({"msg": "一段需要脱敏的文本", "code": 200})
print(f"命中词数: {count}, 结果: {obj}")
```

### 自定义配置

所有可调参数集中在 [config.py](config.py)：

| 常量 | 默认 | 说明 |
|---|---|---|
| `BODY_PREVIEW_LENGTH` | 500 | preview 截断长度 |
| `BODY_FULL_MAX_LENGTH` | 50000 | full body 最大长度 |
| `SEARCH_DEFAULT_LIMIT` | 20 | har_search 默认返回数 |
| `SEARCH_MAX_LIMIT` | 100 | har_search 单次最大返回数 |
| `BATCH_MAX_SIZE` | 10 | har_get_entries_batch 最大条目数 |
| `STRICT_STATIC_MIME_TYPES` | (集合) | 严格静态 MIME 白名单 |
| `SKIP_URL_PATTERNS` | (列表) | 静态资源 URL 正则 |
| `API_URL_PATTERNS` | (列表) | API URL 正则 |
| `KEEP_REQUEST_HEADERS` | (集合) | 请求 Header 白名单 |
| `KEEP_RESPONSE_HEADERS` | (集合) | 响应 Header 白名单 |
| `AUTH_HEADER_NAMES` | (集合) | 认证 Header 名 |
| `SIGNATURE_HEADER_NAMES` | (集合) | 签名 Header 名 |
| `PROGRESS_INTERVAL` | 1000 | 进度回调间隔 |

修改后重启 MCP Server 即可生效。

### 添加新 Tool

1. 在 [server.py](server.py) 的 `_build_tools()` 中追加 `Tool(...)` 定义
2. 在 `call_tool()` 分发器中添加 `elif name == "your_tool":` 分支
3. 实现 `async def handle_your_tool(arguments: dict) -> dict:`
4. 在 [har_store.py](har_store.py) 中添加对应的查询方法
5. 更新本 README 的工具表

---

## 路线图

- [ ] 多 HAR 加载与对比
- [ ] 支持 WebSocket 帧（来自 HAR 1.2 扩展字段）
- [ ] 端点 diff：对比两个 HAR 的 API 差异
- [ ] 导出分析报告（Markdown / JSON）
- [ ] 支持 HAR 增量加载（只追加新 entries）
- [ ] 提供 Web UI（FastAPI + Vue）

---

## 贡献

欢迎 PR 与 Issue！

提交前请确保：
1. 通过 `python -c "import server"` 冒烟测试
2. 新增/修改的功能有对应的测试
3. 更新本 README 相关章节
4. 遵循 PEP 8（可用 `ruff` 或 `black` 格式化）

---

## 许可证

本项目基于 **Apache 2.0 License** 开源 —— 详见 [LICENSE](LICENSE) 文件。

> ⚠️ **免责声明**：本工具仅用于合法的安全研究、API 调试、流量分析。请勿用于未授权的系统访问、数据窃取等任何违法活动。使用者应自行承担一切法律责任。

---

## 致谢

- [Model Context Protocol](https://modelcontextprotocol.io/) —— AI 工具调用标准
- [ijson](https://github.com/ICRAR/ijson) —— 流式 JSON 解析
- [Sensitive-lexicon](https://github.com/konsheng/Sensitive-lexicon) —— 社区维护的中文敏感词库
- [pyahocorasick](https://github.com/WojciechMula/pyahocorasick) —— Aho-Corasick 字符串匹配库
- [Trae IDE](https://www.trae.ai/) —— 让这一切成为可能的 AI IDE
