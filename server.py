"""HAR Analyzer MCP Server 主入口。

注册 8 个 MCP Tool：
1. har_load              - 加载并解析 HAR 文件
2. har_summary           - 生成 API 端点聚合摘要
3. har_search            - 按条件搜索请求列表
4. har_get_entry         - 获取单条请求详情
5. har_get_entries_batch - 批量获取请求详情
6. har_extract_auth      - 提取认证信息摘要
7. har_detect_patterns   - 检测加密/签名特征
8. har_unload            - 清除已加载数据

设计要点：
- 全局 HarStore 单例，生命周期与 Server 进程相同
- 所有 Tool 返回结构化 JSON，错误时返回 {"error": {...}} 而非抛异常
- har_load 是耗时操作，支持进度回调（若 MCP 协议支持）
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import traceback
from typing import Any

# 确保当前目录在 sys.path 中，便于 import 同级模块
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if _CURRENT_DIR not in sys.path:
    sys.path.insert(0, _CURRENT_DIR)

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import mcp.types as types

from har_store import HarStore
from config import (
    BATCH_MAX_SIZE,
    SEARCH_DEFAULT_LIMIT,
    SEARCH_MAX_LIMIT,
)


# ============================================================
# 全局 HarStore 单例
# ============================================================
_store: HarStore | None = None
_store_lock = asyncio.Lock()


def get_store() -> HarStore:
    """获取全局 HarStore 单例。"""
    global _store
    if _store is None:
        _store = HarStore()
    return _store


# ============================================================
# 错误对象构造
# ============================================================
def make_error(code: str, message: str, detail: str = "") -> dict:
    """构造结构化错误对象。"""
    return {
        "error": {
            "code": code,
            "message": message,
            "detail": detail,
        }
    }


# ============================================================
# MCP Server 实例
# ============================================================
app = Server("har-analyzer")


# ============================================================
# Tool 定义
# ============================================================
def _build_tools() -> list[Tool]:
    """构建所有 Tool 定义。"""
    return [
        Tool(
            name="har_load",
            description=(
                "加载并解析 HAR 文件到内存，完成清洗和索引。必须先调用此工具，"
                "其他工具才能使用。支持流式解析大文件（数十 MB），自动过滤静态资源，"
                "识别 API 请求，并建立 SQLite 内存索引。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "HAR 文件的绝对路径"
                    },
                    "include_static": {
                        "type": "boolean",
                        "default": False,
                        "description": "是否包含静态资源（图片/CSS/JS 等），默认 False"
                    },
                    "api_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "是否只索引 API 请求，默认 False"
                    }
                },
                "required": ["filepath"]
            }
        ),
        Tool(
            name="har_summary",
            description=(
                "生成所有 API 端点的聚合摘要（去重 + 统计），是 AI 的'地图视图'。"
                "按 method + url_pattern 分组，返回每组的请求次数、状态码集合、"
                "平均耗时、请求/响应 body 结构（仅键名+类型，不暴露实际值）。"
                "建议在 har_load 后首先调用此工具获取全局视图。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "host_filter": {
                        "type": "string",
                        "description": "只看指定域名，留空则全部"
                    },
                    "api_only": {
                        "type": "boolean",
                        "default": True,
                        "description": "是否只统计 API 请求，默认 True"
                    }
                }
            }
        ),
        Tool(
            name="har_search",
            description=(
                "按条件搜索请求列表，返回摘要列表（不含完整 body）。"
                "支持按 URL 关键词、HTTP 方法、状态码、域名、标签过滤，"
                "支持分页。返回的每条结果包含 entry_id，可用于 har_get_entry 获取详情。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url_contains": {
                        "type": "string",
                        "description": "URL 包含的关键词"
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP 方法：GET/POST/PUT/PATCH/DELETE 等"
                    },
                    "status": {
                        "type": "integer",
                        "description": "HTTP 状态码，如 200/404/500"
                    },
                    "host": {
                        "type": "string",
                        "description": "域名过滤"
                    },
                    "has_tag": {
                        "type": "string",
                        "description": "标签过滤，可选值：json/form/text/binary/auth/signed/encrypted/error/redirect/truncated"
                    },
                    "limit": {
                        "type": "integer",
                        "default": SEARCH_DEFAULT_LIMIT,
                        "description": f"最多返回条目数，默认 {SEARCH_DEFAULT_LIMIT}，最大 {SEARCH_MAX_LIMIT}"
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "description": "分页偏移量"
                    }
                }
            }
        ),
        Tool(
            name="har_get_entry",
            description=(
                "获取单条请求的完整详情（含完整 body）。"
                "AI 在通过 har_search 定位目标后才调用此工具，避免一次性加载过多数据。"
                "对不存在的 entry_id 会返回结构化错误而非崩溃。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "entry_id": {
                        "type": "integer",
                        "description": "来自 har_search 结果的 id"
                    },
                    "include_full_body": {
                        "type": "boolean",
                        "default": True,
                        "description": "是否包含完整 body，默认 True"
                    }
                },
                "required": ["entry_id"]
            }
        ),
        Tool(
            name="har_get_entries_batch",
            description=(
                f"批量获取多条请求详情，一次最多 {BATCH_MAX_SIZE} 条。"
                "去掉单条循环的开销，适合在 har_summary 后批量查看一组端点的详情。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "entry_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": f"entry_id 列表，最多 {BATCH_MAX_SIZE} 个"
                    },
                    "include_full_body": {
                        "type": "boolean",
                        "default": True,
                        "description": "是否包含完整 body，默认 True"
                    }
                },
                "required": ["entry_ids"]
            }
        ),
        Tool(
            name="har_extract_auth",
            description=(
                "专门提取所有请求中出现的认证信息摘要，辅助逆向认证机制。"
                "返回认证 Header 的 scheme（Bearer/Basic/JWT 等）、出现次数、"
                "token 长度样本，以及 Cookie 统计。"
                "注意：不返回 token 的实际值，只返回长度、格式特征等元信息。"
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="har_detect_patterns",
            description=(
                "自动检测流量中的加密/混淆/签名特征，生成分析报告。"
                "检测项包括：加密 body（Base64 + 16 倍数长度）、URL 哈希混淆、"
                "请求签名 Header（x-sign/x-signature 等）、错误状态码集中。"
                "每项发现包含受影响的 entry_id 列表与证据描述。"
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="har_unload",
            description=(
                "清除当前已加载的 HAR 数据，释放内存。"
                "调用 har_load 会自动清空旧数据，通常无需手动调用此工具。"
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
    ]


@app.list_tools()
async def list_tools() -> list[Tool]:
    """列出所有可用的 Tool。"""
    return _build_tools()


# ============================================================
# Tool 调用分发
# ============================================================
@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.ContentBlock]:
    """Tool 调用入口，分发到对应 handler。"""
    try:
        if name == "har_load":
            result = await handle_har_load(arguments or {})
        elif name == "har_summary":
            result = await handle_har_summary(arguments or {})
        elif name == "har_search":
            result = await handle_har_search(arguments or {})
        elif name == "har_get_entry":
            result = await handle_har_get_entry(arguments or {})
        elif name == "har_get_entries_batch":
            result = await handle_har_get_entries_batch(arguments or {})
        elif name == "har_extract_auth":
            result = await handle_har_extract_auth(arguments or {})
        elif name == "har_detect_patterns":
            result = await handle_har_detect_patterns(arguments or {})
        elif name == "har_unload":
            result = await handle_har_unload(arguments or {})
        else:
            result = make_error("UNKNOWN_TOOL", f"未知工具: {name}")
    except FileNotFoundError as e:
        result = make_error("FILE_NOT_FOUND", str(e))
    except PermissionError as e:
        result = make_error("PERMISSION_DENIED", str(e))
    except ValueError as e:
        result = make_error("PARSE_ERROR", f"HAR 文件解析失败: {e}")
    except Exception as e:
        result = make_error(
            "INTERNAL_ERROR",
            f"内部错误: {e}",
            detail=traceback.format_exc()
        )

    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]


# ============================================================
# Tool Handler 实现
# ============================================================
async def handle_har_load(arguments: dict) -> dict:
    """处理 har_load 调用。"""
    filepath = arguments.get("filepath")
    if not filepath:
        return make_error("INVALID_PARAMS", "filepath 参数不能为空。")

    filepath = os.path.abspath(os.path.expanduser(filepath))
    if not os.path.exists(filepath):
        return make_error(
            "FILE_NOT_FOUND",
            f"HAR 文件不存在: {filepath}",
            detail=f"绝对路径: {filepath}"
        )
    if not os.path.isfile(filepath):
        return make_error("INVALID_PARAMS", f"路径不是文件: {filepath}")

    include_static = bool(arguments.get("include_static", False))
    api_only = bool(arguments.get("api_only", False))

    # 在线程池中执行同步的加载逻辑，避免阻塞事件循环
    loop = asyncio.get_event_loop()
    store = get_store()

    def _do_load():
        return store.load(
            filepath=filepath,
            include_static=include_static,
            api_only=api_only,
        )

    result = await loop.run_in_executor(None, _do_load)
    return result


async def handle_har_summary(arguments: dict) -> dict:
    """处理 har_summary 调用。"""
    store = get_store()
    if store.is_empty():
        return make_error("NOT_LOADED", "尚未加载 HAR 文件，请先调用 har_load。")

    host_filter = arguments.get("host_filter")
    api_only = bool(arguments.get("api_only", True))

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, lambda: store.summary(host_filter=host_filter, api_only=api_only)
    )


async def handle_har_search(arguments: dict) -> dict:
    """处理 har_search 调用。"""
    store = get_store()
    if store.is_empty():
        return make_error("NOT_LOADED", "尚未加载 HAR 文件，请先调用 har_load。")

    url_contains = arguments.get("url_contains")
    method = arguments.get("method")
    status = arguments.get("status")
    host = arguments.get("host")
    has_tag = arguments.get("has_tag")
    limit = int(arguments.get("limit", SEARCH_DEFAULT_LIMIT))
    offset = int(arguments.get("offset", 0))

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: store.search(
            url_contains=url_contains,
            method=method,
            status=status,
            host=host,
            has_tag=has_tag,
            limit=limit,
            offset=offset,
        )
    )


async def handle_har_get_entry(arguments: dict) -> dict:
    """处理 har_get_entry 调用。"""
    store = get_store()
    if store.is_empty():
        return make_error("NOT_LOADED", "尚未加载 HAR 文件，请先调用 har_load。")

    entry_id = arguments.get("entry_id")
    if entry_id is None:
        return make_error("INVALID_PARAMS", "entry_id 参数不能为空。")
    entry_id = int(entry_id)

    include_full_body = bool(arguments.get("include_full_body", True))

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, lambda: store.get_entry(entry_id, include_full_body)
    )


async def handle_har_get_entries_batch(arguments: dict) -> dict:
    """处理 har_get_entries_batch 调用。"""
    store = get_store()
    if store.is_empty():
        return make_error("NOT_LOADED", "尚未加载 HAR 文件，请先调用 har_load。")

    entry_ids = arguments.get("entry_ids")
    if not entry_ids or not isinstance(entry_ids, list):
        return make_error("INVALID_PARAMS", "entry_ids 参数必须是整数数组。")

    entry_ids = [int(eid) for eid in entry_ids]
    if len(entry_ids) > BATCH_MAX_SIZE:
        return make_error(
            "INVALID_PARAMS",
            f"单次最多获取 {BATCH_MAX_SIZE} 条，当前传入 {len(entry_ids)} 条。"
        )

    include_full_body = bool(arguments.get("include_full_body", True))

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, lambda: store.get_entries_batch(entry_ids, include_full_body)
    )


async def handle_har_extract_auth(arguments: dict) -> dict:
    """处理 har_extract_auth 调用。"""
    store = get_store()
    if store.is_empty():
        return make_error("NOT_LOADED", "尚未加载 HAR 文件，请先调用 har_load。")

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, store.extract_auth)


async def handle_har_detect_patterns(arguments: dict) -> dict:
    """处理 har_detect_patterns 调用。"""
    store = get_store()
    if store.is_empty():
        return make_error("NOT_LOADED", "尚未加载 HAR 文件，请先调用 har_load。")

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, store.detect_patterns)


async def handle_har_unload(arguments: dict) -> dict:
    """处理 har_unload 调用。"""
    store = get_store()
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, store.unload)


# ============================================================
# Server 启动
# ============================================================
async def main():
    """MCP Server 主入口。"""
    async with stdio_server() as streams:
        await app.run(
            streams[0],
            streams[1],
            app.create_initialization_options(
                notification_options=None,
                experimental_capabilities={},
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
