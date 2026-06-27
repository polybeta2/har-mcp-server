"""HAR 流式解析模块。

核心职责：
1. 使用 ijson 流式解析 HAR 文件，避免一次性加载大文件导致 OOM
2. 逐条 Entry 进行清洗：
   - 提取关键字段（method/url/status/mime/time 等）
   - 清洗 Header（请求/响应）
   - 处理 Body（preview/full/encoding/decoded）
   - 识别 API 请求
   - 生成标签
3. yield 清洗后的 dict，供 HarStore 入库

绝对禁止使用 json.load() 加载整个 HAR 文件。
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterator

try:
    import ijson
except ImportError as e:
    raise ImportError(
        "ijson 未安装，请运行: pip install ijson\n"
        "ijson 是流式 JSON 解析的核心依赖，用于处理大体积 HAR 文件。"
    ) from e

from config import PROGRESS_INTERVAL
from filters import (
    clean_headers,
    generate_tags,
    get_host_from_url,
    is_api_request,
    is_static_resource,
    process_body,
)


# ============================================================
# 流式解析主入口
# ============================================================
def stream_parse_har(
    filepath: str,
    include_static: bool = False,
    api_only: bool = False,
    progress_callback=None,
) -> tuple[int, int, int, int, list[str], tuple[str, str]]:
    """流式解析 HAR 文件，逐条清洗并入库。

    本函数本身不持有 SQLite 连接，而是通过 yield 返回清洗后的 dict，
    由调用方（HarStore）负责入库。这样保持模块职责单一。

    但为了性能，本函数返回统计信息（总数/跳过数/API 数等），
    调用方在迭代过程中自行累计。

    Args:
        filepath: HAR 文件绝对路径
        include_static: 是否包含静态资源
        api_only: 是否只索引 API 请求
        progress_callback: 可选的进度回调 fn(processed: int) -> None

    Returns:
        (total_entries, indexed_entries, skipped_static, api_count,
         unique_hosts, (time_start, time_end))

    注意：本函数是生成器，调用方需要迭代消费。
    实际使用时建议直接调用 stream_parse_har_iter。
    """
    raise NotImplementedError("请使用 stream_parse_har_iter 迭代器")


def stream_parse_har_iter(
    filepath: str,
    include_static: bool = False,
    api_only: bool = False,
    progress_callback=None,
) -> Iterator[tuple[dict, dict]]:
    """流式解析 HAR，逐条 yield (cleaned_entry, stats_delta)。

    每次迭代返回：
        cleaned_entry: 清洗后的 dict（含 url/method/status/headers/body 等）
        stats_delta: 统计增量 dict，包含：
            - 'is_static': bool
            - 'is_api': bool
            - 'host': str
            - 'started_at': str

    调用方根据 stats_delta 累计统计信息，并决定是否入库。

    Args:
        filepath: HAR 文件绝对路径
        include_static: 是否包含静态资源（默认 False）
        api_only: 是否只索引 API 请求（默认 False）
        progress_callback: 进度回调 fn(processed: int) -> None
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"HAR 文件不存在: {filepath}")

    processed = 0

    # ijson 必须以二进制模式读取
    with open(filepath, 'rb') as f:
        # ijson 路径语法：log.entries 数组的每个 item
        # 使用 items 而不是 parse，性能更好
        try:
            entries = ijson.items(f, 'log.entries.item')
        except ijson.JSONError as e:
            raise ValueError(f"HAR 文件 JSON 格式错误: {e}") from e

        for entry in entries:
            processed += 1

            if progress_callback and processed % PROGRESS_INTERVAL == 0:
                try:
                    progress_callback(processed)
                except Exception:
                    pass  # 进度回调失败不影响主流程

            # 基本校验
            if not isinstance(entry, dict):
                continue

            # 静态资源过滤
            static = is_static_resource(entry)
            if static and not include_static:
                continue

            # API 识别
            is_api = is_api_request(entry)

            # api_only 模式下，非 API 请求跳过
            if api_only and not is_api:
                continue

            # 清洗
            cleaned = _clean_entry(entry)

            stats_delta = {
                'is_static': static,
                'is_api': is_api,
                'host': cleaned.get('host', ''),
                'started_at': cleaned.get('started_at', ''),
            }

            yield cleaned, stats_delta


# ============================================================
# 单条 Entry 清洗
# ============================================================
def _clean_entry(entry: dict) -> dict:
    """清洗单条 HAR Entry，提取关键字段并压缩。

    返回 dict 字段：
        url, method, status, mime_type, host,
        req_body_preview, req_body_full,
        res_body_preview, res_body_full,
        req_headers (JSON str), res_headers (JSON str),
        time_ms, started_at, is_api, tags
    """
    request = entry.get('request', {}) or {}
    response = entry.get('response', {}) or {}

    # 基本字段
    url = request.get('url', '') or ''
    method = (request.get('method', '') or '').upper()
    status = response.get('status')
    time_ms = entry.get('time')
    started_at = entry.get('startedDateTime', '') or ''

    # 响应 MIME
    res_content = response.get('content', {}) or {}
    mime_type = res_content.get('mimeType', '') or ''

    # host
    host = get_host_from_url(url)

    # Header 清洗
    req_headers = clean_headers(request.get('headers') or [], side='request')
    res_headers = clean_headers(response.get('headers') or [], side='response')

    # Body 处理
    # 请求 body
    post_data = request.get('postData') or {}
    req_raw_body = post_data.get('text', '')
    req_encoding = post_data.get('encoding', '')
    req_mime = req_headers.get('content-type', '')
    req_body_info = process_body(req_raw_body, req_mime, req_encoding)

    # 响应 body
    res_raw_body = res_content.get('text', '')
    res_encoding = res_content.get('encoding', '')
    res_body_info = process_body(res_raw_body, mime_type, res_encoding)

    # 生成标签
    tags = generate_tags(entry, req_headers, req_body_info)

    # API 判定（重新调用以确保一致性）
    from filters import is_api_request
    is_api = is_api_request(entry)

    return {
        'url': url,
        'method': method,
        'status': status if status is not None else 0,
        'mime_type': mime_type,
        'host': host,
        'req_body_preview': req_body_info['preview'],
        'req_body_full': req_body_info['full'],
        'res_body_preview': res_body_info['preview'],
        'res_body_full': res_body_info['full'],
        'req_headers': json.dumps(req_headers, ensure_ascii=False),
        'res_headers': json.dumps(res_headers, ensure_ascii=False),
        'time_ms': float(time_ms) if time_ms is not None else 0.0,
        'started_at': started_at,
        'is_api': 1 if is_api else 0,
        'tags': ','.join(tags),
        # 额外字段（不入库，但供 HarStore 使用）
        '_req_body_truncated': req_body_info['truncated'],
        '_res_body_truncated': res_body_info['truncated'],
        '_req_body_encoding': req_body_info['encoding'],
        '_res_body_encoding': res_body_info['encoding'],
    }


# ============================================================
# 辅助：快速读取 HAR 元信息（不解析 entries）
# ============================================================
def peek_har_meta(filepath: str) -> dict:
    """快速读取 HAR 文件的元信息（creator/version 等），不解析 entries。

    用于在加载前预览文件信息。
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"HAR 文件不存在: {filepath}")

    meta = {'version': '', 'creator': '', 'pages': 0}
    try:
        with open(filepath, 'rb') as f:
            # 只解析 log 顶层字段，不解析 entries
            parser = ijson.parse(f)
            for prefix, event, value in parser:
                if prefix == 'log.version' and event == 'string':
                    meta['version'] = value
                elif prefix == 'log.creator.name' and event == 'string':
                    meta['creator'] = value
                elif prefix == 'log.pages.item' and event == 'start_map':
                    meta['pages'] += 1
                # 遇到 entries 就停止
                elif prefix == 'log.entries.item' and event == 'start_map':
                    break
    except (ijson.JSONError, Exception):
        pass

    return meta
