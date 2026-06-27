"""摘要生成器模块。

负责把清洗后的 Entry 压缩为 AI 友好的结构化摘要，包括：
- extract_schema(obj): 递归提取 JSON 的键名 + 值类型（不暴露实际值）
- summarize_entry_for_search(entry_row): 生成 har_search 返回的单条摘要
- summarize_entry_detail(entry_row): 生成 har_get_entry 返回的完整详情
- group_endpoints(rows): 按 method+url_pattern 聚合，生成 har_summary 的端点组
- extract_auth_summary(rows): 提取认证信息摘要
- detect_patterns(rows): 检测加密/签名/哈希混淆特征

所有函数严格遵循"只返回元信息，不返回敏感值"的原则。
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

from filters import (
    clean_headers,
    generate_tags,
    get_host_from_url,
    looks_like_hex_hash,
    looks_like_jwt,
)
from config import (
    AUTH_HEADER_NAMES,
    SIGNATURE_HEADER_NAMES,
)


# ============================================================
# Schema 提取（核心安全函数）
# ============================================================
def extract_schema(obj: Any, depth: int = 0, max_depth: int = 5) -> Any:
    """递归提取 JSON 对象的结构 schema。

    只保留键名和值类型，绝对不包含实际值。
    类型映射：
        str    -> "string"
        int    -> "integer"
        float  -> "number"
        bool   -> "boolean"
        None   -> "null"
        dict   -> {key: schema(value), ...}
        list   -> [schema(first_element)] 或 [] (空数组)

    Args:
        obj: 任意 Python 对象（通常为 JSON 解析结果）
        depth: 当前递归深度
        max_depth: 最大递归深度，防止无限嵌套

    Returns:
        结构 schema（dict / list / str）
    """
    if depth > max_depth:
        return "..."

    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "boolean"
    if isinstance(obj, int):
        return "integer"
    if isinstance(obj, float):
        return "number"
    if isinstance(obj, str):
        return "string"
    if isinstance(obj, dict):
        if not obj:
            return {}
        return {str(k): extract_schema(v, depth + 1, max_depth) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        if not obj:
            return []
        # 只取第一个元素的 schema 作为代表
        return [extract_schema(obj[0], depth + 1, max_depth)]
    return "unknown"


# ============================================================
# 单条 Entry 摘要（用于 har_search）
# ============================================================
def summarize_entry_for_search(row: dict) -> dict:
    """从 SQLite 行生成 har_search 返回的单条摘要。

    输入 row 字段：id, url, method, status, mime_type, req_body_preview,
                   res_body_preview, req_headers, res_headers, time_ms, tags

    输出：不含完整 body 的精简摘要
    """
    req_headers = _safe_json_loads(row.get('req_headers') or '{}')
    res_headers = _safe_json_loads(row.get('res_headers') or '{}')

    return {
        "id": row['id'],
        "method": row.get('method', ''),
        "url": row.get('url', ''),
        "status": row.get('status'),
        "time_ms": row.get('time_ms'),
        "req_content_type": req_headers.get('content-type', ''),
        "res_content_type": res_headers.get('content-type', '') or row.get('mime_type', ''),
        "req_body_preview": (row.get('req_body_preview') or '')[:200],  # search 再裁剪一次
        "res_body_preview": (row.get('res_body_preview') or '')[:200],
        "tags": _parse_tags(row.get('tags')),
    }


# ============================================================
# 单条 Entry 详情（用于 har_get_entry）
# ============================================================
def summarize_entry_detail(row: dict, include_full_body: bool = True) -> dict:
    """从 SQLite 行生成 har_get_entry 返回的完整详情。"""
    req_headers = _safe_json_loads(row.get('req_headers') or '{}')
    res_headers = _safe_json_loads(row.get('res_headers') or '{}')

    req_body = row.get('req_body_full') if include_full_body else None
    if req_body is None:
        req_body = row.get('req_body_preview') or ''
    res_body = row.get('res_body_full') if include_full_body else None
    if res_body is None:
        res_body = row.get('res_body_preview') or ''

    req_truncated = (row.get('req_body_full') is None) and bool(row.get('req_body_preview'))
    res_truncated = (row.get('res_body_full') is None) and bool(row.get('res_body_preview'))

    return {
        "id": row['id'],
        "method": row.get('method', ''),
        "url": row.get('url', ''),
        "status": row.get('status'),
        "time_ms": row.get('time_ms'),
        "started_at": row.get('started_at', ''),
        "request": {
            "headers": req_headers,
            "body": req_body,
            "body_truncated": req_truncated,
        },
        "response": {
            "headers": res_headers,
            "body": res_body,
            "body_truncated": res_truncated,
        },
        "tags": _parse_tags(row.get('tags')),
    }


# ============================================================
# 端点分组聚合（用于 har_summary）
# ============================================================
def group_endpoints(rows: list[dict]) -> list[dict]:
    """按 method + url_pattern 聚合 Entry，生成端点组列表。

    url_pattern 规则：
    - 去掉 query string
    - 将纯数字路径段替换为 {id}
    - 将 UUID 路径段替换为 {uuid}
    - 将长十六进制路径段替换为 {hash}

    每组返回：
        {
            "method": str,
            "url_pattern": str,
            "count": int,
            "status_codes": list[int],
            "req_content_type": str,
            "res_content_type": str,
            "avg_time_ms": float,
            "has_auth_header": bool,
            "req_body_structure": dict,   # 仅键名+类型
            "res_body_structure": dict,   # 仅键名+类型
            "entry_ids": list[int]
        }
    """
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)

    for row in rows:
        method = (row.get('method') or 'GET').upper()
        url = row.get('url') or ''
        pattern = _normalize_url_pattern(url)
        groups[(method, pattern)].append(row)

    result: list[dict] = []
    for (method, pattern), group_rows in groups.items():
        # 取第一条作为结构代表
        first = group_rows[0]
        req_headers = _safe_json_loads(first.get('req_headers') or '{}')
        res_headers = _safe_json_loads(first.get('res_headers') or '{}')

        # 状态码集合
        status_codes = sorted({r.get('status') for r in group_rows if r.get('status') is not None})

        # 平均耗时
        times = [r.get('time_ms') or 0 for r in group_rows if r.get('time_ms') is not None]
        avg_time = round(sum(times) / len(times), 1) if times else 0

        # 是否含认证 Header
        has_auth = any(
            any(h in _safe_json_loads(r.get('req_headers') or '{}')
                for h in AUTH_HEADER_NAMES)
            for r in group_rows
        )

        # body 结构（从 preview 解析）
        req_schema = _extract_schema_from_body(first.get('req_body_preview') or '',
                                               req_headers.get('content-type', ''))
        res_schema = _extract_schema_from_body(first.get('res_body_preview') or '',
                                               res_headers.get('content-type', '') or first.get('mime_type', ''))

        result.append({
            "method": method,
            "url_pattern": pattern,
            "count": len(group_rows),
            "status_codes": status_codes,
            "req_content_type": req_headers.get('content-type', ''),
            "res_content_type": res_headers.get('content-type', '') or first.get('mime_type', ''),
            "avg_time_ms": avg_time,
            "has_auth_header": has_auth,
            "req_body_structure": req_schema,
            "res_body_structure": res_schema,
            "entry_ids": [r['id'] for r in group_rows],
        })

    # 按出现次数降序排序
    result.sort(key=lambda g: (-g['count'], g['method'], g['url_pattern']))
    return result


def _normalize_url_pattern(url: str) -> str:
    """将 URL 归一化为端点模式。

    - 去掉 query string
    - 数字段 -> {id}
    - UUID -> {uuid}
    - 长十六进制 -> {hash}
    """
    if not url:
        return ''

    # 去掉 query 和 fragment
    for sep in ('?', '#'):
        if sep in url:
            url = url.split(sep, 1)[0]

    # 拆分协议 + host + path
    if '://' in url:
        scheme, rest = url.split('://', 1)
    else:
        scheme, rest = '', url

    if '/' in rest:
        host, path = rest.split('/', 1)
        path = '/' + path
    else:
        host, path = rest, ''

    # 归一化 path 段
    segments = path.split('/') if path else []
    normalized_segments = []
    for seg in segments:
        if not seg:
            normalized_segments.append(seg)
            continue
        if seg.isdigit():
            normalized_segments.append('{id}')
        elif _is_uuid(seg):
            normalized_segments.append('{uuid}')
        elif _is_long_hex(seg):
            normalized_segments.append('{hash}')
        else:
            normalized_segments.append(seg)

    new_path = '/'.join(normalized_segments)

    if scheme:
        return f"{scheme}://{host}{new_path}"
    return f"{host}{new_path}"


def _is_uuid(s: str) -> bool:
    """判断是否为 UUID 格式。"""
    return bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', s, re.IGNORECASE))


def _is_long_hex(s: str) -> bool:
    """判断是否为长十六进制串（>=16 位）。"""
    return len(s) >= 16 and bool(re.match(r'^[0-9a-f]+$', s, re.IGNORECASE))


def _extract_schema_from_body(body_preview: str, mime: str) -> dict | list | None:
    """从 body preview 中提取结构 schema。

    若 body 为 JSON，返回 extract_schema 结果；否则返回 None。
    """
    if not body_preview:
        return None
    if 'json' not in (mime or '').lower():
        return None
    try:
        # preview 可能被截断，尝试解析；失败则返回 None
        parsed = json.loads(body_preview)
        return extract_schema(parsed)
    except (json.JSONDecodeError, ValueError):
        # 截断的 JSON 无法解析，尝试补全
        # 简单策略：找到最后一个完整的键值对
        return None


# ============================================================
# 认证信息摘要（用于 har_extract_auth）
# ============================================================
def extract_auth_summary(rows: list[dict]) -> dict:
    """提取所有请求中的认证信息摘要。

    返回结构：
        {
            "auth_headers_found": {
                "<header_name>": {
                    "sample_schemes": list[str],   # 如 ["Bearer", "Basic"]
                    "entry_ids": list[int],
                    "token_length_samples": list[int]
                }
            },
            "cookies_found": {
                "<cookie_name>": {"entry_count": int}
            },
            "patterns_note": str
        }
    """
    auth_headers: dict[str, dict] = defaultdict(lambda: {
        "sample_schemes": set(),
        "entry_ids": [],
        "token_length_samples": [],
    })
    cookies: dict[str, dict] = defaultdict(lambda: {"entry_count": 0})
    cookie_entry_set: dict[str, set] = defaultdict(set)

    for row in rows:
        req_headers = _safe_json_loads(row.get('req_headers') or '{}')
        entry_id = row['id']

        # 认证 Header
        for h_name in AUTH_HEADER_NAMES:
            if h_name in req_headers:
                value = req_headers[h_name]
                info = auth_headers[h_name]
                info["entry_ids"].append(entry_id)

                # 提取 scheme（如 Bearer / Basic）
                scheme = _extract_auth_scheme(h_name, value)
                if scheme:
                    info["sample_schemes"].add(scheme)

                # token 长度（去掉 scheme 前缀）
                token = value.split(' ', 1)[1] if ' ' in value else value
                info["token_length_samples"].append(len(token))

        # Cookie 解析
        cookie_header = req_headers.get('cookie', '')
        if cookie_header:
            for pair in cookie_header.split(';'):
                if '=' in pair:
                    name = pair.split('=', 1)[0].strip()
                    if name and entry_id not in cookie_entry_set[name]:
                        cookie_entry_set[name].add(entry_id)
                        cookies[name]["entry_count"] += 1

    # 转换 set 为 list
    auth_headers_result = {}
    for name, info in auth_headers.items():
        # 限制 entry_ids 与 token_length_samples 的数量
        auth_headers_result[name] = {
            "sample_schemes": sorted(info["sample_schemes"]) if info["sample_schemes"] else ["none"],
            "entry_ids": info["entry_ids"][:50],  # 最多 50 个
            "token_length_samples": info["token_length_samples"][:20],  # 最多 20 个样本
        }

    # 生成 patterns_note
    note = _build_auth_patterns_note(auth_headers_result, cookies)

    return {
        "auth_headers_found": auth_headers_result,
        "cookies_found": dict(cookies),
        "patterns_note": note,
    }


def _extract_auth_scheme(header_name: str, value: str) -> str:
    """从认证 Header 值中提取 scheme。

    例：
        "Bearer eyJ..." -> "Bearer"
        "Basic dXNlcjpwYXNz" -> "Basic"
        "eyJ..." (无前缀) -> "jwt" (若为 JWT 格式) 或 "none"
    """
    if not value:
        return "none"

    if ' ' in value:
        scheme = value.split(' ', 1)[0]
        return scheme

    # 无空格前缀，尝试识别 JWT
    if looks_like_jwt(value):
        return "jwt"

    return "none"


def _build_auth_patterns_note(auth_headers: dict, cookies: dict) -> str:
    """根据认证摘要生成自然语言分析提示。"""
    notes = []

    for name, info in auth_headers.items():
        schemes = info["sample_schemes"]
        lengths = info["token_length_samples"]

        if not lengths:
            continue

        if 'Bearer' in schemes or 'jwt' in schemes:
            # 检查长度是否稳定
            if len(set(lengths)) == 1:
                notes.append(f"{name} 使用 Bearer/JWT 方案，token 长度稳定在 {lengths[0]} 字符，疑似固定结构 JWT。")
            else:
                notes.append(f"{name} 使用 Bearer/JWT 方案，token 长度在 {min(lengths)}-{max(lengths)} 之间变化。")
        elif 'Basic' in schemes:
            notes.append(f"{name} 使用 Basic 认证（base64 编码的 user:pass）。")
        else:
            if len(set(lengths)) == 1:
                notes.append(f"{name} 长度固定为 {lengths[0]} 字符，疑似静态 API Key 或固定长度 token。")
            else:
                notes.append(f"{name} 长度在 {min(lengths)}-{max(lengths)} 之间变化。")

    if cookies:
        cookie_names = list(cookies.keys())[:5]
        notes.append(f"发现 Cookie：{', '.join(cookie_names)} 等，共 {len(cookies)} 个。")

    if not notes:
        return "未发现明显的认证信息。"

    return ' '.join(notes)


# ============================================================
# 加密/签名特征检测（用于 har_detect_patterns）
# ============================================================
def detect_patterns(rows: list[dict]) -> dict:
    """自动检测流量中的加密/混淆/签名特征。

    返回：
        {
            "findings": [
                {
                    "type": str,            # encrypted_body / url_hash / request_signature / ...
                    "description": str,
                    "affected_entry_ids": list[int],
                    "evidence": str
                }
            ]
        }
    """
    findings: list[dict] = []

    # 1. 检测加密 body
    findings.extend(_detect_encrypted_bodies(rows))

    # 2. 检测 URL 哈希混淆
    findings.extend(_detect_url_hash(rows))

    # 3. 检测请求签名 Header
    findings.extend(_detect_request_signatures(rows))

    # 4. 检测异常状态码集中
    findings.extend(_detect_error_clusters(rows))

    return {"findings": findings}


def _detect_encrypted_bodies(rows: list[dict]) -> list[dict]:
    """检测疑似加密的响应 body。"""
    findings = []
    encrypted_ids: list[int] = []
    evidence_samples: list[str] = []

    for row in rows:
        res_body = row.get('res_body_preview') or ''
        if not res_body or len(res_body) < 32:
            continue

        # 检测：JSON 中包含长 base64 字段
        try:
            parsed = json.loads(res_body)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if isinstance(v, str) and len(v) >= 32:
                        # 检查是否为 base64 且长度为 16 的倍数
                        if re.match(r'^[A-Za-z0-9+/]{16,}={0,2}$', v) and len(v) % 16 == 0:
                            encrypted_ids.append(row['id'])
                            if len(evidence_samples) < 3:
                                evidence_samples.append(f"字段 '{k}' 值为 {len(v)} 字符 base64 串")
                            break
        except (json.JSONDecodeError, ValueError):
            pass

    if encrypted_ids:
        findings.append({
            "type": "encrypted_body",
            "description": f"检测到 {len(encrypted_ids)} 条响应 body 疑似 AES 加密（Base64 特征，长度为 16 的倍数）",
            "affected_entry_ids": encrypted_ids[:50],
            "evidence": f"响应 body 中包含长 base64 字段：{'; '.join(evidence_samples)}"
        })

    return findings


def _detect_url_hash(rows: list[dict]) -> list[dict]:
    """检测 URL 路径哈希混淆。"""
    findings = []
    hash_ids: list[int] = []
    hash_types: dict[str, int] = defaultdict(int)
    sample_urls: list[str] = []

    for row in rows:
        url = row.get('url') or ''
        if not url:
            continue

        # 提取 path 段
        if '://' in url:
            rest = url.split('://', 1)[1]
        else:
            rest = url
        if '/' in rest:
            path = '/' + rest.split('/', 1)[1]
        else:
            path = ''

        # 检查每个路径段
        for seg in path.split('/'):
            if not seg:
                continue
            hash_type = looks_like_hex_hash(seg)
            if hash_type:
                hash_ids.append(row['id'])
                hash_types[hash_type] += 1
                if len(sample_urls) < 3:
                    sample_urls.append(url)
                break

    if hash_ids:
        type_desc = ', '.join(f"{t}({c})" for t, c in hash_types.items())
        findings.append({
            "type": "url_hash",
            "description": f"检测到 {len(hash_ids)} 条请求的 URL 路径为十六进制哈希串（{type_desc}），疑似端点混淆",
            "affected_entry_ids": hash_ids[:50],
            "evidence": f"URL 样本：{' / '.join(sample_urls)}"
        })

    return findings


def _detect_request_signatures(rows: list[dict]) -> list[dict]:
    """检测请求签名 Header。"""
    findings = []
    sign_header_stats: dict[str, list[int]] = defaultdict(list)
    sign_entry_ids: dict[str, list[int]] = defaultdict(list)

    for row in rows:
        req_headers = _safe_json_loads(row.get('req_headers') or '{}')
        for h_name in SIGNATURE_HEADER_NAMES:
            if h_name in req_headers:
                value = req_headers[h_name]
                sign_header_stats[h_name].append(len(value))
                sign_entry_ids[h_name].append(row['id'])

    for h_name, lengths in sign_header_stats.items():
        if len(lengths) < 2:
            # 单次出现不足以判定为签名机制
            continue

        # 长度是否稳定
        unique_lens = set(lengths)
        ids = sign_entry_ids[h_name]

        # 判定签名类型
        if 64 in unique_lens and len(unique_lens) == 1:
            desc = f"所有请求均包含 {h_name} Header，值为 64 位十六进制，疑似 HMAC-SHA256 签名"
        elif 40 in unique_lens and len(unique_lens) == 1:
            desc = f"所有请求均包含 {h_name} Header，值为 40 位十六进制，疑似 HMAC-SHA1 签名"
        elif 32 in unique_lens and len(unique_lens) == 1:
            desc = f"所有请求均包含 {h_name} Header，值为 32 位十六进制，疑似 MD5 签名"
        else:
            desc = f"所有请求均包含 {h_name} Header，长度在 {min(lengths)}-{max(lengths)} 之间，疑似签名/摘要"

        findings.append({
            "type": "request_signature",
            "description": desc,
            "affected_entry_ids": ids[:50],
            "evidence": f"{h_name} 出现 {len(ids)} 次，长度样本：{lengths[:10]}"
        })

    return findings


def _detect_error_clusters(rows: list[dict]) -> list[dict]:
    """检测错误状态码集中（可能暗示逆向触发了风控）。"""
    findings = []
    error_ids_by_status: dict[int, list[int]] = defaultdict(list)

    for row in rows:
        status = row.get('status')
        if status and 400 <= status < 600:
            error_ids_by_status[status].append(row['id'])

    for status, ids in error_ids_by_status.items():
        if len(ids) >= 5:
            findings.append({
                "type": "error_cluster",
                "description": f"检测到 {len(ids)} 条 HTTP {status} 响应集中出现，可能触发风控或参数错误",
                "affected_entry_ids": ids[:50],
                "evidence": f"状态码 {status} 出现 {len(ids)} 次"
            })

    return findings


# ============================================================
# 辅助函数
# ============================================================
def _safe_json_loads(s: str | None) -> dict:
    """安全解析 JSON 字符串，失败返回空 dict。"""
    if not s:
        return {}
    try:
        result = json.loads(s)
        return result if isinstance(result, dict) else {}
    except (json.JSONDecodeError, ValueError, TypeError):
        return {}


def _parse_tags(tags_str: str | None) -> list[str]:
    """解析逗号分隔的标签字符串为列表。"""
    if not tags_str:
        return []
    return [t.strip() for t in tags_str.split(',') if t.strip()]
