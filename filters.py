"""数据清洗规则模块。

包含：
- 静态资源识别（默认跳过）
- Header 清洗（请求/响应）
- Body 处理（preview / full / 编码识别 / JSON 解析）
- API 请求识别（打 is_api 标签）
- 标签生成（json / auth / encrypted / form 等）

所有函数均为纯函数，无副作用，便于测试与复用。
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any
from urllib.parse import parse_qs, unquote

from config import (
    API_METHODS,
    API_URL_PATTERNS,
    BODY_FULL_MAX_LENGTH,
    BODY_PREVIEW_LENGTH,
    KEEP_REQUEST_HEADERS,
    KEEP_RESPONSE_HEADERS,
    STRICT_STATIC_MIME_TYPES,
    SKIP_URL_PATTERNS,
)

# 预编译正则，提升性能
_SKIP_URL_REGEX = [re.compile(p, re.IGNORECASE) for p in SKIP_URL_PATTERNS]
_API_URL_REGEX = [re.compile(p, re.IGNORECASE) for p in API_URL_PATTERNS]

# Base64 特征正则（用于检测加密 body）
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
# 32 位十六进制（MD5）
_MD5_RE = re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE)
# 64 位十六进制（SHA256 / HMAC-SHA256）
_SHA256_RE = re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE)
# 40 位十六进制（SHA1）
_SHA1_RE = re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE)
# JWT 三段式
_JWT_RE = re.compile(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')


# ============================================================
# 静态资源识别
# ============================================================
def is_static_resource(entry: dict) -> bool:
    """判断 Entry 是否为静态资源（默认跳过）。

    判定规则（任一命中即视为静态）：
    1. response.content.mimeType 在 STRICT_STATIC_MIME_TYPES 中
    2. URL 匹配任一 SKIP_URL_PATTERNS
    3. URL 路径以静态资源后缀结尾
    """
    # 1. MIME 判定
    mime = _get_response_mime(entry)
    if mime and mime.split(';')[0].strip().lower() in STRICT_STATIC_MIME_TYPES:
        return True

    url = entry.get('request', {}).get('url', '') or ''
    if not url:
        return False

    # 2. URL 正则匹配
    for rx in _SKIP_URL_REGEX:
        if rx.search(url):
            return True

    return False


# ============================================================
# Header 清洗
# ============================================================
def clean_headers(headers: list[dict] | None, side: str = 'request') -> dict:
    """清洗 HAR 格式的 Header 列表。

    输入：[{"name": "...", "value": "..."}, ...]
    输出：清洗后的 {key_lower: value} 字典

    规则：
    - 请求侧：保留 KEEP_REQUEST_HEADERS 中的 + 所有 x- 开头的 Header
    - 响应侧：保留 KEEP_RESPONSE_HEADERS 中的 + 所有 x- 开头的 Header
    - 同名 Header 合并为逗号分隔
    """
    if not headers:
        return {}

    keep_set = KEEP_REQUEST_HEADERS if side == 'request' else KEEP_RESPONSE_HEADERS
    result: dict[str, str] = {}

    for h in headers:
        if not isinstance(h, dict):
            continue
        name = (h.get('name') or '').strip()
        value = h.get('value')
        if not name or value is None:
            continue
        name_lower = name.lower()

        # 保留白名单 + 所有 x- 开头的自定义 Header
        if name_lower in keep_set or name_lower.startswith('x-'):
            if name_lower in result:
                result[name_lower] = f"{result[name_lower]}, {value}"
            else:
                result[name_lower] = value

    return result


# ============================================================
# Body 处理
# ============================================================
def process_body(raw_body: str | None, mime: str | None, encoding: str | None = None) -> dict:
    """处理请求/响应 body。

    返回：
        {
            "preview": str,          # 前 N 字符
            "full": str | None,      # 完整 body，超长则 None
            "truncated": bool,       # 是否被截断
            "encoding": str,         # "json" / "form" / "base64" / "text" / "binary"
            "decoded": dict | list | None  # 若为 JSON 则解析后的对象
        }
    """
    result = {
        "preview": "",
        "full": None,
        "truncated": False,
        "encoding": "text",
        "decoded": None,
    }

    # 空值快速返回
    if raw_body is None or raw_body == "":
        return result

    mime_lower = (mime or '').split(';')[0].strip().lower()
    is_base64 = (encoding or '').lower() == 'base64'

    # 1. base64 编码处理
    if is_base64:
        try:
            decoded_bytes = base64.b64decode(raw_body, validate=False)
            # 尝试作为 UTF-8 文本解码
            try:
                text = decoded_bytes.decode('utf-8')
                # 如果解码后是可读文本，继续走文本流程
                raw_body = text
            except UnicodeDecodeError:
                # 真正的二进制内容
                result["encoding"] = "binary"
                result["preview"] = f"<binary data, {len(decoded_bytes)} bytes>"
                result["full"] = None
                result["truncated"] = True
                return result
        except (binascii.Error, ValueError):
            result["encoding"] = "binary"
            result["preview"] = "<base64 decode failed>"
            return result

    # 2. 编码类型识别
    body_str = raw_body if isinstance(raw_body, str) else str(raw_body)

    # 优先用 MIME 判定
    if 'json' in mime_lower:
        result["encoding"] = "json"
    elif 'form-urlencoded' in mime_lower or 'x-www-form-urlencoded' in mime_lower:
        result["encoding"] = "form"
    elif mime_lower.startswith('image/') or mime_lower.startswith('audio/') or mime_lower.startswith('video/'):
        result["encoding"] = "binary"
        result["preview"] = f"<binary media, mime={mime_lower}>"
        return result
    else:
        # MIME 未知时，尝试根据内容推断
        stripped = body_str.lstrip()
        if stripped.startswith('{') or stripped.startswith('['):
            result["encoding"] = "json"
        elif '=' in body_str and '&' in body_str and '"' not in body_str[:50]:
            result["encoding"] = "form"
        else:
            result["encoding"] = "text"

    # 3. JSON 解析
    if result["encoding"] == "json":
        try:
            result["decoded"] = json.loads(body_str)
        except (json.JSONDecodeError, ValueError):
            # JSON 解析失败，降级为 text
            result["encoding"] = "text"
            result["decoded"] = None

    # 4. form 解析
    if result["encoding"] == "form":
        try:
            parsed = parse_qs(body_str, keep_blank_values=True)
            # 转为单值 dict
            result["decoded"] = {k: (v[0] if len(v) == 1 else v) for k, v in parsed.items()}
        except Exception:
            result["decoded"] = None

    # 5. 生成 preview 与 full
    body_len = len(body_str)
    if body_len <= BODY_PREVIEW_LENGTH:
        result["preview"] = body_str
    else:
        result["preview"] = body_str[:BODY_PREVIEW_LENGTH]

    if body_len <= BODY_FULL_MAX_LENGTH:
        result["full"] = body_str
        result["truncated"] = False
    else:
        result["full"] = None
        result["truncated"] = True

    return result


# ============================================================
# API 请求识别
# ============================================================
def is_api_request(entry: dict) -> bool:
    """判断 Entry 是否为 API 请求。

    以下任意条件成立则标记为 API：
    - Content-Type 或 Accept 包含 application/json
    - URL 路径包含 /api/, /v1/, /v2/, /graphql, /rest/, /rpc/ 等
    - 响应 body 能成功解析为 JSON 且顶层是 dict 或 list
    - 请求方法为 POST/PUT/PATCH/DELETE（非 GET 静态）
    """
    request = entry.get('request', {}) or {}
    response = entry.get('response', {}) or {}

    # 1. 方法判定
    method = (request.get('method') or '').upper()
    if method in API_METHODS:
        return True

    # 2. URL 路径判定
    url = request.get('url', '') or ''
    for rx in _API_URL_REGEX:
        if rx.search(url):
            return True

    # 3. Content-Type / Accept 判定
    req_headers = {h.get('name', '').lower(): h.get('value', '')
                   for h in (request.get('headers') or []) if isinstance(h, dict)}
    res_headers = {h.get('name', '').lower(): h.get('value', '')
                   for h in (response.get('headers') or []) if isinstance(h, dict)}

    content_type = (req_headers.get('content-type') or '').lower()
    accept = (req_headers.get('accept') or '').lower()
    res_content_type = (res_headers.get('content-type') or '').lower()

    if 'application/json' in content_type or 'application/json' in accept:
        return True
    if 'application/json' in res_content_type:
        return True

    # 4. 响应 body JSON 解析判定
    res_content = response.get('content', {}) or {}
    res_mime = res_content.get('mimeType', '') or ''
    res_text = res_content.get('text', '') or ''
    if res_text and 'json' in res_mime.lower():
        try:
            parsed = json.loads(res_text)
            if isinstance(parsed, (dict, list)):
                return True
        except (json.JSONDecodeError, ValueError):
            pass

    return False


# ============================================================
# 标签生成
# ============================================================
def generate_tags(entry: dict, cleaned_req_headers: dict, body_info: dict) -> list[str]:
    """为 Entry 生成标签列表，用于 har_search 的 has_tag 过滤。

    标签集合：
    - json / form / text / binary / base64  （body 编码）
    - auth                                  （含认证 Header）
    - encrypted                             （疑似加密 body）
    - signed                                （含签名 Header）
    - error                                 （4xx/5xx 状态码）
    - redirect                              （3xx 状态码）
    """
    tags: list[str] = []

    # body 编码标签
    encoding = body_info.get('encoding', 'text')
    if encoding in ('json', 'form', 'text', 'binary'):
        tags.append(encoding)
    if body_info.get('truncated'):
        tags.append('truncated')

    # 认证标签
    has_auth = any(h in cleaned_req_headers for h in (
        'authorization', 'x-auth-token', 'x-api-key', 'x-access-token', 'x-token'
    ))
    if has_auth:
        tags.append('auth')

    # 签名标签
    has_sign = any(k in cleaned_req_headers for k in (
        'x-sign', 'x-signature', 'x-sig', 'x-hmac', 'x-timestamp', 'x-nonce'
    ))
    if has_sign:
        tags.append('signed')

    # 加密标签（基于 body 内容启发式判定）
    if _looks_encrypted(body_info):
        tags.append('encrypted')

    # 状态码标签
    status = (entry.get('response', {}) or {}).get('status', 0) or 0
    if 400 <= status < 600:
        tags.append('error')
    elif 300 <= status < 400:
        tags.append('redirect')

    return tags


def _looks_encrypted(body_info: dict) -> bool:
    """启发式判定 body 是否疑似加密。

    判定依据：
    - JSON body 中存在单个长 base64 字符串字段（如 {"data": "<base64>"}）
    - body 整体为长 base64 串
    - body 长度为 16 的倍数（AES 块对齐特征）
    """
    decoded = body_info.get('decoded')
    full = body_info.get('full') or body_info.get('preview') or ''

    # JSON 中包含长 base64 字段
    if isinstance(decoded, dict):
        for v in decoded.values():
            if isinstance(v, str) and _BASE64_RE.match(v) and len(v) % 16 == 0:
                return True
            if isinstance(v, str) and len(v) >= 32 and _BASE64_RE.match(v):
                return True

    # 整体为长 base64 串
    if isinstance(full, str) and len(full) >= 32:
        stripped = full.strip()
        if _BASE64_RE.match(stripped) and len(stripped) % 16 == 0:
            return True

    return False


# ============================================================
# 辅助函数
# ============================================================
def _get_response_mime(entry: dict) -> str:
    """从 Entry 中提取响应 MIME 类型。"""
    content = (entry.get('response', {}) or {}).get('content', {}) or {}
    return content.get('mimeType', '') or ''


def get_host_from_url(url: str) -> str:
    """从 URL 中提取 host（含端口）。

    例：https://api.example.com:8443/v1/user -> api.example.com:8443
    """
    if not url:
        return ''
    # 简单实现，避免引入 urllib.parse 的开销
    try:
        # 去掉协议
        if '://' in url:
            url = url.split('://', 1)[1]
        # 去掉 path/query/fragment
        for sep in ('/', '?', '#'):
            if sep in url:
                url = url.split(sep, 1)[0]
                break
        return url
    except Exception:
        return ''


def get_path_from_url(url: str) -> str:
    """从 URL 中提取 path（含 query）。"""
    if not url:
        return ''
    try:
        if '://' in url:
            url = url.split('://', 1)[1]
        # 去掉 host
        if '/' in url:
            url = '/' + url.split('/', 1)[1]
        else:
            url = '/'
        return url
    except Exception:
        return ''


def looks_like_jwt(token: str) -> bool:
    """判断字符串是否为 JWT 三段式格式。"""
    return bool(_JWT_RE.match(token))


def looks_like_hex_hash(s: str) -> str | None:
    """判断字符串是否为十六进制哈希，返回类型或 None。

    返回值：'md5' / 'sha1' / 'sha256' / None
    """
    if _MD5_RE.match(s):
        return 'md5'
    if _SHA1_RE.match(s):
        return 'sha1'
    if _SHA256_RE.match(s):
        return 'sha256'
    return None
