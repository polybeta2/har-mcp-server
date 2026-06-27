"""字符串脱敏模块。

核心职责：
1. 在 HAR 数据写入 SQLite 之前，对所有字符串字段做脱敏处理
2. 阻止 API 响应中的特定字符串触发 Trae（或下游 AI）的安全过滤
3. 支持两种脱敏源：
   - 方案A：可选的中文内容过滤库（cn-profanity-filter 等，若安装则启用）
   - 方案B：本地自定义词库文件（wordlist.txt，每行一个词，# 开头为注释）

设计要点：
- 词库文件路径可通过环境变量 HAR_MCP_WORDLIST 覆盖
- 词库文件不应提交到版本控制（已在 .gitignore 中忽略）
- 脱敏是幂等的：对已脱敏的字符串再次脱敏不会产生变化
- 递归处理 JSON 结构，最大深度 20，防止畸形数据爆栈
- 返回替换次数，便于调用方在 tags 中标记 "sanitized"
"""

from __future__ import annotations

import os
import re
from typing import Any

# ============================================================
# 方案A：可选的中文内容过滤库
# ============================================================
# 推荐库（按优先级尝试导入）：
#   pip install cn-profanity-filter   # 中文敏感词过滤
#   pip install better-profanity      # 英文为主，可扩展
#   pip install alt-profanity-check   # 多语言
#
# 这些库内置了由安全团队维护的词库，比手动列表更完整、更新更及时。
# 若未安装任何库，则仅依赖方案B的自定义词库。

_CN_FILTER_AVAILABLE = False
_cn_contains_ad = None
_cn_filter_text = None

try:
    from cn_profanity_filter import contains_ad as _cn_contains_ad
    from cn_profanity_filter import filter_text as _cn_filter_text
    _CN_FILTER_AVAILABLE = True
except ImportError:
    pass

# 若上面的库不可用，尝试 better-profanity
if not _CN_FILTER_AVAILABLE:
    try:
        from better_profanity import profanity as _bp
        _CN_FILTER_AVAILABLE = True

        def _cn_contains_ad(text: str) -> bool:
            return _bp.contains_profanity(text)

        def _cn_filter_text(text: str, repl: str = "*") -> str:
            return _bp.censor(text, repl)
    except ImportError:
        pass


# ============================================================
# 方案B：本地自定义词库文件
# ============================================================
# 词库文件路径优先级：
#   1. 环境变量 HAR_MCP_WORDLIST
#   2. 模块同目录下的 wordlist.txt
CUSTOM_WORDLIST_PATH = os.environ.get(
    "HAR_MCP_WORDLIST",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt"),
)


def load_custom_wordlist(path: str | None = None) -> list[str]:
    """加载自定义词库文件。

    Args:
        path: 词库文件路径，None 则使用默认路径

    Returns:
        词列表（已去除空行和注释行）
    """
    target = path or CUSTOM_WORDLIST_PATH
    if not os.path.exists(target):
        return []
    try:
        with open(target, encoding="utf-8") as f:
            words = []
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    words.append(line)
            return words
    except (OSError, UnicodeDecodeError):
        return []


# 模块加载时读取一次词库（后续可通过 reload_wordlist() 刷新）
_CUSTOM_WORDS: list[str] = load_custom_wordlist()

# 预编译正则：按词长降序匹配，避免短词先命中导致长词被破坏
# 例如词库含 ["abc", "abcdef"]，应优先匹配 "abcdef"
_CUSTOM_WORDS_REGEX: re.Pattern | None = None


def _rebuild_regex() -> None:
    """根据当前 _CUSTOM_WORDS 重建正则。"""
    global _CUSTOM_WORDS_REGEX
    if not _CUSTOM_WORDS:
        _CUSTOM_WORDS_REGEX = None
        return
    # 按长度降序排序，长词优先
    sorted_words = sorted(_CUSTOM_WORDS, key=len, reverse=True)
    # 转义特殊字符
    escaped = [re.escape(w) for w in sorted_words]
    _CUSTOM_WORDS_REGEX = re.compile("|".join(escaped))


_rebuild_regex()


def reload_wordlist(path: str | None = None) -> int:
    """重新加载词库文件（运行时刷新）。

    Args:
        path: 词库文件路径，None 则使用默认路径

    Returns:
        加载的词数量
    """
    global _CUSTOM_WORDS
    _CUSTOM_WORDS = load_custom_wordlist(path)
    _rebuild_regex()
    return len(_CUSTOM_WORDS)


# ============================================================
# 核心脱敏逻辑
# ============================================================
def _mask(word: str) -> str:
    """把词替换为等长的 *。"""
    return "*" * len(word)


def sanitize_string(text: str) -> tuple[str, int]:
    """对单个字符串做脱敏处理。

    Args:
        text: 原始字符串

    Returns:
        (脱敏后的字符串, 替换次数)
        若输入为空或非字符串，原样返回，替换次数为 0
    """
    if not text or not isinstance(text, str):
        return text, 0

    count = 0

    # 1. 自定义词库（正则一次性匹配，长词优先）
    if _CUSTOM_WORDS_REGEX is not None:
        def _replacer(m: re.Match) -> str:
            nonlocal count
            count += 1
            return _mask(m.group(0))

        text = _CUSTOM_WORDS_REGEX.sub(_replacer, text)

    # 2. 中文内容过滤库（若可用）
    if _CN_FILTER_AVAILABLE and _cn_contains_ad is not None and _cn_filter_text is not None:
        try:
            if _cn_contains_ad(text):
                text = _cn_filter_text(text, repl="*")
                count += 1
        except Exception:
            # 过滤库异常不应阻断主流程
            pass

    return text, count


def sanitize_dict(obj: Any, _depth: int = 0) -> tuple[Any, int]:
    """递归处理任意 JSON 结构，对所有字符串值做脱敏。

    Args:
        obj: 任意 Python 对象（通常为 JSON 解析结果）
        _depth: 当前递归深度（内部使用）
            最大递归深度 20，防止畸形数据爆栈

    Returns:
        (处理后的对象, 总替换次数)
        int/float/bool/None 原样返回
    """
    if _depth > 20:
        return obj, 0

    total = 0
    if isinstance(obj, str):
        cleaned, n = sanitize_string(obj)
        return cleaned, n
    elif isinstance(obj, dict):
        result: dict = {}
        for k, v in obj.items():
            # key 也做脱敏（防止敏感词出现在 JSON 键名中）
            cleaned_key, n_key = sanitize_string(k) if isinstance(k, str) else (k, 0)
            cleaned_val, n_val = sanitize_dict(v, _depth + 1)
            result[cleaned_key] = cleaned_val
            total += n_key + n_val
        return result, total
    elif isinstance(obj, list):
        result_list: list = []
        for item in obj:
            cleaned, n = sanitize_dict(item, _depth + 1)
            result_list.append(cleaned)
            total += n
        return result_list, total
    else:
        # int / float / bool / None 原样返回
        return obj, 0


def is_sanitizer_active() -> bool:
    """返回脱敏功能是否处于激活状态（有词库或过滤库可用）。"""
    return _CUSTOM_WORDS_REGEX is not None or _CN_FILTER_AVAILABLE


def get_sanitizer_status() -> dict:
    """返回脱敏模块的当前状态（用于调试与诊断）。"""
    return {
        "custom_wordlist_path": CUSTOM_WORDLIST_PATH,
        "custom_wordlist_loaded": len(_CUSTOM_WORDS),
        "cn_filter_available": _CN_FILTER_AVAILABLE,
        "active": is_sanitizer_active(),
    }
