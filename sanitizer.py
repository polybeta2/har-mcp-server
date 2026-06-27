"""字符串脱敏模块。

核心职责：
1. 在 HAR 数据写入 SQLite 之前，对所有字符串字段做脱敏处理。
2. 阻止 API 响应中的特定字符串触发 Trae（或下游 AI）的安全过滤。
3. 支持多种脱敏源，按优先级自动选择：
   - 方案 A（推荐）：Sensitive-lexicon 词库 + Aho-Corasick 自动机（pyahocorasick）
   - 方案 B：better-profanity（英文为主，可扩展自定义词库）
   - 方案 C：alt-profanity-check（多语言）
   - 方案 D：本地 wordlist.txt 自定义词库（正则匹配，作为兜底）

设计要点：
- 词库路径可通过环境变量 HAR_MCP_LEXICON / HAR_MCP_WORDLIST 覆盖。
- Sensitive-lexicon 与 wordlist.txt 不应提交到版本控制（已在 .gitignore 中忽略）。
- 脱敏是幂等的：对已脱敏的字符串再次脱敏不会产生变化。
- 递归处理 JSON 结构，最大深度 20，防止畸形数据爆栈。
- 若所有脱敏源都不可用，sanitizer 自动降级为空操作，不影响主流程。
"""

from __future__ import annotations

import os
import re
from typing import Any

# ============================================================
# 方案 A：Sensitive-lexicon + Aho-Corasick（推荐）
# ============================================================
_AHOCORASICK_AVAILABLE = False
ahocorasick = None

try:
    import ahocorasick

    _AHOCORASICK_AVAILABLE = True
except ImportError:
    pass

DEFAULT_LEXICON_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "Sensitive-lexicon",
    "sensitive-lexicon.txt",
)
LEXICON_PATH = os.environ.get("HAR_MCP_LEXICON", DEFAULT_LEXICON_PATH)

# ============================================================
# 方案 B：better-profanity（英文为主，可扩展）
# ============================================================
_BP_AVAILABLE = False
_bp = None

try:
    from better_profanity import profanity as _bp

    _BP_AVAILABLE = True
except ImportError:
    pass


# ============================================================
# 方案 C：alt-profanity-check（多语言）
# ============================================================
_APC_AVAILABLE = False
_apc_predict = None

try:
    from alt_profanity_check import predict as _apc_predict

    _APC_AVAILABLE = True
except ImportError:
    pass


# ============================================================
# 方案 D：本地自定义词库文件
# ============================================================
CUSTOM_WORDLIST_PATH = os.environ.get(
    "HAR_MCP_WORDLIST",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt"),
)

MASK_CHAR = "*"


# ============================================================
# 词库加载（方案 A / D 共用）
# ============================================================
def _load_lines(filepath: str) -> list[str]:
    """读取词库文件，返回非空、非注释行列表。"""
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
    except (OSError, UnicodeDecodeError):
        return []


# 模块加载时读取一次自定义词库（后续可通过 reload_wordlist() 刷新）
_CUSTOM_WORDS: list[str] = _load_lines(CUSTOM_WORDLIST_PATH)
_CUSTOM_WORDS_REGEX: re.Pattern | None = None


def _rebuild_custom_regex() -> None:
    """根据当前 _CUSTOM_WORDS 重建正则。"""
    global _CUSTOM_WORDS_REGEX
    if not _CUSTOM_WORDS:
        _CUSTOM_WORDS_REGEX = None
        return
    sorted_words = sorted(_CUSTOM_WORDS, key=len, reverse=True)
    escaped = [re.escape(w) for w in sorted_words]
    _CUSTOM_WORDS_REGEX = re.compile("|".join(escaped))


_rebuild_custom_regex()


# ============================================================
# Aho-Corasick 自动机构建（方案 A）
# ============================================================
def _build_automaton(words: list[str]) -> ahocorasick.Automaton | None:
    """用词表构建 Aho-Corasick 自动机。"""
    if not words or not _AHOCORASICK_AVAILABLE or ahocorasick is None:
        return None
    A = ahocorasick.Automaton()
    for word in words:
        if word:
            A.add_word(word, word)
    A.make_automaton()
    return A


def _load_lexicon_automaton() -> ahocorasick.Automaton | None:
    """加载 Sensitive-lexicon + 自定义词库，去重后构建自动机。"""
    words = _load_lines(LEXICON_PATH) + list(_CUSTOM_WORDS)
    words = list(dict.fromkeys(words))
    return _build_automaton(words)


# 模块加载时初始化一次
_AC_AUTOMATON: ahocorasick.Automaton | None = _load_lexicon_automaton()


# ============================================================
# 公共 API
# ============================================================
def reload_lexicon() -> int:
    """运行时热重载所有词库（Sensitive-lexicon、自定义 wordlist）。"""
    global _CUSTOM_WORDS, _AC_AUTOMATON
    _CUSTOM_WORDS = _load_lines(CUSTOM_WORDLIST_PATH)
    _rebuild_custom_regex()
    _AC_AUTOMATON = _load_lexicon_automaton()
    return _automaton_word_count() + len(_CUSTOM_WORDS)


def is_sanitizer_active() -> bool:
    """返回脱敏功能是否处于激活状态。"""
    return (
        _AC_AUTOMATON is not None
        or _BP_AVAILABLE
        or _APC_AVAILABLE
        or _CUSTOM_WORDS_REGEX is not None
    )


def get_sanitizer_status() -> dict:
    """返回脱敏模块的当前状态（用于调试与诊断）。"""
    return {
        "lexicon_path": LEXICON_PATH,
        "custom_wordlist_path": CUSTOM_WORDLIST_PATH,
        "ahocorasick_available": _AHOCORASICK_AVAILABLE,
        "better_profanity_available": _BP_AVAILABLE,
        "alt_profanity_check_available": _APC_AVAILABLE,
        "custom_words_loaded": len(_CUSTOM_WORDS),
        "lexicon_words_loaded": _automaton_word_count(),
        "active": is_sanitizer_active(),
    }


# ============================================================
# 核心替换逻辑
# ============================================================
def _mask_equal_length(word: str) -> str:
    """把词替换为等长的 MASK_CHAR。"""
    return MASK_CHAR * len(word)


def _sanitize_with_ac(text: str) -> tuple[str, int]:
    """方案 A：Aho-Corasick 敏感词替换。"""
    if _AC_AUTOMATON is None:
        return text, 0

    hits: list[tuple[int, int]] = []
    for end_idx, word in _AC_AUTOMATON.iter(text):
        start_idx = end_idx - len(word) + 1
        hits.append((start_idx, end_idx))

    if not hits:
        return text, 0

    # 合并重叠 / 相邻区间
    hits.sort()
    merged: list[tuple[int, int]] = []
    cur_s, cur_e = hits[0]
    for s, e in hits[1:]:
        if s <= cur_e + 1:
            cur_e = max(cur_e, e)
        else:
            merged.append((cur_s, cur_e))
            cur_s, cur_e = s, e
    merged.append((cur_s, cur_e))

    chars = list(text)
    for s, e in merged:
        for i in range(s, e + 1):
            chars[i] = MASK_CHAR

    return "".join(chars), len(merged)


def _sanitize_with_better_profanity(text: str) -> tuple[str, int]:
    """方案 B：better-profanity 过滤。"""
    if not _BP_AVAILABLE or _bp is None:
        return text, 0
    try:
        if not _bp.contains_profanity(text):
            return text, 0
        # better-profanity 会把命中词替换为 ****
        # 为了统计命中次数，先统计替换前后差异
        censored = _bp.censor(text, MASK_CHAR)
        count = sum(1 for a, b in zip(text, censored) if a != b and b == MASK_CHAR)
        return censored, count
    except Exception:
        return text, 0


def _sanitize_with_alt_profanity_check(text: str) -> tuple[str, int]:
    """方案 C：alt-profanity-check 过滤。

    该库基于机器学习，输入输出为句子级二分类预测。
    若预测为敏感，则将整句替换为等长 MASK_CHAR（粒度较粗）。
    """
    if not _APC_AVAILABLE or _apc_predict is None:
        return text, 0
    try:
        prediction = _apc_predict([text])
        if prediction and prediction[0] == 1:
            return _mask_equal_length(text), 1
        return text, 0
    except Exception:
        return text, 0


def _sanitize_with_custom_wordlist(text: str) -> tuple[str, int]:
    """方案 D：本地自定义词库正则替换（兜底）。"""
    if _CUSTOM_WORDS_REGEX is None:
        return text, 0

    count = 0

    def _replacer(m: re.Match) -> str:
        nonlocal count
        count += 1
        return _mask_equal_length(m.group(0))

    text = _CUSTOM_WORDS_REGEX.sub(_replacer, text)
    return text, count


def sanitize_string(text: str) -> tuple[str, int]:
    """对单个字符串做脱敏处理。

    处理优先级：
        1. Sensitive-lexicon + Aho-Corasick（若有 pyahocorasick 和词库）
        2. better-profanity（若已安装）
        3. alt-profanity-check（若已安装）
        4. 本地 wordlist.txt 自定义词库

    返回：
        (脱敏后的字符串, 总替换次数)
        若输入为空或非字符串，原样返回，替换次数为 0
    """
    if not text or not isinstance(text, str):
        return text, 0

    total_count = 0

    # 方案 A
    text, n = _sanitize_with_ac(text)
    total_count += n

    # 方案 B
    text, n = _sanitize_with_better_profanity(text)
    total_count += n

    # 方案 C
    text, n = _sanitize_with_alt_profanity_check(text)
    total_count += n

    # 方案 D（兜底）
    text, n = _sanitize_with_custom_wordlist(text)
    total_count += n

    return text, total_count


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


# ============================================================
# 内部辅助
# ============================================================
def _automaton_word_count() -> int:
    """获取当前 Aho-Corasick 自动机中的词数量。"""
    if _AC_AUTOMATON is None or not _AHOCORASICK_AVAILABLE:
        return 0
    try:
        return len(list(_AC_AUTOMATON.keys()))
    except Exception:
        return 0
