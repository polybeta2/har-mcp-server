"""全局配置常量。

集中管理 HAR MCP Server 的所有可调参数，便于后续维护与调优。
所有数值与正则模式均根据 HAR 1.2 规范与实际逆向分析经验设定。
"""

# ============================================================
# Body 处理
# ============================================================
BODY_PREVIEW_LENGTH = 500          # Preview 截断长度（字符），存入 preview 列
BODY_FULL_MAX_LENGTH = 50_000      # 超过此长度不存 full body，只存 preview + 截断标记
BATCH_MAX_SIZE = 10                # har_get_entries_batch 最大条目数

# ============================================================
# 搜索
# ============================================================
SEARCH_DEFAULT_LIMIT = 20          # har_search 默认返回条目数
SEARCH_MAX_LIMIT = 100             # har_search 单次最大返回条目数

# ============================================================
# 静态资源过滤（默认跳过，不进入索引）
# ============================================================
SKIP_MIME_TYPES = {
    # 图片
    'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml',
    'image/x-icon', 'image/bmp', 'image/tiff', 'image/avif',
    # 字体
    'font/woff', 'font/woff2', 'font/ttf', 'font/otf', 'font/eot',
    'application/font-woff', 'application/font-woff2',
    'application/x-font-ttf', 'application/x-font-otf',
    # 样式与脚本
    'text/css',
    'application/javascript', 'text/javascript', 'application/x-javascript',
    'application/ecmascript',
    # Source Map
    'application/json',  # 仅当 URL 后缀为 .map 时跳过；这里保留为通用集合，由 is_static_resource 综合判定
    # 媒体
    'video/mp4', 'video/webm', 'video/ogg',
    'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm',
    # 文档（非 API）
    'application/pdf',
}

# 注意：application/json 不能直接放进 SKIP_MIME_TYPES，否则会误伤 API。
# 这里单独维护一份"严格静态"集合，仅包含确定性的静态资源 MIME。
STRICT_STATIC_MIME_TYPES = {
    'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml',
    'image/x-icon', 'image/bmp', 'image/tiff', 'image/avif',
    'font/woff', 'font/woff2', 'font/ttf', 'font/otf', 'font/eot',
    'application/font-woff', 'application/font-woff2',
    'application/x-font-ttf', 'application/x-font-otf',
    'text/css',
    'application/javascript', 'text/javascript', 'application/x-javascript',
    'application/ecmascript',
    'video/mp4', 'video/webm', 'video/ogg',
    'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm',
    'application/pdf',
}

# URL 正则模式：匹配则视为静态资源
SKIP_URL_PATTERNS = [
    r'\.(png|jpg|jpeg|gif|webp|ico|svg|woff2?|ttf|eot|css|js|map)(\?.*)?$',
    r'/_next/static/',
    r'/static/',
    r'/assets/',
    r'/dist/',
    r'/build/',
    r'cdn\.',
    r'analytics\.',
    r'metrics\.',
    r'telemetry\.',
    r'/sentry',
    r'/log\.',
    r'/tracking',
    r'google-analytics\.com',
    r'googletagmanager\.com',
    r'doubleclick\.net',
    r'hotjar\.com',
    r'mixpanel\.com',
    r'segment\.io',
]

# ============================================================
# API 识别
# ============================================================
API_URL_PATTERNS = [
    r'/api/',
    r'/v\d+/',
    r'/graphql',
    r'/rest/',
    r'/rpc/',
    r'/service/',
    r'/gateway/',
]

# 视为 API 的 HTTP 方法（GET 静态资源除外）
API_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}

# ============================================================
# Header 白名单（请求侧）
# ============================================================
# 保留这些 Header + 所有 x- 开头的自定义 Header（可能是签名/设备指纹）
KEEP_REQUEST_HEADERS = {
    'authorization',
    'x-auth-token',
    'x-api-key',
    'x-access-token',
    'x-token',
    'x-csrf-token',
    'x-xsrf-token',
    'content-type',
    'accept',
    'cookie',
    'x-requested-with',
    'origin',
    'referer',
    'user-agent',  # 逆向时 UA 经常参与签名
}

# 响应侧保留的 Header（精简）
KEEP_RESPONSE_HEADERS = {
    'content-type',
    'set-cookie',
    'location',
    'www-authenticate',
    'x-powered-by',
    'x-request-id',
    'x-trace-id',
    'x-sign',
    'x-signature',
    'x-nonce',
    'x-timestamp',
}

# ============================================================
# 认证相关 Header 名（用于 har_extract_auth）
# ============================================================
AUTH_HEADER_NAMES = {
    'authorization',
    'x-auth-token',
    'x-api-key',
    'x-access-token',
    'x-token',
    'x-csrf-token',
    'x-xsrf-token',
    'proxy-authorization',
}

# ============================================================
# 签名/加密特征 Header 名（用于 har_detect_patterns）
# ============================================================
SIGNATURE_HEADER_NAMES = {
    'x-sign', 'x-signature', 'x-sig', 'x-hmac',
    'x-timestamp', 'x-nonce', 'x-nonce-str',
    'x-app-key', 'x-app-id', 'x-device-id', 'x-device-fingerprint',
}

# ============================================================
# 进度反馈
# ============================================================
PROGRESS_INTERVAL = 1000            # 每处理 N 条 Entry 触发一次进度回调

# ============================================================
# SQLite 配置
# ============================================================
SQLITE_PRAGMAS = {
    'journal_mode': 'MEMORY',
    'synchronous': 'OFF',
    'temp_store': 'MEMORY',
    'cache_size': -64000,           # 64MB cache
}
