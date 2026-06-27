# HAR Analyzer MCP Server

一个专为 **Trae IDE** 设计的 Python MCP Server，用于辅助 HAR 流量文件的逆向分析工作。

## 核心设计哲学

> 本地代码负责全部的解析、过滤、清洗工作；AI（Trae）只接收"精炼后"的结构化摘要数据。

直接把完整 HAR 文件塞给 AI 会导致两个致命问题：
1. HAR 文件体积巨大（轻易超过数十 MB），直接传输会立刻耗尽 Token 配额
2. HAR 的原始 JSON 中充斥着大量无关噪音（静态资源、base64 图片、冗余 Header、重复请求），AI 难以聚焦到真正有价值的 API 端点

**解决方案：** MCP Server 在本地完成所有重活（解析、去重、过滤、裁剪、索引），只通过 MCP Tools 向 Trae 暴露干净的摘要接口。

## 文件结构

