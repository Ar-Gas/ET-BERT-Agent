import onnxruntime as ort
import numpy as np
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
import httpx
import uvicorn
import time
import os

app = FastAPI(title="Aegis-WAF-Proxy")

# 1. 配置真实后端服务器的地址 (我们稍后会在 8080 端口启动一个测试后端)
BACKEND_TARGET_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8080")

# 2. 全局复用：高性能异步 HTTP 客户端
http_client = httpx.AsyncClient(base_url=BACKEND_TARGET_URL, timeout=60.0)

# 加载 ET-BERT 模型
print("[WAF] 初始化 Aegis 反向代理防火墙...")
try:
    # 尝试加载模型，如果失败则使用规则引擎作为降级方案
    ort_session = ort.InferenceSession("../models/et_bert_dummy.onnx")
    print("[WAF] ET-BERT ONNX 引擎加载成功。")
except Exception as e:
    print(f"[WAF] AI 模型加载失败，自动降级为【启发式规则引擎模式】。原因: {e}")
    ort_session = None

def extract_http_features(request: Request, body: bytes) -> str:
    """将 HTTP 请求还原为文本特征"""
    headers_str = "\n".join([f"{k}: {v}" for k, v in request.headers.items()])
    raw_http = f"{request.method} {request.url.path + ("?" + request.url.query if request.url.query else "")} HTTP/1.1\n{headers_str}\n\n{body.decode(errors='ignore')}"
    return raw_http

async def ai_threat_detection(raw_http: str) -> float:
    """调用 ET-BERT 或规则引擎进行高危打分"""
    raw_lower = raw_http.lower()
    
    # 模拟 AI 发现 SQL 注入或 XSS 攻击特征
    if "union select" in raw_lower or "1=1" in raw_lower:
        return 0.99  # 极高危：SQL 注入
    elif "<script>" in raw_lower or "javascript:" in raw_lower:
        return 0.98  # 高危：XSS 跨站脚本
    elif "cmd.exe" in raw_lower or "/etc/passwd" in raw_lower:
        return 0.99  # 极高危：命令注入 / 任意文件读取
        
    if ort_session:
        # 如果模型存在，这里是真正的张量推理逻辑
        return 0.01 
        
    return 0.01 # 安全放行

# 3. 核心拦截器：接管所有 HTTP 方法和路径
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def reverse_proxy(request: Request, path: str):
    start_time = time.time()
    
    # 获取请求体
    body = await request.body()
    
    # 步骤 A：特征提取与 AI 打分
    raw_http = extract_http_features(request, body)
    threat_score = await ai_threat_detection(raw_http)
    
    client_ip = request.client.host
    
    # 步骤 B：WAF 阻断逻辑 (毫秒级串联拦截)
    if threat_score > 0.95:
        print(f"[🚨 WAF 串联拦截] 发现攻击！IP: {client_ip} | 路径: {request.url.path + ("?" + request.url.query if request.url.query else "")} | 危险评分: {threat_score:.2f}")
        
        # 记录拦截日志，后续可供 LLM Agent 读取分析
        with open("waf_alerts.log", "a") as f:
            f.write(f"{time.time()},{client_ip},{request.url.path + ("?" + request.url.query if request.url.query else "")},{threat_score}\n")
            
        return Response(
            content='{"error": "Access Denied by Aegis-WAF. Malicious payload detected.", "code": 403}',
            status_code=403,
            media_type="application/json"
        )
        
    # 步骤 C：安全放行，执行透明反向代理
    proxy_headers = dict(request.headers)
    proxy_headers.pop("host", None) # 必须移除原始 host，否则后端可能会拒绝
    
    try:
        proxy_req = http_client.build_request(
            request.method,
            request.url.path + ("?" + request.url.query if request.url.query else ""),
            headers=proxy_headers,
            content=body,
            params=request.query_params
        )
        
        backend_resp = await http_client.send(proxy_req, stream=True)
        
        return StreamingResponse(
            backend_resp.aiter_raw(),
            status_code=backend_resp.status_code,
            headers=dict(backend_resp.headers)
        )
    except httpx.ConnectError:
        return Response(
            content='{"error": "Aegis-WAF: Backend server is offline.", "code": 502}',
            status_code=502,
            media_type="application/json"
        )

if __name__ == "__main__":
    # 监听 8000 端口作为 WAF 入口 (测试环境不用 80 是为了免 sudo)
    print(f"[WAF] Aegis Reverse Proxy started. Listening on http://0.0.0.0:8000")
    print(f"[WAF] Forwarding safe traffic to {BACKEND_TARGET_URL}")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
