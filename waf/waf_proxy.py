import numpy as np
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
import httpx
import uvicorn
import time
import os

try:
    import onnxruntime as ort
    _ort_available = True
except ImportError:
    _ort_available = False

app = FastAPI(title="Aegis-WAF-Proxy")

# 1. 配置真实后端服务器的地址
BACKEND_TARGET_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8080")
WAF_MODEL_PATH     = os.environ.get("WAF_MODEL_PATH", "../models/et_bert_dummy.onnx")

# 2. 全局复用：高性能异步 HTTP 客户端
http_client = httpx.AsyncClient(base_url=BACKEND_TARGET_URL, timeout=60.0)

# 加载 ET-BERT 模型
print("[WAF] 初始化 Aegis 反向代理防火墙...")
ort_session   = None
_input_names  = []   # 在 try 块外初始化，防止加载失败时 NameError
_output_names = []

if _ort_available:
    try:
        _sess_opts = ort.SessionOptions()
        _sess_opts.intra_op_num_threads = 1
        _sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_EXTENDED
        ort_session   = ort.InferenceSession(WAF_MODEL_PATH, _sess_opts)
        _input_names  = [i.name for i in ort_session.get_inputs()]
        _output_names = [o.name for o in ort_session.get_outputs()]
        print(f"[WAF] ET-BERT ONNX 引擎加载成功。inputs={_input_names} outputs={_output_names}")
    except Exception as e:
        print(f"[WAF] AI 模型加载失败，自动降级为【启发式规则引擎模式】。原因: {e}")
else:
    print("[WAF] onnxruntime 未安装，使用规则引擎模式。")


def _tokenize(text: str, max_len: int = 512):
    """byte-level BERT 编码：0=PAD, 1=CLS, 2=SEP, 3+byte_val=token"""
    raw = text.encode("utf-8", errors="replace")
    ids = [1] + [b + 3 for b in raw[:max_len - 2]] + [2]
    mask = [1] * len(ids)
    ids  += [0] * (max_len - len(ids))
    mask += [0] * (max_len - len(mask))
    return (np.array([ids],  dtype=np.int64),
            np.array([mask], dtype=np.int64))


def _onnx_score(raw: str) -> float:
    """调用 ONNX 模型返回威胁概率 [0,1]，失败返回 -1"""
    if ort_session is None or not _input_names:
        return -1.0
    try:
        ids, mask = _tokenize(raw)
        feed = {_input_names[0]: ids}
        if len(_input_names) >= 2:
            feed[_input_names[1]] = mask
        out = ort_session.run(_output_names[:1], feed)[0]  # shape [1, n_class] or [1]
        logits = out.flatten()
        if len(logits) == 1:
            import math
            return float(1.0 / (1.0 + math.exp(-logits[0])))
        # softmax，取最后一列（威胁类）
        logits = logits - logits.max()
        exp_l  = np.exp(logits)
        return float(exp_l[-1] / exp_l.sum())
    except Exception as e:
        print(f"[WAF] ONNX 推理异常: {e}")
        return -1.0

def extract_http_features(request: Request, body: bytes) -> str:
    """将 HTTP 请求还原为文本特征"""
    headers_str = "\n".join([f"{k}: {v}" for k, v in request.headers.items()])
    raw_http = f"{request.method} {request.url.path + ("?" + request.url.query if request.url.query else "")} HTTP/1.1\n{headers_str}\n\n{body.decode(errors='ignore')}"
    return raw_http

_HIGH_RISK_SIGS = [
    ("union select", 0.99),
    ("1=1", 0.97),
    ("<script>", 0.98),
    ("javascript:", 0.97),
    ("cmd.exe", 0.99),
    ("/etc/passwd", 0.99),
    ("../../../", 0.96),
    ("wget ", 0.95),
    ("curl ", 0.95),
    ("base64 -d", 0.96),
]

async def ai_threat_detection(raw_http: str) -> float:
    """规则引擎快速路径 + ET-BERT ONNX 推理"""
    raw_lower = raw_http.lower()

    # 快速路径：签名命中直接返回
    for sig, score in _HIGH_RISK_SIGS:
        if sig in raw_lower:
            return score

    # AI 路径：ONNX 推理
    model_score = _onnx_score(raw_http)
    if model_score >= 0.0:
        return model_score

    return 0.01  # 安全放行

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
