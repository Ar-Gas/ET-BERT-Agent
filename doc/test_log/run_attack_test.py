"""
Aegis-Agent 攻击模拟测试脚本

测试模式：
  - C++ MCP Server (AEGIS_NO_DATAPLANE=1)：真实运行，暴露 NetTools/OSTools/SecTools
  - LLM 推理：真实 API 调用（火山引擎 Doubao）
  - RAG 检索：真实 FAISS + embedding
  - 数据面：注入一条模拟威胁（绕过 libpcap，无需 root）
"""
import sys, os, time, json, subprocess, threading, io, contextlib

# ── 路径配置 ──────────────────────────────────────────────────────────────────
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)

# 加载 .env
from dotenv import load_dotenv
load_dotenv(os.path.join(REPO, ".env"))

# ── 启动 C++ Agent ─────────────────────────────────────────────────────────────
print("=" * 60)
print("[测试] 启动 C++ MCP Server (AEGIS_NO_DATAPLANE=1)...")
env = os.environ.copy()
env["LD_LIBRARY_PATH"] = os.path.join(REPO, "third_party/onnxruntime/lib")
env["AEGIS_NO_DATAPLANE"] = "1"

cpp_proc = subprocess.Popen(
    [os.path.join(REPO, "build/aegis_agent"), "--smp", "1"],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    stdin=subprocess.DEVNULL,
    text=True,
    bufsize=1,
)

# 等待 MCP Server 就绪
import requests as _req
for i in range(15):
    try:
        r = _req.post("http://127.0.0.1:8080/message",
                      json={"jsonrpc": "2.0", "id": 0, "method": "ping"},
                      timeout=1)
        if r.status_code == 200:
            print(f"[测试] C++ MCP Server 就绪 (尝试 {i+1} 次)")
            break
    except Exception:
        time.sleep(0.5)
else:
    # 打印 stderr 帮助诊断
    cpp_proc.terminate()
    print("[错误] C++ Agent 未能启动")
    sys.exit(1)

# 打印 C++ 启动日志
def _drain_stderr():
    for line in cpp_proc.stderr:
        print("[C++]", line.rstrip())
threading.Thread(target=_drain_stderr, daemon=True).start()

# ── 加载 Python SOC 模块 ──────────────────────────────────────────────────────
print("[测试] 初始化 Python SOC 模块（含 RAG）...\n")

# 临时 patch：让 CppProbeWrapper 连接已有的 C++ 进程而不是重新启动
import importlib, unittest.mock as mock

# Patch subprocess.Popen 使 CppProbeWrapper 使用已有 cpp_proc
_orig_popen = subprocess.Popen
def _patched_popen(cmd, **kw):
    if "aegis_agent" in str(cmd):
        return cpp_proc
    return _orig_popen(cmd, **kw)

with mock.patch("subprocess.Popen", side_effect=_patched_popen):
    import scripts.multi_agent_soc as soc

# ── 模拟攻击载荷 ───────────────────────────────────────────────────────────────
ATTACK_IP   = "192.168.100.99"   # 模拟攻击者 IP（不存在于本机）
ATTACK_PORT = 4444               # 模拟反弹 Shell 端口
THREAT_SCORE = 0.99              # ET-BERT 输出高危评分

print("=" * 60)
print(f"[攻击模拟] 注入威胁事件:")
print(f"  源 IP    : {ATTACK_IP}")
print(f"  目标端口 : {ATTACK_PORT}")
print(f"  威胁评分 : {THREAT_SCORE}")
print("=" * 60, "\n")

# ── 运行 LangGraph SOC Workflow ───────────────────────────────────────────────
from langgraph.graph import StateGraph, END

workflow = StateGraph(soc.AgentState)
workflow.add_node("investigator", soc.investigator_node)
workflow.add_node("commander", soc.commander_node)
workflow.set_entry_point("investigator")
workflow.add_edge("investigator", "commander")
workflow.add_edge("commander", END)
app = workflow.compile()

start_time = time.time()

initial_state = {
    "threat_ip":            ATTACK_IP,
    "threat_port":          ATTACK_PORT,
    "investigation_report": "",
    "decision":             "",
}

final_state = app.invoke(initial_state)
elapsed = time.time() - start_time

# ── 汇总输出 ──────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print(f"[测试完成] 总耗时: {elapsed:.1f}s")
print("=" * 60)
print("\n[取证报告]\n", final_state["investigation_report"])
print("\n[处置决议]\n", final_state["decision"])

# ── 清理 ──────────────────────────────────────────────────────────────────────
cpp_proc.terminate()
cpp_proc.wait(timeout=3)
print("\n[测试] C++ Agent 已停止。")
