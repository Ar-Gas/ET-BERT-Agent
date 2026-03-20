import subprocess
import json
import threading
import time
import os
from dotenv import load_dotenv
from openai import OpenAI

# 加载 .env 环境变量
load_dotenv()

client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
    base_url=os.environ.get("OPENAI_BASE_URL")
)
MODEL_NAME = os.environ.get("MODEL_NAME", "deepseek-chat")

print("[Python Agent] 正在启动底层 C++ 探针...")

env = os.environ.copy()
env["LD_LIBRARY_PATH"] = "/home/zyq/aegis-agent/third_party/onnxruntime/lib"

process = subprocess.Popen(
    ["./build/aegis_agent"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
    env=env
)

request_id = 1
tools_schema = []

def send_rpc_request(method, params=None):
    global request_id
    req = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method
    }
    if params:
        req["params"] = params
    
    process.stdin.write(json.dumps(req) + "\n")
    process.stdin.flush()
    request_id += 1

def read_rpc_message():
    while True:
        line = process.stdout.readline()
        if not line:
            break
        try:
            return json.loads(line.strip())
        except json.JSONDecodeError:
            pass
    return None

def run_agent_loop():
    print("[Python Agent] 正在获取 C++ 探针暴露的底层系统工具 (tools/list)...")
    send_rpc_request("tools/list")
    
    msg = read_rpc_message()
    if msg and "result" in msg and "tools" in msg["result"]:
        raw_tools = msg["result"]["tools"]
        global tools_schema
        tools_schema = [
            {
                "type": "function",
                "function": {
                    "name": t.get("name", t.get("description", "").split()[0].lower()), 
                    "description": t["description"],
                    "parameters": t["inputSchema"]
                }
            }
            for t in raw_tools
            if "inputSchema" in t
        ]
        tools_schema[0]["function"]["name"] = "block_malicious_ip"
        tools_schema[1]["function"]["name"] = "analyze_process_behavior"
        tools_schema[2]["function"]["name"] = "get_pid_by_connection"
        
        print(f"[Python Agent] 成功挂载 {len(tools_schema)} 个 C++ Native 工具。")

    print("[Python Agent] 大脑上线，等待 C++ 数据面传回高危告警...")
    time.sleep(2)
    print("\n[🚨 C++ 探针告警] 检测到高危网络行为！源 IP: 1.2.3.4, 目标端口: 443, 置信度: 0.98")
    
    messages = [
        {"role": "system", "content": "你是一个顶级网络安全防御 AI。你现在控制着一台 Linux 服务器。当你收到高危流量告警时，你必须：\n1. 调用 get_pid_by_connection 查出是哪个进程 PID 发出的流量。\n2. 如果查到了 PID，再调用 analyze_process_behavior 分析该进程。\n3. 调用 block_malicious_ip 阻断该恶意 IP。"},
        {"role": "user", "content": "探针刚刚报告：IP 1.2.3.4 (端口 443) 触发了恶意流量规则，置信度 0.98。请立刻调查并处置！"}
    ]

    print(f"\n[🧠 LLM 思考中...] 正在请求大模型 ({MODEL_NAME})...")
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            tools=tools_schema,
            tool_choice="auto"
        )
        
        response_message = response.choices[0].message
        print(f"[🧠 LLM 回复] {response_message.content if response_message.content else '决定调用底层工具...'}")

        if response_message.tool_calls:
            for tool_call in response_message.tool_calls:
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)
                
                print(f"\n[⚡ 执行动作] 大模型下发指令: {function_name}({function_args})")
                print(f"[⚡ 执行动作] 正在穿透至 C++ 内核层执行...")
                
                send_rpc_request("tools/call", {
                    "name": function_name,
                    "arguments": function_args
                })
                
                result_msg = read_rpc_message()
                print(f"[✅ C++ 执行结果] {json.dumps(result_msg['result'], ensure_ascii=False)}")
                
    except Exception as e:
        print(f"[Python Agent] 访问大模型失败: {e}")

if __name__ == "__main__":
    run_agent_loop()
    process.terminate()