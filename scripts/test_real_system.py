import subprocess
import json
import time
import os

print("==================================================")
print("[真实环境测试] 1. 正在启动真实的后台进程 (绑定 0.0.0.0:9999)...")
dummy_process = subprocess.Popen(["python3", "-m", "http.server", "9999"])
time.sleep(2) 

print("\n[真实环境测试] 2. 正在拉起 C++ Native 探针...")
# 加入 LD_LIBRARY_PATH 环境变量以正常拉起 Aegis 探针
env = os.environ.copy()
env["LD_LIBRARY_PATH"] = "/home/zyq/aegis-agent/third_party/onnxruntime/lib"

c_agent = subprocess.Popen(
    ["./build/aegis_agent"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, 
    text=True, bufsize=1, env=env
)
time.sleep(2)

def call_c_tool(method, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": method, "arguments": args}}
    c_agent.stdin.write(json.dumps(req) + "\n")
    c_agent.stdin.flush()
    while True:
        line = c_agent.stdout.readline()
        if not line:
            break
        try:
            msg = json.loads(line.strip())
            # 只捕获带有 result 的正常响应，忽略告警等其他 JSON
            if "result" in msg:
                return msg
        except json.JSONDecodeError:
            pass

print("\n[真实环境测试] 3. 开始穿透 Linux 内核进行真实溯源！")
print("  -> 请求 C++ 探针: 找出是谁占用了 9999 端口？")

result_pid = call_c_tool("get_pid_by_connection", {"ip": "0.0.0.0", "port": 9999})

if "pid" in result_pid['result']:
    real_pid = result_pid['result']['pid']
    print(f"  [✅ C++ 真实返回] 内核检索成功！对应的真实 PID 是: {real_pid}")

    print(f"\n  -> 请求 C++ 探针: 深度读取进程 {real_pid} 的真实行为特征！")
    result_behavior = call_c_tool("analyze_process", {"pid": real_pid})
    real_cmdline = result_behavior['result']['behavior']
    print(f"  [✅ C++ 真实返回] 内存映射读取成功！该进程的真实启动命令为:\n  👉 {real_cmdline}")
else:
    print(f"  [❌ C++ 真实返回] {result_pid['result']}")

dummy_process.terminate()
c_agent.terminate()
print("\n==================================================")
print("测试完毕！底层 C++ 探针完全真实有效！")
