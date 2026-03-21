import time
import os
import subprocess

print("Checking root...")
print(f"EUID: {os.geteuid()}")

print("Benchmarking /proc scan...")
start = time.time()
pid_count = 0
fd_count = 0
for pid in os.listdir("/proc"):
    if pid.isdigit():
        pid_count += 1
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                fd_count += 1
        except:
            pass
print(f"Scanned {pid_count} PIDs and {fd_count} FDs in {time.time() - start:.2f} seconds.")

print("Testing iptables...")
start = time.time()
res = subprocess.run(["iptables", "-w", "-A", "INPUT", "-s", "127.0.0.99", "-j", "DROP"], capture_output=True, text=True)
print(f"iptables returned {res.returncode} in {time.time() - start:.2f} seconds.")
print(res.stderr)
