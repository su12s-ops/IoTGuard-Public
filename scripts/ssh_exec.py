"""SSH 命令执行工具（密码从环境变量 SSH_PASS 读取）。
用法: python ssh_exec.py <host> <user> <command>
"""
import os
import sys

import paramiko

host = sys.argv[1]
user = sys.argv[2]
cmd = sys.argv[3]
pwd = os.environ.get("SSH_PASS")
if not pwd:
    print("[ERROR] 请先设置环境变量 SSH_PASS")
    sys.exit(3)

client = paramiko.SSHClient()
client.load_system_host_keys()
if os.environ.get("SSH_KNOWN_HOSTS"):
    client.load_host_keys(os.environ["SSH_KNOWN_HOSTS"])
client.set_missing_host_key_policy(paramiko.RejectPolicy())
try:
    client.connect(host, username=user, password=pwd, timeout=15, allow_agent=False, look_for_keys=False)
except Exception as exc:
    print(f"[CONNECT FAIL] {type(exc).__name__}: {exc}")
    sys.exit(2)

stdin, stdout, stderr = client.exec_command(cmd, timeout=180)
out = stdout.read().decode("utf-8", "ignore")
err = stderr.read().decode("utf-8", "ignore")
code = stdout.channel.recv_exit_status()
if out:
    sys.stdout.write(out)
if err:
    sys.stdout.write("\n[STDERR] " + err)
sys.stdout.write(f"\n[EXIT {code}]\n")
client.close()

sys.exit(code)
