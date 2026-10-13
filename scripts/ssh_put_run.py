"""上传本地脚本到 VM 并远程执行。用法:
   python ssh_put_run.py <host> <user> <local_file> <remote_path> <run_command>
密码从环境变量 SSH_PASS 读取。
"""
import os
import sys

import paramiko

host = sys.argv[1]
user = sys.argv[2]
local = sys.argv[3]
remote = sys.argv[4]
cmd = sys.argv[5]
pwd = os.environ.get("SSH_PASS")
if not pwd:
    print("[ERROR] 请先设置 SSH_PASS")
    sys.exit(3)

cli = paramiko.SSHClient()
cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect(host, username=user, password=pwd, timeout=15, allow_agent=False, look_for_keys=False)

sftp = cli.open_sftp()
sftp.put(local, remote)
sftp.chmod(remote, 0o755)
sftp.close()
print(f"[PUT] {local} -> {remote}")

stdin, stdout, stderr = cli.exec_command(cmd, timeout=240)
out = stdout.read().decode("utf-8", "ignore")
err = stderr.read().decode("utf-8", "ignore")
code = stdout.channel.recv_exit_status()
if out:
    sys.stdout.write(out)
if err:
    sys.stdout.write("\n[STDERR] " + err)
sys.stdout.write(f"\n[EXIT {code}]\n")
cli.close()
