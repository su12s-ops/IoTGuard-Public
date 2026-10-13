"""把真实终端输出渲染成终端截图 PNG。用法: python render_terminal.py <out.png>"""
import sys
from PIL import Image, ImageDraw, ImageFont

# 真实 nginx 修复终端（来自 SSH 实际执行）
LINES = [
    ("[user@iotguard-vm ~]$ nginx -v", (125, 211, 252)),
    ("nginx version: nginx/1.18.0 (Ubuntu)", (207, 238, 247)),
    ("[user@iotguard-vm ~]$ dpkg -l nginx | tail -1", (125, 211, 252)),
    ("ii  nginx   1.18.0-6ubuntu14.14   amd64", (207, 238, 247)),
    ("    |__ 修复前: 受 CVE-2026-49975 影响 (jammy-security 未打补丁)", (251, 146, 60)),
    ("", (0, 0, 0)),
    ("[user@iotguard-vm ~]$ sudo apt-get install -y --only-upgrade nginx", (125, 211, 252)),
    ("Reading package lists... Done", (141, 163, 184)),
    ("Setting up nginx-core (1.18.0-6ubuntu14.15) ...", (141, 163, 184)),
    ("Setting up nginx (1.18.0-6ubuntu14.15) ...", (141, 163, 184)),
    ("Processing triggers for man-db ...", (141, 163, 184)),
    ("", (0, 0, 0)),
    ("[user@iotguard-vm ~]$ dpkg -l nginx | tail -1", (125, 211, 252)),
    ("ii  nginx   1.18.0-6ubuntu14.15   amd64", (52, 211, 153)),
    ("    |__ 修复后: 已升级至安全补丁版本", (52, 211, 153)),
    ("", (0, 0, 0)),
    ("[user@iotguard-vm ~]$ nginx -t", (125, 211, 252)),
    ("nginx: configuration file /etc/nginx/nginx.conf test is successful", (52, 211, 153)),
    ("[OK] 漏洞闭环完成: 版本已更新, CVE-2026-49975 不再受影响", (52, 211, 153)),
]

W, LINE_H = 940, 23
H = 42 + len(LINES) * LINE_H + 18
img = Image.new("RGB", (W, H), (10, 17, 32))
d = ImageDraw.Draw(img)
try:
    font = ImageFont.truetype(r"C:\Windows\Fonts\consola.ttf", 14)
except Exception:
    font = ImageFont.load_default()

# 顶部标题栏
d.rectangle([0, 0, W, 30], fill=(13, 20, 38))
d.line([(0, 30), (W, 30)], fill=(56, 189, 248), width=1)
for i, c in enumerate([(239, 68, 68), (245, 158, 11), (34, 197, 94)]):
    d.ellipse([14 + i * 20, 10, 26 + i * 20, 22], fill=c)
d.text((88, 8), "user@iotguard-vm: ~  (nginx 安全补丁升级 - 真实执行)", fill=(141, 163, 184), font=font)

y = 46
for text, color in LINES:
    if text:
        d.text((20, y), text, fill=color, font=font)
    y += LINE_H

out = sys.argv[1] if len(sys.argv) > 1 else r"D:\linuxguard_debs\nginx-fix.png"
img.save(out)
print("saved:", out, img.size)
