from app.services.asset_parser import parse_asset_text


def test_parse_collected_asset_text():
    sample = """
hostname: vm-real-01
ip_address: 10.0.0.12
architecture: x86_64
exposure_level: public
business_level: core
owner: security-team
description: collected by LinuxGuard

===== OS_RELEASE =====
NAME="Ubuntu"
VERSION_ID="22.04"
ID=ubuntu

===== KERNEL =====
Linux vm-real-01 5.15.0-91-generic x86_64 GNU/Linux

===== DPKG_PACKAGES =====
ii nginx 1.18.0-ubuntu1.3 amd64

===== OPEN_PORTS =====
nginx|443|tcp|0.0.0.0|nginx
"""
    parsed = parse_asset_text(sample)
    assert parsed.hostname == "vm-real-01"
    assert parsed.distribution == "ubuntu"
    assert parsed.exposure_level == "public"
    assert any(pkg["package_name"] == "nginx" for pkg in parsed.packages)
    assert any(svc["port"] == 443 for svc in parsed.services)
