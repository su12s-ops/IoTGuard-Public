from app import models
from app.services.runtime_context import package_related_to_service, service_is_exposed, service_name


REMOTE_ENTRY_PORTS = {21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 6379, 8080, 8443, 9200}


def analyze_reachability(asset: models.LinuxAsset, package_name: str, services: list[models.AssetService]) -> dict:
    related_services = []
    exposed_services = []
    paths = []
    reasons = []

    for service in services:
        svc_name = service_name(service)
        if not package_related_to_service(package_name, svc_name):
            continue
        related_services.append(service)
        path = [asset.hostname, f"{svc_name}:{service.port}/{service.protocol}"]
        if svc_name != package_name:
            path.append(package_name)
        path.append("CVE")
        paths.append(path)
        if service_is_exposed(service):
            exposed_services.append(
                {
                    "service_name": svc_name,
                    "port": service.port,
                    "protocol": service.protocol,
                    "listen_address": service.listen_address,
                    "entry_port": service.port in REMOTE_ENTRY_PORTS,
                }
            )

    if not related_services:
        return {
            "status": "none",
            "score": 18.0,
            "path_count": 1,
            "exposed_service_count": 0,
            "related_services": [],
            "exposed_services": [],
            "paths": [[asset.hostname, package_name, "CVE"]],
            "confidence": 0.38,
            "conclusion": "当前未观察到服务到软件包的依赖路径，暂按包级命中处理。",
            "reason": "已确认软件包版本命中，但尚未发现通向该漏洞包的明确运行服务路径。",
        }

    exposed_count = len(exposed_services)
    entry_count = sum(1 for item in exposed_services if item["entry_port"])
    score = 38.0 + min(18.0, len(related_services) * 7.0)
    if exposed_services:
        score += 22.0 + min(24.0, exposed_count * 14.0) + min(12.0, entry_count * 6.0)
    else:
        score += 10.0
    confidence = 0.58 + min(0.22, len(related_services) * 0.06) + min(0.12, exposed_count * 0.05)

    if exposed_services:
        status = "internet_exposed"
        reasons.append(f"{exposed_count} 个对外暴露的关联服务")
        if entry_count:
            reasons.append(f"{entry_count} 个服务位于常见远程入口端口")
        conclusion = "该漏洞包可通过对外暴露的关联服务路径到达，具备较强可达性。"
    else:
        status = "linked"
        reasons.append(f"{len(related_services)} 个内部关联服务")
        conclusion = "该漏洞包已与真实服务路径关联，但当前不是直接对外暴露路径。"

    reasons.append(f"{len(paths)} 条依赖路径")

    return {
        "status": status,
        "score": round(min(100.0, score), 2),
        "path_count": len(paths),
        "exposed_service_count": exposed_count,
        "related_services": [
            {
                "service_name": service_name(service),
                "port": service.port,
                "protocol": service.protocol,
                "listen_address": service.listen_address,
                "is_public_exposed": service_is_exposed(service),
            }
            for service in related_services
        ],
        "exposed_services": exposed_services,
        "paths": paths,
        "confidence": round(min(0.94, confidence), 2),
        "conclusion": conclusion,
        "reason": "; ".join(reasons),
    }
