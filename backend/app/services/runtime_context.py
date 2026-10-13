from app import models


SERVICE_DEPENDENCIES = {
    "nginx": ["openssl", "libssl3", "zlib1g", "systemd"],
    "apache2": ["openssl", "libssl3", "zlib1g", "systemd"],
    "redis-server": ["openssl", "libssl3", "systemd", "libc6"],
    "openssh-server": ["openssl", "libssl3", "systemd", "pam", "bash"],
    "ssh": ["openssh-server", "openssl", "libssl3", "bash"],
    "sshd": ["openssh-server", "openssl", "systemd", "bash"],
    "systemd-resolved": ["systemd", "openssl"],
    "curl": ["openssl", "libssl3", "ca-certificates"],
    "bash": ["libc6", "readline-common"],
    "sudo": ["pam", "libc6"],
}

PORT_SERVICE_HINTS = {
    22: "openssh-server",
    53: "systemd-resolved",
    80: "nginx",
    443: "nginx",
    6379: "redis-server",
    8080: "nginx",
    8443: "nginx",
}


def service_name(service: models.AssetService) -> str:
    name = (service.service_name or service.process_name or "").strip()
    if not name or name == "unknown":
        name = PORT_SERVICE_HINTS.get(service.port, "unknown")
    return name


def service_is_exposed(service: models.AssetService) -> bool:
    return bool(service.is_public_exposed or service.listen_address in {"0.0.0.0", "::", "*"})


def package_related_to_service(package_name: str, service_name_value: str) -> bool:
    if not package_name or not service_name_value:
        return False
    if package_name == service_name_value:
        return True
    dependencies = SERVICE_DEPENDENCIES.get(service_name_value, [])
    return package_name in dependencies
