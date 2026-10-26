"""Verified HTTPS transport with explicit compatibility for an existing proxy."""
import os
import ssl
from urllib.request import HTTPSHandler


def verified_https_handler():
    context = ssl.create_default_context()
    maximum = os.getenv("LINUXGUARD_INTEL_TLS_MAX_VERSION", "").strip()
    if maximum:
        if maximum != "1.2":
            raise ValueError("LINUXGUARD_INTEL_TLS_MAX_VERSION supports only explicit 1.2 compatibility")
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    return HTTPSHandler(context=context)
