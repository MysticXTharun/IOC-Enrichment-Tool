import requests

from app.core.config import settings

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


def check_ip(ip: str):
    headers = {
        "X-OTX-API-KEY": settings.OTX_API_KEY
    }

    response = requests.get(
        f"{BASE_URL}/IPv4/{ip}/general",
        headers=headers,
        timeout=15
    )

    response.raise_for_status()

    return response.json()


def check_domain(domain: str):
    headers = {
        "X-OTX-API-KEY": settings.OTX_API_KEY
    }

    response = requests.get(
        f"{BASE_URL}/domain/{domain}/general",
        headers=headers,
        timeout=30,
    )

    response.raise_for_status()

    return response.json()
