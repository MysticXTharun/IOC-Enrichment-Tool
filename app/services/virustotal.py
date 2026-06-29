import requests

from app.core.config import settings

BASE_URL = "https://www.virustotal.com/api/v3"


def check_ip(ip: str):
    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
    }

    response = requests.get(
        f"{BASE_URL}/ip_addresses/{ip}",
        headers=headers,
        timeout=15,
    )

    response.raise_for_status()

    return response.json()


def check_domain(domain: str):
    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY
    }

    response = requests.get(
        f"{BASE_URL}/domains/{domain}",
        headers=headers,
        timeout=30,
    )

    response.raise_for_status()

    return response.json()
