import base64
import requests

from app.core.config import settings
from app.core.logger import logger

BASE_URL = "https://www.virustotal.com/api/v3"


def _request(endpoint: str):
    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
    }

    logger.info(f"VirusTotal request started: {endpoint}")

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=30,
        )

        response.raise_for_status()

        logger.info("VirusTotal request completed successfully")

        return response.json()

    except requests.exceptions.Timeout:
        logger.error("VirusTotal request timed out")

        return {
            "service": "VirusTotal",
            "status": "error",
            "message": "Request timed out",
        }

    except requests.exceptions.HTTPError as e:
        logger.error(f"VirusTotal HTTP error: {e}")

        return {
            "service": "VirusTotal",
            "status": "error",
            "message": str(e),
        }

    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal request failed: {e}")

        return {
            "service": "VirusTotal",
            "status": "error",
            "message": str(e),
        }


def check_ip(ip: str):
    return _request(f"{BASE_URL}/ip_addresses/{ip}")


def check_domain(domain: str):
    return _request(f"{BASE_URL}/domains/{domain}")


def check_url(url: str):
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")

    return _request(f"{BASE_URL}/urls/{url_id}")


def check_hash(file_hash: str):
    return _request(f"{BASE_URL}/files/{file_hash}")
