import requests

from app.core.config import settings
from app.core.logger import logger

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


def _request(endpoint: str):
    headers = {
        "X-OTX-API-KEY": settings.OTX_API_KEY
    }

    logger.info(f"OTX request started: {endpoint}")

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=30,
        )

        response.raise_for_status()

        logger.info("OTX request completed successfully")

        return response.json()

    except requests.exceptions.Timeout:
        logger.error("OTX request timed out")

        return {
            "service": "OTX",
            "status": "error",
            "message": "Request timed out",
        }

    except requests.exceptions.HTTPError as e:
        logger.error(f"OTX HTTP error: {e}")

        return {
            "service": "OTX",
            "status": "error",
            "message": str(e),
        }

    except requests.exceptions.RequestException as e:
        logger.error(f"OTX request failed: {e}")

        return {
            "service": "OTX",
            "status": "error",
            "message": str(e),
        }


def check_ip(ip: str):
    return _request(f"{BASE_URL}/IPv4/{ip}/general")


def check_domain(domain: str):
    return _request(f"{BASE_URL}/domain/{domain}/general")


def check_url(url: str):
    return _request(f"{BASE_URL}/url/{url}/general")
