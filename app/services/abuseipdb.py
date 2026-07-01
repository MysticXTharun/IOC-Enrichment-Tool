import requests

from app.core.config import settings
from app.core.logger import logger

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip(ip: str):
    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    logger.info(f"AbuseIPDB request started: {ip}")

    try:
        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=30,
        )

        response.raise_for_status()

        logger.info("AbuseIPDB request completed successfully")

        return response.json()

    except requests.exceptions.Timeout:
        logger.error("AbuseIPDB request timed out")

        return {
            "service": "AbuseIPDB",
            "status": "error",
            "message": "Request timed out",
        }

    except requests.exceptions.HTTPError as e:
        logger.error(f"AbuseIPDB HTTP error: {e}")

        return {
            "service": "AbuseIPDB",
            "status": "error",
            "message": str(e),
        }

    except requests.exceptions.RequestException as e:
        logger.error(f"AbuseIPDB request failed: {e}")

        return {
            "service": "AbuseIPDB",
            "status": "error",
            "message": str(e),
        }
