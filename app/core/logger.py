import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Create logs directory automatically
Path("logs").mkdir(exist_ok=True)

formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)

logger = logging.getLogger("IOC-Enrichment")
logger.setLevel(logging.INFO)

# Prevent duplicate logs
logger.handlers.clear()

# Console logging
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

# File logging with rotation
file_handler = RotatingFileHandler(
    "logs/app.log",
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=5,
)

file_handler.setFormatter(formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)
