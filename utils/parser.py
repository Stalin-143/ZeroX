import json
from utils.logger import logger

def parse_burp_export(file_path):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
            urls = [item["url"] for item in data if "url" in item]
            logger.info(f"Parsed {len(urls)} URLs from Burp export")
            return urls
    except Exception as e:
        logger.error(f"Error parsing Burp export: {e}")
        return []