import requests
from urllib.parse import urlparse, parse_qs, urlencode
from utils.logger import logger

class IDORScanner:
    def __init__(self):
        self.id_patterns = ["id", "user", "uid", "account", "user_id"]
        self.results = []

    def scan(self, url):
        self.results = []
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            if param.lower() in self.id_patterns:
                original_value = query_params[param][0]
                try:
                    test_values = []
                    if original_value.isdigit():
                        base_id = int(original_value)
                        test_values = [str(base_id + 1), str(base_id - 1), str(base_id + 100)]
                    else:
                        test_values = [original_value + "_test", "1"]

                    for test_value in test_values:
                        new_params = query_params.copy()
                        new_params[param] = test_value
                        new_query = urlencode(new_params, doseq=True)
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

                        response = requests.get(test_url, timeout=5)
                        logger.debug(f"IDOR: {test_url} - Status: {response.status_code}, Length: {len(response.text)}")
                        if response.status_code == 200 and "login" not in response.text.lower() and "error" not in response.text.lower():
                            finding = {
                                "vulnerability": "IDOR",
                                "url": test_url,
                                "payload": test_value,
                                "severity": "medium",
                                "details": f"Potential IDOR detected: Accessed {param}={test_value} without authentication."
                            }
                            self.results.append(finding)
                            logger.info(f"IDOR found: {test_url} with {param}={test_value}")
                except (requests.RequestException, ValueError) as e:
                    logger.error(f"Error scanning {test_url} for IDOR: {e}")

        return self.results