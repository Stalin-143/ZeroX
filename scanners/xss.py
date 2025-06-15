import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from utils.logger import logger

class XSSScanner:
    def __init__(self):
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "javascript:alert(1)",
        ]
        self.results = []

    def scan(self, url):
        self.results = []
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Test GET parameters
        for param in query_params:
            for payload in self.payloads:
                new_params = query_params.copy()
                new_params[param] = payload
                new_query = urlencode(new_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

                try:
                    response = requests.get(test_url, timeout=5)
                    logger.debug(f"XSS GET: {test_url} - Status: {response.status_code}, Length: {len(response.text)}")
                    if payload in response.text or payload.replace("%3C", "<").replace("%3E", ">") in response.text:
                        finding = {
                            "vulnerability": "XSS",
                            "url": test_url,
                            "payload": payload,
                            "severity": "high",
                            "details": f"Reflected XSS detected with payload: {payload}"
                        }
                        self.results.append(finding)
                        logger.info(f"XSS found: {test_url} with payload: {payload}")
                except requests.RequestException as e:
                    logger.error(f"Error scanning {test_url} for XSS: {e}")

        # Test POST forms
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form', method=lambda x: x and x.lower() == 'post')
            for form in forms:
                action = form.get('action', '')
                form_url = urljoin(url, action)
                inputs = form.find_all('input', {'name': True})
                data = {inp['name']: payload for inp in inputs for payload in self.payloads}
                for payload in self.payloads:
                    try:
                        response = requests.post(form_url, data=data, timeout=5)
                        logger.debug(f"XSS POST: {form_url} - Status: {response.status_code}, Length: {len(response.text)}")
                        if payload in response.text:
                            finding = {
                                "vulnerability": "XSS",
                                "url": form_url,
                                "payload": payload,
                                "severity": "high",
                                "details": f"Stored XSS detected in POST request with payload: {payload}"
                            }
                            self.results.append(finding)
                            logger.info(f"XSS found in POST: {form_url} with payload: {payload}")
                    except requests.RequestException as e:
                        logger.error(f"Error scanning {form_url} for XSS POST: {e}")
        except requests.RequestException as e:
            logger.error(f"Error checking forms at {url}: {e}")

        return self.results