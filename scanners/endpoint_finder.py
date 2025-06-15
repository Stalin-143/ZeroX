import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from utils.logger import logger

class EndpointFinder:
    def __init__(self):
        self.endpoints = set()

    def fetch_wayback_urls(self, domain):
        """Fetch endpoints from Wayback Machine CDX API."""
        try:
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=original&collapse=urlkey"
            response = requests.get(cdx_url, timeout=10)
            response.raise_for_status()
            data = response.json()
            urls = [item[0] for item in data[1:] if item]
            self.endpoints.update(urls)
            logger.info(f"Fetched {len(urls)} endpoints from Wayback Machine for {domain}")
        except requests.RequestException as e:
            logger.error(f"Error fetching Wayback URLs for {domain}: {e}")

    def crawl_site(self, url):
        """Crawl the target site to find additional endpoints."""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            base_url = urlparse(url).scheme + "://" + urlparse(url).netloc

            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    self.endpoints.add(full_url)

            for form in soup.find_all('form', action=True):
                action = form['action']
                full_url = urljoin(base_url, action)
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    self.endpoints.add(full_url)

            logger.info(f"Found {len(self.endpoints)} endpoints via crawling {url}")
        except requests.RequestException as e:
            logger.error(f"Error crawling {url}: {e}")

    def find_endpoints(self, url):
        """Combine Wayback and crawling to find endpoints."""
        self.endpoints = set()
        domain = urlparse(url).netloc
        self.fetch_wayback_urls(domain + "/*")
        self.crawl_site(url)
        return list(self.endpoints)