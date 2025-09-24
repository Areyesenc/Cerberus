# maltiverse_client.py — hostname & url lookups
import time
import requests
from urllib.parse import quote

class MaltiverseClient:
    def __init__(self, api_key: str, base: str = "https://api.maltiverse.com", timeout: int = 10):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({"Authorization": "Bearer {}".format(api_key)})
        self.timeout = timeout

    def _get(self, path: str, params=None):
        url = "{}{}".format(self.base, path)
        for _ in range(3):
            r = self.s.get(url, params=params or {}, timeout=self.timeout)
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", "2"))
                time.sleep(wait)
                continue
            if r.status_code == 404:
                return {"reputation": "not_found", "classification": [], "blacklist": False, "_status": 404}
            if r.status_code >= 400:
                raise RuntimeError("HTTP {} -> {}".format(r.status_code, r.text[:300]))
            return r.json()
        raise RuntimeError("Rate limited repetidamente (429)")

    def hostname(self, host: str) -> dict:
        return self._get("/hostname/{}".format(host))

    def url(self, full_url: str) -> dict:
        # Full URL must be encoded
        return self._get("/url/{}".format(quote(full_url, safe="")))
