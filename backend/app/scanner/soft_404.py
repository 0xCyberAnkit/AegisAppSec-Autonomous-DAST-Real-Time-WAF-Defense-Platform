import re
import uuid
import httpx
from typing import Optional


class Soft404Checker:
    """
    Detects and fingerprints 'Soft-404' responses.
    Many modern web frameworks, Single Page Apps (React/Vue/Next.js/Tailwind),
    and reverse proxies return HTTP 200 for ANY requested path with a custom
    error page or index.html.
    This checker prevents the scanner from treating custom 404 pages as active,
    vulnerable endpoints.
    """

    def __init__(self):
        self.has_soft_404: bool = False
        self.probe_status: int = 404
        self.probe_length: int = 0
        self.probe_title: str = ""
        self.probe_snippet: str = ""

    async def fingerprint(self, client: httpx.AsyncClient, base_url: str):
        random_path = f"/_aegis_404_probe_{uuid.uuid4().hex[:10]}"
        test_url = f"{base_url.rstrip('/')}{random_path}"
        try:
            r = await client.get(test_url, timeout=5.0)
            self.probe_status = r.status_code
            self.probe_length = len(r.text)
            self.probe_snippet = r.text[:600].strip().lower()

            # If a completely random non-existent path returns HTTP 200 or 206
            if r.status_code in (200, 206):
                self.has_soft_404 = True
                # Extract <title> if present
                m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                if m:
                    self.probe_title = m.group(1).strip().lower()
        except Exception:
            pass

    def is_dead_or_soft_404(self, resp: Optional[httpx.Response]) -> bool:
        """
        Returns True if the response represents a dead endpoint (404, 410, 502, 503)
        or matches the target's soft-404 page.
        """
        if resp is None:
            return True

        if resp.status_code in (404, 410, 502, 503):
            return True

        # Check soft-404 match on HTTP 200 responses
        if self.has_soft_404 and resp.status_code in (200, 206):
            # 1. Title match (e.g. "404 | CodexSec", "Page Not Found", "404")
            if self.probe_title:
                m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if m and m.group(1).strip().lower() == self.probe_title:
                    return True

            # 2. Length within small variance (templates usually have fixed size)
            if abs(len(resp.text) - self.probe_length) <= 80:
                return True

            # 3. Identical leading content snippet
            if self.probe_snippet and resp.text[:600].strip().lower() == self.probe_snippet:
                return True

        return False
