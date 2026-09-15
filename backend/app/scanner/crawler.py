import asyncio
import re
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
from pydantic import BaseModel
import httpx
from bs4 import BeautifulSoup


from app.scanner.soft_404 import Soft404Checker


class DiscoveredEndpoint(BaseModel):
    url: str
    path: str
    method: str = "GET"  # GET, POST, etc.
    params: Dict[str, str] = {}  # query params
    form_data: Dict[str, str] = {}  # form input names & default/sample values
    content_type: str = "text/html"
    source: str = "link"  # link, form, script, api_meta, robots


class CrawlResult(BaseModel):
    target_url: str
    endpoints: List[DiscoveredEndpoint] = []
    total_pages_visited: int = 0
    duration_seconds: float = 0.0
    soft_404: Optional[Any] = None



class DASTSpider:
    """
    Autonomous Asynchronous Web Spider & Attack Surface Discovery Engine.
    Discovers:
      1. Hyperlinks with query parameters (<a href="...">)
      2. HTML Forms (<form action="..." method="..."> with input/textarea/select fields)
      3. Inline JavaScript API routes & fetch/axios calls
      4. Known API schemas & metadata (/robots.txt, /openapi.json, /swagger.json, etc.)
    """

    DEFAULT_API_PROBES = [
        "/robots.txt",
        "/openapi.json",
        "/swagger.json",
        "/api/docs",
        "/docs",
    ]

    # Regex to extract API endpoints from JS or HTML attributes
    API_ROUTE_REGEX = re.compile(
        r"""(?:['"`])(\/(?:api|v[0-9]+|tools|diagnostics|search|reviews|account|orders|auth|login|records|config)[a-zA-Z0-9_\-\/.]*)(?:['"`])""",
        re.IGNORECASE,
    )

    def __init__(self, max_depth: int = 3, max_pages: int = 30, concurrency: int = 5):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency

    async def crawl(self, client: httpx.AsyncClient, target_url: str) -> CrawlResult:
        import time

        start_time = time.time()
        base_parsed = urlparse(target_url.rstrip("/"))
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

        visited_urls: Set[str] = set()
        queue: List[tuple[str, int]] = [(target_url.rstrip("/"), 0)]

        discovered_dict: Dict[str, DiscoveredEndpoint] = {}

        def make_key(ep: DiscoveredEndpoint) -> str:
            param_keys = ",".join(sorted(ep.params.keys()))
            form_keys = ",".join(sorted(ep.form_data.keys()))
            return f"{ep.method}:{ep.path}:{param_keys}:{form_keys}"

        # 0. Fingerprint target for Soft-404 / custom SPA error pages
        soft_checker = Soft404Checker()
        await soft_checker.fingerprint(client, target_url)

        # 1. Proactive API & metadata probes
        for probe in self.DEFAULT_API_PROBES:
            probe_url = f"{base_origin}{probe}"
            try:
                r = await client.get(probe_url, timeout=3.0)
                if r.status_code == 200 and not soft_checker.is_dead_or_soft_404(r):
                    ep = DiscoveredEndpoint(
                        url=probe_url,
                        path=probe,
                        method="GET",
                        source="api_meta",
                    )
                    discovered_dict[make_key(ep)] = ep

                    # If robots.txt, parse Allow / Disallow paths
                    if probe == "/robots.txt":
                        for line in r.text.splitlines():
                            line = line.strip()
                            if line.lower().startswith(
                                "disallow:"
                            ) or line.lower().startswith("allow:"):
                                parts = line.split(":", 1)
                                if len(parts) == 2:
                                    dis_path = parts[1].strip()
                                    if (
                                        dis_path
                                        and not dis_path.endswith("*")
                                        and "/" in dis_path
                                    ):
                                        full = urljoin(base_origin, dis_path)
                                        queue.append((full, 1))
            except Exception:
                pass

        # 2. Asynchronous BFS crawling loop
        pages_visited = 0
        while queue and pages_visited < self.max_pages:
            current_url, depth = queue.pop(0)

            # Normalize URL (strip fragment, normalize path)
            parsed_current = urlparse(current_url)
            norm_url = f"{parsed_current.scheme}://{parsed_current.netloc}{parsed_current.path}"
            if norm_url in visited_urls:
                continue
            visited_urls.add(norm_url)
            pages_visited += 1

            # Fetch page content
            try:
                resp = await client.get(current_url, timeout=4.0)
            except Exception:
                continue

            # Skip soft-404 or dead pages
            if soft_checker.is_dead_or_soft_404(resp):
                continue

            content_type = resp.headers.get("content-type", "")
            raw_text = resp.text


            # Record current URL as an endpoint
            q_params = {k: v[0] for k, v in parse_qs(parsed_current.query).items()}
            current_ep = DiscoveredEndpoint(
                url=current_url,
                path=parsed_current.path or "/",
                method="GET",
                params=q_params,
                content_type=content_type,
                source="link",
            )
            discovered_dict[make_key(current_ep)] = current_ep

            # Extract endpoints from inline JavaScript / text regex
            found_routes = self.API_ROUTE_REGEX.findall(raw_text)
            for route in set(found_routes):
                if route.startswith("//") or route.startswith("/static"):
                    continue
                full_route_url = urljoin(base_origin, route)
                route_parsed = urlparse(full_route_url)
                if route_parsed.netloc == base_parsed.netloc:
                    ep_js = DiscoveredEndpoint(
                        url=full_route_url,
                        path=route_parsed.path,
                        method="GET",
                        source="script",
                    )
                    k = make_key(ep_js)
                    if k not in discovered_dict:
                        discovered_dict[k] = ep_js
                        if depth + 1 <= self.max_depth:
                            queue.append((full_route_url, depth + 1))

            # Only parse HTML for links and forms
            if "text/html" not in content_type:
                continue

            try:
                soup = BeautifulSoup(raw_text, "html.parser")
            except Exception:
                continue

            # 3. Extract Forms (<form>)
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action") or parsed_current.path
                form_url = urljoin(current_url, action)
                form_parsed = urlparse(form_url)
                method = (form.get("method") or "GET").upper()

                form_data = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    val = (
                        inp.get("value")
                        or inp.text.strip()
                        or ("1" if inp.get("type") == "number" else "test")
                    )
                    form_data[name] = val

                form_ep = DiscoveredEndpoint(
                    url=form_url,
                    path=form_parsed.path or "/",
                    method=method,
                    form_data=form_data if method == "POST" else {},
                    params=form_data if method == "GET" else {},
                    source="form",
                )
                discovered_dict[make_key(form_ep)] = form_ep

            # 4. Extract Hyperlinks (<a>)
            if depth < self.max_depth:
                links = soup.find_all(["a", "link"])
                for link in links:
                    href = link.get("href")
                    if (
                        not href
                        or href.startswith("#")
                        or href.startswith("javascript:")
                        or href.startswith("mailto:")
                    ):
                        continue

                    full_link = urljoin(current_url, href)
                    link_parsed = urlparse(full_link)

                    # Strictly enforce same-origin to avoid scanning off-site
                    if link_parsed.netloc != base_parsed.netloc:
                        continue

                    # Ignore static assets
                    if any(
                        link_parsed.path.lower().endswith(ext)
                        for ext in [
                            ".css",
                            ".js",
                            ".png",
                            ".jpg",
                            ".jpeg",
                            ".gif",
                            ".svg",
                            ".ico",
                            ".woff",
                            ".woff2",
                        ]
                    ):
                        continue

                    link_params = {
                        k: v[0] for k, v in parse_qs(link_parsed.query).items()
                    }
                    link_ep = DiscoveredEndpoint(
                        url=full_link,
                        path=link_parsed.path or "/",
                        method="GET",
                        params=link_params,
                        source="link",
                    )
                    k = make_key(link_ep)
                    if k not in discovered_dict:
                        discovered_dict[k] = link_ep
                        queue.append((full_link, depth + 1))

        duration = round(time.time() - start_time, 2)
        return CrawlResult(
            target_url=target_url,
            endpoints=list(discovered_dict.values()),
            total_pages_visited=pages_visited,
            duration_seconds=duration,
            soft_404=soft_checker,
        )

