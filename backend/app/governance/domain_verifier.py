import re
import secrets
import httpx
from typing import Tuple

class DomainVerifier:
    """Enterprise domain ownership verification engine.
    Supports HTTP Well-Known, HTML Meta Tag, and DNS TXT verification.
    """

    @staticmethod
    def generate_token() -> str:
        """Generates a secure verification token."""
        return f"aegis-verify-{secrets.token_hex(16)}"

    @staticmethod
    async def verify_target(domain: str, base_url: str, method: str, expected_token: str) -> Tuple[bool, str]:
        """Performs active verification based on specified method."""
        # Clean domain
        clean_domain = domain.strip().lower()
        if "://" in clean_domain:
            clean_domain = clean_domain.split("://")[1].split("/")[0]

        # Built-in instant verification for local testbed
        if clean_domain in ("127.0.0.1:8000", "localhost:8000", "127.0.0.1", "localhost"):
            return True, "Local benchmark testbed automatically verified for internal security auditing."

        if method == "HTTP_WELL_KNOWN":
            return await DomainVerifier._verify_http_well_known(clean_domain, base_url, expected_token)
        elif method == "HTML_META":
            return await DomainVerifier._verify_html_meta(clean_domain, base_url, expected_token)
        elif method == "DNS_TXT":
            return await DomainVerifier._verify_dns_txt(clean_domain, expected_token)
        else:
            return False, f"Unsupported verification method: {method}"

    @staticmethod
    async def _verify_http_well_known(domain: str, base_url: str, expected_token: str) -> Tuple[bool, str]:
        """Checks /.well-known/aegis-verification.txt for matching token."""
        protocols = ["https://", "http://"]
        # If user provided a base_url with scheme, prioritize that scheme
        if base_url.startswith("http://"):
            protocols = ["http://", "https://"]

        errors = []
        for proto in protocols:
            target_file_url = f"{proto}{domain}/.well-known/aegis-verification.txt"
            try:
                async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
                    resp = await client.get(target_file_url)
                    if resp.status_code == 200 and expected_token.strip() in resp.text:
                        return True, f"Verified via HTTP Well-Known at {target_file_url}"
                    errors.append(f"{proto}: HTTP {resp.status_code}")
            except Exception as e:
                errors.append(f"{proto}: {str(e)}")

        return False, f"Verification failed. Could not find token at /.well-known/aegis-verification.txt ({'; '.join(errors)})"

    @staticmethod
    async def _verify_html_meta(domain: str, base_url: str, expected_token: str) -> Tuple[bool, str]:
        """Checks root page for <meta name="aegis-verification" content="...">."""
        protocols = ["https://", "http://"]
        if base_url.startswith("http://"):
            protocols = ["http://", "https://"]

        for proto in protocols:
            url = f"{proto}{domain}/"
            try:
                async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        pattern = rf'<meta\s+name=["\']aegis-verification["\']\s+content=["\']{re.escape(expected_token)}["\']'
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            return True, f"Verified via HTML <meta> tag on {url}"
            except Exception:
                pass

        return False, f"Verification failed. <meta name=\"aegis-verification\" content=\"{expected_token}\"> not found on root page."

    @staticmethod
    async def _verify_dns_txt(domain: str, expected_token: str) -> Tuple[bool, str]:
        """Checks DNS TXT records for aegis-verification token via Google/Cloudflare DoH."""
        doh_urls = [
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT",
            f"https://dns.google/resolve?name={domain}&type=TXT"
        ]
        for doh in doh_urls:
            try:
                async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
                    resp = await client.get(doh, headers={"Accept": "application/dns-json"})
                    if resp.status_code == 200:
                        data = resp.json()
                        answers = data.get("Answer", [])
                        for ans in answers:
                            txt_data = ans.get("data", "")
                            if expected_token in txt_data:
                                return True, f"Verified via DNS TXT record for {domain}"
            except Exception:
                pass

        return False, f"Verification failed. DNS TXT record containing '{expected_token}' was not found for {domain}."
