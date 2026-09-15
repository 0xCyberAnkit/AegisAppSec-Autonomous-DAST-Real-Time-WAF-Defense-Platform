from typing import Dict, Any

class PoCBuilder:
    """
    Constructs deterministic Proof-of-Concept (PoC) exploit scripts
    and raw HTTP transaction diffs.
    """

    @staticmethod
    def generate_curl(method: str, url: str, headers: Dict[str, str], body: str = "") -> str:
        cmd = ["curl", "-s", "-i", "-X", method.upper(), f'"{url}"']
        for k, v in headers.items():
            cmd.append(f'-H "{k}: {v}"')
        if body and method.upper() in ("POST", "PUT", "PATCH"):
            # Escape inner single quotes for shell
            safe_body = body.replace("'", "'\\''")
            cmd.append(f"-d '{safe_body}'")
        return " ".join(cmd)

    @staticmethod
    def format_http_exchange(req_raw: str, resp_raw: str) -> Dict[str, str]:
        return {
            "request": req_raw.strip(),
            "response": resp_raw.strip()
        }
