from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import httpx

class Finding(BaseModel):
    id: str
    title: str
    vuln_type: str
    severity: str
    cvss_score: float
    cvss_vector: str
    endpoint: str
    method: str
    parameter: Optional[str] = None
    payload_used: str
    evidence: str
    cwe_id: str
    owasp_category: str
    confidence: str = "HIGH"
    curl_command: str
    request_raw: str
    response_raw: str
    remediation_summary: str

class BaseDetector(ABC):
    """Abstract base class for all vulnerability detectors."""
    
    name: str = "Base Detector"
    vuln_type: str = "Generic"
    
    @abstractmethod
    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        """Runs detector probes against the target base URL and discovered crawl endpoints."""
        pass

