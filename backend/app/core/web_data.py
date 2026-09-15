"""
AegisAppSec - Platform Catalog & Core Data Definitions
Provides OWASP Top 10 classifications, benchmark vulnerabilities, and team metadata.
"""

OWASP_TOP_10 = [
    {
        "id": "01",
        "title": "Broken Access Control",
        "desc": "Failures that allow unauthorized users to view, modify, or delete resources outside their permissions, including IDOR, BOLA, and missing role checks."
    },
    {
        "id": "02",
        "title": "Cryptographic Failures",
        "desc": "Exposures resulting from weak cipher suites, missing TLS, hardcoded encryption keys, or unencrypted transmission of sensitive data."
    },
    {
        "id": "03",
        "title": "Injection",
        "desc": "Flaws such as SQL, NoSQL, OS command, and LDAP injection where untrusted data is sent to an interpreter as part of a command or query."
    },
    {
        "id": "04",
        "title": "Insecure Design",
        "desc": "Risks related to design and architectural flaws, missing threat modeling, and lack of defense-in-depth security controls."
    },
    {
        "id": "05",
        "title": "Security Misconfiguration",
        "desc": "Default credentials, unhardened cloud storage, open cloud ports, verbose error messages, and missing security headers."
    },
    {
        "id": "06",
        "title": "Vulnerable & Outdated Components",
        "desc": "Dependencies, client libraries, web frameworks, and runtime environments with publicly known CVEs and exploitable flaws."
    },
    {
        "id": "07",
        "title": "Identification & Authentication Failures",
        "desc": "Weak credential stuffing defenses, missing brute-force rate limits, flawed session invalidation, and session fixation vulnerabilities."
    },
    {
        "id": "08",
        "title": "Software & Data Integrity Failures",
        "desc": "Code and infrastructure that does not guard against integrity violations, untrusted CI/CD pipelines, and unverified auto-updates."
    },
    {
        "id": "09",
        "title": "Security Logging & Monitoring Failures",
        "desc": "Insufficient logging of critical events, lack of real-time alerting, and absence of tamper-proof audit trails for forensic analysis."
    },
    {
        "id": "10",
        "title": "Server-Side Request Forgery (SSRF)",
        "desc": "Flaws allowing an attacker to coerce the backend web server into making unauthorized HTTP requests to arbitrary internal or remote destinations."
    }
]

TEAM_MEMBERS = []

SCANNER_METRICS = {
    "endpoints_discovered": 247,
    "requests_tested": 1842,
    "vulnerabilities_found": 18,
    "breakdown": {
        "critical": 2,
        "high": 5,
        "medium": 7,
        "low": 4
    }
}

BENCHMARK_VULNERABILITIES = [
    {
        "id": "VULN-001",
        "severity": "CRITICAL",
        "title": "SQL Injection (Error-Based)",
        "endpoint": "GET /api/users",
        "parameter": "id",
        "confidence": 98,
        "evidence": "Database error detected after controlled payload injection: syntax error at or near 'OR 1=1--'",
        "recommendation": "Use parameterized queries / prepared statements with Object-Relational Mapping (ORM) and enforce strict input validation.",
        "payload": "1' UNION SELECT 1, username, password_hash, email FROM users WHERE '1'='1",
        "cvss": "9.8",
        "cwe": "CWE-89",
        "owasp": "03 Injection",
        "http_request": "GET /api/users?id=1%27+UNION+SELECT+1%2Cusername%2Cpassword_hash%2Cemail+FROM+users-- HTTP/1.1\nHost: target.app\nAuthorization: Bearer eyJhbGciOi...\nUser-Agent: AegisAppSec-DAST/2.4.0",
        "http_response": "HTTP/1.1 500 Internal Server Error\nContent-Type: application/json\n\n{\n  \"error\": \"PostgreSQL: syntax error near 'UNION' in query 'SELECT * FROM users WHERE id=1' UNION SELECT...\"\n}",
        "code_fix": {
            "vulnerable": "# Vulnerable Code\ncursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")",
            "secure": "# Remediated Code\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
        }
    },
    {
        "id": "VULN-002",
        "severity": "HIGH",
        "title": "Server-Side Request Forgery (SSRF)",
        "endpoint": "POST /api/webhook/test",
        "parameter": "callback_url",
        "confidence": 94,
        "evidence": "Internal AWS cloud metadata endpoint 169.254.169.254 successfully resolved with 200 OK containing IAM security credentials.",
        "recommendation": "Implement strict IP address allowlisting, resolve DNS before requesting, and block all RFC 1918 / link-local addresses (169.254.0.0/16, 127.0.0.1, 10.0.0.0/8).",
        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "cvss": "8.6",
        "cwe": "CWE-918",
        "owasp": "10 Server-Side Request Forgery",
        "http_request": "POST /api/webhook/test HTTP/1.1\nHost: target.app\nContent-Type: application/json\n\n{\n  \"callback_url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role\"\n}",
        "http_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \"AccessKeyId\": \"ASIAIOSFODNN7EXAMPLE\",\n  \"SecretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n}",
        "code_fix": {
            "vulnerable": "# Vulnerable Code\nresp = requests.get(request.json['callback_url'])",
            "secure": "# Remediated Code\nurl = validate_outbound_url(request.json['callback_url'], allowed_schemes=['https'], block_private_ips=True)\nresp = requests.get(url, timeout=3)"
        }
    },
    {
        "id": "VULN-003",
        "severity": "HIGH",
        "title": "Broken Object Level Authorization (BOLA / IDOR)",
        "endpoint": "GET /api/documents/{doc_id}",
        "parameter": "doc_id",
        "confidence": 92,
        "evidence": "Cross-tenant financial document retrieved without ownership verification for account tenant_9941.",
        "recommendation": "Validate user tenancy and explicit document access ownership at data access layer before returning object data.",
        "payload": "doc_id=9921 (authenticated as tenant_102)",
        "cvss": "8.2",
        "cwe": "CWE-639",
        "owasp": "01 Broken Access Control",
        "http_request": "GET /api/documents/9921 HTTP/1.1\nHost: target.app\nAuthorization: Bearer token_tenant_102\nX-Requested-With: XMLHttpRequest",
        "http_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \"document_id\": 9921,\n  \"tenant_id\": \"tenant_9941\",\n  \"title\": \"Q3 Financial Audit Confidentials.pdf\",\n  \"url\": \"https://s3.target.app/vault/9921.pdf\"\n}",
        "code_fix": {
            "vulnerable": "# Vulnerable Code\ndoc = Document.query.get(doc_id)",
            "secure": "# Remediated Code\ndoc = Document.query.filter_by(id=doc_id, tenant_id=current_user.tenant_id).first_or_404()"
        }
    },
    {
        "id": "VULN-004",
        "severity": "MEDIUM",
        "title": "Cross-Site Scripting (Reflected XSS)",
        "endpoint": "GET /search",
        "parameter": "q",
        "confidence": 96,
        "evidence": "Injected SVG vector '<svg/onload=alert(1)>' reflected directly into HTML output without context sanitization or CSP blocking.",
        "recommendation": "Encode all user-controlled data using context-aware HTML entity encoders and enforce strict Content-Security-Policy (CSP) headers without 'unsafe-inline'.",
        "payload": "\"><svg/onload=confirm(document.domain)>",
        "cvss": "6.1",
        "cwe": "CWE-79",
        "owasp": "03 Injection",
        "http_request": "GET /search?q=%22%3E%3Csvg%2Fonload%3Dconfirm(document.domain)%3E HTTP/1.1\nHost: target.app\nAccept: text/html",
        "http_response": "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\n\n<div class=\"results\">Search for: \"><svg/onload=confirm(document.domain)></div>",
        "code_fix": {
            "vulnerable": "# Vulnerable Code\nreturn f'<div class=\"results\">Search for: {query}</div>'",
            "secure": "# Remediated Code\nreturn render_template('results.html', query=html.escape(query))"
        }
    },
    {
        "id": "VULN-005",
        "severity": "LOW",
        "title": "Missing HTTP Strict-Transport-Security (HSTS)",
        "endpoint": "ALL /*",
        "parameter": "Strict-Transport-Security Header",
        "confidence": 100,
        "evidence": "HTTP response header 'Strict-Transport-Security' is absent, exposing clients to potential SSL-stripping and man-in-the-middle attacks.",
        "recommendation": "Configure reverse proxy or application middleware to return 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
        "payload": "HEAD / HTTP/1.1",
        "cvss": "3.7",
        "cwe": "CWE-319",
        "owasp": "05 Security Misconfiguration",
        "http_request": "HEAD / HTTP/1.1\nHost: target.app",
        "http_response": "HTTP/1.1 200 OK\nServer: nginx/1.24\nConnection: keep-alive\n(Header 'Strict-Transport-Security' missing)",
        "code_fix": {
            "vulnerable": "# Nginx Configuration (Missing HSTS)\nserver {\n    listen 443 ssl;\n    # No HSTS header defined\n}",
            "secure": "# Remediated Nginx Configuration\nserver {\n    listen 443 ssl;\n    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n}"
        }
    }
]
