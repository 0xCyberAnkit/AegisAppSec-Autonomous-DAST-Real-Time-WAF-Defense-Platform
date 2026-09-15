from typing import Dict, Any

REMEDIATION_GUIDES: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "title": "SQL Injection (SQLi)",
        "owasp": "A03:2021-Injection",
        "description": "SQL Injection occurs when user input is concatenated directly into SQL query text, allowing an attacker to manipulate the query structure, bypass authentication, read unauthorized database records, or corrupt data.",
        "checklist": [
            "Never concatenate untrusted input directly into SQL strings.",
            "Always use parameterized queries (prepared statements) with placeholders.",
            "Utilize type-safe Object-Relational Mappers (ORMs) such as SQLAlchemy, Prisma, or Hibernate.",
            "Apply principle of least privilege to the application's database credentials."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Direct string interpolation
cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{search_term}%'")''',
                "secure": '''# SECURE: Parameterized query with bound parameters
cursor.execute(
    "SELECT * FROM products WHERE name LIKE ?",
    (f"%{search_term}%",)
)'''
            },
            "nodejs": {
                "vulnerable": '''// VULNERABLE: String concatenation in query
const query = `SELECT * FROM products WHERE name = '${req.query.q}'`;
db.query(query, (err, rows) => { ... });''',
                "secure": '''// SECURE: Parameterized placeholder
const query = "SELECT * FROM products WHERE name = ?";
db.query(query, [req.query.q], (err, rows) => { ... });'''
            },
            "php": {
                "vulnerable": '''// VULNERABLE: Variable interpolation
$sql = "SELECT * FROM products WHERE name = '" . $_GET['q'] . "'";
$result = $pdo->query($sql);''',
                "secure": '''// SECURE: PDO Prepared Statement
$stmt = $pdo->prepare("SELECT * FROM products WHERE name = :name");
$stmt->execute(['name' => $_GET['q']]);
$result = $stmt->fetchAll();'''
            },
            "go": {
                "vulnerable": '''// VULNERABLE: Sprintf formatting
query := fmt.Sprintf("SELECT * FROM products WHERE name = '%s'", term)
rows, err := db.Query(query)''',
                "secure": '''// SECURE: Parameterized SQL placeholder
query := "SELECT * FROM products WHERE name = ?"
rows, err := db.Query(query, term)'''
            }
        }
    },
    "CWE-79": {
        "title": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021-Injection",
        "description": "Cross-Site Scripting flaws happen when an application includes untrusted user data in an HTML page without proper contextual validation or encoding, allowing attackers to execute arbitrary JavaScript in the victim's browser context.",
        "checklist": [
            "Perform contextual output encoding (HTML body, attribute, JavaScript, and URL contexts).",
            "Use modern UI frameworks (React, Vue, Angular) that auto-escape interpolated values.",
            "Sanitize any required rich text using trusted libraries like DOMPurify or Bleach.",
            "Deploy a rigorous Content Security Policy (CSP) forbidding 'unsafe-inline' scripts."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Raw HTML interpolation
html_output = f"<div class='review'><strong>{author}</strong>: {comment}</div>"
return Response(content=html_output, media_type="text/html")''',
                "secure": '''# SECURE: Contextual HTML entity escaping
import html
safe_author = html.escape(author, quote=True)
safe_comment = html.escape(comment, quote=True)
html_output = f"<div class='review'><strong>{safe_author}</strong>: {safe_comment}</div>"
return Response(content=html_output, media_type="text/html")'''
            },
            "nodejs": {
                "vulnerable": '''// VULNERABLE: Direct innerHTML injection
document.getElementById('reviews').innerHTML += `<p>${review.comment}</p>`;''',
                "secure": '''// SECURE: DOMPurify sanitization & textContent
import DOMPurify from 'dompurify';
const safeComment = DOMPurify.sanitize(review.comment);
document.getElementById('reviews').innerHTML += `<p>${safeComment}</p>`;
// OR use safe textNode:
// const p = document.createElement('p');
// p.textContent = review.comment;'''
            },
            "php": {
                "vulnerable": '''// VULNERABLE: Direct echo without escaping
echo "<div>" . $_POST['comment'] . "</div>";''',
                "secure": '''// SECURE: htmlspecialchars with ENT_QUOTES and UTF-8
echo "<div>" . htmlspecialchars($_POST['comment'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . "</div>";'''
            },
            "go": {
                "vulnerable": '''// VULNERABLE: Writing raw string to template
w.Write([]byte("<div>" + comment + "</div>"))''',
                "secure": '''// SECURE: html/template auto-escaping or HTMLEscapeString
safeComment := html.EscapeString(comment)
w.Write([]byte("<div>" + safeComment + "</div>"))'''
            }
        }
    },
    "CWE-918": {
        "title": "Server-Side Request Forgery (SSRF)",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "description": "SSRF occurs when a web server fetches a remote resource specified by an external user without validating the target IP or domain, allowing attackers to access loopback services, internal subnets, or cloud metadata credentials.",
        "checklist": [
            "Never allow arbitrary user-supplied URLs to be fetched directly by the backend.",
            "Implement a strict domain allowlist (e.g. only allow images from s3.amazonaws.com/mybucket).",
            "Resolve DNS queries and reject loopback (127.0.0.0/8), private (RFC 1918), and link-local (169.254.0.0/16) addresses.",
            "Disable HTTP redirection following or re-verify each redirect location against the IP filter."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Direct fetch of user URL
async with httpx.AsyncClient() as client:
    res = await client.get(user_url)
    return res.text''',
                "secure": '''# SECURE: DNS resolution & IP subnet restriction
import socket, ipaddress, urllib.parse

def is_safe_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    ip_str = socket.gethostbyname(parsed.hostname)
    ip = ipaddress.ip_address(ip_str)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)

if not is_safe_url(user_url):
    raise HTTPException(status_code=400, detail="Target URL not permitted.")'''
            },
            "nodejs": {
                "vulnerable": '''// VULNERABLE: Blind axios/fetch call
const response = await axios.get(req.body.url);''',
                "secure": '''// SECURE: SSRF filter with ipaddr.js & allowlist
const ipaddr = require('ipaddr.js');
const dns = require('dns').promises;

const { address } = await dns.lookup(new URL(req.body.url).hostname);
const ip = ipaddr.parse(address);
if (ip.range() !== 'unicast') {
    throw new Error('Destination IP not allowed.');
}'''
            },
            "php": {
                "vulnerable": '''// VULNERABLE: file_get_contents with user URL
$content = file_get_contents($_POST['url']);''',
                "secure": '''// SECURE: Check IP filter using filter_var
$ip = gethostbyname(parse_url($_POST['url'], PHP_URL_HOST));
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    die("Access denied to private network address.");
}'''
            },
            "go": {
                "vulnerable": '''// VULNERABLE: Direct http.Get
resp, err := http.Get(userURL)''',
                "secure": '''// SECURE: Custom DialContext checking net.IP.IsPrivate()
client := &http.Client{
    Transport: &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            host, port, _ := net.SplitHostPort(addr)
            ips, _ := net.LookupIP(host)
            for _, ip := range ips {
                if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
                    return nil, errors.New("restricted network target")
                }
            }
            return net.Dial(network, addr)
        },
    },
}'''
            }
        }
    },
    "CWE-352": {
        "title": "Cross-Site Request Forgery (CSRF)",
        "owasp": "A01:2021-Broken Access Control",
        "description": "CSRF allows malicious websites to trick an authenticated victim's browser into submitting unwanted state-changing actions to a vulnerable application on their behalf.",
        "checklist": [
            "Use the Synchronizer Token Pattern: inject a cryptographically strong, unique token into forms/headers.",
            "Configure cookies with 'SameSite=Strict' or 'SameSite=Lax'.",
            "Verify Origin and Referer HTTP headers on all state-changing endpoints.",
            "Require re-authentication or password confirmation for high-privilege operations."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: State-changing POST without CSRF validation
@app.post("/api/transfer")
async def transfer(data: TransferModel):
    execute_transfer(data)''',
                "secure": '''# SECURE: Anti-CSRF token verification
from fastapi import Header, HTTPException

@app.post("/api/transfer")
async def transfer(data: TransferModel, x_csrf_token: str = Header(...), session_token: str = Cookie(...)):
    if not verify_csrf_token(session_token, x_csrf_token):
        raise HTTPException(status_code=403, detail="Invalid Anti-CSRF Token")
    execute_transfer(data)'''
            },
            "nodejs": {
                "vulnerable": '''// VULNERABLE: Express route without CSRF middleware
app.post('/api/transfer', (req, res) => { transferFunds(req.body); });''',
                "secure": '''// SECURE: csurf or double-csrf middleware
const { doubleCsrf } = require("csrf-csrf");
const { doubleCsrfProtection } = doubleCsrf({ ...options });
app.post('/api/transfer', doubleCsrfProtection, (req, res) => { transferFunds(req.body); });'''
            },
            "php": {
                "vulnerable": '''// VULNERABLE: Direct post handling
if ($_SERVER['REQUEST_METHOD'] === 'POST') { processTransfer($_POST); }''',
                "secure": '''// SECURE: Token session verification
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    http_response_code(403);
    die("CSRF validation failed.");
}'''
            },
            "go": {
                "vulnerable": '''// VULNERABLE: No CSRF verification
http.HandleFunc("/transfer", handleTransfer)''',
                "secure": '''// SECURE: nosurf CSRF middleware
csrfHandler := nosurf.New(mux)
http.ListenAndServe(":8080", csrfHandler)'''
            }
        }
    },
    "CWE-639": {
        "title": "Insecure Direct Object References (IDOR)",
        "owasp": "A01:2021-Broken Access Control",
        "description": "IDOR vulnerabilities occur when an application provides direct access to objects based on user-supplied input without verifying that the requesting user has the authorization to access the specific object.",
        "checklist": [
            "Always validate user ownership of the requested resource using server-side session identity.",
            "Use indirect reference maps or unguessable cryptographic GUIDs instead of sequential IDs.",
            "Enforce role-based (RBAC) or attribute-based (ABAC) access control at the data layer."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Direct query by client-supplied ID
@app.get("/orders/{order_id}")
async def get_order(order_id: int):
    return db.query("SELECT * FROM orders WHERE id = ?", (order_id,))''',
                "secure": '''# SECURE: Enforce session tenant ownership check
@app.get("/orders/{order_id}")
async def get_order(order_id: int, current_user: User = Depends(get_current_user)):
    order = db.query("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, current_user.id))
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order'''
            },
            "nodejs": {
                "vulnerable": '''// VULNERABLE: Direct query using route param
app.get('/orders/:id', async (req, res) => {
    const order = await db.orders.findById(req.params.id);
    res.json(order);
});''',
                "secure": '''// SECURE: Match tenant user ID against auth session
app.get('/orders/:id', authMiddleware, async (req, res) => {
    const order = await db.orders.findOne({ _id: req.params.id, userId: req.user.id });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json(order);
});'''
            },
            "php": {
                "vulnerable": '''// VULNERABLE: Query with just ID
$stmt = $pdo->prepare("SELECT * FROM orders WHERE id = ?");
$stmt->execute([$_GET['id']]);''',
                "secure": '''// SECURE: Query filtering by session user_id
$stmt = $pdo->prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?");
$stmt->execute([$_GET['id'], $_SESSION['user_id']]);
$order = $stmt->fetch();
if (!$order) { http_response_code(404); exit; }'''
            },
            "go": {
                "vulnerable": '''// VULNERABLE: Direct ID query
row := db.QueryRow("SELECT * FROM orders WHERE id = ?", orderID)''',
                "secure": '''// SECURE: Filter by authenticated user context
userID := r.Context().Value("user_id").(int)
row := db.QueryRow("SELECT * FROM orders WHERE id = ? AND user_id = ?", orderID, userID)'''
            }
        }
    },
    "CWE-78": {
        "title": "OS Command Injection",
        "owasp": "A03:2021-Injection",
        "description": "Command Injection flaws occur when untrusted input is passed directly to an operating system shell, allowing attackers to execute arbitrary server-level commands.",
        "checklist": [
            "Never invoke operating system shell commands (system, popen, exec) with user data.",
            "Use language-level APIs (e.g. Python subprocess with argument lists and shell=False).",
            "Apply strict regex allowlisting to all command arguments.",
            "Run services under least-privileged non-root service accounts."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Shell interpolation
import os
os.system(f"ping -c 1 {user_ip}")''',
                "secure": '''# SECURE: Argument list without shell invocation
import subprocess
subprocess.run(["ping", "-c", "1", validated_ip], shell=False, check=True)'''
            },
            "nodejs": {
                "vulnerable": '''// VULNERABLE: exec() with string concatenation
const { exec } = require('child_process');
exec(`ping -c 1 ${req.query.ip}`);''',
                "secure": '''// SECURE: execFile() with discrete arguments
const { execFile } = require('child_process');
execFile('ping', ['-c', '1', validatedIp], (err, stdout) => { ... });'''
            }
        }
    },
    "CWE-22": {
        "title": "Path Traversal & Local File Inclusion",
        "owasp": "A01:2021-Broken Access Control",
        "description": "Path Traversal allows attackers to access arbitrary files on the server by submitting relative path sequences (../) in file parameters.",
        "checklist": [
            "Use canonicalization / realpath to resolve full filesystem paths.",
            "Verify that the canonical path starts with the authorized base directory.",
            "Avoid accepting user-specified file paths; use an indirect ID mapping table."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Direct file open with user path
with open(f"/var/www/uploads/{filename}", "rb") as f:
    return f.read()''',
                "secure": '''# SECURE: Safe canonicalization check
import os
base_dir = os.path.abspath("/var/www/uploads")
target_path = os.path.abspath(os.path.join(base_dir, filename))
if not target_path.startswith(base_dir + os.sep):
    raise HTTPException(status_code=403, detail="Access Denied")
with open(target_path, "rb") as f:
    return f.read()'''
            }
        }
    },
    "CWE-16": {
        "title": "Security Misconfiguration & Missing Headers",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Security Misconfiguration encompasses missing defensive HTTP response headers, default credentials, verbose error pages, and open cloud storage.",
        "checklist": [
            "Enforce Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, and X-Content-Type-Options.",
            "Disable debug banners and stack traces in production environments.",
            "Audit all API gateways and reverse proxies for default settings."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Missing hardening headers
@app.get("/")
def index():
    return {"status": "ok"}''',
                "secure": '''# SECURE: Hardening middleware enforcement
@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp'''
            }
        }
    },
    "CWE-287": {
        "title": "Broken Authentication",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": "Authentication failures allow adversaries to compromise credentials, hijack sessions, or assume the identity of authorized users.",
        "checklist": [
            "Implement sliding-window rate limiting on login attempts to prevent brute force attacks.",
            "Require multi-factor authentication (MFA) for high-privilege accounts.",
            "Set HttpOnly, Secure, and SameSite flags on all session cookies."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Unlimited login attempts
@app.post("/login")
def login(creds: LoginCreds):
    user = auth(creds)
    return {"token": make_token(user)}''',
                "secure": '''# SECURE: Rate-limited authentication
@app.post("/login")
def login(creds: LoginCreds):
    check_bruteforce_lockout(request.client.host, creds.username)
    user = auth(creds)
    reset_failed_attempts(creds.username)
    return {"token": make_token(user)}'''
            }
        }
    },
    "CWE-611": {
        "title": "XML External Entity (XXE) Injection",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "XXE flaws occur when an XML parser evaluates external entity declarations, leading to local file disclosure or SSRF.",
        "checklist": [
            "Disable external DTD resolution (resolve_entities=False) across all XML parsers.",
            "Prefer standard, structured formats like JSON over XML where possible."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Default XML parser
from xml.etree import ElementTree
root = ElementTree.fromstring(xml_data)''',
                "secure": '''# SECURE: Safe XML parsing with defusedxml
import defusedxml.ElementTree as ET
root = ET.fromstring(xml_data)'''
            }
        }
    },
    "CWE-502": {
        "title": "Insecure Deserialization",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "description": "Insecure Deserialization occurs when untrusted serialized objects are parsed, enabling remote code execution or state tampering.",
        "checklist": [
            "Do not use native serialization formats (pickle, Java Serialization, YAML unsafe load) for client data.",
            "Use strictly validated JSON with Pydantic schemas."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Unpickling user data
import pickle
obj = pickle.loads(user_bytes)''',
                "secure": '''# SECURE: JSON schema deserialization
import json
from pydantic import BaseModel
data = json.loads(user_str)
validated = MyModel(**data)'''
            }
        }
    },
    "CWE-601": {
        "title": "Unvalidated Open Redirect",
        "owasp": "A01:2021-Broken Access Control",
        "description": "Open Redirects allow attackers to craft links that redirect victims to malicious phishing sites via trusted domains.",
        "checklist": [
            "Enforce destination allowlists for redirect targets.",
            "Reject full URLs (http:// or https://) and restrict to relative local paths."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Direct redirect to parameter
@app.get("/redirect")
def redirect(target: str):
    return RedirectResponse(target)''',
                "secure": '''# SECURE: Allowlist verification
@app.get("/redirect")
def redirect(target: str):
    if not is_allowed_internal_path(target):
        return RedirectResponse("/")
    return RedirectResponse(target)'''
            }
        }
    },
    "CWE-942": {
        "title": "CORS Misconfiguration",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Permissive CORS policies (wildcard origins or reflecting untrusted origins with credentials) allow cross-site data extraction.",
        "checklist": [
            "Never reflect the incoming Origin header into Access-Control-Allow-Origin with credentials enabled.",
            "Maintain an explicit allowlist of authorized partner origins."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Wildcard origin with credentials
response.headers["Access-Control-Allow-Origin"] = "*"
response.headers["Access-Control-Allow-Credentials"] = "true"''',
                "secure": '''# SECURE: Verified explicit origin
if origin in AUTHORIZED_ORIGINS:
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"'''
            }
        }
    },
    "CWE-200": {
        "title": "Information Disclosure",
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "Sensitive data exposure reveals stack traces, API keys, database credentials, or private internal IP addresses.",
        "checklist": [
            "Disable verbose debug exception views in production.",
            "Sanitize API error responses to return generic error messages."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Returning raw exception details
except Exception as e:
    return {"error": str(e), "traceback": traceback.format_exc()}''',
                "secure": '''# SECURE: Generic user message with internal logging
except Exception as e:
    logger.error("Internal error: %s", str(e), exc_info=True)
    return {"error": "An internal system error occurred. Reference ID logged."}'''
            }
        }
    },
    "CWE-1104": {
        "title": "Vulnerable and Outdated Components",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "description": "Running third-party libraries or web servers with published vulnerabilities allows exploitation via publicly known CVEs.",
        "checklist": [
            "Continuously scan dependencies using automated tools (e.g. Snyk, Dependabot, Safety).",
            "Cloak runtime version banners in Server and X-Powered-By response headers."
        ],
        "code_snippets": {
            "python": {
                "vulnerable": '''# VULNERABLE: Disclosing server and runtime versions
headers["Server"] = "Uvicorn/0.18.0 OpenSSL/1.0.1 Python/3.8"''',
                "secure": '''# SECURE: Cloaked generic server identity
headers["Server"] = "Aegis-Gateway"'''
            }
        }
    }
}
