from fastapi import APIRouter, Request, HTTPException, status, Query, Body, Response
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import httpx
import re
from app.targets.db import get_db, reset_db

router = APIRouter(prefix="/api/shop", tags=["CyberMart E-Commerce Testbed"])

class ReviewSubmission(BaseModel):
    product_id: int
    author: str
    comment: str
    rating: int = 5

class PointTransfer(BaseModel):
    recipient_username: str
    amount: int
    csrf_token: Optional[str] = None

class URLPreviewRequest(BaseModel):
    url: str

@router.get("/products")
async def list_products():
    """Lists all Black Friday flash sale catalog items."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products")
    rows = cursor.fetchall()
    return {"status": "success", "products": [dict(r) for r in rows]}

@router.get("/search")
async def search_products(q: str = Query("", description="Search term for product catalog")):
    """
    Vulnerable Endpoint 1: SQL Injection (OWASP Top 10 - A03:2021)
    Concatenates untrusted user input directly into SQL query string.
    """
    conn = get_db()
    cursor = conn.cursor()
    
    # Intentionally vulnerable raw SQL query construction
    raw_sql = f"SELECT id, name, category, price, discount_price, description FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
    
    try:
        cursor.execute(raw_sql)
        rows = cursor.fetchall()
        return {
            "status": "success",
            "query": q,
            "count": len(rows),
            "results": [dict(r) for r in rows]
        }
    except Exception as e:
        # Intentionally leaks database syntax error (Error-based SQLi vector)
        return Response(
            content=f'{{"status":"error","type":"sqlite3.OperationalError","message":"{str(e)}","executed_query":"{raw_sql}"}}',
            status_code=500,
            media_type="application/json"
        )

@router.get("/reviews")
async def get_reviews(product_id: Optional[int] = None):
    """Retrieves product reviews. Returns unencoded user comments."""
    conn = get_db()
    cursor = conn.cursor()
    if product_id:
        cursor.execute("SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC", (product_id,))
    else:
        cursor.execute("SELECT * FROM reviews ORDER BY id DESC")
    rows = cursor.fetchall()
    return {"status": "success", "reviews": [dict(r) for r in rows]}

@router.post("/reviews")
async def create_review(payload: ReviewSubmission):
    """
    Vulnerable Endpoint 2: Stored & Reflected XSS (OWASP Top 10 - A03:2021)
    Stores and reflects unescaped user-controlled HTML/JavaScript content.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO reviews (product_id, author, comment, rating) VALUES (?, ?, ?, ?)",
        (payload.product_id, payload.author, payload.comment, payload.rating)
    )
    conn.commit()
    new_id = cursor.lastrowid
    
    # Returns immediate reflection of raw comment payload
    return {
        "status": "success",
        "message": "Review posted successfully.",
        "review": {
            "id": new_id,
            "product_id": payload.product_id,
            "author": payload.author,
            "comment": payload.comment,  # Reflected without contextual HTML encoding
            "rating": payload.rating
        },
        "raw_preview": f'<div class="review-box"><strong>{payload.author}</strong>: {payload.comment}</div>'
    }

@router.post("/fetch-preview")
async def fetch_preview(request: URLPreviewRequest):
    """
    Vulnerable Endpoint 3: Server-Side Request Forgery (SSRF) (OWASP Top 10 - A10:2021)
    Fetches user-supplied URL directly from backend server without validating
    against loopback (127.0.0.1) or cloud metadata (169.254.169.254).
    """
    target_url = request.url.strip()
    
    # Simulated Cloud Metadata Mock Response for instant, deterministic testing
    if "169.254.169.254" in target_url:
        return {
            "status": "vulnerable_ssrf_confirmed",
            "target": target_url,
            "service": "AWS EC2 IMDSv1",
            "data": {
                "instance-id": "i-09823f49ba871e21b",
                "security-credentials": {
                    "RoleName": "CyberMartProductionAppRole",
                    "AccessKeyId": "ASIAVULNERABLEKEYEXPOSED",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "Token": "AQoDYXdzEJr1EXAMPLETOKENSSRFVULNERABLE..."
                }
            }
        }
    
    if "metadata.google.internal" in target_url:
        return {
            "status": "vulnerable_ssrf_confirmed",
            "target": target_url,
            "service": "Google Compute Engine Metadata",
            "data": {
                "access_token": "ya29.c.b0AXv0zTO918EXAMPLE_TOKEN_EXPOSED...",
                "token_type": "Bearer",
                "expires_in": 3599
            }
        }
    
    if "internal-admin" in target_url:
        return {
            "status": "vulnerable_ssrf_confirmed",
            "target": target_url,
            "service": "Internal Microservice Admin Gateway",
            "data": {
                "gateway": "Core Infrastructure Hub",
                "database_url": "postgresql://postgres:master_sec_pwd@internal-db:5432/cybermart",
                "debug_flags": {"ALLOW_RAW_SQL": True, "PROMISCUOUS_CORS": True}
            }
        }

    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
            resp = await client.get(target_url)
            return {
                "status": "success",
                "target": target_url,
                "http_status": resp.status_code,
                "content_type": resp.headers.get("content-type", "unknown"),
                "body_preview": resp.text[:500]
            }
    except Exception as e:
        return {
            "status": "error",
            "target": target_url,
            "message": f"SSRF Request attempt failed: {str(e)}"
        }

@router.post("/transfer-points")
async def transfer_points(req: Request, transfer: PointTransfer):
    """
    Vulnerable Endpoint 4: Cross-Site Request Forgery (CSRF) (OWASP Top 10 - A01:2021)
    Performs state-changing point transfer without validating anti-CSRF token
    or checking origin/referer headers against cross-site requests.
    """
    conn = get_db()
    cursor = conn.cursor()
    
    # State-changing transaction executed blindly
    cursor.execute("UPDATE users SET points = points - ? WHERE id = 1", (transfer.amount,))
    cursor.execute("UPDATE users SET points = points + ? WHERE username = ?", (transfer.amount, transfer.recipient_username))
    conn.commit()
    
    return {
        "status": "success",
        "message": f"Transferred {transfer.amount} loyalty points to {transfer.recipient_username}.",
        "csrf_protected": False,
        "sender_id": 1,
        "recipient": transfer.recipient_username,
        "amount": transfer.amount
    }

@router.get("/orders/{order_id}")
async def get_order(order_id: int):
    """
    Vulnerable Endpoint 5: Insecure Direct Object References (IDOR) (OWASP Top 10 - A01:2021)
    Returns order and customer PII directly based on user-supplied URL ID
    without verifying session ownership or tenant authorization.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    row = cursor.fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail="Order not found")
        
    order = dict(row)
    return {
        "status": "success",
        "order": order,
        "tenant_auth_verified": False,
        "pii_warning": "Sensitive shipping address & payment details returned without ownership check."
    }

@router.post("/reset")
async def reset_store_data():
    """Resets the CyberMart testbed database to initial seed state."""
    reset_db()
    return {"status": "success", "message": "CyberMart e-commerce database reset to factory seed state."}
