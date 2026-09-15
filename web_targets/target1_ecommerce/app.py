"""
VoltMart Electronics & Gadgets - E-Commerce Target
Port: 8001
Vulnerabilities Demonstrated:
- SQL Injection (SQLi / CWE-89) in /search
- Stored / Reflected Cross-Site Scripting (XSS / CWE-79) in /reviews
- Cross-Site Request Forgery (CSRF / CWE-352) in /account/email
- Insecure Direct Object Reference (IDOR / CWE-639) in /api/orders/{id}
"""

import sqlite3
import os
from pathlib import Path
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="VoltMart Electronics Store (Target 1)", version="1.4.2")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Initialize in-memory / local SQLite DB
DB_FILE = str(BASE_DIR / "voltmart.db")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL,
            description TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            author TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            customer_name TEXT NOT NULL,
            customer_email TEXT NOT NULL,
            total_amount REAL NOT NULL,
            shipping_address TEXT NOT NULL,
            status TEXT DEFAULT 'Processing'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            username TEXT NOT NULL
        )
    """)
    
    # Pre-seed if empty
    c.execute("SELECT COUNT(*) FROM products")
    if c.fetchone()[0] == 0:
        c.executemany("""
            INSERT INTO products (name, category, price, stock, description)
            VALUES (?, ?, ?, ?, ?)
        """, [
            ("CyberDeck Alpha X-1", "Laptops", 1899.99, 14, "Next-gen dual-display offensive security rig."),
            ("NeuralJack USB Interceptor", "Hardware", 149.50, 45, "Hardware packet tap with active bypass."),
            ("QuantumCrypt Hardware Key", "Security", 89.00, 120, "FIDO2 Level 3 Hardware token."),
            ("Spectre Stealth Backpack", "Accessories", 129.99, 30, "EMP and RFID shielded field pack.")
        ])
        c.executemany("""
            INSERT INTO reviews (product_id, author, comment)
            VALUES (?, ?, ?)
        """, [
            (1, "Alice Security", "Insane performance, battery lasts all day during field ops."),
            (2, "Bob Pentester", "Flawless packet sniffing capabilities on gigabit lines.")
        ])
        c.executemany("""
            INSERT INTO orders (user_id, customer_name, customer_email, total_amount, shipping_address, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, [
            (101, "Marcus Vance", "marcus.vance@corpsec.io", 2049.49, "742 Evergreen Terrace, Sector 4", "Shipped"),
            (102, "Sarah Connor", "sarah@cyberdyne.net", 89.00, "1049 Bunker Hill Rd, Tech Zone", "Delivered"),
            (103, "Dr. Elliot Alderson", "elliot@fsociety.org", 3799.98, "217 E Broadway, NY", "Processing")
        ])
        c.execute("INSERT INTO accounts (id, email, username) VALUES (1, 'victim.user@voltmart.io', 'vuser1')")
        conn.commit()
    conn.close()

init_db()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, name, category, price, stock, description FROM products")
    products = [{"id": r[0], "name": r[1], "category": r[2], "price": r[3], "stock": r[4], "desc": r[5]} for r in c.fetchall()]
    c.execute("SELECT author, comment, created_at FROM reviews ORDER BY id DESC LIMIT 5")
    reviews = [{"author": r[0], "comment": r[1], "time": r[2]} for r in c.fetchall()]
    c.execute("SELECT email, username FROM accounts WHERE id = 1")
    acc = c.fetchone()
    conn.close()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "products": products,
            "reviews": reviews,
            "account": {"email": acc[0] if acc else "user@voltmart.io", "username": acc[1] if acc else "user"}
        }
    )

# 1. SQL Injection (SQLi / CWE-89)
@app.get("/search")
async def search_products(q: str = ""):
    """Vulnerable Search endpoint: raw string concatenation into SQL query."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        # VULNERABILITY: Raw SQL string formatting allows SQL injection
        query = f"SELECT id, name, category, price, stock FROM products WHERE name LIKE '%{q}%' OR category LIKE '%{q}%'"
        c.execute(query)
        rows = c.fetchall()
        products = [{"id": r[0], "name": r[1], "category": r[2], "price": r[3], "stock": r[4]} for r in rows]
        conn.close()
        return {"status": "success", "count": len(products), "query": q, "data": products}
    except Exception as e:
        conn.close()
        # VULNERABILITY: Leaking raw database exception messages
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e), "executed_sql": query})

# 2. Stored / Reflected XSS (CWE-79)
@app.post("/reviews")
async def add_review(author: str = Form(...), comment: str = Form(...), product_id: int = Form(1)):
    """Vulnerable Review submission: unescaped payload stored and reflected."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # VULNERABILITY: Stores raw unescaped input
    c.execute("INSERT INTO reviews (product_id, author, comment) VALUES (?, ?, ?)", (product_id, author, comment))
    conn.commit()
    conn.close()
    # Return HTML embedding unescaped user string
    return HTMLResponse(content=f"""
        <div class="review-item alert alert-success" style="border-left: 3px solid #00f0ff; padding: 10px; margin-top: 10px;">
            <strong>Review posted by {author}:</strong>
            <p>{comment}</p>
            <a href="/" style="color: #00f0ff;">&larr; Back to VoltMart</a>
        </div>
    """)

@app.get("/reviews")
async def get_reviews(author: str = ""):
    """Reflected XSS via author query parameter."""
    if author:
        # VULNERABILITY: Reflected verbatim in response
        return HTMLResponse(content=f"<h3>Filtering reviews by author: {author}</h3><p>No matching author profile found.</p>")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, author, comment FROM reviews")
    revs = [{"id": r[0], "author": r[1], "comment": r[2]} for r in c.fetchall()]
    conn.close()
    return {"reviews": revs}

# 3. Cross-Site Request Forgery (CSRF / CWE-352)
@app.post("/account/email")
@app.get("/account/email")
async def update_email(email: str = Form(None), new_email: str = None):
    """Vulnerable Email update: changes state on GET/POST without Anti-CSRF token."""
    target_email = email or new_email or "updated.user@voltmart.io"
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE accounts SET email = ? WHERE id = 1", (target_email,))
    conn.commit()
    conn.close()
    return JSONResponse(content={
        "status": "success",
        "message": f"Account email updated to: {target_email}",
        "vulnerability_note": "CWE-352: State change executed without Anti-CSRF token or SameSite validation."
    })

# 4. Insecure Direct Object Reference (IDOR / CWE-639)
@app.get("/api/orders/{order_id}")
async def get_order(order_id: int):
    """Vulnerable Order retrieval: returns any customer order without tenant authorization."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, user_id, customer_name, customer_email, total_amount, shipping_address, status FROM orders WHERE id = ?", (order_id,))
    order = c.fetchone()
    conn.close()
    if not order:
        return JSONResponse(status_code=404, content={"status": "error", "message": f"Order #{order_id} not found."})
    return {
        "status": "success",
        "order_id": order[0],
        "user_id": order[1],
        "customer_name": order[2],
        "customer_email": order[3],
        "total_amount": order[4],
        "shipping_address": order[5],
        "order_status": order[6],
        "vulnerability_note": "CWE-639 IDOR: Unrestricted access to private PII & shipping data."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8001, reload=True)
