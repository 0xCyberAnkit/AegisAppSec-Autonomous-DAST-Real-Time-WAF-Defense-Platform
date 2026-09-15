import sqlite3
import threading

_lock = threading.Lock()
_connection = None

def get_db():
    global _connection
    with _lock:
        if _connection is None:
            _connection = sqlite3.connect(":memory:", check_same_thread=False)
            _connection.row_factory = sqlite3.Row
            _init_schema_and_seeds(_connection)
        return _connection

def _init_schema_and_seeds(conn: sqlite3.Connection):
    cursor = conn.cursor()
    
    # Products table
    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            discount_price REAL NOT NULL,
            stock INTEGER NOT NULL,
            description TEXT NOT NULL,
            rating REAL DEFAULT 4.8
        )
    """)
    
    # Reviews table (vulnerable to XSS)
    cursor.execute("""
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            author TEXT NOT NULL,
            comment TEXT NOT NULL,
            rating INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Orders table (vulnerable to IDOR)
    cursor.execute("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            total_amount REAL NOT NULL,
            status TEXT NOT NULL,
            shipping_address TEXT NOT NULL,
            card_last4 TEXT NOT NULL
        )
    """)
    
    # Users table (stores sensitive data, vulnerable to SQLi exfiltration)
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            points INTEGER DEFAULT 500,
            role TEXT DEFAULT 'customer',
            secret_api_token TEXT NOT NULL
        )
    """)
    
    # Seed Products
    products = [
        (1, "AeroBlade Pro Max Gaming Laptop", "Electronics", 2199.99, 1599.99, 45, "High-octane 240Hz RTX 4090 gaming beast.", 4.9),
        (2, "Quantum OLED 4K 65-inch Smart TV", "Home Entertainment", 1499.00, 999.00, 20, "Infinite contrast with 120Hz refresh.", 4.8),
        (3, "EchoWave Active Noise-Canceling Headphones", "Audio", 349.99, 199.99, 110, "Hi-Res studio acoustics with 40-hour battery life.", 4.7),
        (4, "CyberShield Hardened Titanium Phone 15", "Mobile", 1199.00, 899.00, 30, "Hardware encryption with zero-trust biometric enclave.", 4.9),
        (5, "PulseDrive 4TB NVMe Gen5 SSD", "Storage", 399.99, 249.99, 85, "14,000 MB/s read transfer rates for extreme loads.", 4.9),
    ]
    cursor.executemany("INSERT INTO products VALUES (?, ?, ?, ?, ?, ?, ?, ?)", products)
    
    # Seed Users
    users = [
        (1, "alice_shopper", "alice@enterprise-blackfriday.com", "pbkdf2_sha256$260000$h4sh123", 1250, "customer", "tok_live_sec_991823a"),
        (2, "bob_supplier", "bob@supplychain-logistics.io", "pbkdf2_sha256$260000$h4sh456", 3400, "supplier", "tok_live_sec_884712b"),
        (3, "admin_blackfriday", "secops@cybermart-internal.net", "pbkdf2_sha256$260000$superadmin_secret", 99999, "administrator", "tok_live_admin_root_master_001"),
    ]
    cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)", users)
    
    # Seed Reviews
    reviews = [
        (1, 1, "DevSecOps Dave", "Incredible performance, compiles our security microservices in seconds!", 5),
        (2, 2, "Sarah C.", "The Black Friday discount is insane! Great picture quality.", 5),
        (3, 3, "Marcus B.", "Decent audio, but wireless range is slightly lower than expected.", 4),
    ]
    cursor.executemany("INSERT INTO reviews (id, product_id, author, comment, rating) VALUES (?, ?, ?, ?, ?)", reviews)
    
    # Seed Orders
    orders = [
        (1, 1, "AeroBlade Pro Max Gaming Laptop", 1599.99, "Delivered", "742 Evergreen Terrace, Sector 7", "4242"),
        (2, 2, "Quantum OLED 4K 65-inch Smart TV", 999.00, "In Transit", "100 Broadway Ave, Suite 400", "9812"),
        (3, 3, "CyberShield Hardened Titanium Phone 15", 899.00, "Processing", "55 Defense Road, Federal Compound", "1104"),
    ]
    cursor.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?, ?)", orders)
    
    conn.commit()

def reset_db():
    global _connection
    with _lock:
        if _connection is not None:
            _connection.close()
            _connection = None
        get_db()
