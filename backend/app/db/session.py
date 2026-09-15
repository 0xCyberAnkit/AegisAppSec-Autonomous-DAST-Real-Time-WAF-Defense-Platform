import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Database URL resolution: Defaults to MySQL in Docker, falls back to SQLite locally
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./aegis_enterprise.db"
)

# Connect args (needed for SQLite multi-thread)
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """FastAPI dependency yielding a SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes schema and pre-seeds default roles & demo accounts."""
    from app.db import models
    Base.metadata.create_all(bind=engine)
    
    # Pre-seed initial accounts if not exists
    db = SessionLocal()
    try:
        from app.core.auth import get_password_hash
        admin_user = db.query(models.User).filter_by(email="admin@aegisappsec.io").first()
        if not admin_user:
            admin_user = models.User(
                email="admin@aegisappsec.io",
                hashed_password=get_password_hash("Admin@Aegis2026!"),
                full_name="Alex Mercer (Enterprise SecOps Lead)",
                role="admin",
                company="CyberMart Holdings",
            )
            db.add(admin_user)
            
            pentester_user = models.User(
                email="pentester@aegisappsec.io",
                hashed_password=get_password_hash("Pentester@2026!"),
                full_name="Sarah Chen (Offensive Red Team)",
                role="pentester",
                company="RedTeam Autonomous Labs",
            )
            db.add(pentester_user)

            dev_user = models.User(
                email="dev@aegisappsec.io",
                hashed_password=get_password_hash("DevAppSec@2026!"),
                full_name="David Patel (Lead Backend Engineer)",
                role="developer",
                company="CyberMart E-Commerce Dev",
            )
            db.add(dev_user)

            # Pre-seed verified target for testbed
            target = models.Target(
                name="CyberMart E-Commerce (Testbed)",
                domain="127.0.0.1:8000",
                base_url="http://127.0.0.1:8000/api/shop",
                verification_method="HTTP_WELL_KNOWN",
                verification_token="aegis-verify-prod-seed-8899",
                is_verified=True,
                user_id=1,
            )
            db.add(target)

            # Pre-seed pending target for domain verification demonstrations
            target_pending = models.Target(
                name="Acme FinTech Cloud API",
                domain="api.acmefin.corp",
                base_url="https://api.acmefin.corp/v2",
                verification_method="DNS_TXT",
                verification_token="aegis-verify-token-acme-8812",
                is_verified=False,
                user_id=1,
            )
            db.add(target_pending)
            db.commit()
    except Exception as e:
        db.rollback()
        print(f"[Aegis DB] Notice during seed: {e}")
    finally:
        db.close()
