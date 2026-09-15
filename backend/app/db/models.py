import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.db.session import Base

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), default="pentester") # admin, pentester, developer
    company = Column(String(255), default="Independent")
    created_at = Column(DateTime, default=utcnow)

    targets = relationship("Target", back_populates="owner", cascade="all, delete-orphan")
    scans = relationship("ScanRun", back_populates="user")
    api_keys = relationship("ApiKeyRecord", back_populates="owner", cascade="all, delete-orphan")
    webhooks = relationship("WebhookRecord", back_populates="owner", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    base_url = Column(String(1024), nullable=False)
    verification_method = Column(String(50), default="HTTP_WELL_KNOWN") # HTTP_WELL_KNOWN, DNS_TXT, HTML_META
    verification_token = Column(String(128), nullable=False)
    is_verified = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    owner = relationship("User", back_populates="targets")
    scans = relationship("ScanRun", back_populates="target", cascade="all, delete-orphan")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(String(64), primary_key=True, index=True) # e.g. SCAN-1789376309-49D7
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    status = Column(String(50), default="PENDING") # PENDING, RUNNING, COMPLETED, FAILED
    triggered_by = Column(String(100), default="Manual UI") # Manual UI, CI/CD Pipeline, Scheduled
    target_url = Column(String(1024), nullable=False)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    avg_cvss = Column(Float, default=0.0)
    duration_seconds = Column(Float, default=0.0)
    started_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)

    target = relationship("Target", back_populates="scans")
    user = relationship("User", back_populates="scans")
    findings = relationship("FindingRecord", back_populates="scan", cascade="all, delete-orphan")


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), ForeignKey("scan_runs.id"), nullable=False)
    target_id = Column(Integer, nullable=True)
    vuln_type = Column(String(100), nullable=False) # sqli, xss, ssrf, csrf, idor
    severity = Column(String(50), nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    title = Column(String(512), nullable=False)
    cwe_id = Column(String(50), nullable=False)
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(255), nullable=True)
    endpoint = Column(String(1024), nullable=False)
    parameter = Column(String(255), nullable=True)
    poc_curl = Column(Text, nullable=True)
    status = Column(String(50), default="OPEN") # OPEN, RESOLVED, FALSE_POSITIVE
    created_at = Column(DateTime, default=utcnow)

    scan = relationship("ScanRun", back_populates="findings")


class ApiKeyRecord(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    name = Column(String(255), nullable=False)
    key_prefix = Column(String(16), nullable=False) # e.g. aegis_live_ab12
    key_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="ci_cd_runner")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    last_used_at = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="api_keys")


class WebhookRecord(Base):
    __tablename__ = "webhooks"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    name = Column(String(255), nullable=False)
    url = Column(String(1024), nullable=False)
    event_types = Column(String(255), default="scan_completed,vulnerability_critical")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

    owner = relationship("User", back_populates="webhooks")


class WafCustomRule(Base):
    __tablename__ = "waf_custom_rules"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    name = Column(String(255), nullable=False)
    pattern = Column(String(1024), nullable=False) # Regex pattern
    action = Column(String(50), default="BLOCK") # BLOCK, DETECT, SANITIZE
    description = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
