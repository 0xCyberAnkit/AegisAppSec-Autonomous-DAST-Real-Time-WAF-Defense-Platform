from fastapi import APIRouter, HTTPException, Depends, Response
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
import datetime

from app.core.auth import get_current_user_optional, create_access_token
from app.db import models

router = APIRouter(prefix="/api/team", tags=["Enterprise Team & RBAC"])

# In-memory team store with pre-seeded demo members, backed by database users if logged in
DEFAULT_TEAM_MEMBERS = [
    {
        "id": 1,
        "name": "Alex Mercer",
        "email": "admin@aegisappsec.io",
        "role": "admin",
        "role_title": "Enterprise CISO / SecOps Lead",
        "two_factor": True,
        "status": "ACTIVE",
        "joined_date": "2025-11-12",
        "last_active": "Just now"
    },
    {
        "id": 2,
        "name": "Sarah Chen",
        "email": "pentester@aegisappsec.io",
        "role": "pentester",
        "role_title": "Lead Offensive Security / Red Team",
        "two_factor": True,
        "status": "ACTIVE",
        "joined_date": "2026-01-08",
        "last_active": "15 minutes ago"
    },
    {
        "id": 3,
        "name": "David Patel",
        "email": "dev@aegisappsec.io",
        "role": "developer",
        "role_title": "Principal Application Engineer",
        "two_factor": False,
        "status": "ACTIVE",
        "joined_date": "2026-02-19",
        "last_active": "2 hours ago"
    },
    {
        "id": 4,
        "name": "Elena Rostova",
        "email": "elena.rostova@aegisappsec.io",
        "role": "pentester",
        "role_title": "External Bug Bounty / Security Auditor",
        "two_factor": True,
        "status": "ACTIVE",
        "joined_date": "2026-03-01",
        "last_active": "1 day ago"
    }
]

_team_members = list(DEFAULT_TEAM_MEMBERS)

class MemberInviteRequest(BaseModel):
    name: str
    email: str
    role: str # admin, pentester, developer
    company: Optional[str] = "CyberMart Enterprise Defense Corp"
    two_factor: Optional[bool] = False

class MemberRoleUpdateRequest(BaseModel):
    role: str # admin, pentester, developer

class MemberStatusUpdateRequest(BaseModel):
    status: str # ACTIVE, SUSPENDED

@router.get("/organization")
async def get_team_organization():
    """Returns corporate tenant metadata, seat licensing quotas, and SSO status."""
    return {
        "status": "success",
        "organization": {
            "name": "CyberMart Enterprise Defense Corp",
            "tenant_id": "AEGIS-ORG-2026-9042",
            "plan_name": "Enterprise Shield (Multi-Seat)",
            "tier": "ENTERPRISE",
            "seats_total": 10,
            "seats_assigned": len(_team_members),
            "seats_available": max(0, 10 - len(_team_members)),
            "sso_enforced": True,
            "sso_provider": "Okta SAML 2.0 (okta.aegisappsec.io)",
            "created_at": "2025-11-12",
            "mfa_policy": "STRICT_HARDWARE_OR_TOTP",
            "compliance_status": "SOC 2 Type II // ISO 27001 Compliant"
        }
    }

@router.get("/members")
async def get_team_members(current_user: Optional[models.User] = Depends(get_current_user_optional)):
    """Returns all active enterprise team members and external security collaborators."""
    return {
        "status": "success",
        "count": len(_team_members),
        "members": _team_members
    }

@router.post("/members")
async def invite_team_member(payload: MemberInviteRequest, current_user: Optional[models.User] = Depends(get_current_user_optional)):
    """Invites a new colleague or external pentester with designated RBAC permissions."""
    role_titles = {
        "admin": "Enterprise SecOps Admin",
        "pentester": "Offensive Security / Pentester",
        "developer": "AppSec Software Engineer"
    }
    
    # Check duplicate
    for m in _team_members:
        if m["email"].lower() == payload.email.lower():
            raise HTTPException(status_code=400, detail=f"User with email '{payload.email}' is already in the organization.")
            
    new_id = max([m["id"] for m in _team_members] or [0]) + 1
    new_member = {
        "id": new_id,
        "name": payload.name,
        "email": payload.email,
        "role": payload.role if payload.role in ("admin", "pentester", "developer") else "developer",
        "role_title": role_titles.get(payload.role, "Security Analyst"),
        "two_factor": bool(payload.two_factor),
        "status": "INVITED",
        "joined_date": datetime.date.today().isoformat(),
        "last_active": "Invitation Pending"
    }
    _team_members.append(new_member)
    return {"status": "success", "message": f"Invitation dispatched to {payload.email}", "member": new_member}

@router.put("/members/{member_id}/role")
async def update_member_role(member_id: int, payload: MemberRoleUpdateRequest):
    """Updates a team member's operational role and capability level."""
    role_titles = {
        "admin": "Enterprise SecOps Admin",
        "pentester": "Offensive Security / Pentester",
        "developer": "AppSec Software Engineer"
    }
    if payload.role not in role_titles:
        raise HTTPException(status_code=400, detail="Invalid role specified.")
    for m in _team_members:
        if m["id"] == member_id:
            m["role"] = payload.role
            m["role_title"] = role_titles.get(payload.role, "Security Analyst")
            return {"status": "success", "message": f"Updated role to {payload.role}", "member": m}
    raise HTTPException(status_code=404, detail=f"Member ID {member_id} not found.")

@router.put("/members/{member_id}/status")
async def update_member_status(member_id: int, payload: MemberStatusUpdateRequest):
    """Toggles member operational access between ACTIVE and SUSPENDED."""
    valid_statuses = ("ACTIVE", "SUSPENDED", "INVITED")
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail="Invalid status specified.")
    for m in _team_members:
        if m["id"] == member_id:
            m["status"] = payload.status
            return {"status": "success", "message": f"Member #{member_id} status updated to {payload.status}", "member": m}
    raise HTTPException(status_code=404, detail=f"Member ID {member_id} not found.")

@router.put("/members/{member_id}/2fa")
async def toggle_member_2fa(member_id: int):
    """Toggles 2FA security enforcement for a team member."""
    for m in _team_members:
        if m["id"] == member_id:
            m["two_factor"] = not m.get("two_factor", False)
            status_txt = "Enforced" if m["two_factor"] else "Optional"
            return {"status": "success", "message": f"2FA policy for Member #{member_id} set to {status_txt}", "two_factor": m["two_factor"], "member": m}
    raise HTTPException(status_code=404, detail=f"Member ID {member_id} not found.")

@router.delete("/members/{member_id}")
async def remove_team_member(member_id: int, current_user: Optional[models.User] = Depends(get_current_user_optional)):
    """Revokes access and removes a team member from the enterprise workspace."""
    global _team_members
    before_len = len(_team_members)
    _team_members = [m for m in _team_members if m["id"] != member_id]
    if len(_team_members) == before_len:
        raise HTTPException(status_code=404, detail=f"Member ID {member_id} not found.")
    return {"status": "success", "message": f"Member #{member_id} revoked successfully."}

@router.post("/switch-admin")
async def switch_to_admin(response: Response):
    """Convenience endpoint allowing operator to elevate session to Company Admin (Alex Mercer)."""
    token = create_access_token({"sub": "1", "email": "admin@aegisappsec.io", "role": "admin"})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=86400,
        path="/",
        samesite="lax",
        secure=False
    )
    return {
        "status": "success",
        "message": "Switched to Company Admin session (admin@aegisappsec.io)",
        "user": {
            "email": "admin@aegisappsec.io",
            "role": "admin",
            "full_name": "Alex Mercer (Enterprise SecOps Lead)"
        }
    }

@router.post("/switch-operator")
async def switch_to_operator(response: Response):
    """Convenience endpoint allowing switching back to Pentester operator view (Sarah Chen)."""
    token = create_access_token({"sub": "2", "email": "pentester@aegisappsec.io", "role": "pentester"})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=86400,
        path="/",
        samesite="lax",
        secure=False
    )
    return {
        "status": "success",
        "message": "Switched to Pentester operator session (pentester@aegisappsec.io)",
        "user": {
            "email": "pentester@aegisappsec.io",
            "role": "pentester",
            "full_name": "Sarah Chen (Offensive Red Team)"
        }
    }

@router.get("/roles")
async def get_rbac_matrix():
    """Returns the enterprise Role-Based Access Control (RBAC) permission matrix."""
    return {
        "roles": [
            {
                "id": "admin",
                "name": "Enterprise SecOps Admin",
                "description": "Full administrative control, domain validation, billing, and API key management.",
                "badge_color": "var(--neon-red)",
                "permissions": {
                    "domain_verification": True,
                    "launch_dast_scans": True,
                    "manual_payload_injection": True,
                    "waf_mode_toggle": True,
                    "custom_virtual_patches": True,
                    "manage_team": True,
                    "api_key_management": True,
                    "export_executive_reports": True
                }
            },
            {
                "id": "pentester",
                "name": "Offensive Security / Pentester",
                "description": "Hands-on vulnerability testing, cURL PoC verification, and CVSS score calibration.",
                "badge_color": "var(--neon-cyan)",
                "permissions": {
                    "domain_verification": False,
                    "launch_dast_scans": True,
                    "manual_payload_injection": True,
                    "waf_mode_toggle": True,
                    "custom_virtual_patches": True,
                    "manage_team": False,
                    "api_key_management": False,
                    "export_executive_reports": True
                }
            },
            {
                "id": "developer",
                "name": "AppSec Software Engineer",
                "description": "Remediation-focused role with access to vulnerability details and secure code recipes.",
                "badge_color": "var(--neon-green)",
                "permissions": {
                    "domain_verification": False,
                    "launch_dast_scans": False,
                    "manual_payload_injection": False,
                    "waf_mode_toggle": False,
                    "custom_virtual_patches": False,
                    "manage_team": False,
                    "api_key_management": False,
                    "export_executive_reports": True
                }
            }
        ]
    }
