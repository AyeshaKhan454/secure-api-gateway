from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app import models
from app.auth import get_current_user

router = APIRouter(prefix="/admin", tags=["Admin"])

ADMIN_USERNAME = "admin"

@router.get("/threat-report")
def get_threat_report(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Admin-only: Returns Top 3 most malicious IP addresses
    based on blocked request count.
    """
    if current_user.username != ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Access forbidden")

    results = (
        db.query(
            models.SecurityLog.ip_address,
            func.count(models.SecurityLog.id).label("attack_count")
        )
        .group_by(models.SecurityLog.ip_address)
        .order_by(func.count(models.SecurityLog.id).desc())
        .limit(3)
        .all()
    )

    return {
        "top_malicious_ips": [
            {"ip": r.ip_address, "blocked_requests": r.attack_count}
            for r in results
        ]
    }