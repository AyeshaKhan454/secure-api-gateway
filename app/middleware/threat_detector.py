import re
import time
from collections import defaultdict
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app import models

# --- Threat Patterns ----------------------------------------------
SQLI_PATTERNS = [
    r"(\bOR\b\s+\d+=\d+)",        # OR 1=1
    r"(;\s*DROP\s+TABLE)",         # ; DROP TABLE
    r"(;\s*DELETE\s+FROM)",        # ; DELETE FROM
    r"(UNION\s+SELECT)",           # UNION SELECT
    r"(--\s*$)",                   # SQL comment
]

XSS_PATTERNS = [
    r"<script.*?>",                # <script> tags
    r"onerror\s*=",                # onerror= events
    r"javascript:",                # javascript: URLs
    r"<iframe.*?>",                # iframe injection
]

# --- Rate Limiter ---------------------------------------------------
request_counts = defaultdict(list)
RATE_LIMIT = 10
WINDOW = 60

def is_rate_limited(ip: str) -> bool:
    """Return True if the IP has exceeded the rate limit."""
    now = time.time()
    request_counts[ip] = [t for t in request_counts[ip] if now - t < WINDOW]
    if len(request_counts[ip]) >= RATE_LIMIT:
        return True
    request_counts[ip].append(now)
    return False

def scan_for_threats(text: str) -> str | None:
    """
    Scan a string for SQLi or XSS patterns.
    Returns the threat type if found, else None.
    """
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return "SQL_INJECTION"
    for pattern in XSS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return "XSS_ATTACK"
    return None

def log_threat(ip: str, threat_type: str, path: str, payload: str):
    """Save a blocked threat to the database."""
    db: Session = SessionLocal()
    try:
        log_entry = models.SecurityLog(
            ip_address=ip,
            threat_type=threat_type,
            request_path=path,
            blocked_payload=payload[:500],
        )
        db.add(log_entry)
        db.commit()
    finally:
        db.close()

class ThreatDetectionMiddleware(BaseHTTPMiddleware):
    """Middleware that blocks SQLi, XSS, and rate-limit violations."""

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host

        # 1. Rate limiting check
        if is_rate_limited(ip):
            log_threat(ip, "RATE_LIMIT", str(request.url.path), "Too many requests")
            return Response(content="Too many requests", status_code=429)

        # 2. Scan query parameters
        for key, value in request.query_params.items():
            threat = scan_for_threats(value)
            if threat:
                log_threat(ip, threat, str(request.url.path), value)
                return Response(content="Internal Server Error", status_code=400)

        # 3. Scan request body
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body_bytes = await request.body()
                body_text = body_bytes.decode("utf-8", errors="ignore")
                threat = scan_for_threats(body_text)
                if threat:
                    log_threat(ip, threat, str(request.url.path), body_text)
                    return Response(content="Internal Server Error", status_code=400)
            except Exception:
                pass

        return await call_next(request)