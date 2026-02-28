from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class User(Base):
    """Represents a registered user in the system."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    notes = relationship("Note", back_populates="owner")

class Note(Base):
    """Represents a secure note belonging to a user."""
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    content = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="notes")

class SecurityLog(Base):
    """Logs every blocked malicious request."""
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), nullable=False, index=True)
    threat_type = Column(String(50), nullable=False)
    request_path = Column(String(255))
    blocked_payload = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)