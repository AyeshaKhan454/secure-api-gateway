from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import engine, get_db, Base
from app import models, schemas
from app.auth import hash_password, verify_password, create_access_token
from app.routers import notes, admin
from app.middleware.threat_detector import ThreatDetectionMiddleware

# Create all tables automatically on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure API Gateway", version="1.0.0")

# Register middleware
app.add_middleware(ThreatDetectionMiddleware)

# Register routers
app.include_router(notes.router)
app.include_router(admin.router)

@app.post("/auth/register", tags=["Auth"])
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Register a new user."""
    existing = db.query(models.User).filter(
        models.User.username == user.username
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")
    new_user = models.User(
        username=user.username,
        hashed_password=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/auth/login", response_model=schemas.Token, tags=["Auth"])
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    """Login and receive a JWT token."""
    db_user = db.query(models.User).filter(
        models.User.username == user.username
    ).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(data={"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/", tags=["Health"])
def root():
    return {"status": "Secure API Gateway is running"}