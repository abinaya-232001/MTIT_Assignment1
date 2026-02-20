from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordRequestForm

from app.database import get_db
from app.models import User, RefreshToken
from app.schemas import UserCreate, Token, TokenRefresh, UserResponse
from app.core.security import (
    hash_password, verify_password, create_access_token,
    create_refresh_token, decode_token, hash_token
)
from app.core.utils import validate_password
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.post("/register", response_model=Token)
def register(data: UserCreate, db: Session = Depends(get_db)):
    """Create a new user account and return tokens.

    - password is validated for complexity requirements.
    - username and email are checked for uniqueness.
    - the password is hashed before insertion.
    - an access token and a refresh token are generated; the refresh
      token is hashed and stored in the database along with its JTI and
      expiry date.

    These steps ensure that plaintext passwords and tokens are never
    persisted, helping make the system suitable for production use.
    """

    validate_password(data.password)

    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password)
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    access = create_access_token(user.id, user.role)
    refresh, jti, exp = create_refresh_token(user.id)

    db.add(RefreshToken(
        token_hash=hash_token(refresh),
        jti=jti,
        user_id=user.id,
        expires_at=exp
    ))
    db.commit()

    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


@router.post("/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(),
          db: Session = Depends(get_db)):
    """Authenticate existing user and issue fresh tokens.

    - rate limit: counts failed attempts and locks account when the
      threshold is exceeded.  The lock expires after
      ``ACCOUNT_LOCK_MINUTES``.
    - successful login resets the counter and lock.
    - refresh token created and stored as with registration.
    """

    user = db.query(User).filter(User.username == form.username).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.lock_until and user.lock_until > datetime.utcnow():
        raise HTTPException(status_code=403, detail="Account temporarily locked")

    if not verify_password(form.password, user.hashed_password):
        user.failed_attempts += 1
        if user.failed_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            user.lock_until = datetime.utcnow() + timedelta(minutes=settings.ACCOUNT_LOCK_MINUTES)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.failed_attempts = 0
    user.lock_until = None
    db.commit()

    access = create_access_token(user.id, user.role)
    refresh, jti, exp = create_refresh_token(user.id)

    db.add(RefreshToken(
        token_hash=hash_token(refresh),
        jti=jti,
        user_id=user.id,
        expires_at=exp
    ))
    db.commit()

    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


@router.post("/refresh", response_model=Token)
def refresh_token(data: TokenRefresh, db: Session = Depends(get_db)):

    payload = decode_token(data.refresh_token, refresh=True)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    stored = db.query(RefreshToken).filter(
        RefreshToken.token_hash == hash_token(data.refresh_token)
    ).first()

    if not stored or stored.revoked:
        raise HTTPException(status_code=401, detail="Refresh token reuse detected")
    if stored.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")

    stored.revoked = True
    db.commit()

    access = create_access_token(stored.user_id, stored.user.role)
    new_refresh, jti, exp = create_refresh_token(stored.user_id)

    db.add(RefreshToken(
        token_hash=hash_token(new_refresh),
        jti=jti,
        user_id=stored.user_id,
        expires_at=exp
    ))
    db.commit()

    return {"access_token": access, "refresh_token": new_refresh, "token_type": "bearer"}