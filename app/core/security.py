from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from uuid import uuid4
import hashlib

from app.config import settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)

def hash_token(token: str):
    return hashlib.sha256(token.encode()).hexdigest()

def create_access_token(user_id: int, role: str):
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire,
        "type": "access",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(user_id: int):
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    jti = str(uuid4())
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "exp": expire,
        "type": "refresh",
    }
    token = jwt.encode(payload, settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)
    return token, jti, expire

def decode_token(token: str, refresh: bool = False):
    try:
        secret = settings.REFRESH_SECRET_KEY if refresh else settings.SECRET_KEY
        return jwt.decode(token, secret, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None