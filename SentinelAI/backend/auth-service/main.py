"""
SentinelAI — Auth Service
JWT Authentication + MFA (TOTP) + RBAC
"""
import os
import secrets
import base64
import io
from datetime import datetime, timedelta, timezone
from typing import Optional, List

import pyotp
import qrcode
import asyncpg
import aioredis
from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt
from loguru import logger

# ─── Config ──────────────────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "CHANGE_ME")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_TOKEN_EXPIRE = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7))
def normalize_asyncpg_dsn(dsn: Optional[str]) -> str:
    if not dsn:
        raise RuntimeError("DATABASE_URL is not configured")
    if dsn.startswith("postgresql+asyncpg://"):
        return "postgresql://" + dsn.removeprefix("postgresql+asyncpg://")
    return dsn

DATABASE_URL = normalize_asyncpg_dsn(os.getenv("DATABASE_URL"))
REDIS_URL = os.getenv("REDIS_URL")
MFA_ISSUER = os.getenv("MFA_ISSUER", "SentinelAI")

# ─── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SentinelAI Auth Service",
    version="1.0.0",
    description="JWT + MFA + RBAC authentication for SentinelAI platform",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

# ─── Roles ───────────────────────────────────────────────────────────────────
ROLES = {
    "admin":    ["read", "write", "delete", "manage_users", "view_reports", "soar_execute"],
    "analyst":  ["read", "write", "view_reports"],
    "viewer":   ["read"],
    "soar_bot": ["soar_execute", "read"],
}

# ─── Models ──────────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "analyst"
    full_name: str

class UserLogin(BaseModel):
    username: str
    password: str
    mfa_token: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

class MFASetupResponse(BaseModel):
    secret: str
    qr_code_base64: str
    provisioning_uri: str

class RefreshRequest(BaseModel):
    refresh_token: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class APIKeyCreate(BaseModel):
    name: str
    permissions: List[str]
    expires_days: int = 365

# ─── Helpers ─────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE)
    payload["iat"] = datetime.now(timezone.utc)
    payload["type"] = "access"
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_refresh_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE)
    payload["iat"] = datetime.now(timezone.utc)
    payload["type"] = "refresh"
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def verify_totp(secret: str, token: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)

def get_qr_code_base64(secret: str, username: str) -> str:
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=MFA_ISSUER)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

# ─── DB Helpers ──────────────────────────────────────────────────────────────
async def get_db():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        await conn.close()

async def get_redis():
    redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        yield redis
    finally:
        await redis.close()

async def get_user_by_username(conn, username: str) -> Optional[dict]:
    row = await conn.fetchrow(
        "SELECT * FROM users WHERE username = $1 AND is_active = true", username
    )
    return dict(row) if row else None

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    return payload

def require_permission(permission: str):
    async def checker(user=Depends(get_current_user)):
        role = user.get("role", "viewer")
        perms = ROLES.get(role, [])
        if permission not in perms:
            raise HTTPException(status_code=403, detail=f"Permission '{permission}' required")
        return user
    return checker

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "auth-service", "version": "1.0.0"}

@app.post("/auth/register", response_model=dict)
async def register(user: UserCreate):
    """Register a new analyst/user account (admin only in production)."""
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        existing = await get_user_by_username(conn, user.username)
        if existing:
            raise HTTPException(status_code=409, detail="Username already exists")

        if user.role not in ROLES:
            raise HTTPException(status_code=400, detail=f"Invalid role: {user.role}")

        user_id = secrets.token_hex(16)
        hashed = hash_password(user.password)
        mfa_secret = generate_totp_secret()

        await conn.execute(
            """INSERT INTO users (id, username, email, password_hash, role, full_name, mfa_secret, mfa_enabled, is_active, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, false, true, NOW())""",
            user_id, user.username, user.email, hashed, user.role, user.full_name, mfa_secret
        )
        logger.info(f"New user registered: {user.username} role={user.role}")
        return {"message": "User created successfully", "user_id": user_id}
    finally:
        await conn.close()

@app.post("/auth/login", response_model=TokenResponse)
async def login(data: UserLogin):
    """Login with username + password + optional MFA token."""
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        user = await get_user_by_username(conn, data.username)
        if not user or not verify_password(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if user["mfa_enabled"]:
            if not data.mfa_token:
                raise HTTPException(status_code=200, detail="MFA_REQUIRED")
            if not verify_totp(user["mfa_secret"], data.mfa_token):
                raise HTTPException(status_code=401, detail="Invalid MFA token")

        token_data = {
            "sub": user["id"],
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
        }
        access_token = create_access_token(token_data)
        refresh_token = create_refresh_token(token_data)

        # Store refresh token in Redis
        redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
        await redis.setex(
            f"refresh:{user['id']}",
            REFRESH_TOKEN_EXPIRE * 86400,
            refresh_token
        )
        await redis.close()

        # Update last login
        await conn.execute(
            "UPDATE users SET last_login = NOW() WHERE id = $1", user["id"]
        )

        logger.info(f"User logged in: {data.username}")
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=ACCESS_TOKEN_EXPIRE * 60,
            user={
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "full_name": user["full_name"],
                "mfa_enabled": user["mfa_enabled"],
            }
        )
    finally:
        await conn.close()

@app.post("/auth/refresh", response_model=dict)
async def refresh_token(data: RefreshRequest):
    """Refresh access token using refresh token."""
    payload = decode_token(data.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
    stored = await redis.get(f"refresh:{payload['sub']}")
    await redis.close()

    if stored != data.refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token revoked or invalid")

    new_access = create_access_token({
        "sub": payload["sub"],
        "username": payload["username"],
        "role": payload["role"],
        "email": payload["email"],
    })
    return {"access_token": new_access, "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE * 60}

@app.post("/auth/logout")
async def logout(user=Depends(get_current_user)):
    """Revoke refresh token on logout."""
    redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
    await redis.delete(f"refresh:{user['sub']}")
    await redis.close()
    logger.info(f"User logged out: {user['username']}")
    return {"message": "Logged out successfully"}

@app.post("/auth/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(user=Depends(get_current_user)):
    """Get MFA setup QR code."""
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        row = await conn.fetchrow("SELECT mfa_secret FROM users WHERE id = $1", user["sub"])
        secret = row["mfa_secret"]
        qr = get_qr_code_base64(secret, user["username"])
        totp = pyotp.TOTP(secret)
        return MFASetupResponse(
            secret=secret,
            qr_code_base64=qr,
            provisioning_uri=totp.provisioning_uri(user["username"], MFA_ISSUER)
        )
    finally:
        await conn.close()

@app.post("/auth/mfa/enable")
async def enable_mfa(token: str, user=Depends(get_current_user)):
    """Verify TOTP token and enable MFA."""
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        row = await conn.fetchrow("SELECT mfa_secret FROM users WHERE id = $1", user["sub"])
        if not verify_totp(row["mfa_secret"], token):
            raise HTTPException(status_code=400, detail="Invalid MFA token")
        await conn.execute("UPDATE users SET mfa_enabled = true WHERE id = $1", user["sub"])
        logger.info(f"MFA enabled for user: {user['username']}")
        return {"message": "MFA enabled successfully"}
    finally:
        await conn.close()

@app.post("/auth/apikey/create")
async def create_api_key(
    data: APIKeyCreate,
    user=Depends(require_permission("manage_users"))
):
    """Create an API key for service-to-service auth."""
    key = "sk_" + secrets.token_hex(32)
    key_hash = hash_password(key)
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute(
            """INSERT INTO api_keys (id, name, key_hash, permissions, created_by, expires_at)
               VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '1 day' * $6)""",
            secrets.token_hex(8), data.name, key_hash,
            ",".join(data.permissions), user["sub"], data.expires_days
        )
    finally:
        await conn.close()
    return {"api_key": key, "name": data.name, "message": "Store this key safely — it won't be shown again"}

@app.get("/auth/me")
async def get_me(user=Depends(get_current_user)):
    """Get current user profile."""
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        row = await conn.fetchrow(
            "SELECT id, username, email, role, full_name, mfa_enabled, last_login, created_at FROM users WHERE id = $1",
            user["sub"]
        )
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        u = dict(row)
        u["permissions"] = ROLES.get(u["role"], [])
        return u
    finally:
        await conn.close()

@app.get("/auth/users", dependencies=[Depends(require_permission("manage_users"))])
async def list_users():
    """List all users (admin only)."""
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        rows = await conn.fetch(
            "SELECT id, username, email, role, full_name, is_active, last_login, created_at FROM users ORDER BY created_at DESC"
        )
        return [dict(r) for r in rows]
    finally:
        await conn.close()

# ─── OAuth2 Integration ──────────────────────────────────────
try:
    import sys, os as _os
    sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', 'ai-service'))
    from missing_features import build_oauth2_routes
    _redis_for_oauth = None  # Will be lazily initialized

    @app.on_event("startup")
    async def _init_oauth2():
        global _redis_for_oauth
        _redis_for_oauth = await aioredis.from_url(REDIS_URL, decode_responses=True)
        build_oauth2_routes(app, _redis_for_oauth, create_access_token, create_refresh_token)
        logger.info("OAuth2 routes registered (Google, GitHub, Microsoft)")
except Exception as _e:
    logger.warning(f"OAuth2 not loaded: {_e}")

@app.get("/auth/oauth2/providers")
async def list_oauth2_providers():
    """List configured OAuth2 SSO providers."""
    providers = []
    if os.getenv("GOOGLE_CLIENT_ID"):
        providers.append({"id": "google",    "name": "Google",    "icon": "🔵"})
    if os.getenv("GITHUB_CLIENT_ID"):
        providers.append({"id": "github",    "name": "GitHub",    "icon": "⚫"})
    if os.getenv("AZURE_CLIENT_ID"):
        providers.append({"id": "microsoft", "name": "Microsoft", "icon": "🟦"})
    return {"providers": providers, "sso_enabled": len(providers) > 0}
