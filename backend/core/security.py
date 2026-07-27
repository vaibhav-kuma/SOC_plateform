import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from passlib.context import CryptContext
import pyotp
import secrets
from cryptography.fernet import Fernet, InvalidToken
from core.config import settings
from core.redis import redis_client

logger = logging.getLogger("soc.security")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =====================
# MFA Secret Encryption
# =====================
_mfa_fernet: Optional[Fernet] = None


def _get_mfa_fernet() -> Fernet:
    global _mfa_fernet
    if _mfa_fernet is None:
        key = settings.MFA_SECRET_ENCRYPTION_KEY
        if not key:
            if settings.ENV == "production":
                raise RuntimeError("MFA_SECRET_ENCRYPTION_KEY must be set in production")
            key = Fernet.generate_key().decode()
            logger.warning("Generated temporary MFA encryption key - not for production use")
        if len(key) != 44 or not key.endswith("="):
            raise ValueError("MFA_SECRET_ENCRYPTION_KEY must be a valid Fernet key (44 chars, base64)")
        _mfa_fernet = Fernet(key.encode() if isinstance(key, str) else key)
    return _mfa_fernet


def encrypt_mfa_secret(secret: str) -> str:
    """Encrypt MFA secret for database storage"""
    if not secret:
        return secret
    return _get_mfa_fernet().encrypt(secret.encode()).decode()


def decrypt_mfa_secret(encrypted_secret: str) -> str:
    """Decrypt MFA secret from database"""
    if not encrypted_secret:
        return encrypted_secret
    try:
        return _get_mfa_fernet().decrypt(encrypted_secret.encode()).decode()
    except InvalidToken:
        logger.error("Failed to decrypt MFA secret - possible key rotation needed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA decryption failed"
        )


# =====================
# Token Revocation (Redis-backed)
# =====================
async def revoke_token(jti: str, ttl_seconds: int = 3600) -> bool:
    """Revoke a token by its JTI"""
    if not redis_client.client:
        logger.warning("Redis unavailable - cannot revoke token")
        return False
    try:
        await redis_client.set(f"revoked_token:{jti}", "1", ttl=ttl_seconds)
        return True
    except Exception as e:
        logger.error(f"Failed to revoke token: {e}")
        return False


async def is_token_revoked(jti: str) -> bool:
    """Check if a token has been revoked"""
    if not redis_client.client:
        return False
    try:
        result = await redis_client.get(f"revoked_token:{jti}")
        return result is not None
    except Exception:
        return False


# =====================
# JWT with RS256 Support
# =====================
def _load_rsa_keys() -> tuple[bytes, bytes]:
    """Load RSA private and public keys from configured paths"""
    private_key_path = settings.JWT_PRIVATE_KEY_PATH
    public_key_path = settings.JWT_PUBLIC_KEY_PATH

    if not private_key_path or not public_key_path:
        raise RuntimeError("JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH must be set for RS256")

    try:
        with open(private_key_path, "r") as f:
            private_key = f.read().strip()
        with open(public_key_path, "r") as f:
            public_key = f.read().strip()
        return private_key.encode(), public_key.encode()
    except FileNotFoundError as e:
        raise RuntimeError(f"RSA key file not found: {e}") from e
    except IOError as e:
        raise RuntimeError(f"Failed to read RSA keys: {e}") from e


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    algorithm: Optional[str] = None,
) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update(
        {
            "exp": expire,
            "type": "access",
            "iat": datetime.now(timezone.utc),
            "iss": settings.APP_NAME,
        }
    )

    alg = algorithm or settings.JWT_ALGORITHM

    if alg == "RS256":
        try:
            private_key_bytes, _ = _load_rsa_keys()
            return jwt.encode(
                to_encode,
                private_key_bytes,
                algorithm=alg,
                headers={"kid": "RS256"},
            )
        except RuntimeError as e:
            logger.error(f"RS256 key loading failed: {e}")
            raise

    secret_key = settings.JWT_SECRET_KEY
    return jwt.encode(
        to_encode,
        secret_key,
        algorithm=alg,
    )


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update(
        {
            "exp": expire,
            "type": "refresh",
            "iat": datetime.now(timezone.utc),
            "iss": settings.APP_NAME,
        }
    )

    alg = settings.JWT_ALGORITHM
    if alg == "RS256":
        try:
            private_key_bytes, _ = _load_rsa_keys()
            return jwt.encode(
                to_encode,
                private_key_bytes,
                algorithm=alg,
                headers={"kid": "RS256"},
            )
        except RuntimeError as e:
            logger.error(f"RS256 key loading failed for refresh token: {e}")
            raise

    secret_key = settings.JWT_SECRET_KEY
    return jwt.encode(
        to_encode,
        secret_key,
        algorithm=alg,
    )


def decode_token(token: str) -> dict:
    try:
        if settings.JWT_ALGORITHM == "RS256":
            _, public_key_bytes = _load_rsa_keys()
            payload = jwt.decode(
                token,
                public_key_bytes,
                algorithms=["RS256"],
                issuer=settings.APP_NAME,
            )
        else:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
                issuer=settings.APP_NAME,
            )
        return payload
    except JWTError:
        return {}


def verify_token(token: str) -> dict:
    """Verify token with revocation check"""
    payload = decode_token(token)
    if not payload:
        return {}

    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        logger.info(f"Revoked token used: {jti}")
        return {}

    return payload


# =====================
# PKCE Implementation
# =====================
def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code verifier and challenge for OAuth authorization code flow"""
    verifier = secrets.token_urlsafe(32)
    challenge = hashlib.sha256(verifier.encode()).hexdigest()
    return verifier, challenge


def verify_pkce_challenge(code_verifier: str, code_challenge: str) -> bool:
    """Verify PKCE challenge for OAuth authorization code flow"""
    hashed_verifier = hashlib.sha256(code_verifier.encode()).hexdigest()
    return hashed_verifier == code_challenge


# =====================
# MFA Implementation
# =====================
def generate_mfa_secret() -> str:
    """Generate a new MFA secret for TOTP setup"""
    return pyotp.random_base32()


def get_mfa_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=settings.MFA_ISSUER_NAME,
    )


def verify_mfa_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code)


def generate_api_key() -> str:
    return f"soc_{secrets.token_urlsafe(32)}"


def check_permissions(user_permissions: List[str], required_permissions: List[str]) -> bool:
    return all(p in user_permissions for p in required_permissions)


# =====================
# Authentication Dependencies
# =====================
async def require_mfa(current_user: dict = Depends("get_current_user")):
    """Dependency that requires MFA verification"""
    mfa_verified = current_user.get("mfa_verified", False)
    mfa_method = current_user.get("mfa_method", "totp")

    if not mfa_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA verification required",
        )
    return current_user