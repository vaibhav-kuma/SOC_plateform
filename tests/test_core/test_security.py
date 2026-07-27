import pytest
import os
from datetime import timedelta
from unittest.mock import AsyncMock, patch
from core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    verify_token,
    generate_mfa_secret,
    verify_mfa_code,
    get_mfa_uri,
    generate_api_key,
    check_permissions,
    generate_pkce_pair,
    verify_pkce_challenge,
    encrypt_mfa_secret,
    decrypt_mfa_secret,
)


def test_hash_password_and_verify():
    hashed = hash_password("SecurePass123!")
    assert hashed != "SecurePass123!"
    assert verify_password("SecurePass123!", hashed)
    assert not verify_password("WrongPass456!", hashed)


def test_hash_password_different_salts():
    h1 = hash_password("testpass")
    h2 = hash_password("testpass")
    assert h1 != h2
    assert verify_password("testpass", h1)
    assert verify_password("testpass", h2)


def test_create_and_decode_access_token():
    data = {"sub": "user-123", "role": "admin", "org_id": "org-456"}
    token = create_access_token(data)
    payload = verify_token(token)
    assert payload["sub"] == "user-123"
    assert payload["role"] == "admin"
    assert payload["org_id"] == "org-456"
    assert payload["type"] == "access"
    assert "exp" in payload
    assert "iss" in payload


def test_verify_invalid_token():
    payload = verify_token("invalid.token.payload")
    assert payload == {}


def test_verify_malformed_token():
    payload = verify_token("not-a-jwt")
    assert payload == {}


def test_verify_expired_token():
    data = {"sub": "user-123"}
    token = create_access_token(data, expires_delta=timedelta(seconds=-1))
    payload = verify_token(token)
    assert payload == {}


def test_create_and_decode_refresh_token():
    data = {"sub": "user-123"}
    token = create_refresh_token(data)
    payload = verify_token(token)
    assert payload["sub"] == "user-123"
    assert payload["type"] == "refresh"
    assert "exp" in payload


def test_access_token_expiry():
    data = {"sub": "user-123"}
    token = create_access_token(data, expires_delta=timedelta(hours=1))
    payload = verify_token(token)
    assert payload["sub"] == "user-123"


def test_mfa_secret_generation():
    secret = generate_mfa_secret()
    assert secret
    assert len(secret) > 10
    assert isinstance(secret, str)


def test_mfa_verify_valid():
    secret = generate_mfa_secret()
    import pyotp
    totp = pyotp.TOTP(secret)
    code = totp.now()
    assert verify_mfa_code(secret, code)


def test_mfa_verify_invalid():
    secret = generate_mfa_secret()
    assert not verify_mfa_code(secret, "000000")


def test_mfa_uri():
    secret = generate_mfa_secret()
    uri = get_mfa_uri(secret, "admin@socplatform.io")
    assert "admin%40socplatform.io" in uri or "admin@socplatform.io" in uri
    assert "SOCPlatform" in uri
    assert uri.startswith("otpauth://")


def test_generate_api_key():
    key = generate_api_key()
    assert key.startswith("soc_")
    assert len(key) > 10


def test_check_permissions_all_match():
    assert check_permissions(["read", "write", "delete"], ["read", "write"])


def test_check_permissions_missing():
    assert not check_permissions(["read", "write"], ["delete"])


def test_check_permissions_empty():
    assert check_permissions([], [])
    assert not check_permissions([], ["read"])


def test_check_permissions_wildcard_not_implemented():
    assert not check_permissions(["*"], ["read"])


def test_generate_pkce_pair():
    verifier, challenge = generate_pkce_pair()
    assert verifier
    assert challenge
    assert len(verifier) > 0
    assert len(challenge) == 64  # SHA256 hex digest


def test_verify_pkce_challenge_valid():
    verifier, challenge = generate_pkce_pair()
    assert verify_pkce_challenge(verifier, challenge)


def test_verify_pkce_challenge_invalid():
    verifier, challenge = generate_pkce_pair()
    assert not verify_pkce_challenge("wrong_verifier", challenge)
    assert not verify_pkce_challenge(verifier, "wrong_challenge")


def test_encrypt_decrypt_mfa_secret():
    secret = "test_mfa_secret_123"
    encrypted = encrypt_mfa_secret(secret)
    assert encrypted != secret
    decrypted = decrypt_mfa_secret(encrypted)
    assert decrypted == secret


def test_encrypt_empty_mfa_secret():
    assert encrypt_mfa_secret("") == ""


def test_decrypt_empty_mfa_secret():
    assert decrypt_mfa_secret("") == ""


@patch("core.security.redis_client")
def test_token_revocation(mock_redis):
    mock_redis.client = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    token = create_access_token({"sub": "user-123", "type": "access"})
    payload = verify_token(token)
    assert payload["sub"] == "user-123"

    mock_redis.get = AsyncMock(return_value="1")
    payload = verify_token(token)
    assert payload == {}


def test_token_issuer_validation():
    data = {"sub": "user-123", "type": "access"}
    token = create_access_token(data)
    payload = verify_token(token)
    assert payload.get("iss") == "SOC Platform"


@pytest.mark.asyncio
async def test_token_revocation():
    from unittest.mock import patch, AsyncMock
    import core.security as security_module

    original_client = security_module.redis_client.client
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value="1")
    security_module.redis_client.client = mock_redis

    try:
        result = await security_module.is_token_revoked("test-jti-123")
        assert result is True
        mock_redis.get.assert_called_once_with("revoked_token:test-jti-123")
    finally:
        security_module.redis_client.client = original_client