from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
import pytest

from app.core.security import (
    InvalidAccessToken,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_argon2id_and_password_boundaries():
    password = "test-only-untrimmed-password "
    hashed = hash_password(password)
    assert hashed != password
    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed)
    assert not verify_password(password.strip(), hashed)
    assert not verify_password("incorrect", hashed)
    assert not verify_password(password, "malformed")
    assert not verify_password("\ud800", hashed)
    with pytest.raises(ValueError):
        hash_password("x" * 1025)
    long_password = "x" * 1024
    assert verify_password(long_password, hash_password(long_password))


def test_access_token_round_trip(auth_settings):
    user_id = uuid4()
    token = create_access_token(user_id, auth_settings)
    assert decode_access_token(token, auth_settings) == user_id
    claims = jwt.decode(
        token, auth_settings.jwt_secret.get_secret_value(), algorithms=["HS256"]
    )
    assert set(claims) == {"sub", "iat", "exp", "type"}
    assert claims["exp"] - claims["iat"] == 1800


@pytest.mark.parametrize(
    "case",
    [
        "expired", "signature", "malformed", "type", "missing_sub", "invalid_uuid",
        "missing_exp", "missing_iat", "missing_type", "wrong_algorithm", "none",
        "future_iat", "invalid_exp", "invalid_sub_type", "nonfinite_exp",
    ],
)
def test_invalid_access_tokens_are_rejected(auth_settings, case):
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(uuid4()), "iat": now, "exp": now + timedelta(minutes=1),
        "type": "access",
    }
    key = auth_settings.jwt_secret.get_secret_value()
    algorithm = "HS256"
    if case == "expired":
        claims.update(iat=now - timedelta(minutes=2), exp=now - timedelta(minutes=1))
    elif case == "signature":
        key = "different-test-key-of-at-least-32-characters"
    elif case == "type":
        claims["type"] = "refresh"
    elif case.startswith("missing_"):
        del claims[case.removeprefix("missing_")]
    elif case == "invalid_uuid":
        claims["sub"] = "not-a-uuid"
    elif case == "invalid_sub_type":
        claims["sub"] = 123
    elif case == "wrong_algorithm":
        algorithm = "HS384"
        key = key * 2
    elif case == "none":
        algorithm, key = "none", ""
    elif case == "future_iat":
        claims["iat"] = now + timedelta(minutes=5)
    elif case == "invalid_exp":
        claims["exp"] = "invalid"
    elif case == "nonfinite_exp":
        claims["exp"] = float("inf")
    token = "malformed" if case == "malformed" else jwt.encode(
        claims, key, algorithm=algorithm
    )
    with pytest.raises(InvalidAccessToken, match="Invalid access token"):
        decode_access_token(token, auth_settings)
