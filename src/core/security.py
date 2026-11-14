import hashlib
import hmac
import secrets
import string
import time


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def secret() -> str:
    return secrets.token_urlsafe(32)


def code() -> str:
    raw = "".join(secrets.choice(string.ascii_uppercase + "234567") for _ in range(12))
    return "-".join(raw[i : i + 4] for i in range(0, 12, 4))


def code_hash(value: str) -> str:
    return digest(value.replace("-", "").strip().upper())


def current_timestamp() -> int:
    """
    Return Unix seconds for persisted expiry times.
    """
    return int(time.time())


def derive_token(seed: str, request_id: str, nonce: str, kind: str) -> str:
    """
    Recreate one grant for an identical bounded retry without storing raw tokens.
    """
    message = f"{request_id}:{nonce}:{kind}".encode()
    return hmac.digest(seed.encode(), message, "sha256").hex()
