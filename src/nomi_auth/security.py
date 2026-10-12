import hashlib
import secrets
import string


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def secret() -> str:
    return secrets.token_urlsafe(32)


def code() -> str:
    raw = "".join(secrets.choice(string.ascii_uppercase + "234567") for _ in range(12))
    return "-".join(raw[i : i + 4] for i in range(0, 12, 4))


def code_hash(value: str) -> str:
    return digest(value.replace("-", "").strip().upper())
