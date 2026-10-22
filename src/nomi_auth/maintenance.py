"""Complete local snapshots and conservative orphan-texture maintenance."""

import hashlib
import re
import shutil
import sqlite3
import tarfile
import tempfile
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .db import Database


def cleanup_textures(db: Database, timestamp: int, retention: int = 86400):
    """Keep referenced textures and recently uploaded files, including interrupted uploads."""
    removed = 0
    with db.write() as conn:
        referenced = {row[0] for row in conn.execute("SELECT skin_hash FROM profiles WHERE skin_hash IS NOT NULL")}
        for path in (db.path.parent / "textures").glob("*"):
            if (path.is_file() and not path.is_symlink() and path.name not in referenced
                    and path.stat().st_mtime <= timestamp - retention):
                path.unlink()
                removed += 1
    return removed


def validate_snapshot(directory: Path):
    """Reject incomplete or corrupt backups before restoring any service data."""
    if not (directory / "nomi-auth.sqlite3").is_file():
        raise ValueError("Snapshot is missing its database")
    key = load_pem_private_key((directory / "texture-signing.pem").read_bytes(), password=None)
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    if not isinstance(key, RSAPrivateKey):
        raise TypeError("Snapshot signing key must be RSA")
    with closing(sqlite3.connect(directory / "nomi-auth.sqlite3")) as conn:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or conn.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("Snapshot database is corrupt")
        for row in conn.execute("SELECT DISTINCT skin_hash FROM profiles WHERE skin_hash IS NOT NULL"):
            name = row[0]
            if not re.fullmatch(r"[0-9a-f]{64}", name) or not (directory / "textures" / name).is_file():
                raise ValueError("Snapshot is missing a referenced texture")
            texture = directory / "textures" / name
            if texture.stat().st_size > 1024 * 1024 or hashlib.sha256(texture.read_bytes()).hexdigest() != name:
                raise ValueError("Snapshot contains a corrupt texture")


def backup_data(db: Database, destination: Path):
    """Snapshot database, referenced skins and the signing key without overwriting backups."""
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nomi-backup-") as staging:
        root = Path(staging)
        (root / "textures").mkdir()
        # Writers publish texture files under this same database lock.
        with db.write():
            with db.read() as source, closing(sqlite3.connect(root / "nomi-auth.sqlite3")) as target:
                source.backup(target)
            shutil.copyfile(db.path.parent / "texture-signing.pem", root / "texture-signing.pem")
            with closing(sqlite3.connect(root / "nomi-auth.sqlite3")) as conn:
                for (name,) in conn.execute("SELECT DISTINCT skin_hash FROM profiles WHERE skin_hash IS NOT NULL"):
                    if not re.fullmatch(r"[0-9a-f]{64}", name):
                        raise ValueError("Invalid texture reference")
                    shutil.copyfile(db.path.parent / "textures" / name, root / "textures" / name)
        validate_snapshot(root)
        # Exclusive creation protects existing archives, including concurrent backup attempts.
        created = False
        try:
            with destination.open("xb") as output:
                created = True
                destination.chmod(0o600)
                with tarfile.open(fileobj=output, mode="w:gz") as archive:
                    for path in sorted(root.rglob("*")):
                        if path.is_file():
                            archive.add(path, arcname=path.relative_to(root).as_posix())
        except BaseException:
            if created:
                destination.unlink(missing_ok=True)
            raise



def restore_data(archive_path: Path, destination: Path):
    """Restore only into a new directory; never overwrite a running service's data."""
    destination = destination.resolve()
    if destination.exists():
        raise FileExistsError("Restore destination must not exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".nomi-restore-", dir=destination.parent) as staging:
        root = Path(staging) / "data"
        root.mkdir(mode=0o700)
        (root / "textures").mkdir()
        with tarfile.open(archive_path, "r:gz") as archive:
            seen = set()
            for member in archive:
                if not member.isfile() or not re.fullmatch(r"(?:nomi-auth\.sqlite3|texture-signing\.pem|textures/[0-9a-f]{64})", member.name):
                    raise ValueError("Unexpected or unsafe backup entry")
                if member.name in seen:
                    raise ValueError("Duplicate backup entry")
                seen.add(member.name)
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("Unreadable backup entry")
                with stream, (root / member.name).open("xb") as output:
                    shutil.copyfileobj(stream, output)
                (root / member.name).chmod(0o600)
        validate_snapshot(root)
        root.rename(destination)
