import hashlib
import io
import os
import sqlite3
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from nomi_auth.db import Database
from nomi_auth.maintenance import backup_data, cleanup_textures, restore_data

SKIN_HASH = hashlib.sha256(b"skin").hexdigest()


@pytest.fixture
def data(tmp_path):
    root = tmp_path / "data"
    db = Database(root / "nomi-auth.sqlite3")
    (root / "texture-signing.pem").write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root / "textures").mkdir()
    name = SKIN_HASH
    (root / "textures" / name).write_bytes(b"skin")
    with db.write() as conn:
        conn.execute("INSERT INTO accounts VALUES('account','Alice','alice','active',1)")
        conn.execute("INSERT INTO profiles(uuid,account_id,name,name_normalized,skin_hash) VALUES('profile','account','Alice','alice',?)", (name,))
    return db


def test_complete_backup_restore_and_overwrite_protection(data, tmp_path):
    archive = tmp_path / "snapshot.tar.gz"
    backup_data(data, archive)
    original = archive.read_bytes()
    with pytest.raises(FileExistsError):
        backup_data(data, archive)
    assert archive.read_bytes() == original
    destination = tmp_path / "restored"
    restore_data(archive, destination)
    assert (destination / "texture-signing.pem").read_bytes() == (data.path.parent / "texture-signing.pem").read_bytes()
    assert (destination / "textures" / (SKIN_HASH)).read_bytes() == b"skin"
    with sqlite3.connect(destination / "nomi-auth.sqlite3") as conn:
        assert conn.execute("SELECT name,uuid FROM profiles").fetchone() == ("Alice", "profile")
    with pytest.raises(FileExistsError):
        restore_data(archive, destination)


def test_missing_skin_prevents_incomplete_backup(data, tmp_path):
    (data.path.parent / "textures" / (SKIN_HASH)).unlink()
    archive = tmp_path / "snapshot.tar.gz"
    with pytest.raises(FileNotFoundError):
        backup_data(data, archive)
    assert not archive.exists()


def test_corrupt_skin_prevents_incomplete_backup(data, tmp_path):
    (data.path.parent / "textures" / SKIN_HASH).write_bytes(b"corrupted")
    archive = tmp_path / "snapshot.tar.gz"
    with pytest.raises(ValueError, match="corrupt texture"):
        backup_data(data, archive)
    assert not archive.exists()


def test_restore_rejects_corrupt_skin_without_publishing_directory(data, tmp_path):
    archive = tmp_path / "snapshot.tar.gz"
    corrupt = tmp_path / "corrupt-skin.tar.gz"
    backup_data(data, archive)
    with tarfile.open(archive, "r:gz") as source, tarfile.open(corrupt, "w:gz") as target:
        for member in source:
            stream = source.extractfile(member)
            if member.name.startswith("textures/"):
                content = b"corrupted"
                member.size = len(content)
                target.addfile(member, io.BytesIO(content))
            else:
                target.addfile(member, stream)
            if stream is not None:
                stream.close()
    with pytest.raises(ValueError, match="corrupt texture"):
        restore_data(corrupt, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_restore_rejects_corrupt_database_without_publishing_directory(data, tmp_path):
    archive = tmp_path / "snapshot.tar.gz"
    corrupt = tmp_path / "corrupt.tar.gz"
    backup_data(data, archive)
    with tarfile.open(archive, "r:gz") as source, tarfile.open(corrupt, "w:gz") as target:
        for member in source:
            stream = source.extractfile(member)
            if member.name == "nomi-auth.sqlite3":
                content = b"not a database"
                member.size = len(content)
                target.addfile(member, io.BytesIO(content))
            else:
                target.addfile(member, stream)
            if stream is not None:
                stream.close()
    with pytest.raises(sqlite3.DatabaseError):
        restore_data(corrupt, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize("name", ["../escaped", "/absolute", "textures/../../escaped"])
def test_unsafe_archive_cannot_write_outside_restore(tmp_path, name):
    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        entry = tarfile.TarInfo(name)
        entry.size = 1
        output.addfile(entry, io.BytesIO(b"x"))
    with pytest.raises(ValueError):
        restore_data(archive, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()
    assert not (tmp_path / "escaped").exists()


def test_texture_cleanup_keeps_references_and_recent_files(data):
    root = data.path.parent / "textures"
    referenced = root / (SKIN_HASH)
    orphan = root / ("b" * 64)
    recent = root / ("c" * 64)
    orphan.write_bytes(b"old")
    recent.write_bytes(b"new")
    old = time.time() - 90000
    for path in (referenced, orphan):
        os.utime(path, (old, old))
    assert cleanup_textures(data, int(time.time())) == 1
    assert referenced.exists() and recent.exists() and not orphan.exists()


def test_concurrent_cleanup_is_coalesced_and_failure_can_retry(data, monkeypatch):
    calls = []

    def cleanup(timestamp):
        calls.append(timestamp)

    monkeypatch.setattr(data, "cleanup", cleanup)
    with ThreadPoolExecutor(8) as executor:
        list(executor.map(data.cleanup_if_due, [100] * 20))
    assert calls == [100]
    data.cleanup_if_due(129)
    assert calls == [100]
    data.cleanup_if_due(130)
    assert calls == [100, 130]
    monkeypatch.setattr(data, "cleanup", lambda timestamp: (_ for _ in ()).throw(sqlite3.OperationalError()))
    with pytest.raises(sqlite3.OperationalError):
        data.cleanup_if_due(160)
    monkeypatch.setattr(data, "cleanup", cleanup)
    data.cleanup_if_due(160)
    assert calls == [100, 130, 160]


def test_backup_remains_consistent_during_concurrent_write(data, tmp_path, monkeypatch):
    from nomi_auth import maintenance

    entered, release = Event(), Event()
    copy = maintenance.shutil.copyfile

    def slow_copy(source, target):
        if source.name == "texture-signing.pem":
            entered.set()
            assert release.wait(5)
        return copy(source, target)

    monkeypatch.setattr(maintenance.shutil, "copyfile", slow_copy)

    def rename():
        with data.write() as conn:
            conn.execute("UPDATE profiles SET name='Renamed', name_normalized='renamed'")

    with ThreadPoolExecutor(2) as executor:
        backup = executor.submit(backup_data, data, tmp_path / "consistent.tar.gz")
        try:
            assert entered.wait(5)
            writer = executor.submit(rename)
            with data.read() as conn:
                assert conn.execute("SELECT name FROM profiles").fetchone()[0] == "Alice"
            assert not writer.done()
        finally:
            release.set()
        backup.result(timeout=5)
        writer.result(timeout=5)
    restore_data(tmp_path / "consistent.tar.gz", tmp_path / "restored")
    restored = Database(tmp_path / "restored" / "nomi-auth.sqlite3")
    with restored.read() as conn:
        assert conn.execute("SELECT name FROM profiles").fetchone()[0] == "Alice"
    with data.read() as conn:
        assert conn.execute("SELECT name FROM profiles").fetchone()[0] == "Renamed"
