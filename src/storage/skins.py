import hashlib
import io
import re
import uuid
from pathlib import Path
from typing import BinaryIO

from PIL import Image, UnidentifiedImageError

from src.core.errors import Problem


class SkinStore:
    """
    Validate skin images and publish immutable files under their content hashes.
    Database writers must hold their shared lock while publishing or retiring files.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(exist_ok=True)

    def read_image(self, source: BinaryIO) -> tuple[bytes, str]:
        image_bytes = source.read(1024 * 1024 + 1)
        if len(image_bytes) > 1024 * 1024:
            raise Problem("INVALID_IMAGE", "图片不能超过 1 MiB", 413)

        # Decode and re-encode to avoid publishing unrelated PNG metadata or payloads.
        try:
            with Image.open(io.BytesIO(image_bytes)) as image:
                if image.format != "PNG" or image.size not in ((64, 64), (64, 32)):
                    raise Problem("INVALID_IMAGE", "只接受 64x64 或 64x32 PNG")
                clean_image = image.convert("RGBA")
                output = io.BytesIO()
                clean_image.save(output, format="PNG")
        except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
            raise Problem("INVALID_IMAGE", "PNG 图片损坏") from None

        content = output.getvalue()
        texture_hash = hashlib.sha256(content).hexdigest()
        return content, texture_hash

    def publish(self, content: bytes, texture_hash: str) -> None:
        target = self.directory / texture_hash
        if target.exists():
            return

        # A reader sees either the complete old file or the complete new file.
        temporary = self.directory / ("." + uuid.uuid4().hex)
        try:
            temporary.write_bytes(content)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)

    def retire(self, texture_hash: str | None) -> None:
        if not texture_hash:
            return
        path = self.directory / texture_hash
        if path.is_file():
            # Retention starts when a skin stops being used, not at upload time.
            path.touch()

    def find(self, texture_hash: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", texture_hash):
            raise Problem("NOT_FOUND", "材质不存在", 404)
        path = self.directory / texture_hash
        if not path.is_file():
            raise Problem("NOT_FOUND", "材质不存在", 404)
        return path
