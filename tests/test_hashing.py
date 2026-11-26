# Tests for SHA-256 hashing in fim_core.
# The known vectors here come from the SHA-256 standard, not from this code.
"""Hashing tests: known vectors, chunked hashing, empty and large files."""

from __future__ import annotations

import hashlib
from pathlib import Path

from fim_core import EMPTY_SHA256, hash_bytes, hash_file

HELLO_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_hash_bytes_hello_vector() -> None:
    """SHA-256 of b"hello" must match the published test vector."""
    assert hash_bytes(b"hello") == HELLO_SHA256


def test_hash_file_hello_vector(tmp_path: Path) -> None:
    """Hashing a file holding "hello" gives the same vector."""
    target = tmp_path / "hello.txt"
    target.write_bytes(b"hello")
    assert hash_file(target) == HELLO_SHA256


def test_empty_file_hash(tmp_path: Path) -> None:
    """An empty file hashes to the well-known empty-input digest."""
    target = tmp_path / "empty.txt"
    target.write_bytes(b"")
    assert hash_file(target) == EMPTY_SHA256
    assert hash_bytes(b"") == EMPTY_SHA256


def test_chunked_hash_equals_whole_file_hash(tmp_path: Path) -> None:
    """Chunked hashing must equal hashing the whole content at once."""
    data = bytes(range(256)) * 4096  # 1 MiB of repeating bytes.
    target = tmp_path / "large.bin"
    target.write_bytes(data)
    assert hash_file(target, chunk_size=65536) == hashlib.sha256(data).hexdigest()
    assert hash_file(target, chunk_size=1024) == hashlib.sha256(data).hexdigest()


def test_hash_is_stable_across_calls(tmp_path: Path) -> None:
    """Hashing the same unchanged file twice gives the same digest."""
    target = tmp_path / "stable.txt"
    target.write_text("deterministic content\n", encoding="utf-8")
    assert hash_file(target) == hash_file(target)


def test_hash_changes_when_content_changes(tmp_path: Path) -> None:
    """Changing one byte must change the digest."""
    target = tmp_path / "change.txt"
    target.write_text("version one\n", encoding="utf-8")
    first = hash_file(target)
    target.write_text("version two\n", encoding="utf-8")
    assert hash_file(target) != first


def test_unicode_filename_hashes(tmp_path: Path) -> None:
    """A file with Hindi characters and spaces in its name must hash."""
    target = tmp_path / "my file \u0939\u093f\u0928\u094d\u0926\u0940.txt"
    # write_bytes, not write_text: on Windows write_text translates
    # "\n" to "\r\n", so the file on disk would not be b"unicode name\n".
    target.write_bytes(b"unicode name\n")
    digest = hash_file(target)
    assert len(digest) == 64
    assert digest == hashlib.sha256(b"unicode name\n").hexdigest()
