"""Fixtures for the CVE-2007-4559 rediscovery benchmark.

These are the target-under-test samples. ``unpack`` is the vulnerable pattern that
CVE-2007-4559 describes: a tar is extracted with no sanitization of member paths,
so a member named ``../something`` writes outside the destination. ``unpack_safe``
is the fixed pattern using the extraction filter added in Python 3.12 (PEP 706).

The detector must flag the first and leave the second alone. Neither is ever
called by the benchmark. They exist to be read, not run.
"""

import tarfile


def unpack(archive_path: str, dest: str) -> None:
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest)  # CVE-2007-4559: no member sanitization


def unpack_safe(archive_path: str, dest: str) -> None:
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest, filter="data")  # 3.12+ safe extraction
