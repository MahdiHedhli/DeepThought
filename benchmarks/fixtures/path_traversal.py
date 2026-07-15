"""Read-only benchmark fixture. The functions are parsed and never called."""

import os
from pathlib import Path


def extract_vulnerable(root, filename, write_file):
    destination = os.path.join(root, filename)
    return write_file(destination)


def extract_patched(root, filename, write_file):
    destination = Path(root).joinpath(filename)
    destination.relative_to(Path(root))
    return write_file(destination)
