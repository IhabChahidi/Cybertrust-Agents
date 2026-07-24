"""Compute and patch the integrity_hash field of Evidence JSON objects.

integrity_hash = sha256:<hex digest of json.dumps(content, sort_keys=True)>
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


def compute_hash(content: dict) -> str:
    """Return the sha256:<hex> integrity hash for an Evidence 'content' object."""
    canonical = json.dumps(content, sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def patch_file(path: Path) -> str:
    """Recompute and write the integrity_hash for a single Evidence JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    new_hash = compute_hash(data["content"])
    data["integrity_hash"] = new_hash
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return new_hash


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "files", nargs="*", type=Path,
        help="Evidence JSON files to patch in place with a freshly computed integrity_hash",
    )
    args = parser.parse_args()

    if not args.files:
        parser.print_help()
        sys.exit(1)

    for path in args.files:
        new_hash = patch_file(path)
        print(f"{path}: {new_hash}")


if __name__ == "__main__":
    main()
