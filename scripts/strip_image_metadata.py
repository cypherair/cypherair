#!/usr/bin/env python3
"""Strip non-rendering metadata chunks from PNG image assets in place.

Removes only the ancillary metadata chunks an authoring tool leaves behind —
C2PA Content Credentials (`caBX`), EXIF (`eXIf`), the text chunks that carry
XMP / authoring provenance (`tEXt`, `iTXt`, `zTXt`), and the modification time
(`tIME`). Every other chunk — `IHDR`, palette/transparency (`PLTE`, `tRNS`),
and all colour chunks (`iCCP`, `cICP`, `sRGB`, `gAMA`, `cHRM`, `sBIT`, `pHYs`),
plus the untouched `IDAT` image data and `IEND` — is copied through byte for
byte, so the decoded pixels and colour rendering are identical.

Usage:
    scripts/strip_image_metadata.py <path.png> [<path.png> ...]
    scripts/strip_image_metadata.py --check <path.png> ...   # non-zero if any carry metadata

With no paths, scans the repository's known icon asset locations.
"""

import struct
import sys
from pathlib import Path

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# Ancillary chunks that carry only authoring/provenance metadata, never pixels
# or colour. Everything not listed here is preserved.
METADATA_CHUNK_TYPES = {b"caBX", b"eXIf", b"tEXt", b"iTXt", b"zTXt", b"tIME"}

DEFAULT_SCAN_ROOTS = (
    "AppIcon.icon",
    "AppIconA.icon",
    "AppIconB.icon",
    "AppIconC.icon",
    "AppIconD.icon",
    "AppIconE.icon",
    "Assets.xcassets",
    "Sources/Resources",
)


def iter_chunks(data: bytes):
    if data[:8] != PNG_SIGNATURE:
        raise ValueError("not a PNG (bad signature)")
    offset = 8
    while offset < len(data):
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        chunk_type = data[offset + 4 : offset + 8]
        end = offset + 12 + length  # length + type + data + crc
        yield chunk_type, data[offset:end]
        offset = end


def strip_bytes(data: bytes) -> tuple[bytes, list[str]]:
    kept = [PNG_SIGNATURE]
    removed: list[str] = []
    for chunk_type, raw in iter_chunks(data):
        if chunk_type in METADATA_CHUNK_TYPES:
            removed.append(chunk_type.decode("latin1"))
        else:
            kept.append(raw)
    return b"".join(kept), removed


def image_data_fingerprint(data: bytes) -> bytes:
    """Concatenated bytes of every rendering chunk (IHDR + colour + IDAT + …).

    Two PNGs with the same fingerprint decode to identical pixels and colour;
    used to prove the strip changed nothing but metadata.
    """
    parts = []
    for chunk_type, raw in iter_chunks(data):
        if chunk_type not in METADATA_CHUNK_TYPES:
            parts.append(raw)
    return b"".join(parts)


def resolve_targets(args: list[str]) -> list[Path]:
    if args:
        return [Path(a) for a in args]
    targets: list[Path] = []
    for root in DEFAULT_SCAN_ROOTS:
        targets.extend(sorted(Path(root).rglob("*.png")))
    return targets


def main() -> int:
    args = sys.argv[1:]
    check_only = False
    if args and args[0] == "--check":
        check_only = True
        args = args[1:]

    targets = resolve_targets(args)
    if not targets:
        print("no PNG targets found", file=sys.stderr)
        return 1

    dirty = 0
    for path in targets:
        original = path.read_bytes()
        stripped, removed = strip_bytes(original)
        if not removed:
            continue
        dirty += 1
        if check_only:
            print(f"{path}: carries metadata chunks {sorted(set(removed))}")
            continue
        # Prove the strip preserved every rendering chunk before writing.
        if image_data_fingerprint(original) != image_data_fingerprint(stripped):
            print(f"error: {path} rendering chunks changed — refusing to write", file=sys.stderr)
            return 2
        path.write_bytes(stripped)
        saved = len(original) - len(stripped)
        print(f"{path}: removed {sorted(set(removed))} (-{saved} bytes)")

    if check_only and dirty:
        print(f"\n{dirty} file(s) carry metadata; run without --check to strip", file=sys.stderr)
        return 1
    if not check_only:
        print(f"\nstripped {dirty} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
