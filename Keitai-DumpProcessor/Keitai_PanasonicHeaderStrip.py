# Keitai_PanasonicHeaderStrip.py
"""
Strip 0x50-byte preambles from JPG/GIF/SWF/UCP files on a per-folder basis.

Behavior (per folder):
- Probe one file per type (jpg/jpeg, gif, swf, ucp).
- If at offset 0x50 we find that type's real magic (e.g., FF D8 FF for JPG,
  "GIF89a" for GIF, "FWS/CWS/ZWS" for SWF, or "PK.." for UCP/ZIP),
  assume ALL files of that type in the same folder have the same preamble.
- Strip the first 0x50 bytes from each of those files (in-place, atomic replace).

Returns a dict summary: {'.jpg': N, '.jpeg': M, '.gif': K, '.swf': X, '.ucp': Y}
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Dict, Iterable, Tuple

PREAMBLE_OFFSET = 0x50  # 80 bytes

# File-type magics we support (what we expect to see at offset 0x50)
MAGIC_BY_EXT: Dict[str, Tuple[bytes, ...]] = {
    # JPEG: FF D8 FF (SOI + marker), allow both .jpg and .jpeg
    ".jpg":  (b"\xFF\xD8\xFF",),
    ".jpeg": (b"\xFF\xD8\xFF",),
    # GIF: "GIF87a" or "GIF89a"
    ".gif":  (b"GIF87a", b"GIF89a"),
    # SWF: "FWS" (raw), "CWS" (zlib), "ZWS" (lzma)
    ".swf":  (b"FWS", b"CWS", b"ZWS"),
    # UCP (Kisekae package): ZIP magics. The most common is local header PK\x03\x04,
    # include other ZIP signatures to be safe.
    ".ucp":  (b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"PK\x07\x08"),
}

TARGET_EXTS = set(MAGIC_BY_EXT.keys())


def _has_magic_at(fp: Path, offset: int, magics: Tuple[bytes, ...]) -> bool:
    """Return True if file at `fp` has any of `magics` starting at `offset`."""
    try:
        size = fp.stat().st_size
        need = max(len(m) for m in magics)
        if size < offset + need:
            return False
        with open(fp, "rb") as f:
            f.seek(offset)
            head = f.read(need)
        return any(head.startswith(m) for m in magics)
    except Exception:
        return False


def _strip_preamble_in_file(fp: Path, offset: int) -> bool:
    """Strip first `offset` bytes from file in-place (atomic). Return True on success."""
    tmp = None
    try:
        size = fp.stat().st_size
        if size <= offset:
            return False
        tmp = fp.with_suffix(fp.suffix + ".tmp")
        with open(fp, "rb") as r, open(tmp, "wb") as w:
            r.seek(offset)
            while True:
                chunk = r.read(1024 * 1024)
                if not chunk:
                    break
                w.write(chunk)
        os.replace(tmp, fp)  # atomic on same filesystem
        return True
    except Exception:
        try:
            if tmp and tmp.exists():
                tmp.unlink(missing_ok=True)  # type: ignore[attr-defined]
        except Exception:
            pass
        return False


def _iter_files_with_ext(folder: Path, exts: Iterable[str]):
    exts_lower = {e.lower() for e in exts}
    for p in folder.iterdir():
        if p.is_file() and p.suffix.lower() in exts_lower:
            yield p


def scan_and_strip_dir(
    folder: Path,
    *,
    offset: int = PREAMBLE_OFFSET,
    dry_run: bool = False,
) -> dict:
    """
    Scan a single folder. For each target type (jpg/jpeg, gif, swf, ucp):
      - Probe one file to see if REAL magic appears at `offset`.
      - If yes, strip `offset` bytes from ALL files of that type in the folder.

    Returns a dict summary: {'.jpg': N, '.jpeg': M, '.gif': K, '.swf': X, '.ucp': Y}
    """
    summary = {".jpg": 0, ".jpeg": 0, ".gif": 0, ".swf": 0, ".ucp": 0}
    if not folder.is_dir():
        return summary

    # Group candidates by extension for per-type probing
    by_ext: Dict[str, list[Path]] = {ext: [] for ext in TARGET_EXTS}
    for f in _iter_files_with_ext(folder, TARGET_EXTS):
        by_ext.setdefault(f.suffix.lower(), []).append(f)

    for ext, files in by_ext.items():
        if not files:
            continue
        magics = MAGIC_BY_EXT.get(ext)
        if not magics:
            continue

        # Probe the first file of this type in this folder
        probe = files[0]
        if not _has_magic_at(probe, offset, magics):
            # Nothing to do for this type in this folder
            continue

        # Strip all files of this type in this folder
        for fp in files:
            if dry_run:
                print(f"[DRY] STRIP {offset:#x} from {fp}")
                summary[ext] += 1
                continue
            ok = _strip_preamble_in_file(fp, offset)
            if ok:
                summary[ext] += 1

    return summary
