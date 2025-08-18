# Keitai_PanasonicHeaderStrip.py
"""
Strip 0x50-byte preambles from JPG/GIF/SWF/UCP files on a per-folder basis,
and skip link-like fake assets.

Behavior (per folder):
- Build candidate lists for .jpg/.jpeg, .gif, .swf, .ucp
- Skip files that look like links (contain '/usr/local/share/dfe/data//')
- Probe one remaining file per type; if its REAL magic appears at offset 0x50,
  strip 0x50 bytes from ALL files of that type in that folder (in-place, atomic)

Return:
  (summary_dict, skipped_paths_set)
  where summary_dict is like {'.jpg': N, '.jpeg': M, '.gif': K, '.swf': X, '.ucp': Y}
        skipped_paths_set is a set of Path objects that matched the link-like pattern
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Dict, Iterable, Tuple, Set

PREAMBLE_OFFSET = 0x50  # 80 bytes
LINK_MARKER = b"/usr/local/share/"  # link-like files; skip these entirely

# File-type magics we expect to see at offset 0x50
MAGIC_BY_EXT: Dict[str, Tuple[bytes, ...]] = {
    ".jpg":  (b"\xFF\xD8\xFF",),                 # JPEG SOI + marker
    ".jpeg": (b"\xFF\xD8\xFF",),
    ".gif":  (b"GIF87a", b"GIF89a"),            # GIF headers
    ".swf":  (b"FWS", b"CWS", b"ZWS"),          # SWF variants
    ".ucp":  (b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"PK\x07\x08"),  # ZIP signatures
}

TARGET_EXTS = set(MAGIC_BY_EXT.keys())


def _has_magic_at(fp: Path, offset: int, magics: Tuple[bytes, ...]) -> bool:
    """True if file at `fp` has any of `magics` starting at `offset`."""
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


def _is_fake_link_file(fp: Path) -> bool:
    """Heuristic: if the first ~64KB contains the dfe path marker, treat as link-like and skip."""
    try:
        size = fp.stat().st_size
        to_read = min(size, 65536)
        with open(fp, "rb") as f:
            buf = f.read(to_read)
        return LINK_MARKER in buf
    except Exception:
        return False


def scan_and_strip_dir(
    folder: Path,
    *,
    offset: int = PREAMBLE_OFFSET,
    dry_run: bool = False,
):
    """
    Scan a single folder. For each target type (jpg/jpeg, gif, swf, ucp):
      - Skip link-like files (contain LINK_MARKER)
      - Probe one file to see if REAL magic appears at `offset`
      - If yes, strip `offset` bytes from ALL files of that type in the folder

    Returns (summary, skipped_paths)
    """
    summary = {".jpg": 0, ".jpeg": 0, ".gif": 0, ".swf": 0, ".ucp": 0}
    skipped: Set[Path] = set()

    if not folder.is_dir():
        return summary, skipped

    # Group candidates by extension for per-type probing, skipping link-like files
    by_ext: Dict[str, list[Path]] = {ext: [] for ext in TARGET_EXTS}
    for f in _iter_files_with_ext(folder, TARGET_EXTS):
        if _is_fake_link_file(f):
            if dry_run:
                print(f"[DRY] SKIP link-like file (no export): {f}")
            skipped.add(f)
            continue
        by_ext.setdefault(f.suffix.lower(), []).append(f)

    # Per-type probe + strip
    for ext, files in by_ext.items():
        if not files:
            continue
        magics = MAGIC_BY_EXT.get(ext)
        if not magics:
            continue

        # Probe the first file of this type in this folder
        probe = files[0]
        if not _has_magic_at(probe, offset, magics):
            continue  # no preamble for this type in this folder

        # Strip all files of this type in this folder
        for fp in files:
            if dry_run:
                print(f"[DRY] STRIP {offset:#x} from {fp}")
                summary[ext] += 1
                continue
            ok = _strip_preamble_in_file(fp, offset)
            if ok:
                summary[ext] += 1

    return summary, skipped