#!/usr/bin/env python3
"""
Recursive sorter for Keitai assets

Categories:
- appli        = .jar, .jam, .sp, .scr, .jad, .rms
- emoji        = .gif that is exactly 20x20 px
- kisekae      = .ucp, .ucm, .vui
- charaden     = .afd
- machichara   = .cfd, .mmd
- flash        = .swf
- book files   = .zbf
- jpgs         = .jpg, .jpeg, .img  ('.img' is extracted: header 0x80, name at 0x30..0x30+35 SJIS)
- camera photos= .jpg, .jpeg, .png, .bmp where width>640 or height>480
- png          = .png  (non "camera photos")
- bmp          = .bmp  (non "camera photos")
- midi         = .mid
- melodies     = .mld, .mel
- toruca       = .trc
- videos       = .3gp, .mp2

Usage:
  python Keitai_DumpProcessor.py /path/to/input /path/to/output
  Normally use this: python Keitai_DumpProcessor.py --flatten /in /out
"""

import argparse
import os
import sys
import shutil
from typing import Optional
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("This script requires Pillow. Install it with: pip install pillow", file=sys.stderr)
    sys.exit(1)

# -------- Config / Mappings --------

APPLI_EXTS = {'.jar', '.jam', '.sp', '.scr', '.jad', '.rms'}  # .rms added here
KISEKAE_EXTS = {'.ucp', '.ucm', '.vui'}
MACHICHARA_EXTS = {'.cfd', '.mmd'}
FLASH_EXTS = {'.swf'}
BOOK_EXTS = {'.zbf'}
JPG_EXTS = {'.jpg', '.jpeg'}
PNG_EXTS = {'.png'}
BMP_EXTS = {'.bmp'}
MIDI_EXTS = {'.mid'}
MELODIES_EXTS = {'.mld', '.mel'}
TORUCA_EXTS = {'.trc'}
VIDEO_EXTS = {'.3gp', '.mp2'}

CATEGORIES_ORDER = [
    "emoji",
    "charaden",
    "appli",
    "kisekae",
    "machichara",
    "flash",
    "book files",
    "camera photos",
    "jpgs",
    "png",
    "bmp",
    "midi",
    "melodies",
    "toruca",
    "videos",
]

# -------- Helpers --------

def is_camera_photo(p: Path) -> bool:
    ext = p.suffix.lower()
    if ext in JPG_EXTS | PNG_EXTS | BMP_EXTS:
        try:
            with Image.open(p) as im:
                w, h = im.size
            return (w > 640) or (h > 480)
        except Exception:
            return False
    return False

def is_emoji_gif(p: Path) -> bool:
    if p.suffix.lower() == '.gif':
        try:
            with Image.open(p) as im:
                return im.size == (20, 20)
        except Exception:
            return False
    return False

def unique_path(p: Path) -> Path:
    if not p.exists():
        return p
    stem, suffix = p.stem, p.suffix
    n = 1
    while True:
        candidate = p.with_name(f"{stem}_{n}{suffix}")
        if not candidate.exists():
            return candidate
        n += 1

def copy_or_move(src: Path, dst: Path, move: bool):
    dst.parent.mkdir(parents=True, exist_ok=True)
    if move:
        shutil.move(str(src), str(dst))
    else:
        shutil.copy2(str(src), str(dst))

def sanitize_filename(name: str) -> str:
    lower = name.lower()
    for ext in ('.jpg', '.jpeg'):
        if lower.endswith(ext):
            name = name[:-(len(ext))]
            break
    name = ''.join(ch for ch in name if ch >= ' ')
    for ch in '<>:"/\\|?*':
        name = name.replace(ch, '_')
    name = name.rstrip(' .')
    reserved = {
        'con','prn','aux','nul','com1','com2','com3','com4','com5','com6','com7','com8','com9',
        'lpt1','lpt2','lpt3','lpt4','lpt5','lpt6','lpt7','lpt8','lpt9'
    }
    if name.lower() in reserved:
        name = f"{name}_"
    if len(name) > 240:
        name = name[:240]
    return name or "extracted"

def extract_img_header_name(src: Path) -> str:
    """
    Read name from .img header:
      - bytes[0x30 : 0x30+36] -> SJIS string, null-terminated
    Returns sanitized base name (no extension).
    """
    with open(src, 'rb') as f:
        f.seek(0x30)
        raw = f.read(36)
    raw = raw.split(b'\x00', 1)[0]
    try:
        name = raw.decode('shift_jis', errors='ignore').strip()
    except Exception:
        name = ""
    return sanitize_filename(name)

def write_img_payload_as_jpg(src: Path, dest: Path) -> None:
    """
    Write bytes from offset 0x80 to EOF into dest (.jpg).
    No decoding/transcoding—just strip the header and dump the JPEG.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(src, 'rb') as fin, open(dest, 'wb') as fout:
        fin.seek(0x80)
        shutil.copyfileobj(fin, fout)

def build_dest(base_out: Path, category: str, src: Path, root_in: Path, flatten: bool, new_ext: Optional[str]=None) -> Path:
    rel = src.relative_to(root_in)
    if flatten:
        name = src.stem + (new_ext if new_ext else src.suffix)
        return base_out / category / name
    else:
        subdir = rel.parent if str(rel.parent) != '.' else Path()
        name = src.stem + (new_ext if new_ext else src.suffix)
        return base_out / category / subdir / name

def build_dest_forced_name(base_out: Path, category: str, src: Path, root_in: Path, flatten: bool, forced_basename: str, ext: str) -> Path:
    rel = src.relative_to(root_in)
    if flatten:
        return base_out / category / (forced_basename + ext)
    else:
        subdir = rel.parent if str(rel.parent) != '.' else Path()
        return base_out / category / subdir / (forced_basename + ext)

def classify(path: Path):
    ext = path.suffix.lower()

    if is_emoji_gif(path):
        return "emoji", None

    if ext == '.afd':
        return "charaden", None

    if ext in APPLI_EXTS:
        return "appli", None
    if ext in KISEKAE_EXTS:
        return "kisekae", None
    if ext in MACHICHARA_EXTS:
        return "machichara", None
    if ext in FLASH_EXTS:
        return "flash", None
    if ext in BOOK_EXTS:
        return "book files", None
    if ext in MELODIES_EXTS:
        return "melodies", None
    if ext in MIDI_EXTS:
        return "midi", None
    if ext in TORUCA_EXTS:
        return "toruca", None
    if ext in VIDEO_EXTS:
        return "videos", None

    if ext in JPG_EXTS | PNG_EXTS | BMP_EXTS:
        if is_camera_photo(path):
            return "camera photos", None
        if ext in JPG_EXTS:
            return "jpgs", None
        if ext in PNG_EXTS:
            return "png", None
        if ext in BMP_EXTS:
            return "bmp", None

    if ext == '.img':
        return "jpgs", "extract_img_header_jpg"

    return None, None

# -------- Main --------

def main():
    parser = argparse.ArgumentParser(description="Sort keitai-related files into category folders.")
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--move", action="store_true", help="Move files instead of copying.")
    parser.add_argument("--flatten", action="store_true", help="Do not preserve relative subfolder structure under each category.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without writing files.")
    args = parser.parse_args()

    inp = args.input_dir.resolve()
    out = args.output_dir.resolve()
    if not inp.exists() or not inp.is_dir():
        print(f"Input directory does not exist: {inp}", file=sys.stderr)
        sys.exit(2)

    counts = {cat: 0 for cat in CATEGORIES_ORDER}
    errors = 0

    for root, dirs, files in os.walk(inp):
        for fname in files:
            src = Path(root) / fname
            category, action = classify(src)
            if not category:
                continue

            try:
                if action == "extract_img_header_jpg":
                    base = extract_img_header_name(src) or src.stem
                    dest = build_dest_forced_name(out, category, src, inp, args.flatten, base, ".jpg")
                    dest = unique_path(dest)
                    if args.dry_run:
                        print(f"[DRY] EXTRACT .img {src} -> {dest}")
                    else:
                        write_img_payload_as_jpg(src, dest)
                    counts[category] += 1
                else:
                    dest = build_dest(out, category, src, inp, args.flatten)
                    dest = unique_path(dest)
                    if args.dry_run:
                        print(f"[DRY] {'MOVE' if args.move else 'COPY'} {src} -> {dest}")
                    else:
                        copy_or_move(src, dest, move=args.move)
                    counts[category] += 1
            except Exception as e:
                errors += 1
                print(f"[WARN] Failed to process {src}: {e}", file=sys.stderr)

    print("\n=== Summary ===")
    total = 0
    for cat in CATEGORIES_ORDER:
        n = counts[cat]
        total += n
        print(f"{cat:14s}: {n}")
    print(f"Errors: {errors}")
    print(f"Total processed: {total}")

if __name__ == "__main__":
    main()
