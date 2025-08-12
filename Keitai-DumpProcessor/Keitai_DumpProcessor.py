#!/usr/bin/env python3
"""
Recursive sorter for Keitai assets with:
- .img header extraction (name at 0x30..+35 SJIS; JPEG starts at 0x80)
- .mht / .dmt extraction:
  * Standard MHTML (multipart/related)
  * Fallback for HTTP-capture style files (concatenated HTTP/1.x responses)

Categories:
- appli        = .jar, .jam, .sp, .scr, .jad, .rms
- emoji        = .gif exactly 20x20 px
- gifs         = .gif (non-emoji)
- kisekae      = .ucp, .ucm, .vui
- charaden     = .afd
- machichara   = .cfd, .mmd
- flash        = .swf
- book files   = .zbf
- html         = .html, .htm
- jpgs         = .jpg, .jpeg, .img
- camera photos= .jpg, .jpeg, .png, .bmp where width>640 or height>480
- png          = .png
- bmp          = .bmp
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
import tempfile
import mimetypes
import re
from typing import Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse

try:
    from PIL import Image
except ImportError:
    print("This script requires Pillow. Install it with: pip install pillow", file=sys.stderr)
    sys.exit(1)

# email parser (used for real MHTML)
try:
    from email import policy
    from email.parser import BytesParser
    HAVE_EMAIL = True
except Exception:
    HAVE_EMAIL = False

# -------- Config / Mappings --------

APPLI_EXTS = {'.jar', '.jam', '.sp', '.scr', '.jad', '.rms'}
KISEKAE_EXTS = {'.ucp', '.ucm', '.vui'}
MACHICHARA_EXTS = {'.cfd', '.mmd'}
FLASH_EXTS = {'.swf'}
BOOK_EXTS = {'.zbf'}
HTML_EXTS = {'.html', '.htm'}
JPG_EXTS = {'.jpg', '.jpeg'}
PNG_EXTS = {'.png'}
BMP_EXTS = {'.bmp'}
GIF_EXTS = {'.gif'}
MIDI_EXTS = {'.mid'}
MELODIES_EXTS = {'.mld', '.mel'}
TORUCA_EXTS = {'.trc'}
VIDEO_EXTS = {'.3gp', '.mp2'}

CATEGORIES_ORDER = [
    "emoji",
    "gifs",
    "charaden",
    "appli",
    "kisekae",
    "machichara",
    "flash",
    "book files",
    "html",
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
    if p.suffix.lower() in GIF_EXTS:
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

def build_dest_forced_name(base_out: Path, category: str, src_rel_parent: Path, flatten: bool, forced_basename: str, ext: str) -> Path:
    if flatten:
        return base_out / category / (forced_basename + ext)
    else:
        return base_out / category / src_rel_parent / forced_basename

# -------- Classification --------

def classify(path: Path) -> Tuple[Optional[str], Optional[str]]:
    ext = path.suffix.lower()

    if ext in GIF_EXTS:
        return ("emoji" if is_emoji_gif(path) else "gifs"), None
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
    if ext in HTML_EXTS:
        return "html", None
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
    if ext in ('.mht', '.dmt'):
        return None, "extract_mhtdmt"
    return None, None

# -------- MHTML / HTTP-dump extraction --------
def preprocess_mhtml(raw: bytes) -> bytes:
    """
    Some containers (e.g., DMT/Decomail) start with a non-MIME preamble like
    'Decomail-Template' before the real headers. Trim to the first MIME header.
    """
    for marker in (b"MIME-Version:", b"Content-Type:"):
        i = raw.find(marker)
        if 0 <= i < 512:  # near the top of the file
            return raw[i:]
    return raw

def _guess_name_from_part(part, idx: int) -> str:
    loc = part.get('Content-Location')
    if loc:
        try:
            path = urlparse(loc).path
            base = os.path.basename(path) or f"part{idx}"
        except Exception:
            base = f"part{idx}"
    else:
        base = part.get_param('filename', header='content-disposition')
        if not base:
            base = part.get_param('name', header='content-type')
        if not base:
            ext = mimetypes.guess_extension(part.get_content_type()) or ''
            base = f"part{idx}{ext}"
    base = os.path.basename(base)
    if '.' not in base:
        ext = mimetypes.guess_extension(part.get_content_type()) or ''
        base += ext
    return base

def process_mhtml_standard(raw: bytes, container_path: Path, out_base: Path, inp_root: Path, flatten: bool, counts: dict, dry_run: bool) -> bool:
    if not HAVE_EMAIL:
        return False
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    if not msg.is_multipart():
        return False

    group = sanitize_filename(container_path.stem)
    rel_parent = container_path.parent.relative_to(inp_root) if container_path.parent != inp_root else Path()
    extracted_any = False

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        for idx, part in enumerate(msg.walk()):
            if part.is_multipart():
                continue
            ctype = (part.get_content_type() or '').lower()
            name_probe = _guess_name_from_part(part, idx)
            ext = Path(name_probe).suffix.lower()
            if ctype not in ("application/x-shockwave-flash", "image/gif", "text/html") and ext not in ('.swf', '.gif', '.html', '.htm'):
                continue

            payload = part.get_payload(decode=True)
            if not payload:
                continue

            fname = sanitize_filename(name_probe)
            stage_path = tmpdir_path / fname
            stage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(stage_path, 'wb') as w:
                w.write(payload)

            category, action = classify(stage_path)
            if not category and not action:
                continue

            if action == "extract_img_header_jpg":
                base = extract_img_header_name(stage_path) or stage_path.stem
                dest_dir = build_dest_forced_name(out_base, "jpgs", rel_parent / group, flatten, base, ".jpg")
                final_path = unique_path(dest_dir)
                if dry_run:
                    print(f"[DRY] EXTRACT(.img from {container_path.suffix}) {stage_path} -> {final_path}")
                else:
                    write_img_payload_as_jpg(stage_path, final_path)
                counts["jpgs"] += 1
                extracted_any = True
            else:
                dest = (out_base / category / (rel_parent / group) / stage_path.name) if not flatten \
                       else (out_base / category / f"{group}_{stage_path.name}")
                final_path = unique_path(dest)
                if dry_run:
                    print(f"[DRY] EXTRACT({container_path.suffix}) {stage_path} -> {final_path}")
                else:
                    final_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(stage_path), str(final_path))
                counts[category] += 1
                extracted_any = True

    return extracted_any

HTTP_MARKER = re.compile(br'HTTP/1\.[01]\s+\d{3}')

def _parse_headers(data: bytes, start: int):
    i1 = data.find(b'\r\n\r\n', start)
    i2 = data.find(b'\n\n', start)
    if i1 == -1 and i2 == -1:
        return None
    end = min([x for x in (i1, i2) if x != -1])
    header_blob = data[start:end]
    try:
        text = header_blob.decode('iso-8859-1', errors='replace')
    except Exception:
        text = ""
    lines = re.split(r'\r?\n', text)
    status_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    body_start = end + (4 if header_blob.find(b'\r\n') != -1 else 2)
    return status_line, headers, body_start

def _ext_from_ctype(ctype: str) -> Optional[str]:
    ctype = (ctype or '').lower()
    if 'x-shockwave-flash' in ctype:
        return '.swf'
    if 'image/gif' in ctype:
        return '.gif'
    if 'text/html' in ctype or 'application/xhtml+xml' in ctype:
        return '.html'
    return None

def process_httpdump(raw: bytes, container_path: Path, out_base: Path, inp_root: Path, flatten: bool, counts: dict, dry_run: bool) -> bool:
    extracted_any = False
    group = sanitize_filename(container_path.stem)
    rel_parent = container_path.parent.relative_to(inp_root) if container_path.parent != inp_root else Path()

    matches = list(HTTP_MARKER.finditer(raw))
    for idx, m in enumerate(matches):
        start = m.start()
        parsed = _parse_headers(raw, start)
        if not parsed:
            continue
        status_line, headers, body_start = parsed
        ctype = headers.get('content-type', '')
        ext = _ext_from_ctype(ctype)
        if not ext:
            continue
        try:
            clen = int(headers.get('content-length', '0'))
        except ValueError:
            clen = 0
        if clen <= 0 or body_start + clen > len(raw):
            next_start = matches[idx + 1].start() if idx + 1 < len(matches) else len(raw)
            body = raw[body_start:next_start]
        else:
            body = raw[body_start:body_start + clen]

        fname = f"part{idx:02d}{ext}"
        with tempfile.TemporaryDirectory() as tmpdir:
            stage_path = Path(tmpdir) / fname
            with open(stage_path, 'wb') as w:
                w.write(body)

            category, action = classify(stage_path)
            if not category and not action:
                continue

            if action == "extract_img_header_jpg":
                base = stage_path.stem
                dest_dir = build_dest_forced_name(out_base, "jpgs", rel_parent / group, flatten, base, ".jpg")
                final_path = unique_path(dest_dir)
                if dry_run:
                    print(f"[DRY] EXTRACT(.img from {container_path.suffix}) {stage_path} -> {final_path}")
                else:
                    write_img_payload_as_jpg(stage_path, final_path)
                counts["jpgs"] += 1
                extracted_any = True
            else:
                dest = (out_base / category / (rel_parent / group) / stage_path.name) if not flatten \
                       else (out_base / category / f"{group}_{stage_path.name}")
                final_path = unique_path(dest)
                if dry_run:
                    print(f"[DRY] EXTRACT({container_path.suffix}) {stage_path} -> {final_path}")
                else:
                    final_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(stage_path), str(final_path))
                counts[category] += 1
                extracted_any = True

    return extracted_any

def process_mhtdmt_file(src_container: Path, out_base: Path, inp_root: Path, flatten: bool, counts: dict, dry_run: bool):
    raw = src_container.read_bytes()
    raw = preprocess_mhtml(raw)  # <<< NEW: strip preamble if present
    # Try real MHTML first
    if HAVE_EMAIL and process_mhtml_standard(raw, src_container, out_base, inp_root, flatten, counts, dry_run):
        return True
    # Fallback to HTTP dump style (concatenated HTTP/1.x responses)
    return process_httpdump(raw, src_container, out_base, inp_root, flatten, counts, dry_run)


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
            try:
                category, action = classify(src)
                if action == "extract_img_header_jpg":
                    base = extract_img_header_name(src) or src.stem
                    rel_parent = src.parent.relative_to(inp) if src.parent != inp else Path()
                    dest = build_dest_forced_name(out, "jpgs", rel_parent, args.flatten, base, ".jpg")
                    dest = unique_path(dest)
                    if args.dry_run:
                        print(f"[DRY] EXTRACT .img {src} -> {dest}")
                    else:
                        write_img_payload_as_jpg(src, dest)
                        if args.move:
                            try: src.unlink()
                            except Exception: pass
                    counts["jpgs"] += 1

                elif action == "extract_mhtdmt":
                    processed = process_mhtdmt_file(src, out, inp, args.flatten, counts, args.dry_run)
                    if args.move and processed and not args.dry_run:
                        try: src.unlink()
                        except Exception: pass

                elif category:
                    dest = build_dest(out, category, src, inp, args.flatten)
                    dest = unique_path(dest)
                    if args.dry_run:
                        print(f"[DRY] {'MOVE' if args.move else 'COPY'} {src} -> {dest}")
                    else:
                        copy_or_move(src, dest, move=args.move)
                    counts[category] += 1
                else:
                    continue

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
