#!/usr/bin/env python3
"""
Recursive sorter for Keitai assets with:
- .img header extraction (name at 0x30..+35 SJIS; JPEG starts at 0x80)
- .mht / .dmt extraction:
  * Standard MHTML (multipart/related)
  * Fallback for HTTP-capture style files (concatenated HTTP/1.x responses)
- .ucp extraction (UCP files are ZIP archives)
- .afd extraction (AFD files contain embedded GIF images)
- Optional phone model suffix added to filenames (before extension) for:
  * emoji, gifs, jpgs, bmp

Usage:
  python Keitai_DumpProcessor.py /path/to/input /path/to/output
  python Keitai_DumpProcessor.py --p "SH-10C" --flatten /in /out
"""

import argparse
import os
import sys
import shutil
import tempfile
import mimetypes
import subprocess
import re
import zipfile
from typing import Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse
from Keitai_PanasonicHeaderStrip import scan_and_strip_dir, PREAMBLE_OFFSET

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
PDF_EXTS = {'.pdf'}

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
    "pdf",
    "camera photos",
    "jpgs",
    "png",
    "bmp",
    "midi",
    "melodies",
    "toruca",
    "videos",
]

# categories that receive a phone suffix
PHONE_SUFFIX_CATS = {"emoji", "gifs", "jpgs", "bmp"}

# How the suffix is formatted in filenames (before extension)
PHONE_SUFFIX_FMT = "_{tag}"

# -------- Helpers --------

def is_file_all_zeros(fp: Path) -> bool:
    """Check if a file contains only null bytes (0x00)."""
    try:
        chunk_size = 1024 * 1024  # 1MB chunks
        with open(fp, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                if any(b != 0 for b in chunk):
                    return False
        return True
    except Exception:
        return False

def is_image_corrupt(fp: Path) -> bool:
    """
    Check if an image file is corrupt or not viewable.
    Returns True if corrupt, False if valid.
    """
    try:
        with Image.open(fp) as im:
            # Verify the image integrity
            im.verify()
        # Re-open to test actual loading (verify() closes the file)
        with Image.open(fp) as im:
            im.load()
        return False  # Image is valid
    except Exception:
        return True  # Image is corrupt

def preprocess_mhtml(raw: bytes) -> bytes:
    """
    Some containers (e.g., Decomail DMT) prepend a non-MIME line like 'Decomail-Template'
    before the real MIME headers. Trim to the first MIME header if found.
    """
    for marker in (b"MIME-Version:", b"Content-Type:"):
        i = raw.find(marker)
        if 0 <= i < 512:
            return raw[i:]
    return raw

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

def sanitize_tag(tag: str) -> str:
    """Safe compact tag for filenames like SH-10C, N902iS, etc."""
    tag = (tag or "").strip()
    tag = tag.replace(" ", "_")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+.")
    return "".join(ch if ch in allowed else "-" for ch in tag) or ""

def append_phone_suffix(path: Path, category: str, phone_tag: str) -> Path:
    if not phone_tag or category not in PHONE_SUFFIX_CATS:
        return path
    return path.with_name(path.stem + PHONE_SUFFIX_FMT.format(tag=phone_tag) + path.suffix)

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
        return base_out / category / src_rel_parent / (forced_basename + ext)

# -------- UCP Extraction --------

def extract_ucp_file(src: Path, out_base: Path, inp_root: Path, flatten: bool, dry_run: bool) -> int:
    """
    Extract UCP file (ZIP archive) into kisekae category.
    Returns the number of files extracted.
    """
    folder_name = sanitize_filename(src.stem)
    rel_parent = src.parent.relative_to(inp_root) if src.parent != inp_root else Path()
    
    if flatten:
        extract_dir = out_base / "kisekae" / folder_name
    else:
        extract_dir = out_base / "kisekae" / rel_parent / folder_name
    
    if dry_run:
        print(f"[DRY] EXTRACT UCP {src} -> {extract_dir}/")
        try:
            with zipfile.ZipFile(src, 'r') as zf:
                for name in zf.namelist():
                    print(f"[DRY]   - {name}")
                return len(zf.namelist())
        except Exception as e:
            print(f"[DRY]   Error reading UCP: {e}")
            return 0
    else:
        try:
            extract_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(src, 'r') as zf:
                zf.extractall(extract_dir)
                return len(zf.namelist())
        except Exception as e:
            print(f"[WARN] Failed to extract UCP {src}: {e}", file=sys.stderr)
            return 0

# -------- AFD (Charaden) GIF Extraction --------

def find_gif_boundaries(data: bytes) -> list:
    """
    Find all GIF images in binary data by locating GIF headers and trailers.
    Returns list of (start_offset, end_offset) tuples.
    """
    gifs = []
    # GIF magic numbers: GIF87a or GIF89a
    gif_signatures = [b'GIF87a', b'GIF89a']
    
    offset = 0
    while offset < len(data):
        # Find next GIF header
        next_gif = -1
        for sig in gif_signatures:
            pos = data.find(sig, offset)
            if pos != -1 and (next_gif == -1 or pos < next_gif):
                next_gif = pos
        
        if next_gif == -1:
            break
        
        # Find the GIF trailer (0x3B) which marks the end
        # Start searching after the header
        trailer_search_start = next_gif + 6
        trailer_pos = data.find(b'\x3B', trailer_search_start)
        
        if trailer_pos != -1:
            # Include the trailer byte
            gifs.append((next_gif, trailer_pos + 1))
            offset = trailer_pos + 1
        else:
            # No trailer found, skip this one
            offset = next_gif + 6
    
    return gifs

def extract_gifs_from_afd(src: Path, out_base: Path, inp_root: Path, flatten: bool, 
                          dry_run: bool, phone_tag: str, corrupt_tracker: dict) -> int:
    """
    Extract embedded GIF images from AFD (charaden) files.
    Creates a subfolder named after the AFD file and extracts GIFs there.
    Moves corrupt GIFs to a Corrupt subfolder.
    Returns the number of GIFs extracted.
    """
    try:
        data = src.read_bytes()
    except Exception as e:
        print(f"[WARN] Failed to read AFD file {src}: {e}", file=sys.stderr)
        return 0
    
    gifs = find_gif_boundaries(data)
    if not gifs:
        return 0
    
    folder_name = sanitize_filename(src.stem)
    rel_parent = src.parent.relative_to(inp_root) if src.parent != inp_root else Path()
    
    if flatten:
        extract_dir = out_base / "charaden" / folder_name
    else:
        extract_dir = out_base / "charaden" / rel_parent / folder_name
    
    extracted_count = 0
    for idx, (start, end) in enumerate(gifs):
        gif_data = data[start:end]
        gif_name = f"gif_{idx:02d}.gif"
        gif_path = extract_dir / gif_name
        
        if dry_run:
            print(f"[DRY] EXTRACT GIF from AFD {src} -> {gif_path} ({len(gif_data)} bytes)")
        else:
            try:
                gif_path.parent.mkdir(parents=True, exist_ok=True)
                with open(gif_path, 'wb') as f:
                    f.write(gif_data)
                
                # Check if the extracted GIF is corrupt
                if is_image_corrupt(gif_path):
                    # Move to Corrupt subfolder
                    corrupt_dir = extract_dir / "Corrupt"
                    corrupt_dir.mkdir(parents=True, exist_ok=True)
                    corrupt_path = corrupt_dir / gif_name
                    shutil.move(str(gif_path), str(corrupt_path))
                    corrupt_tracker["gifs"] += 1
                
                extracted_count += 1
            except Exception as e:
                print(f"[WARN] Failed to write GIF {gif_path}: {e}", file=sys.stderr)
    
    return extracted_count if not dry_run else len(gifs)

# -------- Classification --------

def classify(path: Path) -> Tuple[Optional[str], Optional[str]]:
    ext = path.suffix.lower()

    if ext in GIF_EXTS:
        return ("emoji" if is_emoji_gif(path) else "gifs"), None

    if ext == '.afd':
        return "charaden", "extract_afd_gifs"

    if ext in APPLI_EXTS:
        return "appli", None
    
    # Special handling for UCP files - they need extraction
    if ext == '.ucp':
        return "kisekae", "extract_ucp"
    
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
    if ext in PDF_EXTS:
        return "pdf", None
    if ext in MELODIES_EXTS:
        return "melodies", "process_mlds"
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

def process_mhtml_standard(raw: bytes, container_path: Path, out_base: Path, inp_root: Path,
                           flatten: bool, counts: dict, dry_run: bool, phone_tag: str, corrupt_tracker: dict) -> bool:
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
            allowed_ctypes = {"application/x-shockwave-flash", "image/gif", "text/html", "application/pdf"}
            allowed_exts   = {'.swf', '.gif', '.html', '.htm', '.pdf'}
            if ctype not in allowed_ctypes and ext not in allowed_exts:
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
                dest_path = build_dest_forced_name(out_base, "jpgs", rel_parent / group, flatten, base, ".jpg")
                dest_path = append_phone_suffix(dest_path, "jpgs", phone_tag)
                dest_path = unique_path(dest_path)
                
                if dry_run:
                    print(f"[DRY] EXTRACT(.img from {container_path.suffix}) {stage_path} -> {dest_path}")
                else:
                    write_img_payload_as_jpg(stage_path, dest_path)
                    # Check if the extracted JPEG is corrupt
                    if is_image_corrupt(dest_path):
                        # Move to Corrupt subfolder
                        if flatten:
                            corrupt_dest = out_base / "jpgs" / "Corrupt" / dest_path.name
                        else:
                            corrupt_dest = out_base / "jpgs" / "Corrupt" / (rel_parent / group) / dest_path.name
                        corrupt_dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(dest_path), str(corrupt_dest))
                        corrupt_tracker["jpgs"] += 1
                
                counts["jpgs"] += 1
                extracted_any = True
            else:
                if not flatten:
                    dest_path = out_base / category / (rel_parent / group) / stage_path.name
                else:
                    dest_path = out_base / category / f"{group}_{stage_path.name}"
                dest_path = append_phone_suffix(dest_path, category, phone_tag)
                dest_path = unique_path(dest_path)
                
                # Check if it's a corrupt image
                image_categories = {"emoji", "gifs", "jpgs", "png", "bmp"}
                is_corrupt = False
                if category in image_categories and not dry_run:
                    is_corrupt = is_image_corrupt(stage_path)
                    if is_corrupt:
                        # Adjust destination to Corrupt subfolder
                        if flatten:
                            dest_path = out_base / category / "Corrupt" / dest_path.name
                        else:
                            dest_path = out_base / category / "Corrupt" / (rel_parent / group) / stage_path.name
                        dest_path = unique_path(dest_path)
                        corrupt_tracker[category] += 1
                
                if dry_run:
                    corrupt_tag = " (CORRUPT)" if is_corrupt else ""
                    print(f"[DRY] EXTRACT({container_path.suffix}){corrupt_tag} {stage_path} -> {dest_path}")
                else:
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(stage_path), str(dest_path))
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
    if 'application/pdf' in ctype:
        return '.pdf'
    return None

def process_httpdump(raw: bytes, container_path: Path, out_base: Path, inp_root: Path,
                     flatten: bool, counts: dict, dry_run: bool, phone_tag: str, corrupt_tracker: dict) -> bool:
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
                dest_path = build_dest_forced_name(out_base, "jpgs", rel_parent / group, flatten, base, ".jpg")
                dest_path = append_phone_suffix(dest_path, "jpgs", phone_tag)
                dest_path = unique_path(dest_path)
                
                if dry_run:
                    print(f"[DRY] EXTRACT(.img from {container_path.suffix}) {stage_path} -> {dest_path}")
                else:
                    write_img_payload_as_jpg(stage_path, dest_path)
                    # Check if the extracted JPEG is corrupt
                    if is_image_corrupt(dest_path):
                        # Move to Corrupt subfolder
                        if flatten:
                            corrupt_dest = out_base / "jpgs" / "Corrupt" / dest_path.name
                        else:
                            corrupt_dest = out_base / "jpgs" / "Corrupt" / (rel_parent / group) / dest_path.name
                        corrupt_dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(dest_path), str(corrupt_dest))
                        corrupt_tracker["jpgs"] += 1
                
                counts["jpgs"] += 1
                extracted_any = True
            else:
                if not flatten:
                    dest_path = out_base / category / (rel_parent / group) / stage_path.name
                else:
                    dest_path = out_base / category / f"{group}_{stage_path.name}"
                dest_path = append_phone_suffix(dest_path, category, phone_tag)
                dest_path = unique_path(dest_path)
                
                # Check if it's a corrupt image
                image_categories = {"emoji", "gifs", "jpgs", "png", "bmp"}
                is_corrupt = False
                if category in image_categories and not dry_run:
                    is_corrupt = is_image_corrupt(stage_path)
                    if is_corrupt:
                        # Adjust destination to Corrupt subfolder
                        if flatten:
                            dest_path = out_base / category / "Corrupt" / dest_path.name
                        else:
                            dest_path = out_base / category / "Corrupt" / (rel_parent / group) / stage_path.name
                        dest_path = unique_path(dest_path)
                        corrupt_tracker[category] += 1
                
                if dry_run:
                    corrupt_tag = " (CORRUPT)" if is_corrupt else ""
                    print(f"[DRY] EXTRACT({container_path.suffix}){corrupt_tag} {stage_path} -> {dest_path}")
                else:
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(stage_path), str(dest_path))
                counts[category] += 1
                extracted_any = True

    return extracted_any

def process_mhtdmt_file(src_container: Path, out_base: Path, inp_root: Path,
                        flatten: bool, counts: dict, dry_run: bool, phone_tag: str, corrupt_tracker: dict):
    raw = src_container.read_bytes()
    raw = preprocess_mhtml(raw)
    # Try real MHTML first
    if HAVE_EMAIL:
        if process_mhtml_standard(raw, src_container, out_base, inp_root, flatten, counts, dry_run, phone_tag, corrupt_tracker):
            return True
    # Fallback to HTTP-dump
    return process_httpdump(raw, src_container, out_base, inp_root, flatten, counts, dry_run, phone_tag, corrupt_tracker)

# -------- Main --------

def main():
    parser = argparse.ArgumentParser(description="Sort keitai-related files into category folders.")
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--move", action="store_true", help="Move files instead of copying.")
    parser.add_argument("--flatten", action="store_true", help="Do not preserve relative subfolder structure under each category.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without writing files.")
    parser.add_argument("--p", dest="phone", type=str, default="", help="Phone model tag to append to GIF/JPG/BMP/emoji filenames (e.g., SH-10C).")
    args = parser.parse_args()

    inp = args.input_dir.resolve()
    out = args.output_dir.resolve()
    if not inp.exists() or not inp.is_dir():
        print(f"Input directory does not exist: {inp}", file=sys.stderr)
        sys.exit(2)

    # decide based on the ORIGINAL phone string (not the sanitized one)
    phone_raw = (args.phone or "").strip()
    auto_strip_preamble = phone_raw.lower().startswith("p")
    phone_tag = sanitize_tag(args.phone)

    # totals for preamble stripping across the whole run
    prestrip_totals = {".jpg": 0, ".jpeg": 0, ".gif": 0, ".swf": 0, ".ucp": 0, ".cfd": 0}
    linkskip_paths = set()
    counts = {cat: 0 for cat in CATEGORIES_ORDER}
    # make sure we can count MLDs even if "mlds" is not pre-initialized
    counts.setdefault("melodies", 0)
    # track extracted GIFs from AFD separately
    afd_gifs_extracted = 0
    # track files moved to Empty_SP
    empty_sp_files = 0
    # track corrupt images
    corrupt_images = {"emoji": 0, "gifs": 0, "jpgs": 0, "png": 0, "bmp": 0, "camera photos": 0}

    errors = 0
    processed_dirs = set()
    processed_files = set()  # Track files we've already processed (for empty SP handling)

    for root, dirs, files in os.walk(inp):
        root_path = Path(root)

        # If phone model starts with 'p', strip 0x50 junk headers in-place for JPG/GIF/SWF in this folder
        if auto_strip_preamble and root_path not in processed_dirs:
            res_summary, res_skipped = scan_and_strip_dir(root_path, offset=PREAMBLE_OFFSET, dry_run=args.dry_run)
            for ext, n in res_summary.items():
                prestrip_totals[ext] = prestrip_totals.get(ext, 0) + n
            linkskip_paths.update(res_skipped)
            processed_dirs.add(root_path)

        # Pre-pass: Check for empty SP files and move matching JAR/JAM/SP as a set
        for fname in files:
            src = root_path / fname
            
            # Skip link-like files
            if auto_strip_preamble and src in linkskip_paths:
                continue
            
            if src.suffix.lower() == '.sp' and src not in processed_files:
                # Check if SP is empty (all zeros)
                if is_file_all_zeros(src):
                    stem = src.stem
                    # Find matching JAR and JAM files
                    matching_files = [src]  # Start with the SP file itself
                    
                    for ext in ['.jar', '.jam']:
                        match_file = root_path / f"{stem}{ext}"
                        if match_file.exists() and match_file.is_file():
                            # Skip if it's a link-like file
                            if auto_strip_preamble and match_file in linkskip_paths:
                                continue
                            matching_files.append(match_file)
                    
                    # Move all matching files to Empty_SP subfolder
                    for match_src in matching_files:
                        if match_src in processed_files:
                            continue
                        
                        try:
                            rel_parent = match_src.parent.relative_to(inp) if match_src.parent != inp else Path()
                            if args.flatten:
                                dest = out / "appli" / "Empty_SP" / match_src.name
                            else:
                                dest = out / "appli" / "Empty_SP" / rel_parent / match_src.name
                            
                            dest = unique_path(dest)
                            
                            if args.dry_run:
                                print(f"[DRY] {'MOVE' if args.move else 'COPY'} (Empty SP) {match_src} -> {dest}")
                            else:
                                copy_or_move(match_src, dest, move=args.move)
                            
                            counts["appli"] += 1
                            empty_sp_files += 1
                            processed_files.add(match_src)
                        except Exception as e:
                            errors += 1
                            print(f"[WARN] Failed to process empty SP match {match_src}: {e}", file=sys.stderr)

        for fname in files:
            src = root_path / fname

            # Skip if already processed by empty SP handler
            if src in processed_files:
                continue

            # if this file was identified as a link-like fake, skip it completely
            if auto_strip_preamble and src in linkskip_paths:
                if args.dry_run:
                    print(f"[DRY] SKIP link-like file (no export): {src}")
                continue

            try:
                category, action = classify(src)
                
                if action == "extract_afd_gifs":
                    # First, copy/move the AFD file itself to charaden
                    dest = build_dest(out, "charaden", src, inp, args.flatten)
                    dest = unique_path(dest)
                    if args.dry_run:
                        print(f"[DRY] {'MOVE' if args.move else 'COPY'} {src} -> {dest}")
                    else:
                        copy_or_move(src, dest, move=args.move)
                    counts["charaden"] += 1
                    
                    # Then extract GIFs from the AFD
                    gif_count = extract_gifs_from_afd(src, out, inp, args.flatten, args.dry_run, phone_tag, corrupt_images)
                    afd_gifs_extracted += gif_count
                    
                elif action == "extract_img_header_jpg":
                    base = extract_img_header_name(src) or src.stem
                    rel_parent = src.parent.relative_to(inp) if src.parent != inp else Path()
                    dest = build_dest_forced_name(out, "jpgs", rel_parent, args.flatten, base, ".jpg")
                    dest = append_phone_suffix(dest, "jpgs", phone_tag)
                    dest = unique_path(dest)
                    if args.dry_run:
                        print(f"[DRY] EXTRACT .img {src} -> {dest}")
                    else:
                        write_img_payload_as_jpg(src, dest)
                        # Check if the extracted JPEG is corrupt
                        if is_image_corrupt(dest):
                            # Move to Corrupt subfolder
                            corrupt_dest = dest.parent / "Corrupt" / dest.name
                            corrupt_dest.parent.mkdir(parents=True, exist_ok=True)
                            shutil.move(str(dest), str(corrupt_dest))
                            corrupt_images["jpgs"] += 1
                        if args.move:
                            try: src.unlink()
                            except Exception: pass
                    counts["jpgs"] += 1

                elif action == "extract_ucp":
                    # Extract UCP (ZIP) file
                    extracted_count = extract_ucp_file(src, out, inp, args.flatten, args.dry_run)
                    counts["kisekae"] += extracted_count
                    
                    if args.move and not args.dry_run:
                        try: src.unlink()
                        except Exception: pass

                elif action == "process_mlds":
                    # Stage MLDs into out/melodies; we'll run the tool once after the walk.
                    melodies_dir = Path(out) / "melodies"
                    if not args.dry_run:
                        melodies_dir.mkdir(parents=True, exist_ok=True)

                    dest = melodies_dir / src.name
                    if args.dry_run:
                        print(f"[DRY] {'MOVE' if args.move else 'COPY'} (MLD stage) {src} -> {dest}")
                    else:
                        copy_or_move(src, dest, move=args.move)

                    # ensure key exists and count under 'melodies'
                    counts.setdefault("melodies", 0)
                    counts["melodies"] += 1

                elif action == "extract_mhtdmt":
                    processed = process_mhtdmt_file(src, out, inp, args.flatten, counts, args.dry_run, phone_tag, corrupt_images)
                    if args.move and processed and not args.dry_run:
                        try: src.unlink()
                        except Exception: pass

                elif category:
                    # Check if this is an image file that might be corrupt
                    image_categories = {"emoji", "gifs", "jpgs", "png", "bmp", "camera photos"}
                    is_corrupt = False
                    
                    if category in image_categories:
                        is_corrupt = is_image_corrupt(src)
                    
                    # Build destination path
                    dest = build_dest(out, category, src, inp, args.flatten)
                    dest = append_phone_suffix(dest, category, phone_tag)
                    
                    # If corrupt, move to Corrupt subfolder
                    if is_corrupt:
                        if args.flatten:
                            dest = out / category / "Corrupt" / dest.name
                        else:
                            # Insert "Corrupt" before the filename
                            rel_parent = src.parent.relative_to(inp) if src.parent != inp else Path()
                            dest = out / category / "Corrupt" / rel_parent / dest.name
                        corrupt_images[category] += 1
                    
                    dest = unique_path(dest)
                    
                    if args.dry_run:
                        corrupt_tag = " (CORRUPT)" if is_corrupt else ""
                        print(f"[DRY] {'MOVE' if args.move else 'COPY'}{corrupt_tag} {src} -> {dest}")
                    else:
                        copy_or_move(src, dest, move=args.move)
                    counts[category] += 1
                else:
                    continue

            except Exception as e:
                errors += 1
                print(f"[WARN] Failed to process {src}: {e}", file=sys.stderr)

    # --- Post-pass: dedupe/rename MLDs with extract_mld.py (once) ---
    try:
        melodies_in_dir = Path(out) / "melodies"
        if melodies_in_dir.is_dir():
            temp_out = Path(out) / "temp"

            if not args.dry_run and temp_out.exists():
                shutil.rmtree(temp_out, ignore_errors=True)

            cmd = [
                sys.executable,
                str(Path("Support_Scripts") / "mld-tools-main" / "extract_mld.py"),
                str(melodies_in_dir),
                "--out", str(temp_out),
            ]

            if args.dry_run:
                print(f"[DRY] RUN {' '.join(map(str, cmd))}")
                print(f"[DRY] Would remove {melodies_in_dir} and rename {temp_out} -> {melodies_in_dir}")
            else:
                subprocess.run(cmd, check=True)
                shutil.rmtree(melodies_in_dir)
                os.rename(temp_out, melodies_in_dir)
    except subprocess.CalledProcessError as e:
        errors += 1
        print(f"[WARN] extract_mld.py failed with exit code {e.returncode}: {e}", file=sys.stderr)
    except Exception as e:
        errors += 1
        print(f"[WARN] Post-pass MLD processing failed: {e}", file=sys.stderr)

    # --- Summary output ---
    print("\n=== Summary ===")
    total = 0
    for cat in CATEGORIES_ORDER:
        n = counts.get(cat, 0)
        total += n
        print(f"{cat:14s}: {n}")
    print(f"Errors: {errors}")
    print(f"Total processed: {total}")
    
    if empty_sp_files > 0:
        print(f"\nFiles moved to Empty_SP folder: {empty_sp_files}")
    
    if afd_gifs_extracted > 0:
        print(f"\nGIFs extracted from AFD files: {afd_gifs_extracted}")

    # preamble-strip stats
    strip_total = sum(prestrip_totals.values())
    if strip_total > 0 or args.dry_run:
        print("\n=== Preamble strip (offset 0x50) ===")
        for ext in (".jpg", ".jpeg", ".gif", ".swf", ".ucp", ".cfd"):
            print(f"{ext:6s}: {prestrip_totals[ext]}")
        print(f"TOTAL : {strip_total}")

    # Link-like skip stats
    skip_total = len(linkskip_paths)
    if skip_total > 0 or args.dry_run:
        print("\n=== Link-like files skipped ===")
        by_ext = {}
        for p in linkskip_paths:
            by_ext[p.suffix.lower()] = by_ext.get(p.suffix.lower(), 0) + 1
        for ext, n in sorted(by_ext.items()):
            print(f"{ext:6s}: {n}")
        print(f"TOTAL : {skip_total}")


if __name__ == "__main__":
    main()