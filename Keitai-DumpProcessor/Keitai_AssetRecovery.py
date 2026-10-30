"""Complete asset export with a byte-exact source archive and per-file accounting.

Unknown/proprietary formats are preserved and reported, not claimed as decoded.
No speculative signature carving is performed inside arbitrary databases/apps.
"""
from collections import Counter
from email import policy
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
from urllib.parse import urlparse
import zipfile

from PIL import Image
from Keitai_Media import find_gifs, image_info, media_end

MAX_MEMBER = 64 * 1024 * 1024
MAX_ARCHIVE = 256 * 1024 * 1024
IMAGE_EXTS = {'.gif', '.jpg', '.jpeg', '.png', '.bmp'}


def safe_name(name):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).rstrip(' .')[:180]
    if re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', name):
        name = '_' + name
    return name or 'asset'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def iso_media(data):
    if len(data) < 12 or data[4:8] != b'ftyp':
        return False
    pos = 0
    while pos < len(data):
        if pos + 8 > len(data):
            return False
        size = int.from_bytes(data[pos:pos + 4], 'big')
        header = 8
        if size == 1:
            if pos + 16 > len(data):
                return False
            size = int.from_bytes(data[pos + 8:pos + 16], 'big')
            header = 16
        elif size == 0:
            size = len(data) - pos
        if size < header or pos + size > len(data):
            return False
        pos += size
    return pos == len(data)


def dvui_bounds(data, pos=0):
    """DVUI ZIP bounds plus an optional length-prefixed XML filename index."""
    if data[pos:pos + 4] != b'DVUI' or pos + 20 > len(data):
        raise ValueError('Invalid DVUI header')
    start, end, size = struct.unpack_from('<III', data, pos + 8)
    if start != 20 or start + size != end or pos + end > len(data):
        raise ValueError('Invalid DVUI ZIP bounds')
    zip_start, zip_end = pos + start, pos + end
    end = zip_end
    if end + 8 <= len(data):
        length, count = struct.unpack_from('<II', data, end)
        if 4 <= length <= 1024 * 1024 and 0 < count <= 4096 and end + 4 + length <= len(data):
            cursor, limit = end + 8, end + 4 + length
            for _ in range(count):
                if cursor + 2 > limit:
                    break
                n = struct.unpack_from('<H', data, cursor)[0]
                cursor += 2
                if not 0 < n <= 1024 or cursor + n > limit or not data[cursor:cursor + n].endswith(b'.xml'):
                    break
                cursor += n
            else:
                if cursor == limit:
                    end = limit
    return zip_start, zip_end, end


def process_tree(input_dir, output_dir, *, phone='', flatten=False, dry_run=False, move=False):
    import Keitai_DumpProcessor as legacy
    inp, out = Path(input_dir).resolve(), Path(output_dir).resolve()
    if not inp.is_dir():
        raise ValueError('Input must be an extracted directory')
    if inp == out or out.is_relative_to(inp) or inp.is_relative_to(out):
        raise ValueError('Complete export requires separate, non-overlapping input/output trees')
    if out.exists() and any(out.iterdir()):
        raise ValueError('Complete export requires an empty output folder')
    files = sorted(p for p in inp.rglob('*') if p.is_file())
    report = dict(schema_version=1, mode='complete', input=str(inp), sources=[],
                  scope='Files present in supplied extracted tree; not deleted NAND recovery',
                  dry_run=dry_run, input_warnings=[])
    for directory in inp.rglob('*'):
        if directory.is_dir() and directory.suffix.lower() in {'.ilm', '.jar', '.ucp'}:
            report['input_warnings'].append(
                f'Directory named like an asset file: {directory.relative_to(inp).as_posix()}; verify upstream filesystem extraction')
    # Cache app descriptor names before --move can remove any descriptor sources.
    app_titles = {}
    for descriptor in files:
        if descriptor.parent.name == 'adf' and re.fullmatch(r'adffile\d+', descriptor.name):
            text = descriptor.read_text(encoding='cp932', errors='replace')
            match = re.search(r'^PackageURL\s*=\s*(.+)$', text, re.M)
            if match:
                app_titles[descriptor] = safe_name(Path(urlparse(match[1].strip()).path).stem)
    counts = Counter()
    if not dry_run:
        out.mkdir(parents=True, exist_ok=True)
    for src in files:
        rel = src.relative_to(inp)
        data = src.read_bytes()
        record = dict(source=rel.as_posix(), bytes=len(data), sha256=digest(data),
                      archived_source=(Path('_originals') / rel).as_posix(),
                      outputs=[], notes=[], status='preserved_only')
        if not dry_run:
            original = out / '_originals' / rel
            original.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, original)
            if digest(original.read_bytes()) != record['sha256']:
                raise OSError(f'Source archive verification failed: {rel}')
        # A group per source prevents flattening from mixing unrelated app slots,
        # archive members, or icon sets with identical filenames.
        source_group = safe_name(src.stem) + '_' + digest(rel.as_posix().encode())[:8]
        group = Path(source_group) if flatten else rel.parent / source_group

        def emit(payload, category, name, offset=None, validation='preserved', relative=None):
            name = safe_name(name)
            if phone and category in legacy.PHONE_SUFFIX_CATS:
                name = Path(name).stem + '_' + legacy.sanitize_tag(phone) + Path(name).suffix
            dest_rel = Path(category) / group / name if relative is None else Path(category) / group / relative
            dest = out / dest_rel
            if any(item['path'].casefold() == dest_rel.as_posix().casefold() for item in record['outputs']):
                raise ValueError(f'Duplicate output pathname: {dest_rel}')
            if not dest.resolve().is_relative_to(out):
                raise ValueError('Output path escapes destination')
            info = dict(path=dest_rel.as_posix(), bytes=len(payload), sha256=digest(payload),
                        offset=offset, validation=validation, category=category)
            if Path(name).suffix.lower() in IMAGE_EXTS:
                try:
                    info.update(image_info(payload))
                    info['validation'] = 'all image frames decoded'
                except Exception as error:
                    info['validation'] = 'image decode failed'
                    info['error'] = str(error)
                    dest_rel = Path('Corrupt') / dest_rel
                    dest = out / dest_rel
                    info['path'] = dest_rel.as_posix()
            if not dry_run:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with dest.open('xb') as f:
                    f.write(payload)
            record['outputs'].append(info)
            counts[category] += 1

        def emit_media(payload, name, offset=None, category=None):
            end, ext = media_end(payload)
            payload = payload[:end]
            if ext in IMAGE_EXTS:
                with Image.open(io.BytesIO(payload)) as im:
                    category = category or ('emoji' if ext == '.gif' and im.size == (20, 20) else
                                            'gifs' if ext == '.gif' else
                                            'camera photos' if legacy.is_camera_image(im) else
                                            {'.jpg': 'jpgs', '.png': 'png', '.bmp': 'bmp'}[ext])
            category = category or 'flash'
            emit(payload, category, Path(name).stem + ext, offset, 'media structure')
            return end

        def unpack_zip(payload, category='kisekae', prefix='content'):
            with zipfile.ZipFile(io.BytesIO(payload)) as z:
                members = [m for m in z.infolist() if not m.is_dir()]
                if len(members) > 20000 or sum(m.file_size for m in members) > MAX_ARCHIVE:
                    raise ValueError('Archive exceeds member/count limits')
                for member in members:
                    path = PurePosixPath(member.filename.replace('\\', '/'))
                    if (path.is_absolute() or '..' in path.parts or not path.parts
                            or ':' in member.filename or (member.external_attr >> 16) & 0o170000 == 0o120000):
                        raise ValueError('Unsafe archive member')
                    if member.file_size > MAX_MEMBER:
                        raise ValueError('Archive member too large')
                    content = z.read(member)  # ZIP CRC is checked by zipfile.
                    relative = Path(prefix, *(safe_name(p) for p in path.parts))
                    emit(content, category, path.name, validation='ZIP CRC checked', relative=relative)

        def mime_assets(raw):
            # Strip a single HTTP request/status line, retaining MIME headers.
            if raw.startswith((b'HTTP/', b'POST ', b'GET ')):
                raw = raw.split(b'\n', 1)[1]
            raw = legacy.preprocess_mhtml(raw)
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            n = 0
            extensions = {'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif',
                          'image/bmp': '.bmp', 'text/html': '.html',
                          'application/x-shockwave-flash': '.swf', 'application/pdf': '.pdf',
                          'video/3gpp': '.3gp', 'audio/midi': '.mid'}
            for index, part in enumerate(msg.walk()):
                if part.is_multipart():
                    continue
                ctype = part.get_content_type().lower()
                if ctype not in extensions:
                    continue
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                name = part.get_filename() or part.get('Content-Location') or f'part{index}'
                name = safe_name(Path(urlparse(name).path).stem or f'part{index}') + extensions[ctype]
                # Every part gets an index: identical Content-Location values are valid.
                name = f'{index:03d}_' + name
                if extensions[ctype] in IMAGE_EXTS | {'.swf'}:
                    emit_media(payload, name)
                else:
                    category = {'.html': 'html', '.pdf': 'pdf', '.3gp': 'videos', '.mid': 'midi'}[extensions[ctype]]
                    emit(payload, category, name, validation='MIME transfer decoded')
                n += 1
            return n

        try:
            ext = src.suffix.lower()
            parts = [p.lower() for p in rel.parts]
            is_nec_icons = 'icon' in parts[:-1] and re.fullmatch(r'ICON\d+(?:_\w+)?', src.name, re.I)
            slot = re.fullmatch(r'(jar|sp|adffile|sdffile|adf|amt)(\d+)', src.name)
            if not data:
                record['notes'].append('Empty source file')
            elif slot and 'javaap' in parts:
                kind, number = slot.groups()
                adf = src.parent.parent / 'adf' / f'adffile{number}'
                if src.parent.name == 'adf':
                    adf = src.parent / f'adffile{number}'
                title = 'app' + number
                title = app_titles.get(adf, title)
                group = (Path('appli-slots') / rel.parent.parent.parent / f'slot_{int(number):03d}')
                suffix = {'jar': '.jar', 'sp': '.sp', 'adffile': '.jam', 'sdffile': '.sdf', 'adf': '.adf', 'amt': '.amt'}[kind]
                if kind == 'jar':
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        if sum(m.file_size for m in z.infolist()) > MAX_ARCHIVE:
                            raise ValueError('JAR exceeds archive size limit')
                        if z.testzip() is not None:
                            raise ValueError('JAR CRC failure')
                emit(data, 'appli', title + suffix, validation='ZIP CRC checked' if kind == 'jar' else 'original NEC app component')
            elif is_nec_icons:
                pos = 0
                while pos < len(data):
                    if not any(data[pos:]):
                        break
                    try:
                        if data[pos:pos + 4] == b'DVUI' and pos + 20 <= len(data):
                            start, zip_end, end = dvui_bounds(data, pos)
                            unpack_zip(data[start:zip_end], 'system icons', f'dvui_{pos:08x}')
                            if end > zip_end:
                                emit(data[zip_end:end], 'system icons', f'dvui_{pos:08x}_index.bin', zip_end, 'DVUI filename table')
                            pos = end
                            continue
                        end, suffix = media_end(data, pos)
                        emit_media(data[pos:end], f'asset_{len(record["outputs"]):04d}{suffix}', pos, 'system icons')
                        pos = end
                    except ValueError as error:
                        record['notes'].append(f'Unparsed icon data at {pos:#x}: {error}')
                        break
            elif ext == '.img' and len(data) >= 472 and int.from_bytes(data[:4], 'little') in (2, 3):
                nsize = int.from_bytes(data[460:464], 'little')
                if not 0 < nsize <= 1024 or 472 + nsize > len(data):
                    raise ValueError('Invalid NEC message-image name length')
                name = data[468:468 + nsize].rstrip(b'\0').decode('cp932', errors='replace')
                size = int.from_bytes(data[468 + nsize:472 + nsize], 'little')
                start = 472 + nsize
                if not name.startswith('cid:') or start + size > len(data):
                    raise ValueError('Invalid NEC message-image payload length')
                emit_media(data[start:start + size], name[4:], start)
            elif ext == '.img' and any(data[n:n + 3] == b'\xff\xd8\xff' for n in (0, 0x80, 0xBC)):
                offset = legacy.img_payload_offset(src)
                emit_media(data[offset:], legacy.extract_img_header_name(src) + '.jpg', offset)
            elif data.startswith(b'DVUI') and len(data) >= 20:
                start, zip_end, end = dvui_bounds(data)
                unpack_zip(data[start:zip_end])
                if end > zip_end:
                    emit(data[zip_end:end], 'kisekae', 'file-index.bin', zip_end, 'DVUI filename table')
                record['notes'].append('DVUI wrapper retained in source archive')
            elif ext in ('.ucp', '.zip'):
                unpack_zip(data, 'kisekae' if ext == '.ucp' else 'archives')
            elif data.startswith(b'PK\x03\x04'):
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    members = z.infolist()
                    if sum(m.file_size for m in members) > MAX_ARCHIVE:
                        raise ValueError('Archive exceeds size limit')
                    if z.testzip() is not None:
                        raise ValueError('Archive CRC failure')
                    is_jar = ext == '.jar' or any(m.filename.endswith('.class') for m in members)
                if is_jar:
                    emit(data, 'appli', src.stem + '.jar', validation='ZIP CRC checked')
                else:
                    unpack_zip(data, 'archives')
            elif data.startswith((b'Decomail-Template', b'MIME-Version:', b'Content-Type:', b'HTTP/', b'POST ')) or ext in ('.dmt', '.mht'):
                mime_assets(data)
                record['notes'].append('Container/message retained; only recognized MIME asset parts exported')
            elif ext == '.afd':
                emit(data, 'charaden', src.name)
                for index, (start, end) in enumerate(find_gifs(data)):
                    emit(data[start:end], 'charaden', f'gif_{index:03d}.gif', start, 'GIF block structure')
            elif data.startswith(b'DLAN17') or ext == '.ilm':
                emit(data, 'illumination', src.name, validation='proprietary ILM retained; not rendered')
            elif data.startswith((b'VE3D', b'VF3D')) or ext in ('.vivid', '.vividsysfont'):
                emit(data, 'fonts and vector assets', src.name, validation='proprietary vector/font retained; not rendered')
            elif data[:4] in (b'E2J\0', b'J2E\0', b'KKG\0'):
                emit(data, 'dictionaries', src.name, validation='dictionary signature; proprietary data retained')
            elif iso_media(data):
                emit(data, 'videos', src.stem + '.3gp', validation='ISO media box lengths checked; playback not tested')
            elif data.startswith(b'ZVFA'):
                emit(data, 'book files', src.stem + '.zbf', validation='ZVFA signature; proprietary data retained')
            elif data.startswith(b'melo'):
                size = int.from_bytes(data[4:8], 'big') + 8
                if size > len(data) or size < 12:
                    raise ValueError('Invalid MFi length')
                emit(data[:size], 'melodies', src.stem + '.mld', validation='MFi declared length checked')
            elif data.startswith(b'MThd'):
                emit(data, 'midi', src.stem + '.mid', validation='MIDI signature')
            elif data.startswith((b'GIF87a', b'GIF89a', b'BM', b'\xff\xd8\xff', b'\x89PNG', b'FWS', b'CWS')):
                end = emit_media(data, src.name)
                if end < len(data) and any(data[end:]):
                    record['notes'].append(f'{len(data) - end} trailing bytes preserved in source archive')
            else:
                category, action = legacy.classify(src)
                if category and not action:
                    emit(data, category, src.name)
                elif ext in ('.m2t', '.mai', '.moi', '.inf') and 'dtv' in parts:
                    emit(data, 'videos', src.name, validation='DTV stream/sidecar retained; playback not tested')
                elif 'mail' in parts:
                    record['notes'].append('Mail data/metadata retained; proprietary parts may remain undecoded')
                else:
                    record['notes'].append('Unrecognized format retained for future decoding')
            if record['outputs']:
                record['status'] = 'exported'
            if any(p['validation'] == 'image decode failed' for p in record['outputs']):
                record['status'] = 'partial'
            if any(n.startswith(('Unparsed', 'Unrecognized')) for n in record['notes']):
                if record['outputs']:
                    record['status'] = 'partial'
        except Exception as error:
            record['status'] = 'error'
            record['notes'].append(str(error))
        # --move is lossless here: every source has a verified byte-exact archive,
        # including unsupported formats and files whose derivative export failed.
        if move and not dry_run:
            src.unlink()
        report['sources'].append(record)
    report['summary'] = dict(source_files=len(files), source_bytes=sum(r['bytes'] for r in report['sources']),
                             outputs=sum(counts.values()), categories=dict(counts),
                             statuses=dict(Counter(r['status'] for r in report['sources'])),
                             all_sources_archived=not dry_run,
                             input_warnings=len(report['input_warnings']))
    if not dry_run:
        (out / 'asset-manifest.json').write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding='utf8')
    print(json.dumps(report['summary'], indent=2))
    return report
