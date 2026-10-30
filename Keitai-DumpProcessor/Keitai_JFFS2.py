#!/usr/bin/env python3
"""Extract one JFFS2 partition without mixing inode namespaces or stale names.

Supports NONE, ZERO, COPY and ZLIB compression. Other compression methods fail
explicitly per file instead of silently producing zero-filled data. Input must
already have NAND OOB bytes removed (e.g. KTdumper's onenand.bin).
"""
import argparse
from collections import defaultdict
import json
import mmap
from pathlib import Path
import stat
import struct
import zlib


def crc(data):
    return (zlib.crc32(data, -1) ^ -1) & 0xFFFFFFFF


def scan(data, start, end):
    """Keep newest dirents by (parent, name), including ino=0 deletions."""
    entries = {}
    inodes = defaultdict(list)
    rejected = defaultdict(int)
    pos = start
    while True:
        pos = data.find(b'\x85\x19', pos, end)
        if pos < 0 or pos + 12 > end:
            break
        _, kind, length, header_crc = struct.unpack_from('<HHII', data, pos)
        if (length < 12 or pos + length > end
                or crc(data[pos:pos + 8]) != header_crc):
            pos += 1
            continue
        if kind == 0xE001 and length >= 40:
            parent, version, ino, _, nsize, dtype = struct.unpack_from('<IIIIBB', data, pos + 12)
            node_crc, name_crc = struct.unpack_from('<II', data, pos + 32)
            name = data[pos + 40:pos + 40 + nsize]
            if (40 + nsize > length or crc(data[pos:pos + 32]) != node_crc
                    or crc(name) != name_crc):
                rejected['dirent_crc_or_length'] += 1
            else:
                key = parent, name
                entry = dict(parent=parent, version=version, ino=ino,
                             name=name, dtype=dtype, pos=pos)
                if key not in entries or (version, pos) > (entries[key]['version'], entries[key]['pos']):
                    entries[key] = entry
        elif kind == 0xE002 and length >= 68:
            fields = struct.unpack_from('<IIIHHIIIIIIIBBHII', data, pos + 12)
            ino, version, mode, _, _, size, _, mtime, _, offset, csize, dsize, compr, _, _, data_crc, node_crc = fields
            if (68 + csize > length or crc(data[pos:pos + 60]) != node_crc
                    or crc(data[pos + 68:pos + 68 + csize]) != data_crc):
                rejected['inode_crc_or_length'] += 1
            else:
                inodes[ino].append(dict(pos=pos, version=version, mode=mode,
                                       size=size, offset=offset, csize=csize,
                                       dsize=dsize, compr=compr, mtime=mtime))
        pos += (length + 3) & ~3
    # Independent filesystems in full NAND dumps commonly reuse inode 2. The
    # caller must bound the partition rather than replay unrelated nodes together.
    roots = defaultdict(set)
    for entry in entries.values():
        if entry['parent'] == 1 and entry['ino'] and entry['dtype'] == 4:
            roots[entry['ino']].add(entry['name'])
    if any(len(names) > 1 for names in roots.values()):
        raise ValueError('Ambiguous root directories: likely multiple JFFS2 partitions. '
                         'Supply --offset and --length for ONE partition.')
    return entries, inodes, dict(rejected)


def rebuild(data, nodes, max_file_size):
    """Replay checked fragments by version, applying file truncations."""
    result = bytearray()
    for node in sorted(nodes, key=lambda n: (n['version'], n['pos'])):
        size, offset, dsize = node['size'], node['offset'], node['dsize']
        if max(size, offset + dsize) > max_file_size:
            raise ValueError('Inode exceeds --max-file-size')
        if len(result) > size:
            del result[size:]
        if len(result) < size:
            result.extend(b'\0' * (size - len(result)))
        raw = data[node['pos'] + 68:node['pos'] + 68 + node['csize']]
        if node['compr'] in (0, 4):
            payload = raw
        elif node['compr'] == 1:
            payload = b'\0' * dsize
        elif node['compr'] == 6:
            decoder = zlib.decompressobj()
            payload = decoder.decompress(raw, dsize + 1)
            if not decoder.eof or decoder.unconsumed_tail:
                raise ValueError('Invalid or oversized ZLIB fragment')
        else:
            raise ValueError(f"Unsupported JFFS2 compression {node['compr']}")
        if len(payload) != dsize:
            raise ValueError('Decompressed fragment length mismatch')
        # Clip to this version's EOF; never retain stale trailing bytes.
        count = min(dsize, max(0, size - offset))
        if count:
            result[offset:offset + count] = payload[:count]
    return bytes(result)


def extract(raw, destination, offset=0, length=None, max_file_size=512 * 1024 * 1024):
    raw, destination = Path(raw).resolve(), Path(destination).resolve()
    if destination.exists() and any(destination.iterdir()):
        raise ValueError('Destination must be empty; use a fresh folder')
    total_size = raw.stat().st_size
    end = total_size if length is None else offset + length
    if not 0 <= offset < end <= total_size:
        raise ValueError('Partition range is outside the input file')
    report = dict(input=str(raw), offset=offset, length=end - offset,
                  files=[], skipped=[], errors=[])
    with raw.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        entries, inodes, report['rejected_nodes'] = scan(data, offset, end)
        if not entries:
            raise ValueError('No supported little-endian JFFS2 directory entries found')
        children = defaultdict(list)
        for entry in entries.values():
            if entry['ino']:
                children[entry['parent']].append(entry)
        destination.mkdir(parents=True, exist_ok=True)
        pending = [(1, Path(), frozenset({1}))]
        while pending:
            parent, relative, ancestors = pending.pop()
            for entry in children[parent]:
                try:
                    name = entry['name'].decode('utf8')
                    if name in ('', '.', '..') or any(c in name for c in '/\\\0:'):
                        raise ValueError('Unsafe filename')
                    rel = relative / name
                    target = destination / rel
                    if not target.resolve().is_relative_to(destination):
                        raise ValueError('Path escapes output directory')
                    ino = entry['ino']
                    nodes = inodes.get(ino)
                    if not nodes:
                        raise ValueError(f'Missing valid inode {ino}')
                    newest = max(nodes, key=lambda n: (n['version'], n['pos']))
                    if stat.S_ISDIR(newest['mode']):
                        if ino in ancestors:
                            raise ValueError('Directory cycle')
                        target.mkdir(parents=True, exist_ok=True)
                        pending.append((ino, rel, ancestors | {ino}))
                    elif stat.S_ISREG(newest['mode']):
                        payload = rebuild(data, nodes, max_file_size)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        # Refuse collisions, including case-folding collisions on Windows.
                        with target.open('xb') as output:
                            output.write(payload)
                        report['files'].append(dict(path=rel.as_posix(), inode=ino,
                                                    size=len(payload), fragments=len(nodes)))
                    else:
                        report['skipped'].append(dict(path=rel.as_posix(), inode=ino,
                                                      reason='Non-regular file (e.g. symlink)'))
                except (OSError, ValueError, UnicodeError) as error:
                    report['errors'].append(dict(parent=str(relative),
                                                 name=repr(entry['name']), error=str(error)))
    (destination / '_jffs2_report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    return report


def integer(value):
    return int(value, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--offset', type=integer, default=0, help='Partition start, decimal or 0xHEX')
    parser.add_argument('--length', type=integer, help='Partition byte length, decimal or 0xHEX')
    parser.add_argument('--max-file-size', type=integer, default=512 * 1024 * 1024)
    args = parser.parse_args()
    try:
        report = extract(args.input, args.output, args.offset, args.length, args.max_file_size)
    except (OSError, ValueError) as error:
        parser.exit(1, f'Extraction failed: {error}\n')
    print(f"Extracted {len(report['files'])} files; {len(report['errors'])} errors; "
          f"{len(report['skipped'])} non-regular files skipped; "
          f"{sum(report['rejected_nodes'].values())} invalid nodes rejected")
    return 1 if report['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
