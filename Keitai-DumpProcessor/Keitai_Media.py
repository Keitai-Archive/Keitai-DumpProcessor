"""Bounded media parsing for embedded assets; never split on a raw trailer byte."""
import io
import struct
import zlib
from PIL import Image


def gif_end(data, start=0):
    if data[start:start + 6] not in (b'GIF87a', b'GIF89a') or start + 13 > len(data):
        raise ValueError('Invalid GIF header')
    pos = start + 13
    packed = data[start + 10]
    if packed & 128:
        pos += 3 * (2 << (packed & 7))
    while pos < len(data):
        marker = data[pos]
        pos += 1
        if marker == 0x3B:
            return pos
        if marker == 0x21:
            pos += 1  # extension label, followed by size-prefixed sub-blocks
        elif marker == 0x2C:
            if pos + 9 > len(data):
                raise ValueError('Truncated GIF descriptor')
            packed = data[pos + 8]
            pos += 9
            if packed & 128:
                pos += 3 * (2 << (packed & 7))
            pos += 1  # LZW minimum code size
        else:
            raise ValueError('Invalid GIF block')
        while pos < len(data):
            size = data[pos]
            pos += 1
            if size == 0:
                break
            pos += size
        else:
            raise ValueError('Truncated GIF sub-blocks')
    raise ValueError('Truncated GIF')


def find_gifs(data):
    result = []
    pos = 0
    while pos < len(data):
        found = [p for p in (data.find(b'GIF87a', pos), data.find(b'GIF89a', pos)) if p >= 0]
        if not found:
            break
        start = min(found)
        try:
            end = gif_end(data, start)
            result.append((start, end))
            pos = end
        except ValueError:
            pos = start + 6
    return result


def image_info(payload):
    with Image.open(io.BytesIO(payload)) as im:
        im.verify()
    with Image.open(io.BytesIO(payload)) as im:
        # GIF verification/loading of just frame zero misses damaged animations.
        for frame in range(getattr(im, 'n_frames', 1)):
            im.seek(frame)
            im.load()
        return dict(width=im.width, height=im.height, frames=getattr(im, 'n_frames', 1))


def media_end(data, start=0):
    head = data[start:start + 12]
    if head.startswith((b'GIF87a', b'GIF89a')):
        return gif_end(data, start), '.gif'
    if head.startswith(b'BM') and start + 26 <= len(data):
        size = struct.unpack_from('<I', data, start + 2)[0]
        pixels = struct.unpack_from('<I', data, start + 10)[0]
        if not 26 <= pixels <= size or start + size > len(data):
            raise ValueError('Invalid BMP length')
        return start + size, '.bmp'
    if head.startswith(b'\xff\xd8\xff'):
        pos = start + 2
        # Skip length-delimited segments (including EXIF thumbnails) and JPEG
        # entropy byte stuffing/restart markers before accepting the outer EOI.
        while pos < len(data):
            pos = data.find(b'\xff', pos)
            if pos < 0 or pos + 1 >= len(data):
                break
            marker = data[pos + 1]
            pos += 2
            if marker == 0xD9:
                return pos, '.jpg'
            if marker == 0xFF:
                pos -= 1
                continue
            if marker == 0 or 0xD0 <= marker <= 0xD8 or marker == 1:
                continue
            if pos + 2 > len(data):
                break
            size = struct.unpack_from('>H', data, pos)[0]
            if size < 2:
                raise ValueError('Invalid JPEG segment')
            pos += size
        raise ValueError('Truncated JPEG')
    if head.startswith(b'\x89PNG\r\n\x1a\n'):
        pos = start + 8
        while pos + 12 <= len(data):
            size = struct.unpack_from('>I', data, pos)[0]
            end = pos + size + 12
            if end > len(data):
                break
            if zlib.crc32(data[pos + 4:end - 4]) & 0xFFFFFFFF != struct.unpack_from('>I', data, end - 4)[0]:
                raise ValueError('PNG CRC mismatch')
            kind = data[pos + 4:pos + 8]
            pos = end
            if kind == b'IEND':
                return end, '.png'
        raise ValueError('Truncated PNG')
    if head.startswith((b'FWS', b'CWS')) and len(head) >= 8:
        size = struct.unpack_from('<I', head, 4)[0]
        if not 8 <= size <= 128 * 1024 * 1024:
            raise ValueError('Invalid SWF declared length')
        if head.startswith(b'FWS'):
            if start + size > len(data):
                raise ValueError('Truncated SWF')
            return start + size, '.swf'
        decoder = zlib.decompressobj()
        raw = data[start + 8:]
        expanded = decoder.decompress(raw, size - 8 + 1)
        if not decoder.eof or len(expanded) != size - 8:
            raise ValueError('Invalid compressed SWF')
        return start + 8 + len(raw) - len(decoder.unused_data), '.swf'
    raise ValueError('No supported media signature')
