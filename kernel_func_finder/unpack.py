import gzip
import lzma
import struct
import io


def _is_gzip(data):
    return data[:2] == b"\x1f\x8b"


def _is_xz(data):
    return data[:6] == b"\xfd7zXZ\x00"


def _is_lzma(data):
    return data[:3] in (b"]\x00\x00", b"\x6d\x00\x00")


def _is_bootimg(data):
    return data[:8] == b"ANDROID!"


def _is_uimage(data):
    return len(data) >= 64 and struct.unpack_from(">I", data, 0)[0] == 0x27051956


def _is_arm64_image(data):
    if len(data) < 64:
        return False
    if data[:4] == b"\x7fELF":
        return False
    if _is_gzip(data) or _is_xz(data) or _is_lzma(data):
        return False
    if _is_bootimg(data) or _is_uimage(data):
        return False

    code0 = struct.unpack_from("<I", data, 0)[0]
    if code0 == 0x14000008:
        return True

    return b"Linux version " in data


def _decompress_gzip(data):
    return gzip.decompress(data)


def _decompress_xz(data):
    return lzma.decompress(data)


def _decompress_lzma(data):
    props = data[0:5]
    decomp = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    return decomp.decompress(data)


def _extract_bootimg(data):
    if len(data) < 1648:
        return data

    header_version = struct.unpack_from("<I", data, 40)[0]
    kernel_size = struct.unpack_from("<I", data, 8)[0]
    page_size = struct.unpack_from("<I", data, 36)[0]

    if kernel_size > 128 * 1024 * 1024:
        return data

    if header_version == 0:
        actual_offset = page_size if page_size else 2048
    else:
        actual_offset = page_size if page_size else 4096

    start = actual_offset
    end = min(start + kernel_size, len(data))
    return data[start:end]


def _extract_uimage(data):
    if len(data) < 64:
        return data
    data_size = struct.unpack_from(">I", data, 12)[0]
    start = 64
    end = min(start + data_size, len(data))
    return data[start:end]


def unpack_kernel(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    if not data:
        raise ValueError("empty file")

    for _ in range(5):
        if _is_gzip(data):
            data = _decompress_gzip(data)
        elif _is_xz(data):
            data = _decompress_xz(data)
        elif _is_lzma(data):
            data = _decompress_lzma(data)
        elif _is_bootimg(data):
            data = _extract_bootimg(data)
        elif _is_uimage(data):
            data = _extract_uimage(data)
        else:
            break

        if b"Linux version " in data:
            break

    if b"Linux version " not in data:
        raise ValueError("no Linux version string found after decompression, not a valid kernel image")

    return data
