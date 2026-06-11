import argparse
import os
import struct

from .modscan import (scan_ko_file, mount_and_scan, decompress_lz4,
                      _find_lz4_frames, parse_cpio, scan_ko_from_ramdisk)
from .unpack import unpack_kernel

TARGET = "qcom_scm_update_rollback_version"


def detect(path):
    with open(path, "rb") as f:
        magic = f.read(8)
    if magic[:4] == b"\x7fELF":
        return "elf"
    if magic[:8] == b"ANDROID!":
        return "bootimg"
    if magic[:8] == b"VNDRBOOT":
        return "vendor_boot"
    with open(path, "rb") as f:
        f.seek(0x400)
        sb = f.read(64)
    if sb[56:58] == b"\x53\xef":
        return "ext"
    if magic[:4] in (b"\xe2\xe1\xf5\xe0", b"\xf1\xf3\xe1\xe2"):
        return "erofs"
    return "kernel"


def hexdump(data, start, length):
    end = min(start + length, len(data))
    for off in range(start, end, 16):
        chunk = data[off:off + 16]
        print(f"  {off:016x}:  {' '.join(f'{b:02x}' for b in chunk)}")


def disasm(data, start, length):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    except ImportError:
        print("  (capstone not installed)")
        return
    code = data[start:start + length]
    if not code:
        return
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for insn in md.disasm(code, start):
        print(f"  {insn.address:016x}:  {insn.mnemonic}\t{insn.op_str}")


def scan_kallsyms(data, func, list_flag, extract_func):
    from .kallsyms import (analyze_kallsyms, decompress_symbol_name,
                           get_symbol_offset, parse_all_symbols)
    info = analyze_kallsyms(data)

    if list_flag:
        for name, sym_type, offset, size in parse_all_symbols(info, data):
            print(f"  {sym_type} 0x{offset:08x} ({size:5d}) {name}")
        return True

    pos = info.names_offset
    for i in range(info.num_syms):
        sym_type, name, pos = decompress_symbol_name(info, data, pos)
        if sym_type is None:
            continue
        if name == func:
            offset = get_symbol_offset(info, data, i)
            size = 0
            for j in range(i + 1, info.num_syms):
                nxt = get_symbol_offset(info, data, j)
                if nxt != offset:
                    size = nxt - offset
                    break
            print(f"FOUND: {sym_type} 0x{offset:08x} ({size:5d}) {name}")
            if extract_func and size > 0:
                print()
                hexdump(data, offset, size)
                print()
                disasm(data, offset, size)
            return True
    print(f"  kernel: {func} NOT FOUND")
    return False


def handle_bootimg(path, func, list_flag, extract_func):
    found = False
    with open(path, "rb") as f:
        hdr = f.read(1648)
    page_sz = struct.unpack_from("<I", hdr, 36)[0] or 4096
    kernel_sz = struct.unpack_from("<I", hdr, 8)[0]
    ramdisk_sz = struct.unpack_from("<I", hdr, 16)[0]

    if kernel_sz > 0:
        try:
            raw = unpack_kernel(path)
            if scan_kallsyms(raw, func, list_flag, extract_func):
                found = True
        except Exception:
            pass

    if ramdisk_sz > 0:
        with open(path, "rb") as f:
            f.seek((page_sz + kernel_sz + page_sz - 1) // page_sz * page_sz)
            ram = f.read(ramdisk_sz)
        lz4 = _find_lz4_frames(ram)
        if lz4:
            dec = decompress_lz4(ram)
            entries = parse_cpio(dec)
            if list_flag:
                print(f"  init_boot ramdisk:")
                scan_ko_from_ramdisk(entries, func, list_flag, extract_func)
                return True
            if scan_ko_from_ramdisk(entries, func, list_flag, extract_func):
                found = True

    if not list_flag and not found and func:
        pass
    return found


def handle_vendor_boot(path, func, list_flag, extract_func):
    with open(path, "rb") as f:
        payload = f.read()[4096:]
    if not _find_lz4_frames(payload):
        print(f"  no LZ4 ramdisk found")
        return False

    entries = parse_cpio(decompress_lz4(payload))
    if not entries:
        print(f"  no cpio entries")
        return False

    found = scan_ko_from_ramdisk(entries, func, list_flag, extract_func)
    if not found and not list_flag and not extract_func and func:
        print(f"  {func}: NOT FOUND")
    return found


def handle_ext(path, func, list_flag, extract_func):
    found = mount_and_scan(path, func, list_flag, extract_func)
    if not list_flag and not found and func:
        print(f"  {func}: NOT FOUND")
    return found


def handle_elf(path, func, list_flag, extract_func):
    return scan_ko_file(path, func, list_flag, extract_func)


def handle_kernel(path, func, list_flag, extract_func):
    try:
        raw = unpack_kernel(path)
        return scan_kallsyms(raw, func, list_flag, extract_func)
    except Exception as e:
        print(f"  kernel parse error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="kernel function finder")
    parser.add_argument("files", nargs="+")
    parser.add_argument("--func", default=TARGET, help="function name to search")
    parser.add_argument("--list", nargs="?", const=True, default=False,
                        help="list symbols (optional pattern)")
    parser.add_argument("--extract", metavar="FUNC", nargs="?", const=True, default=False,
                        help="extract and disasm function")
    args = parser.parse_args()

    func = args.func
    extract_func = False
    if args.extract:
        extract_func = args.extract
        if args.extract is not True:
            func = args.extract

    for path in args.files:
        print(f"==> {os.path.basename(path)}")
        typ = detect(path)
        h = {"elf": handle_elf, "bootimg": handle_bootimg,
             "vendor_boot": handle_vendor_boot, "ext": handle_ext,
             "erofs": handle_ext, "kernel": handle_kernel}.get(typ)
        if h:
            h(path, func, args.list, extract_func)
        else:
            print(f"  unknown type")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
