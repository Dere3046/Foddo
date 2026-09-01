import struct
import os
import subprocess
import tempfile


def _find_lz4_frames(data):
    frames = []
    pos = 0
    while pos + 8 <= len(data):
        magic = struct.unpack_from("<I", data, pos)[0]
        if magic != 0x184C2102:
            pos += 1
            continue
        block_size = struct.unpack_from("<I", data, pos + 4)[0]
        if block_size == 0 or block_size > 8 * 1024 * 1024:
            pos += 1
            continue
        if pos + 8 + block_size > len(data):
            break
        frames.append((pos, 8 + block_size))
        pos += 8 + block_size
    return frames


def decompress_lz4(data):
    from lz4.block import decompress as lz4block
    pos = 0
    result = bytearray()
    while pos + 8 <= len(data):
        magic = struct.unpack_from("<I", data, pos)[0]
        if magic != 0x184C2102:
            pos += 1
            continue
        block_size = struct.unpack_from("<I", data, pos + 4)[0]
        if block_size == 0 or block_size > 8 * 1024 * 1024 or pos + 8 + block_size > len(data):
            pos += 1
            continue
        try:
            dec = lz4block(data[pos + 8 : pos + 8 + block_size], 8 * 1024 * 1024)
            result += dec
            pos += 8 + block_size
            if len(dec) < 8 * 1024 * 1024:
                break
        except Exception:
            pos += 1
    return bytes(result)


def parse_cpio(data):
    entries = []
    pos = 0
    while pos + 110 <= len(data):
        magic = data[pos : pos + 6]
        if magic not in (b"070701", b"070702"):
            pos += 1
            continue
        raw = data[pos : pos + 110]
        try:
            filesize = int(raw[54:62], 16)
            namesize = int(raw[94:102], 16)
        except ValueError:
            pos += 1
            continue
        if namesize <= 0 or namesize > 4096 or filesize < 0 or filesize > 256 * 1024 * 1024:
            pos += 1
            continue
        name_off = pos + 110
        if name_off + namesize > len(data):
            break
        name = data[name_off : name_off + namesize]
        null = name.find(b"\x00")
        if null >= 0:
            name = name[:null]
        name_str = name.decode("utf-8", errors="replace")
        if name_str == "TRAILER!!!":
            break
        file_pad = (name_off + namesize + 3) & ~3
        if file_pad + filesize > len(data):
            break
        entries.append((name_str, filesize, data[file_pad : file_pad + filesize]))
        pos = (file_pad + filesize + 3) & ~3
    return entries


def scan_elf_symbols(ko_data, target=None, pattern=None):
    if len(ko_data) < 64 or ko_data[:4] != b"\x7fELF":
        return []
    is_64 = ko_data[4] == 2
    is_be = ko_data[5] == 2
    endian = ">Q" if is_be else "<Q"
    endian4 = ">I" if is_be else "<I"
    endian2 = ">H" if is_be else "<H"

    if is_64:
        e_shoff = struct.unpack_from(endian, ko_data, 40)[0]
        e_shentsize = struct.unpack_from(endian2, ko_data, 58)[0]
        e_shnum = struct.unpack_from(endian2, ko_data, 60)[0]
        e_shstrndx = struct.unpack_from(endian2, ko_data, 62)[0]
    else:
        e_shoff = struct.unpack_from(endian4, ko_data, 32)[0]
        e_shentsize = struct.unpack_from(endian2, ko_data, 46)[0]
        e_shnum = struct.unpack_from(endian2, ko_data, 48)[0]
        e_shstrndx = struct.unpack_from(endian2, ko_data, 50)[0]

    if not e_shentsize or not e_shnum:
        return []

    shstr_off = shstr_sz = None
    if e_shstrndx < e_shnum:
        hdr = e_shoff + e_shstrndx * e_shentsize
        if hdr + e_shentsize <= len(ko_data):
            if is_64:
                shstr_off = struct.unpack_from(endian, ko_data, hdr + 24)[0]
                shstr_sz = struct.unpack_from(endian, ko_data, hdr + 32)[0]
            else:
                shstr_off = struct.unpack_from(endian4, ko_data, hdr + 16)[0]
                shstr_sz = struct.unpack_from(endian4, ko_data, hdr + 20)[0]

    sections = []
    for i in range(e_shnum):
        hdr = e_shoff + i * e_shentsize
        if hdr + e_shentsize > len(ko_data):
            break
        if is_64:
            s = dict(zip(["name_idx", "type", "addr", "offset", "size", "link"],
                         [struct.unpack_from(endian4, ko_data, hdr)[0],
                          struct.unpack_from(endian4, ko_data, hdr + 4)[0],
                          struct.unpack_from(endian, ko_data, hdr + 16)[0],
                          struct.unpack_from(endian, ko_data, hdr + 24)[0],
                          struct.unpack_from(endian, ko_data, hdr + 32)[0],
                          struct.unpack_from(endian4, ko_data, hdr + 40)[0]]))
        else:
            s = dict(zip(["name_idx", "type", "addr", "offset", "size", "link"],
                         [struct.unpack_from(endian4, ko_data, hdr)[0],
                          struct.unpack_from(endian4, ko_data, hdr + 4)[0],
                          struct.unpack_from(endian4, ko_data, hdr + 12)[0],
                          struct.unpack_from(endian4, ko_data, hdr + 16)[0],
                          struct.unpack_from(endian4, ko_data, hdr + 20)[0],
                          struct.unpack_from(endian4, ko_data, hdr + 28)[0]]))
        sections.append(s)

    section_names = []
    for s in sections:
        name = ""
        if shstr_off is not None and s["name_idx"] >= 0:
            end = ko_data.find(b"\x00", shstr_off + s["name_idx"])
            if end != -1:
                name = ko_data[shstr_off + s["name_idx"] : end].decode("utf-8", errors="replace")
        section_names.append(name)

    symtab_s = strtab_s = None
    for i, s in enumerate(sections):
        if section_names[i] == ".symtab":
            symtab_s = s
        elif section_names[i] == ".strtab":
            strtab_s = s

    if not symtab_s or not strtab_s:
        return []

    sym_ent = 24 if is_64 else 16
    sym_data = ko_data[symtab_s["offset"] : symtab_s["offset"] + symtab_s["size"]]
    str_data = ko_data[strtab_s["offset"] : strtab_s["offset"] + strtab_s["size"]]

    results = []
    for i in range(symtab_s["size"] // sym_ent):
        ent = sym_data[i * sym_ent : (i + 1) * sym_ent]
        if len(ent) < sym_ent:
            break
        if is_64:
            st_name = struct.unpack_from(endian4, ent, 0)[0]
            st_value = struct.unpack_from(endian, ent, 8)[0]
            st_size = struct.unpack_from(endian4, ent, 16)[0]
            st_info = ent[4]
        else:
            st_name = struct.unpack_from(endian4, ent, 0)[0]
            st_value = struct.unpack_from(endian4, ent, 4)[0]
            st_size = struct.unpack_from(endian4, ent, 8)[0]
            st_info = ent[12]
        if st_name == 0 or st_name >= len(str_data):
            continue
        end = str_data.find(b"\x00", st_name)
        if end == -1:
            continue
        sym_name = str_data[st_name:end].decode("utf-8", errors="replace")

        if target and sym_name == target:
            results.append((sym_name, st_value, st_size, st_info, True))
        elif pattern and pattern in sym_name:
            results.append((sym_name, st_value, st_size, st_info, False))
        elif not target and not pattern:
            results.append((sym_name, st_value, st_size, st_info, False))

    return results


def list_elf_all(ko_data):
    return scan_elf_symbols(ko_data)


def scan_ko_file(path, func, list_flag):
    with open(path, "rb") as f:
        data = f.read(8 * 1024 * 1024)
    if list_flag:
        syms = list_elf_all(data)
        for name, val, sz, info, _ in syms:
            bind = ["LOCAL", "GLOBAL", "WEAK"][(info >> 4) & 3] if (info >> 4) < 3 else f"UNK({info>>4})"
            typ = ["NOTYPE", "OBJECT", "FUNC"][info & 0xF] if (info & 0xF) < 3 else f"UNK({info&0xF})"
            print(f"  {bind:6s} {typ:6s} 0x{val:016x} ({sz:4d}) {name}")
        return True
    syms = scan_elf_symbols(data, target=func)
    if syms:
        print(f"FOUND: in {os.path.basename(path)}")
        for name, val, sz, info, _ in syms:
            typ = ["NOTYPE", "OBJECT", "FUNC"][info & 0xF] if (info & 0xF) < 3 else f"UNK({info&0xF})"
            print(f"  {typ} value=0x{val:x} size={sz}")
        return True
    if func:
        print(f"{os.path.basename(path)}: {func} NOT FOUND")
    return False


def scan_ko_from_ramdisk(entries, func, list_flag):
    found_any = False
    for name, size, content in entries:
        if not name.endswith(".ko"):
            continue
        if list_flag:
            syms = list_elf_all(content)
            if syms:
                print(f"  {name}:")
                for sym_name, val, sz, info, _ in syms:
                    bind = ["LOCAL", "GLOBAL", "WEAK"][(info >> 4) & 3] if (info >> 4) < 3 else f"UNK({info>>4})"
                    typ = ["NOTYPE", "OBJECT", "FUNC"][info & 0xF] if (info & 0xF) < 3 else f"UNK({info&0xF})"
                    print(f"    {bind:6s} {typ:6s} 0x{val:016x} ({sz:4d}) {sym_name}")
            found_any = True
            continue
        syms = scan_elf_symbols(content, target=func)
        if syms:
            found_any = True
            print(f"  {name}:")
            for sym_name, val, sz, info, _ in syms:
                typ = ["NOTYPE", "OBJECT", "FUNC"][info & 0xF] if (info & 0xF) < 3 else f"UNK({info&0xF})"
                print(f"    {typ} value=0x{val:x} size={sz}")
    return found_any


def mount_and_scan(path, func, list_flag):
    mnt = tempfile.mkdtemp()
    rc = subprocess.run(["sudo", "mount", "-o", "loop,ro", path, mnt],
                        capture_output=True, timeout=15)
    if rc.returncode != 0:
        print(f"mount failed: {rc.stderr.decode(errors='replace')}")
        os.rmdir(mnt)
        return False

    found_any = False
    for dirpath, _, filenames in os.walk(mnt):
        for fn in filenames:
            if not fn.endswith(".ko"):
                continue
            full = os.path.join(dirpath, fn)
            with open(full, "rb") as f:
                content = f.read(8 * 1024 * 1024)
            if list_flag:
                syms = list_elf_all(content)
                if syms:
                    print(f"  {full[len(mnt)+1:]}:")
                    for sym_name, val, sz, info, _ in syms:
                        bind = ["LOCAL", "GLOBAL", "WEAK"][(info >> 4) & 3] if (info >> 4) < 3 else f"UNK({info>>4})"
                        typ = ["NOTYPE", "OBJECT", "FUNC"][info & 0xF] if (info & 0xF) < 3 else f"UNK({info&0xF})"
                        print(f"    {bind:6s} {typ:6s} 0x{val:016x} ({sz:4d}) {sym_name}")
                found_any = True
                continue
            syms = scan_elf_symbols(content, target=func)
            if syms:
                found_any = True
                rel = full[len(mnt) + 1:]
                print(f"  {rel}:")
                for sym_name, val, sz, info, _ in syms:
                    typ = ["NOTYPE", "OBJECT", "FUNC"][info & 0xF] if (info & 0xF) < 3 else f"UNK({info&0xF})"
                    print(f"    {typ} value=0x{val:x} size={sz}")
    subprocess.run(["sudo", "umount", mnt], capture_output=True, timeout=10)
    os.rmdir(mnt)
    return found_any


def scan_ramdisk_for_func(data, func, list_flag):
    lz4 = _find_lz4_frames(data)
    if not lz4:
        return None
    dec = decompress_lz4(data)
    entries = parse_cpio(dec)
    if not entries:
        return None
    return scan_ko_from_ramdisk(entries, func, list_flag)


def scan_kallsyms(data, func, list_flag):
    from .kallsyms import analyze_kallsyms, decompress_symbol_name, get_symbol_offset, parse_all_symbols

    info = analyze_kallsyms(data)

    if list_flag:
        symbols = parse_all_symbols(info, data)
        for name, sym_type, offset, size in symbols:
            print(f"  {sym_type} 0x{offset:08x} ({size:5d}) {name}")
        return True

    pos = info.names_offset
    for i in range(info.num_syms):
        sym_type, name, pos = decompress_symbol_name(info, data, pos)
        if sym_type is None:
            continue
        if name == func or (list_flag and func in name):
            offset = get_symbol_offset(info, data, i)
            size = 0
            for j in range(i + 1, info.num_syms):
                nxt = get_symbol_offset(info, data, j)
                if nxt != offset:
                    size = nxt - offset
                    break
            print(f"  {sym_type} 0x{offset:08x} ({size:5d}) {name}")

    pos = info.names_offset
    for i in range(info.num_syms):
        sym_type, name, pos = decompress_symbol_name(info, data, pos)
        if sym_type is None:
            continue
        if name == func:
            print(f"FOUND: {name}  type={sym_type}")
            return True

    if func:
        print(f"{func}: NOT FOUND in kernel Image")
    return False
