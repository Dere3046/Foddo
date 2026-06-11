import struct
import re

KSYM_TOKEN_NUMS = 256
KSYM_MIN_NEQ_SYMS = 25600
KSYM_MIN_MARKER = 100
KSYM_FIND_NAMES_USED_MARKER = 5
ELF64_KERNEL_MIN_VA = 0xFFFFFF8008080000
ELF64_KERNEL_MAX_VA = 0xFFFFFFFFFFFFFFFF
ARM64_RELO_MIN_NUM = 4000


class KallsymsInfo:
    def __init__(self):
        self.is_be = 0
        self.asm_long_size = 4
        self.asm_ptr_size = 8
        self.try_relo = 1
        self.kernel_base = 0
        self.relo_applied = 0
        self._marker_num = 0
        self._approx_num = 0
        self._approx_start = 0
        self._approx_end = 0
        self.has_relative_base = 1

        self.token_table_offset = 0
        self.token_index_offset = 0
        self.markers_offset = 0
        self.names_offset = 0
        self.num_syms_offset = 0
        self.num_syms = 0
        self.offsets_offset = 0
        self.addresses_offset = 0

        self.token_table = [b""] * KSYM_TOKEN_NUMS
        self.symbols = []

        self.is_kallsyms_all_yes = 1


def _le32(data, off):
    return struct.unpack_from("<i", data, off)[0]


def _ule32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _ule64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def _ule16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def _ube16(data, off):
    return struct.unpack_from(">H", data, off)[0]


def _uint(data, off, size, is_be):
    if size == 8:
        return struct.unpack_from(">Q" if is_be else "<Q", data, off)[0]
    elif size == 4:
        return struct.unpack_from(">I" if is_be else "<I", data, off)[0]
    return 0


def _int(data, off, size, is_be):
    if size == 8:
        return struct.unpack_from(">q" if is_be else "<q", data, off)[0]
    elif size == 4:
        return struct.unpack_from(">i" if is_be else "<i", data, off)[0]
    return 0


def find_token_table(info, data):
    seq = b"".join(b"%c\0" % i for i in range(ord("0"), ord("9") + 1))

    skip_seqs = [b":\0", b"\0\0", b"\0\1", b"\0\2", b"ASCII\0"]

    candidates = []
    candidates_strict = []

    pos = 0
    while True:
        pos = data.find(seq, pos + 1)
        if pos == -1:
            break
        after = pos + len(seq)
        for skip in skip_seqs:
            if data[after : after + len(skip)] == skip:
                break
        else:
            candidates.append(pos)
            if after < len(data) and data[after : after + 1].isalnum():
                candidates_strict.append(pos)

    if len(candidates_strict) == 1:
        candidates = candidates_strict
    elif len(candidates) == 0:
        return -1
    elif len(candidates) > 1:
        return -1

    pos = candidates[0]

    position = pos - 1
    assert position >= 0 and data[position] == 0

    for _ in range(ord("0")):
        for __ in range(50):
            position -= 1
            assert position >= 0
            if data[position] == 0 or data[position] > ord("z"):
                break

    position += 1
    position += -position % 4

    info.token_table_offset = position

    p = position
    for i in range(KSYM_TOKEN_NUMS):
        end = data.find(b"\x00", p)
        if end == -1:
            break
        info.token_table[i] = data[p:end]
        p = end + 1

    return 0


def find_token_index(info, data):
    token_count = info.token_table_offset
    for i in range(KSYM_TOKEN_NUMS):
        if not info.token_table[i]:
            token_count += 1
        else:
            token_count += len(info.token_table[i]) + 1

    le_index = bytearray()
    be_index = bytearray()
    offset = info.token_table_offset
    for i in range(KSYM_TOKEN_NUMS):
        tok_off = offset - info.token_table_offset
        le_index += struct.pack("<H", tok_off)
        be_index += struct.pack(">H", tok_off)
        while offset < len(data) and data[offset] != 0:
            offset += 1
        offset += 1

    lepos = data.find(bytes(le_index))
    bepos = data.find(bytes(be_index))

    if lepos == -1 and bepos == -1:
        return -1

    info.is_be = 0 if lepos != -1 else 1
    pos = lepos if lepos != -1 else bepos
    info.token_index_offset = pos
    return 0


def find_markers(info, data):
    elem_size = info.asm_long_size

    def try_size(es):
        cand = info.token_table_offset - es
        last_marker = len(data)
        count = 0
        while cand > 0x10000:
            marker = _uint(data, cand, es, info.is_be)
            if last_marker > marker:
                count += 1
                if marker == 0 and count > KSYM_MIN_MARKER:
                    break
            else:
                count = 0
                last_marker = len(data)
            last_marker = marker
            cand -= es

        if count < KSYM_MIN_MARKER:
            return -1
        info.markers_offset = cand
        info._marker_num = count
        return 0

    rc = try_size(elem_size)
    if rc and elem_size == 8:
        rc = try_size(4)
    return rc


def find_approx_offsets(info, data):
    elem_size = info.asm_long_size
    sym_num = 0
    prev_offset = 0

    for cand in range(0, len(data) - KSYM_MIN_NEQ_SYMS * elem_size, elem_size):
        offset = _int(data, cand, elem_size, info.is_be)
        if sym_num == 0:
            if offset == 0:
                continue
            prev_offset = offset
            sym_num = 1
            continue
        if offset == prev_offset:
            continue
        elif offset > prev_offset:
            prev_offset = offset
            sym_num += 1
            if sym_num >= KSYM_MIN_NEQ_SYMS:
                break
        else:
            prev_offset = 0
            sym_num = 0

    if sym_num < KSYM_MIN_NEQ_SYMS:
        return -1

    cand -= KSYM_MIN_NEQ_SYMS * elem_size

    while cand >= elem_size and _int(data, cand, elem_size, info.is_be) != 0:
        cand -= elem_size
    zero_count = 0
    while cand >= elem_size and _int(data, cand, elem_size, info.is_be) == 0:
        cand -= elem_size
        zero_count += 1
        if zero_count > 10:
            break
    cand += elem_size

    approx_start = cand
    prev_offset = 0
    while cand < len(data) - elem_size:
        offset = _int(data, cand, elem_size, info.is_be)
        if offset < prev_offset:
            break
        prev_offset = offset
        cand += elem_size
    approx_end = cand

    info._approx_start = approx_start
    info._approx_end = approx_end
    info._approx_num = (approx_end - approx_start) // elem_size
    info.has_relative_base = 1
    return 0


def find_approx_addresses(info, data):
    elem_size = info.asm_ptr_size
    sym_num = 0
    prev_addr = 0

    for cand in range(0, len(data) - KSYM_MIN_NEQ_SYMS * elem_size, elem_size):
        addr = _uint(data, cand, elem_size, info.is_be)
        if sym_num == 0:
            if addr & 0xFF:
                continue
            if elem_size == 4 and (addr & 0xFF800000) != 0xFF800000:
                continue
            if elem_size == 8 and (addr & 0xFFFF000000000000) != 0xFFFF000000000000:
                continue
            prev_addr = addr
            sym_num = 1
            continue
        if addr >= prev_addr:
            prev_addr = addr
            sym_num += 1
            if sym_num >= KSYM_MIN_NEQ_SYMS:
                break
        else:
            prev_addr = 0
            sym_num = 0

    if sym_num < KSYM_MIN_NEQ_SYMS:
        return -1

    cand -= KSYM_MIN_NEQ_SYMS * elem_size
    approx_start = cand
    prev_addr = 0
    while cand < len(data) - elem_size:
        addr = _uint(data, cand, elem_size, info.is_be)
        if addr < prev_addr:
            break
        prev_addr = addr
        cand += elem_size
    approx_end = cand

    info._approx_start = approx_start
    info._approx_end = approx_end
    info._approx_num = (approx_end - approx_start) // elem_size
    info.has_relative_base = 0
    return 0


def find_approx_addresses_or_offset(info, data):
    rc = find_approx_offsets(info, data)
    if rc:
        rc = find_approx_addresses(info, data)
    return rc


def decompress_symbol_name(info, data, pos):
    p = pos
    length = data[p]
    p += 1
    if length > 0x7F:
        length = (length & 0x7F) + (data[p] << 7)
        p += 1
    if length == 0 or length >= 512:
        return None, None, pos

    sym_type = None
    name = bytearray()
    for i in range(length):
        tok = data[p + i]
        if tok >= KSYM_TOKEN_NUMS:
            return None, None, pos
        token = info.token_table[tok]
        if i == 0:
            sym_type = chr(token[0])
            name += token[1:]
        else:
            name += token

    return sym_type, bytes(name).decode("ascii", errors="replace"), p + length


def verify_names_candidate(info, data, elem_size, cand):
    p = cand
    for i in range(KSYM_FIND_NAMES_USED_MARKER * 256 + 1):
        if p >= info.markers_offset:
            return -1
        length = data[p]
        p += 1
        if length > 0x7F:
            if p >= info.markers_offset:
                return -1
            length = (length & 0x7F) + (data[p] << 7)
            p += 1
        if length == 0 or length >= 512:
            return -1
        if p + length > info.markers_offset:
            return -1
        p += length
        if p >= info.markers_offset:
            return -1

        if i and (i & 0xFF) == 0xFF:
            marker_idx = (i >> 8) + 1
            if marker_idx >= info._marker_num:
                return -1
            marker_off = info.markers_offset + marker_idx * elem_size
            mark_len = _int(data, marker_off, elem_size, info.is_be)
            if p - cand != mark_len:
                return -1
    return 0


def find_names(info, data):
    elem_size = info.asm_long_size

    if info._marker_num > KSYM_FIND_NAMES_USED_MARKER:
        last_marker = _int(data, info.markers_offset + (info._marker_num - 1) * elem_size, elem_size, info.is_be)
        guess = info.markers_offset - last_marker
        guess_start = max(guess - 0x10000, 0x4000)
        guess_end = min(guess + 0x1000, info.markers_offset)
        for cand in range(guess_start, guess_end):
            if verify_names_candidate(info, data, elem_size, cand) == 0:
                info.names_offset = cand
                return 0

    for cand in range(0x4000, info.markers_offset):
        if verify_names_candidate(info, data, elem_size, cand) == 0:
            info.names_offset = cand
            return 0

    return -1


def find_num_syms(info, data):
    approx_end = info.names_offset
    approx_num = info._approx_num

    for cand in range(approx_end, max(approx_end - 4096, 0), -4):
        nsyms = _int(data, cand, 4, info.is_be)
        if nsyms == 0:
            continue
        if abs(approx_num - nsyms) > 10:
            continue
        info.num_syms = nsyms
        info.num_syms_offset = cand
        break

    if info.num_syms == 0:
        info.num_syms = approx_num - 10
    return 0


def find_linux_banner(info, data):
    prefix = b"Linux version "
    banners = []
    pos = 0
    while True:
        p = data.find(prefix, pos)
        if p == -1:
            break
        ch = data[p + len(prefix) : p + len(prefix) + 1]
        if ch and ch[0] >= ord("0") and ch[0] <= ord("9"):
            if p + len(prefix) + 1 < len(data) and data[p + len(prefix) + 1] == ord("."):
                banners.append(p)
        pos = p + 1

    if not banners:
        return -1

    info._banner_offsets = banners
    return 0


def correct_addresses_or_offsets(info, data):
    if find_linux_banner(info, data):
        info.is_kallsyms_all_yes = 0
        return correct_by_vectors(info, data)

    rc = correct_by_banner(info, data)
    if rc:
        rc = correct_by_vectors(info, data)
    return rc


def correct_by_banner(info, data):
    elem_size = info.asm_long_size if info.has_relative_base else info.asm_ptr_size
    pos = info.names_offset
    index = 0
    banner_idx = -1

    while pos < info.markers_offset:
        sym_type, name, pos = decompress_symbol_name(info, data, pos)
        if sym_type is None:
            break
        if name == "linux_banner":
            banner_idx = index
            break
        index += 1

    if banner_idx < 0:
        return -1

    info.is_kallsyms_all_yes = 1

    for banner_off in info._banner_offsets:
        for cand in range(info._approx_start, info._approx_start + 4096 + elem_size, elem_size):
            base = _uint(data, cand, elem_size, info.is_be)
            offset = _uint(data, cand + banner_idx * elem_size, elem_size, info.is_be) - base
            if offset == banner_off:
                if info.has_relative_base:
                    info.offsets_offset = cand
                else:
                    info.addresses_offset = cand
                    info.kernel_base = _uint(data, info.addresses_offset, elem_size, info.is_be)
                return 0

    return -1


def correct_by_vectors(info, data):
    elem_size = info.asm_long_size if info.has_relative_base else info.asm_ptr_size
    pos = info.names_offset
    index = 0
    vector_idx = -1

    while pos < info.markers_offset:
        sym_type, name, pos = decompress_symbol_name(info, data, pos)
        if sym_type is None:
            break
        if name == "vectors":
            vector_idx = index
            break
        index += 1

    if vector_idx < 0:
        return -1

    base_candidates = [0]
    if not info.has_relative_base:
        base = _uint(data, info._approx_start, elem_size, info.is_be)
        base_candidates = [base, info.kernel_base, ELF64_KERNEL_MIN_VA]
        base_candidates = [b for b in base_candidates if b]

    max_shift = max(info._approx_num - info.num_syms, 0)
    search_end = info._approx_start + (max_shift + 1) * elem_size
    pid_vnr_limit = info._approx_end - vector_idx * elem_size
    search_end = min(search_end, pid_vnr_limit)

    for base in base_candidates:
        if info.has_relative_base:
            base = 0
        for cand in range(info._approx_start, search_end, elem_size):
            vec_off = _uint(data, cand + vector_idx * elem_size, elem_size, info.is_be) - base
            vec_next = _uint(data, cand + vector_idx * elem_size + elem_size, elem_size, info.is_be) - base
            if vec_next - vec_off >= 0x600 and (vec_off & 0x7FF) == 0:
                if info.has_relative_base:
                    info.offsets_offset = cand
                else:
                    info.addresses_offset = cand
                    info.kernel_base = base
                return 0

    return -1


def get_symbol_offset(info, data, idx):
    if info.has_relative_base:
        elem_size = info.asm_long_size
        start = info.offsets_offset
        return _uint(data, start + idx * elem_size, elem_size, info.is_be)
    else:
        elem_size = info.asm_ptr_size
        start = info.addresses_offset
        target = _uint(data, start + idx * elem_size, elem_size, info.is_be)
        return int(target - info.kernel_base)


def is_symbol_exists(info, data, symbol):
    pos = info.names_offset
    for i in range(info.num_syms):
        sym_type, name, pos = decompress_symbol_name(info, data, pos)
        if sym_type is None:
            return False
        if name == symbol:
            return True
    return False


def get_symbol_offset_and_size(info, data, symbol):
    pos = info.names_offset
    for i in range(info.num_syms):
        sym_type, name, pos = decompress_symbol_name(info, data, pos)
        if sym_type is None:
            continue
        if name == symbol:
            offset = get_symbol_offset(info, data, i)
            size = 0
            for j in range(i + 1, info.num_syms):
                nxt = get_symbol_offset(info, data, j)
                if nxt != offset:
                    size = nxt - offset
                    break
            return offset, size, sym_type
    return None, 0, None


def analyze_kallsyms(data):
    info = KallsymsInfo()

    steps = [
        (find_token_table, "token_table"),
        (find_token_index, "token_index"),
        (find_markers, "markers"),
        (find_approx_addresses_or_offset, "approx_offsets"),
        (find_names, "names"),
        (find_num_syms, "num_syms"),
        (correct_addresses_or_offsets, "correct_offsets"),
    ]

    for fn, name in steps:
        rc = fn(info, data)
        if rc:
            raise ValueError(f"kallsyms parse failed at {name}: {rc}")

    return info


def parse_all_symbols(info, data):
    symbols = []
    pos = info.names_offset
    for i in range(info.num_syms):
        sym_type, name, pos = decompress_symbol_name(info, data, pos)
        if sym_type is None:
            break
        offset = get_symbol_offset(info, data, i)
        size = 0
        for j in range(i + 1, info.num_syms):
            nxt = get_symbol_offset(info, data, j)
            if nxt != offset:
                size = nxt - offset
                break
        symbols.append((name, sym_type, offset, size))
    info.symbols = symbols
    return symbols
