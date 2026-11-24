"""
极简标准 QR Code 编码器（ISO/IEC 18004，Byte 模式，纠错等级 M，支持 Version 1~10，最大 213 字节 UTF-8）
纯 Python 标准库，零第三方依赖。返回二维布尔矩阵（不含静区，渲染时四周各留 4 格白边）。
"""

# (version): (total_codewords, ec_per_block, blocks_g1, data_g1, blocks_g2, data_g2, alignment_centers)
_VER_INFO = {
    1:  (26,   10, 1, 16, 0,  0, ()),
    2:  (44,   16, 1, 28, 0,  0, (6, 18)),
    3:  (70,   26, 1, 44, 0,  0, (6, 22)),
    4:  (100,  18, 2, 32, 0,  0, (6, 26)),
    5:  (134,  24, 2, 43, 0,  0, (6, 30)),
    6:  (172,  16, 4, 27, 0,  0, (6, 34)),
    7:  (196,  18, 4, 31, 0,  0, (6, 22, 38)),
    8:  (242,  22, 2, 38, 2, 39, (6, 24, 42)),
    9:  (292,  22, 3, 36, 2, 37, (6, 26, 46)),
    10: (346,  26, 4, 43, 1, 44, (6, 28, 50)),
}

# GF(256) with primitive polynomial 0x11D
_EXP = [0] * 512
_LOG = [0] * 256
_v = 1
for _i in range(255):
    _EXP[_i] = _v
    _LOG[_v] = _i
    _v <<= 1
    if _v & 0x100:
        _v ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    return 0 if (a == 0 or b == 0) else _EXP[_LOG[a] + _LOG[b]]


def _rs_gen(degree: int) -> list[int]:
    poly = [1]
    for i in range(degree):
        nxt = [0] * (len(poly) + 1)
        root = _EXP[i]
        for j, c in enumerate(poly):
            nxt[j] ^= c
            nxt[j + 1] ^= _gf_mul(c, root)
        poly = nxt
    return poly


def _rs_remainder(data: list[int], degree: int) -> list[int]:
    gen = _rs_gen(degree)
    rem = [0] * degree
    for b in data:
        factor = b ^ rem[0]
        rem = rem[1:] + [0]
        if factor:
            for i in range(degree):
                rem[i] ^= _gf_mul(gen[i + 1], factor)
    return rem


def _format_bits(mask: int) -> int:
    # EC Level M = 00
    data = (0b00 << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ (((rem >> 9) & 1) * 0x537)
    return ((data << 10) | rem) ^ 0x5412


def _version_bits(ver: int) -> int:
    rem = ver
    for _ in range(12):
        rem = (rem << 1) ^ (((rem >> 11) & 1) * 0x1F25)
    return (ver << 12) | rem


def _mask_cond(mask: int, r: int, c: int) -> bool:
    if mask == 0: return (r + c) % 2 == 0
    if mask == 1: return r % 2 == 0
    if mask == 2: return c % 3 == 0
    if mask == 3: return (r + c) % 3 == 0
    if mask == 4: return ((r // 2) + (c // 3)) % 2 == 0
    if mask == 5: return ((r * c) % 2) + ((r * c) % 3) == 0
    if mask == 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 == 0
    return (((r + c) % 2) + ((r * c) % 3)) % 2 == 0


def _penalty(grid: list[list[bool]]) -> int:
    n = len(grid)
    score = 0
    # Rule 1: adjacent runs >= 5
    for line in grid:
        run, prev = 1, line[0]
        for cell in line[1:]:
            if cell == prev:
                run += 1
                if run == 5: score += 3
                elif run > 5: score += 1
            else:
                run, prev = 1, cell
    for c in range(n):
        run, prev = 1, grid[0][c]
        for r in range(1, n):
            cell = grid[r][c]
            if cell == prev:
                run += 1
                if run == 5: score += 3
                elif run > 5: score += 1
            else:
                run, prev = 1, cell
    # Rule 2: 2x2 blocks
    for r in range(n - 1):
        for c in range(n - 1):
            v = grid[r][c]
            if v == grid[r][c + 1] == grid[r + 1][c] == grid[r + 1][c + 1]:
                score += 3
    # Rule 4: balance
    dark = sum(sum(row) for row in grid)
    score += abs(dark * 20 // (n * n) - 10) * 10
    return score


def encode_qr(text: str) -> list[list[bool]]:
    """把 UTF-8 字符串编码为标准 QR Code 布尔矩阵（True=黑，False=白）。"""
    payload = text.encode("utf-8")
    ver = None
    for v in range(1, 11):
        _, _, g1, d1, g2, d2, _ = _VER_INFO[v]
        cap = g1 * d1 + g2 * d2
        # 4 bit mode + (8 or 16 bit len) => Byte mode V1..9 uses 8 bits, V10 uses 16 bits
        hdr_bytes = 2 if v <= 9 else 3
        if len(payload) + hdr_bytes <= cap:
            ver = v
            break
    if ver is None:
        raise ValueError("QR 文本过长（最多 210 字节）")

    _, ec_len, g1, d1, g2, d2, align = _VER_INFO[ver]
    data_cap = g1 * d1 + g2 * d2

    # 1) 构造比特流（Byte 模式 0100）
    bits = []
    def push(val: int, length: int):
        for i in range(length - 1, -1, -1):
            bits.append((val >> i) & 1)

    push(0b0100, 4)
    push(len(payload), 8 if ver <= 9 else 16)
    for b in payload:
        push(b, 8)
    push(0, min(4, data_cap * 8 - len(bits)))
    while len(bits) % 8 != 0:
        bits.append(0)
    data_bytes = []
    for i in range(0, len(bits), 8):
        v = 0
        for j in range(8):
            v = (v << 1) | bits[i + j]
        data_bytes.append(v)
    pad = (0xEC, 0x11)
    pi = 0
    while len(data_bytes) < data_cap:
        data_bytes.append(pad[pi])
        pi ^= 1

    # 2) 分块计算 Reed-Solomon 纠错码并交织
    blocks, ecs = [], []
    off = 0
    for cnt, dlen in ((g1, d1), (g2, d2)):
        for _ in range(cnt):
            blk = data_bytes[off:off + dlen]
            off += dlen
            blocks.append(blk)
            ecs.append(_rs_remainder(blk, ec_len))

    codewords = []
    max_d = max(len(b) for b in blocks)
    for i in range(max_d):
        for b in blocks:
            if i < len(b):
                codewords.append(b[i])
    for i in range(ec_len):
        for e in ecs:
            codewords.append(e[i])

    # 3) 放置功能图形（Finder / Timing / Alignment / Format & Version 保留区）
    size = ver * 4 + 17
    grid = [[False] * size for _ in range(size)]
    func = [[False] * size for _ in range(size)]

    def set_fn(r: int, c: int, val: bool):
        if 0 <= r < size and 0 <= c < size:
            grid[r][c] = val
            func[r][c] = True

    def place_finder(r0: int, c0: int):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = r0 + dr, c0 + dc
                if 0 <= r < size and 0 <= c < size:
                    dark = (0 <= dr <= 6 and 0 <= dc <= 6 and
                            (dr in (0, 6) or dc in (0, 6) or (2 <= dr <= 4 and 2 <= dc <= 4)))
                    set_fn(r, c, dark)

    place_finder(0, 0)
    place_finder(0, size - 7)
    place_finder(size - 7, 0)

    for i in range(8, size - 8):
        set_fn(6, i, i % 2 == 0)
        set_fn(i, 6, i % 2 == 0)

    for r0 in align:
        for c0 in align:
            if (r0 == 6 and c0 == 6) or (r0 == 6 and c0 == size - 7) or (r0 == size - 7 and c0 == 6):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    dark = max(abs(dr), abs(dc)) != 1
                    set_fn(r0 + dr, c0 + dc, dark)

    set_fn(size - 8, 8, True)  # Dark module

    # 保留格式信息位
    for i in range(9):
        if i != 6:
            set_fn(8, i, False)
            set_fn(i, 8, False)
    for i in range(8):
        set_fn(8, size - 1 - i, False)
        set_fn(size - 1 - i, 8, False)

    # Version >= 7 版本信息位
    if ver >= 7:
        vb = _version_bits(ver)
        for i in range(18):
            bit = bool((vb >> i) & 1)
            a, b = size - 11 + (i % 3), i // 3
            set_fn(a, b, bit)
            set_fn(b, a, bit)

    # 4) 蛇形写入数据比特
    cw_bits = []
    for b in codewords:
        for i in range(7, -1, -1):
            cw_bits.append(bool((b >> i) & 1))
    bi = 0
    up = True
    c = size - 1
    while c > 0:
        if c == 6:
            c -= 1
        rows = range(size - 1, -1, -1) if up else range(size)
        for r in rows:
            for dc in (0, -1):
                cc = c + dc
                if not func[r][cc]:
                    grid[r][cc] = cw_bits[bi] if bi < len(cw_bits) else False
                    bi += 1
        c -= 2
        up = not up

    # 5) 评估 8 种掩码选最优
    best_grid, best_score = None, 10**9
    for mask in range(8):
        cand = [row[:] for row in grid]
        for r in range(size):
            for col in range(size):
                if not func[r][col] and _mask_cond(mask, r, col):
                    cand[r][col] = not cand[r][col]
        fb = _format_bits(mask)
        for i in range(6):
            cand[8][i] = bool((fb >> (14 - i)) & 1)
        cand[8][7] = bool((fb >> 8) & 1)
        cand[8][8] = bool((fb >> 7) & 1)
        cand[7][8] = bool((fb >> 6) & 1)
        for i in range(6):
            cand[5 - i][8] = bool((fb >> (5 - i)) & 1)
        for i in range(8):
            cand[8][size - 1 - i] = bool((fb >> i) & 1)
        for i in range(7):
            cand[size - 1 - i][8] = bool((fb >> (14 - i)) & 1)

        sc = _penalty(cand)
        if sc < best_score:
            best_score, best_grid = sc, cand
    return best_grid
