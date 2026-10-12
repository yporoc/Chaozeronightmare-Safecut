"""三条互不依赖的判据：计划逐段到位、产物无计划外差异、对照区与文件头未被波及。
判据三的唯一例外是 CheckSum 字段——它本身就落在 SizeOfHeaders 内。
"""
from . import pe as _pe


def verify(data, fi, pe, prof, tier, writes):
    if len(data) != len(fi):
        raise AssertionError('长度变化 %d -> %d' % (len(fi), len(data)))
    for s, e, want in writes:
        if data[s:e] != want:
            raise AssertionError('写入未到位 %#x..%#x' % (s, e))
    rr = _pe.diff_ranges(data, fi)
    merged = []
    for s, e, _ in sorted(writes):
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    for s, e in rr:
        if not any(ws <= s and e <= we for ws, we in merged):
            raise AssertionError('差异 %#x..%#x 落在计划外' % (s, e))
    for c in prof['ctrl']:
        if c['skip_if_tier'] and tier >= c['skip_if_tier']:
            continue
        off = pe.r2o(c['rva'])
        if data[off:off + 16] != fi[off:off + 16]:
            raise AssertionError('对照组被误伤: %s @%#x' % (c['id'], c['rva']))
    # 判据三必须独立于判据二：豁免表不取自 writes（否则判据二先拦，这条永远轮不到），
    # 只允许 CheckSum 那 4 字节变动（校验和可复现时引擎会写回新值）。
    ck_lo, ck_hi = pe.checksum_off, pe.checksum_off + 4
    for s, e in rr:
        if s >= pe.sizeof_headers:
            continue
        if not (ck_lo <= s and e <= ck_hi):
            raise AssertionError('文件头被改动 %#x..%#x' % (s, e))
    return rr, sum(e - s for s, e in rr)


def poison_test(data, fi, pe, prof, tier, writes):
    """必须红：在对照组靶子上翻 1 bit，尺子若放行就是尺子坏。"""
    tgt = [c for c in prof['ctrl'] if c['poison']]
    if not tgt:
        raise AssertionError('profile 没标 poison 靶子，无法自证')
    off = pe.r2o(tgt[0]['rva'])
    bad = bytearray(data)
    bad[off] ^= 0xFF
    try:
        verify(bytes(bad), fi, pe, prof, tier, writes)
    except AssertionError as ex:
        return dict(target=tgt[0]['id'], off=hex(off), caught=str(ex))
    raise AssertionError('RED 失败：对 %#x 下毒 1 字节被尺子放行' % off)
