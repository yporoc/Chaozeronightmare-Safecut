"""只读体检：把一颗 PE 的结构事实整理成可机读报告，不做判定、不写输入。"""
import hashlib
import struct
from collections import Counter

from . import pe as _pe

DLLCH = {0x0020: 'HIGH_ENTROPY_VA', 0x0040: 'DYNAMIC_BASE', 0x0080: 'FORCE_INTEGRITY',
         0x0100: 'NX_COMPAT', 0x0200: 'NO_ISOLATION', 0x0400: 'NO_SEH', 0x1000: 'NO_BIND',
         0x2000: 'APPCONTAINER', 0x4000: 'GUARD_CF', 0x8000: 'TERMINAL_SERVER_AWARE'}
GUARD = {0x0001: 'WF_ATL_THUNK2', 0x0002: 'WF_ATL_THUNK1', 0x0004: 'RLF', 0x0008: 'FID',
         0x0010: 'IAT', 0x0020: 'DELAY_IAT', 0x0100: 'CFG', 0x0200: 'STRICTCFG',
         0x0400: 'CET_COMPAT', 0x1000: 'CET_COMPAT_STRICT'}
ANCHORS = [b'uncheetah', b'init_uncheetah', b'cookkie', b'.smt', b'custodia', b'XignCode',
           b'xigncode', b'hack_detected', b'cookie_complete', b'cookie_fail', b'init_fail',
           b'beginthreadex', b'GuardCF', b'PMAL']


def high_entropy_spans(pe, text, thr=7.5, blk=0x10000):
    """按 64 KiB 块标出高熵区，返回合并后的极大区间 [(rva,bytes,mean_ent)]。"""
    seg = text['rs']
    out = []
    cur = None
    for i in range(0, seg, blk):
        d = pe.b[text['rp'] + i:text['rp'] + min(i + blk, seg)]
        e = _pe.entropy(d)
        if e >= thr:
            if cur and cur[1] == text['va'] + i:
                cur = (cur[0], text['va'] + i + len(d), max(cur[2], e))
            else:
                if cur:
                    out.append(cur)
                cur = (text['va'] + i, text['va'] + i + len(d), e)
        else:
            if cur:
                out.append(cur)
                cur = None
    if cur:
        out.append(cur)
    return sorted(out, key=lambda x: -(x[1] - x[0]))


def report(fi, keyword=True):
    pe = _pe.PE(fi)
    h = hashlib.sha256(fi).hexdigest()
    d = dict(file=dict(size=len(fi), sha256=h),
             header=dict(machine=hex(pe.machine), image_base=hex(pe.image_base),
                        entry=hex(pe.entry), sizeof_image=pe.sizeof_image,
                        sizeof_headers=pe.sizeof_headers, dllchars=hex(pe.dllchars),
                        dllchars_decoded=[DLLCH.get(b, hex(b)) for b in sorted(DLLCH) if pe.dllchars & b],
                        sections=[[x['n'], hex(x['va']), x['vs'], x['rs'], x['rp'],
                                   round(_pe.entropy(fi[x['rp']:x['rp'] + min(x['rs'], 1 << 20)]), 4)]
                                  for x in pe.sections]))
    dirs = []
    for i in range(16):
        rva, sz = pe.dir(i)
        if rva or sz:
            s = pe.sect_of(rva)
            dirs.append([i, _pe.DIR[i], hex(rva), sz, s['n'] if s else '-'])
    d['directories'] = dirs
    fr = pe.functions()
    d['exception'] = dict(functions=len(fr),
                         total_bytes=sum(b - a for a, b, u in fr))
    rl = pe.reloc_targets()
    d['reloc'] = dict(dir=hex(pe.dir(5)[0]), size=pe.dir(5)[1], targets=len(rl))
    # LoadConfig 手工偏移解码（x64），并与 pefile 交叉对账（装了就对，没装就单路）
    lcrva, lcsz = pe.dir(10)
    lc = dict(present=bool(lcrva), rva=hex(lcrva), size=lcsz)
    if lcrva:
        off = pe.r2o(lcrva)
        f = lambda o, fmt: struct.unpack_from(fmt, fi, off + o)[0]
        raw = fi[off:off + lcsz]
        lc['nonzero_bytes'] = sum(1 for x in raw if x)
        lc['raw_first_96'] = raw[:96].hex()
        lc['nonzero_dwords'] = [[hex(i), hex(struct.unpack_from('<I', raw, i)[0])]
                                for i in range(0, lcsz - 3, 4) if any(raw[i:i + 4])]
        # 字段偏移以 pefile 为准；手工偏移表只在没有 pefile 时兜底，并且绝不与 pefile 混着报同一个名字
        try:
            import pefile
            p = pefile.PE(data=fi, fast_load=True)
            p.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']])
            g = p.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            gf = int(g.GuardFlags)
            lc['source'] = 'pefile'
            lc['guard_flags'] = hex(gf)
            lc['guard_flags_decoded'] = [GUARD.get(b, hex(b)) for b in sorted(GUARD) if gf & b]
            lc['guard_cf_count'] = int(g.GuardCFFunctionCount)
            lc['seh_count'] = int(g.SEHandlerCount)
            lc['lock_prefix'] = hex(int(g.LockPrefixTable)) if hasattr(g, 'LockPrefixTable') else None
        except Exception as ex:
            f = lambda o: struct.unpack_from('<Q', fi, off + o)[0]
            gf = struct.unpack_from('<I', fi, off + 0x58)[0]
            lc['source'] = '手工偏移兜底(pefile 不可用): %s' % type(ex).__name__
            lc['guard_flags'] = hex(gf)
            lc['guard_flags_decoded'] = [GUARD.get(b, hex(b)) for b in sorted(GUARD) if gf & b]
            lc['guard_cf_count'] = f(0x50)
            lc['seh_count'] = f(0x40)
            lc['caveat'] = '无 pefile 时偏移表可能读错，不要把这三项当结论'
    d['loadcfg'] = lc
    t = next((x for x in pe.sections if x['n'] == '.text'), None)
    if t:
        d['high_entropy_spans_in_text'] = [[hex(a), hex(b), b - a, round(e, 4)]
                                          for a, b, e in high_entropy_spans(pe, t)[:8]]
    if keyword:
        d['anchor_keyword_census'] = {k.decode(): fi.count(k) for k in ANCHORS}
    c = Counter(fi)
    d['file_entropy'] = round(_pe.entropy(fi), 4)
    d['nul_ratio'] = round(c[0] / len(fi), 4)
    return d
