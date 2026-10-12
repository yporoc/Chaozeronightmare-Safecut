"""前置检查与四档构建。全部改动只由 profile 决定，构建器本身不含目标程序坐标。"""
import re
import struct

from . import pe as _pe


class PreflightError(RuntimeError):
    pass


def _text(pe):
    for x in pe.sections:
        if x['n'] == '.text':
            return x
    raise PreflightError('没有 .text 节')


def checksum_candidates(fi, pe):
    """返回三种候选算法的算得值。写不写字段由 profile 的 candidates + 是否命中存储值决定。"""
    stored = struct.unpack_from('<I', fi, pe.checksum_off)[0]
    probe = bytearray(fi)
    struct.pack_into('<I', probe, pe.checksum_off, 0)
    crva, csz = pe.cert()
    out = {'stored': stored, 'whole_file': _pe.checksum16(bytes(probe))}
    if crva:
        out['trunc_at_cert_rva'] = _pe.checksum16(bytes(probe)[:crva])
        cof = None
        try:
            cof = pe.r2o(crva)
        except _pe.PEError:
            cof = None
        if cof is not None and csz:
            merged = bytes(probe[:cof]) + bytes(probe[cof + csz:])
            out['excl_cert_region'] = _pe.checksum16(merged)
    return out


def preflight(fi, pe, prof):
    sites = []
    for e in prof['ents']:
        off = pe.r2o(e['rva'])
        cur = fi[off:off + e['n']]
        if cur != e['orig']:
            raise PreflightError('点位 %s 非原样: 现场 %s 期望 %s' % (e['id'], cur.hex(), e['orig'].hex()))
        sites.append((e['id'], e['rva'], off, cur.hex()))
    fr = pe.functions()
    for b in prof['bds']:
        if not any(x[0] == b['lo'] and x[1] == b['hi'] for x in fr):
            raise PreflightError('函数体 %#x..%#x 与 .pdata 边界不符' % (b['lo'], b['hi']))
    t = _text(pe)
    seg = fi[t['rp']:t['rp'] + t['rs']]
    intr = []
    for b in prof['bds']:
        for pat in (b'\xe8', b'\xe9'):
            for m in re.finditer(pat, seg):
                frm = t['va'] + m.start()
                tgt = frm + 5 + struct.unpack_from('<i', seg, m.start() + 1)[0]
                if b['lo'] < tgt < b['hi'] and not (b['lo'] <= frm < b['hi']):
                    intr.append((hex(frm), hex(tgt)))
    blob_fr = [x for x in fr if x[0] < prof['blob'][1] and x[1] > prof['blob'][0]]
    ckd = checksum_candidates(fi, pe)
    hit = [k for k in prof['ck_candidates'] if ckd.get(k) == ckd['stored']]
    return dict(sites=sites, intr=intr, blob_fr=len(blob_fr), ckd=ckd,
                ck_write=bool(hit), ck_hit=hit)


def build(fi, pe, prof, tier, ck_write=False):
    buf = bytearray(fi)
    writes = []
    done = []
    for e in prof['ents']:
        if e['tier'] > tier:
            continue
        off = pe.r2o(e['rva'])
        buf[off:off + e['n']] = e['new']
        writes.append((off, off + e['n'], e['new']))
        done.append(['entry', e['id'], hex(e['rva']), hex(off), e['orig'].hex(), e['new'].hex()])
    for b in prof['bds']:
        if tier < b.get('min_tier', 2):
            continue
        off = pe.r2o(b['lo'])
        ln = b['hi'] - b['lo']
        fill = b['head'] + b'\xcc' * (ln - len(b['head']))
        buf[off:off + ln] = fill
        writes.append((off, off + ln, fill))
        done.append(['body_fill', hex(b['lo']), hex(off), str(ln)])
    for z in prof.get('zeros', []):
        if tier < z['min_tier']:
            continue
        off = pe.r2o(z['lo'])
        ln = z['hi'] - z['lo']
        buf[off:off + ln] = b'\x00' * ln
        writes.append((off, off + ln, b'\x00' * ln))
        done.append(['zero_' + z['id'], hex(z['lo']), hex(off), str(ln)])
    for pk in prof.get('pokes', []):
        if tier < pk['min_tier']:
            continue
        off = pe.r2o(pk['rva'])
        buf[off:off + len(pk['bytes'])] = pk['bytes']
        writes.append((off, off + len(pk['bytes']), pk['bytes']))
        done.append(['poke_' + pk['id'], hex(pk['rva']), hex(off), pk['bytes'].hex()])
    if tier >= 3:
        off = pe.r2o(prof['blob'][0])
        ln = prof['blob'][1] - prof['blob'][0]
        buf[off:off + ln] = b'\x00' * ln
        writes.append((off, off + ln, b'\x00' * ln))
        done.append(['blob_zero', hex(prof['blob'][0]), hex(off), str(ln)])
    if tier >= 4:
        for r in prof['strs']:
            off = pe.r2o(r)
            ln = len(fi[off:off + 96].split(b'\0')[0])
            buf[off:off + ln] = b'\x00' * ln
            writes.append((off, off + ln, b'\x00' * ln))
            done.append(['str_scrub', hex(r), hex(off), str(ln)])
    old_ck = struct.unpack_from('<I', fi, pe.checksum_off)[0]
    new_ck = old_ck
    if ck_write and writes:
        new_ck = _pe.checksum16(bytes(buf))
        struct.pack_into('<I', buf, pe.checksum_off, new_ck)
        writes.append((pe.checksum_off, pe.checksum_off + 4, new_ck.to_bytes(4, 'little')))
        done.append(['checksum', hex(old_ck), hex(new_ck)])
    return bytes(buf), writes, done
