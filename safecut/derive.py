"""自动重锚定：从一颗 PE 推出各档坐标，八条锚按依赖顺序逐条带唯一性断言。
任一条 0 命中或多命中且无法消歧 ⇒ 拒绝产出 profile 并打印候选分布。
"""
import bisect
import re
import struct
from collections import defaultdict

from . import pe as _pe

THREAD_APIS = ('beginthreadex', '_beginthreadex', 'beginthread', 'createthread',
               'rtlcreateuserthread', 'ntcreatethreadex')
EVENT_RE = re.compile(rb'uncheetah_[a-z_]{4,24}\0')
SEAM_RE = re.compile(rb'(?:init|cookkie)_uncheetah\0')
PATH_RE = re.compile(rb'\\[A-Za-z0-9_\\.-]{3,40}\.smt\0')
FMT_RE = re.compile(rb'error (?:code: 0x%x|Hcode: %ud)\0')
TOKEN_RE = re.compile(rb'[0-9A-Za-z_]{12,20}\0')
CALL_IAT = re.compile(rb'\xff\x15(.{4})', re.S)
LEA = re.compile(rb'([\x48\x4c][\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d])(.{4})', re.S)
RIP_ALL = re.compile(rb'([\x48\x4c][\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d])(.{4})', re.S)


class DeriveError(RuntimeError):
    pass


def _need(cond, anchor, detail):
    if not cond:
        raise DeriveError('%s 断言失败: %s' % (anchor, detail))


class Deriver:
    def __init__(self, fi):
        self.fi = fi
        self.pe = _pe.PE(fi)
        self.ib = self.pe.image_base
        self.t = next((x for x in self.pe.sections if x['n'] == '.text'), None)
        _need(self.t is not None, 'A0', '没有 .text 节')
        self.tb, self.tlen = self.t['va'], self.t['rs']
        self.tc = fi[self.t['rp']:self.t['rp'] + self.t['rs']]
        fr = self.pe.functions()
        self.begin = sorted(x[0] for x in fr)
        self.frmap = {x[0]: (x[0], x[1]) for x in fr}
        self.evid = {}

    def func_of(self, rva):
        i = bisect.bisect_right(self.begin, rva) - 1
        if i < 0:
            return None
        lo, hi = self.frmap[self.begin[i]]
        return (lo, hi) if lo <= rva < hi else None

    def strings(self):
        """在 .rdata/.data 里按形状分箱的 ASCII 串（返回 [(rva, 文本)]）。"""
        out = defaultdict(list)
        for x in self.pe.sections:
            if x['n'] not in ('.rdata', '.data'):
                continue
            seg = self.fi[x['rp']:x['rp'] + x['rs']]
            base = x['va']
            for rx, tag in ((EVENT_RE, 'event'), (SEAM_RE, 'seam'), (PATH_RE, 'path'), (FMT_RE, 'fmt')):
                for m in rx.finditer(seg):
                    out[tag].append((base + m.start(), seg[m.start():m.end() - 1].decode('latin1')))
        # token 只在"磁盘路径串所在的名字块"里找，否则任何 12~20 字符标识符都会误命中
        win = []
        for rva, txt in out['path']:
            win.append((rva - 0x80, rva + 0x80))
        for x in self.pe.sections:
            if x['n'] not in ('.rdata', '.data'):
                continue
            seg = self.fi[x['rp']:x['rp'] + x['rs']]
            for m in TOKEN_RE.finditer(seg):
                r = x['va'] + m.start()
                if any(a <= r < b for a, b in win):
                    out['token'].append((r, seg[m.start():m.end() - 1].decode('latin1')))
        return out

    def rip_index(self):
        idx = defaultdict(list)
        for m in RIP_ALL.finditer(self.tc):
            off = m.start()
            idx[self.tb + off + 7 + struct.unpack('<i', m.group(2))[0]].append(self.tb + off)
        self.rip = idx
        return idx

    def iat_names(self):
        irva, isz = self.pe.dir(1)
        out = {}
        if not irva:
            return out
        p = self.pe.r2o(irva)
        while True:
            of, ts, fc, name, ft = struct.unpack_from('<IIIII', self.fi, p)
            if name == 0 and ft == 0 and of == 0:
                break
            dn = self.fi[self.pe.r2o(name):self.pe.r2o(name) + 60].split(b'\0')[0].decode('latin1')
            q = self.pe.r2o(ft)
            i = 0
            while True:
                th = struct.unpack_from('<Q', self.fi, q + i * 8)[0]
                if th == 0:
                    break
                if not (th >> 63):
                    so = self.pe.r2o(th & 0x3FFFFFFFF)
                    fn = self.fi[so + 2:so + 62].split(b'\0')[0].decode('latin1') if so is not None else ''
                    out[ft + i * 8] = '%s!%s' % (dn, fn)
                i += 1
            p += 20
        return out

    # ---- B 派发器：被数据段指针引用、且共享同一个 .data 全局上下文的邻近函数 ----
    def dispatchers(self, s):
        d = defaultdict(set)
        for x in self.pe.sections:
            if x['n'] not in ('.rdata', '.data'):
                continue
            seg = self.fi[x['rp']:x['rp'] + x['rs']]
            for i in range(0, len(seg) - 8, 8):
                v = struct.unpack_from('<Q', seg, i)[0] - self.ib
                f = self.func_of(v)
                if f and f[0] == v and self.tb <= v < self.tb + self.tlen:
                    d[v].add(x['va'] + i)
        self.ptr_referred = d
        n_ev = len({t for _, t in s['event']})
        self.evid['events'] = n_ev
        self.evid['data_ptr_referred_text_funcs'] = len(d)
        return dict(sorted(((hex(k), v) for k, v in d.items())))

    def dispatchers_near_body(self, body, s):
        """候选=线程体邻域内、共享同一数据段全局、且它们的指针槽等距(gcd>8)的那一组。"""
        from math import gcd
        near = [v for v in self.ptr_referred if 0 < abs(v - body) < 0x2000 and v != body]
        _need(near, 'B 派发器', '线程体 %#x 邻域内没有可当派发槽的函数' % body)
        shares = defaultdict(set)
        for v in near:
            lo, hi = self.frmap[v]
            off = self.pe.r2o(lo)
            seg = self.fi[off:off + min(hi - lo, 0x2000)]
            for m in RIP_ALL.finditer(seg):
                t = lo + m.start() + 7 + struct.unpack('<i', m.group(2))[0]
                sv = self.pe.sect_of(t)
                if sv and sv['n'] in ('.data', '.rdata'):
                    shares[t].add(v)
        n_ev = len({t for _, t in s['event']})
        survivors = []
        for g, fs in sorted(shares.items()):
            if len(fs) != n_ev or not all(f in near for f in fs):
                continue
            slots = sorted({p for f in fs for p in self.ptr_referred.get(f, set())})
            if len(slots) != n_ev:
                continue
            G = 0
            for a0, b0 in zip(slots, slots[1:]):
                d0 = b0 - a0
                G = gcd(G, d0) if G else d0
            if G > 8 and G % 8 == 0:
                survivors.append((g, fs, slots, G))
        _need(len(survivors) == 1, 'B 派发器', '共享全局且槽位等距的候选组有 %d 个: %s' % (
            len(survivors), [(hex(x[0]), sorted(hex(y) for y in x[1])) for x in survivors]))
        g, fs, slots, G = survivors[0]
        self.shared = (g, G, slots)
        self.evid['dispatchers'] = dict(shared_global=hex(g), group_stride=hex(G),
                                        event_names=n_ev, funcs=sorted(hex(x) for x in fs),
                                        slots=[hex(x) for x in slots])
        return {('slot%d' % i): v for i, v in enumerate(sorted(fs))}

    # ---- C 线程体 ----
    def thread_body(self, s):
        cand = defaultdict(set)
        for tag in ('path', 'token'):
            for rva, txt in s[tag]:
                for x in self.rip.get(rva, []):
                    f = self.func_of(x)
                    if f:
                        cand[tag + ':' + txt].add(f[0])
        vote = defaultdict(set)
        for k, fs in cand.items():
            for f in fs:
                vote[f].add(k)
        good = {f: ks for f, ks in vote.items() if len(ks) >= 2}
        _need(len(good) == 1, 'C 线程体', '引用≥2 条锚串的函数有 %d 个: %s' % (
            len(good), {hex(k): sorted(v) for k, v in good.items()}))
        f = list(good)[0]
        self.evid['thread_body'] = dict(rva=hex(f), refs=sorted(good[f]),
                                        bounds=hex(self.frmap[f][0]) + '..' + hex(self.frmap[f][1]))
        return f

    # ---- D spawn 站点 ----
    def spawn_site(self, body):
        iat = self.iat_names()
        sites = []
        for m in CALL_IAT.finditer(self.tc):
            off = m.start()
            slot = self.tb + off + 6 + struct.unpack('<i', m.group(1))[0]
            nm = iat.get(slot, '')
            if not nm:
                continue
            low = nm.lower()
            if not any(a in low for a in THREAD_APIS):
                continue
            back = self.tc[max(0, off - 0x80):off + 6]
            bstart = max(0, off - 0x80)
            tgt = []
            for mm in LEA.finditer(back):
                so = bstart + mm.start()
                tgt.append(self.tb + so + 7 + struct.unpack('<i', mm.group(2))[0])
            if body in tgt:
                sites.append((self.tb + off, slot, nm))
        uniq = sorted({s[0] for s in sites})
        _need(len(uniq) == 1, 'D spawn 站点', '把线程体当参数的创建站点有 %d 处: %s' % (
            len(uniq), [hex(x) for x in uniq]))
        st, slot, nm = sites[0]
        self.evid['spawn'] = dict(site=hex(st), iat=hex(slot), api=nm,
                                  bytes=self.fi[self.pe.r2o(st):self.pe.r2o(st) + 6].hex())
        return st

    # ---- E 解密单元表 ⇒ blob 边界 ----
    def blob(self):
        """找"等差指针数组"（每个解密单元一员，步长 D）：数组在数据段，值指向 .text 里的高熵体。"""
        import numpy as np
        best = None
        for x in self.pe.sections:
            if not x['rs']:
                continue
            seg = self.fi[x['rp']:x['rp'] + x['rs']]
            n = len(seg) // 8
            if n < 12:
                continue
            q = np.frombuffer(seg[:n * 8], dtype='<u8').astype(np.int64) - self.ib
            for D in (0x20000, 0x10000, 0x40000, 0x80000):
                for sgn in (D, -D):
                    arr = ((q[:-1] - q[1:]) == sgn).astype(np.int8)
                    st = np.flatnonzero((arr == 1) & (np.concatenate(([0], arr[:-1])) == 0))
                    for s0 in st:
                        k = 0
                        while s0 + k < len(arr) and arr[s0 + k]:
                            k += 1
                        if k >= 12 and (best is None or k > best[0]):
                            best = (k, x['va'] + int(s0) * 8, D)
        _need(best is not None, 'E 解密单元表',
              '没有任何节里有 ≥13 项的等差指针数组（步长候选 0x20000/0x10000/0x40000/0x80000）')
        k, arva, D = best
        vals = [struct.unpack_from('<Q', self.fi, self.pe.r2o(arva) + 8 * i)[0] - self.ib
                for i in range(k + 1)]
        chain_lo = min(vals)
        lo, hi = min(vals), max(vals)
        # 数组头部常有 1~2 个非等差项（单元总数、blob 真正的头），回头最多 4 个槽把它们捡回来
        rl0 = self.pe.reloc_targets()
        for back in range(1, 5):
            try:
                v = struct.unpack_from('<Q', self.fi, self.pe.r2o(arva - back * 8))[0] - self.ib
            except Exception:
                break
            if chain_lo - D < v < chain_lo:
                lo = min(lo, v)
        slot_in_reloc = sum(1 for i in range(k + 1) if (arva + i * 8) in rl0)
        _need(self.tb <= lo < hi <= self.tb + self.tlen, 'E blob 位置',
              '数组 %#x 的值 %#x..%#x 不在 .text 内' % (arva, lo, hi))
        e = _pe.entropy(self.fi[self.pe.r2o(lo):self.pe.r2o(hi)])
        _need(e > 7.0, 'E blob 高熵', '区间 %#x..%#x 熵只有 %.3f' % (lo, hi, e))
        rl = self.pe.reloc_targets()
        self.evid['blob'] = dict(lo=hex(lo), hi=hex(hi), bytes=hi - lo, stride=hex(D),
                                 units=k + 1, array_rva=hex(arva), entropy=round(e, 4),
                                 slots_in_reloc='%d/%d' % (slot_in_reloc, k + 1),
                                 steps=[hex(vals[i + 1] - vals[i]) for i in range(min(3, k))])
        return lo, hi

    # ---- F 抹串目标 ----
    def scrub_strings(self, s, body):
        out = []
        for tag in ('path', 'token'):
            for rva, txt in s[tag]:
                if any(self.func_of(x) and self.func_of(x)[0] == body for x in self.rip.get(rva, [])):
                    out.append(rva)
        _need(len(out) >= 2, 'F 抹串目标', '线程体引用的磁盘/串锚只有 %d 条' % len(out))
        self.evid['strings'] = [hex(x) for x in sorted(out)]
        return sorted(out)

    # ---- G 派发表本体 ----
    def table(self, disp):
        """派发器在数据段里的指针槽等距排列 ⇒ 组步长 G = 相邻差的 gcd；再试组内偏移 j 让形状成立。"""
        from math import gcd
        slots = sorted({p for v in disp.values() for p in self.ptr_referred.get(v, set())})
        _need(len(slots) == len(disp), 'G 派发表', '每个派发器应在数据段恰有一个指针槽，实得 %s' %
              [hex(x) for x in slots])
        diffs = [b - a for a, b in zip(slots, slots[1:])]
        G = 0
        for d0 in diffs:
            G = gcd(G, d0) if G else d0
        _need(G >= 16 and G % 8 == 0, 'G 派发表', '指针槽 gcd=%s 不像表步长' % hex(G))
        good = []
        for j in range(1, G // 8):
            A = slots[0] - j * 8
            ok = True
            try:
                for g in range(len(disp)):
                    s0 = struct.unpack_from('<Q', self.fi, self.pe.r2o(A + g * G))[0] - self.ib
                    if self.pe.sect_of(s0) is None or self.pe.sect_of(s0)['n'] not in ('.rdata', '.data'):
                        ok = False
                        break
                    for k in range(1, G // 8):
                        v = struct.unpack_from('<Q', self.fi, self.pe.r2o(A + g * G + k * 8))[0] - self.ib
                        if self.pe.sect_of(v) is None or self.pe.sect_of(v)['n'] != '.text':
                            ok = False
                            break
                    if not ok:
                        break
            except Exception:
                ok = False
            if ok:
                good.append((A, j))
        _need(len(good) == 1, 'G 派发表', '形状成立的表起点有 %d 个: %s' % (len(good), [(hex(x), y) for x, y in good]))
        A, j = good[0]
        self.evid['table'] = dict(rva=hex(A), group_stride=hex(G), dispatcher_slot_index=j,
                                  slots=[hex(x) for x in slots])
        return A

    # ---- H 对照组 ----
    def controls(self, body, disp, tbl, blobs):
        keep = {body} | set(disp.values())
        fr = self.pe.functions()
        near = [b for b, e, u in fr if any(abs(b - k) < 0x4000 for k in keep) and b not in keep]
        out = []
        for b in near:
            if blobs[0] <= b < blobs[1]:
                continue
            refs = set()
            for m in LEA.finditer(self.fi[self.pe.r2o(b):self.pe.r2o(b) + 512]):
                t = b + m.start() + 7 + struct.unpack('<i', m.group(2))[0]
                refs.add(t)
            if any(t in keep for t in refs):
                continue
            out.append(b)
        _need(len(out) >= 3, 'H 对照组', '同窗口内无关函数只有 %d 个: %s' % (len(out), [hex(x) for x in out]))
        self.evid['controls'] = [hex(x) for x in out[:4]]
        return out[:4]

    def run(self):
        s = self.strings()
        _need(len(s['event']) >= 2, 'A 字符串锚', '事件名命中=%d  seam=%d path=%d token=%d' % (
            len(s['event']), len(s['seam']), len(s['path']), len(s['token'])))
        self.rip_index()
        self.dispatchers(s)
        body = self.thread_body(s)
        disp = self.dispatchers_near_body(body, s)
        site = self.spawn_site(body)
        blobs = self.blob()
        strs = self.scrub_strings(s, body)
        tbl = self.table(disp)
        ctrl = self.controls(body, disp, tbl, blobs)
        return dict(strings=s, disp=disp, body=body, site=site, blob=blobs, strs=strs,
                    table=tbl, ctrl=ctrl, evidence=self.evid)


RET0 = '31c0c39090'          # xor eax,eax; ret; nop
RET1 = 'b001c39090'          # mov al,1; ret; nop
NOP6 = '31c090909090'        # xor eax,eax + 4 nop（覆盖 6 字节 call [rip+d]）


def emit(dv, r, pid, bname):
    """把 derive 结果写成 profile 结构。返回的桩字节策略：线程体/创建点返回 0，派发槽返回 1。"""
    body, site, disp = r['body'], r['site'], r['disp']
    ents = [dict(id='T1_thread_loader', rva=hex(body), n=5,
                 orig=dv.fi[dv.pe.r2o(body):dv.pe.r2o(body) + 5].hex(), new=RET0, tier=1,
                 note='自动锚定：线程体入口，返回 0 走原有失败分支'),
            dict(id='T2_spawn_site', rva=hex(site), n=6,
                 orig=dv.fi[dv.pe.r2o(site):dv.pe.r2o(site) + 6].hex(), new=NOP6, tier=1,
                 note='自动锚定：唯一线程创建站点，eax=0 让既有 je 跳过后续')]
    for i, v in enumerate(sorted(disp.values())):
        ents.append(dict(id='T%d_disp' % (3 + i), rva=hex(v), n=5,
                         orig=dv.fi[dv.pe.r2o(v):dv.pe.r2o(v) + 5].hex(), new=RET1, tier=1,
                         note='自动锚定：派发表槽（组%d）' % i))
    bds = [dict(lo=hex(x), hi=hex(dv.frmap[x][1]), head=(RET0 if x == body else RET1))
           for x in sorted([body] + list(disp.values()))]
    ctrl = [dict(id='handler_table_body', rva=hex(r['table']), poison=True),
            dict(id='blob_head', rva=hex(r['blob'][0]), skip_if_tier=3)]
    for i, c in enumerate(r['ctrl']):
        ctrl.append(dict(id='neighbor_%d' % i, rva=hex(c)))
    return dict(schema=1, id=pid, product_prefix=pid,
                blueprint=dict(name=bname, sha256=__import__('hashlib').sha256(dv.fi).hexdigest(),
                               size=len(dv.fi)),
                tiers=[dict(tier=t, name=n) for t, n in [(1, 'V1-entries'), (2, 'V2-bodypurged'),
                                                          (3, 'V3-blobzero'), (4, 'V4-strscrub')]],
                entries=ents, bodies=bds, blob=dict(lo=hex(r['blob'][0]), hi=hex(r['blob'][1])),
                strings=[dict(rva=hex(x)) for x in r['strs']], controls=ctrl,
                assertions=dict(no_external_jump_into_bodies=True, bodies_must_match_pdata=True),
                checksum=dict(candidates=['whole_file', 'trunc_at_cert_rva'],
                              note='候选由 derive 计算，命中存储值才写字段'))
