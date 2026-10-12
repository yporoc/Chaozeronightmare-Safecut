# -*- coding: utf-8 -*-
"""逐项判定作用点：坐标全部现场推导，断言不过就不产出，只做证据支持的动作。"""
import hashlib
import os
import re
import struct
import sys
from bisect import bisect_right
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from paths import engine_dir, profiles_dir  # noqa: E402

ENGINE = engine_dir()
if ENGINE not in sys.path:
    sys.path.insert(0, ENGINE)
from safecut.pe import PE, entropy  # noqa: E402
from safecut import derive as _d  # noqa: E402

RIP = re.compile(b'([\\x48\\x4c][\\x8b\\x8d][\\x05\\x0d\\x15\\x1d\\x25\\x2d\\x35\\x3d])(.{4})', re.S)
CALL = re.compile(b'([\\xe8\\xe9])(.{4})', re.S)
GS, GROUPS = 7, 4
# 尾区的正面指纹：这几条同时出现才允许清零（缺任何一条 ⇒ 那段可能已被别人的东西占住）
TAIL_FINGERPRINTS = {
    'AC_PDB': b'client_x64.pdb',
    'WinVerifyTrust': b'WinVerifyTrust',
    'wintrust_dll': b'wintrust.dll',
    'sec_text_mn': b'.text$mn',
    'sec_rdata_dbg': b'.rdata$zzzdbg',
    'sec_rsrc01': b'.rsrc$01',
}
NAMEBLK_HINT = (0x2122100, 0x2122d90)
# 档位依据只登记这一份：构建与降级 profile 都从这里取，避免两处各写一套等级。
TIERS_META = {
    'V1-entries': ('实证', '真机长时间游玩无异常（V1/V4 已在装机机上跑过）'),
    'V2-bodypurged': ('实证', '函数体按 .pdata 全长填充，外部零跳入'),
    'V3-blobzero': ('实证', '装机版即此档口径，逐字节总账闭合'),
    'V4-strscrub': ('实证', '装机机上正在跑的就是这档，全内存串普查归零'),
    'V5-tailzero': ('实机跑过（随 L7 装机，未逐档隔离）',
                    '静态：尾区无 .pdata 覆盖、真实指令引用 0（正则假阳性逐条否掉）、区内重定位目标 0。'
                    '实机：L7 装机后进程里该 131,072 B 与文件逐字节相同，无游戏崩溃转储'),
    'V6-objectscrub': ('实机跑过（随 L7 装机，未逐档隔离）',
                        '静态：4 个对象各 128 B，静态引用者 0、区内重定位目标 0。'
                       '实机：活进程读回这 4 段全为零，功能项（切窗/干净退出/二次启动/久置）待复测'),
    'V7-table-and-readers': ('实机跑过（随 L7 装机，未逐档隔离）',
                             '静态：改的是表里的指针不是别人的代码，18 个非入口槽重定向到"返回 1"的桩，'
                             '4 个读取者静态零调用者，1 个共享槽不动。'
                            '实机：表在内存里逐槽读回与计划一致（19 桩/4 清零/1 未动），总账 0 处未解释；'
                            '功能项（切窗/干净退出/二次启动/久置）待复测'),
}


class SurfaceError(RuntimeError):
    pass


def _md():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    return Cs(CS_ARCH_X86, CS_MODE_64)


class Surface:
    def __init__(self, buf, name=''):
        self.buf = buf
        self.pe = PE(buf)
        self.name = name
        self.prof = None
        self.derived = None

    def derive_first(self):
        dv = _d.Deriver(self.buf)
        r = dv.run()
        self.derived = _d.emit(dv, r, 'auto', 'input.exe')
        self.evidence = r['evidence']
        return self

    def _load(self):
        p = self.derived
        self.T = [x for x in self.pe.sections if x['n'] == '.text'][0]
        self.BLOB = (int(p['blob']['lo'], 16), int(p['blob']['hi'], 16))
        self.TABLE = int([c for c in p['controls'] if c['id'] == 'handler_table_body'][0]['rva'], 16)
        self.fns = self.pe.functions()
        self.ent = set(a for a, b, u in self.fns)
        self.unwind = {a: b for a, b, u in self.fns}
        self.span = sorted((a, b) for a, b, u in self.fns)
        self.stubbed = set(int(e['rva'], 16) for e in p['entries'])

    def func_of(self, rva):
        i = bisect_right(self.span, (rva, (1 << 64))) - 1
        return self.span[i][0] if i >= 0 and self.span[i][0] <= rva < self.span[i][1] else None

    def refs_and_callers(self):
        if hasattr(self, '_rc'):
            return self._rc
        T = self.T
        seg = self.buf[T['rp']:T['rp'] + T['rs']]
        base = T['va'] - T['rp']
        refs = defaultdict(set)
        callers = defaultdict(set)
        sites = defaultdict(list)
        for pat, ln in ((RIP, 7), (CALL, 5)):
            for m in pat.finditer(seg):
                off = T['rp'] + m.start()
                f = self.func_of(base + off)
                t = base + off + ln + struct.unpack('<i', m.group(2))[0]
                if f is None:
                    continue
                refs[f].add(t)
                sites[t].append((f, base + off))
                if ln == 5 and t in self.ent:
                    callers[t].add(f)
        self._rc = (refs, callers, sites)
        return self._rc

    def real_instruction(self, addr):
        """addr 是否真的落在某函数从入口线性反汇编出来的指令边界上（正则命中的假阳性全在这里被否掉）。"""
        f = self.func_of(addr)
        if f is None:
            return None
        end = self.unwind[f]
        o = self.pe.r2o(f)
        for ins in _md().disasm(self.buf[o:o + (end - f)], f):
            if ins.address == addr:
                return (ins.mnemonic, ins.op_str)
            if ins.address > addr:
                break
        return None

    # ---- 1) AC 区完整范围：加密体 + 明文尾 ----
    def ac_region(self):
        self._load()
        T = self.T
        tail = (self.BLOB[1], T['va'] + T['vs'])
        fns = self.pe.functions()
        overlap = [a for a, b, u in fns if not (b <= self.BLOB[0] or a >= tail[1])]
        code_end = max(b for a, b, u in fns if b <= self.BLOB[0])
        refs, callers, sites = self.refs_and_callers()
        claims = [(t, f, s) for t, lst in sites.items() if tail[0] <= t < tail[1] for f, s in lst]
        real = []
        for t, f, s in claims:
            if self.real_instruction(s):
                real.append((hex(t), hex(f), hex(s)))
        d = self.buf[self.pe.r2o(tail[0]):self.pe.r2o(tail[1])]
        reloc_in_tail = sum(1 for r in self.pe.reloc_targets() if tail[0] <= r < tail[1])
        # 尾区必须是"AC 自己的明文尾"：靠指纹串正面认定，缺一条就不许清零
        fp = {name: (pat in d) for name, pat in TAIL_FINGERPRINTS.items()}
        return dict(region_lo=self.BLOB[0], region_hi=tail[1], enc_lo=self.BLOB[0], enc_hi=self.BLOB[1],
                    tail_lo=tail[0], tail_hi=tail[1], tail_bytes=tail[1] - tail[0],
                    tail_entropy=round(entropy(d), 4), tail_nonzero=sum(1 for c in d if c),
                    tail_reloc_targets=reloc_in_tail,
                    pdata_functions_overlapping_region=len(overlap),
                    game_code_last_end=code_end, gap_before_region=self.BLOB[0] - code_end,
                    regex_claimed_refs_into_tail=len(claims), real_refs_into_tail=len(real),
                    tail_fingerprints=fp,
                    real_ref_detail=real,
                    tail_strings=[m.group().decode('latin1') for m in
                                  re.finditer(rb'[\x20-\x7e]{6,}', d)][:14])

    # ---- 2) 派发表逐槽 + 对象 + 读取者 ----
    def table_map(self):
        refs, callers, sites = self.refs_and_callers()
        IB = self.pe.image_base
        slots = {}
        for gi in range(GROUPS):
            for si in range(GS):
                q = self.TABLE + (gi * GS + si) * 8
                v = struct.unpack_from('<Q', self.buf, self.pe.r2o(q))[0]
                slots[(gi, si)] = v - IB if v >= IB else v
        objs = sorted({slots[(gi, 0)] for gi in range(GROUPS)})
        obj_ranges = []
        for o in objs:
            hi = o + 0x80
            body = self.buf[self.pe.r2o(o):self.pe.r2o(hi)]
            who = sorted({hex(f) for t, lst in sites.items() if o <= t < hi for f, _s in lst})
            nr = sum(1 for r in self.pe.reloc_targets() if o <= r < hi)
            obj_ranges.append(dict(lo=o, hi=hi, referrers=who, reloc_targets=nr,
                                   nonzero=sum(1 for c in body if c), bytes=len(body)))
        readers = sorted({f for f, ts in refs.items()
                          if any(self.TABLE <= t < self.TABLE + GROUPS * GS * 8 for t in ts)})
        rd = []
        for f in readers:
            up = sorted(hex(x) for x in callers.get(f, set()))
            rd.append(dict(func=f, length=self.unwind[f] - f if f in self.ent else -1,
                           is_pdata_entry=f in self.ent, already_stubbed=f in self.stubbed,
                           callers=up))
        per_slot = []
        for si in range(GS):
            vs = [slots[(gi, si)] for gi in range(GROUPS)]
            per_slot.append(dict(slot=si, distinct=len(set(vs)), values=[hex(v) for v in vs],
                                 is_func=[v in self.ent for v in vs],
                                 shared_by_groups=len(vs) - len(set(vs))))
        return dict(table=self.TABLE, groups=GROUPS, slots_per_group=GS, per_slot=per_slot,
                    objects=obj_ranges, readers=rd)

    # ---- 3) AC 字面量清点 ----
    def literals(self):
        refs, callers, sites = self.refs_and_callers()
        KEY = re.compile(b'(uncheetah|uncheater|custodia|\\.smt|1t_cPrPctNtF|XignCode|error code|error Hcode)')
        lo, hi = NAMEBLK_HINT
        try:
            d0 = self.buf[self.pe.r2o(lo):self.pe.r2o(hi)]
        except Exception:
            lo = min(int(s['rva'], 16) for s in self.derived['strings']) - 0xB00
            hi = lo + 0x1000
            d0 = self.buf[self.pe.r2o(lo):self.pe.r2o(hi)]
        items = [(lo + m.start(), m.group()[:-1]) for m in re.finditer(rb'[^\x00]{4,}\x00', d0)]
        out = []
        for r, s in items:
            if not KEY.search(s):
                continue
            wr = sorted({hex(f) for t, lst in sites.items() if r <= t < r + len(s) + 1 for f, _s in lst})
            scrubbed = any(int(x['rva'], 16) == r for x in self.derived['strings'])
            out.append(dict(rva=r, text=s.decode('latin1'), rip_referrers=wr, already_scrubbed=scrubbed))
        return dict(block=(hex(lo), hex(hi)), strings=len(items), ac_strings=out)

    # ---- 4) 最大安全档位组装 ----
    def slot_pokes(self):
        """把派发表里所有指向 .text 且不是 .pdata 函数入口的槽，改写成一个已桩派发器的地址。
        槽值本身是"镜像基+RVA"且 28/28 都是重定位目标，所以写入值也必须按 VA 存，加载器照常搬家。"""
        tm = self.table_map()
        IB = self.pe.image_base
        ents = self.derived['entries']
        stubs = [int(e['rva'], 16) for e in ents if e['new'] == 'b001c39090']
        if not stubs:
            raise SurfaceError('找不到一个"返回 1"的已桩派发器作重定向目标')
        tgt = min(stubs)
        refs, callers, sites = self.refs_and_callers()
        out = []
        shared = []
        for gi in range(GROUPS):
            for si in range(GS):
                q = self.TABLE + (gi * GS + si) * 8
                v = struct.unpack_from("<Q", self.buf, self.pe.r2o(q))[0]
                r = v - IB if v >= IB else v
                sec = self.pe.sect_of(r)
                if not (sec and sec["n"] == ".text"):
                    continue
                if r in self.ent or r in self.stubbed:
                    continue
                # 表是数据，sites 只收代码引用：用它标出"槽指向的是不是共享例程"
                ext = sorted({hex(f) for f, s in sites.get(r, [])})
                rec = dict(id="slot%d_%d" % (gi, si), rva=q, min_tier=7,
                           bytes=struct.pack("<Q", IB + tgt).hex(), from_rva=r,
                           enclosing=self.func_of(r), shared_referrers=len(ext), extern=ext[:5])
                out.append(rec)
                if ext:
                    shared.append(rec)
        if not out:
            raise SurfaceError('没有需要重定向的槽（可能表结构判断变了）')
        return dict(target=tgt, pokes=out, shared=shared)

    def max_tiers(self):
        chk, reg, tm = self.checks()
        bad = [x for x in chk if not x[2]]
        if bad:
            raise SurfaceError('%s：%s' % (bad[0][1], bad[0][4]))
        readers = [r for r in tm['readers'] if not r['already_stubbed']]
        return dict(region=reg, table=tm, literals=self.literals(), readers=readers,
                    slots=self.slot_pokes())

    def checks(self):
        """逐项判定作用点是否存在、可否安全改写，不抛错。
        rows = [(组, 名称, 命中?, 命中说法, 缺失说法)]；max_tiers() 用它硬断言，plan() 用它逐项取舍。"""
        reg = self.ac_region()
        tm = self.table_map()
        n_fp = sum(1 for v in reg['tail_fingerprints'].values() if v)
        rows = [
            ('V5', '尾区无 .pdata 函数覆盖', not reg['pdata_functions_overlapping_region'],
             '无函数异常表伸进 AC 区',
             '%d 个函数的 .pdata 伸进 AC 区' % reg['pdata_functions_overlapping_region']),
            ('V5', '尾区无真实指令引用', not reg['real_refs_into_tail'],
             '0 条真实引用（正则假阳性 %d 条已逐条否掉）' % reg['regex_claimed_refs_into_tail'],
             '%d 条真实引用 %s' % (reg['real_refs_into_tail'], reg['real_ref_detail'][:2])),
            ('V5', '尾区无重定位目标', not reg['tail_reloc_targets'],
             '区内 0 个重定位目标',
             '区内 %d 个重定位目标，清零会变成坏指针' % reg['tail_reloc_targets']),
            ('V5', '尾区 AC 正面指纹齐全', not [k for k, v in reg['tail_fingerprints'].items() if not v],
             '%d 条 AC 指纹都在' % n_fp,
             '缺 %s' % [k for k, v in reg['tail_fingerprints'].items() if not v]),
        ]
        for i, o in enumerate(tm['objects']):
            ok = not o['referrers'] and not o['reloc_targets']
            rows.append(('V6', '派发对象 %d 可抹' % i, ok,
                         '%d B，零静态引用零重定位' % o['bytes'],
                         '被静态引用 %s' % o['referrers'][:3] if o['referrers']
                         else '含 %d 个重定位目标' % o['reloc_targets']))
        for rd in tm['readers']:
            if rd['already_stubbed']:
                continue
            rows.append(('V7', '读取者 %s 是 .pdata 入口' % hex(rd['func']), rd['is_pdata_entry'],
                         '调用者 %d 个' % len(rd['callers']), '不是函数入口，不能下桩（CFG 要求）'))
        try:
            sp = self.slot_pokes()
            rows.append(('V7', '派发表有待重定向的槽', bool(sp['pokes']),
                         '%d 个槽 → 桩 %s（共享槽 %d 个不动）' % (
                             len(sp['pokes']), hex(sp['target']), len(sp['shared'])),
                         '一个槽都不需要重定向'))
        except SurfaceError as ex:
            rows.append(('V7', '派发表有待重定向的槽', False, '', str(ex)))
        return rows, reg, tm

    def derive_steps(self):
        """逐级跑引擎锚定，返回 (rows, dv, r)。某一级不成立就停，后面不再猜。"""
        dv = _d.Deriver(self.buf)
        rows = []
        try:
            s = dv.strings()
            n = len({t for _, t in s['event']})
            rows.append(('锚定', '字符串锚命中', n >= 2, '事件名 %d / 接缝 %d / 路径 %d / token %d' % (
                len(s['event']), len(s['seam']), len(s['path']), len(s['token']))))
            if n < 2:
                raise _d.DeriveError('引用≥2 条锚串的函数只有 %d 个' % n)
            dv.rip_index()
            d0 = dv.dispatchers(s)
            rows.append(('锚定', '数据侧引用的 .text 函数', len(d0) > 0, '%d 个候选' % len(d0)))
            body = dv.thread_body(s)
            tb = dv.evid['thread_body']
            rows.append(('锚定', 'AC 线程体入口', True, '%s（锚串 %d 条）' % (tb['rva'], len(tb['refs']))))
            disp = dv.dispatchers_near_body(body, s)
            rows.append(('锚定', '槽位派发器', len(disp) >= 2, '%d 个：%s' % (
                len(disp), dv.evid['dispatchers']['funcs'])))
            site = dv.spawn_site(body)
            sp = dv.evid['spawn']
            rows.append(('锚定', '线程创建站点', True, '%s → %s' % (sp['site'], sp['api'])))
            blobs = dv.blob()
            bl = dv.evid['blob']
            rows.append(('锚定', 'AC 加密体', True, '%s..%s = %s B（步长 %s）' % (
                bl['lo'], bl['hi'], format(bl['bytes'], ','), bl['stride'])))
            strs = dv.scrub_strings(s, body)
            rows.append(('锚定', '待抹路径/token 串', len(dv.evid['strings']) > 0,
                         '%d 条：%s' % (len(dv.evid['strings']), dv.evid['strings'])))
            tbl = dv.table(disp)
            tb2 = dv.evid['table']
            rows.append(('锚定', '派发表', True, '%s（组步长 %s）' % (tb2['rva'], tb2['group_stride'])))
            ctrl = dv.controls(body, disp, tbl, blobs)
            rows.append(('锚定', '对照组（不动的邻居）', True, '%d 个' % len(ctrl)))
        except Exception as ex:
            rows.append(('锚定', '中止', False, '%s' % ex))
            return rows, dv, None
        r = dict(strings=s, disp=disp, body=body, site=site, blob=blobs, strs=strs, table=tbl,
                 ctrl=ctrl, evidence=dv.evid)
        return rows, dv, r

    def plan(self, pid=None):
        """一条流程用的容忍式计划：命中的动作写进 profile，没命中的记进报告并跳过。
        返回 (rows, prof)；prof=None 表示基础锚定不成立，这颗没有可执行的东西。"""
        import copy
        rows, dv, r = self.derive_steps()
        if r is None:
            return rows, None
        p = _d.emit(dv, r, pid or 'plan', self.name or 'input.exe')
        self.derived = p          # checks()/slot_pokes() 都从这份锚定结果取坐标
        self.prof = p
        p = copy.deepcopy(p)
        try:
            chk, reg, tm = self.checks()
        except Exception as ex:
            rows.append(('高档', '表面积测量', False, '%s' % ex))
            chk, reg, tm = [], None, None
        for g, nm, ok, why_ok, why_bad in chk:
            rows.append((g, nm, ok, why_ok if ok else why_bad))
        if reg is not None:
            self.measure = {'region': reg, 'table': tm}   # 调用方直接取测量值，不必再测一遍
        fam = {}
        for g, _nm, ok, _a, _b in chk:
            fam[g] = fam.get(g, True) and ok
        p['id'] = pid or ('pt-' + hashlib.sha256(self.buf).hexdigest()[:12])
        p['product_prefix'] = p['id']
        p['tiers'] = list(p['tiers'])
        p['zeros'] = []
        p['pokes'] = []
        if fam.get('V5'):
            p['zeros'].append(dict(id='ac_tail', lo=hex(reg['tail_lo']), hi=hex(reg['tail_hi']), min_tier=5))
            p['tiers'].append(dict(tier=5, name='V5-tailzero'))
        if fam.get('V6'):
            for i, o in enumerate(tm['objects']):
                p['zeros'].append(dict(id='handler_object_%d' % i, lo=hex(o['lo']), hi=hex(o['hi']),
                                       min_tier=6))
            p['tiers'].append(dict(tier=6, name='V6-objectscrub'))
        if fam.get('V7'):
            sp = self.slot_pokes()
            p['pokes'] = [dict(id=k['id'], rva=hex(k['rva']), bytes=k['bytes'], min_tier=k['min_tier'])
                          for k in sp['pokes']]
            RET1 = 'b001c39090'
            for rd in [x for x in tm['readers'] if not x['already_stubbed']]:
                off = self.pe.r2o(rd['func'])
                p['entries'].append(dict(id='D7_reader_%x' % rd['func'], rva=hex(rd['func']), n=5,
                                         orig=self.buf[off:off + 5].hex(), new=RET1, tier=7,
                                         note='引用派发表的函数，静态零调用者'))
                p['bodies'].append(dict(lo=hex(rd['func']), hi=hex(self.unwind[rd['func']]),
                                        head=RET1, min_tier=7))
            for c in p['controls']:
                if c.get('poison'):
                    c['skip_if_tier'] = 7
            p['tiers'].append(dict(tier=7, name='V7-table-and-readers'))
        for t in p['tiers']:
            g = TIERS_META.get(t['name'], ('未知', '没有登记依据'))
            t['grade'], t['basis'] = g[0], g[1]
        # 找到了但故意不动的东西也要占一行，否则"清到什么程度"这件事只有我知道
        try:
            lit = self.literals()
            keep = [x for x in lit['ac_strings'] if not x['already_scrubbed']]
            rows.append(('保留', 'AC 字面量 %d 条不动' % len(keep), True,
                         '与 _app_exit 这类业务导出名同处一个名字池，静态看不到消费者 ⇒ 删了无法证明不伤功能'))
        except Exception as ex:
            rows.append(('保留', 'AC 字面量清点失败', False, '%r' % ex))
        try:
            info = dv.evid['blob']
            rows.append(('保留', '控制块数组不动', True,
                         '%s 起 %s 项是 AC 自己的账本，指向已清零的镜像体；无静态消费者可证 ⇒ 保留' % (
                             info.get('array_rva'), info.get('units'))))
        except Exception:
            pass
        return rows, p

    def build_profile(self):
        import copy
        p = copy.deepcopy(self.derived)
        mt = self.max_tiers()
        reg, tm = mt['region'], mt['table']
        p['id'] = (p.get('id') or 'auto') + '-max'
        GRADE = TIERS_META
        p['tiers'] = p['tiers'] + [dict(tier=5, name='V5-tailzero'), dict(tier=6, name='V6-objectscrub'),
                                   dict(tier=7, name='V7-table-and-readers')]
        for t in p['tiers']:
            g = GRADE.get(t['name'], ('未知', '没有登记依据'))
            t['grade'], t['basis'] = g[0], g[1]
        p['zeros'] = [dict(id='ac_tail', lo=hex(reg['tail_lo']), hi=hex(reg['tail_hi']), min_tier=5)]
        for i, o in enumerate(tm['objects']):
            p['zeros'].append(dict(id='handler_object_%d' % i, lo=hex(o['lo']), hi=hex(o['hi']), min_tier=6))
        p['pokes'] = [dict(id=k['id'], rva=hex(k['rva']), bytes=k['bytes'], min_tier=k['min_tier'])
                      for k in mt['slots']['pokes']]
        for c in p['controls']:
            if c.get('poison'):
                c['skip_if_tier'] = 7      # 第 7 档会合法改写表槽，这一对照组到 7 就不再核
        RET1 = 'b001c39090'
        for r in tm['readers']:
            if r['already_stubbed']:
                continue
            off = self.pe.r2o(r['func'])
            p['entries'].append(dict(id='D7_reader_%x' % r['func'], rva=hex(r['func']), n=5,
                                     orig=self.buf[off:off + 5].hex(), new=RET1, tier=7,
                                     note='引用派发表的函数，静态零调用者；返回值取 1 与既有派发器一致'))
            p['bodies'].append(dict(lo=hex(r['func']), hi=hex(self.unwind[r['func']]),
                                    head=RET1, min_tier=7))
        return p


def main():
    import io
    import json
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    src = sys.argv[1]
    buf = open(src, 'rb').read()
    s = Surface(buf).derive_first()
    p = s.build_profile()
    out = os.path.join(profiles_dir(), (os.environ.get('PROFILE_ID') or p['id']) + '.json')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    io.open(out, 'w', encoding='utf-8').write(json.dumps(p, ensure_ascii=False, indent=1))
    mt = s.max_tiers()
    print('新增桩点(打印用第二次推导，已含第一次结果)=%s' % [hex(r['func']) for r in mt['readers']])
    print('档位=%d 入口=%d 函数体=%d zeros=%d' % (len(p['tiers']), len(p['entries']), len(p['bodies']), len(p['zeros'])))
    print('尾区 %s..%s = %s B 熵=%.4f 区内重定位目标=%d 真实引用=%d 正则假阳性=%d' % (
        hex(mt['region']['tail_lo']), hex(mt['region']['tail_hi']), format(mt['region']['tail_bytes'], ','),
        mt['region']['tail_entropy'], mt['region']['tail_reloc_targets'],
        mt['region']['real_refs_into_tail'], mt['region']['regex_claimed_refs_into_tail']))
    print('对象=%d 个各 %d B，静态引用=%s 区内重定位=%s' % (
        len(mt['table']['objects']), mt['table']['objects'][0]['bytes'],
        [o['referrers'] for o in mt['table']['objects']], [o['reloc_targets'] for o in mt['table']['objects']]))
    print('新增桩点=%s' % [hex(r['func']) for r in mt['readers'] if not r['already_stubbed']])
    print('AC 字面量=%d 条，其中已抹=%d 条' % (
        len(mt['literals']['ac_strings']), sum(1 for x in mt['literals']['ac_strings'] if x['already_scrubbed'])))
    print('写出 %s' % out)


if __name__ == '__main__':
    main()
