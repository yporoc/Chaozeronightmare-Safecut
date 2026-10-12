# -*- coding: utf-8 -*-
"""一次扫描给出：作用点是否存在、外部改动与哪些动作区重叠、可执行动作清单。"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
WS = os.path.dirname(REPO)
sys.path.insert(0, HERE)
import paths as _paths  # noqa: E402
import acsurface  # noqa: E402
from safecut.pe import PE, diff_ranges  # noqa: E402

# 参照用的已知原版：机器路径一律来自环境变量 CZN_GAME_EXE 或本机 local_paths.txt
KNOWN_PRISTINE = [os.path.join(WS, 'ssr-stove-shield.exe.exe')]
for _g in ([_paths.game_exe()] if _paths.game_exe() else []) + (
        [_paths.factory_original()] if _paths.factory_original() else []):
    if _g not in KNOWN_PRISTINE:
        KNOWN_PRISTINE.append(_g)


def sha(b):
    return hashlib.sha256(b if isinstance(b, (bytes, bytearray)) else open(b, 'rb').read()).hexdigest()


def plan_ranges(prof):
    """profile 里所有计划动作摊成 (名字, 起RVA, 止RVA, 该动作从第几档起生效)。
    档位号取自 profile 自己的 tier/min_tier 字段，不在这里另抄一份映射。"""
    out = []
    for e in prof['entries']:
        out.append(('entry:' + e['id'], int(e['rva'], 16), int(e['rva'], 16) + int(e['n']),
                    int(e.get('tier', 1))))
    for b in prof['bodies']:
        out.append(('body:' + b['lo'], int(b['lo'], 16), int(b['hi'], 16), int(b.get('min_tier', 2))))
    out.append(('blob', int(prof['blob']['lo'], 16), int(prof['blob']['hi'], 16), 3))
    for z in prof.get('zeros', []):
        out.append(('zero:' + z['id'], int(z['lo'], 16), int(z['hi'], 16), int(z['min_tier'])))
    for k in prof.get('pokes', []):
        out.append(('poke:' + k['id'], int(k['rva'], 16),
                    int(k['rva'], 16) + len(bytes.fromhex(k['bytes'])), int(k['min_tier'])))
    for s in prof['strings']:
        r = int(s['rva'], 16) if isinstance(s, dict) else int(s, 16) if isinstance(s, str) else int(s)
        out.append(('str:%x' % r, r, r + 40, 4))
    return out


def overlap(a0, a1, b0, b1):
    return max(a0, b0) < min(a1, b1)


def _drop(prof, kind, arg):
    """把一个动作从计划里移除（跳过），并清掉因此变空的档位。"""
    if kind == 'entry':
        prof['entries'] = [e for e in prof['entries'] if e['id'] != arg]
    elif kind == 'body':
        prof['bodies'] = [b for b in prof['bodies'] if int(b['lo'], 16) != arg]
    elif kind == 'blob':
        prof['tiers'] = [t for t in prof['tiers'] if t['tier'] != 3]
        prof['blob'] = dict(lo=prof['blob']['lo'], hi=prof['blob']['lo'])   # 长度 0 ⇒ 不清任何东西
    elif kind == 'str':
        prof['strings'] = [s for s in prof['strings'] if int(s['rva'], 16) != arg]
    elif kind == 'zero':
        prof['zeros'] = [z for z in prof['zeros'] if z['id'] != arg]
        if not any(z['min_tier'] == 5 for z in prof['zeros']):
            prof['tiers'] = [t for t in prof['tiers'] if t['tier'] != 5]
        if not any(z['min_tier'] == 6 for z in prof['zeros']):
            prof['tiers'] = [t for t in prof['tiers'] if t['tier'] != 6]
    elif kind == 'poke':
        prof['pokes'] = [k for k in prof['pokes'] if k['id'] != arg]
        if not prof['pokes']:
            prof['tiers'] = [t for t in prof['tiers'] if t['tier'] != 7]
    tiers = {t['tier'] for t in prof['tiers']}
    if 7 not in tiers:
        prof['entries'] = [e for e in prof['entries'] if int(e.get('tier', 1)) != 7]
        prof['bodies'] = [b for b in prof['bodies'] if int(b.get('min_tier', 2)) != 7]
    for t in (5, 6, 7):
        if t not in tiers:
            prof['zeros'] = [z for z in prof['zeros'] if z['min_tier'] != t]
    return prof


def _pristine_ref(buf):
    """在同尺寸同镜像的已知原版里挑差异最小的一颗；差太多判为另一颗 build，不做参照。"""
    pe = PE(buf)
    best = None
    for k in KNOWN_PRISTINE:
        if not os.path.exists(k):
            continue
        cand = open(k, 'rb').read()
        if len(cand) != len(buf) or sha(cand) == sha(buf):
            continue
        if PE(cand).sizeof_image != pe.sizeof_image:
            continue
        n = sum(e - s for s, e in diff_ranges(buf, cand))
        if best is None or n < best[0]:
            best = (n, k, cand)
    if not best:
        return None, None, 0
    if best[0] > max(4096, int(len(buf) * 0.02)):
        return None, '最近参照 %s 差 %s B（>2%%）⇒ 判为另一颗 build，不做逐字节参照' % (
            os.path.basename(best[1]), format(best[0], ',')), best[0]
    return (best[1], best[2]), None, best[0]


def scan(path, verbose=False, stamp=True):
    """一次扫描，返回 (rows, prof, meta)：rows = [(组, 名称, 命中?, 说明)]，
    prof 只含命中的动作（None = 没有可执行的东西），meta = {size, sha256, ref, their_ranges, tiers}。"""
    buf = open(path, 'rb').read()
    meta = {'input': os.path.basename(path), 'size': len(buf), 'sha256': sha(buf),
            'ref': None, 'their_ranges': [], 'conflicts': []}
    s = acsurface.Surface(buf, name=os.path.basename(path))
    rows, prof = s.plan()
    m = getattr(s, 'measure', None)
    if m:
        reg = m['region']
        meta['ac_region'] = [hex(reg['region_lo']), hex(reg['region_hi']),
                             reg['region_hi'] - reg['region_lo']]
        meta['tail_fingerprints'] = reg['tail_fingerprints']
        meta['tail_reloc'] = reg['tail_reloc_targets']
        meta['tail_real_refs'] = reg['real_refs_into_tail']
    if prof is None:
        meta['tiers'] = []
        return rows, None, meta
    pe = PE(buf)
    ref, note, ndiff = _pristine_ref(buf)
    if note:
        rows.append(('他人补丁', '参照不可用', True, note))
    elif ref is None:
        rows.append(('他人补丁', '没有同代际原版可比', True, '只做结构自证（不判别人改了什么）'))
    else:
        rp, rb = ref
        blocks = []
        for a, b in diff_ranges(buf, rb):
            if blocks and a - blocks[-1][1] <= 16:
                blocks[-1][1] = b
            else:
                blocks.append([a, b])
        pr = plan_ranges(prof)
        hits = {}
        for blk in blocks:
            for nm, s0, s1, tier in pr:
                if overlap(blk[0], blk[1], pe.r2o(s0), pe.r2o(s1)):
                    hits[nm] = (tier, [hex(blk[0]), hex(blk[1])])
                    break
        meta['ref'] = {'file': os.path.basename(rp), 'sha256': sha(rb)[:16],
                       'their_changed_bytes': sum(b - a for a, b in blocks), 'their_blocks': len(blocks),
                       'their_ranges': [[a, b] for a, b in blocks][:400]}
        meta['their_ranges'] = meta['ref']['their_ranges']
        for nm, (tier, rng) in sorted(hits.items()):
            kind, _, arg = nm.partition(':')      # 'blob' 这类动作名里没有冒号
            _drop(prof, kind, int(arg, 16) if kind in ('str', 'body') else arg)
            meta['conflicts'].append({'kind': '别人的改动与我的动作区重叠', 'hit': nm, 'tier': tier,
                                      'range': rng})
        rows.append(('他人补丁', '别人的改动与抹除区不重叠', not hits,
                     '参照 %s(%s…)：别人改了 %s B / %d 处%s' % (
                         os.path.basename(rp), sha(rb)[:12],
                         format(meta['ref']['their_changed_bytes'], ','), meta['ref']['their_blocks'],
                         '' if not hits else '；重叠 %d 处已跳过：%s' % (
                             len(hits), ', '.join(sorted(hits))) )))
    tiers = [t['tier'] for t in prof['tiers']]
    meta['tiers'] = tiers
    rows.append(('结论', '可执行动作', bool(tiers), '做到 V%d（档位 %s）' % (
        max(tiers), ','.join('V%d' % t for t in tiers))))
    if stamp:
        prof['id'] = 'pt-' + meta['sha256'][:12]
        prof['product_prefix'] = prof['id']
        prof['blueprint'] = dict(name=meta['input'], sha256=meta['sha256'], size=len(buf))
        pd = _paths.profiles_dir()
        os.makedirs(pd, exist_ok=True)
        pp = os.path.join(pd, prof['id'] + '.json')
        io.open(pp, 'w', encoding='utf-8').write(json.dumps(prof, ensure_ascii=False, indent=1))
        meta['profile_out'] = pp
    if verbose:
        for g, nm, ok, why in rows:
            print('  [%s] %-9s %-26s %s' % ('在' if ok else '缺', g, nm, str(why)[:96]))
        print('  profile=%s' % meta.get('profile_out'))
    return rows, prof, meta


def check(path, verbose=True):
    """旧接口（test_compat 那 12 条腿在用）：把 scan() 的结果摊成兼容性报告。"""
    rows, prof, meta = scan(path, verbose=False)
    rep = {'input': meta['input'], 'size': meta['size'], 'sha256': meta['sha256'],
           'conflicts': list(meta['conflicts']), 'notes': [], 'blocked_tiers': [],
           'max_allowed_tier': max(meta['tiers']) if meta['tiers'] else 0,
           'top_tier': 7, 'derivable': prof is not None, 'ref': meta['ref'],
           'profile_out': meta.get('profile_out')}
    for k in ('ac_region', 'tail_fingerprints', 'tail_reloc', 'tail_real_refs'):
        if k in meta:
            rep[k] = meta[k]
    miss = [(g, nm, why) for g, nm, ok, why in rows if not ok]
    if prof is None:
        kind = '锚定失败' if any(nm == '中止' for _g, nm, _o, _w in rows) else '结构自证不通过'
        rep['conflicts'].append({'kind': kind,
                                 'detail': ('%s：%s' % (miss[0][1], miss[0][2])) if miss else '没有可执行动作'})
        rep['blocked_tiers'] = ['V1', 'V2', 'V3', 'V4', 'V5', 'V6', 'V7'] if kind == '锚定失败' \
            else ['V5', 'V6', 'V7']
        rep['verdict'] = '不能处理' if kind == '锚定失败' else '冲突'
    else:
        rep['verdict'] = '兼容' if not rep['conflicts'] and not miss else '冲突'
        rep['plan'] = {'entries': len(prof['entries']), 'bodies': len(prof['bodies']),
                       'zeros': len(prof.get('zeros', [])), 'pokes': len(prof.get('pokes', [])),
                       'strings': len(prof['strings'])}
        rep['tiers'] = meta['tiers']
    for g, nm, _why in miss:
        if g in ('V5', 'V6', 'V7'):
            rep.setdefault('surface_miss', []).append('%s/%s' % (g, nm))
    if verbose:
        print('输入 %s sha=%s…' % (rep['input'], rep['sha256'][:16]))
        print('  可自动重锚定=%s  计划=%s' % (rep['derivable'], rep.get('plan')))
        if rep.get('ref'):
            print('  参照 %s(%s…)：别人改了 %s B / %d 块' % (rep['ref']['file'], rep['ref']['sha256'],
                  format(rep['ref']['their_changed_bytes'], ','), rep['ref']['their_blocks']))
        print('  冲突=%d %s' % (len(rep['conflicts']), rep['conflicts'][:3]))
        print('  缺失项=%s' % ([('%s/%s' % (g, nm)) for g, nm, _w in miss] or '无'))
        print('  结论=%s 最高可构建=%s' % (rep['verdict'],
              ('V%d' % rep['max_allowed_tier']) if rep['max_allowed_tier'] else '无'))
    return rep


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    r = check(sys.argv[1])
    if len(sys.argv) > 2:
        json.dump(r, io.open(sys.argv[2], 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
