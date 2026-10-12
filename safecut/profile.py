"""profile 的加载与净化检查：只允许哈希、长度、RVA、桩字节、阈值与 ASCII 说明。"""
import io
import json
import os
import re

BAD_PATH = re.compile(r'[A-Za-z]:[\\/]')
BAD_MAIL = re.compile(r'[\w.+-]+@[\w-]+\.[A-Za-z]{2,}')
HEX = re.compile(r'^[0-9a-f]*$')


class ProfileError(RuntimeError):
    pass


def _i(v):
    return v if isinstance(v, int) else int(v, 16)


def _walk_strings(o, path=''):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _walk_strings(v, path + '/' + str(k))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _walk_strings(v, '%s[%d]' % (path, i))
    elif isinstance(o, str):
        yield path, o


def hexbytes(s, where, maxlen=64):
    if not isinstance(s, str) or len(s) > maxlen or len(s) % 2 or not HEX.match(s):
        raise ProfileError('%s 不是 <=%d 位十六进制小写串: %r' % (where, maxlen, s))
    return bytes.fromhex(s)


def load(path):
    raw = io.open(path, encoding='utf-8').read()
    for where, s in _walk_strings(json.loads(raw)):
        if BAD_PATH.search(s):
            raise ProfileError('profile 里出现绝对路径（不可公开分发）: %s = %r' % (where, s))
        if BAD_MAIL.search(s):
            raise ProfileError('profile 里出现邮箱（不可公开分发）: %s' % where)
    p = json.loads(raw)
    need = ['schema', 'id', 'blueprint', 'tiers', 'entries', 'bodies', 'blob', 'strings',
            'controls', 'checksum']
    miss = [k for k in need if k not in p]
    if miss:
        raise ProfileError('profile 缺字段: %s' % miss)
    if p['schema'] != 1:
        raise ProfileError('不认识的 profile schema=%s' % p['schema'])
    bp = p['blueprint']
    if len(bp.get('sha256', '')) != 64 or not HEX.match(bp['sha256']):
        raise ProfileError('blueprint.sha256 必须是 64 位十六进制')
    if not isinstance(bp.get('size'), int) or bp['size'] <= 0:
        raise ProfileError('blueprint.size 必须是正整数')
    out = dict(p)
    out['blob'] = (_i(p['blob']['lo']), _i(p['blob']['hi']))
    out['ents'] = []
    for e in p['entries']:
        o = dict(id=e['id'], rva=_i(e['rva']), n=int(e['n']), tier=int(e['tier']),
                 orig=hexbytes(e['orig'], e['id'] + '.orig'), new=hexbytes(e['new'], e['id'] + '.new'),
                 note=e.get('note', ''))
        if o['n'] != len(o['new']) or len(o['orig']) != o['n']:
            raise ProfileError('%s: n=%d 与 orig/new 长度不符' % (o['id'], o['n']))
        out['ents'].append(o)
    out['bds'] = [dict(lo=_i(b['lo']), hi=_i(b['hi']), head=hexbytes(b['head'], 'body.head'),
                       min_tier=int(b.get('min_tier', 2))) for b in p['bodies']]
    out['zeros'] = [dict(id=z['id'], lo=_i(z['lo']), hi=_i(z['hi']), min_tier=int(z['min_tier']))
                    for z in p.get('zeros', [])]
    out['pokes'] = [dict(id=k['id'], rva=_i(k['rva']), bytes=hexbytes(k['bytes'], 'poke.' + k['id'], 64),
                         min_tier=int(k['min_tier'])) for k in p.get('pokes', [])]
    for z in out['zeros']:
        if z['hi'] <= z['lo']:
            raise ProfileError('zero %s 区间反了' % z['id'])
    out['strs'] = [_i(s['rva']) for s in p['strings']]
    out['ctrl'] = [dict(id=c['id'], rva=_i(c['rva']), poison=bool(c.get('poison')),
                        skip_if_tier=int(c.get('skip_if_tier', 0))) for c in p['controls']]
    if sum(1 for c in out['ctrl'] if c['poison']) != 1:
        raise ProfileError('必须恰好有一个 control 标 poison:true（RED 下毒腿的靶子）')
    if not p['tiers']:
        raise ProfileError('没有档位')
    out['tier_list'] = [(int(t['tier']), t['name']) for t in sorted(p['tiers'], key=lambda x: int(x['tier']))]
    out['ck_candidates'] = p['checksum']['candidates']
    for k in out['ck_candidates']:
        if k not in ('whole_file', 'trunc_at_cert_rva', 'excl_cert_region'):
            raise ProfileError('不认识的校验和候选算法: %s' % k)
    out['path'] = os.path.abspath(path)
    return out


def autodetect(profdir, fi):
    """在目录里找唯一能匹配这颗输入的 profile。两级：先 sha256，再锚指纹。
    命中 0 个或多个都拒绝——绝不"取第一个匹配"。返回 (profile, 依据)。"""
    import glob
    import hashlib
    cands = sorted(glob.glob(os.path.join(profdir, '*.json')))
    want = hashlib.sha256(fi).hexdigest()
    bysha = []
    for p in cands:
        try:
            q = load(p)
        except ProfileError:
            continue
        if q['blueprint']['sha256'] == want:
            bysha.append(q)
    if len(bysha) == 1:
        return bysha[0], 'blueprint sha256 唯一命中'
    if len(bysha) > 1:
        raise ProfileError('多颗 profile 钉了同一个 sha256: %s' % [x['id'] for x in bysha])
    from . import pe as _pe
    pe = _pe.PE(fi)
    def r2o(r):
        x = pe.sect_of(r)
        return x['rp'] + (r - x['va']) if x else None
    hits = []
    for p in cands:
        try:
            q = load(p)
        except ProfileError:
            continue
        ok = True
        for e in q['ents']:
            off = r2o(e['rva'])
            if off is None or fi[off:off + e['n']] != e['orig']:
                ok = False
                break
        if ok:
            for b in q['bds']:
                fr = [(a, c) for a, c, u in pe.functions() if a == b['lo']]
                if not fr or fr[0][1] != b['hi']:
                    ok = False
                    break
        if ok:
            hits.append(q)
    if len(hits) == 1:
        return hits[0], '锚指纹（入口原字节 + .pdata 体边界）唯一命中，sha256 不同=同代际'
    raise ProfileError('代际判不出：sha256 无命中，锚指纹命中 %d 个 %s（要人工确认后再加 profile）' % (
        len(hits), [x['id'] for x in hits]))
