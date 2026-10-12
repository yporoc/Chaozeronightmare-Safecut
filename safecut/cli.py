"""命令行：build / verify-file / derive / probe / doctor。
写盘边界：输入哈希须匹配 profile，产物目录不得等于源目录，写完读回再核，核不过删除本次写入。
"""
import argparse
import hashlib
import io
import json
import os
import sys
import time

from . import pe as _pe
from . import patch as _patch
from . import profile as _profile
from . import derive as _derive
from . import ruler as _ruler


def sha(b):
    return hashlib.sha256(b).hexdigest()


def _load_input(path, prof):
    fi = open(path, 'rb').read()
    want = prof['blueprint']['sha256']
    got = sha(fi)
    if got != want:
        raise SystemExit('REFUSE: 输入哈希不符: 期望 %s… 现场 %s…（%s）' % (want[:16], got[:16], path))
    if len(fi) != prof['blueprint']['size']:
        raise SystemExit('REFUSE: 输入长度不符: 期望 %d 现场 %d' % (prof['blueprint']['size'], len(fi)))
    return fi


def _get_profile(a, fi):
    if a.profile == 'auto':
        d = os.path.dirname(os.path.abspath(a.inp))
        pdir = a.profile_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'profiles')
        p, why = _profile.autodetect(pdir, fi)
        print('代际识别: profile=%s  依据=%s' % (p['id'], why))
        return p
    return _profile.load(a.profile)


def cmd_build(a):
    fi = open(a.inp, 'rb').read()
    prof = _get_profile(a, fi)
    want = prof['blueprint']['sha256']
    if sha(fi) != want:
        raise SystemExit('REFUSE: 输入哈希不符: 期望 %s… 现场 %s…（%s）' % (want[:16], sha(fi)[:16], a.inp))
    if len(fi) != prof['blueprint']['size']:
        raise SystemExit('REFUSE: 输入长度不符: 期望 %d 现场 %d' % (prof['blueprint']['size'], len(fi)))
    pe = _pe.PE(fi)
    outdir = os.path.abspath(a.out)
    if os.path.normcase(outdir) == os.path.normcase(os.path.abspath(os.path.dirname(a.inp))):
        raise SystemExit('REFUSE: 产物目录就是输入所在目录，拒绝（永不覆盖源）')
    os.makedirs(outdir, exist_ok=True)
    t0 = time.time()
    pf = _patch.preflight(fi, pe, prof)
    print('== 前置 ==')
    print('  蓝本            %s  size=%d  sha256=%s…' % (os.path.basename(a.inp), len(fi), sha(fi)[:16]))
    print('  镜像基 %#x  SizeOfImage=%d  DllCharacteristics=%#x  入口RVA=%#x' % (
        pe.image_base, pe.sizeof_image, pe.dllchars, pe.entry))
    print('  PRISTINE        %d 个点位原字节全部命中' % len(pf['sites']))
    print('  函数体边界      与 .pdata 全等（%d 个体）' % len(prof['bds']))
    print('  外部跳入体内    %d 处 %s' % (len(pf['intr']), pf['intr'][:4]))
    print('  .pdata 覆盖blob %d 条' % pf['blob_fr'])
    c = pf['ckd']
    print('  校验和          存储=%s whole=%s trunc_at_cert_rva=%s excl_cert_region=%s' % (
        hex(c['stored']), hex(c['whole_file']), hex(c.get('trunc_at_cert_rva', 0)),
        hex(c.get('excl_cert_region', 0))))
    print('                profile 候选=%s 命中=%s ⇒ %s' % (
        prof['ck_candidates'], pf['ck_hit'], '可复现，写入新值' if pf['ck_write'] else '不可复现，字段保持原值'))
    if pf['intr'] and prof.get('assertions', {}).get('no_external_jump_into_bodies', True):
        raise SystemExit('REFUSE: 有外部代码跳进待填充函数体内部，拒绝产出')
    tiers = prof['tier_list']
    if a.only:
        pick = {int(x) for x in a.only.split(',')}
        tiers = [t for t in tiers if t[0] in pick]
    want = {}
    if a.expect_sha:
        for i, s in enumerate(a.expect_sha.split(',')):
            want[tiers[i][1]] = s
    ledger = []
    for tier, nm in tiers:
        data, writes, done = _patch.build(fi, pe, prof, tier, pf['ck_write'])
        po = None
        if tier == tiers[0][0]:
            po = _ruler.poison_test(data, fi, pe, prof, tier, writes)
        rr, tot = _ruler.verify(data, fi, pe, prof, tier, writes)
        p = os.path.join(outdir, '%s-%s.exe' % (prof.get('product_prefix', prof['id']), nm))
        open(p, 'wb').write(data)
        back = open(p, 'rb').read()
        rr2, tot2 = _ruler.verify(back, fi, pe, prof, tier, writes)
        rec = dict(name=nm, tier=tier, file=os.path.relpath(p, os.getcwd()).replace('\\', '/'),
                   size=len(back), sha256=sha(back), changed_bytes=tot, regions=len(rr),
                   reread_changed_bytes=tot2, reread_identical=(back == data),
                   regions_first=[[hex(s), hex(e)] for s, e in rr][:8],
                   sites=done, poison=po)
        got = rec['sha256']
        verdict = ''
        exp = want.get(nm) if want else None
        rec['expected_sha256'] = exp
        if exp:
            ok = (exp == got)
            verdict = '  复现=%s' % ('一致 ✔' if ok else '不符 ✘ 期望 %s…' % exp[:16])
        rec['reproduced'] = (got == exp) if exp else None
        print('\n[%s] %s' % (nm, rec['file']))
        print('   sha256=%s…  size=%d  改动=%d B / %d 段  复读盘=%d B%s' % (
            got[:32], len(back), tot, len(rr), tot2, verdict))
        if po:
            print('   尺子自证: 对 %s(%s) 下毒 1 bit 被拒 ⇒ "%s"' % (po['target'], po['off'], po['caught'][:70]))
        if exp and exp != got:
            os.remove(p)
            raise SystemExit('REFUSE: %s 哈希不复现，已删除刚写的产物' % nm)
        ledger.append(rec)
    prof_out = os.path.join(outdir, 'proof.json')
    json.dump(dict(profile=os.path.basename(prof['path']), profile_id=prof['id'],
                   blueprint=dict(name=os.path.basename(a.inp), sha256=sha(fi), size=len(fi),
                                  image_base=hex(pe.image_base), dllchars=hex(pe.dllchars),
                                  entry=hex(pe.entry), sizeof_headers=pe.sizeof_headers),
                   preflight=dict(sites=[dict(id=i, rva=hex(r), off=hex(o), orig=h) for i, r, o, h in pf['sites']],
                                  external_jumps_into_bodies=pf['intr'],
                                  pdata_overlap_with_blob=pf['blob_fr'], checksum=
                                  {k: hex(v) for k, v in pf['ckd'].items()}, checksum_write=pf['ck_write']),
                   seconds=round(time.time() - t0, 1), outputs=ledger),
              io.open(prof_out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('\n总用时 %.1fs  台账=%s' % (time.time() - t0, os.path.relpath(prof_out, os.getcwd()).replace('\\', '/')))
    pin = [r for r in ledger if r['reproduced'] is not None]
    print('钉住 sha 的档位=%d/%d，全复现=%s；未钉住的档位=%s' % (
        len(pin), len(ledger), all(r['reproduced'] for r in pin) if pin else '（没钉任何档）',
        [r['name'] for r in ledger if r['reproduced'] is None]))



def cmd_derive(a):
    fi = open(a.inp, 'rb').read()
    pid = a.id or ('auto-' + sha(fi)[:12])
    dv = _derive.Deriver(fi)
    try:
        r = dv.run()
    except _derive.DeriveError as ex:
        raise SystemExit('REFUSE: 锚定失败——%s（绝不"取第一个匹配"，请人工加规则后重跑）' % ex)
    prof = _derive.emit(dv, r, pid, os.path.basename(a.inp))
    outdir = os.path.abspath(a.out)
    os.makedirs(outdir, exist_ok=True)
    pp = os.path.join(outdir, pid + '.derived.json')
    rp = os.path.join(outdir, pid + '.derive-report.json')
    if os.path.normcase(os.path.abspath(a.inp)) in (os.path.normcase(pp), os.path.normcase(rp)):
        raise SystemExit('REFUSE: 不许把推导结果写到输入位置')
    json.dump(prof, io.open(pp, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    json.dump(dict(profile_id=pid, input=dict(name=os.path.basename(a.inp), sha256=sha(fi), size=len(fi)),
                   evidence=r['evidence'],
                   image=dict(base=hex(dv.ib), entry=hex(dv.pe.entry), dllchars=hex(dv.pe.dllchars),
                              sections=[[x['n'], hex(x['va']), x['vs'], x['rs']] for x in dv.pe.sections])),
              io.open(rp, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    e = r['evidence']
    print('== derive ==  输入 %s sha=%s…' % (os.path.basename(a.inp), sha(fi)[:16]))
    print('  线程体      %#x  体=%s  引用=%s' % (r['body'], e['thread_body']['bounds'],
          [x.split(':')[1] for x in e['thread_body']['refs']]))
    print('  创建站点    %s  %s' % (e['spawn']['site'], e['spawn']['api']))
    print('  派发器      %s（共享全局 %s，组步长 %s）' % (
          e['dispatchers']['funcs'], e['dispatchers']['shared_global'], e['dispatchers']['group_stride']))
    print('  blob        %s..%s (%s B) 步长=%s 单元=%s 熵=%s 数组@%s 槽位命中reloc=%s' % (
          e['blob']['lo'], e['blob']['hi'], format(e['blob']['bytes'], ','), e['blob']['stride'],
          e['blob']['units'], e['blob']['entropy'], e['blob']['array_rva'], e['blob']['slots_in_reloc']))
    print('  派发表      %s（槽内偏移 %d）' % (e['table']['rva'], e['table']['dispatcher_slot_index']))
    print('  抹串        %s' % e['strings'])
    print('  对照组      %s' % e['controls'])
    print('  档位条目=%d 函数体=%d ⇒ %s | %s' % (len(prof['entries']), len(prof['bodies']),
          os.path.relpath(pp, os.getcwd()), os.path.relpath(rp, os.getcwd())))




def cmd_probe(a):
    from . import probe as _probe       # 只有 probe 子命令需要，GUI 路径不加载
    fi = open(a.inp, 'rb').read()
    rep = _probe.report(fi)
    os.makedirs(os.path.abspath(a.out), exist_ok=True)
    p = os.path.join(a.out, os.path.basename(a.inp) + '.probe.json')
    json.dump(rep, io.open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    h = rep['header']
    print('== probe ==  %s size=%d sha=%s…' % (os.path.basename(a.inp), rep['file']['size'], h and rep['file']['sha256'][:16]))
    print('  镜像基=%s 入口=%s SizeOfImage=%d DllChars=%s [%s]' % (
        h['image_base'], h['entry'], h['sizeof_image'], h['dllchars'], ', '.join(h['dllchars_decoded'])))
    print('  节=%s' % [[x[0], x[1], x[3], x[5]] for x in h['sections']])
    print('  目录=%s' % [[x[1], x[2], x[3]] for x in rep['directories']])
    print('  异常表函数=%d 共 %d B   重定位目标=%d' % (rep['exception']['functions'],
          rep['exception']['total_bytes'], rep['reloc']['targets']))
    lc = rep['loadcfg']
    print('  LoadConfig=%s size=%s GuardFlags=%s [%s] CF函数=%s SEH表项=%s 非零字节=%s' % (
        lc.get('present'), lc.get('size'), lc.get('guard_flags'),
        ','.join(lc.get('guard_flags_decoded', [])), lc.get('guard_cf_count'), lc.get('seh_count'),
        lc.get('nonzero_bytes')))
    print('                pefile 交叉对账=%s 一致=%s' % (json.dumps(lc.get('pefile_crosscheck'), ensure_ascii=False)[:120],
          lc.get('pefile_agrees')))
    print('  .text 高熵极大区间(前 4)=%s' % rep.get('high_entropy_spans_in_text', [])[:4])
    z = {k: v for k, v in rep['anchor_keyword_census'].items() if v}
    print('  锚关键字命中=%s  全零关键字=%s' % (json.dumps(z, ensure_ascii=False),
          [k for k, v in rep['anchor_keyword_census'].items() if not v]))
    print('  报告=%s' % p)



def cmd_verify_file(a):
    prof = _profile.load(a.profile)
    fi = _load_input(a.inp, prof)
    pe = _pe.PE(fi)
    prod = open(a.product, 'rb').read()
    # 重建必须与 cmd_build 用同一个 ck_write：校验和可复现时引擎会写回，固定 False 会让复核在这里不一致
    pf = _patch.preflight(fi, pe, prof)
    data, writes, _ = _patch.build(fi, pe, prof, a.tier, pf['ck_write'])
    if sha(prod) != sha(data):
        rr = _pe.diff_ranges(prod, data)
        raise SystemExit('REFUSE: 与 profile 重建结果不一致：%d 处差异 %s' % (len(rr), rr[:6]))
    rr, tot = _ruler.verify(prod, fi, pe, prof, a.tier, writes)
    print('%s tier=%d 复核通过：与重建逐字节相同；相对蓝本改动 %d B / %d 段，全部在计划内' % (
        os.path.basename(a.product), a.tier, tot, len(rr)))


def cmd_doctor(a):
    import numpy
    print('python=%s  numpy=%s  平台=%s' % (sys.version.split()[0], numpy.__version__, sys.platform))
    prof = _profile.load(a.profile) if a.profile else None
    if prof:
        print('profile=%s  档位=%s  入口=%d 函数体=%d 串=%d 控制组=%d' % (
            prof['id'], prof['tier_list'], len(prof['ents']), len(prof['bds']),
            len(prof['strs']), len(prof['ctrl'])))
        print('净化检查通过（无绝对路径/邮箱/长密文）')
    if a.inp:
        h = sha(open(a.inp, 'rb').read())
        print('输入 %s sha256=%s%s' % (os.path.basename(a.inp), h[:32],
              '  与 profile 相符' if prof and h == prof['blueprint']['sha256'] else ''))


def main(argv=None):
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    ap = argparse.ArgumentParser(prog='safecut', description='PE 保护逻辑定长摘除 + 自证尺子')
    sp = ap.add_subparsers(dest='cmd', required=True)
    b = sp.add_parser('build', help='按 profile 产出各档位')
    b.add_argument('--profile', required=True, help='profile 路径，或 auto 做代际识别')
    b.add_argument('--profile-dir', dest='profile_dir')
    b.add_argument('--in', dest='inp', required=True)
    b.add_argument('--out', required=True)
    b.add_argument('--only', help='逗号分隔的档位号，如 4')
    b.add_argument('--expect-sha', help='逗号分隔的期望产物 sha256，任一不符即红并删除')
    b.set_defaults(fn=cmd_build)
    pb = sp.add_parser('probe', help='只读体检报告')
    pb.add_argument('--in', dest='inp', required=True)
    pb.add_argument('--out', required=True)
    pb.set_defaults(fn=cmd_probe)
    dv = sp.add_parser('derive', help='从一颗 PE 自动推导 profile（只读输入）')
    dv.add_argument('--in', dest='inp', required=True)
    dv.add_argument('--out', required=True)
    dv.add_argument('--id')
    dv.set_defaults(fn=cmd_derive)
    v = sp.add_parser('verify-file', help='复核一个已存在的产物')
    v.add_argument('--profile', required=True)
    v.add_argument('--in', dest='inp', required=True)
    v.add_argument('--product', required=True)
    v.add_argument('--tier', type=int, required=True)
    v.set_defaults(fn=cmd_verify_file)
    d = sp.add_parser('doctor', help='环境与 profile 净化自检')
    d.add_argument('--profile')
    d.add_argument('--in', dest='inp')
    d.set_defaults(fn=cmd_doctor)
    from . import cmd_live
    cmd_live.register(sp)
    a = ap.parse_args(argv)
    try:
        a.fn(a)
    except (SystemExit, KeyboardInterrupt):
        raise
    except (_profile.ProfileError, _derive.DeriveError, _pe.PEError, RuntimeError, ValueError) as ex:
        raise SystemExit('REFUSE: %s: %s' % (type(ex).__name__, ex))


if __name__ == '__main__':
    main()
