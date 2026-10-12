# -*- coding: utf-8 -*-
"""图形界面：「只读检测」列作用点是否存在，「执行」按检测结果构建产物。
输入只读，只写输出目录；--analyze <exe> 与 --selfcheck 为无界面入口。
"""
import argparse
import contextlib
import io
import json
import os
import queue
import re
import sys
import threading

import customtkinter as ctk
from tkinter import filedialog, messagebox

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
if os.path.isdir(os.path.join(REPO, 'tools')):
    sys.path.insert(0, os.path.join(REPO, 'tools'))
import paths  # noqa: E402
ENGINE = paths.engine_dir()
if ENGINE not in sys.path:
    sys.path.insert(0, ENGINE)
import compat  # noqa: E402
from safecut import cli as scl  # noqa: E402
from safecut.pe import PE  # noqa: E402

C_BG, C_PANEL, C_LOG, C_ACCENT, C_OK = '#1a1a1c', '#202024', '#121214', '#0a84ff', '#3fb950'
C_WARN, C_ERR, C_FG, C_DIM = '#d29922', '#f85149', '#e6edf3', '#8b949e'
TIER_IN_LINE = re.compile(r'\bV\d-[a-z][a-z0-9-]*\b')
TIER_EQ = re.compile(r'\btier=\d+')
N_LINE = re.compile(r'改动=(\d+) B / (\d+) 段')
T_LINE = re.compile(r'总用时 ([\d.]+)s')


def sha(p):
    import hashlib
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 24), b''):
            h.update(b)
    return h.hexdigest()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('safecut')
        self.geometry('1000x620')
        self.minsize(820, 480)
        self.configure(fg_color=C_BG)
        ctk.set_appearance_mode('dark')
        self.q = queue.Queue()
        self.busy = False
        self.det = None          # (源路径, rows, prof, meta)：执行只认这份检测结果
        self.interactive = True  # 命令行入口置 False：没有弹窗可问，缺失项按跳过继续

        body = ctk.CTkFrame(self, fg_color='transparent')
        body.pack(fill='both', expand=True, padx=12, pady=10)
        self.log = ctk.CTkTextbox(body, font=('Consolas', 13), fg_color=C_LOG, text_color=C_FG,
                                  corner_radius=10, wrap='word')
        self.log.pack(side='left', fill='both', expand=True)
        self.init_tags()

        panel = ctk.CTkFrame(body, fg_color=C_PANEL, width=300, corner_radius=10)
        panel.pack(side='right', fill='y', padx=(12, 0))
        panel.pack_propagate(False)
        ctk.CTkLabel(panel, text='源文件', text_color=C_DIM, anchor='w', font=('Segoe UI', 12)).pack(
            fill='x', padx=14, pady=(16, 2))
        row = ctk.CTkFrame(panel, fg_color='transparent')
        row.pack(fill='x', padx=12)
        self.src = ctk.CTkEntry(row, text_color=C_FG, fg_color='#101014', border_color='#3a3a40')
        self.src.pack(side='left', fill='x', expand=True)
        ctk.CTkButton(row, text='浏览', width=56, height=26, fg_color='#2f3037', hover_color='#3a3a40',
                      text_color=C_FG, command=self.pick).pack(side='right', padx=(6, 0))

        ctk.CTkLabel(panel, text='输出目录', text_color=C_DIM, anchor='w', font=('Segoe UI', 12)).pack(
            fill='x', padx=14, pady=(12, 2))
        self.out = ctk.CTkEntry(panel, text_color=C_FG, fg_color='#101014', border_color='#3a3a40')
        self.out.insert(0, paths.default_out())
        self.out.pack(fill='x', padx=14)
        ctk.CTkButton(panel, text='打开输出目录', height=28, fg_color='transparent',
                      hover_color='#2f3037', border_color='#3a3a40', border_width=1,
                      text_color=C_DIM, font=('Segoe UI', 11), command=self.open_out).pack(
            fill='x', padx=14, pady=(6, 0))

        self.btn_scan = ctk.CTkButton(panel, text='只读检测', height=42, fg_color='#2f3037',
                                      hover_color='#3a3a40', text_color=C_FG, font=('Segoe UI', 14),
                                      command=lambda: self.go(self.do_detect))
        self.btn_scan.pack(fill='x', padx=14, pady=(20, 6))
        self.btn_run = ctk.CTkButton(panel, text='执行', height=50, fg_color=C_ACCENT, hover_color='#0672d9',
                                     text_color='#fff', font=('Segoe UI', 16, 'bold'),
                                     command=lambda: self.go(self.do_exec))
        self.btn_run.pack(fill='x', padx=14, pady=(0, 14))

        self.status = ctk.CTkLabel(self, text='就绪：选择 exe，点“只读检测”', anchor='w',
                                   text_color=C_FG, fg_color=C_PANEL, height=30, corner_radius=0)
        self.status.pack(fill='x', side='bottom')
        self.after(60, self.pump)

    # ---------- 通用 ----------
    def _tb(self):
        return getattr(self.log, '_textbox', None)

    def say(self, s, col=None):
        # CTkTextbox 的 text_color 是控件级前景色：按行改色会把全文重染 ⇒ 用 Tk tag 上色
        tb = self._tb()
        if tb is None:
            self.log.insert('end', s + '\n')
        else:
            tag = {C_OK: 'ok', C_ERR: 'err', C_WARN: 'warn', C_DIM: 'dim'}.get(col)
            tb.insert('end', s + '\n', (tag,) if tag else ())
        self.log.see('end')

    def init_tags(self):
        tb = self._tb()
        if tb is not None:
            for tag, c in (('ok', C_OK), ('err', C_ERR), ('warn', C_WARN), ('dim', C_DIM)):
                tb.tag_configure(tag, foreground=c)

    def head(self, s):
        self.q.put(('line', ('', C_DIM)))
        self.q.put(('line', ('── %s ' % s + '─' * max(2, 52 - len(s)), C_DIM)))

    def row(self, label, value, col=None):
        self.q.put(('line', ('%-6s %s' % (label, value), col)))

    def set_status(self, s, col=C_FG):
        self.status.configure(text=s, text_color=col)

    def pick(self):
        p = filedialog.askopenfilename(title='选择要处理的 exe', filetypes=[('exe', '*.exe'), ('所有', '*.*')])
        if p:
            self.src.delete(0, 'end')
            self.src.insert(0, p)
            self.det = None

    def open_out(self):
        d = self.out.get().strip() or paths.default_out()
        os.makedirs(d, exist_ok=True)
        try:
            os.startfile(d)
        except Exception as ex:
            self.q.put(('line', ('打不开输出目录：%r' % ex, C_WARN)))

    def pump(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == 'line':
                    txt, col = payload if isinstance(payload, tuple) else (payload, None)
                    self.say(txt, col)
                elif kind == 'done':
                    self.busy = False
                    self.set_status(*payload)
        except queue.Empty:
            pass
        self.after(60, self.pump)

    def go(self, fn):
        if self.busy:
            self.set_status('正在执行，请稍候', C_WARN)
            return
        self.busy = True
        self.set_status('执行中…', C_WARN)
        threading.Thread(target=self.worker, args=(fn,), daemon=True).start()

    def worker(self, fn):
        try:
            ok, msg = fn()
            self.q.put(('done', (msg, C_OK if ok else C_ERR)))
        except Exception as ex:
            self.q.put(('line', ('异常：%r' % ex, C_ERR)))
            self.q.put(('done', ('失败：%r' % ex, C_ERR)))

    def eng(self, fn, ns):
        """调用引擎自身的命令行函数（与命令行同一份代码），捕获其打印，退出码即结论。"""
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                fn(argparse.Namespace(**ns))
            rc = 0
        except SystemExit as ex:
            rc = ex.code if isinstance(ex.code, int) else 0
            if rc == 0 and ex.code not in (None, '', 0):
                buf.write('\n%s' % ex.code)
                rc = 1
        return rc, buf.getvalue()

    @staticmethod
    def digest(txt):
        """引擎输出压成三行：前置、构建、尺子自证；失败时原样给出全部输出便于定位。"""
        out = []
        pre = [l.strip() for l in txt.splitlines() if 'PRISTINE' in l or '外部跳入体内' in l]
        if pre:
            out.append('前置    ' + '；'.join(x.split('  ')[-1] for x in pre))
        m = N_LINE.search(txt)
        t = T_LINE.search(txt)
        if m:
            out.append('构建    改动 %s B / %s 段%s' % (
                format(int(m.group(1)), ','), m.group(2), ('  用时 %ss' % t.group(1)) if t else ''))
        for l in txt.splitlines():
            if '尺子自证' in l:
                out.append('自证    ' + l.split('尺子自证:')[-1].strip()[:96])
        return out

    # ---------- ① 只读检测 ----------
    def detect(self, path):
        self.head('输入')
        buf = open(path, 'rb').read()
        pe = PE(buf)
        self.row('文件', '%s    %s B    sha256 %s…' % (
            os.path.basename(path), format(len(buf), ','), sha(path)[:16]))
        self.row('PE', 'x64  镜像 %s  节 %d  入口 %s' % (
            hex(pe.sizeof_image), len(pe.sections), hex(pe.entry)))
        self.head('检测（只读）')
        rows, prof, meta = compat.scan(path, stamp=False)
        for g, nm, ok, why in rows:
            if g == '结论':
                continue
            self.q.put(('line', ('%-6s %-26s %s' % ('在' if ok else '缺', nm, str(why)[:98]),
                                 C_FG if ok else C_ERR)))
        return rows, prof, meta

    def do_detect(self):
        path = self.src.get().strip().strip('"')
        if not path or not os.path.exists(path):
            self.q.put(('line', ('拒绝：源文件不存在', C_ERR)))
            return False, '源文件不存在'
        rows, prof, meta = self.detect(path)
        miss = [(g, nm, why) for g, nm, ok, why in rows if not ok]
        self.det = (path, rows, prof, meta)
        if prof is None:
            self.q.put(('line', ('结论    该文件内没有可定位的作用点，不能执行', C_ERR)))
            return False, '没有可执行的东西'
        if miss:
            self.row('结论', '缺 %d 项，可执行但会跳过缺失项' % len(miss), C_WARN)
            for g, nm, why in miss:
                self.row('缺失', '%s：%s' % (nm, str(why)[:80]), C_WARN)
            return True, '检测完成：有缺失'
        self.row('结论', '作用点全部找到，可以执行', C_OK)
        return True, '检测完成：全部找到'

    # ---------- ② 执行 ----------
    def ask_missing(self, miss):
        """界面里弹窗问要不要跳过着做；命令行入口没有弹窗，直接按跳过继续并把这句话写进日志。"""
        if self.interactive:
            return messagebox.askyesno(
                '存在未找到的作用点',
                '\n'.join('%s：%s' % (nm, str(w)[:60]) for g, nm, w in miss) +
                '\n\n是否继续？未找到的项将被跳过，已找到的正常处理。')
        self.row('结果', '无界面模式：继续执行，未找到的 %d 项跳过' % len(miss), C_WARN)
        return True

    def do_exec(self):
        path = self.src.get().strip().strip('"')
        if not self.det or self.det[0] != path:
            self.q.put(('line', ('拒绝：需要先完成一次只读检测', C_ERR)))
            return False, '还没检测'
        _p, rows, prof, meta = self.det
        if prof is None:
            self.q.put(('line', ('拒绝：该文件内没有可定位的作用点', C_ERR)))
            return False, '没有可执行的东西'
        miss = [(g, nm, why) for g, nm, ok, why in rows if not ok]
        if miss and not self.ask_missing(miss):
            self.row('结果', '未执行，未写入任何文件', C_WARN)
            return False, '未执行'
        outdir = self.out.get().strip() or paths.default_out()
        if os.path.normcase(os.path.abspath(outdir)) == os.path.normcase(os.path.dirname(os.path.abspath(path))):
            self.q.put(('line', ('拒绝：输出目录与源文件同目录', C_ERR)))
            return False, '输出目录不安全'
        os.makedirs(outdir, exist_ok=True)
        before = (sha(path), os.path.getsize(path), os.path.getmtime(path))
        prof['id'] = 'pt-' + meta['sha256'][:12]
        prof['product_prefix'] = prof['id']
        prof['blueprint'] = dict(name=meta['input'], sha256=meta['sha256'], size=meta['size'])
        pd = paths.profiles_dir()
        os.makedirs(pd, exist_ok=True)
        pp = os.path.join(pd, prof['id'] + '.json')
        io.open(pp, 'w', encoding='utf-8').write(json.dumps(prof, ensure_ascii=False, indent=1))
        top = max(t['tier'] for t in prof['tiers'])
        self.head('执行')
        tmp = os.path.join(outdir, '_build')
        rc, txt = self.eng(scl.cmd_build, dict(profile=pp, profile_dir=None, inp=path, out=tmp,
                                               only=str(top), expect_sha=None))
        made = [f for f in os.listdir(tmp) if f.endswith('.exe')] if os.path.isdir(tmp) else []
        if rc != 0 or not made:
            self.q.put(('line', ('构建失败（退出码 %d），未产出' % rc, C_ERR)))
            for l in txt.strip().splitlines()[-12:]:
                self.q.put(('line', ('    ' + TIER_EQ.sub('', TIER_IN_LINE.sub('', l)), C_DIM)))
            return False, '构建失败'
        fp = os.path.join(outdir, '%s-noac.exe' % prof['id'])
        os.replace(os.path.join(tmp, made[0]), fp)
        try:
            os.remove(os.path.join(tmp, 'proof.json'))
            os.rmdir(tmp)
        except OSError:
            pass
        for l in self.digest(txt):
            self.q.put(('line', ('    ' + l, C_DIM)))
        rc2, txt2 = self.eng(scl.cmd_verify_file, dict(profile=pp, inp=path, product=fp, tier=top))
        alive = True
        if meta.get('their_ranges'):
            inp, outb = open(path, 'rb').read(), open(fp, 'rb').read()
            gone = [x for x in meta['their_ranges'] if inp[x[0]:x[1]] != outb[x[0]:x[1]]]
            alive = not gone
            self.row('他人改动', '%d 处，存活 %d，被抹掉 %d' % (
                len(meta['their_ranges']), len(meta['their_ranges']) - len(gone), len(gone)))
        same = (sha(path), os.path.getsize(path), os.path.getmtime(path)) == before
        ok = rc2 == 0 and alive and same
        self.head('结果')
        self.row('复核', '三条判据通过' if rc2 == 0 else '复核未通过', C_OK if rc2 == 0 else C_ERR)
        self.row('产物', fp)
        self.row('', 'sha256 %s…    %s B（与原文件同尺寸）' % (
            sha(fp)[:16], format(os.path.getsize(fp), ',')))
        self.row('跳过', '、'.join(nm for _g, nm, _w in miss) or '无')
        self.row('源文件', '未改动（sha / 大小 / 修改时间一致）' if same else '警告：源文件属性发生变化',
                 C_OK if same else C_ERR)
        return ok, '完成' if ok else '执行未完全通过'


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    a = App()
    if '--selfcheck' in sys.argv:
        # 自检结果一律落盘：无控制台的 exe 里 sys.stdout 可能是 None
        a.update()
        txt = 'RESULT OK | python=%s frozen=%s ctk=%s engine=%s profiles=%s out=%s\n' % (
            sys.version.split()[0], bool(getattr(sys, 'frozen', False)),
            getattr(ctk, '__version__', '?'), ENGINE, paths.profiles_dir(), paths.default_out())
        a.destroy()
        try:
            print(txt)
        except Exception:
            pass
        with io.open(os.path.join(paths.app_dir(), 'safecut-selfcheck.txt'), 'w', encoding='utf-8') as f:
            f.write(txt)
        return 0
    if '--analyze' in sys.argv:
        a.update()
        a.src.insert(0, sys.argv[sys.argv.index('--analyze') + 1])
        ok, msg = a.do_detect()
        a.pump()
        a.update()
        txt = '\n'.join(a.log.get('1.0', 'end').splitlines()[-40:]) + \
            '\nRESULT %s | %s\n' % ('OK' if ok else 'RED', msg)
        try:
            print(txt)
        except Exception:
            pass        # 无控制台的冻结 exe 里 sys.stdout 可能为 None
        with io.open(os.path.join(paths.app_dir(), 'safecut-analyze.txt'), 'w', encoding='utf-8') as f:
            f.write(txt)   # 同一份内容落盘，供脚本化验收读取
        return 0 if ok else 1
    if '--build' in sys.argv:
        # 无界面走同一条流程：检测 → 执行（缺失项跳过并说明）→ 复核；结果既打印也落盘
        i = sys.argv.index('--build')
        if len(sys.argv) <= i + 1:
            return 2
        a.interactive = False
        a.update()
        a.src.insert(0, sys.argv[i + 1])
        if len(sys.argv) > i + 2:
            a.out.delete(0, 'end')
            a.out.insert(0, sys.argv[i + 2])
        ok, msg = a.do_detect()
        if ok:
            ok, msg = a.do_exec()
        a.pump()
        a.update()
        txt = '\n'.join(a.log.get('1.0', 'end').splitlines()[-60:]) + \
            '\nRESULT %s | %s\n' % ('OK' if ok else 'RED', msg)
        try:
            print(txt)
        except Exception:
            pass
        with io.open(os.path.join(paths.app_dir(), 'safecut-build.txt'), 'w', encoding='utf-8') as f:
            f.write(txt)
        return 0 if ok else 1
    a.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
