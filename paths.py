# -*- coding: utf-8 -*-
"""路径解析：机器路径只来自环境变量与本机登记表，源码里不写死绝对路径。"""
import os
import sys

REPO = os.path.dirname(os.path.abspath(__file__))
LOCAL = os.path.join(REPO, 'local_paths.txt')
SAMPLES = os.path.join(REPO, 'local_samples.txt')


def app_dir():
    """可写数据目录：开发时为仓库，冻结后为 exe 所在目录（_MEIPASS 里的东西退出即没）。"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return REPO


def profiles_dir():
    return os.path.join(app_dir(), 'profiles')


def default_out():
    """产物目录：一律 ASCII 路径（冻结后落在 exe 同级的 out\\，不出现中文目录名）。"""
    return os.path.join(app_dir(), 'out') if getattr(sys, 'frozen', False) \
        else os.path.join(app_dir(), 'out', 'gui')


def engine_dir():
    """定位引擎目录（其下有 safecut/pe.py）：冻结、pip 安装、同级开发区、解包根四种布局都要成立。"""
    if getattr(sys, 'frozen', False):
        return getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(sys.executable)))
    try:
        import importlib.util
        sp = importlib.util.find_spec('safecut')
    except Exception:
        sp = None
    if sp and sp.origin and os.path.exists(sp.origin):
        return os.path.dirname(os.path.dirname(sp.origin))
    d = REPO
    while True:
        # 两种布局：解包后 <根>/safecut/pe.py；开发区引擎是工作台的同级目录
        for cand in (d, os.path.join(d, 'safecut')):
            if os.path.exists(os.path.join(cand, 'safecut', 'pe.py')):
                return cand
        p = os.path.dirname(d)
        if p == d:
            break
        d = p
    raise SystemExit('找不到 safecut 引擎目录（期望其下有 safecut/pe.py）。两条出路：'
                     '在解包根目录跑 python -m pip install . ，或把引擎所在目录加进 PYTHONPATH。')


def candidates():
    out = []
    v = os.environ.get('CZN_GAME_EXE')
    if v:
        out.append(v)
    if os.path.exists(LOCAL):
        for line in open(LOCAL, encoding='utf-8'):
            line = line.strip()
            if line and not line.startswith('#'):
                out.append(line)
    return [p for p in out if p]


def game_exe():
    for p in candidates():
        if os.path.exists(p):
            return p
    return ''


def factory_original():
    g = game_exe()
    if not g:
        return ''
    for suf in ('.1', '.orig', '.bak'):
        if os.path.exists(g + suf):
            return g + suf
    return ''


def write_local(paths):
    with open(LOCAL, 'w', encoding='utf-8') as f:
        f.write('# 由 laydown.py 在本机生成，只给本地脚本用；不随包分发\n')
        for p in paths:
            f.write(p + '\n')


def blueprint():
    """蓝本（未抹原版）：CZN_BLUEPRINT 优先，否则取工作区默认文件名；找不到返回空串由调用方报错。"""
    v = os.environ.get('CZN_BLUEPRINT')
    if v and os.path.exists(v):
        return v
    d = os.path.join(os.path.dirname(REPO), 'ssr-stove-shield.exe.exe')
    return d if os.path.exists(d) else (v or '')


def samples():
    """本机登记的额外样本（打过别的补丁的真实 exe），单放 local_samples.txt 以免被 laydown 重写。"""
    out = []
    if os.path.exists(SAMPLES):
        for line in open(SAMPLES, encoding='utf-8'):
            line = line.strip()
            if line and not line.startswith('#') and os.path.exists(line):
                out.append(line)
    return out
