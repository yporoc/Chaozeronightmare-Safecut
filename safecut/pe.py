"""PE x64 底盘：节表/数据目录/重定位/校验和/差异区段。只做解析与计算，不含任何目标程序语义。"""
import struct
import re
import math
from collections import Counter

DIR = ['export', 'import', 'resource', 'exception', 'cert', 'basereloc', 'debug', 'arch',
       'globalptr', 'tls', 'loadcfg', 'boundimp', 'iat', 'delayimp', 'clr', 'reserved']


class PEError(RuntimeError):
    pass


class PE:
    def __init__(self, buf):
        self.b = buf
        elf = struct.unpack_from('<I', buf, 0x3C)[0]
        if buf[elf:elf + 4] != b'PE\x00\x00':
            raise PEError('e_lfanew %#x 处没有 PE 头' % elf)
        co = elf + 4
        self.machine = struct.unpack_from('<H', buf, co)[0]
        ns = struct.unpack_from('<H', buf, co + 2)[0]
        self.oz = struct.unpack_from('<H', buf, co + 16)[0]
        o = co + 20
        if struct.unpack_from('<H', buf, o)[0] != 0x20b:
            raise PEError('不是 PE32+（魔法 %s），本工具只处理 x64' % hex(struct.unpack_from('<H', buf, o)[0]))
        self.o = o
        self.opt_size = o + self.oz
        self.sections = []
        for i in range(ns):
            q = self.opt_size + i * 40
            vs, va, rs, rp = struct.unpack_from('<IIII', buf, q + 8)
            self.sections.append(dict(n=buf[q:q + 8].rstrip(b'\0').decode('latin1'),
                                      vs=vs, va=va, rs=rs, rp=rp))
        self.dd = o + 112
        self.checksum_off = o + 64
        self.image_base = struct.unpack_from('<Q', buf, o + 24)[0]
        self.sizeof_image = struct.unpack_from('<I', buf, o + 56)[0]
        self.sizeof_headers = struct.unpack_from('<I', buf, o + 60)[0]
        self.dllchars = struct.unpack_from('<H', buf, o + 70)[0]
        self.entry = struct.unpack_from('<I', buf, o + 16)[0]

    def dir(self, i):
        return struct.unpack_from('<II', self.b, self.dd + i * 8)

    def sect_of(self, rva):
        for x in self.sections:
            if x['va'] <= rva < x['va'] + max(x['vs'], x['rs']):
                return x
        return None

    def r2o(self, rva):
        x = self.sect_of(rva)
        if x is None:
            raise PEError('RVA %#x 不落任何节' % rva)
        return x['rp'] + (rva - x['va'])

    def o2r(self, off):
        for x in self.sections:
            if x['rp'] <= off < x['rp'] + x['rs']:
                return x['va'] + (off - x['rp'])
        raise PEError('文件偏移 %#x 不落任何节' % off)

    def functions(self):
        """异常目录 (.pdata) 里的 (Begin,End,Unwind) 三元组。"""
        rva, sz = self.dir(3)
        if not rva:
            return []
        p = self.r2o(rva)
        out = []
        for i in range(sz // 12):
            a, b, u = struct.unpack_from('<III', self.b, p + i * 12)
            if 0 < a < b:
                out.append((a, b, u))
        return sorted(out)

    def reloc_targets(self):
        """基址重定位目标 RVA 集合，含类型号（5=HIGHLOW 10=DIR64）。"""
        rva, sz = self.dir(5)
        if not rva:
            return set()
        p = self.r2o(rva)
        out = set()
        off, end = p, p + sz
        while off + 8 <= end:
            page, tot = struct.unpack_from('<II', self.b, off)
            if not tot:
                break
            for j in range((tot - 8) // 2):
                e16 = struct.unpack_from('<H', self.b, off + 8 + j * 2)[0]
                if e16 >> 12 in (5, 10):
                    out.add(page + (e16 & 0xFFF))
            off += tot
        return out

    def cert(self):
        return self.dir(4)


def checksum16(buf):
    """PE 头部 CheckSum 字段的标准算法（16 位累加 + 长度）。"""
    import numpy as np
    a = np.frombuffer(buf, dtype=np.uint16)
    s = int(a[:len(a) // 2 * 2].astype(np.uint64).sum())
    s = (s & 0xFFFF) + (s >> 16)
    s = (s + (s >> 16)) & 0xFFFF
    if len(buf) & 1:
        s = (s + buf[-1]) & 0xFFFF
    s = (s + (s >> 16)) & 0xFFFF
    return (s + len(buf)) & 0xFFFFFFFF


def diff_ranges(a, b):
    """两个等长缓冲的不相同起始文件偏移区段 [(start,end)]。"""
    import numpy as np
    if len(a) != len(b):
        raise PEError('长度不等 %d/%d' % (len(a), len(b)))
    ne = np.nonzero(np.frombuffer(a, np.uint8) != np.frombuffer(b, np.uint8))[0]
    if not len(ne):
        return []
    brk = np.nonzero(np.diff(ne) > 1)[0]
    st = np.concatenate(([ne[0]], ne[brk + 1]))
    en = np.concatenate((ne[brk], [ne[-1]])) + 1
    return list(zip(st.tolist(), en.tolist()))


def entropy(d):
    c = Counter(d)
    n = len(d) or 1
    return -sum(v / n * math.log2(v / n) for v in c.values())


RIP_PAT = re.compile(rb'([\x48\x4c][\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d])(.{4})', re.S)


def rip_targets(buf, base_rva, lo_off, hi_off):
    """给出 [lo_off,hi_off) 内所有 rip 相对指令的 (指令文件偏移, 目标RVA)。"""
    out = []
    seg = buf[lo_off:hi_off]
    for m in RIP_PAT.finditer(seg):
        off = lo_off + m.start()
        out.append((off, base_rva + off + 7 + struct.unpack('<i', m.group(2))[0]))
    return out
