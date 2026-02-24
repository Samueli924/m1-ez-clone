from m1.schemas import dll, HID_DEVICE
from m1.error import HidError, check_status
from m1.constants import *
from ctypes import c_ushort, c_ubyte, byref
import time
from pathlib import Path
import json
import sys
from m1.utils import _banner

DEBUG = False

KEY_A_MODE = 0x60
KEY_B_MODE = 0x61

NUM_SECTORS = 16
BLOCKS_PER_SECTOR = 4
TOTAL_BLOCKS = NUM_SECTORS * BLOCKS_PER_SECTOR  # 64

WUPA_MODE = 0x52  # 所有状态的卡
REQA_MODE = 0x26  # 未休眠的卡

class HidReader:
    def __init__(self, vid=VID, pid=PID, index=0):
        self.vid = vid
        self.pid = pid
        self.index = index
        self.device = HID_DEVICE(-1)
        self._opened = False

    def open(self):
        if self._opened:
            return

        ret = dll.Sys_Open(byref(self.device), self.index, self.vid, self.pid)

        if DEBUG:
            print(
                f"Opening HID device {self.device.value} (index={self.index}, vid={self.vid:04X}, pid={self.pid:04X})"
            )

        check_status(ret, "Sys_Open")

        self._opened = True

    def close(self):
        if self._opened:
            dll.Sys_Close(byref(self.device))
            self.device = HID_DEVICE(-1)
            self._opened = False

    def set_mode(self, mode: str = "A"):
        if mode not in ["A", "B", "r", "s", "l"]:
            raise ValueError("Invalid mode")

        ret = dll.Sys_InitType(self.device, ord(mode))
        check_status(ret, "Sys_InitType")

    def set_antenna(self, antenna: int = 1):
        if antenna not in [0, 1]:
            raise ValueError("Invalid antenna")

        ret = dll.Sys_SetAntenna(self.device, antenna)
        check_status(ret, "Sys_SetAntenna")

    def __enter__(self):
        """
        初始化读写器，设置ISO14443A方式，并启用天线
        """
        self.open()

        self.set_mode("A")

        self.set_antenna(1)

        return self

    def __exit__(self, exc_type, exc, tb):
        """
        关闭读写器，并禁用天线
        """
        self.set_antenna(0)

        self.close()


class MifareSession:
    """Mifare Classic 操作会话（ISO14443A Type A）"""

    def __init__(self, reader: HidReader):
        if not reader._opened:
            raise HidError("Reader not opened")

        self.reader = reader
        self.device = reader.device
        self.selected = False
        self.uid: bytes | None = None
        self.sak: int | None = None

    # ---------- 初始化流程 ----------

    def request(self, mode=WUPA_MODE) -> int:
        """发送 Request，返回 ATQA 值"""
        tag_type = c_ushort()
        ret = dll.TyA_Request(self.device, mode, byref(tag_type))
        check_status(ret, "TyA_Request")
        if DEBUG:
            print(f"Tag type: {tag_type.value} (0x{tag_type.value:02X})")
        return tag_type.value

    def anticoll(self) -> bytes:
        snr = (c_ubyte * 10)()
        snr_len = c_ubyte()
        ret = dll.TyA_Anticollision(self.device, c_ubyte(0), snr, byref(snr_len))
        check_status(ret, "TyA_Anticollision")
        if DEBUG:
            print(f"SNR: {bytes(snr[:snr_len.value])}")
            print(f"SNR length: {snr_len.value}")
        return bytes(snr[: snr_len.value])


    def select(self, uid: bytes) -> int:
        """
        TyA_Select — Level 1 选卡（适用于 4 字节 UID 的 Mifare Classic 卡）。
        uid   : 4 字节卡序列号（由上层防冲撞步骤获得）
        返回   : SAK 字节（整数）
        """
        if len(uid) != 4:
            raise ValueError(f"TyA_Select 需要 4 字节 UID，实际传入 {len(uid)} 字节")

        snr = (c_ubyte * 4)(*uid)
        sak = c_ubyte()

        ret = dll.TyA_Select(self.device, snr, c_ubyte(4), byref(sak))
        check_status(ret, "TyA_Select")

        self.uid = bytes(uid)
        self.sak = sak.value
        self.selected = True
        if DEBUG:
            print(f"SAK: {sak.value} (0x{sak.value:02X})")
        return sak.value

    def halt(self):
        ret = dll.TyA_Halt(self.device)
        check_status(ret, "TyA_Halt")
        self.selected = False

    def reselect(self) -> int:
        """
        Halt → Request → Anticoll → Select，用于认证失败后重新激活卡片。
        返回 SAK 值。
        """
        try:
            dll.TyA_Halt(self.device)
        except Exception:
            pass
        self.selected = False

        tag_type = c_ushort()
        ret = dll.TyA_Request(self.device, WUPA_MODE, byref(tag_type))
        if ret != 0:
            return -1

        snr = (c_ubyte * 10)()
        snr_len = c_ubyte()
        ret = dll.TyA_Anticollision(self.device, c_ubyte(0), snr, byref(snr_len))
        if ret != 0:
            return -1

        uid = bytes(snr[: snr_len.value])
        if len(uid) != 4:
            return -1

        snr4 = (c_ubyte * 4)(*uid)
        sak = c_ubyte()
        ret = dll.TyA_Select(self.device, snr4, c_ubyte(4), byref(sak))
        if ret != 0:
            return -1

        self.uid = uid
        self.sak = sak.value
        self.selected = True
        return sak.value

    def authenticate(self, mode: int, block: int, key: bytes) -> int:
        """
        使用 TyA_CS_Authentication2 验证指定扇区块的密钥。

        mode  : 0x60 -> Key A；0x61 -> Key B
        block : 绝对块号（扇区首块，sector * 4）
        key   : 6 字节密钥
        返回  : 0 表示成功，其它为错误码（不抛出异常）
        """
        if len(key) != 6:
            raise ValueError("密钥必须为 6 字节")
        arr = (c_ubyte * 6)(*key)
        return dll.TyA_CS_Authentication2(
            self.device, c_ubyte(mode), c_ubyte(block), arr
        )

    # ---------- 读写 ----------

    def read_block(self, block: int) -> bytes:
        """
        调用 TyA_CS_Read 读取指定绝对块（16 字节）。
        调用前必须已通过 authenticate() 完成扇区认证。
        """
        self._require_selected()
        buf = (c_ubyte * 16)()
        buf_len = c_ubyte()
        ret = dll.TyA_CS_Read(self.device, c_ubyte(block), buf, byref(buf_len))
        check_status(ret, f"TyA_CS_Read(block={block})")
        if DEBUG:
            print(f"Read block {block}: {bytes(buf[:buf_len.value]).hex().upper()}")
        return bytes(buf[: buf_len.value])

    def write_block(self, block: int, data: bytes):
        """
        调用 TyA_CS_Write 向指定绝对块写入 16 字节。
        调用前必须已通过 authenticate() 完成扇区认证。
        """
        self._require_selected()
        if len(data) != 16:
            raise ValueError(f"Mifare 块必须写入恰好 16 字节，当前 {len(data)} 字节")
        arr = (c_ubyte * 16)(*data)
        ret = dll.TyA_CS_Write(self.device, c_ubyte(block), arr)
        check_status(ret, f"TyA_CS_Write(block={block})")
        if DEBUG:
            print(f"Write block {block}: {data.hex().upper()}")

    # ---------- 内部 ----------

    def _require_selected(self):
        if not self.selected:
            raise HidError("Mifare card not selected")


def wait_for_card(mf: MifareSession) -> tuple[int, bytes, int]:
    """阻塞直到检测到卡片，返回 (atqa, uid, sak)"""
    while True:
        try:
            atqa = mf.request()
            uid = mf.anticoll()
            sak = mf.select(uid)
            return atqa, uid, sak
        except Exception:
            time.sleep(0.1)


def brute_sector(mf: MifareSession, sector: int, key_dict: list[bytes]):
    """对单个扇区爆破 Key A 和 Key B，返回 (keyA_hex|None, keyB_hex|None)"""
    block = sector * BLOCKS_PER_SECTOR
    found_a: str | None = None
    found_b: str | None = None

    for key in key_dict:
        if mf.reselect() < 0:
            time.sleep(0.05)
            continue
        if mf.authenticate(KEY_A_MODE, block, key) == 0:
            found_a = key.hex().upper()
            break

    for key in key_dict:
        if mf.reselect() < 0:
            time.sleep(0.05)
            continue
        if mf.authenticate(KEY_B_MODE, block, key) == 0:
            found_b = key.hex().upper()
            break

    return found_a, found_b


# ── DUMP ──────────────────────────────────────────────────────────────────────

def cmd_dump(output: Path, key_dict: list[bytes], debug: bool = False):
    global DEBUG
    DEBUG = debug

    _banner(f"DUMP 模式  →  {output}")

    with HidReader() as reader:
        mf = MifareSession(reader)

        print("请将 Mifare Classic 卡片放在读卡器上…")
        atqa, uid, sak = wait_for_card(mf)
        uid_str = " ".join(f"{b:02X}" for b in uid)
        print(f"  UID  : {uid_str}")
        print(f"  ATQA : 0x{atqa:04X}  SAK : 0x{sak:02X}\n")

        # ── 阶段一：爆破所有扇区密钥 ──
        _banner(f"阶段一：密钥爆破（字典 {len(key_dict)} 条）")
        sector_keys: dict[int, dict] = {}

        for sector in range(NUM_SECTORS):
            blk = sector * BLOCKS_PER_SECTOR
            print(f"  Sector {sector:2d}  (block {blk:3d}) … ", end="", flush=True)
            key_a, key_b = brute_sector(mf, sector, key_dict)
            sector_keys[sector] = {"key_a": key_a, "key_b": key_b}
            a_str = key_a or "未找到"
            b_str = key_b or "未找到"
            print(f"KeyA={a_str}  KeyB={b_str}")

        # ── 阶段二：读取所有块 ──
        _banner("阶段二：读取全部块")
        dump: list[bytes | None] = [None] * TOTAL_BLOCKS
        read_ok = 0
        read_fail = 0

        for sector in range(NUM_SECTORS):
            info = sector_keys[sector]
            key_a = bytes.fromhex(info["key_a"]) if info["key_a"] else None
            key_b = bytes.fromhex(info["key_b"]) if info["key_b"] else None

            # 选择用于读取的密钥（优先 Key A，因为 Key A 默认有读权限）
            auth_key = key_a
            auth_mode = KEY_A_MODE
            if auth_key is None and key_b is not None:
                auth_key = key_b
                auth_mode = KEY_B_MODE

            if auth_key is None:
                print(f"  Sector {sector:2d} — 无可用密钥，跳过")
                read_fail += BLOCKS_PER_SECTOR
                continue

            first_block = sector * BLOCKS_PER_SECTOR
            for blk in range(first_block, first_block + BLOCKS_PER_SECTOR):
                # 每块读取前重新认证（认证状态在读卡器侧是扇区级别的）
                if mf.reselect() < 0:
                    print(f"  Block {blk:3d} — 重新选卡失败，跳过")
                    read_fail += 1
                    continue
                ret = mf.authenticate(auth_mode, first_block, auth_key)
                if ret != 0:
                    print(f"  Block {blk:3d} — 认证失败 (ret={ret:#04x})，跳过")
                    read_fail += 1
                    continue
                try:
                    data = mf.read_block(blk)
                    dump[blk] = data
                    read_ok += 1
                    print(f"  Block {blk:3d} : {data.hex().upper()}")
                except Exception as e:
                    print(f"  Block {blk:3d} — 读取异常: {e}")
                    read_fail += 1

        print(f"\n  读取完成：成功 {read_ok} 块 / 失败 {read_fail} 块")

        # ── 保存文件 ──
        _banner("保存文件")

        # 二进制 .mfd（缺失块用 0xFF 填充）
        mfd_path = output.with_suffix(".mfd")
        with mfd_path.open("wb") as f:
            for blk in range(TOTAL_BLOCKS):
                f.write(dump[blk] if dump[blk] is not None else b"\xff" * 16)
        print(f"  ✓ 数据文件  : {mfd_path}  ({TOTAL_BLOCKS * 16} 字节)")

        # JSON 密钥文件
        keys_path = output.with_suffix(".keys.json")
        payload = {
            "uid": uid_str,
            "atqa": f"0x{atqa:04X}",
            "sak": f"0x{sak:02X}",
            "sectors": {str(s): sector_keys[s] for s in range(NUM_SECTORS)},
        }
        keys_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  ✓ 密钥文件  : {keys_path}")

    print()


# ── RESTORE ───────────────────────────────────────────────────────────────────

def cmd_restore(mfd_path: Path, write_trailer: bool, write_block0: bool = False, debug: bool = False):
    global DEBUG
    DEBUG = debug

    keys_path = mfd_path.with_suffix(".keys.json")

    if not mfd_path.exists():
        sys.exit(f"[错误] 数据文件不存在: {mfd_path}")
    if not keys_path.exists():
        sys.exit(f"[错误] 密钥文件不存在: {keys_path}（需与 .mfd 同目录同名）")

    # 加载文件
    raw = mfd_path.read_bytes()
    if len(raw) != TOTAL_BLOCKS * 16:
        sys.exit(f"[错误] .mfd 文件大小应为 {TOTAL_BLOCKS * 16} 字节，实际 {len(raw)} 字节")

    dump: list[bytes] = [raw[i * 16 : (i + 1) * 16] for i in range(TOTAL_BLOCKS)]
    meta = json.loads(keys_path.read_text(encoding="utf-8"))
    sector_keys: dict[str, dict] = meta["sectors"]

    _banner(f"RESTORE 模式  ←  {mfd_path}")
    print(f"  源卡 UID : {meta.get('uid', '未知')}")
    print(f"  写扇区尾 : {'是（含密钥/权限）' if write_trailer else '否（保留目标卡默认值）'}")
    print(f"  写Block0 : {'是（厂商块，需目标卡支持）' if write_block0 else '否（跳过，仅 Magic Card 可写）'}\n")

    with HidReader() as reader:
        mf = MifareSession(reader)

        print("请将【目标新卡】放在读卡器上，按 Enter 继续…")
        input()
        print("等待卡片…")
        atqa, uid, sak = wait_for_card(mf)
        uid_str = " ".join(f"{b:02X}" for b in uid)
        print(f"  UID  : {uid_str}")
        print(f"  ATQA : 0x{atqa:04X}  SAK : 0x{sak:02X}\n")

        _banner("开始写入")
        write_ok = 0
        write_skip = 0
        write_fail = 0

        for sector in range(NUM_SECTORS):
            info = sector_keys.get(str(sector), {})
            key_a = bytes.fromhex(info["key_a"]) if info.get("key_a") else None
            key_b = bytes.fromhex(info["key_b"]) if info.get("key_b") else None

            # 写入优先用 Key B（通常有写权限），其次 Key A
            auth_key = key_b
            auth_mode = KEY_B_MODE
            if auth_key is None and key_a is not None:
                auth_key = key_a
                auth_mode = KEY_A_MODE

            if auth_key is None:
                print(f"  Sector {sector:2d} — 无可用密钥，跳过整个扇区")
                write_skip += BLOCKS_PER_SECTOR
                continue

            first_block = sector * BLOCKS_PER_SECTOR
            trailer_block = first_block + 3

            # 确定本扇区要写哪些块
            blocks_to_write = list(range(first_block, trailer_block))  # 数据块
            if write_trailer:
                blocks_to_write.append(trailer_block)

            for blk in blocks_to_write:
                # Block 0 是厂商只读块，默认跳过；--write-block0 时强制写入（需 Magic Card）
                if blk == 0 and not write_block0:
                    print(f"  Block   0 — 厂商块，跳过（可用 --write-block0 强制写入）")
                    write_skip += 1
                    continue

                # 重新选卡 + 认证
                if mf.reselect() < 0:
                    print(f"  Block {blk:3d} — 重新选卡失败，跳过")
                    write_fail += 1
                    continue
                ret = mf.authenticate(auth_mode, first_block, auth_key)
                if ret != 0:
                    print(f"  Block {blk:3d} — 认证失败 (ret={ret:#04x})，跳过")
                    write_fail += 1
                    continue

                try:
                    mf.write_block(blk, dump[blk])
                    print(f"  Block {blk:3d} ✓  {dump[blk].hex().upper()}")
                    write_ok += 1
                except Exception as e:
                    print(f"  Block {blk:3d} ✗  写入异常: {e}")
                    write_fail += 1

        print(f"\n  写入完成：成功 {write_ok} 块 / 跳过 {write_skip} 块 / 失败 {write_fail} 块")

    print()