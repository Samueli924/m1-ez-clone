"""
Mifare Classic 1K 克隆工具
═══════════════════════════════════════════════════════════════════════════════
用法：
  python main.py dump    [-o card]    # 读卡 → 文件
  python main.py restore [-i card.mfd] # 文件 → 新卡

dump 流程：
  1. 对每个扇区（0‑15）用字典爆破找到 Key A / Key B
  2. 用找到的密钥读取全部 64 块（每块 16 字节，共 1 024 字节）
  3. 保存为 <output>.mfd（二进制）和 <output>.keys.json（扇区密钥）

restore 流程：
  1. 加载 .mfd 和 .keys.json
  2. 等待放上新卡
  3. 逐扇区认证 → 写入数据块（0,1,2）→ 可选写扇区尾块（3）
  注意：Block 0（厂商块）默认跳过；使用 --no-write-block0 可跳过（需 Magic Card / CUID 卡）
═══════════════════════════════════════════════════════════════════════════════
"""

import argparse
from pathlib import Path

from m1.keys import BruteKeysGetter
from m1.app import cmd_dump, cmd_restore


def main():
    parser = argparse.ArgumentParser(
        prog="main",
        description="Mifare Classic 1K 克隆工具：dump（读卡→文件）/ restore（文件→新卡）",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dump = sub.add_parser("dump", help="读取卡片并保存到文件")
    p_dump.add_argument(
        "-o", "--output", default="card",
        help="输出文件名前缀（默认 card，会生成 card.mfd + card.keys.json）",
    )
    p_dump.add_argument("--debug", action="store_true", help="调试模式")

    p_restore = sub.add_parser("restore", help="将文件写入新卡")
    p_restore.add_argument(
        "-i", "--input", default="card.mfd",
        help="输入 .mfd 文件路径（默认 card.mfd）",
    )
    p_restore.add_argument(
        "--no-write-trailer", action="store_true",
        help="不写入扇区尾块（含密钥/访问控制位），默认写",
    )
    p_restore.add_argument(
        "--no-write-block0", action="store_true",
        help="不写入 Block 0（厂商块，仅 Magic Card / CUID 卡支持），默认写",
    )
    p_restore.add_argument("--debug", action="store_true", help="调试模式")

    args = parser.parse_args()
    debug = getattr(args, "debug", False)

    if args.cmd == "dump":
        key_dict = BruteKeysGetter().get()
        cmd_dump(Path(args.output), key_dict, debug=debug)

    elif args.cmd == "restore":
        cmd_restore(Path(args.input), not args.no_write_trailer, not args.no_write_block0, debug=debug)


if __name__ == "__main__":
    main()
