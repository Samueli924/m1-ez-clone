from pathlib import Path

KEY_FILE = Path(__file__).parent.parent / "keys.dic"


class BruteKeysGetter:
    def get(self) -> list[bytes]:
        keys: list[bytes] = []
        with open(KEY_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    key = bytes.fromhex(line)
                    if len(key) == 6 and key not in keys:
                        keys.append(key)
                except ValueError:
                    pass
        print(f"成功加载 {len(keys)} 个密钥")
        return keys
