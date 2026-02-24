# M1 EZ Clone

Mifare Classic 1K 门禁卡克隆工具。通过 USB HID 读写器，将卡片数据完整备份到文件，再写入新空白卡，实现一对一克隆。

## 功能

- **dump**：对卡片 16 个扇区自动爆破密钥，读取全部 64 块数据并保存
- **restore**：将备份数据写回新卡（支持选择是否写入扇区尾块与厂商块）

## 设备要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows（依赖 `hfrdapi.dll`, 可使用其他dll库） |
| Python | 3.10 及以上 |
| 读写器协议 | ISO 14443A（Mifare Classic / Crypto1） |
| 读写器 USB ID | VID `0x0416` / PID `0x8020` (可自定义) |
| 目标卡（写入） | Magic Card / CUID 卡（支持写入 Block 0） |

> **注意**：普通 Mifare Classic 卡的 Block 0（厂商块）为只读，完整克隆（含 UID）需使用 Magic Card 或 CUID 卡。

## 安装

```bash
# 克隆仓库
git clone https://github.com/yourname/m1-ez-clone.git
cd m1-ez-clone

# 安装依赖（仅标准库，无需额外安装）
# 将 hfrdapi.dll 放入项目根目录
```

> 将读写器厂商提供的 `hfrdapi.dll` 或其他 `dll` 库放入项目根目录，否则程序无法启动。

## 密钥字典

程序使用项目根目录下的 `keys.dic` 进行密钥爆破。文件格式为每行一个 12 位十六进制密钥（6 字节）：

字典条目越多，爆破成功率越高，但耗时也相应增加。

## 使用方法

### 第一步：读取（Dump）原卡

将原卡放在读写器上，运行：

```bash
python main.py dump -o card
```

成功后生成两个文件：
- `card.mfd`：1024 字节二进制数据（64 块 × 16 字节）
- `card.keys.json`：各扇区密钥及卡片信息

### 第二步：写入（Restore）新卡

将空白 Magic Card / CUID 卡放在读写器上，运行：

```bash
python main.py restore -i card.mfd
```

### 完整选项

```
dump:
  -o, --output   输出文件名前缀（默认 card）
  --debug        打印调试信息

restore:
  -i, --input         输入 .mfd 文件路径（默认 card.mfd）
  --no-write-trailer  不写入扇区尾块（跳过密钥/访问控制位）
  --no-write-block0   不写入 Block 0（跳过厂商块）
  --debug             打印调试信息
```

### 示例

```bash
# 读取并保存为 office.mfd + office.keys.json
python main.py dump -o office

# 还原，跳过 Block 0（目标卡不支持写厂商块时使用）
python main.py restore -i office.mfd --no-write-block0
```

## 输出文件说明

| 文件 | 说明 |
|------|------|
| `<name>.mfd` | 原始二进制卡数据，1024 字节，读取失败的块用 `0xFF` 填充 |
| `<name>.keys.json` | 卡片 UID、ATQA、SAK 及各扇区 Key A / Key B |

## License

Apache 2.0
