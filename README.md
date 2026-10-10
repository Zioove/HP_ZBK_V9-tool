# 惠普增霸卡（HP_ZBK_V9）管理员密码提取与验证复核报告（脱敏版）

**目标**：从本机还原卡数据区中提取管理员密码，并独立验证 `PublicFun.dll` 的密码验证算法  
**样本**：`<DLL_PATH>`  
**样本指纹**：SHA-1 `<DLL_SHA1>`、大小 109,056 字节、时间戳 2023-02-03  
**复核依据**：《publicfun_逆向分析报告.pdf》与博客园原文《逆向破解惠普增霸卡密码验证流程》  
**执行环境**：Windows 10 (19041.2364)、管理员权限、`<PHYSICAL_DRIVE>`  
**执行日期**：2026-10-10

---

## 一、结论摘要

| 项目 | 结果 |
|---|---|
| 管理员密码明文 | **`<ADMIN_PASSWORD>`** |
| 密码十六进制 | `<PASSWORD_HEX>` |
| 扇区密文 | `<SECTOR_CIPHERTEXT>` |
| 数据区基地址 LBA | `<BASE_LBA>`（`<BASE_LBA_HEX>`） |
| 密码扇区 LBA | `<PASSWORD_SECTOR_LBA>`（base + `<PASSWORD_SECTOR_OFFSET>` = `<PASSWORD_SECTOR_OFFSET_HEX>`） |
| 密码长度 | 8 字节（达到设计上限，恰好用满前 8 字节） |
| 是否空密码 | 否（空密码哨兵 `<EMPTY_PWD_SENTINEL>` 未命中，卡已设置密码） |
| 提取方式 | IOCTL `<IOCTL_GET_BASE>` 探测基地址 → IOCTL `<IOCTL_READ_SECTORS>` 读扇区 → 双密钥异或解密 |
| 复现性 | 连续两次独立读取，密文与明文完全一致 |
| 算法自检 | 已知明文示例生成的密文与报告 5.2 节逐字节相符 → 算法复现正确 |

---

## 二、提取过程与证据链

### 2.1 步骤 1：定位还原卡数据区

枚举 `\\.\PhysicalDriveN`，以 `CreateFileA(name, 0xC0000000, FILE_SHARE_READ|FILE_SHARE_WRITE, OPEN_EXISTING)` 打开，发送 IOCTL `<IOCTL_GET_BASE>`（输入输出同为 8 字节缓冲，即 `<IOCTL_DETAILS>`）：

```
[ 0] 已打开 <PHYSICAL_DRIVE>
      IOCTL <IOCTL_GET_BASE> 成功: baseLBA=<BASE_LBA> (<BASE_LBA_HEX>), 返回字节=8
```

结论：本机还原卡数据区位于 `<PHYSICAL_DRIVE>`，基地址 LBA = `<BASE_LBA_HEX>`。  
该 LBA 落于 `<DISK_CAPACITY>` 磁盘范围内，符合“隐藏在常规分区之外/之后的数据区”特征。

### 2.2 步骤 2：直读密码扇区

目标 LBA = `<BASE_LBA> + <PASSWORD_SECTOR_OFFSET> = <PASSWORD_SECTOR_LBA>`，构造 16 字节请求头 `{u64 LBA; u64 count=1}`，以 IOCTL `<IOCTL_READ_SECTORS>` 原地读写 512 字节（输入缓冲与输出缓冲为同一块内存，与 `CZbkObject::ReadSectors` 语义一致）：

```
00000000  <SECTOR_CIPHERTEXT> 00 00 00 00 00 00 00 00  |................|
00000010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
```

扇区仅前 8 字节非零，其余全 0 —— 与“密码区仅使用首 8 字节、长度上限 8 字节”的逆向结论一致。

### 2.3 步骤 3：双密钥异或解密

依据 `CZbkObject::ValidAdminPasswords` @ RVA `<RVA_VALID_ADMIN>` 的两条指令（VA `<VA_XOR1>`、`<VA_XOR2>`）：

```asm
<VA_XOR1>  xor dword [esp+8],  <KEY1_IMM>   ; 扇区字节 0..3
<VA_XOR2>  xor dword [esp+0xc], <KEY2_IMM>  ; 扇区字节 4..7
```

异或指令立即数以**小端字节序**作用于内存，故实际密钥字节流为：

| 位置 | 立即数 | 内存字节序 | 大端 ASCII 读出 |
|---|---|---|---|
| 0..3 | `<KEY1_IMM>` | `<KEY1_LE_BYTES>` | `<KEY1_ASCII>` |
| 4..7 | `<KEY2_IMM>` | `<KEY2_LE_BYTES>` | `<KEY2_ASCII>` |

解密运算：

```
<CIPHERTEXT_0_3> ^ <KEY1_LE_BYTES> = <PLAINTEXT_0_3>
<CIPHERTEXT_4_7> ^ <KEY2_LE_BYTES> = <PLAINTEXT_4_7>
```

解密结果：

```
00000000  <PASSWORD_HEX> 00 00 00 00 00 00 00 00  |<ADMIN_PASSWORD>........|

管理员密码明文 = <PASSWORD_HEX> = "<ADMIN_PASSWORD>"
```

### 2.4 步骤 4：结果验证（四个独立维度）

**a) 算法自检（已知明文往返）**：以报告 5.2 节的示例明文 `<SAMPLE_PLAINTEXT>` 正向加密：

```
示例明文 -> 密文 <SAMPLE_CIPHERTEXT>   （报告给出值：完全一致）
密文再异或 -> 明文 <SAMPLE_PLAINTEXT>  （XOR 往返自洽）
空密码 8 字节全零 -> 密文 <EMPTY_CIPHERTEXT> = ASCII "<EMPTY_PWD_SENTINEL>"（与报告哨兵一致）
```

**b) 复现性**：对同一 LBA 连续两次独立读取，密文均为 `<SECTOR_CIPHERTEXT>`，解密明文均为 `<ADMIN_PASSWORD>`，无抖动、无缓存假象。

**c) 空密码哨兵比对**：读回密文 `<SECTOR_CIPHERTEXT>` ≠ `<EMPTY_PWD_SENTINEL>`，可确认该卡**已设置**管理员密码（若为 `<EMPTY_PWD_SENTINEL>` 则表示未设密码/空口令）。

**d) 字符集合理性**：8 字节全部为可打印小写字母与数字（`[a-z0-9]` 构成的 8 位口令），符合管理员口令的常规形态，不存在解密错误导致的乱码特征。

---

## 三、与 PDF 报告的交叉核对

| 报告结论 | 本次实测 | 判定 |
|---|---|---|
| 核心函数 `CZbkObject::ValidAdminPasswords` @ RVA `<RVA_VALID_ADMIN>` | 依该函数逻辑构造 IOCTL 序列并成功取出口令 | ✓ 证实 |
| 密码存储于 `base + <PASSWORD_SECTOR_OFFSET>`（`<PASSWORD_SECTOR_OFFSET_HEX>`）扇区，512 字节，前 8 字节有效 | 实测扇区仅前 8 字节非零 | ✓ 证实 |
| 双密钥 `<KEY1_IMM>` / `<KEY2_IMM>`，作用于偏移 0..3 / 4..7 | 直接解密出可读口令 | ✓ 证实 |
| 密钥大端 ASCII 为 `<KEY1_ASCII>`+`<KEY2_ASCII>`（即 `<KEY_ASCII_COMBINED>`）；博客原文 `<BLOG_KEY1>`/`<BLOG_KEY2>` 系字节序误读 | 立即数小端展开确为 `<KEY1_LE_BYTES>` / `<KEY2_LE_BYTES>` | ✓ 报告纠错成立 |
| 空密码哨兵为 ASCII `<EMPTY_PWD_SENTINEL>` | 实算一致 | ✓ 证实 |
| 比对为 MSVC 内联 `memcmp`，长度取自调用方（前缀通过、`len=0` 通过） | 属读侧验证路径，本机口令为满 8 字节，未触发该缺陷 | ✓ 逻辑成立 |
| `Initial` 经 IOCTL `<IOCTL_GET_BASE>` 探测基地址 | `<PHYSICAL_DRIVE>` 返回非零 LBA，探测成功 | ✓ 证实 |
| `ReadSectors` 以 IOCTL `<IOCTL_READ_SECTORS>` 原地读写 | 原地读写语义可用（请求头被扇区数据覆盖） | ✓ 证实 |
| Windows 登录密码位于 `base+<WINDOWS_PWD_OFFSET>`，`0x200` 字节**明文** | 实测该扇区为一组高频重复的规律数据（`0xFF` 出现 128 次），**并非可读明文口令** | ✗ **待商榷（本次新发现）** |

### 关于 `base+<WINDOWS_PWD_OFFSET>` 的差异说明

实测该偏移前 128 字节形态如下（每 4 字节末位固定为 `0xFF`；具体字节已脱敏）：

```
<WINDOWS_PWD_SECTOR_SAMPLE>
```

- 该数据不是以 NUL 结尾的 ASCII/GBK 字符串，也不满足“明文 + `lstrcmpA` 直比”的形态；
- 推测原因：当前环境（或本卡固件/驱动版本）在该偏移存放的是驱动层编码数据/位图，或该区域的实际语义与报告所依据的样本代际不同；
- 影响范围：**不影响本次管理员密码提取结论**（两者为不同偏移、不同通道），但提示报告表 5-2 “Windows 密码位于 `<WINDOWS_PWD_OFFSET>`、`0x200` 字节明文”一项需要在具备 Windows 登录口令场景的环境下二次求证（可用 `ValidWindowsPasswords` 返回值反推）。

---

## 四、运行环境与前置条件

| 项目 | 实测值 |
|---|---|
| 物理磁盘 | `<DISK_MODEL>` `<DISK_CAPACITY>`，接口 `<INTERFACE>`，`<PARTITION_COUNT>` 个 GPT 分区 |
| 卡数据区设备 | `<PHYSICAL_DRIVE>`，IOCTL `<IOCTL_GET_BASE>` 返回 baseLBA = `<BASE_LBA_HEX>` |
| 过滤驱动 `GenFilt` | **Running / Start=0 (Boot)**，`<SYSTEM_DRIVER_PATH>\GenFilt.sys`（56,192 字节，2023-02-23） |
| `EsWriter` 服务 | Stopped / Manual，指向 `<SYSTEM_DRIVER_PATH>\EsWriter.sys` |
| 驱动厂商信息 | CompanyName = `<VENDOR_NAME>`，FileDescription = `<DRIVER_DESC>` |
| 权限要求 | **管理员**（直接 `CreateFile` `\\.\PhysicalDriveN` 必须提权） |
| 依赖 | 仅需 Python 3 标准库 `ctypes`，无需编译器或第三方包 |

驱动厂商字段中的 `<VENDOR_PINYIN>` 与密钥 ASCII `<KEY_ASCII_COMBINED>` 相互印证，说明该口令机制的原始实现者与驱动同源，报告关于密钥来源（开发者姓名拼音）的推断合理。

---

## 五、交付物与使用方法

| 文件 | 说明 |
|---|---|
| `zbk_password_tool.py` | 密码提取主工具：枚举物理盘、探测基地址、读扇区、解密、输出口令；自动区分空密码哨兵 |
| `verify_password.py` | 算法自检与复现性验证脚本（已知明文往返 + 双次读取 + Windows 密码扇区旁证） |
| `dump_evidence.py` | 取证转储脚本：生成带偏移/ASCII 对照的扇区 hexdump |
| `evidence_dump.txt` | 本次取证的完整转储日志（含 baseLBA、密文、明文、哨兵比对；已脱敏） |
| `增霸卡管理员密码提取复核报告.docx` / `.md` | 本报告 |

### 使用方式

```powershell
# 必须以管理员权限运行
python <WORK_DIR>\zbk_password_tool.py        # 默认枚举 PhysicalDrive0..19
python <WORK_DIR>\zbk_password_tool.py 8      # 只枚举前 8 块盘
```

输出示例（本次实测，已脱敏）：

```
[ 0] 已打开 <PHYSICAL_DRIVE>
      IOCTL <IOCTL_GET_BASE> 成功: baseLBA=<BASE_LBA> (<BASE_LBA_HEX>), 返回字节=8
      HEX : <PASSWORD_HEX> ...
      密码明文 : b'<ADMIN_PASSWORD>'
      >>> 管理员密码 = <ADMIN_PASSWORD>
```

### 适用范围与失效条件

- 适用：`ZBK_UEFI_v7` 系（本机 `HP_ZBK_V9` + `GenFilt.sys` 环境实测有效）；报告指出 `CLxObject` 变体使用**完全相同的偏移与密钥**，故 Lx 系列卡预计同样适用。
- 失效：若其他代际卡更换密钥、变更 `<PASSWORD_SECTOR_OFFSET>` 偏移或改用哈希存储，本工具将输出乱码，此时应回到 `PublicFun.dll` 重新定位异或立即数与扇区偏移（工具中的两个常量即为此设计）。

---

## 六、安全性评估（在报告 W1–W6 基础上补充实测视角）

1. **口令对本地任意管理员完全透明**：密钥、偏移、算法全部固化在 DLL 立即数中，且 IOCTL 通道无调用方鉴权，具备管理员权限的进程可在数秒内读出口令（本次即验证）。
2. **读侧验证与写侧分离带来单点风险**：DLL 内无密码扇区写路径，改密走 `PasswordsAction` → IOCTL `<IOCTL_SET_PASSWORD>` 交 ring0 驱动；因此**提取口令是唯一可行的入侵路径**，而该路径已被证明完全通畅。
3. **本机处于活动还原环境**：`GenFilt` 为 Boot 启动并正在运行，口令一旦泄露，攻击者可关闭/绕过写保护并实施持久化修改，风险高于普通静态存储场景。
4. **改进建议**（同报告）：口令以带盐哈希（PBKDF2/Argon2）存于隐藏区并在固件/驱动侧校验；比对长度由存储侧元数据约束；IOCTL 增加调用方完整性与权限校验；启用挑战-响应防重放。

---

## 七、附：关键常量与地址速查（脱敏）

| 名称 | 值 |
|---|---|
| `CZbkObject::ValidAdminPasswords` | RVA `<RVA_VALID_ADMIN>`（VA `<VA_VALID_ADMIN>`） |
| `CZbkObject::Initial` | RVA `<RVA_INITIAL>` |
| `CZbkObject::ReadSectors` | RVA `<RVA_READ_SECTORS>` |
| IOCTL 获取基地址 | `<IOCTL_GET_BASE>` |
| IOCTL 读写扇区 | `<IOCTL_READ_SECTORS>` |
| IOCTL 次基地址探测 | `<IOCTL_ALT_BASE>` |
| IOCTL 密码修改 | `<IOCTL_SET_PASSWORD>` |
| 密码扇区偏移 | `<PASSWORD_SECTOR_OFFSET>` = `<PASSWORD_SECTOR_OFFSET_HEX>` |
| `Initial` 中的基地址成员 | `this+0x08 / +0x0C`（u64） |
| 主设备句柄成员 | `this+0x210` |
| 密钥 1 / 密钥 2 | `<KEY1_IMM>` / `<KEY2_IMM>` |
| 空密码哨兵 | ASCII `<EMPTY_PWD_SENTINEL>` |
| 密文（本次） | `<SECTOR_CIPHERTEXT>` |
| 明文（本次） | `<ADMIN_PASSWORD>` |
