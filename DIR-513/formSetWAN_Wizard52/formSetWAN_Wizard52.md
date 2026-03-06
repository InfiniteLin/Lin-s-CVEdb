**Vulnerability Title:** Stack-based Buffer Overflow in D-Link DIR-513 `formSetWAN_Wizard52` function

**Vulnerability Description:**

A critical stack-based buffer overflow vulnerability exists in the Web management interface of D-Link DIR-513 routers (A1 FW110, A2 FW110). The flaw is located within the `formSetWAN_Wizard52` function at memory address `0x44a940`.

The vulnerability is triggered when the application processes an HTTP POST request containing a specially crafted, overlong `curTime` parameter. The program retrieves this parameter via `websGetVar` and subsequently utilizes the unsafe `sprintf` function (at `0x44ac84`) to format the input into a fixed-size stack buffer `v30` (200 bytes) located at `SP + 0xE0`.

Because the function lacks any boundary or length validation for the `curTime` input, an attacker can provide a payload that overflows the buffer and overwrites the saved return address (RA) at `SP + 0x1C8`. This allows a remote attacker to hijack the program's control flow, leading to a Denial of Service (DoS) or arbitrary Remote Code Execution (RCE) with elevated privileges.

---

### Technical Details

- **Vulnerability Type:** CWE-121 (Stack-based Buffer Overflow)

- **Affected Component:** `goform/formSetWAN_Wizard52`

- **Attack Vector:** Network (Remote via HTTP POST)

- **Impact:** Remote Code Execution (RCE) / Denial of Service (DoS)

- **Authentication:** Not required (depending on specific device deployment)

#### Stack Frame & Offset Analysis:

- **Buffer `v30` Start:** `SP + 0xE0`

- **Return Address (RA) Position:** `SP + 0x1C8`

- **Calculated Offset to RA:** $0x1C8 - 0xE0 = 232$ bytes

- **Vulnerable Instruction:** `sprintf(v30, "/Basic/Wizard_WAN_complete.asp?t=%s", v3);`

---

### Proof of Concept (PoC) Sketch

The vulnerability can be reached by sending a POST request where the `curTime` parameter, when combined with the 35-byte static prefix `"/Basic/Wizard_WAN_complete.asp?t="`, exceeds 232 bytes in length to reach and overwrite the Return Address.

---

### Mitigation and Fix

**Official Fix:**

The vendor should replace the unsafe `sprintf` call with `snprintf` to ensure the data written does not exceed the buffer size:

`snprintf(v30, sizeof(v30), "/Basic/Wizard_WAN_complete.asp?t=%s", v3);`

**Temporary Mitigation:**

- Implement input length validation for the `curTime` parameter at the Web Server entry point (e.g., limit to 64 bytes).

- Enable compiler-level protections such as Stack Canaries (`-fstack-protector-all`) and NX (No-Execute) bits.
