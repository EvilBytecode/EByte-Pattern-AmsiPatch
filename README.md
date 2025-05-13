# 🛡️ EByte-Pattern-AmsiPatch 🛡️

EByte-Pattern-AmsiPatch bypasses AMSI by directly patching the AMSI.dll module **in memory** of a target process. It does **not** modify any files on disk.

### 🧬 How It Works

1. **Target Selection**: Takes an existing process ID or creates a new PowerShell process
2. **Memory Patching**: Modifies AMSI.dll code in the target process memory:
   - Changes result comparison values (`cmp eax,0/1` → `cmp eax,-1`)
   - Converts conditional jumps to unconditional jumps
   - Replaces function prologues with immediate returns (`xor eax,eax; ret`)

### 💻 Technical Details

```cpp
// Key patterns that neutralize AMSI functionality
const PatternInfo AMSI_PATTERNS[] = {
    { "AMSI_RESULT_CLEAN", { 0x83, 0xF8, 0x00 }, { 0x83, 0xF8, 0xFF }, 3 },
    { "AMSI_RESULT_DETECTED", { 0x83, 0xF8, 0x01 }, { 0x83, 0xF8, 0xFF }, 3 },
    { "AMSI_TEST_JZ", { 0x85, 0xC0, 0x74 }, { 0x85, 0xC0, 0xEB }, 3 },
    { "AMSI_SCAN_FUNC_START", { 0x48, 0x89, 0x5C, 0x24, 0x08 }, { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 5 }
    // ... and wayyy more patterns
};
```

- **In-Memory Only**
- **Pattern-Based**: No LoadLibrary, or GetProcAddress calls

### ⚡ Usage

- Run without parameters to create and patch a new PowerShell process
- Run with a PID to patch AMSI in an existing process (powershell for example): `EByte-Pattern-AmsiPatch.exe $pid`


## ⚠️ Legal Disclaimer

For educational purposes only. Using this to bypass security mechanisms may violate system policies, terms of service, or applicable laws.

---
# PoC ⭐
![image](https://github.com/user-attachments/assets/ce4aaa03-82b8-44f8-ba35-efeb953f3b34)

---

**Copyright © 2025 EvilByteCode. All Rights Reserved.** 
