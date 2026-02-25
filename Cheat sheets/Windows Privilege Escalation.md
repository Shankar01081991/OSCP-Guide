# 🛡️ Thick Client VAPT Automation Toolkit

**Safe, read-only misconfiguration detection for Windows thick-client applications**

A **PowerShell automation toolkit** designed to quickly identify **security misconfigurations**, **weak security controls**, and **potential vulnerabilities** in Windows thick-client applications — **without performing exploitation**.

---

## 🧯 Non-Intrusive by Design

This toolkit focuses strictly on **safe security assessment**.

- ✔ Read-only checks only  
- ✔ No exploitation or payload execution  
- ✔ Safe for authorized production environments  
- ✔ Focused on security misconfiguration discovery  

---

## ✨ Features

### 🔎 Binary & DLL Analysis
- Inventory of application binaries
- Digital signature validation
- Extraction of **security-relevant strings**

### 📂 File System Security Checks
- Folder **ACL analysis**
- Detection of **writable directories**
- **DLL hijacking risk indicators**

### 🔐 Secrets Discovery
Searches for sensitive data in configuration files:

- Passwords  
- Tokens  
- API keys  
- Authentication data  

### 🔑 Crypto & Key Material Checks
Identifies weak cryptographic implementations such as:

- MD5  
- SHA1  
- DES  
- RC4  
- Embedded private keys  

### 📑 Logs & Registry Analysis
- Sensitive information inside logs
- Weak **registry key permissions**

### ⚙️ Process Module Enumeration
- Enumerates **loaded DLL modules**
- Identifies suspicious **DLL load paths**

---

# 📁 Output Structure

All scan results are written to:

```
VAPT_TEST/
```

Example structure:

```
VAPT_TEST/
├── dll_list.txt
├── SignatureReport.csv
├── InterestingStrings.txt
├── FolderPermissions.txt
├── WritableSubdirectories.txt
├── ConfigSensitiveData.txt
├── ConfigExtendedSensitiveData.txt
├── WeakCrypto.txt
├── InsecureProtocols.txt
├── EmbeddedPrivateKeys.txt
├── ConnectionStrings.txt
├── DebugSettings.txt
├── TempUsage.txt
├── LoadedDLLs.txt
├── RegistryPermissions.txt
└── VulnerabilitySummary.txt
```

---

# 📊 Vulnerability Summary

At the end of execution, the toolkit generates a consolidated report:

```
VAPT_TEST/VulnerabilitySummary.txt
```

Example:

```
[HIGH] Invalid or unsigned binary: helper.dll
[HIGH] Writable subdirectories detected (DLL hijacking risk)
[MEDIUM] Weak cryptographic algorithms detected
[MEDIUM] Hardcoded connection strings detected
[LOW] Debug/verbose flags detected
```

### Severity Levels

| Severity | Meaning |
|--------|--------|
| 🔴 HIGH | High-risk misconfiguration |
| 🟠 MEDIUM | Security weakness |
| 🟡 LOW | Informational security concern |

---

# 🚀 Quick Start

## 1️⃣ Copy the Script

Place the script inside the **application installation directory**.

Example:

```
C:\Program Files\TEST_APP\
```

---

## 2️⃣ Open PowerShell

Administrator privileges are **recommended** for registry analysis.

---

## 3️⃣ Run the Script

```powershell
.\thickclient.ps1
```

---

## 4️⃣ Follow Prompts (If Required)

The script may ask for:

### Process Selection
Choose a **process index or PID** for DLL enumeration.

### Registry Key Selection
Optionally analyze discovered registry keys.

---

## 5️⃣ Review Results

All findings will appear in:

```
VAPT_TEST/
```

---

# ⚠️ Usage Notice

This tool is intended **only for authorized security assessments**.

- Do **not** run against systems without permission
- The toolkit performs **non-intrusive security checks**
- **No exploitation is performed**

---

# 📌 Typical Use Cases

This toolkit is useful during:

- Thick client **VAPT assessments**
- **Secure code review preparation**
- **Security configuration audits**
- **Application hardening reviews**
- **Red team reconnaissance (safe mode)**

---

# 🛠 Recommended Workflow

1. Deploy the tool inside the application directory  
2. Run the scan  
3. Review `VulnerabilitySummary.txt`  
4. Investigate detailed findings  
5. Document risks in the **VAPT report**

---

# 📄 License

Use responsibly and only for **authorized security testing**.
