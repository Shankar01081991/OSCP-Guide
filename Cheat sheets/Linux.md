## ✅ **System-Based Commands**

| **Command** | **Description & Alternatives** |
| --- | --- |
| `uname`, `uname -r`, `uname -a` | Kernel version and architecture info. 🔁 Try: `hostnamectl` (for OS + kernel + architecture) |
| `uptime` | Current time, uptime, load averages. 🔁 Use `w` or `top` for extra load/user info. |
| `hostname`, `hostname -i` | Show hostname and IP. 🔁 Use `ip addr show` for more IPs/interfaces. |
| `last reboot` | View previous system reboots. |
| `date`, `timedatectl`, `cal` | Date/time, timezone, and calendar info. |
| `w`, `who`, `whoami`, `id` | Active sessions, user info, and UID/GID data. |
| `finger user` | Needs `finger` installed. Shows login name, home dir, shell. |

---

## 🛠️ **Hardware-Based Commands**

| **Command** | **Use Case & Notes** |
| --- | --- |
| `dmesg` | Kernel ring buffer—look for hardware issues. Try `dmesg |
| `/proc/cpuinfo`, `/proc/meminfo` | Read CPU and memory details. 🔁 Use `lscpu`, `free -m` as friendly alternatives. |
| `lsblk`, `lspci`, `lsusb` | Storage, PCI, and USB enumeration. Use `-tv` for tree view. |
| `lshw` | Requires root for full output. Use `-short` for a summary. |
| `dmidecode`, `hdparm`, `badblocks` | BIOS + disk info. `hdparm` & `badblocks` useful in forensics/disk integrity. |

---

## 👥 **User Management**

| **Command** | **Use Case** |
| --- | --- |
| `adduser`, `userdel`, `usermod`, `groupadd` | Create, remove, or modify users/groups. 🔁 For scripting, use `useradd` (lower-level). |
| `id`, `last`, `who` | Enumerate identity and login history. |
| `groups <user>` | Show user's group membership—helpful in privilege checks. |

---

## 📁 **File Management**

| **Command** | **Use Case** |
| --- | --- |
| `ls -al`, `pwd`, `mkdir`, `rm`, `cp`, `mv`, `touch` | Basic file operations. |
| `cat`, `more`, `less`, `head`, `tail` | File content view. |
| `ln -s` | Create symlinks—used in privilege escalation sometimes. |
| `gpg -c`, `gpg` | Encrypt/decrypt files with passphrase. |
| `wc`, `xargs` | Count lines/chars. `xargs` used in chaining. |

---

## 🧠 **Process Management**

| **Command** | **Use Case** |
| --- | --- |
| `ps`, `top`, `htop` | List active processes. `htop` is interactive. |
| `kill`, `pkill`, `killall`, `pgrep` | Terminate or search for processes. |
| `lsof` | List open files (used in lateral movement/debugging). |
| `pmap`, `pstree`, `renice` | Memory, process tree, priority adjustments. |
| `bg`, `fg`, `jobs` | Control background/foreground jobs. |

---

## 🔒 **File Permissions**

| **Command** | **Use Case** |
| --- | --- |
| `chmod`, `chown` | Change ownership & permission. |
| `getfacl`, `setfacl` | Advanced ACLs (not in default list, but relevant). |

---

## 🌐 **Network**

| **Command** | **Use Case & Notes** |
| --- | --- |
| `ip addr`, `ifconfig` | Show interfaces & IPs. Note: `ifconfig` deprecated on many distros. |
| `ping`, `dig`, `host`, `whois` | Test connectivity & DNS info. |
| `wget`, `curl` | File downloads. Helpful for uploading post-ex tools. |
| `netstat`, `ss` | Show sockets and connections. 🔁 Prefer `ss` for speed. |

---

## 📦 **Compression & Archives**

| **Command** | **Use Case** |
| --- | --- |
| `tar`, `gzip`, `xz`, `zip` | Create and extract archives. |
| `tar -zcvf`, `tar -xf` | Compress/decompress `.tar.gz`. |
| `zip`, `unzip` | If available, useful on Windows-compatible archives. |

---

## 📥 **Package Installation**

| **Command** | **Use Case** |
| --- | --- |
| `rpm`, `dnf`, `yum` | RPM-based systems. |
| `apt install`, `dpkg -i` | For Debian-based systems. |
| `pacman -S` | Arch Linux systems. |
| `zypper install` | SUSE/openSUSE |

---

## 🧱 **Compilation from Source**

| **Command** | **Use Case** |
| --- | --- |
| `./configure`, `make`, `make install` | Compile and install from source. 🔁 Alternative: `cmake . && make` |

---

## 🔍 **Search & Locate**

| **Command** | **Use Case** |
| --- | --- |
| `grep`, `grep -r` | Search patterns in files/directories. |
| `find`, `locate` | Locate files by name, size, permission, owner, etc. |
| `find / -perm -4000 2>/dev/null` | SUID binary discovery. |

---

## 🔐 **Login & File Transfer**

| **Command** | **Use Case** |
| --- | --- |
| `ssh`, `telnet`, `scp`, `rsync` | Remote connection and transfer. |
| `rsync -avz` | Add compression for fast sync. |

---

## 💽 **Disk & Mount**

| **Command** | **Use Case** |
| --- | --- |
| `df -h`, `du -sh`, `findmnt`, `fdisk -l` | Disk usage and partitioning. |
| `mount`, `umount`, `cat /etc/fstab` | Mount info, persistent entries. |

---

## 📁 **Directory Traversal**

| **Command** | **Use Case** |
| --- | --- |
| `cd`, `cd ..`, `cd /mnt`, `pwd` | Navigate directory structures. |
| `tree`, `ls -R` | Visualize folder hierarchy (useful in recon). |

---

## 🔐 **Linux Privilege Escalation – Additions & Automation Tools**

### 🧰 **Automation Tools**

- [**linPEAS**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) – System enum script
- [**pspy**](https://github.com/DominicBreuker/pspy) – Monitor scheduled cron/system activity
- [**GTFOBins**](https://gtfobins.github.io/) – SUID abuse database
- [**traitor**](https://github.com/liamg/traitor) – Auto local root exploit tool

### 🔍 **Manual Checks**

- **SUID/GUID:** `find / -perm -u=s -type f 2>/dev/null`
- **Shell Capability:** `getcap -r / 2>/dev/null`
- **Writable paths:** `find / -writable -type d 2>/dev/null`
- **Interesting files:** `ls -lsaht /etc/`, `/opt/`, `/var/www/`, `/tmp/`, `/dev/shm/`
- **NFS mount misconfig:** `cat /etc/exports`

---

### 💡 **Common Escalation Checks**

| **Check** | **Command / Tip** |
| --- | --- |
| PATH Hijacking | Check `echo $PATH` for writable dirs. |
| Cron Jobs | `cat /etc/crontab`, `ls /etc/cron.*` |
| Sudo Rights | `sudo -l` |
| SUID Misuse | Abuse binaries via GTFOBins |
| Writable `/etc/passwd` | `echo 'user:<hash>:0:0:...' >> /etc/passwd` |
| Shell Upgrade | `python3 -c 'import pty; pty.spawn("/bin/bash")'` + `stty raw -echo` etc. |
| Kernel/Release | `uname -a`, `cat /etc/os-release` |
| SSH Keys | `find /home -name authorized_keys` |
