##### ****SSH port forwarding (pivoting) to RDP into a Windows machine ****

### **Setup Summary**

- **Your Machine** (Attacker): `144.54.163.17`
- **Pivot Machine** (Ubuntu with SSH access): `130.141.168.70`
- **Internal Windows Target**: `192.168.176.254` (RDP enabled on port 3389)

---

## ✅ Goal:

Access `192.168.176.254:3389` (RDP) from **your attacker machine**, by tunneling through the **Ubuntu pivot box**.

---

## 🧩 Step-by-Step Port Forwarding (SSH Tunnel)

### 🔁 **Option 1: Local Port Forwarding via SSH (best if you're on Linux/macOS or WSL)**

Run this command **on your attacker machine** (144.54.163.17):

```bash
ssh -L 3389:192.168.176.254:3389 user@130.141.168.70
```

> Replace user with your actual SSH username on the Ubuntu box.
> 
- This forwards port `3389` on **your local machine** to `192.168.176.254:3389` **via** `130.141.168.70`.
- After logging in, leave the SSH session running.

![image](https://github.com/user-attachments/assets/14b96d67-dab9-487e-9941-b801b15c20ac)


### 🎯 **Now**, open your **RDP client** (like Remmina, xfreerdp, or Microsoft Remote Desktop) and connect to:

```bash
127.0.0.1:3389  
NOTE: use 3390 or other port if 3389 is already in use.
```

You should now reach the internal Windows box (`192.168.176.254`) via the tunnel.

![image](https://github.com/user-attachments/assets/d3ced9cd-f17c-48bb-9267-69baccaf05d1)


---

![image](https://github.com/user-attachments/assets/921a2dcd-5c46-44b3-a624-b1ce8694a684)


## 📌 If You're Using Windows on the Attacker Machine

Use **PuTTY** to set up port forwarding:

1. Open PuTTY.
2. Hostname: `130.141.168.70`, Port: `22`
3. In the sidebar: Go to **Connection > SSH > Tunnels**
4. Add the following tunnel:
    - **Source port**: `3389`
    - **Destination**: `192.168.176.254:3389`
    - Select **Local**
    - Click **Add**
5. Go back to **Session** and click **Open** (log in as usual)

Then, open **Remote Desktop Connection** and connect to:

```

127.0.0.1:3389
```

---

## 🔐 Bonus: Make the Tunnel Run in Background (Linux)

If you don’t want to keep the SSH session interactive:

```bash

ssh -f -N -L 3389:192.168.176.254:3389 user@130.141.168.70

```

- `f`: Background after authentication
- `N`: No remote command
- `L`: Port forwarding

---

## 🧠 Pro Tips

- If port 3389 is **already in use locally**, use another local port, like `3390`, and connect to `127.0.0.1:3390`.
- If RDP doesn't respond, ensure the **Windows firewall** allows RDP, and the service is running.
- Use `xfreerdp` or `rdesktop` on Kali for command-line RDP.
