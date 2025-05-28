
if your VM or system not able to connect to offsec labs reasion may be public IP Behavior
check `curl ifconfig.me` if it returns IPV6 add and if your VPN lab primarly use IPv4 that coulc cause an issue
Fix: `sudo sysctl -w net.ipv6.config.all.disable_ipv6=1` 
