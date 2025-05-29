If your virtual machine (VM) or system is unable to connect to OffSec labs, one possible reason could be related to how your public IP address is being handled—specifically, whether it's using IPv6 instead of IPv4.

🔍 How to Check:
You can verify the type of IP your system is using by running the following command in your terminal:

    curl ifconfig.me
If this command returns an IPv6 address (e.g., something like 2001:0db8:85a3:0000:0000:8a2e:0370:7334), and your VPN or lab environment primarily supports IPv4, this mismatch can cause connectivity issues.

🛠️ How to Fix:

To disable IPv6 and force your system to use IPv4, run the following command:

    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1

This command temporarily disables IPv6 on your system. If you want to make this change permanent, you can add the following line to your /etc/sysctl.conf file:

    net.ipv6.conf.all.disable_ipv6 = 1

Then apply the changes with:

    sudo sysctl -p
