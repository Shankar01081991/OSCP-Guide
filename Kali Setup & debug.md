After launching Kali Linux in a virtual machine, update and upgrade the system using sudo apt-get update && apt-get upgrade -y. Then, disable the lock screen and screen saver in power management settings/ screensaver prefrences and set terminal application transparency to 0%. Finally, use PimpMyKali to install all essential tools. You can find the setup details here[https://github.com/Dewalt-arch/pimpmykali]. 🚀


If your virtual machine (VM) or system is unable to connect to OffSec labs, 

MTU Issues You tried MTU adjustments (1200, 1000, 900), but ACT broadband might require a different size. Try further lowering: NOTE if conneted to VPN the Adapter will be tun0
        
        sudo ip link set dev eth0 mtu 850

You can make the MTU change persistent across reboots by configuring it in your network settings.

Permanent Solution:
1. Use a Systemd Service (Recommended)
Create a systemd service that applies the MTU setting at startup:

        sudo nano /etc/systemd/system/set-mtu.service
Add the following:


        [Unit]
        Description=Set MTU for tun0
        After=network.target

        [Service]
        ExecStart=/sbin/ip link set dev tun0 mtu 1000
        Restart=always
        User=root

        [Install]
        WantedBy=multi-user.target

Save the file and enable the service:

        sudo systemctl daemon-reload
        sudo systemctl enable set-mtu.service
        sudo systemctl start set-mtu.service
This ensures the MTU is set automatically on every boot.
check if its enabled:

        systemctl is-enabled set-mtu.service

one possible reason could be related to how your public IP address is being handled—specifically, whether it's using IPv6 instead of IPv4.

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
    
🔄 Equivalent in Windows:
To disable IPv6 in Windows, you can use PowerShell or modify the Windows Registry.

✅ Using PowerShell (Recommended for most users):

    Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6

Replace "Ethernet" with the name of your network adapter (e.g., "Wi-Fi").
This disables IPv6 on that specific adapter.
🔧 To disable IPv6 system-wide via Registry (Advanced):
Open Registry Editor (regedit).
Navigate to:

      HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters
Create a new DWORD (32-bit) value named:

    DisabledComponents
Set its value to:

    0xFF
Restart your computer.
⚠️ Caution: Editing the registry can affect system stability. Always back up the registry before making changes.

🔧 Here's how to modify Firfox on Kali Linux:
Open Firefox.
In the address bar, type:

    about:config
Click “Accept the Risk and Continue” if prompted.
In the search bar, type:

    network.stricttransportsecurity.preloadlist
When it appears, double-click it to toggle the value to false.
This disables Firefox’s use of the preloaded HSTS list, which can force HTTPS even if the site doesn’t request it.

![image](https://github.com/user-attachments/assets/3f02962c-7df3-4dad-85d7-f8c8dc660098)

