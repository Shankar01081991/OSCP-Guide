## **Nmap**

**Nmap** which is also known as **Network Mapper** is one of the best open-source and the handiest tool that is widely used for security auditing and network scanning by pentesters. It also provides an additional feature where the results of a network scan can be recorded in various formats.

## **Host Scan**

Host scan is used by penetration tester to identify active host in a network by sending ARP request packets to all system in that network. As result it will show a message “Host is up” by receiving MAC address from each active host. -sP, it performs a "ping scan," which is used to discover live hosts on a network.

```jsx
nmap -sP <Target IP>

```

![image](https://github.com/user-attachments/assets/fa35cab0-2f7c-4e89-bf78-582bda1c8dd1)


## **Port scan /TCP scan**

If penetration testers want to identify open or close state of a particular port on target machine then they should go with nmap port scan.

**Port Status:** After scanning, you may see some results with a port status like filtered, open, closed, etc. Let me explain this.

- Open: This indicates that an application is listening for connections on this port.
- Closed: This indicates that the probes were received but there is no application listening on this port.
- Filtered: This indicates that the probes were not received and the state could not be established. It also indicates that the probes are being dropped by some kind of filtering.
- Unfiltered: This indicates that the probes were received but a state could not be established.
- Open/Filtered: This indicates that the port was filtered or open but Nmap couldn’t establish the state.
- Closed/Filtered: This indicates that the port was filtered or closed but Nmap couldn’t establish the state.

```jsx
sudo nmap -p135 <Target IP>
```

![image.png](attachment:3da86ea7-f2bd-41f1-8f5f-ec0e2cdcc0c7:image.png)

## **Scan Output Formats**

![0.png](attachment:faf202cc-0f75-4b1d-91d4-91a1fae9df82:0.png)

If you wants to create the scan reports in Normal as well as XML form in a combination.

```
sudo nmap -oN port_scan.txt -oX port_scan.xml <Target IP>

```

![image.png](attachment:dd2674e4-56f3-41b1-a2e1-998c12d1dc25:image.png)

Getting an html stylesheet as their report as it gives much-organised scan results:

```
sudo nmap -oX scan.xml --stylesheet=nmap.xsl <Target IP>
xsltproc -o scan.html nmap.xsl scan.xml
firefox scan.html
```

![image.png](attachment:514673e0-8867-48c8-9bc6-6d38d17bfb4e:image.png)

## **Verbosity mode**

To increase the level of verbosity for printing more information about the scan . In this scan details like open ports, estimated time of completion, etc are highlighted.

This mode is used twice or more for better verbosity: -vv, or give a verbosity level directly, like -vv, v2, v3.

```jsx
sudo nmap -vv -oN Verbos_scan.txt <Target IP>

```

![image.png](attachment:633c35d9-cd1d-4522-b00d-45c0de2521ca:image.png)

# **OS Detection Scan**

## **Version Scan**

When doing vulnerability assessments of your companies or clients, you really want to know which mail and DNS servers and versions are running. Having an accurate version number helps dramatically in determining which exploits a server is vulnerable to. Version detection helps you obtain this information. Fingerprinting a service may also reveal additional information about a target, such as available modules and specific protocol information. Version scan is also categories as “**Banner Grabbing**” in penetration testing.

```
nmap -sV <Target IP>
```

![image.png](attachment:b65b4591-6cdf-4c35-8134-8badcdf86ed8:image.png)

## **Timing Template Scan**

The main timing option is set through the -T parameter if you may want more control over the timing in order get the scan over and done with quicker. However, Nmap adjusts its timings automatically depending on network speed and response times of the victim.

Nmap offers a simpler approach, with six timing templates. You can specify them with the -T option and their number (0–5) or their name as shown below:

- T0: paranoid
- T1: sneaky
- T2: polite
- T3: normal
- T4: aggressive
- T5: insane

```
nmap –T4 192.168.188.131
```

## **Aggressive Scan**

This option enables additional advanced and aggressive options. Presently this enables OS detection (-O), version scanning (-sV), script scanning (-sC) and traceroute (–traceroute). This option only enables features, and not timing options (such as -T4) or verbosity options (-v) that you might want as well. You can see this by using one of the following commands:

```
nmap -A <Target IP>
```

## **List Scan**

When you want to scan multiple host to perform more than one scanning then –iL option is used which support nmap to load the targets from an external file. Only you need to add all targeted IP in a text file and save it at a location.

To load the targets from the file targets.txt, the following command can be used:

```
nmap -iL /root/Desktop/scan.txt
```

Ref: [Nmap for Pentester: Host Discovery - Hacking Articles](https://www.hackingarticles.in/nmap-for-pentester-host-discovery/)

=================================================================

## Debugging mode

Debugging mode is generally used when the verbose mode doesn’t provide enough details about the scan, so it digs deeper into the scanning process. The level of debug can be increased by specifying its number. Here you get details like the flags [resent in the packets, the time-to-live etc.

```
nmap -d2 -oN scan.txt <Target IP>
```

![image.png](attachment:62727a5c-9739-4559-b334-8e158b06830d:image.png)

## OS fingerprinting

Apart from open port enumeration nmap is quite useful in OS fingerprinting. This scan very helpful to penetration tester in order to conclude possible security vulnerabilities and determining the available system calls to set the specific exploit payloads.

```
nmap -O <Target IP>
```

![image.png](attachment:30e09b80-d7be-441c-971d-193d404dcf3f:image.png)

## Scripts

Nmap scripts are part of the Nmap Scripting Engine (NSE), which allows users to write and use scripts to automate a wide range of network tasks. These scripts can be used for various purposes, such as:

**Vulnerability Detection**:

- Identify vulnerabilities in network services.
- Example: `vuln` scripts.

**Network Discovery**:

- Gather information about network devices and services.
- Example: `discovery` scripts.

**Brute Force Attacks**:

- Perform brute force attacks to test the strength of passwords.
- Example: `brute` scripts.

**Exploitation**:

- Exploit known vulnerabilities to gain access or perform specific actions.
- Example: `exploit` scripts.

**Malware Detection**:

- Detect malware or backdoors on network devices.
- Example: `malware` scripts.

**Information Gathering**:

- Collect detailed information about network services and configurations.
- Example: `info` scripts.

You can list all available Nmap scripts using the `ls` command:
