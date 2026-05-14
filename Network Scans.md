## **Nmap Overview**

**Nmap** (short for **Network Mapper**) is a powerful open-source tool that plays a critical role in network security assessments, helping penetration testers and system administrators to discover network devices, open ports, and services running on a network. Nmap is widely appreciated for its versatility in security auditing, vulnerability scanning, and network discovery. In addition, Nmap can generate scan results in a variety of formats, making it easier to analyze and report findings in a structured way.

---

## **Host Scan**

The **Host Scan** feature is used to identify which hosts in a network are active. This is essential when penetration testers need to discover live devices within a target network. By sending ARP (Address Resolution Protocol) requests to all systems in the network, Nmap can determine if the systems are "up" by receiving MAC addresses from active hosts.

- **Command**:
    
    The `-sP` option, also referred to as a **Ping Scan**, helps discover live hosts on a network. The scan works by sending ICMP echo requests (pings) to all the specified IP addresses. If a system responds, it indicates the host is live.
    

```bash

nmap -sP <Target IP>

```


This command scans for active devices on the network, and if a device responds, the message "Host is up" will be displayed.

---

## **Port Scan / TCP Scan**

A **Port Scan** or **TCP Scan** is used by penetration testers to identify which ports on a target machine are open, closed, or filtered. Understanding the status of ports is essential for identifying potential vulnerabilities in the system.

**Port Status Indicators:**

- **Open**: An application is actively listening for connections on the port.
- **Closed**: The probe was received, but no application is currently listening on the port.
- **Filtered**: The probes were not received, indicating that a firewall or other filter might be dropping packets.
- **Unfiltered**: The probes were received, but the port's status could not be determined.
- **Open/Filtered**: Nmap cannot distinguish if the port is open or filtered, only that it is either one of them.
- **Closed/Filtered**: The status of the port is ambiguous, potentially due to firewall filtering or other network defenses.
- **Command**:
    
    To scan a specific port (e.g., port 135), use the following command:
    

```bash

sudo nmap -p135 <Target IP>

```

This will display whether port 135 is open, closed, or filtered on the target system.

---

## **Scan Output Formats**

Nmap offers various output formats for the results of a scan, allowing penetration testers to customize how they store and analyze scan data. Common formats include **Normal**, **XML**, and **HTML**.

- **Normal Output** -oN: Stores the results in plain text.
- **XML Output** -oX: Stores the results in an XML format, which is useful for further processing or automated analysis.
- **HTML Output**: Provides a more readable and organized report using an XSLT stylesheet.
- **Command for Normal and XML Output**:
    
    To store the scan results in both normal and XML formats, use the following command:
    

```bash

sudo nmap -oN port_scan.txt -oX port_scan.xml <Target IP>

```

- **Command for HTML Output**:
    
    To generate an HTML report, first perform the scan in XML format, then convert it to HTML using the `xsltproc` tool:
    

```bash

sudo nmap -oX scan.xml --stylesheet=nmap.xsl <Target IP>
xsltproc -o scan.html nmap.xsl scan.xml
firefox scan.html

```

This process creates a well-organized HTML report of your scan results.

---

## **Verbosity Mode**

The **Verbosity Mode** in Nmap helps to provide more detailed output during a scan. By increasing the verbosity level, you can view extra details such as open ports, the estimated time for scan completion, and other scan-related information.

- **Command for Increased Verbosity**:
    
    To increase verbosity, use the `-v` option. For even more detail, you can use `-vv` for a higher verbosity level. You can also specify the verbosity level directly (e.g., `-v2`).
    

```bash

sudo nmap -vv -oN Verbose_scan.txt <Target IP>

```

This command provides an in-depth look at the scan's progress and status.

---

## **Version Scan**

A **Version Scan** is critical for identifying the exact versions of services running on the target machine. This information helps penetration testers determine if a system is vulnerable to specific exploits associated with those service versions. This technique is often referred to as **Banner Grabbing** in the context of penetration testing.

- **Command**:
    
    To perform a version scan, use the `-sV` option, which attempts to identify versions of services running on open ports:
    

```bash

nmap -sV <Target IP>

```

This scan provides detailed information about the services and their versions running on the target.

---

## **Timing Template Scan**

Nmap’s **Timing Template** option allows you to control the speed of your scan. Adjusting the timing can help balance between scan accuracy and speed, depending on the network's response time and how stealthy you want your scan to be. There are six predefined timing templates in Nmap:

- **T0**: Paranoid (slow, stealthy)
- **T1**: Sneaky
- **T2**: Polite
- **T3**: Normal
- **T4**: Aggressive
- **T5**: Insane (fast, but can be very noisy)
- **Command**:
    
    For faster scans with an aggressive timing template (T4), use the following:
    

```bash

nmap -T4 <Target Ip>

```

This command applies the **T4** timing template, which speeds up the scan without being too intrusive.

---

## **Aggressive Scan**

The **Aggressive Scan** mode enables a set of advanced options to gather comprehensive information about the target. This includes **OS detection**, **version scanning**, **script scanning**, and **traceroute**. It is a highly effective scan for gathering detailed insights, but it is also quite noisy and can alert intrusion detection systems.

- **Command**:
    
    To initiate an aggressive scan, use the `-A` option:
    

```bash

nmap -A <Target IP>

```

This command combines multiple advanced scans to gather extensive data about the target.

---

## **List Scan**

The **List Scan** option allows you to scan multiple hosts at once by loading IP addresses from a file. This is useful for penetration testers who need to scan large numbers of systems quickly.

- **Command**:
    
    To load IP addresses from a file (e.g., `targets.txt`) and scan them:
    

```bash

nmap -iL /root/Desktop/scan.txt

```

This will read the list of targets from `scan.txt` and scan each one.

---

## **Debugging Mode**

If **Verbose Mode** doesn’t provide enough information, Nmap’s **Debugging Mode** can be used to get even more granular details about the scan process, including packet-level details, flags, and other technical aspects. Debugging mode is useful when troubleshooting a scan or when needing to perform a deep analysis of a network.

- **Command**:
    
    To enable debugging with a specified debug level (e.g., `-d2`), use the following command:
    

```bash

nmap -d2 -oN scan.txt <Target IP>

```

This provides detailed insights into the scanning process.

---

## **OS Fingerprinting**

Nmap can also perform **OS Fingerprinting**, which helps penetration testers identify the operating system running on a target device based on its response patterns. This information is invaluable for customizing attacks based on the target’s OS vulnerabilities.

- **Command**:
    
    To perform an OS fingerprinting scan:
    

```bash

nmap -O <Target IP>

```

This will provide insights into the target’s operating system and possible security implications.

---

## **Nmap Scripts**

Nmap includes the **Nmap Scripting Engine (NSE)**, which allows users to run scripts for automated tasks such as vulnerability scanning, service discovery, and brute-force password testing. These scripts are categorized for various purposes, such as:

- **Vulnerability Detection**: Identify weaknesses in services (e.g., `vuln` scripts).
- **Network Discovery**: Gather detailed information about devices (e.g., `discovery` scripts).
- **Brute Force Attacks**: Test password strength (e.g., `brute` scripts).
- **Exploitation**: Exploit known vulnerabilities (e.g., `exploit` scripts).
- **Malware Detection**: Detect malware on devices (e.g., `malware` scripts).
- **Information Gathering**: Collect detailed information on network services (e.g., `info` scripts).
- **Command to use specific scripts**:
    
    To search for and use specific scripts, such as `ssh-hostkey.nse`, the following command is used:
    

```bash
ls /usr/share/nmap/scripts | grep ssh
nmap -p22 --script ssh-hostkey.nse <Target IP>

```

This allows you to execute specific scripts related to SSH key scanning.
---
## **Nmap Scan automate for all subnet**

```
# List all subnets you want to scan
$subnets = @(
	"<Subnet>",
	"<Subnet>",
	"<Subnet>",
	"<Subnet>"
)

# ============================
# Nmap Multi-Subnet Deep Scanner
# Host Identity + Services + Classification
# Safe NSE scripts + Parallel per-host scans
# Output: Excel-ready CSV
# ============================

# Assumes: $subnets is already defined as an array of CIDR strings
# Example:
# $subnets = @("xx.x1.x30.0/24","xx.1x.x31.0/24")

$output  = "Nmap-Asset-Inventory.csv"
$results = @()

foreach ($subnet in $subnets) {

    Write-Host "Scanning (host discovery) $subnet ..."

    # Host discovery
    $scan = nmap -n -sn $subnet 2>&1

    if ($scan -and ($scan | Select-String "Nmap scan report for")) {
        $upHosts = ($scan | Select-String "Nmap scan report for").Line |
                   ForEach-Object { ($_ -split " ")[-1] }
    } else {
        $upHosts = @()
    }

    # Generate full IP list for the subnet (assumes /24)
    $ips = (0..255 | ForEach-Object {
        $base   = $subnet.Split("/")[0]
        $octets = $base.Split(".")
        "$($octets[0]).$($octets[1]).$($octets[2]).$_"
    })

    # Parallel deep scan for UP hosts
    $jobs = @()
    foreach ($ip in $upHosts) {
        $jobs += Start-Job -ArgumentList $ip, $subnet -ScriptBlock {
            param($ip, $subnet)

            $detail = nmap -n -Pn -O -sV --script safe $ip 2>&1

            # Hostname / FQDN
            $hostname = ""
            $fqdn     = ""
            try {
                $dns = Resolve-DnsName -Name $ip -ErrorAction Stop
                $ptr = $dns | Where-Object { $_.QueryType -eq "PTR" }
                if ($ptr) {
                    $fqdn     = $ptr.NameHost
                    $hostname = $fqdn.Split(".")[0]
                }
            } catch { }

            # MAC + Vendor
            $mac       = ""
            $macVendor = ""
            $macLine = $detail | Select-String "MAC Address"
            if ($macLine) {
                $m = $macLine.Line -replace "MAC Address:\s*", ""
                if ($m -match "([0-9A-Fa-f:]{17})\s+\((.+)\)") {
                    $mac       = $matches[1]
                    $macVendor = $matches[2]
                } elseif ($m -match "([0-9A-Fa-f:]{17})") {
                    $mac = $matches[1]
                }
            }

            # Device type
            $deviceType = ""
            $devLine = $detail | Select-String "Device type:"
            if ($devLine) {
                $deviceType = ($devLine.Line -replace "Device type:\s*", "").Trim()
            }

            # OS details + accuracy
            $osDetails  = ""
            $osAccuracy = ""
            $osLine = $detail | Select-String "OS details:"
            if ($osLine) {
                $osDetails = ($osLine.Line -replace "OS details:\s*", "").Trim()
            }
            $accLine = $detail | Select-String "OS detection performed"
            if ($accLine -and $accLine.Line -match "Accuracy: (\d+)%") {
                $osAccuracy = $matches[1] + "%"
            }

            # Ports table (open/closed/filtered + service summary)
            $portLines = @()
            $openPorts = @()
            $closedPorts = @()
            $filteredPorts = @()
            $serviceSummary = @()

            $inPorts = $false
            foreach ($line in $detail) {
                if ($line -match "PORT\s+STATE\s+SERVICE") {
                    $inPorts = $true
                    continue
                }
                if ($inPorts) {
                    if ([string]::IsNullOrWhiteSpace($line)) { break }
                    $portLines += $line
                }
            }

            foreach ($line in $portLines) {
                if ($line -match "^\d+\/\w+\s+open") {
                    $openPorts += $line.Trim()
                } elseif ($line -match "^\d+\/\w+\s+closed") {
                    $closedPorts += $line.Trim()
                } elseif ($line -match "^\d+\/\w+\s+filtered") {
                    $filteredPorts += $line.Trim()
                }
                $serviceSummary += $line.Trim()
            }

            $openPortsStr     = $openPorts -join "; "
            $closedPortsStr   = $closedPorts -join "; "
            $filteredPortsStr = $filteredPorts -join "; "
            $serviceSummaryStr = $serviceSummary -join " | "

            # HTTP title
            $httpTitle = ""
            $httpLine = $detail | Select-String "http-title"
            if ($httpLine) {
                $httpTitle = ($httpLine | ForEach-Object { $_.Line }) -join " | "
            }

            # SSL/TLS info
            $sslInfo = ""
            $sslLines = $detail | Select-String "ssl-cert|ssl-enum-ciphers"
            if ($sslLines) {
                $sslInfo = ($sslLines | ForEach-Object { $_.Line.Trim() }) -join " | "
            }

            # SSH host key
            $sshHostKey = ""
            $sshLines = $detail | Select-String "ssh-hostkey"
            if ($sshLines) {
                $sshHostKey = ($sshLines | ForEach-Object { $_.Line.Trim() }) -join " | "
            }

            # Basic asset classification
            $assetRole    = "Unknown"
            $isVirtual    = "Unknown"
            $cloudProvider = "Unknown"

            $lowerDetail = ($detail -join "`n").ToLower()

            if ($deviceType.ToLower() -match "router|switch|firewall|wap|bridge") {
                $assetRole = "Network Device"
            } elseif ($osDetails -match "Windows" -or $serviceSummaryStr -match "msrpc|ms-wbt-server|microsoft-ds") {
                $assetRole = "Windows Host"
            } elseif ($osDetails -match "Linux|Unix|BSD") {
                $assetRole = "Unix/Linux Host"
            }

            if ($lowerDetail -match "vmware|virtualbox|kvm|hyper-v") {
                $isVirtual = "Yes"
            } elseif ($lowerDetail -match "amazon|aws|azure|google cloud|gcp") {
                $isVirtual = "Yes"
                $cloudProvider = "Cloud"
            }

            [PSCustomObject]@{
                IPAddress       = $ip
                Hostname        = $hostname
                FQDN            = $fqdn
                Status          = "UP"
                Subnet          = $subnet
                MACAddress      = $mac
                MACVendor       = $macVendor
                DeviceType      = $deviceType
                OSDetails       = $osDetails
                OSAccuracy      = $osAccuracy
                OpenPorts       = $openPortsStr
                ClosedPorts     = $closedPortsStr
                FilteredPorts   = $filteredPortsStr
                ServiceSummary  = $serviceSummaryStr
                HttpTitle       = $httpTitle
                SslInfo         = $sslInfo
                SshHostKey      = $sshHostKey
                AssetRole       = $assetRole
                IsVirtual       = $isVirtual
                CloudProvider   = $cloudProvider
            }
        }
    }

    # Wait for all jobs for this subnet
    if ($jobs.Count -gt 0) {
        Write-Host "Waiting for detailed scans to complete for $subnet ..."
        Wait-Job -Job $jobs | Out-Null
        $upResults = Receive-Job -Job $jobs
        Remove-Job -Job $jobs
    } else {
        $upResults = @()
    }

    # Index UP results by IP
    $upIndex = @{}
    foreach ($r in $upResults) {
        $upIndex[$r.IPAddress] = $r
    }

    # Build final results for all IPs in subnet
    foreach ($ip in $ips) {
        if ($upIndex.ContainsKey($ip)) {
            $results += $upIndex[$ip]
        } else {
            $results += [PSCustomObject]@{
                IPAddress       = $ip
                Hostname        = ""
                FQDN            = ""
                Status          = "DOWN"
                Subnet          = $subnet
                MACAddress      = ""
                MACVendor       = ""
                DeviceType      = ""
                OSDetails       = ""
                OSAccuracy      = ""
                OpenPorts       = ""
                ClosedPorts     = ""
                FilteredPorts   = ""
                ServiceSummary  = ""
                HttpTitle       = ""
                SslInfo         = ""
                SshHostKey      = ""
                AssetRole       = "Unknown"
                IsVirtual       = "Unknown"
                CloudProvider   = "Unknown"
            }
        }
    }
}

$results | Export-Csv -NoTypeInformation -Path $output -Encoding UTF8
Write-Host "Scan completed. Results saved to $output"


---

