[*Active Directory Domain Services*](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview), often referred to as Active Directory (AD), is a service that allows system administrators to update and manage operating systems, applications, users, and data access on a large scale. Active Directory is installed with a standard configuration; however, system administrators often customize it to fit the needs of the organization.

![image.png](attachment:176b1c53-3bb2-40ba-a944-802e4f99cfeb:image.png)

## 🧭 **Active Directory - Enumeration**

### 🔹 **Basic Net Commands**

- `net user /domain`
    
    → *List all domain users*
    
    🔁 **Alternative**: `Get-ADUser -Filter * | Select-Object Name`
    
- `net user jeffadmin /domain`
    
    → *View info about a specific domain user*
    
    🔁 **Alternative**: `Get-ADUser jeffadmin -Properties *`
    
- `net group /domain`
    
    → *List domain groups*
    
- `net group "Sales Department" /domain`
    
    → *List users in a specific group*
    
    🔁 **Alternative**: `Get-ADGroupMember -Identity "Sales Department"`
    

---

### 🔹 **PowerShell & .NET Enumeration**

- `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`
    
    → *Get current domain object*
    
- `Get-ADDomain`, `Get-ADForest`
    
    → *More granular info on domain/forest (requires RSAT tools)*
    

---

### 🔹 **Scripts for Enumeration**

- [**absolomb/WindowsEnum**](https://github.com/absolomb/WindowsEnum)
    
    → *Local Privilege Escalation helper script*
    
- `.\enumeration.ps1`
    
    → *Run script and check variable outputs*
    
- [**PowerView**](https://powersploit.readthedocs.io/en/latest/Recon/)
    
    → *PowerShell-based AD enumeration suite*
    
    **Examples:**
    
    - `Import-Module .\PowerView.ps1`
    - `Get-NetUser | select cn,pwdlastset,lastlogon`
    - `Get-NetGroup | select cn`
    - `Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion`
    - `Find-LocalAdminAccess`
        
        🔁 *Check which machines you are local admin on*
        

---

### 🔹 **ACL / SID / Group Enumeration**

- `Get-Acl -Path HKLM:SYSTEM\...`
    
    → *Check registry permissions*
    
- `Get-ObjectAcl -Identity stephanie`
    
    → *View ACLs for a user*
    
- `Convert-SidToName S-1-5-...`
    
    → *Translate SID to username/groupname*
    
- `Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights`
    
    → *Find which SIDs have full rights*
    
- `"S-1-5-21-...","S-1-5-18"` | `Convert-SidToName`
    
    → *Batch SID resolution*
    
- `net group "Management Department" stephanie /add /domain`
    
    → *Add yourself to a group*
    
- `Get-NetGroup "Management Department" | select member`
    
    → *Verify group members before/after manipulation*
    

---

### 🔹 **Domain Shares & SYSVOL**

- `Find-DomainShare`
    
    → *Enumerate accessible shares on domain*
    
- `ls \\dc1.corp.com\sysvol\corp.com\`
    
    → *Browse SYSVOL for Group Policy Preferences (GPP)*
    
- `gpp-decrypt "<encrypted-password>"`
    
    → *Decrypt passwords from GPP XMLs*
    

---

## 🔎 **Active Directory - Automated Enumeration (BloodHound)**

### 🧰 **BloodHound Collection**

- `Import-Module .\Sharphound.ps1`
- `Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp_audit"`

📝 **Tips**:

- Use `All` for thorough data, or use selective methods like:
    - `LoggedOn`, `ACL`, `Session`, `Trusts`, `GroupMembership`

---

### 🧭 **BloodHound GUI: Filtering & Key Focus Areas**

### 🔹 **Recommended Filters to Use**

1. **Shortest Paths to Domain Admins**
    - Use "Find Principals with Shortest Paths to Domain Admins"
    - Helps identify lateral movement opportunities
2. **Users with Admin Rights**
    - Query: `MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN u.name, c.name`
    - Shows users who are local admins on machines
3. **Kerberoastable Users**
    - Built-in query in BloodHound:
        
        > "Users with Kerberoastable SPNs"
        > 
4. **Unconstrained Delegation**
    - Filter for computers with unconstrained delegation
    - Attack path: compromise → dump ticket → impersonate
5. **Outbound Control Rights**
    - Graph: "Outbound Object Control"
    - Useful for discovering privilege escalation via ACL abuse
6. **Path to High Value Targets (HVT)**
    - Select any object → right-click → *"Shortest Path to Here"*
    - Ideal for targeting `Domain Admins`, `Enterprise Admins`, or `DCs`

---

### 🧷 **What to Focus On**

- **Local Admin Rights**: Users/groups with `AdminTo` edges
- **ACL Abuse**: `GenericAll`, `WriteDacl`, `WriteOwner`, `AddMember`
- **GPO Permissions**: GPOs you can modify → control computers
- **Session Data**: Overlapping sessions between low and high-priv users
- **Trust Relationships**: Inter-forest trust abuse
- **SPNs & Delegation**: Kerberoasting & abuse of constrained/unconstrained delegation
