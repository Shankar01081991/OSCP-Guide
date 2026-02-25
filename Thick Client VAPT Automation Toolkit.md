### 🛡️ **Thick Client VAPT Automation Toolkit**
# Safe, read‑only misconfiguration detection for Windows thick‑client applications

A **PowerShell automation toolkit** to quickly spot **misconfigurations**, **weak security controls**, and **potential vulnerabilities** in Windows thick‑client apps — **without exploitation**.

<aside>
🧯

### **Non-intrusive by design**

- Read-only checks only
- Safe to run on production (authorized) environments
- No exploitation or payload execution
</aside>

### ✨ **Highlights**

- **Binary & DLL analysis** (inventory, signature checks, interesting strings)
- **File system ACL checks** (writable dirs, DLL hijack indicators)
- **Secrets discovery** (configs and common formats)
- **Crypto & key material checks** (weak algorithms, embedded keys)
- **Log & registry checks** (sensitive content, weak ACLs)
- **Process module enumeration** (loaded DLLs + suspicious load paths)

### 📁 **Output**

All findings are written to:

```
VAPT_TEST/
```

Key files:

```
VAPT_TEST/
├── dll_list.txt
├── SignatureReport.csv
├── InterestingStrings.txt
├── FolderPermissions.txt
├── WritableSubdirectories.txt
├── ConfigSensitiveData.txt
├── ConfigExtendedSensitiveData.txt
├── WeakCrypto.txt
├── InsecureProtocols.txt
├── EmbeddedPrivateKeys.txt
├── ConnectionStrings.txt
├── DebugSettings.txt
├── TempUsage.txt
├── LoadedDLLs.txt
├── RegistryPermissions.txt
└── VulnerabilitySummary.txt
```

### 📊 **Vulnerability summary**

At the end of execution, the script generates:

```
VAPT_TEST/VulnerabilitySummary.txt
```

Example output:

```
[HIGH] Invalid or unsigned binary: helper.dll
[HIGH] Writable subdirectories detected (DLL hijacking risk)
[MEDIUM] Weak cryptographic algorithms detected
[MEDIUM] Hardcoded connection strings detected
[LOW] Debug/verbose flags detected
```

### 🚀 **Quick start**

1. Copy the script into the application install directory

```
C:\Program Files\TEST_APP\
```

1. Open PowerShell
- Admin is recommended for registry checks.
1. Run the script

```powershell
.\thickclient.ps1
```

1. Follow prompts (only when needed)
- Pick a process (index or PID) for DLL enumeration
- Optionally select a discovered registry key
1. Review results inside `VAPT_TEST/`

### ⚠️ **Notes**

- Use only for **authorized** assessments.
- The toolkit is **read-only** and **does not exploit** vulnerabilities.

---

### 🧩 **Script**

```powershell
# ================================
# Thick Client VAPT Automation Script (Safe)
# ================================

$BasePath = (Get-Location).Path
$OutDir = Join-Path $BasePath "VAPT_TEST"

# Create output folder
if (!(Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

Write-Host "Running safe VAPT checks..." -ForegroundColor Cyan

# ================================
# 1. Generate DLL/EXE List
# ================================
$dllList = Join-Path $OutDir "dll_list.txt"
Get-ChildItem -Recurse -Include *.dll, *.exe -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName |
    Out-File $dllList

Write-Host "Generated dll_list.txt" -ForegroundColor Green

# ================================
# 2. Signature Validation
# ================================
$SignatureReport = Join-Path $OutDir "SignatureReport.csv"
$files = Get-Content $dllList
$results = @()

foreach ($file in $files) {
    if (Test-Path $file) {
        $sig = Get-AuthenticodeSignature -FilePath $file

        $results += [PSCustomObject]@{
            FileName  = (Split-Path $file -Leaf)
            FullPath  = $file
            Status    = $sig.Status
            Signer    = $sig.SignerCertificate.Subject
            Issuer    = $sig.SignerCertificate.Issuer
            NotBefore = $sig.SignerCertificate.NotBefore
            NotAfter  = $sig.SignerCertificate.NotAfter
        }
    }
    else {
        $results += [PSCustomObject]@{
            FileName  = (Split-Path $file -Leaf)
            FullPath  = $file
            Status    = "FileNotFound"
            Signer    = ""
            Issuer    = ""
            NotBefore = ""
            NotAfter  = ""
        }
    }
}

$results | Export-Csv $SignatureReport -NoTypeInformation
Write-Host "SignatureReport.csv created" -ForegroundColor Green

# ================================
# 3b. Extract ONLY Interesting Strings (Filtered)
# ================================

$InterestingOut = Join-Path $OutDir "InterestingStrings.txt"

# Define patterns that indicate interesting strings
$patterns = @(
    "password",
    "passwd",
    "token",
    "secret",
    "key",
    "auth",
    "bearer",
    "api",
    "jdbc",
    "sql",
    "select ",
    "insert ",
    "update ",
    "delete ",
    "http://",
    "https://",
    "ftp://",
    "\\\\",              # UNC paths
    "C:\\",              # Windows paths
    "HKEY_",             # Registry keys
    "@",                 # Email addresses
    "\.config",
    "\.xml",
    "\.json",
    "\.ini",
    "\.dll",
    "\.exe"
)

Write-Host "Filtering interesting strings..." -ForegroundColor Cyan

# Read all extracted string files
$AllStrings = Get-ChildItem $StringsDir -Filter *.txt | ForEach-Object {
    Get-Content $_.FullName
}

# Apply filtering
$Interesting = foreach ($line in $AllStrings) {
    foreach ($pattern in $patterns) {
        if ($line -match $pattern) {
            $line
            break
        }
    }
}

# Remove duplicates and save
$Interesting | Sort-Object -Unique | Out-File $InterestingOut

Write-Host "InterestingStrings.txt created with filtered results" -ForegroundColor Green

# ================================
# 4. Folder Permission Analysis
# ================================
$FolderACL = Join-Path $OutDir "FolderPermissions.txt"
Get-Acl $BasePath | Format-List | Out-File $FolderACL

Write-Host "Folder permission analysis complete" -ForegroundColor Green

# ================================
# 5. Automatic Registry Discovery (Safe)
# ================================
$RegOut = Join-Path $OutDir "RegistryPermissions.txt"

$AppName = Read-Host "Enter application name to search in registry (or press Enter to skip)"

if ($AppName -ne "") {

    Write-Host "Searching registry for keys matching: $AppName ..." -ForegroundColor Cyan

    $RegMatches = @()

    # 64-bit hive
    $RegMatches += Get-ChildItem -Path HKLM:\Software -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*$AppName*" }

    # 32-bit hive (WOW6432Node)
    $RegMatches += Get-ChildItem -Path HKLM:\Software\WOW6432Node -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*$AppName*" }

    if ($RegMatches.Count -eq 0) {
        Write-Host "No registry keys found for '$AppName'." -ForegroundColor Yellow
    }
    else {
        Write-Host "`nFound the following registry keys:" -ForegroundColor Green

        # Display numbered list
        for ($i = 0; $i -lt $RegMatches.Count; $i++) {
            Write-Host "[$i] $($RegMatches[$i].Name)"
        }

        $choice = Read-Host "Enter the number of the registry key to analyze (or press Enter to skip)"

        if ($choice -match '^\d+$' -and $choice -lt $RegMatches.Count) {
            $SelectedKey = $RegMatches[$choice].PsPath

            Write-Host "Analyzing permissions for: $SelectedKey" -ForegroundColor Cyan

            try {
                Get-Acl $SelectedKey | Format-List | Out-File $RegOut
                Write-Host "Registry permissions saved to RegistryPermissions.txt" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to read ACL for selected key." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "Registry permission check skipped." -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host "Registry search skipped." -ForegroundColor Yellow
}
# ================================
# 6. Weak Crypto Pattern Scan
# ================================
$CryptoOut = Join-Path $OutDir "WeakCrypto.txt"
Select-String -Path *.dll, *.exe -Pattern "MD5|SHA1|DES|RC4" -ErrorAction SilentlyContinue |
    Out-File $CryptoOut

Write-Host "Weak crypto scan complete" -ForegroundColor Green

# ================================
# 7. Config File Sensitive Data Scan
# ================================
$ConfigOut = Join-Path $OutDir "ConfigSensitiveData.txt"
Select-String -Path *.config -Pattern "password|key|token|secret" -ErrorAction SilentlyContinue |
    Out-File $ConfigOut

Write-Host "Config sensitive data scan complete" -ForegroundColor Green

# ================================
# 8. Log File Sensitive Data Scan
# ================================
$LogOut = Join-Path $OutDir "LogSensitiveData.txt"
if (Test-Path ".\Logs") {
    Select-String -Path ".\Logs\*" -Pattern "password|token|error|exception" -ErrorAction SilentlyContinue |
        Out-File $LogOut
}

Write-Host "Log scan complete" -ForegroundColor Green

# ================================
# 9. DLL Load Enumeration (Safe)
# ================================

Write-Host "`nListing all running processes..." -ForegroundColor Cyan

$ProcessList = Get-Process | Sort-Object ProcessName

# Display numbered list
for ($i = 0; $i -lt $ProcessList.Count; $i++) {
    Write-Host "[$i] $($ProcessList[$i].ProcessName)  (PID: $($ProcessList[$i].Id))"
}

$choice = Read-Host "Enter the number OR PID of the process (or press Enter to skip)"

if ($choice -match '^\d+$') {

    # Check if input matches an index
    if ($choice -lt $ProcessList.Count) {
        $SelectedProc = $ProcessList[$choice]
    }
    else {
        # Check if input matches a PID
        try {
            $SelectedProc = Get-Process -Id $choice -ErrorAction Stop
        }
        catch {
            Write-Host "Invalid process number or PID." -ForegroundColor Yellow
            $SelectedProc = $null
        }
    }

    if ($SelectedProc) {
        Write-Host "Enumerating DLLs for: $($SelectedProc.ProcessName) (PID: $($SelectedProc.Id))" -ForegroundColor Cyan

        try {
            $DLLReport = Join-Path $OutDir "LoadedDLLs.txt"
            $SelectedProc.Modules |
                Select ModuleName, FileName |
                Out-File $DLLReport

            Write-Host "Loaded DLL list saved to LoadedDLLs.txt" -ForegroundColor Green
        }
        catch {
            Write-Host "Unable to enumerate DLLs (access denied or protected process)." -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host "DLL enumeration skipped." -ForegroundColor Yellow
}
# ================================
# 10. Writable Subdirectories Check
# ================================
$WritableDirsOut = Join-Path $OutDir "WritableSubdirectories.txt"
$WritableFindings = @()

Get-ChildItem -Path $BasePath -Recurse -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $acl = Get-Acl $_.FullName
    foreach ($ace in $acl.Access) {
        if ($ace.FileSystemRights -match "Write" -and $ace.IdentityReference -match "Users|Everyone|Authenticated Users") {
            $WritableFindings += "Writable by $($ace.IdentityReference): $($_.FullName)"
            break
        }
    }
}

if ($WritableFindings.Count -gt 0) {
    $WritableFindings | Out-File $WritableDirsOut
    Write-Host "Writable subdirectories found (potential DLL hijack risk)." -ForegroundColor Yellow
} else {
    "No writable subdirectories for non-admin users detected." | Out-File $WritableDirsOut
    Write-Host "No writable subdirectories detected." -ForegroundColor Green
}
# ================================
# 11. Extended Config Secret Scan
# ================================
$ConfigExtendedOut = Join-Path $OutDir "ConfigExtendedSensitiveData.txt"

$ConfigFiles = Get-ChildItem -Recurse -Include *.config, *.xml, *.json, *.ini, *.properties, *.yml, *.yaml -ErrorAction SilentlyContinue

if ($ConfigFiles) {
    $patterns = "password","passwd","token","secret","key","auth","connectionstring","user id","uid","pwd"
    $matches = @()

    foreach ($file in $ConfigFiles) {
        foreach ($pattern in $patterns) {
            $res = Select-String -Path $file.FullName -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
            if ($res) { $matches += $res }
        }
    }

    if ($matches.Count -gt 0) {
        $matches | Out-File $ConfigExtendedOut
        Write-Host "Extended config sensitive data found." -ForegroundColor Yellow
    } else {
        "No obvious secrets found in extended config files." | Out-File $ConfigExtendedOut
        Write-Host "No sensitive data in extended config files." -ForegroundColor Green
    }
} else {
    "No extended config files found." | Out-File $ConfigExtendedOut
}
# ================================
# 12. Insecure Protocol Usage Scan
# ================================
$InsecureProtoOut = Join-Path $OutDir "InsecureProtocols.txt"

$patterns = "http://","ftp://","telnet://","ldap://"
$targets  = Get-ChildItem -Recurse -Include *.dll, *.exe, *.config, *.xml, *.json, *.ini -ErrorAction SilentlyContinue

$hits = @()

foreach ($file in $targets) {
    foreach ($pattern in $patterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue
        if ($res) { $hits += $res }
    }
}

if ($hits.Count -gt 0) {
    $hits | Out-File $InsecureProtoOut
    Write-Host "Insecure protocol references found." -ForegroundColor Yellow
} else {
    "No insecure protocol references detected." | Out-File $InsecureProtoOut
    Write-Host "No insecure protocol usage detected." -ForegroundColor Green
}
# ================================
# 13. Embedded Private Key Detection
# ================================
$PrivateKeyOut = Join-Path $OutDir "EmbeddedPrivateKeys.txt"

$KeyPatterns = "-----BEGIN PRIVATE KEY-----","-----BEGIN RSA PRIVATE KEY-----","-----BEGIN EC PRIVATE KEY-----"
$TextFiles   = Get-ChildItem -Recurse -Include *.pem, *.key, *.crt, *.cer, *.pfx, *.p12, *.config, *.xml, *.json, *.txt -ErrorAction SilentlyContinue

$KeyHits = @()

foreach ($file in $TextFiles) {
    foreach ($pattern in $KeyPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue
        if ($res) { $KeyHits += $res }
    }
}

if ($KeyHits.Count -gt 0) {
    $KeyHits | Out-File $PrivateKeyOut
    Write-Host "Embedded private key material detected." -ForegroundColor Yellow
} else {
    "No embedded private key material detected." | Out-File $PrivateKeyOut
    Write-Host "No private keys detected in files." -ForegroundColor Green
}
# ================================
# 14. Connection String Detection
# ================================
$ConnStrOut = Join-Path $OutDir "ConnectionStrings.txt"

$ConnPatterns = "Server=","Data Source=","User ID=","Password=","Uid=","Pwd=","Integrated Security="
$ConnFiles    = Get-ChildItem -Recurse -Include *.config, *.xml, *.json, *.ini, *.properties, *.txt -ErrorAction SilentlyContinue

$ConnHits = @()

foreach ($file in $ConnFiles) {
    foreach ($pattern in $ConnPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue
        if ($res) { $ConnHits += $res }
    }
}

if ($ConnHits.Count -gt 0) {
    $ConnHits | Out-File $ConnStrOut
    Write-Host "Connection strings detected." -ForegroundColor Yellow
} else {
    "No obvious connection strings detected." | Out-File $ConnStrOut
    Write-Host "No connection strings detected." -ForegroundColor Green
}
# ================================
# 15. Debug / Verbose Mode Detection
# ================================
$DebugOut = Join-Path $OutDir "DebugSettings.txt"

$DebugPatterns = "debug=true","trace=true","verbose=true","loglevel=debug","loglevel=trace"
$DebugFiles    = Get-ChildItem -Recurse -Include *.config, *.xml, *.json, *.ini, *.properties -ErrorAction SilentlyContinue

$DebugHits = @()

foreach ($file in $DebugFiles) {
    foreach ($pattern in $DebugPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue
        if ($res) { $DebugHits += $res }
    }
}

if ($DebugHits.Count -gt 0) {
    $DebugHits | Out-File $DebugOut
    Write-Host "Debug/verbose settings detected (check if enabled in production)." -ForegroundColor Yellow
} else {
    "No obvious debug/verbose flags detected." | Out-File $DebugOut
    Write-Host "No debug flags detected." -ForegroundColor Green
}
#  ================================
# 16. Temp/AppData Usage Scan (Safe & Fixed)
# ================================
$TempUsageOut = Join-Path $OutDir "TempUsage.txt"

# Use escaped backslashes + SimpleMatch to avoid regex errors
$TempPatterns = @(
    "%TEMP%",
    "C:\\Temp",
    "AppData\\Local\\Temp",
    "AppData\\Roaming",
    "%APPDATA%",
    "%LOCALAPPDATA%"
)

$TempTargets = Get-ChildItem -Recurse -Include *.dll, *.exe, *.config, *.xml, *.json, *.ini, *.txt -ErrorAction SilentlyContinue

$TempHits = @()

foreach ($file in $TempTargets) {
    foreach ($pattern in $TempPatterns) {
        $res = Select-String -Path $file.FullName -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
        if ($res) { $TempHits += $res }
    }
}

if ($TempHits.Count -gt 0) {
    $TempHits | Out-File $TempUsageOut
    Write-Host "Temp/AppData usage references detected (review for sensitive data handling)." -ForegroundColor Yellow
} else {
    "No explicit Temp/AppData usage patterns detected." | Out-File $TempUsageOut
    Write-Host "No Temp/AppData usage patterns detected." -ForegroundColor Green
}

# ================================
# 17. Vulnerability Summary (Safe & Fixed)
# ================================
$Summary = Join-Path $OutDir "VulnerabilitySummary.txt"
$Findings = @()

Write-Host "`nGenerating vulnerability summary..." -ForegroundColor Cyan

# Safe helper function
function Safe-HasContent {
    param($path)

    if (Test-Path $path) {
        $content = Get-Content $path -ErrorAction SilentlyContinue
        return ($content.Count -gt 0)
    }
    return $false
}

# 1. Unsigned or invalid signatures
$SigData = Import-Csv $SignatureReport
foreach ($item in $SigData) {
    if ($item.Status -ne "Valid") {
        $Findings += "[HIGH] Invalid or unsigned binary: $($item.FileName) ($($item.Status))"
    }
}

# 2. Weak crypto
if (Safe-HasContent $CryptoOut) {
    $Findings += "[MEDIUM] Weak cryptographic algorithms detected (MD5/SHA1/DES/RC4)"
}

# 3. Sensitive strings
if (Safe-HasContent $InterestingOut) {
    $Findings += "[MEDIUM] Sensitive or interesting strings found in binaries"
}

# 4. Sensitive config data
if (Safe-HasContent $ConfigOut) {
    $Findings += "[MEDIUM] Sensitive data found in configuration files"
}

# 5. Extended config secrets
if (Safe-HasContent $ConfigExtendedOut) {
    $Findings += "[MEDIUM] Secrets or credentials found in extended config files"
}

# 6. Sensitive log data
if (Safe-HasContent $LogOut) {
    $Findings += "[LOW] Sensitive information found in log files"
}

# 7. Writable application directory
$acl = Get-Acl $BasePath
$acl.Access | ForEach-Object {
    if ($_.FileSystemRights -match "Write" -and $_.IdentityReference -match "Users|Everyone|Authenticated Users") {
        $Findings += "[HIGH] Application directory is writable by non-admin users"
    }
}

# 8. Writable subdirectories
if (Safe-HasContent $WritableDirsOut) {
    $Findings += "[HIGH] Writable subdirectories detected (DLL hijacking risk)"
}

# 9. Registry permissions
if (Safe-HasContent $RegOut) {
    $Findings += "[MEDIUM] Registry key permissions may allow tampering"
}

# 10. Insecure protocol usage
if (Safe-HasContent $InsecureProtoOut) {
    $Findings += "[MEDIUM] Insecure protocol references found (HTTP/FTP/Telnet/LDAP)"
}

# 11. Embedded private keys
if (Safe-HasContent $PrivateKeyOut) {
    $Findings += "[HIGH] Embedded private key material detected"
}

# 12. Connection strings
if (Safe-HasContent $ConnStrOut) {
    $Findings += "[MEDIUM] Hardcoded connection strings detected"
}

# 13. Debug/verbose mode
if (Safe-HasContent $DebugOut) {
    $Findings += "[LOW] Debug/verbose logging flags detected (review for production)"
}

# 14. Temp/AppData usage
if (Safe-HasContent $TempUsageOut) {
    $Findings += "[LOW] Temp/AppData usage detected (review for sensitive data exposure)"
}

# 15. DLL load anomalies
if ($DLLReport -and (Test-Path $DLLReport)) {
    $dlls = Get-Content $DLLReport
    foreach ($dll in $dlls) {
        if ($dll -match "C:\\Users|Temp|AppData") {
            $Findings += "[HIGH] DLL loaded from user-writable directory: $dll"
        }
    }
}

# Save summary
if ($Findings.Count -eq 0) {
    "No obvious misconfigurations detected." | Out-File $Summary
} else {
    $Findings | Out-File $Summary
}

Write-Host "VulnerabilitySummary.txt created" -ForegroundColor Green

```
