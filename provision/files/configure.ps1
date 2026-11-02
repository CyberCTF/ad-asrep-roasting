# Runs on the DC after it is promoted. Idempotent: safe to re-run.
#   * staff decoys  : pre-auth ON, one strong password (never exposed; they can't be roasted)
#   * svc-scanner   : pre-auth DISABLED (DONT_REQ_PREAUTH), weak wordlist-crackable password
#   * imaging share : only svc-scanner (and admins) may read; holds the flag
#   * the flag      : from the sensitive input at C:\ctf\flag.txt, dev fallback otherwise
$ErrorActionPreference = "Stop"

$realm      = "LAKESIDE.LAB"
$netbios    = "LAKESIDE"
$scanner    = "svc-scanner"
$scannerPw  = ConvertTo-SecureString "Scanner2021" -AsPlainText -Force
$staffPw    = ConvertTo-SecureString "St@ffLakeside#2024!" -AsPlainText -Force
$staff      = @("j.okoro", "a.mensah", "r.kaplan", "d.ferreira", "l.nguyen")
$shareDir   = "C:\Shares\imaging"
$flagSrc    = "C:\ctf\flag.txt"
$devFlag    = "FLAG{dev-asrep-lakeside}"

# Active Directory Web Services can lag the reboot: wait for the directory to answer.
Import-Module ActiveDirectory
for ($i = 0; $i -lt 60; $i++) {
    try { Get-ADDomain -ErrorAction Stop | Out-Null; break }
    catch { Start-Sleep -Seconds 5 }
}
Get-ADDomain | Out-Null   # throws if still not ready, failing the task

function Ensure-User($sam, $pw, $desc) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $sam -SamAccountName $sam -AccountPassword $pw -Enabled $true `
            -PasswordNeverExpires $true -UserPrincipalName "$sam@$realm" -Description $desc
    }
}

# --- ordinary staff: pre-auth ON, strong password (decoys in the username list) ---
foreach ($u in $staff) { Ensure-User $u $staffPw "Lakeside staff" }

# --- the roastable account: pre-auth DISABLED, weak password ---
Ensure-User $scanner $scannerPw "Legacy document-scanner service account"
Set-ADAccountControl -Identity $scanner -DoesNotRequirePreAuth $true

# --- the imaging share: only svc-scanner (and admins) may read ---
New-Item -ItemType Directory -Force $shareDir | Out-Null
$acl = Get-Acl $shareDir
$acl.SetAccessRuleProtection($true, $false)   # drop inherited rules; keep only what we add
$inherit = "ContainerInherit,ObjectInherit"
foreach ($id in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators")) {
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $id, "FullControl", $inherit, "None", "Allow")))
}
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "$netbios\$scanner", "ReadAndExecute", $inherit, "None", "Allow")))
Set-Acl $shareDir $acl

if (-not (Get-SmbShare -Name imaging -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name imaging -Path $shareDir -ReadAccess "$netbios\$scanner" | Out-Null
}

# --- plant the flag: the sensitive input at C:\ctf\flag.txt when non-empty, dev fallback in dev
# (the input lands empty). Written by content so it inherits the share's ACL (svc-scanner read). ---
$flagDst = Join-Path $shareDir "flag.txt"
if ((Test-Path $flagSrc) -and ((Get-Item $flagSrc).Length -gt 0)) {
    $flag = [IO.File]::ReadAllText($flagSrc)
} else {
    $flag = $devFlag
}
[IO.File]::WriteAllText($flagDst, $flag)

Write-Output "LAKESIDE.LAB ready: svc-scanner pre-auth disabled, imaging share planted."
