# Prepare the existing per-user installation folder for PQ custody beneath it.
param([switch]$CheckOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$path = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'age-plugin-tpm-wsl'
$item = Get-Item -LiteralPath $path -Force
if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Ordinary per-user installation directory required'
}
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $path
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -cne $user.Value) {
    throw 'Installation directory must already belong to the current Windows user'
}
if (-not $CheckOnly) {
    $replacement = New-Object System.Security.AccessControl.DirectorySecurity
    $replacement.SetSecurityDescriptorSddlForm(('O:' + $user.Value + 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;' + $user.Value + ')'))
    Set-Acl -LiteralPath $path -AclObject $replacement
    $acl = Get-Acl -LiteralPath $path
}
$rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
if (-not $acl.AreAccessRulesProtected -or $rules.Count -ne 2) {
    throw 'Installation directory needs the protected current-user/SYSTEM custody ACL'
}
$principals = @()
foreach ($rule in $rules) {
    if ($rule.IsInherited -or $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) -or
        $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
        throw 'Installation directory ACL differs from the custody contract'
    }
    $principals += $rule.IdentityReference.Value
}
if (($principals -cnotcontains $user.Value) -or ($principals -cnotcontains 'S-1-5-18')) {
    throw 'Installation directory ACL must grant only the current user and SYSTEM'
}
[Console]::Out.WriteLine('Windows installation directory custody ACL verified.')
