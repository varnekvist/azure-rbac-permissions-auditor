<#
.SYNOPSIS
  Audits Azure RBAC **and** Azure AD PIM (eligible + active) role assignments at a subscription scope
  and all child scopes (resource groups/resources) using Az cmdlets. Expands **group** principals to
  their **member users** via Microsoft Graph and outputs per-user rows. Flags users who are **Guests**
  or (in group-less mode) **not cloud-only**; when ApprovedAdminGroupIds are supplied, flags users who
  are not (**cloud-only AND** members of an approved admin group). Supports scanning **all** subscriptions
  or a **single** subscription via -Subscription. Outputs to **CSV or XLSX** (select via -OutputFormat).
  CSVs/XLSX include an **Eligible** column indicating PIM eligibility; an optional combined file can also
  be produced. Includes retry/backoff for throttling.

.DESCRIPTION
  - Connects to Azure (Az) and Microsoft Graph (Users/Groups) with least-privilege scopes (User.Read.All, GroupMember.Read.All).
  - Collects *active RBAC* role assignments and *PIM* (eligible + active schedules + active instances) at the subscription and below.
  - Normalizes PIM records so group-based assignments expand to users via transitive membership.
  - Policy:
      * Group-less (default): flag Guest users or users that are not cloud-only (synced users).
      * With -ApprovedAdminGroupIds: flag users who are NOT (cloud-only AND members of any approved admin group).
  - Outputs one file per subscription (CSV or XLSX); optionally produces a combined file.
  - Adds an `Eligible` boolean column (true for PIM Eligible; false for RBAC and PIM-active).

.PARAMETER Subscription
  Optional. Subscription **Id (GUID)** or **Name**. When provided, scans only this subscription.
  If omitted, scans **all** subscriptions you can access in the current tenant/context.

.PARAMETER Tenant
  **Mandatory.** Azure AD tenant **Id (GUID)** or verified domain (e.g., contoso.onmicrosoft.com).
  Used for Az and Graph connections.

.PARAMETER ApprovedAdminGroupIds
  Optional array of **group object Ids**. When supplied, tightens the policy to only allow users who are
  **cloud-only AND** members of **any** of these groups. Anyone else is flagged. If omitted, the “group-less”
  policy applies (flag Guest or not-cloud-only).

.PARAMETER OutDir
  Directory for **per-subscription** outputs. The folder is created if it doesn’t exist.
  Default: `.\\rbac_findings`

.PARAMETER CombinedCsv
  Optional **base path** for the combined output. If `-OutputFormat Csv`, a CSV is written here.
  If `-OutputFormat Xlsx`, the same base path is used but with a **.xlsx** extension.

.PARAMETER OutputFormat
  Select output format for per-subscription files (and combined, if specified).
  One of: `Csv` (default) or `Xlsx`. `Xlsx` requires the **ImportExcel** module.

.PARAMETER MaxRetry
  Maximum retry attempts for throttled/transient failures (applies to Az and Graph calls).
  Default: `6`.

.PARAMETER BaseDelaySeconds
  Base delay (in seconds) used for exponential backoff between retries.
  Default: `2`.

.PARAMETER ExcelFriendly
  **Switch.** Only applies to CSV. When present, CSV export uses your **culture delimiter**
  (e.g., `;` in many EU locales) to improve Excel opening behavior. Without it, a comma delimiter is used.

.PARAMETER IncludeClassicAdministrators
  **Switch.** When present, includes **classic administrators** in role assignment enumeration (if supported by your Az version).
  Use when you also want Owner/Co-Admin style classic entries considered.

.PARAMETER TestMode
  **Switch.** When present, **flags every user** (ignores normal policy). Helpful to validate the pipeline
  and confirm group expansion/shape during testing.

.PREREQS
  - Az.Accounts, Az.Resources
  - Microsoft.Graph (v2)
  - Consent: User.Read.All,GroupMember.Read.All
  - For `-OutputFormat Xlsx`: ImportExcel module (`Install-Module ImportExcel -Scope CurrentUser`)

.EXAMPLE
  .\AzureResourcePermissions.ps1 -OutDir .\rbac_findings -OutputFormat Csv -ExcelFriendly -Verbose

.EXAMPLE
  .\AzureResourcePermissions.ps1 -OutDir .\rbac_findings -CombinedCsv .\rbac_all.csv -OutputFormat Xlsx -Verbose

.EXAMPLE
  .\AzureResourcePermissions.ps1 -ApprovedAdminGroupIds "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" -OutDir .\rbac_findings -OutputFormat Xlsx

.EXAMPLE
  .\AzureResourcePermissions.ps1 -Tenant "<tenantId-or-domain>" -Subscription "<subId-or-name>" -OutDir ".\rbac_findings" -OutputFormat Csv -Verbose
#>


[CmdletBinding()]
param(
  [Alias('Subcription')]
  [string] $Subscription,                        # optional: ID (GUID) or Name; if omitted => all subscriptions
  [Parameter(Mandatory=$true, HelpMessage='Enter tenant ID (GUID) or verified domain, e.g. contoso.onmicrosoft.com')]
  [ValidateNotNullOrEmpty()]
  [string] $Tenant,  
  [string[]] $ApprovedAdminGroupIds = @(),       # optional; if omitted => group-less policy
  [string]   $OutDir = ".\rbac_findings",        # per-subscription outputs go here
  [string]   $CombinedCsv = $null,               # optional combined base path (extension auto-adjusts to OutputFormat)
  [ValidateSet('Csv','Xlsx')]
  [string]   $OutputFormat = 'Csv',
  [int]      $MaxRetry = 6,
  [int]      $BaseDelaySeconds = 2,
  [switch]   $ExcelFriendly,                     # CSV-only: use culture delimiter
  [switch]   $IncludeClassicAdministrators,      # include classic admins if your Az version supports it
  [switch]   $TestMode
)

function Invoke-WithRetry {
  param(
    [Parameter(Mandatory=$true)] [ScriptBlock] $ScriptBlock,
    [int] $MaxRetry = 6,
    [int] $BaseDelaySeconds = 2
  )
  $attempt = 0
  while ($true) {
    try { return & $ScriptBlock }
    catch {
      $attempt++
      $msg  = $_.Exception.Message
      $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
      $retryable = ($code -in 429,500,502,503,504) -or ($msg -match 'throttl|temporar|rate limit|timeout|EAI_AGAIN|connection')
      if ($attempt -ge $MaxRetry -or -not $retryable) { throw }
      $delay = [int]([math]::Pow(2, $attempt - 1) * $BaseDelaySeconds + (Get-Random -Minimum 0 -Maximum $BaseDelaySeconds))
      Write-Verbose "Retry $attempt due to '$msg' (HTTP $code). Sleeping $delay s..."
      Start-Sleep -Seconds $delay
    }
  }
}

#Connections  (lightweight Graph import)
if (-not (Get-Module -ListAvailable -Name Az.Accounts))  { throw "Az.Accounts module not found." }
if (-not (Get-Module -ListAvailable -Name Az.Resources)) { throw "Az.Resources module not found." }
if (-not (Get-AzContext)) {
  Write-Host "Connecting to Azure..." -ForegroundColor Cyan
  Connect-AzAccount -Tenant $Tenant -ErrorAction Stop | Out-Null
}
$script:CurrentTenantId = try { (Get-AzContext).Tenant.Id } catch { $null }

# Import only the Graph pieces we actually call
$graphMods = @(
  'Microsoft.Graph.Authentication',
  'Microsoft.Graph.Users',
  'Microsoft.Graph.Groups'
)
foreach ($m in $graphMods) {
  if (-not (Get-Module -ListAvailable -Name $m)) {
    throw "Missing $m. Install it with: Install-Module $m -Scope CurrentUser"
  }
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Users          -ErrorAction Stop
Import-Module Microsoft.Graph.Groups         -ErrorAction Stop

try { Select-MgProfile -Name 'v1.0' } catch {}

# Required Graph scopes (least privilege for your script)
$requiredScopes = @('User.Read.All','GroupMember.Read.All')   # add 'Member.Read.Hidden' if you have hidden-membership groups

$needConnect = $true
try {
    $ctx = Get-MgContext
    if ($ctx) {
        $ctxScopes = if ($ctx.Scopes -is [string]) { $ctx.Scopes -split '\s+' } else { @($ctx.Scopes) }
        $missing   = $requiredScopes | Where-Object { $ctxScopes -notcontains $_ }
        if ($missing.Count -eq 0) { $needConnect = $false }
    }
} catch {}

if ($needConnect) {
    Write-Host "Connecting to Microsoft Graph (scopes: $($requiredScopes -join ', '))..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes $requiredScopes -TenantId $Tenant -ErrorAction Stop | Out-Null
    try { Select-MgProfile -Name 'v1.0' } catch {}
}

# User cache
$UserCache = @{}           # userId => user object
# Group members cache
$GroupMembersCache = @{}   # groupId => [userId...]
# Role name cache
$RoleNameCache = @{}

function Get-GraphUserFast {
  param([string] $UserId)
  if ($UserCache.ContainsKey($UserId)) { return $UserCache[$UserId] }
  $u = Invoke-WithRetry -ScriptBlock {
    Get-MgUser -UserId $UserId -Property "id,displayName,userPrincipalName,userType,onPremisesSyncEnabled,accountEnabled" -ErrorAction Stop
  }
  $obj = [pscustomobject]@{
    Id                     = $u.Id
    DisplayName            = $u.DisplayName
    UPN                    = $u.UserPrincipalName
    UserType               = $u.UserType
    OnPremisesSyncEnabled  = $u.OnPremisesSyncEnabled
    AccountEnabled         = $u.AccountEnabled
  }
  $UserCache[$UserId] = $obj
  return $obj
}

function Get-GroupTransitiveUserIds {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $GroupId
  )

  # ensure cache exists & guard against whitespace
  if (-not $script:GroupMembersCache) { $script:GroupMembersCache = @{} }
  if ([string]::IsNullOrWhiteSpace($GroupId)) {
    Write-Verbose "Get-GroupTransitiveUserIds: GroupId is null/empty; returning empty set."
    return @()
  }

  if ($script:GroupMembersCache.ContainsKey($GroupId)) {
    return $script:GroupMembersCache[$GroupId]
  }

  $users = @()
  try {
    $users = Invoke-WithRetry -ScriptBlock {
      Get-MgGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop
    }
  } catch {
    Write-Verbose ("Get-MgGroupTransitiveMember failed for {0}: {1}" -f $GroupId, $_.Exception.Message)
    $users = @()
  }

  # If you only want users, keep a robust filter; otherwise this returns any directory object IDs
  $ids = @(
    $users |
      Where-Object {
        $_ -and (
          $_.PSObject.TypeNames -contains 'Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser' -or
          ( $_.PSObject.Properties.Name -contains 'AdditionalProperties' -and
            $_.AdditionalProperties.ContainsKey('@odata.type') -and
            $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.user') -or
          ($_.PSObject.Properties.Name -contains 'UserPrincipalName')
        )
      } |
      ForEach-Object { $_.Id }
  ) | Sort-Object -Unique

  $script:GroupMembersCache[$GroupId] = $ids
  Write-Verbose ("[Group] {0}: collected {1} user IDs" -f $GroupId, $ids.Count)
    if ($ids.Count -gt 0) {
      Write-Verbose ("Sample: {0}" -f (($ids | Select-Object -First 10) -join ', '))
    }
  return $ids
}


function Resolve-RoleName {
  param(
    [string] $RoleDefinitionId,
    [string] $RoleDefinitionName
  )
  if ($RoleDefinitionName) { return $RoleDefinitionName }
  if (-not $RoleDefinitionId) { return $null }

  if ($RoleNameCache.ContainsKey($RoleDefinitionId)) { return $RoleNameCache[$RoleDefinitionId] }

  try {
    $def  = Invoke-WithRetry -ScriptBlock { Get-AzRoleDefinition -Id $RoleDefinitionId -ErrorAction Stop }
    $name = if ($def.RoleName) { $def.RoleName } else { $RoleDefinitionId }
    $RoleNameCache[$RoleDefinitionId] = $name
    return $name
  } catch {
    return $RoleDefinitionId
  }
}

function Test-IsCloudOnly { param($User) return -not [bool]$User.OnPremisesSyncEnabled }

function Test-IsApprovedAdmin {
  param($User)
  if (-not $ApprovedAdminGroupIds -or $ApprovedAdminGroupIds.Count -eq 0) { return $true }
  foreach ($gid in $ApprovedAdminGroupIds) {
    $members = Get-GroupTransitiveUserIds -GroupId $gid
    if ($members -contains $User.Id) { return $true }
  }
  return $false
}

function Test-ShouldFlagUser {
  param($User)
  if ($TestMode) { return $true }
  if ($User.UserType -eq 'Guest') { return $true }
  if ($User.UserType -eq 'Guest') { return $true }
  $isCloudOnly = Test-IsCloudOnly $User
  if (-not $ApprovedAdminGroupIds -or $ApprovedAdminGroupIds.Count -eq 0) { return -not $isCloudOnly }
  $isApprovedAdmin = Test-IsApprovedAdmin $User
  return -not ($isCloudOnly -and $isApprovedAdmin)
}

# File helpers
function New-SafeFileName {
  param([string]$Name)
  $invalids = [System.IO.Path]::GetInvalidFileNameChars() -join ''
  return ($Name -replace "[$invalids]", '_').Trim()
}

function Ensure-Dir {
  param([string]$Path)
  $dir = [System.IO.Path]::GetDirectoryName($Path)
  if (-not [string]::IsNullOrEmpty($dir) -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}

function Export-FindingsCsv {
  param(
    [Parameter(Mandatory=$true)] [object[]] $Data,
    [Parameter(Mandatory=$true)] [string]   $Path,
    [switch] $ExcelFriendly
  )
  Ensure-Dir -Path $Path
  if ($ExcelFriendly) {
    $Data | Export-Csv -NoTypeInformation -Path $Path -UseCulture -Encoding UTF8
  } else {
    $Data | Export-Csv -NoTypeInformation -Path $Path -Encoding UTF8
  }
}

function Export-FindingsXlsx {
  param(
    [Parameter(Mandatory=$true)] [object[]] $Data,
    [Parameter(Mandatory=$true)] [string]   $Path,
    [string] $WorksheetName = 'Findings'
  )
  if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    throw "The ImportExcel module is required for -OutputFormat Xlsx. Install it with: Install-Module ImportExcel -Scope CurrentUser"
  }
  Import-Module ImportExcel -ErrorAction Stop
  Ensure-Dir -Path $Path
  # Overwrite/clear the sheet each time to keep a fresh export
  $Data | Export-Excel -Path $Path -WorksheetName $WorksheetName -AutoSize -AutoFilter -TableStyle Medium12 -FreezeTopRow
}

# -------- Resolve which subscriptions to scan (all vs one) --------
function Resolve-TargetSubscriptions {
  param([string] $SubscriptionFilter)

  if ([string]::IsNullOrWhiteSpace($SubscriptionFilter)) {
    $all = Get-AzSubscription -ErrorAction Stop
    Write-Verbose ("Scanning all subscriptions ({0})" -f ($all | Measure-Object).Count)
    return $all
  }

  if ($SubscriptionFilter -match '^[0-9a-fA-F-]{36}$') {
    try {
      $sub = Get-AzSubscription -SubscriptionId $SubscriptionFilter -ErrorAction Stop
      Write-Verbose ("Scanning single subscription by Id: {0} [{1}]" -f $sub.Name, $sub.Id)
      return @($sub)
    } catch {
      throw "Subscription with Id '$SubscriptionFilter' not found."
    }
  } else {
    try {
      $sub = Get-AzSubscription -SubscriptionName $SubscriptionFilter -ErrorAction Stop
      Write-Verbose ("Scanning single subscription by Name: {0} [{1}]" -f $sub.Name, $sub.Id)
      return @($sub)
    } catch {
      $candidates = Get-AzSubscription -ErrorAction Stop | Where-Object { $_.Name -eq $SubscriptionFilter }
      if ($candidates) {
        $sub = $candidates | Select-Object -First 1
        Write-Verbose ("Scanning single subscription by Name: {0} [{1}]" -f $sub.Name, $sub.Id)
        return @($sub)
      } else {
        throw "Subscription with Name '$SubscriptionFilter' not found."
      }
    }
  }
}

function Get-Prop {
  param($Obj,[string[]]$Names)
  foreach ($n in $Names) {
    if ($Obj -and $Obj.PSObject.Properties.Name -contains $n) {
      $v = $Obj.$n
      if ($null -ne $v -and "$v" -ne '') { return $v }
    }
  }
  return $null
}

function Normalize-PimRecord {
  param($Rec)

  $oid    = Get-Prop $Rec @('ObjectId','PrincipalId','PrincipalObjectId','SubjectId')
  $otype0 = Get-Prop $Rec @('ObjectType','PrincipalType','SubjectType')
  $ptype  = if ($otype0) { "$otype0".ToLowerInvariant() } else { '' }

  $rdid   = Get-Prop $Rec @('RoleDefinitionId')
  if (-not $rdid -and $Rec.PSObject.Properties.Name -contains 'RoleDefinition' -and $Rec.RoleDefinition) {
    if ($Rec.RoleDefinition.PSObject.Properties.Name -contains 'Id') { $rdid = $Rec.RoleDefinition.Id }
  }
  $rdnm   = Get-Prop $Rec @('RoleDefinitionName')
  if (-not $rdnm -and $Rec.PSObject.Properties.Name -contains 'RoleDefinition' -and $Rec.RoleDefinition) {
    if ($Rec.RoleDefinition.PSObject.Properties.Name -contains 'Name') { $rdnm = $Rec.RoleDefinition.Name }
  }

  $scp    = Get-Prop $Rec @('Scope')
  if (-not $scp -and $Rec.PSObject.Properties.Name -contains 'Properties' -and $Rec.Properties) {
    if ($Rec.Properties.PSObject.Properties.Name -contains 'Scope') { $scp = $Rec.Properties.Scope }
  }

  $dsp    = Get-Prop $Rec @('DisplayName','PrincipalDisplayName')

  $pTenantId = Get-Prop $Rec @('PrincipalTenantId','LinkedEligibleChildTenantId','LinkedScopeTenantId')

  $otype = switch ($true) {
    { $ptype -match 'user' }              { 'User'; break }
    { $ptype -match 'serviceprincipal' }  { 'ServicePrincipal'; break }
    { $ptype -match 'group' }             {
      if ($pTenantId -and $script:CurrentTenantId -and ($pTenantId -ne $script:CurrentTenantId)) { 'ForeignGroup' }
      else { 
        try {
          if ($oid) { Get-MgGroup -GroupId $oid -ErrorAction Stop | Out-Null; 'Group' }
          else      { 'Group' }
        } catch { 'ForeignGroup' }
      }
      break
    }
    default { $otype0 }
  }

  [pscustomobject]@{
    ObjectId           = $oid
    ObjectType         = $otype
    RoleDefinitionId   = $rdid
    RoleDefinitionName = $rdnm
    Scope              = $scp
    DisplayName        = $dsp
  }
}

$subs = Resolve-TargetSubscriptions -SubscriptionFilter $Subscription
$allFindings = New-Object System.Collections.Generic.List[object]

foreach ($sub in $subs) {
  Write-Host "Processing subscription $($sub.Name) [$($sub.Id)]..." -ForegroundColor Yellow
  Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null

  $perSubFindings = New-Object System.Collections.Generic.List[object]
  $includeClassic = $IncludeClassicAdministrators.IsPresent

  $scope = "/subscriptions/$($sub.Id)"
  $assignments = @()

  $rbac = Invoke-WithRetry -ScriptBlock {
    if ($includeClassic) {
      try { Get-AzRoleAssignment -ErrorAction Stop -IncludeClassicAdministrators }
      catch { Get-AzRoleAssignment -ErrorAction Stop }
    } else {
      Get-AzRoleAssignment -ErrorAction Stop
    }
  }
  if ($rbac) { $assignments += ($rbac | ForEach-Object { $_ | Add-Member NoteProperty Eligible $false -Force -PassThru }) }

  try {
    $elig = Invoke-WithRetry -ScriptBlock {
      Get-AzRoleEligibilitySchedule -Scope $scope -ErrorAction Stop
    }
    foreach ($e in @($elig)) {
      $n = Normalize-PimRecord $e
      $null = $n | Add-Member NoteProperty Eligible $true -Force
      $assignments += $n
    }
  } catch { Write-Verbose ("PIM Eligible not available or failed: {0}" -f $_.Exception.Message) }

  try {
    $inst = Invoke-WithRetry -ScriptBlock {
      Get-AzRoleEligibilityScheduleInstance -Scope $scope -ErrorAction Stop
    }
    foreach ($i in @($inst)) {
      $n = Normalize-PimRecord $i
      $null = $n | Add-Member NoteProperty Eligible $false -Force
      $assignments += $n
    }
  } catch { Write-Verbose ("PIM Instances not available or failed: {0}" -f $_.Exception.Message) }

  try {
    $sch = Invoke-WithRetry -ScriptBlock {
      Get-AzRoleAssignmentSchedule -Scope $scope -ErrorAction Stop
    }
    foreach ($s in @($sch)) {
      $n = Normalize-PimRecord $s
      $null = $n | Add-Member NoteProperty Eligible $false -Force
      $assignments += $n
    }
  } catch { Write-Verbose ("PIM Schedules not available or failed: {0}" -f $_.Exception.Message) }

  foreach ($ra in ($assignments | Where-Object { $_ })) {
    $principalId   = $ra.ObjectId
    $principalType = $ra.ObjectType
    $roleName      = Resolve-RoleName -RoleDefinitionId $ra.RoleDefinitionId -RoleDefinitionName $ra.RoleDefinitionName
    if (-not $roleName) { $roleName = $ra.RoleDefinitionId }
    $scope         = $ra.Scope
    $isEligible    = $false; if ($ra.PSObject.Properties.Name -contains 'Eligible') { $isEligible = [bool]$ra.Eligible }

    if ($principalType -in @('Group','ForeignGroup')) {
      Write-Verbose ("PIM/RA GROUP: Type={0} Id={1} Scope={2} Role={3}" -f $principalType, $principalId, $scope, $roleName)
    }

    switch ($principalType) {
      'User' {
        try {
          $u = Get-GraphUserFast -UserId $principalId
          if (Test-ShouldFlagUser $u) {
            $perSubFindings.Add([pscustomobject]@{
              SubscriptionId = $sub.Id
              Subscription   = $sub.Name
              Scope          = $scope
              Role           = $roleName
              AssignmentType = 'Direct'
              ViaGroupId     = $null
              UserId         = $u.Id
              UPN            = $u.UPN
              DisplayName    = $u.DisplayName
              UserType       = $u.UserType
              CloudOnly      = [bool](Test-IsCloudOnly $u)
              AccountEnabled = $u.AccountEnabled
              Eligible       = $isEligible
            })
          }
        } catch {
          Write-Warning ("Failed to resolve user {0}: {1}" -f $principalId, $_.Exception.Message)
        }
      }
      'Group' {
        try {
          Write-Verbose "$principalId written to"
          $memberIds = Get-GroupTransitiveUserIds -GroupId $principalId
          foreach ($uid in $memberIds) {
            try {
              $u = Get-GraphUserFast -UserId $uid
              if (Test-ShouldFlagUser $u) {
                $perSubFindings.Add([pscustomobject]@{
                  SubscriptionId = $sub.Id
                  Subscription   = $sub.Name
                  Scope          = $scope
                  Role           = $roleName
                  AssignmentType = 'ViaGroup'
                  ViaGroupId     = $principalId
                  UserId         = $u.Id
                  UPN            = $u.UPN
                  DisplayName    = $u.DisplayName
                  UserType       = $u.UserType
                  CloudOnly      = [bool](Test-IsCloudOnly $u)
                  AccountEnabled = $u.AccountEnabled
                  Eligible       = $isEligible
                })
              }
            } catch {
              Write-Warning ("Failed to resolve group member {0}: {1}" -f $uid, $_.Exception.Message)
            }
          }
        } catch {
          Write-Warning ("Failed to expand group {0}: {1}" -f $principalId, $_.Exception.Message)
        }
      }
      'ForeignGroup' {
        try {
          $memberIds = Get-GroupTransitiveUserIds -GroupId $principalId
          foreach ($uid in $memberIds) {
            try {
              $u = Get-GraphUserFast -UserId $uid
              if (Test-ShouldFlagUser $u) {
                $perSubFindings.Add([pscustomobject]@{
                  SubscriptionId = $sub.Id
                  Subscription   = $sub.Name
                  Scope          = $scope
                  Role           = $roleName
                  AssignmentType = 'ViaGroup'
                  ViaGroupId     = $principalId
                  UserId         = $u.Id
                  UPN            = $u.UPN
                  DisplayName    = $u.DisplayName
                  UserType       = $u.UserType
                  CloudOnly      = [bool](Test-IsCloudOnly $u)
                  AccountEnabled = $u.AccountEnabled
                  Eligible       = $isEligible
                })
              }
            } catch {
              Write-Warning ("Failed to resolve foreign group member {0}: {1}" -f $uid, $_.Exception.Message)
            }
          }
        } catch {
          Write-Warning ("Failed to expand foreign group {0}: {1}" -f $principalId, $_.Exception.Message)
        }
      }
      Default { continue }
    }
  }

  # Write per-subscription output
  $ext = if ($OutputFormat -eq 'Xlsx') { '.xlsx' } else { '.csv' }
  $safeSubName = New-SafeFileName -Name $sub.Name
  $perSubPath = Join-Path -Path $OutDir -ChildPath ("{0} {1}{2}" -f $safeSubName, $sub.Id, $ext)

  if ($perSubFindings.Count -gt 0) {
    $sorted = $perSubFindings | Sort-Object Scope, Role, UPN
    if ($OutputFormat -eq 'Xlsx') {
      Export-FindingsXlsx -Data $sorted -Path $perSubPath -WorksheetName 'Findings'
    } else {
      Export-FindingsCsv -Data $sorted -Path $perSubPath -ExcelFriendly:$ExcelFriendly
    }
    Write-Host ("Wrote {0} finding(s) to {1}" -f $sorted.Count, $perSubPath) -ForegroundColor Green
    [void]$allFindings.AddRange(@($sorted))
  } else {
    # write a single header row so the file is still useful
    $headers = [pscustomobject]@{
      SubscriptionId = $sub.Id; Subscription = $sub.Name; Scope=''; Role=''
      AssignmentType=''; ViaGroupId=''; UserId=''; UPN=''; DisplayName=''
      UserType=''; CloudOnly=$null; AccountEnabled=$null; Eligible=$null
    } | Select-Object *
    if ($OutputFormat -eq 'Xlsx') {
      Export-FindingsXlsx -Data @($headers) -Path $perSubPath -WorksheetName 'Findings'
    } else {
      Export-FindingsCsv  -Data @($headers) -Path $perSubPath -ExcelFriendly:$ExcelFriendly
    }
    Write-Host ("No unwanted assignments found in {0}. Wrote empty template to {1}" -f $sub.Name, $perSubPath) -ForegroundColor Yellow
  }
}

if ($CombinedCsv -and $allFindings.Count -gt 0) {
  $sortedAll = $allFindings | Sort-Object Subscription, Scope, Role, UPN
  $combinedPath = if ($OutputFormat -eq 'Xlsx') {
    [System.IO.Path]::ChangeExtension($CombinedCsv, '.xlsx')
  } else {
    $CombinedCsv
  }

  if ($OutputFormat -eq 'Xlsx') {
    Export-FindingsXlsx -Data $sortedAll -Path $combinedPath -WorksheetName 'AllSubscriptions'
  } else {
    Export-FindingsCsv  -Data $sortedAll -Path $combinedPath -ExcelFriendly:$ExcelFriendly
  }

  Write-Host ("Combined {0} written to {1} ({2} rows)" -f $OutputFormat, $combinedPath, $sortedAll.Count) -ForegroundColor Cyan

  $summary = $sortedAll |
    Group-Object Subscription, Role, AssignmentType |
    Select-Object `
      @{N='Subscription';E={$_.Name.Split(',')[0].Trim()}},
      @{N='Role';E={$_.Name.Split(',')[1].Trim()}},
      @{N='AssignmentType';E={$_.Name.Split(',')[2].Trim()}},
      @{N='Count';E={$_.Count}} |
    Sort-Object Subscription, Role, AssignmentType

  Write-Host "`nFlagged assignments by subscription/role/type:" -ForegroundColor Cyan
  $summary | Format-Table -AutoSize
}