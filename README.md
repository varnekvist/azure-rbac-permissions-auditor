# Azure RBAC & PIM Auditor (PowerShell)

Audit Azure **RBAC** and **PIM** assignments across a subscription (and all child scopes), expand **group** memberships to **users**, and flag **risky access** — with exports to **CSV or XLSX**.

> **What it flags (policy)**
>
> - **Default (group-less):** Users who are **Guests** or **not cloud-only** (synced from on-prem).
> - **With `-ApprovedAdminGroupIds`:** Users who are **not** (**cloud-only AND** members of an approved admin group).
> - **`-TestMode`:** Flags **everyone** (great for pipeline validation).

---

## Features

- Enumerates **active RBAC** role assignments **and** **PIM**:
  - Eligible role assignments
  - Active assignment schedules
  - Active schedule instances (on-demand activations)
- Expands **group principals** (including nested) to **member users** via Microsoft Graph.
- Scan **all** subscriptions or a **single** subscription (`-Subscription` by Id or Name).
- Built-in **retry/backoff** to handle throttling (Az & Graph).
- Export **per-subscription** and optional **combined** results:
  - **CSV** (default; `-ExcelFriendly` supports `;` delimiter locales)
  - **XLSX** (`-OutputFormat Xlsx`, via ImportExcel)
- Output includes **`Eligible`** column (true = PIM eligible, false = active RBAC/PIM).

---

## Quick Start

All subscriptions, CSV per subscription, EU-friendly delimiter, verbose tracing:

```powershell
.\Get-AzRbacPimFindings.ps1 -Tenant "<tenantId-or-domain>" -OutDir .\rbac_findings -ExcelFriendly -Verbose
```

Single subscription by **Id**:

```powershell
.\Get-AzRbacPimFindings.ps1 -Tenant "<tenant>" -Subscription "00000000-0000-0000-0000-000000000000" -OutDir .\rbac_findings
```

Single subscription by **Name**:

```powershell
.\Get-AzRbacPimFindings.ps1 -Tenant "<tenant>" -Subscription "Production Subscription" -OutDir .\rbac_findings
```

**XLSX** outputs:

```powershell
.\Get-AzRbacPimFindings.ps1 -Tenant "<tenant>" -OutDir .\rbac_findings -OutputFormat Xlsx
```

**Combined** file (extension auto-adjusts to chosen format):

```powershell
.\Get-AzRbacPimFindings.ps1 -Tenant "<tenant>" -OutputFormat Xlsx -CombinedCsv .\rbac_all.csv
# -> writes .\rbac_all.xlsx
```

Tighten policy with **approved admin groups**:

```powershell
.\Get-AzRbacPimFindings.ps1 -Tenant "<tenant>" -ApprovedAdminGroupIds "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
```

Validation mode (**flag everyone**):

```powershell
.\Get-AzRbacPimFindings.ps1 -Tenant "<tenant>" -TestMode
```

---

## Parameters

| Name                           | Type            | Required | Default            | Description                                                                                                        |
| ------------------------------ | --------------- | -------: | ------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `Tenant`                       | `string`        |  **Yes** | —                  | Tenant Id (GUID) or verified domain (`contoso.onmicrosoft.com`). Used for Az & Graph auth.                         |
| `Subscription`                 | `string`        |       No | —                  | Subscription **Id** or **Name**. If omitted, scans **all** subscriptions you can access.                           |
| `ApprovedAdminGroupIds`        | `string[]`      |       No | `@()`              | Group **object Ids** that define “approved admin” groups; policy becomes **cloud-only AND** in any approved group. |
| `OutDir`                       | `string`        |       No | `.\\rbac_findings` | Folder for **per-subscription** outputs. Created if missing.                                                       |
| `CombinedCsv`                  | `string`        |       No | `null`             | Base path for **combined** output. If `-OutputFormat Xlsx`, extension becomes `.xlsx`.                             |
| `OutputFormat`                 | `Csv` \| `Xlsx` |       No | `Csv`              | Output format. `Xlsx` requires **ImportExcel** module.                                                             |
| `ExcelFriendly`                | `switch`        |       No | `false`            | CSV only: use **culture delimiter** (e.g., `;`) for better Excel import in some locales.                           |
| `IncludeClassicAdministrators` | `switch`        |       No | `false`            | Include **classic administrators** in RBAC enumeration (if supported by your Az version).                          |
| `TestMode`                     | `switch`        |       No | `false`            | Flags **all users** (bypasses policy). Handy for validating export & group expansion.                              |
| `MaxRetry`                     | `int`           |       No | `6`                | Retry count for transient/throttling errors (Az & Graph).                                                          |
| `BaseDelaySeconds`             | `int`           |       No | `2`                | Base delay for exponential backoff between retries.                                                                |

## Requirements

- PowerShell 7+ recommended (Windows PowerShell 5.1 also works)
- Az modules:
  - `Az.Accounts`
  - `Az.Resources`
- Microsoft Graph modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Groups`
- **Graph scopes/consent** (least privilege):
  - `User.Read.All`
  - `GroupMember.Read.All`
  - _(If you have hidden-membership groups, also consent to `Member.Read.Hidden`.)_
- For **XLSX** output:
  - `ImportExcel` module (`Install-Module ImportExcel -Scope CurrentUser`)

---

## Installation

```powershell
# Az
Install-Module Az.Accounts -Scope CurrentUser
Install-Module Az.Resources -Scope CurrentUser

# Microsoft Graph (only the parts we use)
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users          -Scope CurrentUser
Install-Module Microsoft.Graph.Groups         -Scope CurrentUser

# Optional: XLSX export
Install-Module ImportExcel -Scope CurrentUser
```
