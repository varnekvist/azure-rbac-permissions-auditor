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
