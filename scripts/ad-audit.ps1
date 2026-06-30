<#
.SYNOPSIS
    Auditor de permissões de Active Directory / Azure AD (Entra ID).

.DESCRIPTION
    Gera um relatório de compliance identificando:
      • Usuários com permissões excessivas (membros de grupos privilegiados)
      • Contas inativas há X dias (sem logon)
      • Contas com senha que nunca expira / sem pré-autenticação
      • Grupos órfãos (sem membros ou sem owner)
      • Usuários com PasswordNotRequired

    Suporta dois modos:
      -Mode AD     → usa o módulo ActiveDirectory (RSAT) contra um domínio on-premises
      -Mode AzureAD→ usa o módulo Microsoft.Graph contra o Entra ID (cloud)

    Funciona em modo degradado: se o módulo necessário não estiver instalado,
    o script informa claramente e sai sem erro fatal.

.PARAMETER Mode
    'AD' (padrão) ou 'AzureAD'.

.PARAMETER InactiveDays
    Número de dias sem logon para considerar uma conta inativa (padrão: 90).

.PARAMETER OutputPath
    Caminho base dos relatórios (gera .json e .html). Padrão: ./ad-audit-report

.PARAMETER PrivilegedGroups
    Lista de grupos considerados privilegiados.

.EXAMPLE
    .\ad-audit.ps1 -Mode AD -InactiveDays 60 -OutputPath C:\Temp\audit

.EXAMPLE
    .\ad-audit.ps1 -Mode AzureAD -OutputPath .\entra-audit
#>

[CmdletBinding()]
param(
    [ValidateSet('AD', 'AzureAD')]
    [string]$Mode = 'AD',

    [int]$InactiveDays = 90,

    [string]$OutputPath = './ad-audit-report',

    [string[]]$PrivilegedGroups = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins',
        'Administrators', 'Account Operators', 'Backup Operators',
        'Server Operators', 'Print Operators', 'DnsAdmins',
        'Global Administrator', 'Privileged Role Administrator',
        'Security Administrator', 'Exchange Administrator'
    )
)

$ErrorActionPreference = 'Stop'
$findings = [System.Collections.Generic.List[object]]::new()
$cutoff   = (Get-Date).AddDays(-$InactiveDays)

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,   # CRITICAL | HIGH | MEDIUM | LOW
        [string]$Principal,
        [string]$Detail
    )
    $findings.Add([pscustomobject]@{
        Category  = $Category
        Severity  = $Severity
        Principal = $Principal
        Detail    = $Detail
        Timestamp = (Get-Date).ToString('o')
    })
}

# ════════════════════════════════════════════════════════════════════════════
#  Modo AD (on-premises) — módulo ActiveDirectory (RSAT)
# ════════════════════════════════════════════════════════════════════════════
function Invoke-ADAudit {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "Módulo 'ActiveDirectory' (RSAT) não encontrado. Instale com:"
        Write-Warning "  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
        return $false
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "[*] Auditando Active Directory on-premises..." -ForegroundColor Cyan

    # 1) Permissões excessivas: membros de grupos privilegiados
    foreach ($grp in $PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop
            foreach ($m in $members) {
                if ($m.objectClass -eq 'user') {
                    Add-Finding 'Permissão Excessiva' 'HIGH' $m.SamAccountName `
                        "Membro do grupo privilegiado '$grp'"
                }
            }
        } catch {
            Write-Verbose "Grupo '$grp' não encontrado neste domínio."
        }
    }

    # 2) Contas inativas / desabilitadas / senha que nunca expira
    $users = Get-ADUser -Filter * -Properties LastLogonDate, Enabled, PasswordNeverExpires,
                                              PasswordNotRequired, DoesNotRequirePreAuth
    foreach ($u in $users) {
        if ($u.Enabled -and $u.LastLogonDate -and $u.LastLogonDate -lt $cutoff) {
            Add-Finding 'Conta Inativa' 'MEDIUM' $u.SamAccountName `
                "Sem logon desde $($u.LastLogonDate.ToString('yyyy-MM-dd')) (> $InactiveDays dias)"
        }
        if ($u.Enabled -and -not $u.LastLogonDate) {
            Add-Finding 'Conta Inativa' 'LOW' $u.SamAccountName 'Nunca efetuou logon'
        }
        if ($u.PasswordNeverExpires -and $u.Enabled) {
            Add-Finding 'Senha Não Expira' 'MEDIUM' $u.SamAccountName 'PasswordNeverExpires=true'
        }
        if ($u.PasswordNotRequired) {
            Add-Finding 'Senha Não Requerida' 'HIGH' $u.SamAccountName 'PasswordNotRequired=true'
        }
        if ($u.DoesNotRequirePreAuth) {
            Add-Finding 'AS-REP Roasting' 'HIGH' $u.SamAccountName 'Pré-autenticação Kerberos desabilitada'
        }
    }

    # 3) Grupos órfãos (sem membros)
    $groups = Get-ADGroup -Filter * -Properties Members, ManagedBy
    foreach ($g in $groups) {
        if (($g.Members.Count -eq 0)) {
            Add-Finding 'Grupo Órfão' 'LOW' $g.Name 'Grupo sem membros'
        }
        if (-not $g.ManagedBy) {
            Add-Finding 'Grupo Sem Owner' 'LOW' $g.Name 'Grupo sem ManagedBy definido'
        }
    }
    return $true
}

# ════════════════════════════════════════════════════════════════════════════
#  Modo AzureAD / Entra ID — módulo Microsoft.Graph
# ════════════════════════════════════════════════════════════════════════════
function Invoke-AzureADAudit {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Warning "Módulo 'Microsoft.Graph' não encontrado. Instale com:"
        Write-Warning "  Install-Module Microsoft.Graph -Scope CurrentUser"
        return $false
    }
    Import-Module Microsoft.Graph.Users, Microsoft.Graph.Groups,
                  Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
    Connect-MgGraph -Scopes 'User.Read.All', 'Group.Read.All', 'RoleManagement.Read.Directory' | Out-Null
    Write-Host "[*] Auditando Azure AD / Entra ID..." -ForegroundColor Cyan

    # 1) Permissões excessivas: atribuições de roles de diretório privilegiadas
    $roles = Get-MgDirectoryRole -All
    foreach ($role in $roles) {
        if ($PrivilegedGroups -contains $role.DisplayName) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
            foreach ($m in $members) {
                Add-Finding 'Permissão Excessiva' 'HIGH' $m.Id `
                    "Atribuído à role privilegiada '$($role.DisplayName)'"
            }
        }
    }

    # 2) Contas inativas (signInActivity) e desabilitadas
    $users = Get-MgUser -All -Property 'displayName','userPrincipalName','accountEnabled','signInActivity'
    foreach ($u in $users) {
        $last = $u.SignInActivity.LastSignInDateTime
        if ($u.AccountEnabled -and $last -and ([datetime]$last -lt $cutoff)) {
            Add-Finding 'Conta Inativa' 'MEDIUM' $u.UserPrincipalName `
                "Último sign-in em $([datetime]$last | Get-Date -Format 'yyyy-MM-dd') (> $InactiveDays dias)"
        }
        if ($u.AccountEnabled -and -not $last) {
            Add-Finding 'Conta Inativa' 'LOW' $u.UserPrincipalName 'Sem registro de sign-in'
        }
    }

    # 3) Grupos órfãos (sem owners ou sem membros)
    $groups = Get-MgGroup -All
    foreach ($g in $groups) {
        $owners  = Get-MgGroupOwner  -GroupId $g.Id -All -ErrorAction SilentlyContinue
        $members = Get-MgGroupMember -GroupId $g.Id -All -ErrorAction SilentlyContinue
        if (-not $owners)  { Add-Finding 'Grupo Sem Owner' 'LOW' $g.DisplayName 'Grupo sem owners' }
        if (-not $members) { Add-Finding 'Grupo Órfão'     'LOW' $g.DisplayName 'Grupo sem membros' }
    }
    Disconnect-MgGraph | Out-Null
    return $true
}

# ════════════════════════════════════════════════════════════════════════════
#  Geração de relatório
# ════════════════════════════════════════════════════════════════════════════
function Export-Report {
    param([string]$Base)

    $jsonPath = "$Base.json"
    $htmlPath = "$Base.html"

    $summary = $findings | Group-Object Severity | ForEach-Object {
        [pscustomobject]@{ Severity = $_.Name; Count = $_.Count }
    }

    # JSON
    [pscustomobject]@{
        GeneratedAt  = (Get-Date).ToString('o')
        Mode         = $Mode
        InactiveDays = $InactiveDays
        TotalFindings= $findings.Count
        Summary      = $summary
        Findings     = $findings
    } | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding utf8

    # HTML
    $sevColor = @{ CRITICAL='#ff2244'; HIGH='#ff6600'; MEDIUM='#ffcc00'; LOW='#33aaff' }
    $rows = ($findings | Sort-Object @{e={@{CRITICAL=4;HIGH=3;MEDIUM=2;LOW=1}[$_.Severity]}} -Descending |
        ForEach-Object {
            $c = $sevColor[$_.Severity]; if (-not $c) { $c = '#888' }
            "<tr><td><span style='background:$c;color:#000;padding:2px 8px;border-radius:4px;font-weight:bold'>$($_.Severity)</span></td>" +
            "<td>$([System.Web.HttpUtility]::HtmlEncode($_.Category))</td>" +
            "<td>$([System.Web.HttpUtility]::HtmlEncode($_.Principal))</td>" +
            "<td>$([System.Web.HttpUtility]::HtmlEncode($_.Detail))</td></tr>"
        }) -join "`n"

    $html = @"
<!DOCTYPE html><html lang='pt-BR'><head><meta charset='utf-8'>
<title>Relatório de Auditoria AD/Azure AD</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:2rem}
 h1{color:#58a6ff} table{border-collapse:collapse;width:100%;margin-top:1rem}
 th,td{border:1px solid #30363d;padding:8px 12px;text-align:left}
 th{background:#161b22} tr:nth-child(even){background:#161b22}
 .meta{color:#8b949e}
</style></head><body>
<h1>🛡️ Auditoria de Permissões — $Mode</h1>
<p class='meta'>Gerado em $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') • $($findings.Count) achados • Inatividade > $InactiveDays dias</p>
<table><thead><tr><th>Severidade</th><th>Categoria</th><th>Principal</th><th>Detalhe</th></tr></thead>
<tbody>
$rows
</tbody></table></body></html>
"@
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $html | Out-File -FilePath $htmlPath -Encoding utf8

    Write-Host ""
    Write-Host "===== RESUMO DE COMPLIANCE =====" -ForegroundColor Green
    $summary | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "Relatórios gerados:" -ForegroundColor Green
    Write-Host "  JSON: $jsonPath"
    Write-Host "  HTML: $htmlPath"
}

# ════════════════════════════════════════════════════════════════════════════
#  Execução
# ════════════════════════════════════════════════════════════════════════════
# Permite dot-sourcing das funções em testes sem disparar a auditoria:
#   $env:ADAUDIT_NOEXEC=1 ; . .\ad-audit.ps1
if ($env:ADAUDIT_NOEXEC) { return }

Write-Host "Auditor de Permissões AD/Azure AD — modo: $Mode" -ForegroundColor White

$ok = $false
try {
    if ($Mode -eq 'AD') { $ok = Invoke-ADAudit } else { $ok = Invoke-AzureADAudit }
} catch {
    Write-Error "Falha durante a auditoria: $($_.Exception.Message)"
    exit 1
}

if (-not $ok) {
    Write-Warning "Auditoria não executada (módulo ausente). Nenhum relatório gerado."
    exit 0
}

Export-Report -Base $OutputPath
Write-Host "Auditoria concluída." -ForegroundColor Green
exit 0
