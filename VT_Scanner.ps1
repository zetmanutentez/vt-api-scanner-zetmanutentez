# ============================================
# VirusTotal Interactive Scanner v1.2.3
# Standalone / Non-Admin | Proxy Auto-Detect | UX 0/X
# Autor: Zet
# ============================================

[CmdletBinding()]
param(
    [string]$ApiKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------- Paths (Desktop real por utilizador) ----------
$Desktop   = [Environment]::GetFolderPath('Desktop')
$ReportDir = Join-Path $Desktop 'VT_Reports'

# ---------- Config file (fallback) ----------
$ConfigPath = Join-Path $env:USERPROFILE '.vt_scanner.json'

function Get-ConfigApiKey {
    if (Test-Path -LiteralPath $ConfigPath) {
        try {
            $cfg = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json
            if ($cfg -and -not [string]::IsNullOrWhiteSpace($cfg.ApiKey)) {
                return [string]$cfg.ApiKey
            }
        } catch { }
    }
    return $null
}

# ---------- Proxy auto-detect (sem UI) ----------
function Get-AutoProxyUri {

    foreach ($name in @('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy')) {
        $v = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($v)) {
            try {
                if ($v -notmatch '^\w+://') { $v = "http://$v" }
                return [Uri]$v
            } catch { }
        }
    }

    try {
        $ie = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        if ($ie.ProxyEnable -eq 1 -and $ie.ProxyServer) {
            $ps = [string]$ie.ProxyServer

            if ($ps -match 'https=([^;]+)') { $p = $Matches[1] }
            elseif ($ps -match 'http=([^;]+)') { $p = $Matches[1] }
            else { $p = $ps }

            $p = $p.Trim()
            if ($p -notmatch '^\w+://') { $p = "http://$p" }
            return [Uri]$p
        }
    } catch { }

    try {
        $wp = [System.Net.WebRequest]::GetSystemWebProxy()
        $test = [Uri]'https://www.virustotal.com/'
        $pu = $wp.GetProxy($test)
        if ($pu -and $pu.AbsoluteUri -and $pu.AbsoluteUri -ne $test.AbsoluteUri) {
            return $pu
        }
    } catch { }

    return $null
}

$ProxyUri = Get-AutoProxyUri

# ---------- API key precedence: param -> env -> config ----------
if ([string]::IsNullOrWhiteSpace($ApiKey)) { $ApiKey = $env:VT_APIKEY }
if ([string]::IsNullOrWhiteSpace($ApiKey)) { $ApiKey = Get-ConfigApiKey }

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Host ""
    Write-Host "API KEY do VirusTotal não encontrada." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Opções (qualquer uma serve):" -ForegroundColor Yellow
    Write-Host '  1) setx VT_APIKEY "SUA_API_KEY"' -ForegroundColor Cyan
    Write-Host '  2) Criar ficheiro: %USERPROFILE%\.vt_scanner.json com: {"ApiKey":"SUA_API_KEY"}' -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

$Headers = @{ "x-apikey" = $ApiKey }

# ---------- Rate limit (Public API: 4 req/min) ----------
$script:LastRequestAt = Get-Date "2000-01-01"
$MinSecondsBetweenRequests = 16

function Ensure-ReportDir {
    if (-not (Test-Path -LiteralPath $ReportDir)) {
        New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
    }
}

function Invoke-VTRequest {
    param(
        [Parameter(Mandatory)][ValidateSet("GET","POST")] [string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter()][hashtable]$Headers,
        [Parameter()][object]$Body,
        [Parameter()][string]$ContentType
    )

    $elapsed = (Get-Date) - $script:LastRequestAt
    $sleep = $MinSecondsBetweenRequests - [int]$elapsed.TotalSeconds
    if ($sleep -gt 0) { Start-Sleep -Seconds $sleep }

    $params = @{
        Method  = $Method
        Uri     = $Uri
        Headers = $Headers
    }
    if ($PSBoundParameters.ContainsKey("Body"))        { $params.Body = $Body }
    if ($PSBoundParameters.ContainsKey("ContentType")) { $params.ContentType = $ContentType }
    if ($ProxyUri) { $params.Proxy = $ProxyUri.AbsoluteUri }

    $script:LastRequestAt = Get-Date
    return Invoke-RestMethod @params
}

function Get-CategoriesString {
    param($Categories)
    if (-not $Categories) { return "" }
    try {
        if ($Categories -is [System.Collections.IDictionary]) {
            return (($Categories.Values | Where-Object { $_ } | Sort-Object -Unique) -join ", ")
        }
        return [string]$Categories
    } catch {
        return ""
    }
}

function Get-EngineTotals {
    param($Stats)
    $m = [int]($Stats.malicious  ?? 0)
    $s = [int]($Stats.suspicious ?? 0)
    $h = [int]($Stats.harmless  ?? 0)
    $u = [int]($Stats.undetected ?? 0)
    $total = $m + $s + $h + $u
    [pscustomobject]@{
        Malicious  = $m
        Suspicious = $s
        Harmless   = $h
        Undetected = $u
        Total      = $total
        Bad        = ($m + $s)
    }
}

function Get-DecisionText {
    param(
        [Parameter(Mandatory)]$Stats,
        $Categories,
        [string]$Artifact,
        [string]$Type
    )

    $t = Get-EngineTotals -Stats $Stats
    $ratio = if ($t.Total -gt 0) { [math]::Round(($t.Bad / $t.Total) * 100, 1) } else { 0 }
    $cats  = Get-CategoriesString -Categories $Categories

    $benignCat = ($cats -match '(?i)\b(search engines|portals|cloud|cdn|software|microsoft|google)\b')
    $weakReputation = ($t.Malicious -eq 0 -and $t.Suspicious -eq 0 -and $t.Harmless -le 1 -and $t.Undetected -ge 10)

    if ($t.Suspicious -ge 1 -or $t.Malicious -ge 2) {
        return @"
**Análise de segurança (VirusTotal) — RESULTADO: NÃO SEGURO / NÃO DESBLOQUEAR**

Artefacto: $Type
Valor: $Artifact

Deteções (motores VT):
- Malicioso: $($t.Malicious)
- Suspeito:  $($t.Suspicious)
- Limpo:     $($t.Harmless)
- Indet.:    $($t.Undetected)
- Rácio de risco: $ratio%
$(if($cats){ "`nCategorias/Reputação (quando disponíveis): $cats" } else { "" })

Recomendação:
- Não clicar/abrir e não executar qualquer anexo.
- Apagar o conteúdo e limpar a lixeira.
- Se já houve interação: reportar ao suporte/segurança e isolar a máquina conforme procedimento interno.
"@
    }

    if ($t.Malicious -eq 1 -and $t.Suspicious -eq 0 -and ($t.Harmless -ge 10 -or $benignCat)) {
        return @"
**Análise de segurança (VirusTotal) — RESULTADO: PROVÁVEL FALSO POSITIVO**

Artefacto: $Type
Valor: $Artifact

Deteções (motores VT):
- Malicioso: 1 (isolado)
- Suspeito:  0
- Limpo:     $($t.Harmless)
- Indet.:    $($t.Undetected)
$(if($cats){ "`nCategorias/Reputação (quando disponíveis): $cats" } else { "" })

Conclusão:
- A deteção isolada não é suportada pela maioria dos motores.
- Considerado seguro, mantendo atenção ao contexto (remetente, necessidade do link/anexo, etc.).
"@
    }

    if ($weakReputation) {
        return @"
**Análise de segurança (VirusTotal) — RESULTADO: INCONCLUSIVO / NÃO DESBLOQUEAR POR PRECAUÇÃO**

Artefacto: $Type
Valor: $Artifact

Deteções (motores VT):
- Malicioso: 0
- Suspeito:  0
- Limpo:     $($t.Harmless)
- Indet.:    $($t.Undetected)

Observação:
- Sem deteções diretas, mas reputação insuficiente (muitos “undetected” ≠ “limpo”).

Recomendação:
- Não desbloquear.
- Apagar e limpar a lixeira por precaução.
"@
    }

    return @"
**Análise de segurança (VirusTotal) — RESULTADO: INCONCLUSIVO**

Artefacto: $Type
Valor: $Artifact

Deteções (motores VT):
- Malicioso: $($t.Malicious)
- Suspeito:  $($t.Suspicious)
- Limpo:     $($t.Harmless)
- Indet.:    $($t.Undetected)
$(if($cats){ "`nCategorias/Reputação (quando disponíveis): $cats" } else { "" })

Recomendação:
- Manter cautela e não desbloquear se a origem/contexto for duvidoso.
"@
}

function Wait-VTAnalysis {
    param(
        [Parameter(Mandatory)][string]$AnalysisId,
        [int]$MaxTries = 6,
        [int]$DelaySeconds = 5
    )

    $analysisUrl = "https://www.virustotal.com/api/v3/analyses/$AnalysisId"
    $res = $null

    for ($i=1; $i -le $MaxTries; $i++) {
        $res = Invoke-VTRequest -Method GET -Uri $analysisUrl -Headers $Headers
        $status = $res.data.attributes.status
        if ($status -eq "completed") { return $res }
        Start-Sleep -Seconds $DelaySeconds
    }
    return $res
}

function Scan-Hash {
    param([Parameter(Mandatory)][string]$Hash)
    Invoke-VTRequest -Method GET -Uri "https://www.virustotal.com/api/v3/files/$Hash" -Headers $Headers
}

function Scan-URL {
    param([Parameter(Mandatory)][string]$UrlToScan)
    $analysis = Invoke-VTRequest -Method POST -Uri "https://www.virustotal.com/api/v3/urls" -Headers $Headers -Body @{ url = $UrlToScan } -ContentType "application/x-www-form-urlencoded"
    Wait-VTAnalysis -AnalysisId $analysis.data.id
}

function Get-UploadUrl {
    (Invoke-VTRequest -Method GET -Uri "https://www.virustotal.com/api/v3/files/upload_url" -Headers $Headers).data
}

function Scan-File {
    param([Parameter(Mandatory)][string]$FilePath)

    if (-not (Test-Path -LiteralPath $FilePath)) { throw "Ficheiro não encontrado: $FilePath" }

    $fi = Get-Item -LiteralPath $FilePath
    $targetUrl = "https://www.virustotal.com/api/v3/files"
    if ($fi.Length -gt 32MB) { $targetUrl = Get-UploadUrl }

    $boundary = [Guid]::NewGuid().ToString()
    $content  = New-Object System.Net.Http.MultipartFormDataContent($boundary)

    $fileStream = [System.IO.File]::OpenRead($FilePath)
    $client = $null

    try {
        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
        $content.Add($fileContent, "file", [System.IO.Path]::GetFileName($FilePath))

        $handler = New-Object System.Net.Http.HttpClientHandler
        if ($ProxyUri) {
            $handler.Proxy = New-Object System.Net.WebProxy($ProxyUri.AbsoluteUri, $true)
            $handler.UseProxy = $true
        }

        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.DefaultRequestHeaders.Add("x-apikey", $ApiKey)

        $elapsed = (Get-Date) - $script:LastRequestAt
        $sleep = $MinSecondsBetweenRequests - [int]$elapsed.TotalSeconds
        if ($sleep -gt 0) { Start-Sleep -Seconds $sleep }
        $script:LastRequestAt = Get-Date

        $response = $client.PostAsync($targetUrl, $content).Result
        $raw = $response.Content.ReadAsStringAsync().Result
        if (-not $response.IsSuccessStatusCode) { throw "Upload falhou (HTTP $($response.StatusCode)): $raw" }

        $json = $raw | ConvertFrom-Json
        Wait-VTAnalysis -AnalysisId $json.data.id
    }
    finally {
        $fileStream.Dispose()
        if ($client) { $client.Dispose() }
    }
}

function Scan-Domain {
    param([Parameter(Mandatory)][string]$Domain)
    Invoke-VTRequest -Method GET -Uri "https://www.virustotal.com/api/v3/domains/$Domain" -Headers $Headers
}

function Scan-IP {
    param([Parameter(Mandatory)][string]$IP)
    Invoke-VTRequest -Method GET -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IP" -Headers $Headers
}

function Extract-StatsAndCategories {
    param($Result, [string]$Type)

    if ($Type -in @("url","file")) {
        $stats = $Result.data.attributes.stats
        if (-not $stats) { $stats = $Result.data.attributes.last_analysis_stats }
        $categories = $Result.data.attributes.categories
        return ,@($stats, $categories)
    }

    $stats = $Result.data.attributes.last_analysis_stats
    $categories = $Result.data.attributes.categories
    return ,@($stats, $categories)
}

function Show-Result {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][ValidateSet("url","hash","file","domain","ip")] [string]$Type,
        [Parameter(Mandatory)][string]$Artifact
    )

    $pair = Extract-StatsAndCategories -Result $Result -Type $Type
    $stats = $pair[0]
    $categories = $pair[1]

    Write-Host ""
    Write-Host "=== Resumo Técnico (VirusTotal) ===" -ForegroundColor Cyan
    Write-Host ""

    if ($stats) {
        $t = Get-EngineTotals -Stats $stats
        $ratio = if ($t.Total -gt 0) { [math]::Round(($t.Bad / $t.Total) * 100, 1) } else { 0 }
        $cats = Get-CategoriesString -Categories $categories

        Write-Host "Artefacto: $Type"
        Write-Host "Valor:     $Artifact"
        Write-Host "Malicioso: $($t.Malicious)"
        Write-Host "Suspeito:  $($t.Suspicious)"
        Write-Host "Limpo:     $($t.Harmless)"
        Write-Host "Indet.:    $($t.Undetected)"
        Write-Host "Rácio:     $ratio% (mal+sus / total engines)"
        if (-not [string]::IsNullOrWhiteSpace($cats)) {
            Write-Host "Categorias/Reputação: $cats"
        }
    } else {
        Write-Host "Sem estatísticas disponíveis."
    }

    Write-Host ""
    Write-Host "=== Texto para enviar ao utilizador ===" -ForegroundColor Cyan
    Write-Host ""

    if ($stats) {
        $text = Get-DecisionText -Stats $stats -Categories $categories -Artifact $Artifact -Type $Type
        Write-Host $text

        Ensure-ReportDir
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $outFile = Join-Path $ReportDir ("VT_{0}_{1}.txt" -f $Type.ToUpper(), $stamp)
        ($text -replace "`r","") | Set-Content -LiteralPath $outFile -Encoding UTF8
        Write-Host "Relatório guardado em: $outFile" -ForegroundColor Green
    } else {
        Write-Host "Não foi possível gerar texto automático."
    }

    Write-Host ""
    Read-Host "ENTER para voltar ao menu" | Out-Null
}

# ---------- MENU ----------
:MAIN while ($true) {
    Clear-Host
    Write-Host "=== VirusTotal Scanner Interativo v1.2.3 (Standalone / Non-Admin) ===" -ForegroundColor Green
    Write-Host ""

    Write-Host "1 - Analisar URL"
    Write-Host "2 - Analisar HASH (ficheiro já conhecido)"
    Write-Host "3 - Analisar Ficheiro (upload)"
    Write-Host "4 - Analisar Domínio"
    Write-Host "5 - Analisar IP"
    Write-Host ""
    Write-Host "0 - Sair e voltar ao prompt"
    Write-Host "X - Sair e fechar o PowerShell"
    Write-Host ""

    $choice = (Read-Host "Escolha uma opção").Trim()

    try {
        switch ($choice.ToUpper()) {
            "1" {
                $inputUrl = Read-Host "Digite a URL"
                $result = Scan-URL -UrlToScan $inputUrl
                Show-Result -Result $result -Type "url" -Artifact $inputUrl
            }
            "2" {
                $inputHash = Read-Host "Digite o HASH (MD5/SHA1/SHA256)"
                $result = Scan-Hash -Hash $inputHash
                Show-Result -Result $result -Type "hash" -Artifact $inputHash
            }
            "3" {
                $inputFile = Read-Host "Digite o caminho completo do ficheiro"
                $result = Scan-File -FilePath $inputFile
                Show-Result -Result $result -Type "file" -Artifact $inputFile
            }
            "4" {
                $inputDomain = Read-Host "Digite o domínio"
                $result = Scan-Domain -Domain $inputDomain
                Show-Result -Result $result -Type "domain" -Artifact $inputDomain
            }
            "5" {
                $inputIP = Read-Host "Digite o IP"
                $result = Scan-IP -IP $inputIP
                Show-Result -Result $result -Type "ip" -Artifact $inputIP
            }
            "0" {
                break MAIN
            }
            "X" {
                Write-Host ""
                Write-Host "A fechar o PowerShell..." -ForegroundColor Yellow
                Start-Sleep -Seconds 1
                Stop-Process -Id $PID
            }
            default {
                Write-Host "Opção inválida." -ForegroundColor Yellow
                Start-Sleep -Seconds 1
            }
        }
    }
    catch {
        Write-Host ""
        Write-Host "Erro ao processar a análise:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}
