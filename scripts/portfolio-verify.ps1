param(
    [string]$EvidenceDir = "",
    [string]$SnapshotDir = "build/portfolio",
    [string]$ProjectName = "zeekad-portfolio-verify",
    [int]$WafHttpPort = 18480,
    [string]$PublicHost = "soc.example.synology.me",
    [string]$ReportDir = "build/portfolio-verify",
    [switch]$SkipZap
)

# 포트폴리오 스택 리허설 검증(이 PC). compose.portfolio.yml을 NAS와 같은 구성으로 띄우고(프로젝트 이름만 다름),
# 계정 시드를 두 번 실행한 뒤 DSM 역방향 프록시를 흉내 낸 요청으로 E2E [0]~[8]과 ZAP 베이스라인 [9]를 확인하고 down -v로 정리한다.
# - DSM 흉내: http://127.0.0.1:<WAF 포트>에 Host: <PublicHost>, X-Forwarded-Proto: https, X-Forwarded-For: <클라이언트 IP>.
# - 세션·CSRF 쿠키는 Secure라 HTTP 요청에 클라이언트가 보내지 않으므로 Set-Cookie에서 값을 읽어 Cookie 헤더를 직접 만든다
#   (DASHBOARD_COOKIE_SECURE=false로 우회하지 않는다).
# - 비밀값은 실행마다 무작위로 만들어 이 프로세스 환경 변수로만 넘기고 출력하지 않는다.
# - 실패하면 종료 코드가 0이 아니다. 증거는 -EvidenceDir에 남긴다.

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot
$utf8NoBom = [Text.UTF8Encoding]::new($false)

function Resolve-RepoPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path $RepoRoot $Path)
}

$EvidenceFullDir = ""
if ($EvidenceDir) {
    $EvidenceFullDir = Resolve-RepoPath $EvidenceDir
    New-Item -ItemType Directory -Force -Path $EvidenceFullDir | Out-Null
}
$ReportFullDir = Resolve-RepoPath $ReportDir
New-Item -ItemType Directory -Force -Path $ReportFullDir | Out-Null
$SnapshotFullDir = Resolve-RepoPath $SnapshotDir

function Save-Evidence([string]$FileName, [string]$Content) {
    if ($EvidenceFullDir) {
        [IO.File]::WriteAllText((Join-Path $EvidenceFullDir $FileName), $Content, $utf8NoBom)
    }
}

function New-RandomToken([int]$Length = 24) {
    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789".ToCharArray()
    $bytes = New-Object byte[] $Length
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function New-RandomBase32([int]$Length = 32) {
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray()
    $bytes = New-Object byte[] $Length
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function Invoke-NativeCapture([string]$Command, [string[]]$CommandArgs, [switch]$IgnoreExitCode) {
    $savedEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Command @CommandArgs 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedEap
    }
    if (-not $IgnoreExitCode -and $code -ne 0) {
        throw "$Command $($CommandArgs -join ' ') 실패 (exit=$code)`n$output"
    }
    return [pscustomobject]@{ ExitCode = $code; Output = $output }
}

# --- 사전 조건: 스냅샷과 매니페스트, 이미지 ---
$manifestPath = Join-Path $SnapshotFullDir "manifest.json"
foreach ($f in @("zeekad.dump", "zeekad.dump.sha256", "manifest.json", "source-globals.sql")) {
    if (-not (Test-Path (Join-Path $SnapshotFullDir $f))) { throw "스냅샷 파일이 없습니다: $SnapshotFullDir\$f (scripts/portfolio-snapshot.ps1 먼저 실행)" }
}
$manifest = [IO.File]::ReadAllText($manifestPath, $utf8NoBom) | ConvertFrom-Json
$expectedCounts = [ordered]@{}
foreach ($p in $manifest.captureIncidentCounts.PSObject.Properties) { $expectedCounts[$p.Name] = [int]$p.Value }
# T22: demo 허용 캡처는 시드 기본값 cic17-*,syn1-*,lab-20261119(공개 데모는 배포 VM 스냅샷. Kali 실습망 lab-20261119만 공개,
#      시험 캡처 lab-20261201·첫 VM 실행 lab-20261118 등 나머지는 숨김, SPEC 결정 2026-11-21). 정확한 ID는 그 캡처만, 접두사*는 접두사 일치.
$demoPatterns = @("cic17-*", "syn1-*", "lab-20261119")
$demoLabCapture = "lab-20261119"
function Test-DemoPattern([string]$CaptureId) {
    foreach ($p in $demoPatterns) {
        if ($p.EndsWith('*')) { if ($CaptureId.StartsWith($p.Substring(0, $p.Length - 1), [StringComparison]::Ordinal)) { return $true } }
        elseif ($CaptureId -ceq $p) { return $true }
    }
    return $false
}
# 보이는 캡처 = manifest 캡처 중 허용 패턴에 맞는 것, 숨김 캡처 = 나머지 전부.
$demoVisibleCaptures = @($expectedCounts.Keys | Where-Object { Test-DemoPattern $_ })
$demoHiddenCaptures = @($expectedCounts.Keys | Where-Object { -not (Test-DemoPattern $_) })
foreach ($img in @("zeek-ad-dashboard-app:local", "zeek-ad-dashboard-waf:local", "zeekad-pipeline:dev", "pgvector/pgvector:0.8.1-pg17")) {
    [void](Invoke-NativeCapture "docker" @("image", "inspect", "--format", "{{.Id}}", $img))
}

# --- 리허설 비밀값(실행마다 무작위, 이 프로세스 환경 변수로만 전달. Compose는 셸 환경 변수가 --env-file 값보다 우선한다) ---
$secretNames = @("POSTGRES_SUPERUSER_PASSWORD", "ZEEKAD_API_PASSWORD", "DASHBOARD_RO_PASSWORD", "DASHBOARD_RW_PASSWORD",
    "DASHBOARD_APP_PASSWORD", "DEMO_PASSWORD", "BOOTSTRAP_VIEWER1_PASSWORD", "BOOTSTRAP_ANALYST1_PASSWORD",
    "BOOTSTRAP_ANALYST2_PASSWORD", "BOOTSTRAP_ADMIN_PASSWORD")
foreach ($name in $secretNames) { Set-Item -Path "env:$name" -Value (New-RandomToken 24) }
# demo 허용 캡처는 시드 기본값을 쓴다(셸에 남은 값이 Compose 보간을 덮지 않게 지운다).
Remove-Item -Path "env:DEMO_CAPTURE_PATTERNS" -ErrorAction SilentlyContinue
$env:BOOTSTRAP_ADMIN_TOTP_SECRET = New-RandomBase32 32
$env:PORTFOLIO_SNAPSHOT_DIR = $SnapshotFullDir
$env:PORTFOLIO_HTTP_PORT = "$WafHttpPort"
$env:PORTFOLIO_SERVER_NAME = $PublicHost

$composeArgs = @("compose", "-p", $ProjectName, "-f", "compose.portfolio.yml", "--env-file", ".env.portfolio.example")
$networkName = "${ProjectName}_portfolio-net"
$baseUrl = "http://127.0.0.1:$WafHttpPort"
$e2eLogs = [System.Collections.Generic.List[string]]::new()
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) "zeekad-portfolio-$ProjectName-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$script:httpSeq = 0
$failed = $false

function Get-ServiceContainer([string]$Service) {
    $id = (Invoke-NativeCapture "docker" ($composeArgs + @("ps", "-q", $Service))).Output.Trim()
    if (-not $id) { throw "서비스 컨테이너가 없습니다: $Service" }
    return $id
}

function Invoke-Psql([string]$Database, [string]$Sql, [string]$User = "postgres", [string]$PasswordEnv = "") {
    # postgres는 컨테이너 안 로컬 소켓(trust), 다른 역할은 TCP + 비밀번호(환경 변수 이름만 docker exec -e로 넘김).
    $container = Get-ServiceContainer "postgres"
    $dockerArgs = @("exec")
    if ($PasswordEnv) {
        $env:PGPASSWORD = (Get-Item "env:$PasswordEnv").Value
        $dockerArgs += @("-e", "PGPASSWORD")
    }
    $dockerArgs += @($container, "psql", "-v", "ON_ERROR_STOP=1", "-U", $User, "-d", $Database, "-AtF", "|")
    if ($PasswordEnv) { $dockerArgs += @("-h", "127.0.0.1") }
    $dockerArgs += @("-c", $Sql)
    try {
        return Invoke-NativeCapture "docker" $dockerArgs -IgnoreExitCode
    } finally {
        Remove-Item env:PGPASSWORD -ErrorAction SilentlyContinue
    }
}

# --- HTTP: DSM 흉내 헤더 + 직접 관리하는 쿠키 ---
function New-Client([string]$Ip) { return [pscustomobject]@{ Ip = $Ip; Cookies = [ordered]@{}; SetCookieLines = @() } }

function Invoke-Http {
    param(
        [string]$Path,
        [string]$Method = "GET",
        $Client = $null,
        [string]$Xff = "",
        [switch]$Csrf,
        [string]$CsrfValue = "",
        $JsonBody = $null,
        [string]$ProbeId = "",
        [string[]]$ExtraHeaders = @()
    )
    $script:httpSeq++
    $hdrFile = Join-Path $tmpDir "resp-$($script:httpSeq).hdr"
    $bodyFile = Join-Path $tmpDir "resp-$($script:httpSeq).body"
    $xffValue = if ($Xff) { $Xff } elseif ($Client) { $Client.Ip } else { "203.0.113.200" }
    $curlArgs = @("-sS", "--max-time", "60", "-X", $Method, "-D", $hdrFile, "-o", $bodyFile, "-w", "%{http_code}",
        "-H", "Host: $PublicHost", "-H", "X-Forwarded-Proto: https", "-H", "X-Forwarded-For: $xffValue",
        "-H", "Accept: application/json, text/html;q=0.9, */*;q=0.8")
    if ($Client -and $Client.Cookies.Count -gt 0) {
        $curlArgs += @("-H", "Cookie: $(($Client.Cookies.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')")
    }
    if ($Csrf) {
        $token = if ($CsrfValue) { $CsrfValue } else { $Client.Cookies["XSRF-TOKEN"] }
        if (-not $token) { throw "XSRF-TOKEN 쿠키가 없습니다: $Method $Path" }
        $curlArgs += @("-H", "X-XSRF-TOKEN: $token")
    }
    if ($ProbeId) { $curlArgs += @("-H", "X-E2E-Probe: $ProbeId") }
    foreach ($h in $ExtraHeaders) { $curlArgs += @("-H", $h) }
    if ($null -ne $JsonBody) {
        $reqFile = Join-Path $tmpDir "req-$($script:httpSeq).json"
        $jsonText = if ($JsonBody -is [string]) { $JsonBody } else { $JsonBody | ConvertTo-Json -Depth 6 -Compress }
        [IO.File]::WriteAllText($reqFile, $jsonText, $utf8NoBom)
        $curlArgs += @("-H", "Content-Type: application/json", "--data-binary", "@$reqFile")
    } elseif ($Method -ne "GET") {
        $curlArgs += @("-H", "Content-Length: 0")
    }
    $curlArgs += "$baseUrl$Path"

    $savedEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $statusText = & curl.exe @curlArgs 2>&1 | Out-String
    $curlExit = $LASTEXITCODE
    $ErrorActionPreference = $savedEap
    if ($curlExit -ne 0) { throw "curl 실패 (exit=$curlExit) $Method $Path : $statusText" }

    $headers = if (Test-Path $hdrFile) { [IO.File]::ReadAllText($hdrFile, $utf8NoBom) } else { "" }
    $body = if (Test-Path $bodyFile) { [IO.File]::ReadAllText($bodyFile, $utf8NoBom) } else { "" }
    Remove-Item -Force -ErrorAction SilentlyContinue $hdrFile, $bodyFile
    $setCookies = @([regex]::Matches($headers, "(?im)^Set-Cookie:\s*([^\r\n]*)") | ForEach-Object { $_.Groups[1].Value })
    if ($Client) {
        $Client.SetCookieLines = $setCookies
        foreach ($line in $setCookies) {
            $m = [regex]::Match($line, '^([^=;\s]+)=([^;]*)')
            if (-not $m.Success) { continue }
            if ($m.Groups[2].Value -eq "" -or $line -match '(?i)max-age=0') { $Client.Cookies.Remove($m.Groups[1].Value) }
            else { $Client.Cookies[$m.Groups[1].Value] = $m.Groups[2].Value }
        }
    }
    $json = $null
    if ($body.TrimStart().StartsWith("{") -or $body.TrimStart().StartsWith("[")) {
        try { $json = $body | ConvertFrom-Json } catch { $json = $null }
    }
    return [pscustomobject]@{ Method = $Method; Path = $Path; Status = [int]($statusText.Trim()); Headers = $headers; Body = $body; Json = $json; SetCookies = $setCookies }
}

function Get-HeaderValue($Resp, [string]$Name) {
    $m = [regex]::Match($Resp.Headers, "(?im)^$([regex]::Escape($Name)):\s*(.*?)\s*$")
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Format-Resp($Resp, [int]$BodyChars = 300) {
    $ct = Get-HeaderValue $Resp "Content-Type"
    $snippet = $Resp.Body
    if ($snippet.Length -gt $BodyChars) { $snippet = $snippet.Substring(0, $BodyChars) + "..." }
    $snippet = ($snippet -replace "\s+", " ").Trim()
    return "$($Resp.Method) $($Resp.Path) -> HTTP $($Resp.Status) [$ct] $snippet"
}

function Assert-True([bool]$Condition, [string]$What, $Resp = $null) {
    if (-not $Condition) {
        $detail = if ($Resp) { "`n$(Format-Resp $Resp 1200)" } else { "" }
        throw "$What 확인 실패$detail"
    }
}

function Assert-Status($Resp, [int]$Expected, [string]$What) {
    if ($Resp.Status -ne $Expected) { throw "$What : 기대 HTTP $Expected, 실제 $(Format-Resp $Resp 600)" }
}

function Assert-ApiError($Resp, [int]$Status, [string]$Code, [string]$What) {
    Assert-Status $Resp $Status $What
    Assert-True ($null -ne $Resp.Json -and $Resp.Json.code -eq $Code) "$What (JSON code=$Code)" $Resp
}

function Test-SpaShell($Resp) {
    return ($Resp.Body -match '<div id="root"></div>' -and $Resp.Body -match 'src="/assets/')
}

function Redact-Cookies([string]$Text) {
    return ($Text -replace '(ZEEKAD_SESSION|XSRF-TOKEN)=[^;\s]+', '$1=<redacted>')
}

function Login-Api($Client, [string]$Username, [string]$Password) {
    $csrfRes = Invoke-Http -Path "/api/auth/csrf" -Client $Client
    Assert-Status $csrfRes 200 "$Username GET /api/auth/csrf"
    Assert-True ([bool]$Client.Cookies["XSRF-TOKEN"]) "$Username XSRF-TOKEN 쿠키 발급" $csrfRes
    return Invoke-Http -Path "/api/auth/login" -Method POST -Client $Client -Csrf -JsonBody @{ username = $Username; password = $Password }
}

function Assert-WafBlocked($Resp, [string]$ProbeId, [string]$What) {
    Assert-Status $Resp 403 "$What (WAF 403)"
    Assert-True (-not ($null -ne $Resp.Json -and $null -ne $Resp.Json.code)) "$What (응답이 앱 ApiErrorResponse JSON이 아님)" $Resp
    $logLine = $null
    for ($i = 0; $i -lt 10 -and -not $logLine; $i++) {
        $wafLogs = (Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--no-log-prefix", "nginx-waf")) -IgnoreExitCode).Output
        $logLine = $wafLogs -split "`r?`n" | Where-Object { $_.StartsWith('{"transaction"') -and $_.Contains($ProbeId) } | Select-Object -Last 1
        if (-not $logLine) { Start-Sleep -Seconds 1 }
    }
    Assert-True ([bool]$logLine) "$What (nginx-waf ModSecurity 감사 로그에 probe=$ProbeId 기록)"
    $ruleIds = @([regex]::Matches($logLine, '"ruleId":"(\d+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $interrupted = $logLine -match '"is_interrupted":true'
    $logCode = [regex]::Match($logLine, '"http_code":(\d+)').Groups[1].Value
    $clientIp = [regex]::Match($logLine, '"client_ip":"([^"]+)"').Groups[1].Value
    Assert-True ($ruleIds.Count -gt 0 -and $interrupted -and $logCode -eq "403") "$What (WAF 로그 차단 규칙 ID·interrupted·403)"
    return "WAF log: client_ip=$clientIp is_interrupted=true http_code=$logCode ruleIds=[$($ruleIds -join ', ')]"
}

# JSON 전체를 훑어 가려지지 않은 IPv4(네 옥텟이 모두 숫자)가 있는 경로를 모은다. 값은 남기지 않는다.
$ipv4Regex = [regex]'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])'
function Find-UnmaskedIpv4($Node, [string]$Path, [System.Collections.Generic.List[string]]$Hits) {
    if ($null -eq $Node) { return }
    if ($Node -is [string]) {
        if ($ipv4Regex.IsMatch($Node)) { $Hits.Add($Path) }
        return
    }
    if ($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [System.Management.Automation.PSCustomObject])) {
        $i = 0
        foreach ($item in $Node) { Find-UnmaskedIpv4 $item "$Path[$i]" $Hits; $i++ }
        return
    }
    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Node.PSObject.Properties) { Find-UnmaskedIpv4 $p.Value "$Path.$($p.Name)" $Hits }
    }
}

try {
    Write-Host "=== 리허설 스택 기동 ($ProjectName, http://127.0.0.1:$WafHttpPort) ==="
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("down", "-v")) -IgnoreExitCode)
    $upRes = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait")) -IgnoreExitCode
    if ($upRes.ExitCode -ne 0) {
        $diag = (Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--tail=150")) -IgnoreExitCode).Output
        throw "리허설 스택 기동 실패 (exit=$($upRes.ExitCode)):`n$($upRes.Output)`n--- LOGS ---`n$diag"
    }

    # 복원 로그: 오류 0건이어야 한다. 경고는 그대로 남긴다.
    $pgLogs = (Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--no-log-prefix", "postgres")) -IgnoreExitCode).Output
    $restoreLines = @($pgLogs -split "`r?`n" | Where-Object { $_ -match 'portfolio-(init|restore)|pg_restore|ERROR|WARNING|FATAL|init process complete' })
    $restoreErrors = @($restoreLines | Where-Object { $_ -match '(?i)pg_restore: error|ERROR:|FATAL:' })
    $restoreWarnings = @($restoreLines | Where-Object { $_ -match '(?i)warning' })
    Save-Evidence "restore-log.txt" ("errors=$($restoreErrors.Count) warnings=$($restoreWarnings.Count)`n" + ($restoreLines -join "`n") + "`n")
    $e2eLogs.Add("[restore] postgres init log: errors=$($restoreErrors.Count) warnings=$($restoreWarnings.Count) done=$([bool]($restoreLines -match 'portfolio-restore: done'))$(if ($restoreWarnings.Count) { "`n    " + ($restoreWarnings -join "`n    ") })")
    Assert-True ($restoreErrors.Count -eq 0) "스냅샷 복원 로그 오류 0건"
    Assert-True ([bool]($restoreLines -match 'portfolio-restore: done')) "스냅샷 복원 완료 표지"

    # --- 계정 시드 두 번(두 번째는 변경 없음이어야 한다) ---
    Write-Host "=== 계정 시드 1차·2차 실행 ==="
    $seedArgs = $composeArgs + @("--profile", "seed", "run", "--rm", "demo-seed")
    $seed1 = Invoke-NativeCapture "docker" $seedArgs -IgnoreExitCode
    Save-Evidence "seed-run-1.txt" "EXIT_CODE=$($seed1.ExitCode)`n$($seed1.Output)"
    Assert-True ($seed1.ExitCode -eq 0 -and $seed1.Output -match 'RESULT: CHANGED') "시드 1차 실행(RESULT: CHANGED)`n$($seed1.Output)"
    $auditBefore = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM audit_logs").Output.Trim()
    $seed2 = Invoke-NativeCapture "docker" $seedArgs -IgnoreExitCode
    $auditAfter = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM audit_logs").Output.Trim()
    Save-Evidence "seed-run-2.txt" "EXIT_CODE=$($seed2.ExitCode)`naudit_logs rows before=$auditBefore after=$auditAfter`n$($seed2.Output)"
    $seedAudit = (Invoke-Psql "zeekad_dashboard" "SELECT id, actor_username, actor_role, action_type, detail_json FROM audit_logs WHERE action_type = 'USER_ADMIN_CHANGE' ORDER BY id").Output.Trim()
    $userRows = (Invoke-Psql "zeekad_dashboard" "SELECT u.username, u.role, u.enabled, u.totp_enabled, string_agg(a.capture_pattern, ',') FROM users u LEFT JOIN user_capture_access a ON a.user_id = u.id GROUP BY u.id ORDER BY u.id").Output.Trim()
    $e2eLogs.Add("[seed] run1 exit=$($seed1.ExitCode) $([regex]::Match($seed1.Output, 'RESULT: [^\r\n]*').Value)`n[seed] run2 exit=$($seed2.ExitCode) $([regex]::Match($seed2.Output, 'RESULT: [^\r\n]*').Value); audit_logs rows before=$auditBefore after=$auditAfter`n[seed] users (username|role|enabled|totp_enabled|patterns):`n    $($userRows -replace "`r?`n", "`n    ")`n[seed] USER_ADMIN_CHANGE audit rows (id|actor|actor_role|action|detail):`n    $($seedAudit -replace "`r?`n", "`n    ")")
    Assert-True ($seed2.ExitCode -eq 0 -and $seed2.Output -match 'RESULT: NO_CHANGES' -and $auditBefore -eq $auditAfter) "시드 2차 실행 변경 없음(RESULT: NO_CHANGES, 감사 로그 증가 없음)`n$($seed2.Output)"

    Write-Host "=== [0] 컨테이너 상태·포트·non-root·복원 DB 권한·근거 API ==="
    $ids = @((Invoke-NativeCapture "docker" ($composeArgs + @("ps", "-q"))).Output -split "`r?`n" | Where-Object { $_ })
    $states = @()
    $inspected = @()
    foreach ($id in $ids) {
        $info = @((Invoke-NativeCapture "docker" @("inspect", $id)).Output | ConvertFrom-Json)[0]
        $inspected += $info
        $health = if ($info.State.Health) { $info.State.Health.Status } else { "none" }
        $states += "$($info.Config.Labels.'com.docker.compose.service')|$health"
    }
    $e2eLogs.Add("[0a] containers (service|health): $($states -join ', ')")
    foreach ($svc in @("postgres", "api", "dashboard-app", "nginx-waf")) {
        Assert-True (@($states | Where-Object { $_ -eq "$svc|healthy" }).Count -eq 1) "$svc healthy"
    }
    Assert-True ($states.Count -eq 4) "실행 중인 컨테이너 4개(demo-seed는 실행 후 제거)"
    $bindings = @()
    foreach ($info in $inspected) {
        $portsJson = $info.NetworkSettings.Ports
        if (-not $portsJson) { continue }
        foreach ($p in $portsJson.PSObject.Properties) {
            foreach ($b in @($p.Value)) { if ($b -and $b.HostPort) { $bindings += "$($b.HostIp):$($b.HostPort)->$($p.Name)" } }
        }
    }
    $e2eLogs.Add("[0b] host port bindings: $($bindings -join ', ')")
    Assert-True ($bindings.Count -eq 1 -and $bindings[0] -eq "127.0.0.1:$WafHttpPort->8080/tcp") "호스트 포트는 127.0.0.1:$WafHttpPort 하나뿐"
    $uid = (Invoke-NativeCapture "docker" @("exec", (Get-ServiceContainer "dashboard-app"), "id", "-u")).Output.Trim()
    $e2eLogs.Add("[0c] dashboard-app id -u = $uid")
    Assert-True ($uid -match '^\d+$' -and $uid -ne "0") "앱 컨테이너 non-root(id -u != 0)"

    $views = @((Invoke-Psql "zeekad" "SELECT table_name FROM information_schema.views WHERE table_schema = 'dashboard' ORDER BY 1").Output -split "`r?`n" | Where-Object { $_ })
    $roSql = ($views | ForEach-Object { "SELECT '$_', count(*) FROM dashboard.$_" }) -join " UNION ALL "
    $roRes = Invoke-Psql "zeekad" $roSql -User "dashboard_ro" -PasswordEnv "DASHBOARD_RO_PASSWORD"
    $roRows = @($roRes.Output -split "`r?`n" | Where-Object { $_ -match '\|\d+$' })
    $e2eLogs.Add("[0d] dashboard_ro SELECT count(*) on $($views.Count) dashboard views (exit=$($roRes.ExitCode)):`n    $($roRows -join "`n    ")")
    Assert-True ($views.Count -eq 14 -and $roRes.ExitCode -eq 0 -and $roRows.Count -eq 14) "dashboard_ro로 dashboard 뷰 14종 SELECT"
    $roDenied = Invoke-Psql "zeekad" "SELECT count(*) FROM zeekad.incident" -User "dashboard_ro" -PasswordEnv "DASHBOARD_RO_PASSWORD"
    $e2eLogs.Add("[0d] (대조) dashboard_ro SELECT zeekad.incident 원본 표: exit=$($roDenied.ExitCode) $([regex]::Match($roDenied.Output, 'ERROR:[^\r\n+]*').Value.Trim())")
    Assert-True ($roDenied.ExitCode -ne 0 -and $roDenied.Output -match 'permission denied') "dashboard_ro는 zeekad 원본 표를 읽지 못함(권한 복원)"

    $health = Invoke-NativeCapture "docker" @("exec", (Get-ServiceContainer "dashboard-app"), "wget", "-qO-", "http://api:8000/health") -IgnoreExitCode
    $e2eLogs.Add("[0e] dashboard-app -> http://api:8000/health (zeekad_api 계정으로 DB 조회): exit=$($health.ExitCode) $($health.Output.Trim())")
    Assert-True ($health.ExitCode -eq 0 -and $health.Output -match '"status"\s*:\s*"ok"') "근거 API /health"

    $globalsNow = (Invoke-NativeCapture "docker" @("exec", (Get-ServiceContainer "postgres"), "pg_dumpall", "-U", "postgres", "--globals-only", "--no-role-passwords")).Output
    $srcGlobals = [IO.File]::ReadAllText((Join-Path $SnapshotFullDir "source-globals.sql"), $utf8NoBom)
    $norm = { param($t) @($t -split "`r?`n" | Where-Object { $_ -match '^(CREATE ROLE|ALTER ROLE|GRANT|ALTER DATABASE|SET ROLE)' }) }
    $globalsDiff = @(Compare-Object (& $norm $srcGlobals) (& $norm $globalsNow) | ForEach-Object { "$(if ($_.SideIndicator -eq '<=') { 'source  ' } else { 'rehearsal' }) $($_.InputObject)" })
    $membership = (Invoke-Psql "zeekad" "SELECT r.rolname || ' <- ' || m.rolname FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member WHERE m.rolname !~ '^pg_' ORDER BY 1").Output.Trim()
    $settings = (Invoke-Psql "zeekad" "SELECT count(*) FROM pg_db_role_setting").Output.Trim()
    $dbAcl = (Invoke-Psql "postgres" "SELECT datname, datacl FROM pg_database WHERE datname IN ('zeekad', 'zeekad_dashboard') ORDER BY 1").Output.Trim()
    $globalsText = "# 원본(source-globals.sql) 대비 리허설 DB 전역 객체 차이(CREATE/ALTER ROLE·GRANT 줄 비교, 비밀번호 없음)`n" +
        "$(if ($globalsDiff.Count) { $globalsDiff -join "`n" } else { '(no difference)' })`n`n" +
        "# 역할 멤버십(사용자 역할): $(if ($membership) { $membership } else { '(none)' })`n# pg_db_role_setting 행 수: $settings`n# DB ACL:`n$dbAcl`n"
    Save-Evidence "globals-diff.txt" $globalsText
    $e2eLogs.Add("[0f] globals vs source:`n    $($globalsText.Trim() -replace "`n", "`n    ")")

    Write-Host "=== [1] SPA·보안 헤더·리다이렉트 Location ==="
    $loginGet = Invoke-Http -Path "/login"
    $e2eLogs.Add("[1a] GET /login (unauthenticated, DSM headers):`n$(Redact-Cookies $loginGet.Headers.Trim())`n$(Format-Resp $loginGet 300)")
    Assert-Status $loginGet 200 "비인증 GET /login"
    Assert-True (Test-SpaShell $loginGet) "GET /login SPA 셸 표지" $loginGet
    $csp = Get-HeaderValue $loginGet "Content-Security-Policy"
    Assert-True ($csp -and $csp.Contains("script-src 'self'") -and $csp.Contains("style-src 'self'") -and $csp.Contains("frame-ancestors 'none'")) "CSP script-src/style-src 'self', frame-ancestors 'none'" $loginGet
    Assert-True ((Get-HeaderValue $loginGet "X-Content-Type-Options") -eq "nosniff") "X-Content-Type-Options: nosniff" $loginGet
    Assert-True ([bool](Get-HeaderValue $loginGet "Referrer-Policy")) "Referrer-Policy" $loginGet
    Assert-True ($loginGet.Headers -notmatch "(?im)^Server:\s*nginx") "Server: nginx 헤더 비노출" $loginGet
    $locationOk = "^(/login|https://$([regex]::Escape($PublicHost))(:443)?/login)$"
    $rootRes = Invoke-Http -Path "/"
    $rootLoc = Get-HeaderValue $rootRes "Location"
    $e2eLogs.Add("[1b] unauthenticated GET / -> HTTP $($rootRes.Status) Location=$rootLoc")
    Assert-Status $rootRes 302 "비인증 GET /"
    Assert-True ($rootLoc -match $locationOk) "비인증 GET / Location이 상대 경로이거나 https://$PublicHost/login(포트 없음 또는 :443)" $rootRes
    $spoofRes = Invoke-Http -Path "/" -ExtraHeaders @("X-Forwarded-Host: evil.example", "X-Forwarded-Port: 8080", "Forwarded: for=192.0.2.66;host=evil.example;proto=http", "X-Forwarded-Prefix: /evil", "X-Forwarded-Ssl: off")
    $spoofLoc = Get-HeaderValue $spoofRes "Location"
    $e2eLogs.Add("[1c] (위조 전달 헤더 X-Forwarded-Host/Port, Forwarded, X-Forwarded-Prefix/Ssl를 붙인) GET / -> HTTP $($spoofRes.Status) Location=$spoofLoc")
    Assert-True ($spoofRes.Status -eq 302 -and $spoofLoc -match $locationOk) "방문자가 붙인 전달 헤더가 Location에 반영되지 않음" $spoofRes
    # T21: 로그인 화면 안내 문구(compose.portfolio.yml DASHBOARD_LOGIN_NOTICE). 로그인 전 공개 GET이고, 문구만 있고 비밀번호가 없어야 한다.
    $noticeRes = Invoke-Http -Path "/api/auth/login-notice"
    $noticeText = if ($null -ne $noticeRes.Json) { [string]$noticeRes.Json.notice } else { "" }
    $noticeKeys = if ($null -ne $noticeRes.Json) { @($noticeRes.Json.PSObject.Properties.Name) } else { @() }
    $pwShaped = [regex]::Matches($noticeText, '[A-Za-z0-9!@#$%^&*_+=-]{12,}') | ForEach-Object { $_.Value }
    $e2eLogs.Add("[1d] unauthenticated GET /api/auth/login-notice -> HTTP $($noticeRes.Status) keys=[$($noticeKeys -join ',')] notice=$noticeText password-shaped tokens=$(@($pwShaped).Count)")
    Assert-Status $noticeRes 200 "비인증 GET /api/auth/login-notice"
    Assert-True (($noticeKeys -join ',') -eq 'notice') "로그인 안내 응답은 notice 하나뿐" $noticeRes
    Assert-True ($noticeText.StartsWith("포트폴리오 공개 데모입니다.") -and $noticeText.Contains("읽기 전용 계정 demo")) "로그인 안내 문구(포트폴리오 공개 데모) 응답" $noticeRes
    Assert-True ((@($pwShaped).Count -eq 0) -and -not $noticeRes.Body.Contains($env:DEMO_PASSWORD)) "로그인 안내 응답에 비밀번호 형태 문자열·demo 비밀번호 없음" $noticeRes

    Write-Host "=== [2] demo 로그인·쿠키·me ==="
    $demo = New-Client "203.0.113.10"
    $demoLogin = Login-Api $demo "demo" $env:DEMO_PASSWORD
    $e2eLogs.Add("[2a] demo POST /api/auth/login (X-Forwarded-For: $($demo.Ip)):`n$(Redact-Cookies $demoLogin.Headers.Trim())`n$(Format-Resp $demoLogin 300)")
    Assert-Status $demoLogin 200 "demo 로그인"
    $sessionLine = @($demoLogin.SetCookies | Where-Object { $_ -match '^ZEEKAD_SESSION=' }) | Select-Object -First 1
    Assert-True ($sessionLine -and $sessionLine -match '(?i)\bSecure\b' -and $sessionLine -match '(?i)\bHttpOnly\b' -and $sessionLine -match '(?i)\bSameSite=Lax\b') "ZEEKAD_SESSION 쿠키 Secure/HttpOnly/SameSite=Lax" $demoLogin
    $me = Invoke-Http -Path "/api/auth/me" -Client $demo
    $e2eLogs.Add("[2b] demo GET /api/auth/me -> $(Format-Resp $me 400)")
    $mePatterns = @($me.Json.user.allowedCapturePatterns | Sort-Object)
    $expectedPatterns = @($demoPatterns | Sort-Object)
    Assert-True ($me.Status -eq 200 -and $me.Json.authenticated -eq $true -and $me.Json.user.role -eq "VIEWER" -and $me.Json.user.maskedView -eq $true -and
        ($mePatterns -join ',') -eq ($expectedPatterns -join ',')) "demo /api/auth/me role=VIEWER, maskedView=true, allowedCapturePatterns=[$($expectedPatterns -join ',')]" $me

    Write-Host "=== [3] 스냅샷 데이터·마스킹·증적·리포트·운영 상태 ==="
    $ipHits = [System.Collections.Generic.List[string]]::new()
    $queueByCapture = [ordered]@{}
    $bundleByCapture = @{}
    $e2eLogs.Add("[3-scope] manifest captures=[$($expectedCounts.Keys -join ', ')] demo visible=[$($demoVisibleCaptures -join ', ')] hidden=[$($demoHiddenCaptures -join ', ')]")
    Assert-True ($demoVisibleCaptures -contains $demoLabCapture) "demo에게 보이는 캡처에 $demoLabCapture 포함(manifest 기준 $($demoVisibleCaptures.Count)개)"
    $defaultQueue = Invoke-Http -Path "/api/incidents" -Client $demo
    Assert-Status $defaultQueue 200 "demo 인시던트 목록(캡처 지정 없음)"
    $demoAllowed = @($defaultQueue.Json.allowedCaptures | Sort-Object)
    $e2eLogs.Add("[3-scope] demo GET /api/incidents -> HTTP $($defaultQueue.Status) allowedCaptures=[$($demoAllowed -join ', ')]")
    Assert-True (($demoAllowed -join ',') -eq ((@($demoVisibleCaptures) | Sort-Object) -join ',')) "demo 캡처 목록 = 보이는 캡처 $($demoVisibleCaptures.Count)개(숨김 $($demoHiddenCaptures.Count)개 없음)" $defaultQueue
    foreach ($hiddenCap in $demoHiddenCaptures) {
        $hiddenQueue = Invoke-Http -Path "/api/incidents?captureId=$hiddenCap" -Client $demo
        $e2eLogs.Add("[3-scope] demo GET /api/incidents?captureId=$hiddenCap -> $(Format-Resp $hiddenQueue 200)")
        Assert-Status $hiddenQueue 403 "demo $hiddenCap 목록 직접 조회 거부"
        $hiddenRow = (Invoke-Psql "zeekad" "SELECT job_id || '/' || queue_rank FROM dashboard.latest_incident_queue WHERE capture_id = '$hiddenCap' ORDER BY queue_rank LIMIT 1").Output.Trim()
        Assert-True ($hiddenRow -match '^\d+/\d+$') "$hiddenCap 인시던트가 스냅샷에 있음(직접 조회 대상)"
        $hiddenJob, $hiddenRank = $hiddenRow -split '/'
        $hiddenDetail = Invoke-Http -Path "/api/incidents/$hiddenJob/rank/$hiddenRank" -Client $demo
        $e2eLogs.Add("[3-scope] demo GET /api/incidents/$hiddenJob/rank/$hiddenRank ($hiddenCap) -> $(Format-Resp $hiddenDetail 200)")
        Assert-Status $hiddenDetail 403 "demo $hiddenCap 상세 직접 조회 거부"
    }
    foreach ($cap in $demoVisibleCaptures) {
        $q = Invoke-Http -Path "/api/incidents?captureId=$cap" -Client $demo
        Assert-Status $q 200 "demo 인시던트 목록 $cap"
        $items = @($q.Json.incidents)
        $queueByCapture[$cap] = $items
        $bundleByCapture[$cap] = [string]$q.Json.selectedJob.bundleId
        Find-UnmaskedIpv4 $q.Json "queue[$cap]" $ipHits
        $sampleHost = if ($items.Count) { $items[0].hostIp } else { "" }
        $e2eLogs.Add("[3a] demo GET /api/incidents?captureId=$cap -> HTTP $($q.Status) maskedView=$($q.Json.maskedView) job=$($q.Json.selectedJob.jobId) incidents=$($items.Count) (manifest $($expectedCounts[$cap])) hasReport=$(@($items | Where-Object { $_.hasReport }).Count) sample hostIp=$sampleHost")
        Assert-True ($q.Json.maskedView -eq $true) "demo 인시던트 목록 maskedView ($cap)" $q
        Assert-True ($items.Count -eq $expectedCounts[$cap]) "인시던트 건수 $cap = 매니페스트 $($expectedCounts[$cap])" $q
    }
    $detailTargets = [System.Collections.Generic.List[object]]::new()
    foreach ($cap in $queueByCapture.Keys) { if ($queueByCapture[$cap].Count) { $detailTargets.Add($queueByCapture[$cap][0]) } }
    $withReport = @($queueByCapture.Values | ForEach-Object { $_ } | Where-Object { $_.hasReport }) | Select-Object -First 3
    foreach ($r in $withReport) { $detailTargets.Add($r) }
    # T22: 실습망 lab-20261119는 따로 본다(AI 리포트가 있는 사건 상세 1건 이상, 증적 available=true 1건 이상).
    $labWithReport = @(@($queueByCapture[$demoLabCapture]) | Where-Object { $_.hasReport }) | Select-Object -First 3
    foreach ($r in $labWithReport) { $detailTargets.Add($r) }
    $labReportOk = 0; $labEvidenceOk = 0
    $evidenceOk = 0; $reportOk = 0; $slackCount = 0; $sendDecisionCount = 0
    $evidenceStructuredOk = 0
    $expectedProtocolLogKeys = @("dns", "ftp", "smb", "ssh", "tls", "http", "ntlm", "dce_rpc", "kerberos")
    foreach ($t in $detailTargets) {
        $d = Invoke-Http -Path "/api/incidents/$($t.jobId)/rank/$($t.queueRank)" -Client $demo
        Assert-Status $d 200 "demo 인시던트 상세 $($t.jobId)/rank/$($t.queueRank)"
        Find-UnmaskedIpv4 $d.Json "detail[$($t.jobId)/$($t.queueRank)]" $ipHits
        $dd = $d.Json.detail
        if ($dd.evidence.available -eq $true) { $evidenceOk++ }
        if ($dd.report.present -eq $true) { $reportOk++ }
        if ($t.captureId -eq $demoLabCapture) {
            if ($dd.evidence.available -eq $true) { $labEvidenceOk++ }
            if ($dd.report.present -eq $true) { $labReportOk++ }
        }
        $slackCount += @($dd.slackDeliveries).Count
        if ($null -ne $dd.sendDecision) { $sendDecisionCount++ }
        $e2eLogs.Add("[3b] demo GET /api/incidents/$($t.jobId)/rank/$($t.queueRank) ($($t.captureId)) -> HTTP $($d.Status) maskedView=$($d.Json.maskedView) evidence.available=$($dd.evidence.available) connectionCount=$($dd.evidence.connectionCount) topPeers=$(@($dd.evidence.topPeers).Count) report.present=$($dd.report.present) sendDecision=$([bool]$dd.sendDecision) slackDeliveries=$(@($dd.slackDeliveries).Count) hostIp=$($dd.incident.hostIp)")
        if ($dd.evidence.available -eq $true) {
            # T16: 증적 요약 정형 칸(evidence.v1 실제 키 매핑)이 채워졌는지 본다.
            $ev = $dd.evidence
            $transportN = @($ev.transportCounts.PSObject.Properties).Count
            $connStateN = @($ev.connStateCounts.PSObject.Properties).Count
            $topPortsN = @($ev.topPorts).Count
            $limitsN = @($ev.limits).Count
            $protoKeys = @($ev.protocolLogs | Where-Object { $null -ne $_.metrics } | ForEach-Object { $_.protocol } | Sort-Object)
            $protoOk = (($protoKeys -join ',') -eq ((@($expectedProtocolLogKeys) | Sort-Object) -join ','))
            $e2eLogs.Add("[3b-evidence] $($t.jobId)/rank/$($t.queueRank) bytesSent=$($ev.bytesSent) bytesReceived=$($ev.bytesReceived) connectionCount=$($ev.connectionCount) transport=$transportN connState=$connStateN topPorts=$topPortsN limits=$limitsN protocolLogs=[$($protoKeys -join ',')] uniquePeers=$($ev.uniquePeers) uniquePorts=$($ev.uniquePorts)")
            Assert-True (($null -ne $ev.bytesSent) -and ($null -ne $ev.bytesReceived) -and ($null -ne $ev.connectionCount)) "증적 바이트·세션 수 정형 칸 채워짐 $($t.jobId)/rank/$($t.queueRank)" $d
            Assert-True (($transportN -ge 1) -and ($connStateN -ge 1) -and ($topPortsN -ge 1) -and ($limitsN -ge 1)) "증적 전송 계층·세션 상태·상위 포트·관측 한계 1개 이상 $($t.jobId)/rank/$($t.queueRank)" $d
            Assert-True $protoOk "증적 프로토콜 로그 키 9개($($expectedProtocolLogKeys -join ',')) $($t.jobId)/rank/$($t.queueRank)" $d
            $evidenceStructuredOk++
        }
    }
    Assert-True ($evidenceOk -ge 1) "인시던트 상세 증적 available=true 1건 이상(근거 API 동작)"
    Assert-True ($evidenceStructuredOk -eq $evidenceOk) "증적 available=true 상세 모두 정형 칸 채워짐($evidenceStructuredOk/$evidenceOk)"
    Assert-True ($reportOk -ge 1) "리포트가 있는 인시던트 상세에서 리포트 표시 1건 이상"
    $e2eLogs.Add("[3b-lab] $demoLabCapture details with hasReport=$(@($labWithReport).Count) report.present=$labReportOk evidence.available=$labEvidenceOk")
    Assert-True ($labReportOk -ge 1) "$demoLabCapture AI 리포트가 있는 사건 상세 1건 이상"
    Assert-True ($labEvidenceOk -ge 1) "$demoLabCapture 증적 available=true 1건 이상"
    $ops = Invoke-Http -Path "/api/operations" -Client $demo
    Assert-Status $ops 200 "demo /api/operations"
    Find-UnmaskedIpv4 $ops.Json "operations" $ipHits
    $fb = @($ops.Json.feedbackSummaries)
    $e2eLogs.Add("[3c] demo GET /api/operations -> HTTP $($ops.Status) feedbackSummaries=$($fb.Count) captures=[$((@($fb | ForEach-Object { $_.captureId }) | Select-Object -Unique) -join ', ')] slackSummaries=$(@($ops.Json.slackSummaries).Count) bundles=$(@($ops.Json.bundles).Count)")
    Assert-True ($fb.Count -gt 0) "/api/operations feedbackSummaries 있음" $ops
    foreach ($hiddenCap in $demoHiddenCaptures) {
        Assert-True (-not $ops.Body.Contains($hiddenCap)) "demo /api/operations에 $hiddenCap 없음" $ops
    }
    # T22: 공개 전 내용 확인(캡처에 묶이지 않은 VIEWER 응답)용 사본. 쿠키·비밀번호는 들어 있지 않다.
    Save-Evidence "viewer-operations.json" $ops.Body
    $reviewsRes = Invoke-Http -Path "/api/reviews" -Client $demo
    $e2eLogs.Add("[3c] demo GET /api/reviews -> HTTP $($reviewsRes.Status)")
    Save-Evidence "viewer-reviews.json" ("HTTP $($reviewsRes.Status)`n" + $reviewsRes.Body)
    # T21: 목록의 경보 발송(alerted, 사건 알림 Slack 기록) 수가 캡처마다 feedback_summary 'all' 행 alerted와 같다(같은 식).
    #      'all' 행이 둘 이상이면 T20 규칙(목록이 고른 최근 작업과 같은 모델 버전 행)과 비교한다.
    foreach ($cap in $queueByCapture.Keys) {
        $listAlerted = @($queueByCapture[$cap] | Where-Object { $_.alerted -eq $true }).Count
        $listWouldSend = @($queueByCapture[$cap] | Where-Object { $_.zeekadWouldSend -eq $true }).Count
        $missing = @($queueByCapture[$cap] | Where-Object { $null -eq $_.alerted }).Count
        $allRows = @($fb | Where-Object { $_.captureId -eq $cap -and $_.zeekadPickedBy -eq 'all' })
        $allCount = $allRows.Count
        if ($allRows.Count -gt 1) { $allRows = @($allRows | Where-Object { $_.bundleId -eq $bundleByCapture[$cap] }) }
        $kpi = if ($allRows.Count -eq 1) { [int64]$allRows[0].alerted } else { $null }
        $e2eLogs.Add("[3e] $cap list alerted=$listAlerted (wouldSend=$listWouldSend, alerted 필드 없음 $missing) feedback_summary 'all' rows=$allCount used bundle=$(if ($allRows.Count -eq 1) { $allRows[0].bundleId } else { '-' }) alerted=$kpi")
        Assert-True ($missing -eq 0) "목록 항목마다 alerted 필드 있음 ($cap)" $ops
        Assert-True ($allRows.Count -eq 1 -and $listAlerted -eq $kpi) "목록 경보 발송 수 = feedback_summary 'all' alerted ($($cap): $listAlerted vs $kpi)" $ops
    }
    # T21: dashboard.slack_deliveries가 zeekad.slack_delivery를 행 손실 없이 옮기는지(뷰 정의·행 수·report_version 대응) 증거를 남긴다.
    $sdDef = (Invoke-Psql "zeekad" "SELECT pg_get_viewdef('dashboard.slack_deliveries'::regclass, true)").Output
    $sdCounts = (Invoke-Psql "zeekad" "SELECT (SELECT count(*) FROM zeekad.slack_delivery) || '|' || (SELECT count(*) FROM dashboard.slack_deliveries) || '|' || (SELECT count(*) FROM zeekad.slack_delivery d WHERE d.report_version !~~ 'status:%') || '|' || (SELECT count(*) FROM dashboard.slack_deliveries s WHERE s.zeekad_message_version IS NOT NULL AND s.zeekad_message_version NOT LIKE 'status:%')").Output.Trim()
    $sdAlerted = (Invoke-Psql "zeekad" "SELECT string_agg(capture_id || '=' || fs_alerted || '/' || list_alerted, ',' ORDER BY capture_id) FROM (SELECT f.capture_id, f.alerted AS fs_alerted, (SELECT count(*) FROM dashboard.latest_incident_queue l WHERE l.capture_id = f.capture_id AND l.bundle_id = f.bundle_id AND EXISTS (SELECT 1 FROM dashboard.slack_deliveries s WHERE s.incident_id = l.incident_id AND s.zeekad_message_version IS NOT NULL AND s.zeekad_message_version NOT LIKE 'status:%')) AS list_alerted FROM dashboard.feedback_summary f WHERE f.zeekad_picked_by = 'all') x").Output.Trim()
    Save-Evidence "slack_deliveries-viewdef.txt" ("# 리허설 DB(스냅샷 복원) pg_get_viewdef('dashboard.slack_deliveries') — T21`n$($sdDef.Trim())`n`n" +
        "# 행 수: zeekad.slack_delivery | dashboard.slack_deliveries | 원본 report_version !~~ 'status:%' | 뷰 zeekad_message_version IS NOT NULL AND NOT LIKE 'status:%'`n$sdCounts`n`n" +
        "# 캡처별 feedback_summary 'all' alerted / 같은 식(dashboard.slack_deliveries)으로 센 수`n$sdAlerted`n")
    $sdParts = $sdCounts -split '\|'
    $e2eLogs.Add("[3f] slack_deliveries rows source|view|source non-status|view non-status = $sdCounts; per-capture fs/list = $sdAlerted")
    Assert-True ($sdParts.Count -eq 4 -and $sdParts[0] -eq $sdParts[1] -and $sdParts[2] -eq $sdParts[3]) "dashboard.slack_deliveries가 zeekad.slack_delivery 행을 모두 옮기고 상태 알림 제외 수가 같다"
    Assert-True ([bool]($sdDef -match 'report_version\s+AS\s+zeekad_message_version')) "뷰 열 대응 report_version -> zeekad_message_version"
    $e2eLogs.Add("[3d] details checked=$($detailTargets.Count) evidence.available=$evidenceOk report.present=$reportOk sendDecision=$sendDecisionCount slackDeliveries=$slackCount; unmasked IPv4 JSON paths=$($ipHits.Count)$(if ($ipHits.Count) { ' ' + (($ipHits | Select-Object -First 20) -join ', ') })")
    Assert-True ($ipHits.Count -eq 0) "demo 응답(큐·상세·운영) 전체에 가려지지 않은 IPv4 없음"

    Write-Host "=== [4] demo 쓰기 거부(유효 CSRF) ==="
    $first = $queueByCapture.Values | ForEach-Object { $_ } | Select-Object -First 1
    $csrfControl = { param($label)
        $c = Invoke-Http -Path "/api/auth/login" -Method POST -Client $demo -Csrf -JsonBody @{ username = "csrf-control-nonexistent"; password = "x" }
        $e2eLogs.Add("[4-control:$label] same session + same X-XSRF-TOKEN POST /api/auth/login(없는 계정) -> $(Format-Resp $c 160)")
        Assert-ApiError $c 401 "INVALID_CREDENTIALS" "CSRF 대조 요청($label): 같은 토큰이 CSRF 검사를 통과해 앱 인증 단계(401)에 도달"
    }
    $statusBefore = (Invoke-Psql "zeekad" "SELECT (SELECT count(*) FROM zeekad.incident_status) || '/' || (SELECT count(*) FROM zeekad.incident_status_history) || '/' || (SELECT count(*) FROM zeekad.analyst_review)").Output.Trim()
    & $csrfControl "before"
    $writeProbes = @(
        @{ Label = "POST transition"; Path = "/api/incidents/$($first.jobId)/rank/$($first.queueRank)/transition"; Method = "POST"; Body = @{ toStatus = "investigating"; reason = "portfolio-demo-write-test" } },
        @{ Label = "POST /api/reviews/decide"; Path = "/api/reviews/decide"; Method = "POST"; Body = @{ jobId = $first.jobId; incidentId = $first.incidentId; action = "confirm" } },
        @{ Label = "POST review-decision"; Path = "/api/incidents/$($first.jobId)/rank/$($first.queueRank)/review-decision"; Method = "POST"; Body = @{ action = "confirm" } },
        @{ Label = "GET /api/admin/users"; Path = "/api/admin/users"; Method = "GET"; Body = $null },
        @{ Label = "POST /api/admin/users"; Path = "/api/admin/users"; Method = "POST"; Body = @{ username = "demo-escalate"; displayName = "x"; password = "xxxxxxxx"; role = "ADMIN"; capturePatterns = @("*") } }
    )
    foreach ($w in $writeProbes) {
        $res = if ($w.Method -eq "GET") { Invoke-Http -Path $w.Path -Client $demo } else { Invoke-Http -Path $w.Path -Method $w.Method -Client $demo -Csrf -JsonBody $w.Body }
        $e2eLogs.Add("[4] demo $($w.Label) (valid X-XSRF-TOKEN): $(Format-Resp $res 200)")
        Assert-ApiError $res 403 "FORBIDDEN" "demo $($w.Label) 역할 거부"
    }
    & $csrfControl "after"
    $badCsrf = Invoke-Http -Path $writeProbes[0].Path -Method POST -Client $demo -Csrf -CsrfValue "invalid-token" -JsonBody $writeProbes[0].Body
    $e2eLogs.Add("[4-control:bad-token] (참고) 틀린 X-XSRF-TOKEN으로 같은 전이 요청: $(Format-Resp $badCsrf 160) — CSRF 실패도 403 FORBIDDEN이라 위 대조 요청으로 구별한다")
    $statusAfter = (Invoke-Psql "zeekad" "SELECT (SELECT count(*) FROM zeekad.incident_status) || '/' || (SELECT count(*) FROM zeekad.incident_status_history) || '/' || (SELECT count(*) FROM zeekad.analyst_review)").Output.Trim()
    $e2eLogs.Add("[4] zeekad incident_status/incident_status_history/analyst_review rows before=$statusBefore after=$statusAfter")
    Assert-True ($statusBefore -eq $statusAfter) "demo 쓰기 시도 뒤 zeekad 상태·검토 행 수 변화 없음"

    Write-Host "=== [5] 다른 계정 비활성 ==="
    $i = 21
    foreach ($acct in @(@("viewer1", "BOOTSTRAP_VIEWER1_PASSWORD"), @("analyst1", "BOOTSTRAP_ANALYST1_PASSWORD"), @("analyst2", "BOOTSTRAP_ANALYST2_PASSWORD"), @("admin", "BOOTSTRAP_ADMIN_PASSWORD"))) {
        $c = New-Client "203.0.113.$i"; $i++
        $res = Login-Api $c $acct[0] (Get-Item "env:$($acct[1])").Value
        $e2eLogs.Add("[5] $($acct[0]) login with its own .env password: $(Format-Resp $res 200)")
        Assert-ApiError $res 403 "ACCOUNT_DISABLED" "$($acct[0]) 로그인 불가(비활성)"
    }

    Write-Host "=== [6] 계정 잠금 꺼짐 ==="
    for ($k = 1; $k -le 6; $k++) {
        $c = New-Client "198.51.100.$(60 + $k)"
        $res = Login-Api $c "demo" "wrong-password-$k"
        $e2eLogs.Add("[6] demo wrong password #$k (X-Forwarded-For: $($c.Ip)): $(Format-Resp $res 160)")
        Assert-ApiError $res 401 "INVALID_CREDENTIALS" "demo 틀린 비밀번호 #$k (잠금 없이 401)"
    }
    $failState = (Invoke-Psql "zeekad_dashboard" "SELECT failed_attempts, locked_until IS NULL FROM users WHERE username = 'demo'").Output.Trim()
    $c = New-Client "198.51.100.70"
    $res = Login-Api $c "demo" $env:DEMO_PASSWORD
    $e2eLogs.Add("[6] demo users.failed_attempts|locked_until IS NULL before correct login: $failState`n[6] demo correct password after 6 failures: $(Format-Resp $res 160)")
    Assert-Status $res 200 "틀린 비밀번호 6회 뒤 demo 정상 로그인"

    Write-Host "=== [7] 로그인 속도 제한·클라이언트 IP 위조 방지 ==="
    $limitedIp = "203.0.113.77"
    $statuses = @()
    $lc = New-Client $limitedIp
    [void](Invoke-Http -Path "/api/auth/csrf" -Client $lc)
    for ($k = 1; $k -le 12; $k++) {
        $statuses += (Invoke-Http -Path "/api/auth/login" -Method POST -Client $lc -Csrf -JsonBody @{ username = "rate-limit-probe"; password = "x" }).Status
    }
    $first429 = [Array]::IndexOf($statuses, 429) + 1
    $e2eLogs.Add("[7a] 12 x POST /api/auth/login from $limitedIp -> [$($statuses -join ', ')] (first 429 at #$first429; .env.portfolio.example $((Get-Content .env.portfolio.example | Select-String '^PORTFOLIO_LOGIN_(RATE|BURST)=' | ForEach-Object { $_.Line }) -join ' '))")
    Assert-True ($first429 -ge 2 -and $first429 -le 8 -and @($statuses | Where-Object { $_ -ne 429 -and $_ -ne 401 }).Count -eq 0) "한 클라이언트 IP 한도 초과 시 429"
    $other = New-Client "203.0.113.78"
    $otherRes = Login-Api $other "rate-limit-other" "x"
    $e2eLogs.Add("[7b] right after, other client IP 203.0.113.78: $(Format-Resp $otherRes 120)")
    Assert-ApiError $otherRes 401 "INVALID_CREDENTIALS" "다른 클라이언트 IP는 속도 제한 영향 없음"
    $spoof = Invoke-Http -Path "/api/auth/login" -Method POST -Client $lc -Xff "1.2.3.4, $limitedIp" -Csrf -JsonBody @{ username = "rate-limit-probe"; password = "x" }
    $e2eLogs.Add("[7c] same client with forged prefix X-Forwarded-For: 1.2.3.4, $limitedIp -> HTTP $($spoof.Status)")
    Assert-Status $spoof 429 "X-Forwarded-For 앞부분 위조로 속도 제한 우회 불가"
    $auditIp = "203.0.113.90"
    $ac = New-Client $auditIp
    [void](Invoke-Http -Path "/api/auth/csrf" -Client $ac)
    $acRes = Invoke-Http -Path "/api/auth/login" -Method POST -Client $ac -Xff "1.2.3.4, $auditIp" -Csrf -JsonBody @{ username = "demo"; password = $env:DEMO_PASSWORD } -ExtraHeaders @("Forwarded: for=192.0.2.66", "X-Real-IP: 192.0.2.67")
    Assert-Status $acRes 200 "위조 X-Forwarded-For·Forwarded·X-Real-IP를 붙인 demo 로그인"
    $auditRow = (Invoke-Psql "zeekad_dashboard" "SELECT client_ip FROM audit_logs WHERE action_type = 'LOGIN_SUCCESS' AND actor_username = 'demo' ORDER BY id DESC LIMIT 1").Output.Trim()
    $e2eLogs.Add("[7d] demo login with X-Forwarded-For: 1.2.3.4, $auditIp + Forwarded: for=192.0.2.66 + X-Real-IP: 192.0.2.67 -> HTTP $($acRes.Status); latest LOGIN_SUCCESS audit client_ip=$auditRow")
    Assert-True ($auditRow -eq $auditIp) "감사 로그 IP가 위조 값이 아니라 클라이언트 IP($auditIp)"

    Write-Host "=== [8] WAF 차단 ==="
    $wafProbes = @(
        @{ Id = "pf-q-sqli"; Label = "query SQLi (?asset=' OR 1=1--)"; Path = "/api/incidents?asset=%27%20OR%201%3D1--" },
        @{ Id = "pf-q-xss"; Label = "query XSS (?asset=<script>alert(1)</script>)"; Path = "/api/incidents?asset=%3Cscript%3Ealert(1)%3C%2Fscript%3E" },
        @{ Id = "pf-q-traversal"; Label = "query path traversal (?asset=../../etc/passwd)"; Path = "/api/incidents?asset=../../etc/passwd" }
    )
    $wc = New-Client "198.51.100.80"
    foreach ($probe in $wafProbes) {
        $probeRes = Invoke-Http -Path $probe.Path -Client $wc -ProbeId $probe.Id
        $wafEvidence = Assert-WafBlocked $probeRes $probe.Id "WAF $($probe.Label)"
        $e2eLogs.Add("[8] WAF $($probe.Label): $(Format-Resp $probeRes 120)`n    $wafEvidence")
    }
    $jc = New-Client "198.51.100.81"
    [void](Invoke-Http -Path "/api/auth/csrf" -Client $jc)
    $jsonProbes = @(
        @{ Id = "pf-body-sqli"; Label = "JSON body SQLi (username=admin' OR 1=1--)"; Body = '{"username":"admin'' OR 1=1--","password":"x"}' },
        @{ Id = "pf-body-xss"; Label = "JSON body XSS (username=<script>alert(1)</script>)"; Body = '{"username":"<script>alert(1)</script>","password":"x"}' }
    )
    foreach ($probe in $jsonProbes) {
        $probeRes = Invoke-Http -Path "/api/auth/login" -Method POST -Client $jc -Csrf -JsonBody $probe.Body -ProbeId $probe.Id
        $wafEvidence = Assert-WafBlocked $probeRes $probe.Id "WAF $($probe.Label)"
        $e2eLogs.Add("[8] WAF $($probe.Label) with valid XSRF-TOKEN: $(Format-Resp $probeRes 120)`n    $wafEvidence")
    }
    $benign = Invoke-Http -Path "/api/auth/login" -Method POST -Client $jc -Csrf -JsonBody @{ username = "nobody-portfolio"; password = "x" }
    $e2eLogs.Add("[8] (대조) benign JSON login with same CSRF: $(Format-Resp $benign 160)")
    Assert-ApiError $benign 401 "INVALID_CREDENTIALS" "WAF 대조용 정상 JSON 로그인(앱 도달)"

    Write-Host "=== [seed-3] 재시드: 이미 있는 demo 비밀번호 변경(SQL)·비활성 admin 일시 활성화 경로 ==="
    # 운영 중 상태가 어긋난 경우를 흉내 낸다: viewer1이 다시 활성, .env의 DEMO_PASSWORD가 바뀜.
    [void](Invoke-Psql "zeekad_dashboard" "UPDATE users SET enabled = TRUE WHERE username = 'viewer1'")
    $oldDemoPassword = $env:DEMO_PASSWORD
    $env:DEMO_PASSWORD = New-RandomToken 24
    $seed3 = Invoke-NativeCapture "docker" $seedArgs -IgnoreExitCode
    $seed4 = Invoke-NativeCapture "docker" $seedArgs -IgnoreExitCode
    Save-Evidence "seed-run-3.txt" "EXIT_CODE=$($seed3.ExitCode) (viewer1 re-enabled by SQL, DEMO_PASSWORD changed)`n$($seed3.Output)`n--- run 4 ---`nEXIT_CODE=$($seed4.ExitCode)`n$($seed4.Output)"
    $steps3 = @($seed3.Output -split "`r?`n" | Where-Object { $_ -match 'seed: (SQL|API) ' } | ForEach-Object { $_.Trim() })
    $e2eLogs.Add("[seed-3] run3 exit=$($seed3.ExitCode) $([regex]::Match($seed3.Output, 'RESULT: [^\r\n]*').Value)`n    $($steps3 -join "`n    ")`n[seed-3] run4 exit=$($seed4.ExitCode) $([regex]::Match($seed4.Output, 'RESULT: [^\r\n]*').Value)")
    foreach ($expected in @('seed: SQL SET_PASSWORD demo', 'seed: SQL TEMP_ENABLE admin', 'seed: API TOGGLE_ENABLED viewer1 -> disabled', 'seed: SQL DISABLE admin', 'RESULT: CHANGED')) {
        Assert-True ($seed3.ExitCode -eq 0 -and $seed3.Output.Contains($expected)) "재시드 단계 '$expected'`n$($seed3.Output)"
    }
    Assert-True ($seed4.ExitCode -eq 0 -and $seed4.Output -match 'RESULT: NO_CHANGES') "재시드 뒤 다시 실행하면 변경 없음"
    $newLogin = Login-Api (New-Client "198.51.100.90") "demo" $env:DEMO_PASSWORD
    $oldLogin = Login-Api (New-Client "198.51.100.91") "demo" $oldDemoPassword
    $v1Login = Login-Api (New-Client "198.51.100.92") "viewer1" $env:BOOTSTRAP_VIEWER1_PASSWORD
    $e2eLogs.Add("[seed-3] demo new password -> HTTP $($newLogin.Status); old password -> HTTP $($oldLogin.Status) $($oldLogin.Json.code); viewer1 -> HTTP $($v1Login.Status) $($v1Login.Json.code)")
    Assert-Status $newLogin 200 "바뀐 DEMO_PASSWORD로 demo 로그인"
    Assert-ApiError $oldLogin 401 "INVALID_CREDENTIALS" "이전 demo 비밀번호 거부"
    Assert-ApiError $v1Login 403 "ACCOUNT_DISABLED" "재시드 뒤 viewer1 비활성"

    $e2eReport = $e2eLogs -join "`n`n"
    Save-Evidence "portfolio-e2e.txt" $e2eReport
    Write-Host "-> 포트폴리오 리허설 E2E [0]~[8]·재시드 통과"

    if (-not $SkipZap) {
        Write-Host "=== [9] OWASP ZAP 베이스라인 (https://nginx-waf:8443/, 리허설 스택 네트워크 안) ==="
        $zapDir = Join-Path $ReportFullDir "zap"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $zapDir
        New-Item -ItemType Directory -Force -Path $zapDir | Out-Null
        $zapRes = Invoke-NativeCapture "docker" @("run", "--rm", "--network", $networkName, "-v", "${zapDir}:/zap/wrk:rw", "ghcr.io/zaproxy/zaproxy:stable", "zap-baseline.py", "-t", "https://nginx-waf:8443/", "-J", "zap-baseline.json", "-r", "zap-baseline.html", "-w", "zap-baseline.md") -IgnoreExitCode
        $zapJsonPath = Join-Path $zapDir "zap-baseline.json"
        # 판정은 T10(security-scan.ps1)과 같다: High·Medium·Low 0, 허용 예외는 모든 인스턴스 param이 XSRF-TOKEN인 Low 10010뿐.
        $riskCounts = [ordered]@{ High = 0; Medium = 0; Low = 0; Informational = 0 }
        $allowedLines = [System.Collections.Generic.List[string]]::new()
        $alertLines = [System.Collections.Generic.List[string]]::new()
        $zapJsonOk = Test-Path $zapJsonPath
        if ($zapJsonOk) {
            $zapJson = [IO.File]::ReadAllText($zapJsonPath, $utf8NoBom) | ConvertFrom-Json
            foreach ($site in @($zapJson.site)) {
                foreach ($alert in @($site.alerts)) {
                    if (-not $alert) { continue }
                    $riskName = switch ([string]$alert.riskcode) { "3" { "High" } "2" { "Medium" } "1" { "Low" } default { "Informational" } }
                    $instances = @($alert.instances | Where-Object { $_ })
                    $params = @($instances | ForEach-Object { [string]$_.param })
                    $isAllowed = ($riskName -eq "Low" -and [string]$alert.pluginid -eq "10010" -and $instances.Count -gt 0 -and
                        @($params | Where-Object { $_ -cne "XSRF-TOKEN" }).Count -eq 0)
                    if ($isAllowed) {
                        $allowedLines.Add("ALLOWED: 10010 XSRF-TOKEN (instances=$($instances.Count))")
                        $alertLines.Add("- [Low, ALLOWED] $($alert.pluginid) $($alert.name) (instances=$($instances.Count), params=[$(($params | Select-Object -Unique) -join ', ')])")
                        continue
                    }
                    $riskCounts[$riskName]++
                    $alertLines.Add("- [$riskName] $($alert.pluginid) $($alert.name) (instances=$($instances.Count), params=[$(($params | Select-Object -Unique) -join ', ')])")
                }
            }
        }
        $riskLine = "ZAP_RISK_COUNTS High=$($riskCounts.High) Medium=$($riskCounts.Medium) Low=$($riskCounts.Low) Informational=$($riskCounts.Informational)"
        $allowedText = if ($allowedLines.Count) { $allowedLines -join "`n" } else { "ALLOWED: (none)" }
        $zapHeader = "ZAP_EXIT_CODE=$($zapRes.ExitCode)`ntarget=https://nginx-waf:8443/ network=$networkName`n$riskLine (allowed exceptions excluded)`n$allowedText`nzap-baseline.json parsed=$zapJsonOk`n`nAlerts by risk (zap-baseline.json):`n$(if ($alertLines.Count) { $alertLines -join "`n" } else { '(none)' })"
        $zapMd = if (Test-Path (Join-Path $zapDir "zap-baseline.md")) { [IO.File]::ReadAllText((Join-Path $zapDir "zap-baseline.md"), $utf8NoBom) } else { $zapRes.Output }
        Save-Evidence "zap-baseline-summary.md" ("$zapHeader`n`n--- zap-baseline.py output ---`n$($zapRes.Output.Trim())`n`n--- zap-baseline.md ---`n$zapMd")
        Write-Host "-> ZAP exit=$($zapRes.ExitCode) / $riskLine"
        if ($zapRes.ExitCode -eq 1 -or $zapRes.ExitCode -eq 3) { throw "OWASP ZAP 스캔 실패 (exit=$($zapRes.ExitCode))" }
        if (-not $zapJsonOk) { throw "OWASP ZAP 결과 zap-baseline.json이 생성되지 않았습니다" }
        if ($riskCounts.High -gt 0 -or $riskCounts.Medium -gt 0 -or $riskCounts.Low -gt 0) { throw "OWASP ZAP 베이스라인 경고 존재: $riskLine" }
    }

    $stats = (Invoke-NativeCapture "docker" @("stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}}") -IgnoreExitCode).Output -split "`r?`n" | Where-Object { $_ -like "$ProjectName*" }
    Save-Evidence "compose-stats.txt" (($stats -join "`n") + "`n")
    Write-Host "포트폴리오 리허설 검증 통과"
} catch {
    $failed = $true
    $e2eLogs.Add("[FAILED] $($_.Exception.Message)")
    Save-Evidence "portfolio-e2e.txt" ($e2eLogs -join "`n`n")
    Write-Host "[FAILED] $($_.Exception.Message)"
} finally {
    Write-Host "=== 리허설 스택 정리 (down -v) ==="
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("down", "-v")) -IgnoreExitCode)
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmpDir
    foreach ($name in $secretNames + @("BOOTSTRAP_ADMIN_TOTP_SECRET")) { Remove-Item "env:$name" -ErrorAction SilentlyContinue }
}

if ($failed) { exit 1 }
exit 0
