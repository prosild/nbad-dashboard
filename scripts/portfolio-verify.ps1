param(
    [string]$EvidenceDir = "",
    [string]$SnapshotDir = "build/portfolio",
    [string]$ProjectName = "zeekad-portfolio-verify",
    [int]$WafHttpPort = 18480,
    [string]$PublicHost = "soc.example.synology.me",
    [string]$ReportDir = "build/portfolio-verify",
    # T33 노출 확인 결과(exposure.md·exposure-values.txt)를 쓸 폴더. 주면 [T33x]를 돌린다. 실제 값이 들어가므로 커밋하지 않는 곳으로 준다.
    [string]$ExposureDir = "",
    # T39 인시던트 번호 대조 목록(공개 앱 DB에서 읽기 전용으로 내보낸 "번호|sha256(incident_id)" 줄). 주면 [T39c]를 돈다.
    [string]$ExpectedRefsFile = "",
    # T36 빠른 사람 사용 흉내·429 회복 확인 도구(handoff/T36/tools/read-usage.js, playwright-core). 주면 [T36d]를 돌린다.
    [string]$UsageScript = "",
    # T47 응답 시간 비교의 앞 이미지(지금 공개 중인 앱 이미지). 로컬에 없거나 시험 이미지와 같으면 새 이미지 값만 적는다.
    [string]$BaselineAppImage = "zeek-ad-dashboard-app:t49",
    [switch]$SkipZap
)

# 포트폴리오 스택 리허설 검증(로컬 PC). compose.portfolio.yml을 NAS와 같은 구성으로 띄우고(프로젝트 이름만 다름),
# 계정 시드를 두 번 실행한 뒤 DSM 역방향 프록시를 흉내 낸 요청으로 E2E [0]~[8]과 ZAP 베이스라인 [9]를 확인하고 down -v로 정리한다.
# - T61: 네트워크 둘(portfolio-net = nginx-waf·dashboard-app, portfolio-data = 내부 전용)과 capability 없음은 [0] 바로 뒤 [T61a]~[T61d],
#   상태 확인 감사 줄은 끝 무렵 [T61e]가 본다.
# - T52: [T23d]의 우선순위 기준이 중요 자산 규칙을 안다(자산 주소는 앱 DB, 행의 원문 host_ip는 zeekad DB에서 읽는다).
#   [T52a](시드가 중요 자산 목록을 자료 파일과 같게 맞춤)는 재시드 단계 뒤, [T52b]~[T52d](관리자 API 403·지우기 POST가 WAF를 지남·조회자 응답에 이름 없음)는 [T36] 바로 앞에서 본다.
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
$ExposureFullDir = if ($ExposureDir) { Resolve-RepoPath $ExposureDir } else { "" }

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
#      시험 캡처 lab-20261201·첫 VM 실행 lab-20261118 등 나머지는 숨김, 2026-11-21 결정). 정확한 ID는 그 캡처만, 접두사*는 접두사 일치.
# T39: lab-20261122(Kali 공격 6종 + 타깃 VM)를 더하고 시험 뒤 유휴 구간 lab-20261123은 숨긴다(2026-11-23 결정).
#      실습망 단언은 공개 실습망 캡처 목록 전체를 본다. 노출 확인(-ExposureDir)은 처음 공개하는 lab-20261122를 본다(lab-20261119는 T33에서 봤다).
$demoPatterns = @("cic17-*", "syn1-*", "lab-20261119", "lab-20261122")
$demoLabCaptures = @("lab-20261119", "lab-20261122")
$exposureLabCapture = "lab-20261122"
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
# T61: [T32c]·[T36b]의 일회용 컨테이너(portfolio-net에 붙임)는 파이프라인 이미지의 python을 쓴다.
$probeImage = "zeekad-pipeline:dev"
foreach ($img in @("zeek-ad-dashboard-app:local", "zeek-ad-dashboard-waf:local", $probeImage, "pgvector/pgvector:0.8.1-pg17")) {
    [void](Invoke-NativeCapture "docker" @("image", "inspect", "--format", "{{.Id}}", $img))
}

# --- 리허설 비밀값(실행마다 무작위, 이 프로세스 환경 변수로만 전달. Compose는 셸 환경 변수가 --env-file 값보다 우선한다) ---
$secretNames = @("POSTGRES_SUPERUSER_PASSWORD", "ZEEKAD_API_PASSWORD", "DASHBOARD_RO_PASSWORD", "DASHBOARD_RW_PASSWORD",
    "DASHBOARD_APP_PASSWORD", "DEMO_PASSWORD", "BOOTSTRAP_VIEWER1_PASSWORD", "BOOTSTRAP_ANALYST1_PASSWORD",
    "BOOTSTRAP_ANALYST2_PASSWORD", "BOOTSTRAP_ADMIN_PASSWORD", "TRIAL_ANALYST_PASSWORD", "SANDBOX_RESET_DB_PASSWORD")
foreach ($name in $secretNames) { Set-Item -Path "env:$name" -Value (New-RandomToken 24) }
# demo 허용 캡처는 시드 기본값을 쓴다(셸에 남은 값이 Compose 보간을 덮지 않게 지운다).
Remove-Item -Path "env:DEMO_CAPTURE_PATTERNS" -ErrorAction SilentlyContinue
$env:BOOTSTRAP_ADMIN_TOTP_SECRET = New-RandomBase32 32
$env:PORTFOLIO_SNAPSHOT_DIR = $SnapshotFullDir
$env:PORTFOLIO_HTTP_PORT = "$WafHttpPort"
$env:PORTFOLIO_SERVER_NAME = $PublicHost
# T33: 리허설은 초기화 주기를 1분으로 줄인다.
$env:SANDBOX_RESET_INTERVAL_MINUTES = "1"
# T36: 기존 항목은 호스트 한 IP(같은 X-Forwarded-For)로 /api/ 조회를 많이 보내므로 조회 한도를 크게 덮어 돌린다.
# [T36]에서 이 두 값을 지우고 nginx-waf를 기본값(compose 기본 200r/m·30)으로 다시 만든 뒤 [T36b]·[T36d]를 돌린다.
$readOverride = @{ Rate = "6000r/m"; Burst = "3000" }
$env:PORTFOLIO_READ_RATE = $readOverride.Rate
$env:PORTFOLIO_READ_BURST = $readOverride.Burst

$composeArgs = @("compose", "-p", $ProjectName, "-f", "compose.portfolio.yml", "--env-file", ".env.portfolio.example")
$networkName = "${ProjectName}_portfolio-net"
# T61: 데이터 네트워크(내부 전용). dashboard-app·postgres·api·sandbox-*·demo-seed가 붙고 nginx-waf는 붙지 않는다.
$dataNetworkName = "${ProjectName}_portfolio-data"
# T61: portfolio-net에 붙인 일회용 컨테이너(앱·WAF 말고는 그 네트워크에 붙는 것이 없으므로 "같은 네트워크의 다른 컨테이너"를 이것으로 흉내 낸다).
# 뒤에 "-c <코드> <인자...>"를 붙여 쓴다. 이미지를 내려받지 않는다(--pull never).
$netProbeArgs = @("run", "--rm", "--pull", "never", "--network", $networkName, "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--entrypoint", "python", $probeImage)
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

# 서비스 컨테이너의 한 네트워크 주소(T61부터 dashboard-app은 네트워크가 둘이다). Windows PowerShell 5.1은 네이티브 인자 안 큰따옴표를
# 지우므로 템플릿에 index "이름"을 쓰지 않고 네트워크 전체를 JSON으로 받아 고른다. 그 네트워크에 붙어 있지 않으면 빈 문자열.
function Get-NetIp([string]$Service, [string]$Network) {
    $cid = Get-ServiceContainer $Service
    $nets = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{json .NetworkSettings.Networks}}", $cid)).Output | ConvertFrom-Json
    $n = $nets.PSObject.Properties | Where-Object { $_.Name -eq $Network } | Select-Object -First 1
    if (-not $n) { return "" }
    return [string]$n.Value.IPAddress
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

# 표식을 요청 주소에 붙인다(T59): 쿼리가 이미 있으면 &probe=, 없으면 ?probe=. 표식은 영문·숫자·'-'·'_'만 쓴다.
# WAF 감사 로그는 요청 헤더를 남기지 않으므로 그 요청의 감사 줄은 요청 주소로 찾는다.
function Add-ProbeQuery([string]$Path, [string]$ProbeId) {
    if ($ProbeId -notmatch '^[A-Za-z0-9_-]+$') { throw "표식에 쓸 수 없는 글자가 있습니다(영문·숫자·'-'·'_'만)." }
    $separator = '?'
    if ($Path.Contains('?')) { $separator = '&' }
    return $Path + $separator + "probe=" + $ProbeId
}
# 로그 한 줄이 그 표식의 요청 것인지: 요청 주소의 쿼리 probe=<표식>(뒤에 표식 글자가 이어지지 않음)으로 본다.
function Test-ProbeMark([string]$Line, [string]$ProbeId) {
    if (-not $Line -or -not $ProbeId) { return $false }
    return [regex]::IsMatch($Line, '[?&]probe=' + [regex]::Escape($ProbeId) + '(?![A-Za-z0-9_-])')
}

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
    if ($ProbeId) { $Path = Add-ProbeQuery $Path $ProbeId }
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
        $logLine = $wafLogs -split "`r?`n" | Where-Object { $_.StartsWith('{"transaction"') -and (Test-ProbeMark $_ $ProbeId) } | Select-Object -Last 1
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

# T33 노출 확인(-ExposureDir를 줄 때만): 공개 실습망 캡처의 모든 인시던트에 대해 화면이 부르는 API 응답(큐·목록·상세(근거·증거·보고서·Slack·검토 포함)·
# 담당 후보·에스컬레이션·운영 현황·현황판)을 demo(VIEWER, 마스킹)와 체험 분석가(마스킹 없음)로 받아 JSON 경로 단위로 비교한다.
# demo에서 가려지거나 없고 분석가에서 보이는 값을 모두 모은다. exposure.md에는 필드별 개수와 값 형태만, exposure-values.txt에는 실제 값을 쓴다.
# 두 파일은 공개 저장소에 넣지 않는다(-ExposureDir는 저장소 밖이나 커밋하지 않는 폴더로 준다).
function Get-JsonLeaves($Node, [string]$Path, $Out) {
    if ($null -eq $Node) { $Out[$Path] = '<null>'; return }
    if ($Node -is [string] -or $Node -is [ValueType]) { $Out[$Path] = [string]$Node; return }
    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Node.PSObject.Properties) { Get-JsonLeaves $p.Value "$Path.$($p.Name)" $Out }
        return
    }
    if ($Node -is [System.Collections.IEnumerable]) {
        $i = 0
        foreach ($item in $Node) { Get-JsonLeaves $item "$Path[$i]" $Out; $i++ }
        return
    }
    $Out[$Path] = [string]$Node
}

function Get-ValueShape([string]$V) {
    if ($V -eq '<null>') { return 'null' }
    if ($V -ceq 'True' -or $V -ceq 'False') { return '참·거짓' }
    if ($V -match '^-?\d+(\.\d+)?([eE][-+]?\d+)?$') { return '숫자' }
    if ($V -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}') { return '시각' }
    $m = [regex]::Match($V, '^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$')
    if ($m.Success) {
        $a = [int]$m.Groups[1].Value; $b = [int]$m.Groups[2].Value
        $c = [int]([regex]::Match($V, '^\d{1,3}\.\d{1,3}\.(\d{1,3})\.').Groups[1].Value)
        if ($a -gt 255 -or $b -gt 255 -or $c -gt 255) { return 'IPv4 모양(범위 밖 옥텟)' }
        # T36: 사설 셋 밖의 특수 대역은 "공인"과 따로 센다(RFC 6890 등). 그 밖만 공인이다.
        if ($a -eq 10) { return 'IPv4 사설 10.x' }
        if ($a -eq 192 -and $b -eq 168) { return 'IPv4 사설 192.168.x' }
        if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return 'IPv4 사설 172.16-31.x' }
        if ($a -eq 0) { return 'IPv4 0.0.0.0/8' }
        if ($a -eq 127) { return 'IPv4 루프백 127.0.0.0/8' }
        if ($a -eq 169 -and $b -eq 254) { return 'IPv4 링크 로컬 169.254.0.0/16' }
        if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return 'IPv4 CGNAT 100.64.0.0/10' }
        if ($a -ge 224 -and $a -le 239) { return 'IPv4 멀티캐스트 224.0.0.0/4' }
        if ($a -ge 240) { return 'IPv4 예약·브로드캐스트 240.0.0.0/4' }
        if (($a -eq 192 -and $b -eq 0 -and $c -eq 2) -or ($a -eq 198 -and $b -eq 51 -and $c -eq 100) -or ($a -eq 203 -and $b -eq 0 -and $c -eq 113)) { return 'IPv4 문서용(TEST-NET)' }
        if ($a -eq 198 -and ($b -eq 18 -or $b -eq 19)) { return 'IPv4 성능 시험용 198.18.0.0/15' }
        return 'IPv4 공인'
    }
    if ($V -match '^[0-9a-fA-F:]+:[0-9a-fA-F:]*$' -and $V.Contains('::') -or $V -match '^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$') { return 'IPv6' }
    if ($V -match '^\d{1,3}\.\d{1,3}\.\*\.\*$') { return '가려진 IPv4(앞 두 옥텟)' }
    if ($V -match '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])') { return 'IPv4가 든 문자열' }
    if ($V -match '(?<![\d.])\d{1,3}\.\d{1,3}\.\*\.\*') { return '가려진 IPv4가 든 문자열' }
    if ($V -match '^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$') { return '이메일' }
    if ($V -match '^[a-z][a-z0-9+.-]*://') { return 'URL' }
    if ($V -match '^/\S*$') { return 'URI 경로' }
    if ($V -match '^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$') { return 'MAC' }
    if ($V -match '^(?=.*[A-Za-z])[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+\.?$') { return '호스트·도메인 이름' }
    if ($V -match '^[A-Za-z0-9._-]{1,40}$') { return "짧은 식별자(공백 없음)" }
    return "텍스트($([Math]::Min(9, [int][Math]::Floor($V.Length / 50)) * 50)자대)"
}

function Invoke-T33Exposure($TrialClient) {
    Write-Host "=== [T33x] 노출 확인(demo vs $trialUser, $exposureLabCapture) ==="
    New-Item -ItemType Directory -Force -Path $ExposureFullDir | Out-Null
    $dc = New-Client "198.51.100.240"
    Assert-Status (Login-Api $dc "demo" $env:DEMO_PASSWORD) 200 "[T33x] demo 로그인"
    # T39: 큐를 쪽마다 넘겨 그 캡처의 인시던트를 전부 모은다(표본으로 줄이지 않는다).
    $items = [System.Collections.Generic.List[object]]::new()
    $reqs = [System.Collections.Generic.List[object]]::new()
    $qTotal = -1
    for ($page = 1; $page -le 50; $page++) {
        $qPath = "/api/incidents/queue?period=all&captureId=$exposureLabCapture&size=100&page=$page"
        $q = Invoke-Http -Path $qPath -Client $TrialClient
        Assert-Status $q 200 "[T33x] $trialUser 실습망 큐 $page쪽"
        $qTotal = [int]$q.Json.total
        $reqs.Add(@("queue", $qPath))
        foreach ($it in @($q.Json.items)) { $items.Add($it) }
        if (@($q.Json.items).Count -eq 0 -or $items.Count -ge $qTotal) { break }
    }
    Assert-True ($items.Count -eq $qTotal -and $qTotal -eq $expectedCounts[$exposureLabCapture]) "[T33x] 실습망 큐 전부 모음($($items.Count) = total $qTotal = manifest $($expectedCounts[$exposureLabCapture]))"
    $reqs.Add(@("list", "/api/incidents?captureId=$exposureLabCapture"))
    $reqs.Add(@("reviews", "/api/reviews?captureId=$exposureLabCapture"))
    $reqs.Add(@("operations", "/api/operations?period=all&captureId=$exposureLabCapture"))
    $reqs.Add(@("overview", "/api/dashboard/overview?period=all&captureId=$exposureLabCapture"))
    # T39: 캡처에 묶이지 않은 조회자 응답도 본다(공개 전 내용 목록 8)
    $reqs.Add(@("operations-all", "/api/operations?period=all"))
    $reqs.Add(@("reviews-all", "/api/reviews"))
    $reqs.Add(@("overview-all", "/api/dashboard/overview?period=all"))
    # T47: 호스트 위험도(T46). 조회자는 대역 단위 줄이라 분석가와 줄 수·순서가 다르다(차이가 곧 분석가에게만 보이는 값이다)
    $reqs.Add(@("hosts", "/api/hosts?period=all&captureId=$exposureLabCapture&size=100"))
    $reqs.Add(@("hosts-all", "/api/hosts?period=all&size=100"))
    foreach ($it in $items) {
        $reqs.Add(@("detail", "/api/incidents/$($it.jobId)/rank/$($it.queueRank)"))
        $reqs.Add(@("assignees", "/api/incidents/$($it.jobId)/rank/$($it.queueRank)/assignees"))
        # T47: 상세의 같은 호스트 인시던트(T46)
        $reqs.Add(@("related-host", "/api/incidents/$($it.jobId)/rank/$($it.queueRank)/related-host-incidents"))
    }
    # T39: 공개 전 내용 목록(ㄴ)용으로 demo 응답 원문을 남긴다(실제 값, -ExposureDir 안에만. 커밋하지 않는다).
    $demoRawDir = Join-Path $ExposureFullDir "demo-responses"
    New-Item -ItemType Directory -Force -Path $demoRawDir | Out-Null
    $rawSeq = 0
    $fields = @{}   # "kind path" -> @{ Values = HashSet; Count = n; Demo = HashSet(shapes) }
    $statusLines = [System.Collections.Generic.List[string]]::new()
    $leafTotal = 0
    foreach ($r in $reqs) {
        $tRes = Invoke-Http -Path $r[1] -Client $TrialClient
        $dRes = Invoke-Http -Path $r[1] -Client $dc
        $rawSeq++
        [IO.File]::WriteAllText((Join-Path $demoRawDir ("{0:D4}-{1}.json" -f $rawSeq, $r[0])), ("// GET $($r[1]) -> HTTP $($dRes.Status)`n" + [string]$dRes.Body), $utf8NoBom)
        if ($r[0] -ne 'detail' -and $r[0] -ne 'assignees' -and $r[0] -ne 'related-host') { $statusLines.Add("$($r[0]) $($r[1]): $trialUser HTTP $($tRes.Status), demo HTTP $($dRes.Status)") }
        Assert-Status $tRes 200 "[T33x] $trialUser $($r[1])"
        $tLeaves = [ordered]@{}; Get-JsonLeaves $tRes.Json "" $tLeaves
        $dLeaves = @{}
        if ($dRes.Status -eq 200) { Get-JsonLeaves $dRes.Json "" $dLeaves }
        $leafTotal += $tLeaves.Count
        foreach ($k in $tLeaves.Keys) {
            $v = $tLeaves[$k]
            $dv = if ($dLeaves.ContainsKey($k)) { $dLeaves[$k] } else { $null }
            if ($null -ne $dv -and $dv -ceq $v) { continue }
            $key = "$($r[0]) $($k -replace '\[\d+\]', '[]')"
            if (-not $fields.ContainsKey($key)) { $fields[$key] = @{ Values = [System.Collections.Generic.HashSet[string]]::new(); Count = 0; Demo = [System.Collections.Generic.HashSet[string]]::new() } }
            [void]$fields[$key].Values.Add($v)
            $fields[$key].Count++
            [void]$fields[$key].Demo.Add($(if ($dRes.Status -ne 200) { "demo HTTP $($dRes.Status)" } elseif ($null -eq $dv) { '(없음)' } else { Get-ValueShape $dv }))
        }
    }
    $detailStatus = "detail·assignees·related-host: $($items.Count)건씩(모두 $trialUser 200), demo assignees HTTP $((Invoke-Http -Path "/api/incidents/$($items[0].jobId)/rank/$($items[0].queueRank)/assignees" -Client $dc).Status)"
    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add("# T33 노출 확인: $exposureLabCapture, demo(VIEWER) vs $trialUser(ANALYST)")
    $md.Add("")
    $md.Add("리허설 스택(스냅샷 $((Get-Content (Join-Path $SnapshotFullDir 'zeekad.dump.sha256') -Raw).Substring(0, 12))…), 인시던트 $($items.Count)건, 요청 $($reqs.Count)개(두 계정 각각), $trialUser 응답 값 $($leafTotal)개.")
    $md.Add("demo에서 가려지거나 없거나 다른 값만 센다. 값은 적지 않는다(실제 값은 exposure-values.txt, 커밋하지 않음).")
    $md.Add("")
    $md.Add("- 응답 상태: $($statusLines -join '; '); $detailStatus")
    $md.Add("")
    $md.Add("| 응답 | 필드 경로 | 다른 값 수 | 나온 횟수 | 분석가 값 형태(개수) | demo 쪽 |")
    $md.Add("|---|---|---|---|---|---|")
    $vals = [System.Collections.Generic.List[string]]::new()
    foreach ($key in ($fields.Keys | Sort-Object)) {
        $f = $fields[$key]
        $shapes = ($f.Values | Group-Object { Get-ValueShape $_ } | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', '
        $kind, $path = $key -split ' ', 2
        $md.Add("| $kind | ``$path`` | $($f.Values.Count) | $($f.Count) | $shapes | $((@($f.Demo) | Sort-Object) -join ', ') |")
        $vals.Add("## $key (distinct $($f.Values.Count))")
        foreach ($v in ($f.Values | Sort-Object)) { $vals.Add("  $v") }
    }
    [IO.File]::WriteAllText((Join-Path $ExposureFullDir "exposure.md"), (($md -join "`n") + "`n"), $utf8NoBom)
    [IO.File]::WriteAllText((Join-Path $ExposureFullDir "exposure-values.txt"), (($vals -join "`n") + "`n"), $utf8NoBom)
    $e2eLogs.Add("[T33x] exposure check: $($items.Count) incidents, $($reqs.Count) requests per account, exposed fields=$($fields.Count) -> $ExposureFullDir (exposure.md, exposure-values.txt; values not logged)")
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
    # T33: sandbox-setup 전 sandbox-reset 주기 실행의 로그인 실패(역할 없음 = 미설정)는 복원 오류가 아니다. 따로 센다.
    $resetLoginFails = @($restoreLines | Where-Object { $_ -match 'FATAL:\s+password authentication failed for user "zeekad_sandbox_reset"' })
    $restoreLines = @($restoreLines | Where-Object { $_ -notmatch 'FATAL:\s+password authentication failed for user "zeekad_sandbox_reset"' })
    $restoreErrors = @($restoreLines | Where-Object { $_ -match '(?i)pg_restore: error|ERROR:|FATAL:' })
    $restoreWarnings = @($restoreLines | Where-Object { $_ -match '(?i)warning' })
    Save-Evidence "restore-log.txt" ("errors=$($restoreErrors.Count) warnings=$($restoreWarnings.Count)`n" + ($restoreLines -join "`n") + "`n")
    $e2eLogs.Add("[restore] postgres init log: sandbox-reset login failures before sandbox-setup (expected, not counted)=$($resetLoginFails.Count); errors=$($restoreErrors.Count) warnings=$($restoreWarnings.Count) done=$([bool]($restoreLines -match 'portfolio-restore: done'))$(if ($restoreWarnings.Count) { "`n    " + ($restoreWarnings -join "`n    ") })")
    Assert-True ($restoreErrors.Count -eq 0) "스냅샷 복원 로그 오류 0건"
    Assert-True ([bool]($restoreLines -match 'portfolio-restore: done')) "스냅샷 복원 완료 표지"
    # T39: 복원 끝에 zeekad DB 통계를 만든다(02-restore-snapshot.sh의 ANALYZE)
    $analyzeLines = @($restoreLines | Where-Object { $_ -match 'portfolio-restore: ANALYZE' })
    $lastAnalyzed = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "zeekad", "-AtF", "|", "-c",
        "SELECT count(*) || '|' || count(*) FILTER (WHERE last_analyze IS NOT NULL) FROM pg_stat_user_tables WHERE schemaname = 'zeekad'")) -IgnoreExitCode).Output.Trim()
    $e2eLogs.Add("[restore] ANALYZE lines=[$($analyzeLines -join ' / ')]; zeekad tables (all|last_analyze set)=$lastAnalyzed")
    Assert-True ($analyzeLines.Count -ge 2 -and $lastAnalyzed -match '^(\d+)\|\1$') "[T39] 복원 끝 ANALYZE 실행, zeekad 표 모두 통계 있음 ($lastAnalyzed)"

    # T54: 분석이 끝난 예시 셋(시드 자료 파일). 시드 전 값: 예시가 최신 큐에 있고 상태 행·담당 행이 없으며(신규), 세 표의 행 수를 적어 둔다
    #      (기준선의 행 수를 이 값과 견준다: [T54b]). incident_id에 '|'가 있어 결과 칸 구분자와 겹치므로 ID는 결과로 꺼내지 않는다.
    $examples54 = @((Get-Content "docker/portfolio/seed/demo_examples.json" -Raw -Encoding UTF8 | ConvertFrom-Json).examples)
    $ids54Sql = ($examples54 | ForEach-Object { "'$($_.incidentId)'" }) -join ", "
    $pre54 = (Invoke-Psql "zeekad" ("SELECT (SELECT count(*) FROM zeekad.incident_status) || '/' || (SELECT count(*) FROM zeekad.incident_status_history) || '/' || (SELECT count(*) FROM zeekad.analyst_review) " +
        "|| ' examples: queue=' || (SELECT count(*) FROM dashboard.latest_incident_queue WHERE incident_id IN ($ids54Sql)) || ' status=' || (SELECT count(*) FROM zeekad.incident_status WHERE incident_id IN ($ids54Sql))")).Output.Trim()
    $preAssign54 = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM incident_assignments WHERE incident_id IN ($ids54Sql)").Output.Trim()
    $e2eLogs.Add("[T54] before seed: zeekad incident_status/incident_status_history/analyst_review rows and examples = $pre54; example assignment rows=$preAssign54 (examples: $(@($examples54 | ForEach-Object { "$($_.key)=$($_.resolution)" }) -join ', '))")
    Assert-True ($examples54.Count -eq 3 -and $pre54 -match ' examples: queue=3 status=0$' -and $preAssign54 -eq '0') "[T54] 시드 전 예시 셋은 최신 큐에 있고 신규·담당 행 없음 ($pre54, assignment rows=$preAssign54)"
    $pre54Rows = @(($pre54 -split ' ')[0] -split '/' | ForEach-Object { [long]$_ })

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

    # [T54a] 시드 1차가 예시 셋을 앱 API로 기록했다: 상태·판정·마지막 변경자, 정탐 둘의 대응 조치(none, demo-analyst), 담당자 있는 행 0,
    #        demo-analyst 비활성, 이력 순서(착수 → 자동 담당 → (정탐) 조치 → 해제 → 종결). 2차는 그대로 둔다(로그인 없음은 위 단언).
    Write-Host "=== [T54a] 분석이 끝난 예시 셋(시드가 앱 API로 기록) ==="
    Assert-True ($seed1.Output -match 'examples: applied=3 kept=0 skipped=0') "[T54a] 시드 1차 examples: applied=3 kept=0 skipped=0`n$($seed1.Output)"
    Assert-True ($seed2.Output -match 'examples: applied=0 kept=3 skipped=0') "[T54a] 시드 2차 examples: applied=0 kept=3 skipped=0"
    $t54aLines = @(); $t54aBad = @()
    foreach ($ex in $examples54) {
        $id = $ex.incidentId
        # 상태는 zeek_AD 상태 표에서 읽는다(계약 뷰 dashboard.incident_status는 인시던트 × 성공 작업마다 한 행이고 상태 행이 없으면 open으로 채운다)
        $st = (Invoke-Psql "zeekad" "SELECT status || ':' || COALESCE(resolution, '') || ':' || updated_by FROM zeekad.incident_status WHERE incident_id = '$id'").Output.Trim()
        $events = @()
        foreach ($q in @(
                @("zeekad", "SELECT to_status || '=' || (EXTRACT(EPOCH FROM changed_at) * 1000000)::bigint FROM dashboard.incident_status_history WHERE incident_id = '$id' AND actor = 'demo-analyst'"),
                @("zeekad_dashboard", "SELECT 'action:' || action_type || '=' || (EXTRACT(EPOCH FROM recorded_at) * 1000000)::bigint FROM incident_response_actions WHERE incident_id = '$id' AND actor_username = 'demo-analyst'"),
                @("zeekad_dashboard", "SELECT (CASE WHEN to_user_id IS NULL THEN 'release' ELSE 'assign:' || reason END) || '=' || (EXTRACT(EPOCH FROM changed_at) * 1000000)::bigint FROM incident_assignment_history WHERE incident_id = '$id' AND actor_username = 'demo-analyst'"))) {
            $events += @((Invoke-Psql $q[0] $q[1]).Output -split "`r?`n" | Where-Object { $_ -match '=\d+$' } | ForEach-Object { $p = $_ -split '=', 2; [pscustomobject]@{ Name = $p[0]; At = [long]$p[1] } })
        }
        $order = (@($events | Sort-Object At | ForEach-Object { $_.Name }) -join ',')
        $expOrder = if ($ex.resolution -eq 'true_positive') { "investigating,assign:auto_on_start,action:$($ex.responseAction.action),release,closed" } else { "investigating,assign:auto_on_start,release,closed" }
        $t54aLines += "$($ex.key) $($ex.resolution): status=$st order=$order"
        if ($st -ne "closed:$($ex.resolution):demo-analyst" -or $order -ne $expOrder) { $t54aBad += "$($ex.key) status=$st order=$order (expected closed:$($ex.resolution):demo-analyst, $expOrder)" }
    }
    $assigned54 = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM incident_assignments WHERE assignee_user_id IS NOT NULL").Output.Trim()
    $released54 = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) || ':' || count(*) FILTER (WHERE assignee_user_id IS NULL AND assigned_by = 'demo-analyst') FROM incident_assignments WHERE incident_id IN ($ids54Sql)").Output.Trim()
    $acct54 = (Invoke-Psql "zeekad_dashboard" ("SELECT u.role || '|' || u.enabled || '|' || (u.display_name = U&'\C2DC\C5F0 \BD84\C11D\AC00') || '|' || COALESCE(string_agg(a.capture_pattern, ',' ORDER BY a.capture_pattern), '') " +
        "FROM users u LEFT JOIN user_capture_access a ON a.user_id = u.id WHERE u.username = 'demo-analyst' GROUP BY u.id")).Output.Trim()
    $audit54 = (Invoke-Psql "zeekad_dashboard" "SELECT action_type || '=' || count(*) FROM audit_logs WHERE actor_username = 'demo-analyst' GROUP BY action_type ORDER BY action_type").Output.Trim() -replace "`r?`n", ', '
    $e2eLogs.Add("[T54a] examples after seed:`n       $($t54aLines -join "`n       ")`n       assignment rows with an assignee (all)=$assigned54; example assignment rows (all:released by demo-analyst)=$released54`n       demo-analyst (role|enabled|display name ok|patterns)=$acct54; audit rows by demo-analyst: $audit54")
    Assert-True ($t54aBad.Count -eq 0) "[T54a] 예시 셋: 종결·판정·마지막 변경자 demo-analyst, 이력 순서 착수 → 자동 담당 → (정탐) 조치 → 해제 → 종결 ($($t54aBad -join '; '))"
    Assert-True ($assigned54 -eq '0' -and $released54 -eq '3:3') "[T54a] 담당자 있는 담당 행 0, 예시 셋의 담당 행은 demo-analyst가 해제한 행 ($assigned54, $released54)"
    Assert-True ($acct54 -eq 'ANALYST|false|true|lab-20261119,lab-20261122') "[T54a] demo-analyst: ANALYST·비활성·표시 이름·허용 캡처 ($acct54)"
    Assert-True ($audit54 -match '(^|, )INCIDENT_RESPONSE_ACTION=2(,|$)' -and $audit54 -match '(^|, )INCIDENT_STATUS_TRANSITION=6(,|$)' -and $audit54 -match '(^|, )LOGIN_SUCCESS=1(,|$)') "[T54a] demo-analyst 감사: 로그인 1, 상태 변경 6, 대응 조치 2 ($audit54)"

    # T23: 숨김 캡처 = 리허설 DB dashboard.scoring_jobs의 전체 캡처 ID - 공개 캡처(manifest 사건 수 키가 아니다. 최신 작업 사건이 0건인 캡처도 빠지지 않게).
    $dbCaptures = @((Invoke-Psql "zeekad" "SELECT DISTINCT capture_id FROM dashboard.scoring_jobs WHERE capture_id IS NOT NULL ORDER BY 1").Output -split "`r?`n" | Where-Object { $_ })
    $demoPublicDb = @($dbCaptures | Where-Object { Test-DemoPattern $_ })
    $demoHiddenCaptures = @($dbCaptures | Where-Object { -not (Test-DemoPattern $_) })
    $e2eLogs.Add("[scope] DB scoring_jobs captures=[$($dbCaptures -join ', ')] public=[$($demoPublicDb -join ', ')] hidden=[$($demoHiddenCaptures -join ', ')] (manifest captures=[$($expectedCounts.Keys -join ', ')])")

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
    # T33: 초기화 서비스(헬스체크 없음)가 상주한다. 포트 없음·모든 capability 제거·권한 상승 금지·읽기 전용 루트.
    $resetInfo = @($inspected | Where-Object { $_.Config.Labels.'com.docker.compose.service' -eq 'sandbox-reset' })
    Assert-True ($resetInfo.Count -eq 1 -and $resetInfo[0].State.Running) "sandbox-reset 실행 중"
    $ri = $resetInfo[0]
    $e2eLogs.Add("[0a] sandbox-reset: running=$($ri.State.Running) user=$($ri.Config.User) CapDrop=$($ri.HostConfig.CapDrop -join ',') ReadonlyRootfs=$($ri.HostConfig.ReadonlyRootfs) SecurityOpt=$($ri.HostConfig.SecurityOpt -join ',') Memory=$($ri.HostConfig.Memory) ExposedPorts=$(@($ri.Config.ExposedPorts.PSObject.Properties.Name) -join ',') env interval=$(@($ri.Config.Env | Where-Object { $_ -like 'SANDBOX_RESET_INTERVAL_MINUTES=*' }) -join '')")
    Assert-True ((@($ri.HostConfig.CapDrop) -contains 'ALL') -and $ri.HostConfig.ReadonlyRootfs -and (@($ri.HostConfig.SecurityOpt) -contains 'no-new-privileges:true') -and $ri.HostConfig.Memory -gt 0) "sandbox-reset cap_drop ALL·읽기 전용 루트·no-new-privileges·메모리 상한"
    Assert-True ($states.Count -eq 5) "실행 중인 컨테이너 5개(demo-seed·sandbox-setup은 실행 후 제거)"
    # T36: 이 프로젝트 컨테이너에 붙은 볼륨은 postgres의 pgdata 하나(sandbox-*의 이미지 VOLUME 경로는 tmpfs라 익명 볼륨 없음)
    $volMounts = @($inspected | ForEach-Object { $svc = $_.Config.Labels.'com.docker.compose.service'; @($_.Mounts | Where-Object { $_.Type -eq 'volume' } | ForEach-Object { "$svc|$($_.Name)|$($_.Destination)" }) })
    $e2eLogs.Add("[0a] volume mounts (service|volume|destination): $($volMounts -join ', '); sandbox-reset tmpfs=$(@($ri.HostConfig.Tmpfs.PSObject.Properties | ForEach-Object { "$($_.Name):$($_.Value)" }) -join ',')")
    Assert-True ($volMounts.Count -eq 1 -and $volMounts[0] -eq "postgres|${ProjectName}_pgdata|/var/lib/postgresql/data") "[0a] 이 프로젝트 볼륨은 postgres의 pgdata 하나 ($($volMounts -join ', '))"
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

    # ───────── [T61a]~[T61d] 네트워크 둘·WAF에서 DB·근거 API 차단·capability 없음 ─────────
    # [0] 바로 뒤에 둔다: 상주 다섯이 모두 떠 있고 일회용·ZAP 컨테이너가 없으며, 뒤 단계의 실패가 이 단계를 막지 않는다.
    Write-Host "=== [T61] 네트워크 둘(portfolio-net·portfolio-data)·WAF에서 DB·근거 API 차단·capability 없음 ==="
    $svcById61 = @{}
    foreach ($info in $inspected) { $svcById61[[string]$info.Id] = [string]$info.Config.Labels.'com.docker.compose.service' }
    $netOf61 = {
        param([string]$Net)
        $n = @((Invoke-NativeCapture "docker" @("network", "inspect", $Net)).Output | ConvertFrom-Json)[0]
        $svcs = @()
        if ($n.Containers) {
            $svcs = @($n.Containers.PSObject.Properties | ForEach-Object { if ($svcById61.ContainsKey($_.Name)) { $svcById61[$_.Name] } else { "(other:$($_.Value.Name))" } } | Sort-Object)
        }
        return [pscustomobject]@{ Internal = [bool]$n.Internal; Services = ($svcs -join ','); Subnet = (@($n.IPAM.Config | ForEach-Object { $_.Subnet }) -join ',') }
    }
    $pubNet61 = & $netOf61 $networkName
    $dataNet61 = & $netOf61 $dataNetworkName
    # 동작 확인: 내부 전용 네트워크에만 붙은 컨테이너에는 기본 경로(목적지 00000000)가 없다.
    $routes61 = [ordered]@{}
    foreach ($svc in @("postgres", "api", "sandbox-reset", "dashboard-app", "nginx-waf")) {
        $rt = Invoke-NativeCapture "docker" @("exec", (Get-ServiceContainer $svc), "cat", "/proc/net/route") -IgnoreExitCode
        $routes61[$svc] = if ($rt.ExitCode -ne 0) { -1 } else { @($rt.Output -split "`r?`n" | Where-Object { ($_.Trim() -split '\s+')[1] -eq '00000000' }).Count }
    }
    $e2eLogs.Add("[T61a] $networkName internal=$($pubNet61.Internal) subnet=$($pubNet61.Subnet) containers=[$($pubNet61.Services)]`n       $dataNetworkName internal=$($dataNet61.Internal) subnet=$($dataNet61.Subnet) containers=[$($dataNet61.Services)]`n       default routes in /proc/net/route (service=count): $(($routes61.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ')")
    Assert-True ($pubNet61.Services -eq 'dashboard-app,nginx-waf' -and -not $pubNet61.Internal) "[T61a] portfolio-net에는 nginx-waf·dashboard-app만, 내부 전용 아님 ([$($pubNet61.Services)] internal=$($pubNet61.Internal))"
    Assert-True ($dataNet61.Services -eq 'api,dashboard-app,postgres,sandbox-reset' -and $dataNet61.Internal) "[T61a] portfolio-data에는 postgres·api·dashboard-app·sandbox-reset만, 내부 전용 ([$($dataNet61.Services)] internal=$($dataNet61.Internal))"
    Assert-True ($routes61['postgres'] -eq 0 -and $routes61['api'] -eq 0 -and $routes61['sandbox-reset'] -eq 0 -and $routes61['dashboard-app'] -ge 1) "[T61a] postgres·api·sandbox-reset에는 기본 경로가 없고 dashboard-app에는 있다"

    # [T61b] nginx-waf 안에서 api:8000·postgres:5432에 이름으로도 portfolio-data 주소로도 TCP 연결이 되지 않는다.
    # 연결 단계로 판정한다: BusyBox nc -z(입출력 없이 연결만, -w 3 연결 시간 상한, 바깥 timeout 5 전체 상한). 연결되면 exit 0과 "open".
    # 닿지 않음 = bad address·unreachable·timed out·refused(-z의 거부는 메시지 없이 exit 1). 그 밖의 결과는 닿은 것으로 본다(실패).
    $wafCid61 = Get-ServiceContainer "nginx-waf"
    $tcp61 = {
        param([string]$TargetHost, [string]$Port)
        $r = Invoke-NativeCapture "docker" @("exec", $wafCid61, "timeout", "5", "nc", "-z", "-v", "-w", "3", $TargetHost, $Port) -IgnoreExitCode
        $out = ($r.Output -replace "`r?`n", ' ').Trim()
        $why = if ($r.ExitCode -eq 0 -and $out -match '\bopen\b') { "open" }
            elseif ($r.ExitCode -ne 0 -and $out -match "bad address") { "bad address" }
            elseif ($r.ExitCode -ne 0 -and $out -match '(?i)unreachable') { "unreachable" }
            elseif ($r.ExitCode -ne 0 -and ($out -match '(?i)timed out' -or $r.ExitCode -eq 124 -or $r.ExitCode -eq 143)) { "timed out" }
            elseif ($r.ExitCode -ne 0 -and ($out -match '(?i)refused' -or -not $out)) { "refused" }
            else { "other" }
        return [pscustomobject]@{ Target = "${TargetHost}:$Port"; Exit = $r.ExitCode; Why = $why; Out = $out }
    }
    $apiData61 = Get-NetIp "api" $dataNetworkName
    $pgData61 = Get-NetIp "postgres" $dataNetworkName
    Assert-True ($apiData61 -and $pgData61) "[T61b] api·postgres의 portfolio-data 주소 ($apiData61, $pgData61)"
    $blocked61 = @(@(@("api", "8000"), @("postgres", "5432"), @($apiData61, "8000"), @($pgData61, "5432")) | ForEach-Object { & $tcp61 $_[0] $_[1] })
    $control61 = & $tcp61 "dashboard-app" "8080"
    $e2eLogs.Add("[T61b] inside nginx-waf, timeout 5 nc -z -v -w 3 <host> <port> (connect only):`n       $(($blocked61 + @($control61) | ForEach-Object { "$($_.Target) -> exit=$($_.Exit) $($_.Why) [$($_.Out)]" }) -join "`n       ")")
    foreach ($b in $blocked61) {
        Assert-True (@("bad address", "unreachable", "timed out", "refused") -contains $b.Why) "[T61b] nginx-waf에서 $($b.Target)에 TCP 연결이 되지 않음 (exit=$($b.Exit) $($b.Why) [$($b.Out)])"
    }
    Assert-True ($control61.Why -eq "open") "[T61b] (대조) 같은 도구로 nginx-waf에서 dashboard-app:8080은 연결됨 (exit=$($control61.Exit) [$($control61.Out)])"

    # [T61c] api 안에서 nginx-waf:8080(이름)과 WAF 주소:8080이 예외로 끝나고(종류를 적는다) dashboard-app:8080은 연결된다.
    $wafIp61 = Get-NetIp "nginx-waf" $networkName
    $py61 = @(
        'import socket, sys',
        'for t in sys.argv[1:]:',
        '    h, p = t.rsplit(":", 1)',
        '    try:',
        '        s = socket.create_connection((h, int(p)), timeout=3); s.close(); print(t, "connected")',
        '    except Exception as e:',
        '        print(t, "error", type(e).__name__, str(e).replace("\n", " "))'
    ) -join "`n"
    $py61b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($py61))
    $apiOut61 = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "api", "python", "-c", "import base64;exec(base64.b64decode('$py61b64'))", "nginx-waf:8080", "${wafIp61}:8080", "dashboard-app:8080")) -IgnoreExitCode).Output.Trim()
    $e2eLogs.Add("[T61c] inside api, socket.create_connection(timeout=3) (nginx-waf portfolio-net address=$wafIp61):`n       $($apiOut61 -replace "`r?`n", "`n       ")")
    Assert-True ($wafIp61 -and $apiOut61 -match '(?m)^nginx-waf:8080 error \w+') "[T61c] api에서 nginx-waf:8080(이름)은 예외로 끝남"
    Assert-True ($apiOut61 -match "(?m)^$([regex]::Escape($wafIp61)):8080 error \w+") "[T61c] api에서 WAF 주소 ${wafIp61}:8080은 예외로 끝남"
    Assert-True ($apiOut61 -match '(?m)^dashboard-app:8080 connected') "[T61c] (대조) api에서 dashboard-app:8080은 연결됨"

    # [T61d] 상주 다섯의 PID 1: CapBnd 0(모든 capability 제거), NoNewPrivs 1. postgres는 root로 시작하지 않는다(Config.User = postgres, 첫째 안).
    $caps61 = [System.Collections.Generic.List[string]]::new()
    $capBad61 = [System.Collections.Generic.List[string]]::new()
    foreach ($svc in @("postgres", "api", "dashboard-app", "nginx-waf", "sandbox-reset")) {
        $info = @($inspected | Where-Object { $_.Config.Labels.'com.docker.compose.service' -eq $svc })[0]
        $st = (Invoke-NativeCapture "docker" @("exec", (Get-ServiceContainer $svc), "cat", "/proc/1/status") -IgnoreExitCode).Output
        $bnd = [regex]::Match($st, '(?m)^CapBnd:\s*([0-9a-fA-F]+)').Groups[1].Value
        $eff = [regex]::Match($st, '(?m)^CapEff:\s*([0-9a-fA-F]+)').Groups[1].Value
        $nnp = [regex]::Match($st, '(?m)^NoNewPrivs:\s*(\d+)').Groups[1].Value
        $caps61.Add("$svc user=$(if ($info.Config.User) { $info.Config.User } else { '(image default)' }) CapDrop=$(@($info.HostConfig.CapDrop) -join ',') CapAdd=$(@($info.HostConfig.CapAdd) -join ',') SecurityOpt=$(@($info.HostConfig.SecurityOpt) -join ',') | PID 1 CapBnd=$bnd CapEff=$eff NoNewPrivs=$nnp")
        if ($bnd -ne '0000000000000000' -or $eff -ne '0000000000000000' -or $nnp -ne '1') { $capBad61.Add("$svc CapBnd=$bnd CapEff=$eff NoNewPrivs=$nnp") }
    }
    $pgUser61 = [string](@($inspected | Where-Object { $_.Config.Labels.'com.docker.compose.service' -eq 'postgres' })[0].Config.User)
    $e2eLogs.Add("[T61d] privileges (docker inspect | /proc/1/status):`n       $($caps61 -join "`n       ")")
    Assert-True ($capBad61.Count -eq 0) "[T61d] 상주 다섯의 PID 1 CapBnd·CapEff 0, NoNewPrivs 1 ($($capBad61 -join '; '))"
    Assert-True ($pgUser61 -eq 'postgres') "[T61d] postgres는 root로 시작하지 않음(Config.User=$pgUser61)"

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
    # T27: 화면 경로를 새로 연 비인증 GET은 302 대신 SPA 셸 200(no-store). 리다이렉트 Location 위조 확인은 화면 경로가 아닌 /nope로 한다.
    $rootShell = Invoke-Http -Path "/"
    $e2eLogs.Add("[1b] unauthenticated GET / -> HTTP $($rootShell.Status) Cache-Control=$(Get-HeaderValue $rootShell 'Cache-Control') shell=$(Test-SpaShell $rootShell)")
    Assert-True ($rootShell.Status -eq 200 -and (Test-SpaShell $rootShell) -and (Get-HeaderValue $rootShell "Cache-Control") -match "no-store") "비인증 GET / 셸 200(no-store)" $rootShell
    $rootRes = Invoke-Http -Path "/nope"
    $rootLoc = Get-HeaderValue $rootRes "Location"
    $e2eLogs.Add("[1b] unauthenticated GET /nope -> HTTP $($rootRes.Status) Location=$rootLoc")
    Assert-Status $rootRes 302 "비인증 GET /nope"
    Assert-True ($rootLoc -match $locationOk) "비인증 GET /nope Location이 상대 경로이거나 https://$PublicHost/login(포트 없음 또는 :443)" $rootRes
    $spoofRes = Invoke-Http -Path "/nope" -ExtraHeaders @("X-Forwarded-Host: evil.example", "X-Forwarded-Port: 8080", "Forwarded: for=192.0.2.66;host=evil.example;proto=http", "X-Forwarded-Prefix: /evil", "X-Forwarded-Ssl: off")
    $spoofLoc = Get-HeaderValue $spoofRes "Location"
    $e2eLogs.Add("[1c] (위조 전달 헤더 X-Forwarded-Host/Port, Forwarded, X-Forwarded-Prefix/Ssl를 붙인) GET /nope -> HTTP $($spoofRes.Status) Location=$spoofLoc")
    Assert-True ($spoofRes.Status -eq 302 -and $spoofLoc -match $locationOk) "방문자가 붙인 전달 헤더가 Location에 반영되지 않음" $spoofRes
    # T21: 로그인 화면 안내 문구(compose.portfolio.yml DASHBOARD_LOGIN_NOTICE). 로그인 전 공개 GET이고, 문구만 있고 비밀번호가 없어야 한다.
    $noticeRes = Invoke-Http -Path "/api/auth/login-notice"
    $noticeText = if ($null -ne $noticeRes.Json) { [string]$noticeRes.Json.notice } else { "" }
    $noticeKeys = if ($null -ne $noticeRes.Json) { @($noticeRes.Json.PSObject.Properties.Name) } else { @() }
    # T33: 공개 계정 이름 trial-analyst(13자)는 비밀번호 형태 검사에서 뺀다(이름 자체는 안내 문구에 있어야 한다).
    $pwShaped = [regex]::Matches($noticeText, '[A-Za-z0-9!@#$%^&*_+=-]{12,}') | ForEach-Object { $_.Value } | Where-Object { $_ -cne 'trial-analyst' }
    $e2eLogs.Add("[1d] unauthenticated GET /api/auth/login-notice -> HTTP $($noticeRes.Status) keys=[$($noticeKeys -join ',')] notice=$noticeText password-shaped tokens=$(@($pwShaped).Count)")
    Assert-Status $noticeRes 200 "비인증 GET /api/auth/login-notice"
    # T50: 응답 필드는 notice, 그리고 검사를 통과한 link뿐이다. link가 있으면 키는 url·label뿐이고 url은 스택의 설정값과 같다.
    #   스택이 링크 URL을 설정했으면(compose.portfolio.yml DASHBOARD_LOGIN_NOTICE_LINK_URL) link가 내려와야 한다.
    $noticeKeySet = ($noticeKeys -join ',')
    $noticeLink = if ($noticeKeys -contains 'link') { $noticeRes.Json.link } else { $null }
    $noticeLinkKeys = if ($null -ne $noticeLink) { (@($noticeLink.PSObject.Properties.Name) -join ',') } else { "" }
    $noticeLinkEnv = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "dashboard-app", "sh", "-c", 'printf "%s" "${DASHBOARD_LOGIN_NOTICE_LINK_URL-}"')) -IgnoreExitCode).Output.Trim()
    $e2eLogs.Add("[1d] login notice link: keys=[$noticeLinkKeys] url=$(if ($null -ne $noticeLink) { [string]$noticeLink.url }) label=$(if ($null -ne $noticeLink) { [string]$noticeLink.label }); app env DASHBOARD_LOGIN_NOTICE_LINK_URL='$noticeLinkEnv'")
    Assert-True ($noticeKeySet -ceq 'notice' -or $noticeKeySet -ceq 'notice,link') "로그인 안내 응답의 필드는 notice, 그리고 link뿐" $noticeRes
    if ($null -ne $noticeLink) {
        Assert-True ($noticeLinkKeys -ceq 'url,label') "로그인 안내 link의 키는 url·label뿐" $noticeRes
        Assert-True (([string]$noticeLink.url) -ceq $noticeLinkEnv -and ([string]$noticeLink.url).StartsWith("https://")) "로그인 안내 link.url이 스택 설정값과 같고 https 주소" $noticeRes
        Assert-True (([string]$noticeLink.label).Trim().Length -gt 0) "로그인 안내 link.label이 비어 있지 않음" $noticeRes
    }
    Assert-True (($noticeKeys -contains 'link') -eq [bool]$noticeLinkEnv) "스택이 링크 URL을 설정했을 때만(그리고 그때는 반드시) link가 내려옴" $noticeRes
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
    foreach ($labCap in $demoLabCaptures) {
        Assert-True ($demoVisibleCaptures -contains $labCap) "demo에게 보이는 캡처에 $labCap 포함(manifest 기준 $($demoVisibleCaptures.Count)개)"
    }
    $defaultQueue = Invoke-Http -Path "/api/incidents" -Client $demo
    Assert-Status $defaultQueue 200 "demo 인시던트 목록(캡처 지정 없음)"
    $demoAllowed = @($defaultQueue.Json.allowedCaptures | Sort-Object)
    $e2eLogs.Add("[3-scope] demo GET /api/incidents -> HTTP $($defaultQueue.Status) allowedCaptures=[$($demoAllowed -join ', ')]")
    Assert-True (($demoAllowed -join ',') -eq ((@($demoPublicDb) | Sort-Object) -join ',')) "demo 캡처 목록 = DB 공개 캡처 $($demoPublicDb.Count)개(숨김 $($demoHiddenCaptures.Count)개 없음)" $defaultQueue
    foreach ($hiddenCap in $demoHiddenCaptures) {
        $hiddenQueue = Invoke-Http -Path "/api/incidents?captureId=$hiddenCap" -Client $demo
        $e2eLogs.Add("[3-scope] demo GET /api/incidents?captureId=$hiddenCap -> $(Format-Resp $hiddenQueue 200)")
        Assert-Status $hiddenQueue 403 "demo $hiddenCap 목록 직접 조회 거부"
        $hiddenRow = (Invoke-Psql "zeekad" "SELECT job_id || '/' || queue_rank FROM dashboard.incident_queue WHERE capture_id = '$hiddenCap' ORDER BY job_id DESC, queue_rank LIMIT 1").Output.Trim()
        if ($hiddenRow -match '^\d+/\d+$') {
            $hiddenJob, $hiddenRank = $hiddenRow -split '/'
            $hiddenDetail = Invoke-Http -Path "/api/incidents/$hiddenJob/rank/$hiddenRank" -Client $demo
            $e2eLogs.Add("[3-scope] demo GET /api/incidents/$hiddenJob/rank/$hiddenRank ($hiddenCap) -> $(Format-Resp $hiddenDetail 200)")
            Assert-Status $hiddenDetail 403 "demo $hiddenCap 상세 직접 조회 거부"
        } else {
            # 사건이 0건인 숨김 캡처: 그 캡처의 작업으로 직접 조회한다
            $hiddenJob = (Invoke-Psql "zeekad" "SELECT job_id FROM dashboard.scoring_jobs WHERE capture_id = '$hiddenCap' ORDER BY job_id DESC LIMIT 1").Output.Trim()
            $hiddenJobRes = Invoke-Http -Path "/api/incidents?jobId=$hiddenJob" -Client $demo
            $e2eLogs.Add("[3-scope] demo GET /api/incidents?jobId=$hiddenJob ($hiddenCap, no incidents) -> $(Format-Resp $hiddenJobRes 200)")
            Assert-Status $hiddenJobRes 403 "demo $hiddenCap 작업 직접 조회 거부"
        }
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
    # T22: 실습망 캡처는 따로 본다(캡처마다 AI 리포트가 있는 사건 상세 1건 이상, 증적 available=true 1건 이상). T39: 공개 실습망 캡처 전부.
    $labWithReport = @{}; $labReportOk = @{}; $labEvidenceOk = @{}
    foreach ($labCap in $demoLabCaptures) {
        $labWithReport[$labCap] = @(@(@($queueByCapture[$labCap]) | Where-Object { $_.hasReport }) | Select-Object -First 3)
        foreach ($r in $labWithReport[$labCap]) { $detailTargets.Add($r) }
        $labReportOk[$labCap] = 0; $labEvidenceOk[$labCap] = 0
    }
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
        if ($demoLabCaptures -contains $t.captureId) {
            if ($dd.evidence.available -eq $true) { $labEvidenceOk[$t.captureId]++ }
            if ($dd.report.present -eq $true) { $labReportOk[$t.captureId]++ }
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
    foreach ($labCap in $demoLabCaptures) {
        $e2eLogs.Add("[3b-lab] $labCap details with hasReport=$(@($labWithReport[$labCap]).Count) report.present=$($labReportOk[$labCap]) evidence.available=$($labEvidenceOk[$labCap])")
        Assert-True ($labReportOk[$labCap] -ge 1) "$labCap AI 리포트가 있는 사건 상세 1건 이상"
        Assert-True ($labEvidenceOk[$labCap] -ge 1) "$labCap 증적 available=true 1건 이상"
    }
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

    Write-Host "=== [T23] 통합 인시던트 큐(latest-data 기준 시각, 합계·숨김 0·마스킹·쪽 이음·응답 시간) ==="
    function ConvertTo-SqlArray([string[]]$Values) {
        return "ARRAY[" + (($Values | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ",") + "]::text[]"
    }
    function Get-RefPriority($It) {
        $s = ([string]$It.zeekadStatus).Trim().ToLowerInvariant()
        if (-not $s) { $s = 'open' }
        if ($s -eq 'closed') { return '' }
        if ($It.zeekadWouldSend -eq $true -or $It.zeekadReviewPending -eq $true) { return 'high' }
        if (@($It.zeekadAlsoFlaggedBy | Where-Object { $_ }).Count -ge 1 -or $It.hasReport -eq $true) { return 'medium' }
        return 'low'
    }
    # T52 중요 자산: 기준은 응답이 아니라 DB에서 계산한다. 자산 주소는 앱 DB critical_assets, 행의 원문 host_ip는
    #     (jobId, queueRank)로 zeekad DB에서 읽는다(demo 응답의 주소는 가려져 있다). 응답의 assetCritical·priorityBase는 견줄 대상이다.
    #     앞 이미지(T52 전)의 앱 DB에는 표가 없어 빈 목록이다.
    function Get-CriticalAssetHosts {
        $set = [System.Collections.Generic.HashSet[string]]::new()
        $exists = (Invoke-Psql "zeekad_dashboard" "SELECT to_regclass('public.critical_assets') IS NOT NULL").Output.Trim()
        if ($exists -ne 't') { return ,$set }
        foreach ($ip in @((Invoke-Psql "zeekad_dashboard" "SELECT host_ip FROM critical_assets ORDER BY id").Output -split "`r?`n" | Where-Object { $_ })) {
            [void]$set.Add($ip.Trim())
        }
        return ,$set
    }
    function Get-RawHostByRowKey([string]$CaptureArray) {
        $map = @{}
        $sql = "SELECT job_id || '/' || queue_rank || '|' || COALESCE(host_ip, '') FROM dashboard.latest_incident_queue WHERE capture_id = ANY($CaptureArray)"
        foreach ($line in @((Invoke-Psql "zeekad" $sql).Output -split "`r?`n" | Where-Object { $_ })) {
            $parts = $line.Trim() -split '\|', 2
            $map[$parts[0]] = $parts[1]
        }
        return $map
    }
    # 한 단계 올림: Low → Medium, Medium → High, High·종결('')은 그대로
    function Get-RaisedPriority([string]$Base, [bool]$Critical) {
        if (-not $Base -or -not $Critical) { return $Base }
        if ($Base -eq 'low') { return 'medium' }
        return 'high'
    }
    function Get-AllQueueItems($Client, [string]$Query, [int]$Size) {
        $all = [System.Collections.Generic.List[object]]::new()
        $first = Invoke-Http -Path "/api/incidents/queue?$Query&size=$Size&page=1" -Client $Client
        Assert-Status $first 200 "demo 통합 큐 $Query size=$Size page=1"
        $pages = [int]$first.Json.pageCount
        for ($p = 1; $p -le $pages; $p++) {
            $res = if ($p -eq 1) { $first } else { Invoke-Http -Path "/api/incidents/queue?$Query&size=$Size&page=$p" -Client $Client }
            Assert-Status $res 200 "demo 통합 큐 $Query size=$Size page=$p"
            Find-UnmaskedIpv4 $res.Json "queue[$Query p$p]" $t23IpHits
            foreach ($it in @($res.Json.items)) { $all.Add($it) }
        }
        return [pscustomobject]@{ First = $first; Items = $all; Pages = $pages }
    }
    $t23IpHits = [System.Collections.Generic.List[string]]::new()
    $publicArr = ConvertTo-SqlArray $demoPublicDb
    $hiddenArr = if ($demoHiddenCaptures.Count) { ConvertTo-SqlArray $demoHiddenCaptures } else { "ARRAY[]::text[]" }

    # [T23a] period=all 합계 = 공개 캡처 최신 작업 사건 수의 합 = feedback_summary 'all' 행 incidents 합(현황판 KPI)
    $kpiSum = [int](Invoke-Psql "zeekad" "SELECT COALESCE(SUM(incidents),0) FROM dashboard.feedback_summary WHERE zeekad_picked_by = 'all' AND capture_id = ANY($publicArr)").Output.Trim()
    $lqSum = [int](Invoke-Psql "zeekad" "SELECT count(*) FROM dashboard.latest_incident_queue WHERE capture_id = ANY($publicArr)").Output.Trim()
    $all = Get-AllQueueItems $demo "period=all" 100
    $allTotal = [int]$all.First.Json.total
    $e2eLogs.Add("[T23a] demo GET /api/incidents/queue?period=all -> total=$allTotal pages=$($all.Pages) items=$($all.Items.Count); feedback_summary 'all' incidents sum (public)=$kpiSum; latest_incident_queue rows (public)=$lqSum; public captures=[$($demoPublicDb -join ', ')]")
    Assert-True ($allTotal -eq $kpiSum -and $allTotal -eq $lqSum -and $all.Items.Count -eq $allTotal) "[T23a] period=all total = 공개 캡처 최신 작업 사건 수 합 = KPI(feedback_summary 'all') (total=$allTotal, KPI=$kpiSum, rows=$lqSum)"

    # [T23b] 기준 시각 = 공개 캡처 성공 작업 finished_at 최대(SQL 따로 계산), snapshot, time-context
    function ConvertTo-EpochMicros([string]$Iso) {
        $dto = [DateTimeOffset]::Parse($Iso, [Globalization.CultureInfo]::InvariantCulture)
        return [long](($dto.UtcTicks - [DateTimeOffset]::new(1970, 1, 1, 0, 0, 0, [TimeSpan]::Zero).UtcTicks) / 10)
    }
    function Format-Micros([long]$Micros) {
        if ($Micros -le 0) { return '(none)' }
        return [DateTimeOffset]::new(1970, 1, 1, 0, 0, 0, [TimeSpan]::Zero).AddTicks($Micros * 10).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
    }
    $anchorMicros = [long](Invoke-Psql "zeekad" "SELECT (EXTRACT(EPOCH FROM MAX(finished_at)) * 1000000)::bigint FROM dashboard.scoring_jobs WHERE status = 'succeeded' AND finished_at IS NOT NULL AND capture_id = ANY($publicArr)").Output.Trim()
    $hiddenMaxRaw = (Invoke-Psql "zeekad" "SELECT COALESCE((EXTRACT(EPOCH FROM MAX(finished_at)) * 1000000)::bigint, 0) FROM dashboard.scoring_jobs WHERE status = 'succeeded' AND finished_at IS NOT NULL AND capture_id = ANY($hiddenArr)").Output.Trim()
    $hiddenMaxMicros = [long]$hiddenMaxRaw
    $anchorSql = Format-Micros $anchorMicros
    $hiddenMax = Format-Micros $hiddenMaxMicros
    $tc = Invoke-Http -Path "/api/time-context" -Client $demo
    $apiAnchorMicros = ConvertTo-EpochMicros ([string]$all.First.Json.anchor)
    $tcAnchorMicros = ConvertTo-EpochMicros ([string]$tc.Json.anchor)
    $e2eLogs.Add("[T23b] anchor API(queue)=$($all.First.Json.anchor) API(time-context)=$($tc.Json.anchor) SQL(public max finished_at)=$anchorSql hidden max finished_at=$(if ($hiddenMax) { $hiddenMax } else { '(none)' }); anchorMode=$($all.First.Json.anchorMode) snapshot=$($all.First.Json.snapshot) time-context snapshot=$($tc.Json.snapshot)")
    Assert-Status $tc 200 "[T23b] demo GET /api/time-context"
    Assert-True ($apiAnchorMicros -eq $anchorMicros -and $tcAnchorMicros -eq $anchorMicros) "[T23b] 기준 시각 = 공개 캡처 성공 작업 finished_at 최대 (API=$apiAnchorMicros, SQL=$anchorMicros, time-context=$tcAnchorMicros us)"
    Assert-True ($all.First.Json.snapshot -eq $true -and $all.First.Json.anchorMode -eq 'latest-data' -and $tc.Json.snapshot -eq $true) "[T23b] latest-data 고정 스냅샷"

    # [T23c] 기본 24시간: 캡처별 수 = T23에서 정한 기대값 SQL(구현 SQL을 복사하지 않음)
    # T23 정의의 기대값 SQL(:public = 공개 캡처, :anchor = 위 SQL 기준 시각). 구현 SQL을 복사하지 않았다.
    $anchorExpr = "to_timestamp($anchorMicros / 1000000.0)"
    $expect24Sql = "WITH first_seen AS (SELECT q.incident_id, MIN(j.finished_at) AS detected_at FROM dashboard.incident_queue q " +
        "JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL GROUP BY q.incident_id) " +
        "SELECT lq.capture_id, count(*) FROM dashboard.latest_incident_queue lq JOIN first_seen f ON f.incident_id = lq.incident_id " +
        "WHERE lq.capture_id = ANY($publicArr) AND f.detected_at > $anchorExpr - interval '24 hours' AND f.detected_at <= $anchorExpr " +
        "GROUP BY lq.capture_id ORDER BY 1"
    $expect24 = (Invoke-Psql "zeekad" $expect24Sql).Output.Trim()
    $expect24Map = [ordered]@{}
    foreach ($line in @($expect24 -split "`r?`n" | Where-Object { $_ })) { $c, $n = $line -split '\|'; $expect24Map[$c] = [int]$n }
    $d24 = Get-AllQueueItems $demo "period=24h" 100
    $got24Map = [ordered]@{}
    foreach ($g in @($d24.Items | Group-Object captureId | Sort-Object Name)) { $got24Map[$g.Name] = $g.Count }
    $exp24Text = ($expect24Map.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
    $got24Text = ($got24Map.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
    $e2eLogs.Add("[T23c] default period=24h (anchor $anchorSql): API total=$($d24.First.Json.total) by capture [$got24Text]; expected SQL [$exp24Text]")
    Assert-True ($exp24Text -eq $got24Text -and [int]$d24.First.Json.total -eq $d24.Items.Count) "[T23c] 기본 24시간 결과 캡처·수 = 기대 SQL (API [$got24Text], SQL [$exp24Text])"

    # [T23d] summary = 모든 쪽 items로 센 값, 서버 우선순위 = 옛 규칙(PostgreSQL), 쪽 이음(25건씩) = 100건씩 결과, 마스킹
    $s = $all.First.Json.summary
    $cnt = @{ high = 0; medium = 0; low = 0; review = 0; alerted = 0; open = 0; investigating = 0; closed = 0; other = 0 }
    foreach ($it in $all.Items) {
        if ($it.priority) { $cnt[[string]$it.priority]++ }
        if ($it.zeekadReviewPending -eq $true) { $cnt.review++ }
        if ($it.alerted -eq $true) { $cnt.alerted++ }
        $st = ([string]$it.zeekadStatus).Trim().ToLowerInvariant()
        if (-not $st -or $st -eq 'open') { $cnt.open++ } elseif ($st -eq 'investigating') { $cnt.investigating++ } elseif ($st -eq 'closed') { $cnt.closed++ } else { $cnt.other++ }
    }
    $summaryText = "summary total=$($s.total) high=$($s.high) medium=$($s.medium) low=$($s.low) reviewPending=$($s.reviewPending) alerted=$($s.alerted) byStatus=$($s.byStatus | ConvertTo-Json -Compress)"
    $countText = "items total=$($all.Items.Count) high=$($cnt.high) medium=$($cnt.medium) low=$($cnt.low) reviewPending=$($cnt.review) alerted=$($cnt.alerted) open=$($cnt.open) investigating=$($cnt.investigating) closed=$($cnt.closed) other=$($cnt.other)"
    # T52: 기준 = 옛 규칙(기본 우선순위)을 중요 자산이면 한 단계 올린 값. 자산 여부는 DB의 원문 host_ip와 자산 주소로 정한다.
    #      응답의 priorityBase = 기본 우선순위, assetCritical = DB로 정한 자산 여부, demo(조회자)의 criticalAssetName = null
    $assetHosts23 = Get-CriticalAssetHosts
    $rawHost23 = Get-RawHostByRowKey $publicArr
    $raised23 = 0
    $criticalRows23 = 0
    $prioMismatch = @($all.Items | Where-Object {
        $base = Get-RefPriority $_
        $critical = $assetHosts23.Contains([string]$rawHost23["$($_.jobId)/$($_.queueRank)"])
        $expected = Get-RaisedPriority $base $critical
        if ($critical) { $criticalRows23++ }
        if ($expected -ne $base) { $raised23++ }
        ([string]$_.priority) -ne $expected -or ([string]$_.priorityBase) -ne $base -or [bool]$_.assetCritical -ne $critical -or
            $null -ne $_.criticalAssetName -or -not ($_.PSObject.Properties.Name -contains 'criticalAssetName')
    })
    $e2eLogs.Add("[T23d] $summaryText`n       $countText`n       critical asset hosts (app DB)=$($assetHosts23.Count) critical rows (DB host_ip)=$criticalRows23 raised rows=$raised23`n       server priority/priorityBase/assetCritical vs rule (old rule + one step for critical assets) mismatches=$($prioMismatch.Count)$(if ($prioMismatch.Count) { ' ' + (($prioMismatch | Select-Object -First 5 | ForEach-Object { "$($_.jobId)/$($_.queueRank)" }) -join ',') })")
    Assert-True ([int]$s.total -eq $all.Items.Count -and [int]$s.high -eq $cnt.high -and [int]$s.medium -eq $cnt.medium -and [int]$s.low -eq $cnt.low -and
        [int]$s.reviewPending -eq $cnt.review -and [int]$s.alerted -eq $cnt.alerted -and [int]$s.byStatus.open -eq $cnt.open -and
        [int]$s.byStatus.investigating -eq $cnt.investigating -and [int]$s.byStatus.closed -eq $cnt.closed -and [int]$s.byStatus.other -eq $cnt.other) "[T23d] summary = 모든 쪽 items로 센 값"
    Assert-True ($prioMismatch.Count -eq 0) "[T23d] PostgreSQL 서버 우선순위 = 옛 화면 규칙 + 중요 자산 한 단계(priorityBase·assetCritical 포함, demo 이름 null) (불일치 $($prioMismatch.Count))"
    $keys100 = @($all.Items | ForEach-Object { "$($_.jobId)/$($_.queueRank)" })
    $small = Get-AllQueueItems $demo "period=all" 25
    $keys25 = @($small.Items | ForEach-Object { "$($_.jobId)/$($_.queueRank)" })
    $dups = @($keys25 | Group-Object | Where-Object { $_.Count -gt 1 }).Count
    $e2eLogs.Add("[T23d] page join (sort=priority default): size25 pages=$($small.Pages) keys=$($keys25.Count) dups=$dups; size100 keys=$($keys100.Count); same order=$((($keys25 -join ',') -eq ($keys100 -join ',')))")
    Assert-True ((($keys25 -join ',') -eq ($keys100 -join ',')) -and $dups -eq 0 -and $keys25.Count -eq $allTotal) "[T23d] 25건씩 쪽을 이으면 100건씩 결과와 같고 겹침·빠짐 없음"
    Assert-True ($all.First.Json.maskedView -eq $true) "[T23d] demo maskedView"

    # [T23e] 숨김 캡처 흔적 0: queue 행·sources·new-count(숨김만 더 늦은 since)·neighbors(숨김 작업 403)·time-context(위 T23b)
    $rowCaps = @($all.Items | ForEach-Object { $_.captureId } | Select-Object -Unique | Sort-Object)
    $srcCaps = @($all.First.Json.sources | ForEach-Object { $_.captureId } | Sort-Object)
    $leakRows = @($all.Items | Where-Object { $demoHiddenCaptures -contains $_.captureId })
    $sinceIso = $anchorSql
    $nc = Invoke-Http -Path "/api/incidents/queue/new-count?since=$sinceIso" -Client $demo
    $ncAll = Invoke-Http -Path "/api/incidents/queue/new-count?since=2000-01-01T00:00:00Z" -Client $demo
    $e2eLogs.Add("[T23e] queue row captures=[$($rowCaps -join ', ')] hidden rows=$($leakRows.Count); sources=[$($srcCaps -join ', ')] (public DB=[$((@($demoPublicDb | Sort-Object)) -join ', ')]); new-count since=$sinceIso (public max, hidden max=$hiddenMax) -> $(Format-Resp $nc 200); new-count since 2000 -> count=$($ncAll.Json.count)")
    Assert-True ($leakRows.Count -eq 0 -and @($rowCaps | Where-Object { -not (Test-DemoPattern $_) }).Count -eq 0) "[T23e] 통합 큐에 숨김 캡처 행 0"
    Assert-True (($srcCaps -join ',') -eq ((@($demoPublicDb | Sort-Object)) -join ',')) "[T23e] sources = 공개 캡처만"
    Assert-True ($nc.Status -eq 200 -and [int]$nc.Json.count -eq 0) "[T23e] 숨김 캡처만 더 늦은 since로 new-count = 0"
    Assert-True ($ncAll.Status -eq 200 -and [int]$ncAll.Json.count -eq $allTotal) "[T23e] new-count(since 2000) = 공개 합계"
    foreach ($hiddenCap in $demoHiddenCaptures) {
        $hq = Invoke-Http -Path "/api/incidents/queue?captureId=$hiddenCap" -Client $demo
        $hjob = (Invoke-Psql "zeekad" "SELECT job_id FROM dashboard.scoring_jobs WHERE capture_id = '$hiddenCap' ORDER BY job_id DESC LIMIT 1").Output.Trim()
        $hnb = Invoke-Http -Path "/api/incidents/queue/neighbors?jobId=$hjob&queueRank=1" -Client $demo
        $hnc = Invoke-Http -Path "/api/incidents/queue/new-count?captureId=$hiddenCap&since=2000-01-01T00:00:00Z" -Client $demo
        $e2eLogs.Add("[T23e] hidden ${hiddenCap}: queue?captureId -> HTTP $($hq.Status); neighbors jobId=$hjob -> HTTP $($hnb.Status); new-count?captureId -> HTTP $($hnc.Status)")
        Assert-Status $hq 403 "[T23e] demo 통합 큐 숨김 캡처 $hiddenCap"
        Assert-Status $hnb 403 "[T23e] demo neighbors 숨김 캡처 작업 $hjob"
        Assert-Status $hnc 403 "[T23e] demo new-count 숨김 캡처 $hiddenCap"
    }
    $firstKey = $all.Items[0]
    $nb = Invoke-Http -Path "/api/incidents/queue/neighbors?jobId=$($firstKey.jobId)&queueRank=$($firstKey.queueRank)&period=all" -Client $demo
    $e2eLogs.Add("[T23e] neighbors first row: $(Format-Resp $nb 300)")
    Assert-True ($nb.Status -eq 200 -and [int]$nb.Json.position -eq 1 -and [int]$nb.Json.total -eq $allTotal) "[T23e] neighbors 위치·전체 수(공개 합계)" $nb
    Find-UnmaskedIpv4 $nb.Json "neighbors" $t23IpHits
    Find-UnmaskedIpv4 $nc.Json "new-count" $t23IpHits

    # [T23f] VIEWER 자산 검색(PostgreSQL): 가려지지 않은 IP의 뒤 두 옥텟으로는 0건, 가려진 앞부분·호스트 이름으로는 찾아짐
    $maskedTexts = @($all.Items | ForEach-Object { @($_.hostIp) + @($_.hostName) } | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $realIps = @((Invoke-Psql "zeekad" "SELECT DISTINCT host_ip FROM dashboard.latest_incident_queue WHERE capture_id = ANY($publicArr) ORDER BY 1").Output -split "`r?`n" | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
    $tailIp = $null; $tail = $null
    foreach ($ip in $realIps) {
        $o = $ip -split '\.'
        $cand = "$($o[2]).$($o[3])"
        if (-not (@($maskedTexts | Where-Object { $_.Contains($cand) }).Count)) { $tailIp = $ip; $tail = $cand; break }
    }
    Assert-True ([bool]$tail) "[T23f] 가려진 값·호스트 이름에 없는 실제 IP 뒤 두 옥텟 후보"
    $head = (($tailIp -split '\.')[0..1]) -join '.'
    $hostSample = @($all.Items | ForEach-Object { @($_.hostName) } | Where-Object { $_ -and $_ -notmatch '\d+\.\d+\.\*\.\*' } | Select-Object -First 1)
    $aTail = Invoke-Http -Path "/api/incidents/queue?period=all&asset=$tail" -Client $demo
    $aHead = Invoke-Http -Path "/api/incidents/queue?period=all&asset=$head" -Client $demo
    $aHost = if ($hostSample.Count) { Invoke-Http -Path "/api/incidents/queue?period=all&asset=$([uri]::EscapeDataString([string]$hostSample[0]))" -Client $demo } else { $null }
    Find-UnmaskedIpv4 $aHead.Json "asset-head" $t23IpHits
    $e2eLogs.Add("[T23f] demo asset search (masked view): tail of a real public IP '<a>.<b>.$tail' -> HTTP $($aTail.Status) total=$($aTail.Json.total); masked head '$head' -> total=$($aHead.Json.total); host name sample -> $(if ($aHost) { "HTTP $($aHost.Status) total=$($aHost.Json.total)" } else { '(no host name in public data)' })")
    Assert-True ($aTail.Status -eq 200 -and [int]$aTail.Json.total -eq 0) "[T23f] demo 실제 IP 뒤 두 옥텟 검색 0건 (PostgreSQL)" $aTail
    Assert-True ($aHead.Status -eq 200 -and [int]$aHead.Json.total -ge 1) "[T23f] demo 가려진 앞부분 검색은 찾아짐" $aHead
    if ($aHost) { Assert-True ($aHost.Status -eq 200 -and [int]$aHost.Json.total -ge 1) "[T23f] demo 호스트 이름 검색은 찾아짐" $aHost }
    $e2eLogs.Add("[T23d-f] unmasked IPv4 JSON paths in T23 responses=$($t23IpHits.Count)$(if ($t23IpHits.Count) { ' ' + (($t23IpHits | Select-Object -First 20) -join ', ') })")
    Assert-True ($t23IpHits.Count -eq 0) "[T23] demo 통합 큐·neighbors·new-count·자산 검색 응답에 가려지지 않은 IPv4 없음"

    # [T23g] 응답 시간(서버 경유 전체 요청 시간, curl 포함): period=all 첫 쪽, 자산 검색 첫 쪽, new-count
    $timings = [ordered]@{}
    foreach ($t in @(@{ Name = 'period=all page1'; Path = "/api/incidents/queue?period=all" },
                     @{ Name = 'asset search page1'; Path = "/api/incidents/queue?period=all&asset=$head" },
                     @{ Name = 'new-count'; Path = "/api/incidents/queue/new-count?since=$sinceIso" })) {
        $samples = @()
        for ($k = 0; $k -lt 3; $k++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-Http -Path $t.Path -Client $demo
            $sw.Stop()
            Assert-Status $r 200 "[T23g] $($t.Name)"
            $samples += [int]$sw.ElapsedMilliseconds
        }
        $timings[$t.Name] = $samples
    }
    $timingText = ($timings.GetEnumerator() | ForEach-Object { "$($_.Key)=[$($_.Value -join ', ')] ms" }) -join '; '
    $slow = @($timings.GetEnumerator() | Where-Object { ($_.Value | Measure-Object -Minimum).Minimum -gt 1000 } | ForEach-Object { $_.Key })
    $e2eLogs.Add("[T23g] response times (3 samples each, includes curl): $timingText; over 1s (min of 3): [$($slow -join ', ')]")

    # [T23h] 진행 중·실습망 지연(최신 작업 finished_at - 최대 event_end)
    $lagRows = (Invoke-Psql "zeekad" "SELECT lq.capture_id, j.job_id, to_char(j.finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), to_char(MAX(lq.event_end) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), EXTRACT(EPOCH FROM (j.finished_at - MAX(lq.event_end)))::int FROM dashboard.latest_incident_queue lq JOIN dashboard.scoring_jobs j ON j.job_id = lq.job_id WHERE lq.capture_id LIKE 'lab-%' GROUP BY lq.capture_id, j.job_id, j.finished_at ORDER BY 1").Output.Trim()
    $ongoingItems = @($all.Items | Where-Object { $_.ongoing -eq $true })
    $liveItems = @($all.Items | Where-Object { $_.sourceType -eq 'live' })
    $e2eLogs.Add("[T23h] live items=$($liveItems.Count) ongoing items=$($ongoingItems.Count) [$(@($ongoingItems | Select-Object -First 10 | ForEach-Object { "$($_.captureId) $($_.jobId)/$($_.queueRank) end=$($_.eventEnd)" }) -join '; ')]`n       lab latest job lag (capture|job|finished_at UTC|max event_end UTC|lag seconds):`n       $($lagRows -replace "`r?`n", "`n       ")")
    Assert-True (@($ongoingItems | Where-Object { $_.sourceType -ne 'live' }).Count -eq 0) "[T23h] 진행 중은 실습망 센서만"
    Assert-True (@($all.Items | Where-Object { ($_.captureId -like 'lab-*') -ne ($_.sourceType -eq 'live') }).Count -eq 0) "[T23h] 수집원 분류(lab-* = 실습망 센서)"

    Write-Host "=== [T24] 현황판 overview·운영 현황(불변식·KPI = 큐·센서 상태·숨김 0·독립 SQL 24시간 구간·응답 시간) ==="
    $t24IpHits = [System.Collections.Generic.List[string]]::new()
    $t24Fail = [System.Collections.Generic.List[string]]::new()
    $t24Lines = [System.Collections.Generic.List[string]]::new()
    $t24Bodies = [System.Collections.Generic.List[string]]::new()
    # [T24a] 기간 다섯 × 수집원(all·live·imported): 구간 합 + unbucketed = 큐 total = 캡처 행 합, 센서 = 그 캡처 합.
    #        KPI 넷 = 링크 조건 큐 목록 수(total): 탐지된 인시던트·High(priority=high)·경보 발송(alerted=true)·에스컬레이션 대기(period=all, reviewPending=true)
    foreach ($period in @('1h', '24h', '7d', '30d', 'all')) {
        foreach ($cond in @('', '&source=live', '&source=imported')) {
            $q = "period=$period$cond"
            $ov = Invoke-Http -Path "/api/dashboard/overview?$q" -Client $demo
            $qq = Invoke-Http -Path "/api/incidents/queue?$q&size=25" -Client $demo
            Assert-Status $ov 200 "[T24a] demo overview $q"
            Assert-Status $qq 200 "[T24a] demo queue $q"
            $t24Bodies.Add($ov.Body)
            Find-UnmaskedIpv4 $ov.Json "overview[$q]" $t24IpHits
            $bucketSum = 0
            foreach ($b in @($ov.Json.trend.buckets)) {
                $parts = [int]$b.high + [int]$b.medium + [int]$b.low + [int]$b.none
                if ($parts -ne [int]$b.total) { $t24Fail.Add("$q bucket $($b.end) parts=$parts total=$($b.total)") }
                $bucketSum += $parts
            }
            $unb = [int]$ov.Json.trend.unbucketed.noDetectedAt + [int]$ov.Json.trend.unbucketed.afterAnchor
            $capSum = 0
            $bySensor = @{}
            foreach ($c in @($ov.Json.captures)) {
                $capSum += [int]$c.total
                if ($c.sensorKey) { $bySensor[$c.sensorKey] = [int]$bySensor[$c.sensorKey] + [int]$c.total }
            }
            foreach ($s in @($ov.Json.sensors)) {
                if ([int]$s.total -ne [int]$bySensor[$s.sensorKey]) { $t24Fail.Add("$q sensor $($s.sensorKey) $($s.total) != $($bySensor[$s.sensorKey])") }
            }
            $sum = $qq.Json.summary
            if (($bucketSum + $unb) -ne [int]$sum.total -or $capSum -ne [int]$sum.total) { $t24Fail.Add("$q buckets=$bucketSum unbucketed=$unb captures=$capSum queue=$($sum.total)") }
            # KPI = 링크 목록 수
            $hi = Invoke-Http -Path "/api/incidents/queue?$q&priority=high&size=25" -Client $demo
            $al = Invoke-Http -Path "/api/incidents/queue?$q&alerted=true&size=25" -Client $demo
            if ([int]$hi.Json.total -ne [int]$sum.high) { $t24Fail.Add("$q KPI High $($sum.high) != list $($hi.Json.total)") }
            if ([int]$al.Json.total -ne [int]$sum.alerted) { $t24Fail.Add("$q KPI alerted $($sum.alerted) != list $($al.Json.total)") }
            $t24Lines.Add("$q -> buckets=$(@($ov.Json.trend.buckets).Count)($($ov.Json.trend.bucket)) sum=$bucketSum unbucketed=$unb captures=$capSum queue.total=$($sum.total) high=$($sum.high)/list $($hi.Json.total) alerted=$($sum.alerted)/list $($al.Json.total) sensors=[$(@($ov.Json.sensors | ForEach-Object { "$($_.sensorKey)=$($_.total)/$($_.health)" }) -join ',')]")
        }
    }
    foreach ($cond in @('', '&source=live', '&source=imported')) {
        $pAll = Invoke-Http -Path "/api/incidents/queue?period=all$cond&size=25" -Client $demo
        $pList = Invoke-Http -Path "/api/incidents/queue?period=all$cond&reviewPending=true&size=25" -Client $demo
        if ([int]$pList.Json.total -ne [int]$pAll.Json.summary.reviewPending) { $t24Fail.Add("all$cond KPI pending $($pAll.Json.summary.reviewPending) != list $($pList.Json.total)") }
        $t24Lines.Add("pending period=all$cond -> summary.reviewPending=$($pAll.Json.summary.reviewPending) list total=$($pList.Json.total)")
    }
    $e2eLogs.Add("[T24a] overview invariants and KPI = list (demo, latest-data):`n       $($t24Lines -join "`n       ")`n       failures=$($t24Fail.Count)$(if ($t24Fail.Count) { "`n       " + ($t24Fail -join "`n       ") })")
    Assert-True ($t24Fail.Count -eq 0) "[T24a] 구간 합 + unbucketed = 큐 total = 캡처 행 합, 센서 = 캡처 합, KPI = 링크 목록 수 (실패 $($t24Fail.Count))"

    # [T24b] 에스컬레이션 대기: 큐(period=all) reviewPending = /api/reviews 대기 건수(다르면 원인을 적는다)
    $rv = Invoke-Http -Path "/api/reviews?pendingOnly=true" -Client $demo
    Assert-Status $rv 200 "[T24b] demo /api/reviews?pendingOnly=true"
    $rvPending = @($rv.Json.reviews | Where-Object { $_.pending -ne $false }).Count
    $qPending = [int](Invoke-Http -Path "/api/incidents/queue?period=all&size=25" -Client $demo).Json.summary.reviewPending
    $e2eLogs.Add("[T24b] escalation pending: queue(period=all).summary.reviewPending=$qPending; /api/reviews pendingOnly pending=$rvPending (reviews rows=$(@($rv.Json.reviews).Count))$(if ($qPending -ne $rvPending) { '; DIFFERENT: queue counts latest_incident_queue.zeekad_review_pending(latest analysis), /api/reviews lists analyst_review_queue rows' })")

    # [T24c] 실습망 센서 상태 ok, 기준 시각을 만든 공개 실습망 캡처 하나만 active(latest-data 기준), 기준 시각 = [T23b] SQL 기준 시각
    #        T39: 센서의 captureCount = manifest의 공개 실습망 캡처 수, active = 공개 실습망 캡처 가운데 성공 작업 finished_at이 가장 늦은 것.
    $ov24 = Invoke-Http -Path "/api/dashboard/overview?period=24h" -Client $demo
    $labSensor = @($ov24.Json.sensors | Where-Object { $_.sensorKey -eq 'lab-*' })
    $publicLabCaps = @($demoVisibleCaptures | Where-Object { $_ -like 'lab-*' } | Sort-Object)
    $publicLabIn = ($publicLabCaps | ForEach-Object { "'$_'" }) -join ','
    $activeLabExpected = (Invoke-Psql "zeekad" "SELECT capture_id FROM dashboard.scoring_jobs WHERE status = 'succeeded' AND finished_at IS NOT NULL AND capture_id IN ($publicLabIn) ORDER BY finished_at DESC, capture_id LIMIT 1").Output.Trim()
    $labCap = @($ov24.Json.captures | Where-Object { $_.captureId -eq $activeLabExpected })
    $labOthers = @($ov24.Json.captures | Where-Object { $publicLabCaps -contains $_.captureId -and $_.captureId -ne $activeLabExpected })
    $e2eLogs.Add("[T24c] public lab captures=[$($publicLabCaps -join ', ')] expected active (latest succeeded finished_at)=$activeLabExpected others=[$(@($labOthers | ForEach-Object { "$($_.captureId):$($_.state)" }) -join ', ')]")
    $e2eLogs.Add("[T24c] sensors=[$(@($ov24.Json.sensors | ForEach-Object { "$($_.sensorKey):$($_.health) lastScored=$($_.lastScoredAt) lastActivity=$($_.lastActivityAt) captures=$($_.captureCount) active=$($_.activeCaptureId)" }) -join '; ')] captures=[$(@($ov24.Json.captures | ForEach-Object { "$($_.captureId):$($_.state)" }) -join ', ')] anchor=$($ov24.Json.anchor) snapshot=$($ov24.Json.snapshot) alerting=$($ov24.Json.alerting | ConvertTo-Json -Compress)")
    Assert-True ($labSensor.Count -eq 1 -and $labSensor[0].health -eq 'ok' -and $labSensor[0].captureCount -eq $publicLabCaps.Count) "[T24c] 실습망 센서 상태 ok(공개 실습망 캡처 $($publicLabCaps.Count)개 묶음)" $ov24
    Assert-True ($labCap.Count -eq 1 -and $labCap[0].state -eq 'active' -and $labSensor[0].activeCaptureId -eq $activeLabExpected) "[T24c] $activeLabExpected 수집 중(active)" $ov24
    Assert-True ($labOthers.Count -eq ($publicLabCaps.Count - 1) -and @($labOthers | Where-Object { $_.state -eq 'active' }).Count -eq 0) "[T24c] 나머지 공개 실습망 캡처는 active 아님" $ov24
    Assert-True ((ConvertTo-EpochMicros ([string]$ov24.Json.anchor)) -eq $anchorMicros -and $ov24.Json.snapshot -eq $true) "[T24c] overview 기준 시각 = 공개 캡처 SQL 기준 시각(latest-data)" $ov24
    Assert-True (@($ov24.Json.captures | Where-Object { $_.sourceType -eq 'imported' -and $_.state -notin @('imported', 'failed', 'none') }).Count -eq 0) "[T24c] 가져온 데이터 캡처 상태" $ov24

    # [T24d] 독립 SQL로 24시간 구간별 수(KST 시계 1시간, (start, end]): 구현 SQL을 복사하지 않음
    $bucketSql = "WITH first_seen AS (SELECT q.incident_id, MIN(j.finished_at) AS detected_at FROM dashboard.incident_queue q " +
        "JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL GROUP BY q.incident_id), " +
        "d AS (SELECT f.detected_at, date_trunc('hour', f.detected_at AT TIME ZONE 'Asia/Seoul') AS kst_floor, f.detected_at AT TIME ZONE 'Asia/Seoul' AS kst " +
        "FROM dashboard.latest_incident_queue lq JOIN first_seen f ON f.incident_id = lq.incident_id " +
        "WHERE lq.capture_id = ANY($publicArr) AND f.detected_at > $anchorExpr - interval '24 hours' AND f.detected_at <= $anchorExpr) " +
        "SELECT EXTRACT(EPOCH FROM ((CASE WHEN kst = kst_floor THEN kst_floor ELSE kst_floor + interval '1 hour' END) AT TIME ZONE 'Asia/Seoul'))::bigint, count(*) FROM d GROUP BY 1 ORDER BY 1"
    $sqlBuckets = (Invoke-Psql "zeekad" $bucketSql).Output.Trim()
    $sqlMap = [ordered]@{}
    foreach ($line in @($sqlBuckets -split "`r?`n" | Where-Object { $_ })) { $e, $n = $line -split '\|'; $sqlMap[[long]$e] = [int]$n }
    $apiMap = [ordered]@{}
    foreach ($b in @($ov24.Json.trend.buckets)) {
        if ([int]$b.total -gt 0) { $apiMap[[long]((ConvertTo-EpochMicros ([string]$b.end)) / 1000000)] = [int]$b.total }
    }
    $sqlText = ($sqlMap.GetEnumerator() | ForEach-Object { "$(Format-Micros ($_.Key * 1000000))=$($_.Value)" }) -join ', '
    $apiText = ($apiMap.GetEnumerator() | ForEach-Object { "$(Format-Micros ($_.Key * 1000000))=$($_.Value)" }) -join ', '
    $e2eLogs.Add("[T24d] 24h buckets (end UTC=count, non-zero): API [$apiText]; independent SQL [$sqlText]; API buckets=$(@($ov24.Json.trend.buckets).Count) first=$($ov24.Json.trend.buckets[0].start)~$($ov24.Json.trend.buckets[0].end) partial=$($ov24.Json.trend.buckets[0].partial)")
    Assert-True ($apiText -eq $sqlText -and $apiText.Length -gt 0) "[T24d] 24시간 구간별 수 = 독립 SQL (API [$apiText], SQL [$sqlText])"

    # [T24e] 숨김 캡처 흔적 0(overview·operations 기간 다섯), 가려지지 않은 IPv4 0, 허용 밖 captureId 403
    foreach ($period in @('1h', '24h', '7d', '30d', 'all')) {
        $ops = Invoke-Http -Path "/api/operations?period=$period" -Client $demo
        Assert-Status $ops 200 "[T24e] demo operations period=$period"
        $t24Bodies.Add($ops.Body)
        Find-UnmaskedIpv4 $ops.Json "operations[$period]" $t24IpHits
    }
    $leaks = @()
    foreach ($body in $t24Bodies) { foreach ($h in $demoHiddenCaptures) { if ($body.Contains($h)) { $leaks += $h } } }
    $deny = @()
    foreach ($h in @($demoHiddenCaptures | Select-Object -First 2)) {
        $d1 = Invoke-Http -Path "/api/dashboard/overview?period=24h&captureId=$h" -Client $demo
        $d2 = Invoke-Http -Path "/api/operations?period=7d&captureId=$h" -Client $demo
        $deny += "$h overview=$($d1.Status) operations=$($d2.Status)"
        Assert-Status $d1 403 "[T24e] demo overview 숨김 캡처 $h"
        Assert-Status $d2 403 "[T24e] demo operations 숨김 캡처 $h"
    }
    $e2eLogs.Add("[T24e] hidden captures=[$($demoHiddenCaptures -join ', ')] leaks in overview/operations bodies=$($leaks.Count) [$(@($leaks | Select-Object -Unique) -join ', ')]; denied: $($deny -join '; '); unmasked IPv4 JSON paths=$($t24IpHits.Count)$(if ($t24IpHits.Count) { ' ' + (($t24IpHits | Select-Object -First 20) -join ', ') })")
    Assert-True ($leaks.Count -eq 0) "[T24e] overview·operations에 숨김 캡처 흔적 0"
    Assert-True ($t24IpHits.Count -eq 0) "[T24e] overview·operations에 가려지지 않은 IPv4 없음"

    # [T24f] 응답 시간(curl 포함, 3회): overview all·24h, operations?period=7d
    $t24Timings = [ordered]@{}
    foreach ($t in @(@{ Name = 'overview all'; Path = "/api/dashboard/overview?period=all" },
                     @{ Name = 'overview 24h'; Path = "/api/dashboard/overview?period=24h" },
                     @{ Name = 'operations 7d'; Path = "/api/operations?period=7d" })) {
        $samples = @()
        for ($k = 0; $k -lt 3; $k++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-Http -Path $t.Path -Client $demo
            $sw.Stop()
            Assert-Status $r 200 "[T24f] $($t.Name)"
            $samples += [int]$sw.ElapsedMilliseconds
        }
        $t24Timings[$t.Name] = $samples
    }
    $t24TimingText = ($t24Timings.GetEnumerator() | ForEach-Object { "$($_.Key)=[$($_.Value -join ', ')] ms" }) -join '; '
    $t24Slow = @($t24Timings.GetEnumerator() | Where-Object { ($_.Value | Measure-Object -Minimum).Minimum -gt 1000 } | ForEach-Object { $_.Key })
    $e2eLogs.Add("[T24f] response times (3 samples each, includes curl): $t24TimingText; over 1s (min of 3): [$($t24Slow -join ', ')]")

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

    Write-Host "=== [6] demo 잠금 제외(T29) ==="
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
    $acRes = Invoke-Http -Path "/api/auth/login" -Method POST -Client $ac -Xff "1.2.3.4, $auditIp" -Csrf -JsonBody @{ username = "demo"; password = $env:DEMO_PASSWORD } -ExtraHeaders @("Forwarded: for=192.0.2.66", "X-Real-IP: 192.0.2.67", "X-Forwarded-Prefix: /evil")
    Assert-Status $acRes 200 "위조 X-Forwarded-For·Forwarded·X-Real-IP를 붙인 demo 로그인"
    $auditRow = (Invoke-Psql "zeekad_dashboard" "SELECT client_ip FROM audit_logs WHERE action_type = 'LOGIN_SUCCESS' AND actor_username = 'demo' ORDER BY id DESC LIMIT 1").Output.Trim()
    $e2eLogs.Add("[7d] demo login with X-Forwarded-For: 1.2.3.4, $auditIp + Forwarded: for=192.0.2.66 + X-Real-IP: 192.0.2.67 + X-Forwarded-Prefix: /evil -> HTTP $($acRes.Status); latest LOGIN_SUCCESS audit client_ip=$auditRow")
    Assert-True ($auditRow -eq $auditIp) "감사 로그 IP가 위조 값이 아니라 클라이언트 IP($auditIp)"

    # [T60] 관리자 TOTP 확인 경로(POST /api/auth/totp/verify)도 로그인 속도 제한에 든다(T60). 인증 없이 새 클라이언트 주소 하나에서
    #       버스트를 넘겨 보낸다([7a]의 판정 꼴). 한도 전 응답은 401(로그인하지 않음)이고 한도를 넘으면 429다.
    #       리허설을 위해 admin을 켜지 않는다(공개 스택의 admin은 [5]처럼 비활성이다). 인증 없는 요청이라 실패 횟수·감사에 닿지 않는다.
    $totpIp60 = "203.0.113.160"
    $tc60 = New-Client $totpIp60
    [void](Invoke-Http -Path "/api/auth/csrf" -Client $tc60)
    $totpStatuses60 = @()
    for ($k = 1; $k -le 12; $k++) {
        $totpStatuses60 += (Invoke-Http -Path "/api/auth/totp/verify" -Method POST -Client $tc60 -Csrf -JsonBody @{ code = "000000" }).Status
    }
    $totpFirst429 = [Array]::IndexOf($totpStatuses60, 429) + 1
    # 로그인과 영역 하나를 같이 쓴다: 같은 주소의 로그인 POST도 바로 429다
    $totpSameIpLogin60 = Invoke-Http -Path "/api/auth/login" -Method POST -Client $tc60 -Csrf -JsonBody @{ username = "rate-limit-probe"; password = "x" }
    $e2eLogs.Add("[T60] 12 x unauthenticated POST /api/auth/totp/verify from $totpIp60 -> [$($totpStatuses60 -join ', ')] (first 429 at #$totpFirst429); right after, POST /api/auth/login from the same IP -> HTTP $($totpSameIpLogin60.Status)")
    Assert-True ($totpFirst429 -ge 2 -and $totpFirst429 -le 8 -and @($totpStatuses60 | Where-Object { $_ -ne 429 -and $_ -ne 401 }).Count -eq 0) "[T60] 관리자 TOTP 확인 경로도 한 클라이언트 IP 한도 초과 시 429(그 전은 401)"
    Assert-Status $totpSameIpLogin60 429 "[T60] TOTP 확인과 로그인이 속도 제한 영역 하나를 같이 쓴다"

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

    Write-Host "=== [8b] WAF 감사 로그에 남는 값(T59) ==="
    # WAF 이미지가 감사 로그의 부분을 AHZ로 줄였다(docker/nginx-waf/Dockerfile). 공개 스택에서 실제로 걸렸는지 본다:
    # 없는 사용자 이름 + 표식 비밀번호로 로그인 실패(401), demo 세션으로 관리자 API 403을 만든 뒤 nginx-waf 컨테이너 로그 전체
    # (stdout + stderr)에 그 표식 비밀번호·세션 쿠키 값·CSRF 토큰 값이 0번 나온다. 두 요청의 감사 줄(요청 주소의 probe=)은 있고
    # 응답 코드가 맞으며 headers·body 키가 없다(0번이 빈 단언이 아님을 보인다).
    # 로그인 속도 제한(클라이언트 IP당)에 걸리지 않게 이 구간만 쓰는 주소 둘을 쓴다. [seed-3]이 demo 비밀번호를 바꾸기 전에 둔다.
    # 실패 글에는 값이나 로그 줄 원문을 넣지 않는다(개수와 응답 코드만). Login-Api·Assert-Status·Assert-ApiError는 실패하면
    # 응답 본문을 찍으므로 이 구간에서는 쓰지 않는다.
    function Get-WafLogText8b {
        # Out-String은 stderr 줄(ErrorRecord)을 콘솔 폭에서 접어 값이 줄 사이에서 갈릴 수 있다. 줄마다 글로 바꿔 잇는다.
        $logArgs8b = $composeArgs + @("logs", "--no-log-prefix", "nginx-waf")
        $savedEap8b = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $parts8b = @(& docker @logArgs8b 2>&1 | ForEach-Object {
                    if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" }
                })
        } finally {
            $ErrorActionPreference = $savedEap8b
        }
        return ($parts8b -join "`n")
    }
    function Get-Count8b([string]$Text, [string]$Value) {
        if (-not $Text -or -not $Value) { return 0 }
        return [regex]::Matches($Text, [regex]::Escape($Value)).Count
    }
    $pw8b = "PfT59Pw$(New-RandomToken 24)"
    $user8b = "pf-t59-nouser-$(New-RandomToken 8)"
    $probeFail8b = "pf-t59-loginfail-$(New-RandomToken 8)"
    $probeDenied8b = "pf-t59-denied-$(New-RandomToken 8)"

    $anon8b = New-Client "198.51.100.82"
    $csrfAnon8b = Invoke-Http -Path "/api/auth/csrf" -Client $anon8b
    Assert-True ($csrfAnon8b.Status -eq 200) "[8b] 비로그인 GET /api/auth/csrf (HTTP $($csrfAnon8b.Status))"
    $fail8b = Invoke-Http -Path "/api/auth/login" -Method POST -Client $anon8b -Csrf -JsonBody ([ordered]@{ username = $user8b; password = $pw8b }) -ProbeId $probeFail8b
    Assert-True ($fail8b.Status -eq 401 -and $null -ne $fail8b.Json -and $null -ne $fail8b.Json.code) "[8b] 없는 사용자 이름으로 로그인 실패는 앱의 401 (HTTP $($fail8b.Status))"

    $demo8b = New-Client "198.51.100.83"
    $csrfDemo8b = Invoke-Http -Path "/api/auth/csrf" -Client $demo8b
    Assert-True ($csrfDemo8b.Status -eq 200) "[8b] demo GET /api/auth/csrf (HTTP $($csrfDemo8b.Status))"
    $login8b = Invoke-Http -Path "/api/auth/login" -Method POST -Client $demo8b -Csrf -JsonBody @{ username = "demo"; password = $env:DEMO_PASSWORD }
    Assert-True ($login8b.Status -eq 200) "[8b] demo 로그인 (HTTP $($login8b.Status))"
    $session8b = [string]$demo8b.Cookies["ZEEKAD_SESSION"]
    $token8b = [string]$demo8b.Cookies["XSRF-TOKEN"]
    Assert-True ($session8b.Length -ge 16 -and $token8b.Length -ge 16) "[8b] 로그인 뒤 세션 쿠키와 CSRF 토큰이 있음(길이 16 이상)"
    $denied8b = Invoke-Http -Path "/api/admin/users" -Client $demo8b -ProbeId $probeDenied8b
    Assert-True ($denied8b.Status -eq 403 -and $null -ne $denied8b.Json -and $null -ne $denied8b.Json.code) "[8b] demo GET /api/admin/users 는 앱의 403 (HTTP $($denied8b.Status))"
    # 요청 사이에 쿠키 값이 바뀌었으면 바뀐 값도 센다.
    $sessionAfter8b = [string]$demo8b.Cookies["ZEEKAD_SESSION"]
    $tokenAfter8b = [string]$demo8b.Cookies["XSRF-TOKEN"]
    $tokenAnon8b = [string]$anon8b.Cookies["XSRF-TOKEN"]

    # 두 요청의 감사 줄이 나올 때까지 기다린 뒤(최대 10초) 로그 전체에서 센다.
    $expected8b = @(
        [pscustomobject]@{ Name = "로그인 실패"; Probe = $probeFail8b; Code = "401" },
        [pscustomobject]@{ Name = "권한 거부"; Probe = $probeDenied8b; Code = "403" }
    )
    $log8b = ""
    $lineOf8b = @{}
    for ($i = 0; $i -lt 10; $i++) {
        $log8b = Get-WafLogText8b
        $audit8b = @($log8b -split "`r?`n" | Where-Object { $_.StartsWith('{"transaction"') })
        $lineOf8b = @{}
        $missing8b = 0
        foreach ($e8b in $expected8b) {
            $probeNow8b = $e8b.Probe
            $hit8b = @($audit8b | Where-Object { Test-ProbeMark $_ $probeNow8b })
            if ($hit8b.Count -gt 0) { $lineOf8b[$e8b.Probe] = [string]$hit8b[-1] } else { $missing8b++ }
        }
        if ($missing8b -eq 0) { break }
        Start-Sleep -Seconds 1
    }
    $auditSummary8b = [System.Collections.Generic.List[string]]::new()
    foreach ($e8b in $expected8b) {
        $line8b = [string]$lineOf8b[$e8b.Probe]
        $code8b = [regex]::Match($line8b, '"http_code":(\d+)').Groups[1].Value
        $interrupted8b = $line8b -match '"is_interrupted":true'
        $hasHeaders8b = $line8b -match '"headers":\{'
        $hasBody8b = $line8b -match '"body":"'
        $auditSummary8b.Add("$($e8b.Name) http_code=$code8b is_interrupted=$interrupted8b headers=$hasHeaders8b body=$hasBody8b")
        Assert-True ([bool]$line8b) "[8b] $($e8b.Name) 요청의 nginx-waf 감사 줄이 있음(요청 주소의 probe=)"
        Assert-True ($code8b -eq $e8b.Code -and -not $interrupted8b) "[8b] $($e8b.Name) 감사 줄의 http_code=$($e8b.Code)·차단 아님 (실제 http_code=$code8b is_interrupted=$interrupted8b)"
        Assert-True (-not $hasHeaders8b -and -not $hasBody8b) "[8b] $($e8b.Name) 감사 줄에 headers·body 키가 없음 (headers=$hasHeaders8b body=$hasBody8b)"
    }
    $values8b = @(
        [pscustomobject]@{ Name = "표식 비밀번호"; Value = $pw8b },
        [pscustomobject]@{ Name = "세션 쿠키 값(로그인 직후)"; Value = $session8b },
        [pscustomobject]@{ Name = "세션 쿠키 값(요청 뒤)"; Value = $sessionAfter8b },
        [pscustomobject]@{ Name = "CSRF 토큰 값(로그인 직후)"; Value = $token8b },
        [pscustomobject]@{ Name = "CSRF 토큰 값(요청 뒤)"; Value = $tokenAfter8b },
        [pscustomobject]@{ Name = "CSRF 토큰 값(비로그인 요청)"; Value = $tokenAnon8b }
    )
    $counts8b = [System.Collections.Generic.List[string]]::new()
    foreach ($v8b in $values8b) {
        $n8b = Get-Count8b $log8b $v8b.Value
        $counts8b.Add("$($v8b.Name)=$n8b")
    }
    $e2eLogs.Add("[8b] WAF 감사 로그에 남는 값: 로그인 실패(없는 사용자 이름) HTTP $($fail8b.Status), demo GET /api/admin/users HTTP $($denied8b.Status)`n     감사 줄: $($auditSummary8b -join '; ')`n     nginx-waf 로그 전체($(@($log8b -split "`r?`n").Count)줄)에서 센 횟수: $($counts8b -join ', ')")
    foreach ($v8b in $values8b) {
        $n8b = Get-Count8b $log8b $v8b.Value
        Assert-True ([bool]$v8b.Value) "[8b] $($v8b.Name): 값을 읽음(빈 값이면 세지 못한다)"
        Assert-True ($n8b -eq 0) "[8b] nginx-waf 로그 전체에 $($v8b.Name) 0번 (실제 $($n8b)번)"
    }

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

    # ───────── [T52a] 시드가 중요 자산 목록을 자료 파일과 같게 맞춘다 ─────────
    # 1차가 만들고(created=N), 2차는 그대로(kept=N, 로그인 없는 NO_CHANGES). 자산만 다르면(이름 하나를 SQL로 바꾸고 파일에 없는 주소 하나를
    # SQL로 넣음) 관리자 단계를 돌아 고치고 지운 뒤 다시 실행하면 그대로다. 앱 DB 목록 = 파일, 변경마다 감사 CRITICAL_ASSET_CHANGE.
    Write-Host "=== [T52a] 시드의 중요 자산 맞추기 ==="
    $assetFile52 = Get-Content "docker/portfolio/seed/critical_assets.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $assetN52 = @($assetFile52.assets).Count
    $assetWant52 = (@($assetFile52.assets | Sort-Object hostIp | ForEach-Object { $_.hostIp }) -join ',')
    $assetRead52 = { (Invoke-Psql "zeekad_dashboard" "SELECT COALESCE(string_agg(host_ip, ',' ORDER BY host_ip), '') FROM critical_assets").Output.Trim() }
    $assetAuditCount52 = { [long](Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM audit_logs WHERE action_type = 'CRITICAL_ASSET_CHANGE'").Output.Trim() }
    $e2eLogs.Add("[T52a] seed run1: $([regex]::Match($seed1.Output, 'critical-assets: [^\r\n]*').Value); run2: $([regex]::Match($seed2.Output, 'critical-assets: [^\r\n]*').Value); file assets=$assetN52 [$assetWant52]; app DB [$(& $assetRead52)]")
    Assert-True ($seed1.Output -match "critical-assets: created=$assetN52 updated=0 deleted=0 kept=0") "[T52a] 시드 1차 critical-assets: created=$assetN52`n$($seed1.Output)"
    Assert-True ($seed2.Output -match "critical-assets: created=0 updated=0 deleted=0 kept=$assetN52") "[T52a] 시드 2차 critical-assets: kept=$assetN52"
    Assert-True ((& $assetRead52) -eq $assetWant52) "[T52a] 앱 DB 자산 주소 = 자료 파일 ([$(& $assetRead52)] vs [$assetWant52])"
    $firstAsset52 = @($assetFile52.assets)[0]
    $audit52a = & $assetAuditCount52
    [void](Invoke-Psql "zeekad_dashboard" "UPDATE critical_assets SET name = 'rehearsal-changed' WHERE host_ip = '$($firstAsset52.hostIp)'")
    [void](Invoke-Psql "zeekad_dashboard" "INSERT INTO critical_assets (host_ip, name, description, created_by, created_at, updated_by, updated_at) VALUES ('10.99.99.99', 'rehearsal-extra', NULL, 'rehearsal', now(), 'rehearsal', now())")
    $seed5 = Invoke-NativeCapture "docker" $seedArgs -IgnoreExitCode
    $seed6 = Invoke-NativeCapture "docker" $seedArgs -IgnoreExitCode
    $audit52b = & $assetAuditCount52
    Save-Evidence "seed-run-5.txt" "EXIT_CODE=$($seed5.ExitCode) (critical asset name changed and an extra asset inserted by SQL)`n$($seed5.Output)`n--- run 6 ---`nEXIT_CODE=$($seed6.ExitCode)`n$($seed6.Output)"
    $e2eLogs.Add("[T52a] asset-only drift: run5 $([regex]::Match($seed5.Output, 'critical-assets: [^\r\n]*').Value) $([regex]::Match($seed5.Output, 'RESULT: [^\r\n]*').Value); run6 $([regex]::Match($seed6.Output, 'critical-assets: [^\r\n]*').Value) $([regex]::Match($seed6.Output, 'RESULT: [^\r\n]*').Value); CRITICAL_ASSET_CHANGE audit rows $audit52a -> $audit52b")
    Assert-True ($seed5.ExitCode -eq 0 -and $seed5.Output -match "critical-assets: created=0 updated=1 deleted=1 kept=$($assetN52 - 1)" -and $seed5.Output -match 'seed: API admin login' -and $seed5.Output -match 'RESULT: CHANGED') "[T52a] 자산만 달라도 관리자 단계를 돌아 고치고 지운다`n$($seed5.Output)"
    Assert-True ($seed5.Output -notmatch 'seed: SQL SET_PASSWORD|seed: API (CREATE_USER|UPDATE_USER)') "[T52a] 자산만 다른 실행은 계정을 바꾸지 않는다"
    Assert-True ($seed6.ExitCode -eq 0 -and $seed6.Output -match 'RESULT: NO_CHANGES' -and $seed6.Output -match "kept=$assetN52") "[T52a] 맞춘 뒤 다시 실행하면 그대로"
    Assert-True ((& $assetRead52) -eq $assetWant52 -and $audit52b -eq $audit52a + 2) "[T52a] 앱 DB 자산 주소 = 자료 파일, 감사 두 행(고치기·지우기)"

    # ───────── [T33] 체험용 분석가 trial-analyst·매 주기 초기화(리허설 주기 1분) ─────────
    # 순서: 시드 확인 → 설정 전 미설정 로그 → sandbox-setup 두 번(멱등) → 권한 거부 시도 → 쓰기 흐름 → 다음 주기 초기화 확인(세 표 = 기준선,
    #       담당 해제 이력, 감사 로그 줄지 않음, 세 표 밖 zeekad 표 그대로·2분 뒤에도) → 서비스 멈춤 → 옛 기준선 거부 → 잠금 대기·시간 초과
    #       → 기준선 다시 만들기 거부·성공 → 잠금 없음 → 쓰기 속도 제한 → (선택) 노출 확인 → 리허설 일회용 DB의 담당 행 정리.
    Write-Host "=== [T33] 체험용 분석가 trial-analyst·매 주기 초기화 ==="
    $trialUser = "trial-analyst"
    $threeTables = @("incident_status", "incident_status_history", "analyst_review")
    $runSetup = { param([string[]]$Extra) Invoke-NativeCapture "docker" ($composeArgs + @("--profile", "seed", "run", "--rm", "sandbox-setup") + $Extra) -IgnoreExitCode }
    $runResetOnce = { Invoke-NativeCapture "docker" ($composeArgs + @("run", "--rm", "sandbox-reset", "--once")) -IgnoreExitCode }
    $resetLogs = { @((Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--no-log-prefix", "sandbox-reset")) -IgnoreExitCode).Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-reset: ' }) }
    # 세 표와 기준선 비교(기본키 기준 전체 칸 = 행 전체 EXCEPT 양방향, 행 수)
    $diffSql = ($threeTables | ForEach-Object {
            "SELECT '$_' || ':' || (SELECT count(*) FROM zeekad.$_) || '/' || (SELECT count(*) FROM sandbox_baseline.$_) || ':diff=' || " +
            "((SELECT count(*) FROM (SELECT * FROM zeekad.$_ EXCEPT SELECT * FROM sandbox_baseline.$_) a) + (SELECT count(*) FROM (SELECT * FROM sandbox_baseline.$_ EXCEPT SELECT * FROM zeekad.$_) b))"
        }) -join " UNION ALL "
    # UNION ALL은 병렬 실행 때 행 순서가 바뀔 수 있어 정렬한다(문자열로 비교한다).
    $diffSql = "SELECT * FROM ($diffSql) d ORDER BY 1"
    $baselineDiff = { (Invoke-Psql "zeekad" $diffSql).Output.Trim() -replace "`r?`n", '; ' }
    $isBaseline = { param($text) @([regex]::Matches($text, 'diff=(\d+)') | Where-Object { $_.Groups[1].Value -ne '0' }).Count -eq 0 -and @([regex]::Matches($text, ':(\d+)/(\d+):') | Where-Object { $_.Groups[1].Value -ne $_.Groups[2].Value }).Count -eq 0 }
    # 세 표 밖 zeekad 표 전부(기준선 스키마 제외): 행 수와 내용 해시(행마다 md5 → 정렬해 md5)
    $otherTables = @((Invoke-Psql "zeekad" ("SELECT table_schema || '.' || table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' " +
        "AND table_schema NOT IN ('pg_catalog', 'information_schema', 'sandbox', 'sandbox_baseline') " +
        "AND NOT (table_schema = 'zeekad' AND table_name IN ('incident_status', 'incident_status_history', 'analyst_review')) ORDER BY 1")).Output -split "`r?`n" | Where-Object { $_ })
    $otherSql = ($otherTables | ForEach-Object { "SELECT '$_' || '=' || count(*) || ':' || md5(COALESCE(string_agg(md5(t::text), '' ORDER BY md5(t::text)), '')) FROM $_ t" }) -join " UNION ALL "
    $otherSql = "SELECT * FROM ($otherSql) o ORDER BY 1"
    $otherHash = { (Invoke-Psql "zeekad" $otherSql).Output.Trim() }
    $rwPrivSql = "SELECT 'table:' || table_schema || '.' || table_name || ':' || privilege_type FROM information_schema.role_table_grants WHERE grantee = 'dashboard_rw' " +
        "UNION ALL SELECT 'routine:' || routine_schema || '.' || routine_name || ':' || privilege_type FROM information_schema.role_routine_grants WHERE grantee = 'dashboard_rw' " +
        "UNION ALL SELECT 'schema:' || nspname || ':usage=' || has_schema_privilege('dashboard_rw', oid, 'USAGE') || ',create=' || has_schema_privilege('dashboard_rw', oid, 'CREATE') FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema' AND (has_schema_privilege('dashboard_rw', oid, 'USAGE') OR has_schema_privilege('dashboard_rw', oid, 'CREATE')) " +
        "UNION ALL SELECT 'database:' || datname || ':connect=' || has_database_privilege('dashboard_rw', datname, 'CONNECT') || ',create=' || has_database_privilege('dashboard_rw', datname, 'CREATE') || ',temp=' || has_database_privilege('dashboard_rw', datname, 'TEMP') FROM pg_database WHERE datname IN ('zeekad', 'zeekad_dashboard') ORDER BY 1"

    # [T33a] 시드: trial-analyst 활성 ANALYST, 허용 캡처 = demo와 같음. 숨긴 캡처 403.
    $acct33 = (Invoke-Psql "zeekad_dashboard" "SELECT u.username, u.role, u.enabled, string_agg(a.capture_pattern, ',' ORDER BY a.capture_pattern) FROM users u LEFT JOIN user_capture_access a ON a.user_id = u.id WHERE u.username IN ('demo', '$trialUser') GROUP BY u.id ORDER BY u.username").Output.Trim()
    $rows33 = @($acct33 -split "`r?`n")
    $e2eLogs.Add("[T33a] public accounts (username|role|enabled|patterns): $($rows33 -join '; ')")
    $demoPat33 = ($rows33 | Where-Object { $_ -like 'demo|*' }) -replace '^demo\|VIEWER\|t\|', ''
    Assert-True ($rows33 -contains "$trialUser|ANALYST|t|$demoPat33" -and $demoPat33 -eq (($demoPatterns | Sort-Object) -join ',')) "[T33a] $trialUser 활성 ANALYST, 허용 캡처 = demo"
    $tc = New-Client "198.51.100.200"
    Assert-Status (Login-Api $tc $trialUser $env:TRIAL_ANALYST_PASSWORD) 200 "[T33a] $trialUser 로그인"
    $me33 = Invoke-Http -Path "/api/auth/me" -Client $tc
    Assert-True ($me33.Json.user.role -eq 'ANALYST' -and $me33.Json.user.maskedView -eq $false) "[T33a] $trialUser me: ANALYST·마스킹 없음" $me33
    foreach ($h in $demoHiddenCaptures) {
        $hq = Invoke-Http -Path "/api/incidents/queue?period=all&captureId=$h" -Client $tc
        $e2eLogs.Add("[T33a] $trialUser hidden capture $h queue -> HTTP $($hq.Status)")
        Assert-Status $hq 403 "[T33a] $trialUser 숨긴 캡처 $h"
    }

    # [T33b] 설정 전: sandbox-reset은 미설정 한 줄만(오류 아님). 설정 두 번(두 번째는 기준선 유지). 권한 점검.
    $preLogs = & $resetLogs
    $e2eLogs.Add("[T33b] sandbox-reset log before setup (last 2): $(($preLogs | Select-Object -Last 2) -join ' / ')")
    Assert-True ($preLogs.Count -ge 1 -and @($preLogs | Where-Object { $_ -match ' ERROR ' }).Count -eq 0 -and @($preLogs | Where-Object { $_ -match 'NOT_CONFIGURED' }).Count -ge 1) "[T33b] 설정 전 sandbox-reset은 NOT_CONFIGURED만 남김"
    $rwBefore = (Invoke-Psql "zeekad" $rwPrivSql).Output.Trim()
    $volsBeforeSetup = @((Invoke-NativeCapture "docker" @("volume", "ls", "-q")).Output -split "`r?`n" | Where-Object { $_ })
    $setup1 = & $runSetup @()
    $setup2 = & $runSetup @()
    $volsAfterSetup = @((Invoke-NativeCapture "docker" @("volume", "ls", "-q")).Output -split "`r?`n" | Where-Object { $_ })
    $newVolsSetup = @($volsAfterSetup | Where-Object { $volsBeforeSetup -notcontains $_ })
    $e2eLogs.Add("[0a] (T36) docker volumes before sandbox-setup x2=$($volsBeforeSetup.Count) after=$($volsAfterSetup.Count) new=[$($newVolsSetup -join ', ')]")
    Assert-True ($newVolsSetup.Count -eq 0) "[0a] sandbox-setup 실행 뒤 새 볼륨 없음 ($($newVolsSetup -join ', '))"
    Save-Evidence "t33-sandbox-setup.txt" "run1 exit=$($setup1.ExitCode)`n$($setup1.Output)`n--- run2 ---`nexit=$($setup2.ExitCode)`n$($setup2.Output)"
    $e2eLogs.Add("[T33b] sandbox-setup run1 exit=$($setup1.ExitCode): $((@($setup1.Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-setup: (baseline|privileges|RESULT)' })) -join ' / ')`n       run2 exit=$($setup2.ExitCode): $((@($setup2.Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-setup: (baseline|RESULT)' })) -join ' / ')")
    Assert-True ($setup1.ExitCode -eq 0 -and $setup1.Output -match 'baseline created' -and $setup1.Output -match 'RESULT: OK') "[T33b] sandbox-setup 1차(기준선 생성)`n$($setup1.Output)"
    Assert-True ($setup2.ExitCode -eq 0 -and $setup2.Output -match 'baseline kept' -and $setup2.Output -match 'RESULT: OK') "[T33b] sandbox-setup 2차(기준선 유지, 멱등)`n$($setup2.Output)"
    # [T54b] 기준선에 예시 셋이 들어갔다: 상태 행 +3, 이력 행 +6, 검토 행 그대로(시드 전 값과 견줌), 대응 조치 표식이 정탐 둘의 조치 기록 id 이상.
    #        시드 뒤 이 단계까지 zeekad 세 표에 쓰는 단계가 없다([4]의 demo 쓰기는 거부된다).
    $marker54 = (Invoke-Psql "zeekad" "SELECT incident_status_rows || '/' || incident_status_history_rows || '/' || analyst_review_rows FROM sandbox_baseline.marker WHERE id = 1").Output.Trim()
    $baseEx54 = (Invoke-Psql "zeekad" "SELECT (SELECT count(*) FROM sandbox_baseline.incident_status WHERE incident_id IN ($ids54Sql)) || '/' || (SELECT count(*) FROM sandbox_baseline.incident_status_history WHERE incident_id IN ($ids54Sql))").Output.Trim()
    $raMark54 = (Invoke-Psql "zeekad_dashboard" "SELECT (SELECT max_id FROM sandbox.response_action_baseline WHERE id = 1) || ':' || (SELECT max(id) FROM incident_response_actions WHERE actor_username = 'demo-analyst' AND incident_id IN ($ids54Sql)) || ':' || (SELECT count(*) FROM incident_response_actions WHERE actor_username = 'demo-analyst' AND incident_id IN ($ids54Sql))").Output.Trim()
    $expMarker54 = "$($pre54Rows[0] + 3)/$($pre54Rows[1] + 6)/$($pre54Rows[2])"
    $e2eLogs.Add("[T54b] baseline marker rows (status/history/review)=$marker54 (before seed $($pre54Rows -join '/'), expected $expMarker54); example rows in baseline (status/history)=$baseEx54; response action marker max_id:demo-analyst max id:count=$raMark54")
    Assert-True ($marker54 -eq $expMarker54 -and $baseEx54 -eq '3/6') "[T54b] 기준선 = 시드 전 + 예시 셋(상태 +3, 이력 +6, 검토 그대로) ($marker54, expected $expMarker54; examples $baseEx54)"
    $raParts54 = @($raMark54 -split ':')
    Assert-True ($raParts54.Count -eq 3 -and $raParts54[2] -eq '2' -and [long]$raParts54[0] -ge [long]$raParts54[1]) "[T54b] 대응 조치 표식이 예시의 조치 기록 둘의 id 이상 ($raMark54)"
    $rwAfter = (Invoke-Psql "zeekad" $rwPrivSql).Output.Trim()
    $fnPriv = (Invoke-Psql "zeekad" "SELECT 'reset_role_exec=' || has_function_privilege('zeekad_sandbox_reset', 'sandbox.reset_pipeline()', 'EXECUTE') || ' dashboard_rw_exec=' || has_function_privilege('dashboard_rw', 'sandbox.reset_pipeline()', 'EXECUTE') || ' public_exec=' || EXISTS (SELECT 1 FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) x WHERE p.oid = 'sandbox.reset_pipeline()'::regprocedure AND x.grantee = 0) || ' secdef=' || (SELECT prosecdef FROM pg_proc WHERE oid = 'sandbox.reset_pipeline()'::regprocedure) || ' config=' || (SELECT array_to_string(proconfig, ',') FROM pg_proc WHERE oid = 'sandbox.reset_pipeline()'::regprocedure)").Output.Trim()
    $fnPrivD = (Invoke-Psql "zeekad_dashboard" "SELECT 'reset_role_exec=' || has_function_privilege('zeekad_sandbox_reset', 'sandbox.reset_assignments()', 'EXECUTE') || ' app_owner=' || (SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid = 'sandbox.reset_assignments()'::regprocedure) || ' public_exec=' || EXISTS (SELECT 1 FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) x WHERE p.oid = 'sandbox.reset_assignments()'::regprocedure AND x.grantee = 0) || ' config=' || (SELECT array_to_string(proconfig, ',') FROM pg_proc WHERE oid = 'sandbox.reset_assignments()'::regprocedure)").Output.Trim()
    Save-Evidence "t33-privileges.txt" "# dashboard_rw privileges before sandbox-setup`n$rwBefore`n`n# after`n$rwAfter`n`n# functions`nzeekad: $fnPriv`nzeekad_dashboard: $fnPrivD`n"
    $e2eLogs.Add("[T33b] dashboard_rw privileges unchanged=$($rwBefore -eq $rwAfter) (rows=$(@($rwAfter -split "`r?`n").Count)); zeekad: $fnPriv; zeekad_dashboard: $fnPrivD")
    Assert-True ($rwBefore -eq $rwAfter -and $rwBefore.Length -gt 0) "[T33b] dashboard_rw 권한 목록이 설정 전과 같다"
    Assert-True ($fnPriv -match 'reset_role_exec=true dashboard_rw_exec=false public_exec=false secdef=true config=search_path=pg_catalog, pg_temp,lock_timeout=5s') "[T33b] reset_pipeline: 전용 역할만 EXECUTE, SECURITY DEFINER, search_path 고정 ($fnPriv)"
    Assert-True ($fnPrivD -match 'reset_role_exec=true app_owner=dashboard_app public_exec=false config=search_path=pg_catalog, pg_temp,lock_timeout=5s') "[T33b] reset_assignments: 전용 역할만 EXECUTE ($fnPrivD)"

    # [T56a] 대응 조치 초기화 함수와 기준선 표식(sandbox-setup이 만든다): 함수는 소유 dashboard_app, SECURITY DEFINER, search_path·lock_timeout 고정,
    #        초기화 계정만 EXECUTE(PUBLIC 불가). 표식은 한 행(설정 시점의 최대 id)이고 초기화 계정에는 표식 표와 대응 조치 표의 권한이 없다.
    #        대응 조치 표의 트리거는 둘(행 수준 UPDATE·DELETE, 문장 수준 TRUNCATE). 2차 실행은 표식을 그대로 둔다.
    $fnPrivR = (Invoke-Psql "zeekad_dashboard" "SELECT 'reset_role_exec=' || has_function_privilege('zeekad_sandbox_reset', 'sandbox.reset_response_actions()', 'EXECUTE') || ' app_owner=' || (SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid = 'sandbox.reset_response_actions()'::regprocedure) || ' public_exec=' || EXISTS (SELECT 1 FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) x WHERE p.oid = 'sandbox.reset_response_actions()'::regprocedure AND x.grantee = 0) || ' secdef=' || (SELECT prosecdef FROM pg_proc WHERE oid = 'sandbox.reset_response_actions()'::regprocedure) || ' config=' || (SELECT array_to_string(proconfig, ',') FROM pg_proc WHERE oid = 'sandbox.reset_response_actions()'::regprocedure)").Output.Trim()
    $raMarker = (Invoke-Psql "zeekad_dashboard" "SELECT 'owner=' || pg_get_userbyid(c.relowner) || ' rows=' || (SELECT count(*) FROM sandbox.response_action_baseline) || ' max_id=' || (SELECT max_id FROM sandbox.response_action_baseline WHERE id = 1) || ' table_max=' || (SELECT COALESCE(max(id), 0) FROM public.incident_response_actions) || ' reset_role_marker=' || has_table_privilege('zeekad_sandbox_reset', 'sandbox.response_action_baseline', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE') || ' reset_role_actions=' || has_table_privilege('zeekad_sandbox_reset', 'public.incident_response_actions', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE') FROM pg_class c WHERE c.oid = 'sandbox.response_action_baseline'::regclass").Output.Trim()
    $raTriggers = (Invoke-Psql "zeekad_dashboard" "SELECT string_agg(tgname || ':' || pg_get_triggerdef(oid), ' ; ' ORDER BY tgname) FROM pg_trigger WHERE tgrelid = 'public.incident_response_actions'::regclass AND NOT tgisinternal").Output.Trim()
    $setupRaLines = @($setup1.Output -split "`r?`n" | Where-Object { $_ -match 'response' })
    $setupRaLines2 = @($setup2.Output -split "`r?`n" | Where-Object { $_ -match 'response action baseline' })
    $e2eLogs.Add("[T56a] reset_response_actions(): $fnPrivR; baseline marker: $raMarker; incident_response_actions triggers: $raTriggers`n       sandbox-setup run1: $($setupRaLines -join ' / ')`n       run2: $($setupRaLines2 -join ' / ')")
    Assert-True ($fnPrivR -match 'reset_role_exec=true app_owner=dashboard_app public_exec=false secdef=true config=search_path=pg_catalog, pg_temp,lock_timeout=5s') "[T56a] reset_response_actions: 소유 dashboard_app, SECURITY DEFINER, search_path·lock_timeout 고정, 초기화 계정만 EXECUTE(PUBLIC 불가) ($fnPrivR)"
    Assert-True ($raMarker -match '^owner=dashboard_app rows=1 max_id=(\d+) table_max=\1 reset_role_marker=false reset_role_actions=false$') "[T56a] 기준선 표식: 소유 dashboard_app, 한 행, 설정 시점의 최대 id, 초기화 계정은 두 표의 권한 없음 ($raMarker)"
    Assert-True ($raTriggers -match 'trg_incident_response_actions_immutable:.*BEFORE DELETE OR UPDATE ON public\.incident_response_actions FOR EACH ROW' -and $raTriggers -match 'trg_incident_response_actions_no_truncate:.*BEFORE TRUNCATE ON public\.incident_response_actions FOR EACH STATEMENT') "[T56a] incident_response_actions 트리거 둘(UPDATE·DELETE 행 수준, TRUNCATE 문장 수준) ($raTriggers)"
    Assert-True ($setup1.Output -match 'response action baseline created: max_id=\d+' -and $setup1.Output -match 'response_actions\[actions_select=false marker_select=false reset_public_execute=false\]') "[T56a] sandbox-setup 1차가 대응 조치 표식을 만들고 권한을 점검함"
    Assert-True ($setup2.Output -match 'response action baseline kept: max_id=\d+ ') "[T56a] sandbox-setup 2차는 대응 조치 표식을 그대로 둠(멱등)"

    # [T58a] 감사 로그 삭제 함수(앱 migration V4가 만들고 sandbox-setup은 EXECUTE만 준다): 소유 dashboard_app, SECURITY DEFINER,
    #        search_path·lock_timeout 고정, 초기화 계정은 실행 가능, PUBLIC은 실행 불가. audit_logs의 트리거는 둘(행 수준 UPDATE·DELETE, 문장 수준 TRUNCATE).
    $fnPrivP = (Invoke-Psql "zeekad_dashboard" "SELECT 'reset_role_exec=' || has_function_privilege('zeekad_sandbox_reset', 'public.purge_expired_audit_logs(integer)', 'EXECUTE') || ' app_owner=' || (SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid = 'public.purge_expired_audit_logs(integer)'::regprocedure) || ' public_exec=' || EXISTS (SELECT 1 FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) x WHERE p.oid = 'public.purge_expired_audit_logs(integer)'::regprocedure AND x.grantee = 0) || ' secdef=' || (SELECT prosecdef FROM pg_proc WHERE oid = 'public.purge_expired_audit_logs(integer)'::regprocedure) || ' config=' || (SELECT array_to_string(proconfig, ',') FROM pg_proc WHERE oid = 'public.purge_expired_audit_logs(integer)'::regprocedure)").Output.Trim()
    $auditTriggers = (Invoke-Psql "zeekad_dashboard" "SELECT string_agg(tgname || ':' || pg_get_triggerdef(oid), ' ; ' ORDER BY tgname) FROM pg_trigger WHERE tgrelid = 'public.audit_logs'::regclass AND NOT tgisinternal").Output.Trim()
    $resetTableGrants = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'zeekad_sandbox_reset'").Output.Trim()
    $setupPurgeLines = @($setup1.Output -split "`r?`n" | Where-Object { $_ -match 'purge_expired_audit_logs|purge_public_execute' })
    $e2eLogs.Add("[T58a] purge_expired_audit_logs(integer): $fnPrivP; audit_logs triggers: $auditTriggers; table grants of zeekad_sandbox_reset in zeekad_dashboard=$resetTableGrants`n       sandbox-setup: $($setupPurgeLines -join ' / ')")
    Assert-True ($fnPrivP -match 'reset_role_exec=true app_owner=dashboard_app public_exec=false secdef=true config=search_path=pg_catalog, pg_temp,lock_timeout=5s') "[T58a] purge_expired_audit_logs: 소유 dashboard_app, SECURITY DEFINER, search_path·lock_timeout 고정, 초기화 계정만 EXECUTE(PUBLIC 불가) ($fnPrivP)"
    Assert-True ($auditTriggers -match 'trg_audit_logs_immutable:.*BEFORE DELETE OR UPDATE ON public\.audit_logs FOR EACH ROW' -and $auditTriggers -match 'trg_audit_logs_no_truncate:.*BEFORE TRUNCATE ON public\.audit_logs FOR EACH STATEMENT') "[T58a] audit_logs 트리거 둘(UPDATE·DELETE 행 수준, TRUNCATE 문장 수준) ($auditTriggers)"
    Assert-True ($resetTableGrants -eq '0') "[T58a] 초기화 계정의 앱 DB 표 권한 0 ($resetTableGrants)"
    Assert-True ($setup1.Output -match 'EXECUTE on public\.purge_expired_audit_logs\(integer\) granted to zeekad_sandbox_reset' -and $setup1.Output -match 'purge_public_execute=false') "[T58a] sandbox-setup이 삭제 함수 EXECUTE를 주고 PUBLIC 실행 불가를 점검함"
    # 컨테이너 로그 크기 한도(json-file 10MB x 5): 상주 서비스 다섯의 컨테이너에 걸려 있다.
    $logCfg = @(foreach ($svc in @("postgres", "api", "dashboard-app", "nginx-waf", "sandbox-reset")) {
            "$svc=" + (Invoke-NativeCapture "docker" @("inspect", "--format", "{{json .HostConfig.LogConfig}}", (Get-ServiceContainer $svc))).Output.Trim()
        })
    $e2eLogs.Add("[T58a] container log config: $($logCfg -join ' ')")
    Assert-True ($logCfg.Count -eq 5 -and @($logCfg | Where-Object { $_ -notmatch '"Type":"json-file"' -or $_ -notmatch '"max-size":"10m"' -or $_ -notmatch '"max-file":"5"' }).Count -eq 0) "[T58a] 상주 서비스 다섯에 로그 크기 한도 json-file 10m x 5 ($($logCfg -join ' '))"

    # [T33c] 초기화 전용 계정으로 실제 시도: 세 표 SELECT, 기준선 UPDATE, sandbox·public CREATE, 앱 DB 담당 표 SELECT는 모두 거부
    $denyProbes = @(
        @("zeekad", "SELECT count(*) FROM zeekad.incident_status"),
        @("zeekad", "SELECT count(*) FROM zeekad.incident_status_history"),
        @("zeekad", "SELECT count(*) FROM zeekad.analyst_review"),
        @("zeekad", "UPDATE sandbox_baseline.incident_status SET status = status"),
        @("zeekad", "UPDATE sandbox_baseline.marker SET fingerprint = 'x'"),
        @("zeekad", "CREATE TABLE sandbox.t33_probe (id int)"),
        @("zeekad", "CREATE TABLE public.t33_probe (id int)"),
        @("zeekad", "CREATE TABLE sandbox_baseline.t33_probe (id int)"),
        @("zeekad", "SELECT dashboard.transition_incident(1, 'x', 'investigating', 'x', 'x')"),
        # T53: 다시 열기 함수(zeek_AD migration 018)도 초기화 계정은 부를 수 없다(실행 권한은 dashboard_rw뿐)
        @("zeekad", "SELECT dashboard.reopen_incident(1, 'x', 'x', 'x', NULL)"),
        @("zeekad_dashboard", "SELECT count(*) FROM public.incident_assignments"),
        @("zeekad_dashboard", "SELECT count(*) FROM public.audit_logs"),
        @("zeekad_dashboard", "DELETE FROM public.audit_logs"),
        @("zeekad_dashboard", "TRUNCATE public.audit_logs"),
        @("zeekad_dashboard", "UPDATE public.audit_logs SET action_type = action_type"),
        # T56: 대응 조치 표와 기준선 표식 표도 읽지도 고치지도 못한다(표식을 켜도 표 권한이 없다)
        @("zeekad_dashboard", "SELECT count(*) FROM public.incident_response_actions"),
        @("zeekad_dashboard", "UPDATE public.incident_response_actions SET note = note"),
        @("zeekad_dashboard", "DELETE FROM public.incident_response_actions"),
        @("zeekad_dashboard", "SET dashboard.response_actions_reset = 'on'; DELETE FROM public.incident_response_actions"),
        @("zeekad_dashboard", "TRUNCATE public.incident_response_actions"),
        @("zeekad_dashboard", "SELECT max_id FROM sandbox.response_action_baseline"),
        @("zeekad_dashboard", "UPDATE sandbox.response_action_baseline SET max_id = 0"),
        @("zeekad_dashboard", "DELETE FROM sandbox.response_action_baseline"),
        @("zeekad_dashboard", "CREATE TABLE public.t33_probe (id int)"),
        @("zeekad_dashboard", "CREATE TABLE sandbox.t33_probe (id int)")
    )
    $denyLines = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $denyProbes) {
        $r = Invoke-Psql $p[0] $p[1] -User "zeekad_sandbox_reset" -PasswordEnv "SANDBOX_RESET_DB_PASSWORD"
        $err = [regex]::Match($r.Output, 'ERROR:[^\r\n]*').Value.Trim()
        $denyLines.Add("$($p[0]): $($p[1]) -> exit=$($r.ExitCode) $err")
        Assert-True ($r.ExitCode -ne 0 -and $err -match 'permission denied') "[T33c] zeekad_sandbox_reset 거부: $($p[0]) $($p[1]) ($err)"
    }
    $okCall = Invoke-Psql "zeekad" "SELECT count(*) FROM sandbox.reset_pipeline()" -User "zeekad_sandbox_reset" -PasswordEnv "SANDBOX_RESET_DB_PASSWORD"
    $denyLines.Add("(대조) zeekad: SELECT count(*) FROM sandbox.reset_pipeline() -> exit=$($okCall.ExitCode) $($okCall.Output.Trim())")
    Assert-True ($okCall.ExitCode -eq 0) "[T33c] zeekad_sandbox_reset은 초기화 함수는 부른다"
    # T58: 삭제 함수는 부를 수 있지만(기한 90일, 지울 행 없음) 바닥값(30일)보다 짧은 기한은 예외다. 표는 위에서 본 대로 읽지도 지우지도 못한다.
    $okPurge = Invoke-Psql "zeekad_dashboard" "SELECT deleted FROM public.purge_expired_audit_logs(90)" -User "zeekad_sandbox_reset" -PasswordEnv "SANDBOX_RESET_DB_PASSWORD"
    $lowPurge = Invoke-Psql "zeekad_dashboard" "SELECT deleted FROM public.purge_expired_audit_logs(29)" -User "zeekad_sandbox_reset" -PasswordEnv "SANDBOX_RESET_DB_PASSWORD"
    $lowPurgeErr = [regex]::Match($lowPurge.Output, 'ERROR:[^\r\n]*').Value.Trim()
    $denyLines.Add("(대조) zeekad_dashboard: SELECT deleted FROM public.purge_expired_audit_logs(90) -> exit=$($okPurge.ExitCode) $($okPurge.Output.Trim())")
    $denyLines.Add("zeekad_dashboard: SELECT deleted FROM public.purge_expired_audit_logs(29) -> exit=$($lowPurge.ExitCode) $lowPurgeErr")
    Assert-True ($okPurge.ExitCode -eq 0 -and $okPurge.Output.Trim() -match '^\d+$') "[T33c] zeekad_sandbox_reset은 감사 로그 삭제 함수는 부른다 ($($okPurge.Output.Trim()))"
    Assert-True ($lowPurge.ExitCode -ne 0 -and $lowPurgeErr -match 'audit retention must be at least 30 days') "[T33c] 삭제 함수는 30일보다 짧은 기한을 거부한다 ($lowPurgeErr)"
    # T56: 대응 조치 초기화 함수는 부를 수 있다(이 시점에는 기준선 뒤의 행이 없어 0).
    $okResponses = Invoke-Psql "zeekad_dashboard" "SELECT removed FROM sandbox.reset_response_actions()" -User "zeekad_sandbox_reset" -PasswordEnv "SANDBOX_RESET_DB_PASSWORD"
    $denyLines.Add("(대조) zeekad_dashboard: SELECT removed FROM sandbox.reset_response_actions() -> exit=$($okResponses.ExitCode) $($okResponses.Output.Trim())")
    Assert-True ($okResponses.ExitCode -eq 0 -and $okResponses.Output.Trim() -eq '0') "[T33c] zeekad_sandbox_reset은 대응 조치 초기화 함수는 부른다 ($($okResponses.Output.Trim()))"
    Save-Evidence "t33-deny-probes.txt" (($denyLines -join "`n") + "`n")
    $e2eLogs.Add("[T33c] zeekad_sandbox_reset attempts:`n       $($denyLines -join "`n       ")")

    # [T33d] 쓰기 전 기록
    $other0 = & $otherHash
    $other0b = & $otherHash
    Assert-True ($other0 -eq $other0b) "[T33d] 세 표 밖 zeekad 표 해시를 두 번 재면 같다(측정이 안정적)"
    $audit0 = [long](Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM audit_logs").Output.Trim()
    $ahist0 = [long](Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM incident_assignment_history").Output.Trim()
    # T56: 대응 조치 표의 행 수(전체|체험 계정)와 체험 계정의 대응 조치 감사 행 수
    $raCountSql = "SELECT count(*) || '|' || count(*) FILTER (WHERE actor_username = '$trialUser') FROM incident_response_actions"
    $raAuditSql = "SELECT count(*) FROM audit_logs WHERE action_type = 'INCIDENT_RESPONSE_ACTION' AND actor_username = '$trialUser'"
    $ra0 = (Invoke-Psql "zeekad_dashboard" $raCountSql).Output.Trim()
    $raAudit0 = [long](Invoke-Psql "zeekad_dashboard" $raAuditSql).Output.Trim()
    Assert-True ($ra0 -match '^\d+\|0$') "[T33d] 쓰기 전 체험 계정의 대응 조치 기록 0 ($ra0)"
    Assert-True (& $isBaseline (& $baselineDiff)) "[T33d] 쓰기 전 세 표 = 기준선"
    # T39: 표본은 공개 실습망 캡처에서 뽑되 lab-20261122를 먼저 보고 없으면 lab-20261119에서 뽑는다(어느 캡처인지 로그에 남긴다).
    $open33 = @(); $pend33 = @(); $openCap33 = ''; $pendCap33 = ''
    # T54: 두 표본 모두 분석이 끝난 예시 셋을 뺀다(예시 A에는 옛 작업의 미결정 검토가 있다. 리허설 쓰기가 예시를 건드리지 않게).
    foreach ($sampleCap in @('lab-20261122', 'lab-20261119')) {
        if ($open33.Count -lt 6) {
            $open33 = @((Invoke-Psql "zeekad" "SELECT lq.job_id || '|' || lq.queue_rank || '|' || lq.incident_id FROM dashboard.latest_incident_queue lq WHERE lq.capture_id = '$sampleCap' AND lq.incident_id NOT IN ($ids54Sql) AND NOT EXISTS (SELECT 1 FROM zeekad.incident_status s WHERE s.incident_id = lq.incident_id) ORDER BY lq.job_id, lq.queue_rank LIMIT 6").Output -split "`r?`n" | Where-Object { $_ })
            $openCap33 = $sampleCap
        }
        if ($pend33.Count -lt 2) {
            $pend33 = @((Invoke-Psql "zeekad" "SELECT r.job_id || '|' || r.incident_id FROM zeekad.analyst_review r WHERE r.action IS NULL AND split_part(r.incident_id, '|', 1) = '$sampleCap' AND r.incident_id NOT IN ($ids54Sql) ORDER BY r.job_id, r.incident_id LIMIT 2").Output -split "`r?`n" | Where-Object { $_ })
            $pendCap33 = $sampleCap
        }
    }
    $e2eLogs.Add("[T33d] samples: open incidents from $openCap33 ($($open33.Count)), pending reviews from $pendCap33 ($($pend33.Count))")
    Assert-True ($open33.Count -ge 6 -and $pend33.Count -ge 2) "[T33d] 실습망 공개 캡처에 신규 인시던트 6건($openCap33)·미결정 검토 2건($pendCap33) (open=$($open33.Count), pending=$($pend33.Count))"
    $inc = @($open33 | ForEach-Object { $p = $_ -split '\|', 3; [pscustomobject]@{ Job = $p[0]; Rank = $p[1]; Id = $p[2] } })
    $rev = @($pend33 | ForEach-Object { $p = $_ -split '\|', 2; [pscustomobject]@{ Job = [long]$p[0]; Id = $p[1] } })

    # [T33e] trial-analyst 쓰기 흐름: open → investigating(담당 자동 지정) → closed, 검토 결정 하나, 담당 지정 하나
    #        쓰기와 바로 뒤 확인이 주기(매분 0초) 초기화와 겹치지 않게 분의 3~15초에 시작한다.
    #        T56: 대응 조치 기록 하나를 더한다. 같은 클라이언트 주소의 쓰기는 지금처럼 넷으로 두고(공개 설정: 분당 10회·버스트 5)
    #        기록은 다른 클라이언트 주소로 보낸다(그 주소의 쓰기는 하나). 로그인은 기다리기 전에 해 둔다.
    $t56c = New-Client "198.51.100.202"
    Assert-Status (Login-Api $t56c $trialUser $env:TRIAL_ANALYST_PASSWORD) 200 "[T56b] $trialUser 로그인(대응 조치 기록용 클라이언트)"
    while ((Get-Date).ToUniversalTime().Second -notin 3..15) { Start-Sleep -Milliseconds 500 }
    $w1 = Invoke-Http -Path "/api/incidents/$($inc[0].Job)/rank/$($inc[0].Rank)/transition" -Method POST -Client $tc -Csrf -JsonBody @{ toStatus = "investigating"; reason = "T33 리허설: 조사 시작" }
    $w2 = Invoke-Http -Path "/api/incidents/$($inc[0].Job)/rank/$($inc[0].Rank)/transition" -Method POST -Client $tc -Csrf -JsonBody @{ toStatus = "closed"; resolution = "benign"; reason = "T33 리허설: 정상으로 종결" }
    $w3 = Invoke-Http -Path "/api/reviews/decide" -Method POST -Client $tc -Csrf -JsonBody @{ jobId = $rev[0].Job; incidentId = $rev[0].Id; action = "confirm"; note = "T33 리허설: 승인" }
    $w4 = Invoke-Http -Path "/api/incidents/$($inc[1].Job)/rank/$($inc[1].Rank)/assignment" -Method POST -Client $tc -Csrf -JsonBody @{ assignee = $trialUser; expected = $null }
    foreach ($w in @(@($w1, "open -> investigating"), @($w2, "investigating -> closed"), @($w3, "review decide confirm"), @($w4, "assignment"))) {
        $e2eLogs.Add("[T33e] $trialUser $($w[1]): $(Format-Resp $w[0] 200)")
        Assert-Status $w[0] 200 "[T33e] $trialUser $($w[1])"
    }
    # [T56b] 체험 계정이 방금 종결한 인시던트에 대응 조치를 기록한다(종결 뒤에도 덧붙일 수 있다): 행 하나와 감사 INCIDENT_RESPONSE_ACTION 하나.
    $w5 = Invoke-Http -Path "/api/incidents/$($inc[0].Job)/rank/$($inc[0].Rank)/response-actions" -Method POST -Client $t56c -Csrf -JsonBody @{ action = "monitor"; note = "T56 리허설: 모니터링 강화" }
    $ra1 = (Invoke-Psql "zeekad_dashboard" $raCountSql).Output.Trim()
    $raAudit1 = [long](Invoke-Psql "zeekad_dashboard" $raAuditSql).Output.Trim()
    $e2eLogs.Add("[T56b] $trialUser response action (monitor) from 198.51.100.202: $(Format-Resp $w5 200)`n       incident_response_actions (all|trial) $ra0 -> $ra1; INCIDENT_RESPONSE_ACTION audit rows $raAudit0 -> $raAudit1")
    Assert-Status $w5 200 "[T56b] $trialUser 대응 조치 기록"
    Assert-True ($ra1 -eq "$([long]($ra0 -split '\|')[0] + 1)|1" -and $raAudit1 -eq $raAudit0 + 1) "[T56b] 기록 뒤 행 하나·감사 하나 ($ra0 -> $ra1, 감사 $raAudit0 -> $raAudit1)"
    $writeAt = Get-Date
    $after33 = & $baselineDiff
    $assigned33 = (Invoke-Psql "zeekad_dashboard" "SELECT a.incident_id IN ('$($inc[0].Id)', '$($inc[1].Id)') || ':' || u.username || ':' || h.reason FROM incident_assignments a JOIN users u ON u.id = a.assignee_user_id JOIN LATERAL (SELECT reason FROM incident_assignment_history x WHERE x.incident_id = a.incident_id ORDER BY id DESC LIMIT 1) h ON TRUE ORDER BY 1").Output.Trim() -replace "`r?`n", '; '
    $other1 = & $otherHash
    $e2eLogs.Add("[T33e] after writes: three tables vs baseline: $after33; current assignments (target|assignee|last reason): $assigned33; other zeekad tables unchanged=$($other0 -eq $other1) (tables=$($otherTables.Count))")
    Assert-True (-not (& $isBaseline $after33)) "[T33e] 쓰기 뒤 세 표가 기준선과 다르다"
    Assert-True ($assigned33 -eq "true:${trialUser}:auto_on_start; true:${trialUser}:manual") "[T33e] 조사 시작 자동 담당·직접 담당 ($assigned33)"
    $otherChanged = { param($a, $b) @(Compare-Object @($a -split "`r?`n") @($b -split "`r?`n") | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }) -join '; ' }
    if ($other0 -ne $other1) { $e2eLogs.Add("[T33e] other zeekad tables changed: $(& $otherChanged $other0 $other1)") }
    Assert-True ($other0 -eq $other1) "[T33e] 쓰기 직후 세 표 밖 zeekad 표(행 수·내용 해시) 그대로"

    # [T33f] 다음 주기(1분) 초기화 뒤: 세 표 = 기준선, 담당 해제 + 이력 sandbox-reset, 기한 안의 감사 로그는 줄지 않음(T58). 검토 결정 2분 뒤 세 표 밖 표 그대로.
    $deadline = $writeAt.AddSeconds(150)
    while ((Get-Date) -lt $deadline) { Start-Sleep -Seconds 5 }
    $logs33 = & $resetLogs
    $okLines = @($logs33 | Where-Object { $_ -match ' sandbox-reset: OK ' })
    $changedLine = @($okLines | Where-Object { $_ -match '\(-[1-9]|\+[1-9]|~[1-9]|released=[1-9]' }) | Select-Object -Last 1
    $final33 = & $baselineDiff
    $other2 = & $otherHash
    $audit1 = [long](Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM audit_logs").Output.Trim()
    $assignNow = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) FILTER (WHERE assignee_user_id IS NOT NULL) || '/' || count(*) FROM incident_assignments").Output.Trim()
    $resetHist = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) || ':' || count(*) FILTER (WHERE to_user_id IS NULL AND reason = 'manual') FROM incident_assignment_history WHERE actor_username = 'sandbox-reset'").Output.Trim()
    $ahist1 = [long](Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM incident_assignment_history").Output.Trim()
    $e2eLogs.Add("[T33f] reset log line with changes: $changedLine`n       ERROR lines=$(@($logs33 | Where-Object { $_ -match ' ERROR ' }).Count); OK lines=$($okLines.Count)`n       three tables vs baseline after reset: $final33`n       assignments (with assignee/all rows)=$assignNow; sandbox-reset history rows (all:released)=$resetHist; assignment history $ahist0 -> $ahist1; audit_logs $audit0 -> $audit1`n       other zeekad tables unchanged 150 s after the review decision=$($other0 -eq $other2)")
    Save-Evidence "t33-other-tables.txt" "# 세 표 밖 zeekad 표(행 수:내용 해시). before writes / right after / 150 s after`n$other0`n`n$(if ($other1 -eq $other0) { '(same)' } else { $other1 })`n`n$(if ($other2 -eq $other0) { '(same)' } else { $other2 })`n"
    Assert-True ([bool]$changedLine -and @($logs33 | Where-Object { $_ -match ' ERROR ' }).Count -eq 0) "[T33f] sandbox-reset 로그에 바뀐 행 수가 있는 OK 줄, ERROR 없음"
    Assert-True (& $isBaseline $final33) "[T33f] 초기화 뒤 세 표 = 기준선 ($final33)"
    Assert-True ($assignNow -match '^0/') "[T33f] 담당 해제 ($assignNow)"
    Assert-True ($resetHist -eq '2:2' -and $ahist1 -eq $ahist0 + 4) "[T33f] 담당 이력에 sandbox-reset 해제 2행(자동·직접 지정 2행 + 해제 2행) ($resetHist, $ahist0 -> $ahist1)"
    Assert-True ($audit1 -ge $audit0 + 4) "[T33f] 기한 안의 감사 로그는 줄지 않음($audit0 -> $audit1)"
    # [T58b] 초기화 줄마다 끝에 감사 칸이 있다. 삭제 함수는 UTC 날짜마다 한 번만 OK로 끝나고(audit[OK] purged=N cutoff=<UTC>) 그 뒤는 audit[SKIP]이다.
    #        설정 전·설정 도중의 줄은 audit[NOT_CONFIGURED]이고 그것만으로는 줄이 ERROR가 되지 않는다(ERROR 줄 0은 위에서 봤다).
    $cellLines = @($logs33 | Where-Object { $_ -match ' pipeline\[' })
    $noAuditCell = @($cellLines | Where-Object { $_ -notmatch '; audit\[(OK|SKIP|NOT_CONFIGURED)\]' })
    $auditOk = @($cellLines | Where-Object { $_ -match '; audit\[OK\] purged=\d+ cutoff=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' })
    $auditOrderBad = [System.Collections.Generic.List[string]]::new()
    foreach ($day in @($cellLines | ForEach-Object { $_.Substring(0, 10) } | Select-Object -Unique)) {
        $seenOk = $false
        foreach ($l in @($cellLines | Where-Object { $_.StartsWith($day) })) {
            if ($seenOk -and $l -notmatch '; audit\[SKIP\]$') { $auditOrderBad.Add($l) }
            if ($l -match '; audit\[OK\] ') { $seenOk = $true }
        }
    }
    $e2eLogs.Add("[T58b] reset log lines with cells=$($cellLines.Count): without an audit cell=$($noAuditCell.Count), audit[OK]=$($auditOk.Count), audit[SKIP]=$(@($cellLines | Where-Object { $_ -match '; audit\[SKIP\]$' }).Count), audit[NOT_CONFIGURED]=$(@($cellLines | Where-Object { $_ -match '; audit\[NOT_CONFIGURED\]' }).Count); lines after the day's audit[OK] that are not SKIP=$($auditOrderBad.Count)`n       first audit[OK]: $($auditOk | Select-Object -First 1)`n       last line: $($cellLines | Select-Object -Last 1)")
    Assert-True ($cellLines.Count -ge 2 -and $noAuditCell.Count -eq 0) "[T58b] 초기화 로그 줄마다 audit[ 칸이 있음(없는 줄 $($noAuditCell.Count))"
    Assert-True ($auditOk.Count -ge 1) "[T58b] audit[OK] purged=N cutoff=<UTC> 줄이 한 번 이상"
    Assert-True ($auditOrderBad.Count -eq 0 -and @($cellLines | Where-Object { $_ -match '; audit\[SKIP\]$' }).Count -ge 1) "[T58b] 그날 OK 뒤의 주기는 audit[SKIP](하루에 한 번만 부름)`n$($auditOrderBad -join "`n")"
    # [T56c] 초기화 뒤: 체험 계정의 대응 조치 기록(기준선 뒤의 행)은 사라지고 감사 로그의 기록은 남는다.
    #        줄마다 assignments 칸과 audit 칸 사이에 responses[ 칸이 있고, 기록을 지운 주기의 줄은 responses[OK] removed=1이다.
    $ra2 = (Invoke-Psql "zeekad_dashboard" $raCountSql).Output.Trim()
    $raAudit2 = [long](Invoke-Psql "zeekad_dashboard" $raAuditSql).Output.Trim()
    $noRespCell = @($cellLines | Where-Object { $_ -notmatch '; assignments\[[A-Z_]+\].*; responses\[(OK|NOT_CONFIGURED)\].*; audit\[' })
    $respRemoved = @($cellLines | Where-Object { $_ -match '; responses\[OK\] removed=1; audit\[' })
    $e2eLogs.Add("[T56c] after reset: incident_response_actions (all|trial) $ra1 -> $ra2 (before writes $ra0); INCIDENT_RESPONSE_ACTION audit rows $raAudit1 -> $raAudit2`n       reset log lines without a responses cell=$($noRespCell.Count); lines with responses[OK] removed=1: $($respRemoved.Count)`n       $($respRemoved | Select-Object -First 1)")
    Assert-True ($ra2 -eq $ra0) "[T56c] 초기화 뒤 대응 조치 표 = 쓰기 전(체험 계정의 기록 0) ($ra1 -> $ra2)"
    Assert-True ($raAudit2 -eq $raAudit1) "[T56c] 감사 로그의 대응 조치 기록은 남는다 ($raAudit1 -> $raAudit2)"
    Assert-True ($noRespCell.Count -eq 0) "[T56c] 초기화 로그 줄마다 responses[ 칸이 assignments 칸과 audit 칸 사이에 있음(없는 줄 $($noRespCell.Count))`n$($noRespCell -join "`n")"
    Assert-True ($respRemoved.Count -eq 1) "[T56c] responses[OK] removed=1 줄이 한 번($($respRemoved.Count))"
    if ($other0 -ne $other2) { $e2eLogs.Add("[T33f] other zeekad tables changed: $(& $otherChanged $other0 $other2)") }
    Assert-True ($other0 -eq $other2) "[T33f] 검토 결정 뒤 2분 넘게 세 표 밖 zeekad 표 그대로(후속 쓰기 없음)"

    # 이후 단계는 주기 실행과 겹치지 않게 상주 서비스를 멈추고 한 번 실행(run --rm sandbox-reset --once)으로 확인한다.
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("stop", "sandbox-reset")) -IgnoreExitCode)

    # [T33g] 옛 기준선(표지 어긋남)이면 아무것도 바꾸지 않고 오류
    [void](Invoke-Psql "zeekad" "UPDATE sandbox_baseline.marker SET fingerprint = fingerprint || '-t33-tampered'")
    $tg = New-Client "198.51.100.201"
    Assert-Status (Login-Api $tg $trialUser $env:TRIAL_ANALYST_PASSWORD) 200 "[T33g] $trialUser 로그인"
    $g1 = Invoke-Http -Path "/api/incidents/$($inc[2].Job)/rank/$($inc[2].Rank)/transition" -Method POST -Client $tg -Csrf -JsonBody @{ toStatus = "investigating"; reason = "T33 리허설: 옛 기준선" }
    Assert-Status $g1 200 "[T33g] $trialUser 상태 변경"
    $gBefore = & $baselineDiff
    $gRun = & $runResetOnce
    $gAfter = & $baselineDiff
    [void](Invoke-Psql "zeekad" "UPDATE sandbox_baseline.marker SET fingerprint = replace(fingerprint, '-t33-tampered', '')")
    $gRun2 = & $runResetOnce
    $gFinal = & $baselineDiff
    $e2eLogs.Add("[T33g] tampered marker: reset --once exit=$($gRun.ExitCode) $(($gRun.Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-reset:' }) -join ' ')`n       three tables before=$gBefore after=$gAfter`n       restored marker: exit=$($gRun2.ExitCode) $(($gRun2.Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-reset:' }) -join ' '); now $gFinal")
    Assert-True ($gRun.ExitCode -ne 0 -and $gRun.Output -match 'ERROR pipeline\[ERROR\].*does not match the current snapshot' -and $gBefore -eq $gAfter -and -not (& $isBaseline $gAfter)) "[T33g] 옛 기준선이면 초기화 거부·아무것도 안 바뀜"
    Assert-True ($gRun2.ExitCode -eq 0 -and (& $isBaseline $gFinal)) "[T33g] 표지를 되돌리면 초기화되어 기준선과 일치"

    # [T58c] 보관 기한(compose의 90일): 100일 전 행은 다음 초기화에서 지워지고(--once는 늘 삭제 함수를 부른다) 89일 전 행과 그 밖의 행은 그대로다.
    #        지운 사실은 감사 행 하나(행위자 audit-retention, 역할 SYSTEM, 접속 주소 없음)로 남는다. 상주 서비스는 위에서 멈췄다.
    $retSql = "SELECT count(*) FILTER (WHERE occurred_at >= now() - interval '90 days') || '|' || count(*) FILTER (WHERE occurred_at < now() - interval '90 days') || '|' || count(*) FILTER (WHERE action_type = 'AUDIT_RETENTION_PURGE') FROM audit_logs"
    $ret0 = @((Invoke-Psql "zeekad_dashboard" $retSql).Output.Trim() -split '\|')
    $retIns = Invoke-Psql "zeekad_dashboard" "INSERT INTO audit_logs (occurred_at, actor_username, actor_role, action_type, client_ip) VALUES (now() - interval '100 days', 't58-rehearsal-old', 'VIEWER', 'LOGIN_SUCCESS', '198.51.100.58'), (now() - interval '89 days', 't58-rehearsal-keep', 'VIEWER', 'LOGIN_SUCCESS', '198.51.100.58')"
    $retRun = & $runResetOnce
    $ret1 = @((Invoke-Psql "zeekad_dashboard" $retSql).Output.Trim() -split '\|')
    $retRows = (Invoke-Psql "zeekad_dashboard" "SELECT COALESCE(string_agg(actor_username, ',' ORDER BY actor_username), '(none)') FROM audit_logs WHERE actor_username LIKE 't58-rehearsal-%'").Output.Trim()
    $retPurgeRow = (Invoke-Psql "zeekad_dashboard" "SELECT actor_username || ' ' || actor_role || ' ip=' || COALESCE(client_ip, '(null)') || ' ' || detail_json FROM audit_logs WHERE action_type = 'AUDIT_RETENTION_PURGE' ORDER BY id DESC LIMIT 1").Output.Trim()
    $retRun2 = & $runResetOnce
    $ret2 = @((Invoke-Psql "zeekad_dashboard" $retSql).Output.Trim() -split '\|')
    $retLine = (($retRun.Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-reset:' }) -join ' ')
    $retLine2 = (($retRun2.Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-reset:' }) -join ' ')
    $e2eLogs.Add("[T58c] audit_logs (inside 90 days|older than 90 days|purge audit rows): before=$($ret0 -join '|') after insert+reset=$($ret1 -join '|') after second reset=$($ret2 -join '|'); insert exit=$($retIns.ExitCode)`n       reset --once exit=$($retRun.ExitCode) $retLine`n       rows left: $retRows; purge audit row: $retPurgeRow`n       second reset --once exit=$($retRun2.ExitCode) $retLine2")
    Assert-True ($retIns.ExitCode -eq 0 -and $ret0.Count -eq 3 -and $ret0[1] -eq '0') "[T58c] 시험 전 90일 넘은 감사 행 0, 시험 행 둘을 넣음 ($($ret0 -join '|'))"
    Assert-True ($retRun.ExitCode -eq 0 -and $retLine -match ' sandbox-reset: OK pipeline\[OK\].*; audit\[OK\] purged=1 cutoff=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') "[T58c] 초기화 한 번에 기한 지난 행 하나를 지움 ($retLine)"
    Assert-True ($retRows -eq 't58-rehearsal-keep' -and $ret1[1] -eq '0') "[T58c] 100일 전 행만 지워지고 89일 전 행은 남음 ($retRows, 90일 넘은 행 $($ret1[1]))"
    Assert-True ([long]$ret1[0] -ge [long]$ret0[0] + 2 -and [long]$ret1[2] -eq [long]$ret0[2] + 1) "[T58c] 기한 안의 감사 로그는 줄지 않음(89일 전 행과 삭제 기록 행만 늘어남: $($ret0[0]) -> $($ret1[0]), 삭제 기록 $($ret0[2]) -> $($ret1[2]))"
    Assert-True ($retPurgeRow -match '^audit-retention SYSTEM ip=\(null\) \{"deleted" : 1, "cutoff" : "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", "retentionDays" : 90\}$') "[T58c] 삭제 기록 행: 행위자 audit-retention, 역할 SYSTEM, 접속 주소 없음, 지운 수·기준 시각·기한 ($retPurgeRow)"
    Assert-True ($retRun2.ExitCode -eq 0 -and $retLine2 -match '; audit\[OK\] purged=0 cutoff=' -and ($ret2 -join '|') -eq ($ret1 -join '|')) "[T58c] 다시 돌리면 지운 것이 없고 삭제 기록 행이 늘지 않음 ($retLine2)"

    # [T33h] 초기화 중 쓰기: 다른 연결이 세 표 중 하나를 잡고 있으면 기다렸다가 끝내고(4초 잡음), 잠금 시간(5초)을 넘기면(15초 잡음) 아무것도 바꾸지 않고 오류
    $pgC = Get-ServiceContainer "postgres"
    $holdJob = { param($cid, $secs) & docker exec $cid psql -U postgres -d zeekad -v ON_ERROR_STOP=1 -c "BEGIN; LOCK TABLE zeekad.analyst_review IN ROW EXCLUSIVE MODE; SELECT pg_sleep($secs); COMMIT;" 2>&1 | Out-String }
    $waitHeld = {
        for ($k = 0; $k -lt 60; $k++) {
            $n = (Invoke-Psql "zeekad" "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation WHERE c.relname = 'analyst_review' AND l.mode = 'RowExclusiveLock' AND l.granted AND l.pid <> pg_backend_pid()").Output.Trim()
            if ($n -ne '0') { return $true }
            Start-Sleep -Milliseconds 250
        }
        return $false
    }
    $h1 = Invoke-Http -Path "/api/incidents/$($inc[3].Job)/rank/$($inc[3].Rank)/transition" -Method POST -Client $tg -Csrf -JsonBody @{ toStatus = "investigating"; reason = "T33 리허설: 잠금 대기" }
    Assert-Status $h1 200 "[T33h] $trialUser 상태 변경(대기 시험)"
    $job1 = Start-Job -ScriptBlock $holdJob -ArgumentList $pgC, 4
    Assert-True (& $waitHeld) "[T33h] 다른 연결이 analyst_review 잠금을 잡음(4초)"
    $sw = [Diagnostics.Stopwatch]::StartNew(); $hRun1 = & $runResetOnce; $sw.Stop()
    $waitMs = $sw.ElapsedMilliseconds
    [void](Wait-Job $job1 -Timeout 30); Remove-Job $job1 -Force
    $hAfter1 = & $baselineDiff
    $h2 = Invoke-Http -Path "/api/incidents/$($inc[4].Job)/rank/$($inc[4].Rank)/transition" -Method POST -Client $tg -Csrf -JsonBody @{ toStatus = "investigating"; reason = "T33 리허설: 잠금 시간 초과" }
    Assert-Status $h2 200 "[T33h] $trialUser 상태 변경(시간 초과 시험)"
    $hBefore2 = & $baselineDiff
    $job2 = Start-Job -ScriptBlock $holdJob -ArgumentList $pgC, 15
    Assert-True (& $waitHeld) "[T33h] 다른 연결이 analyst_review 잠금을 잡음(15초)"
    $hRun2 = & $runResetOnce
    $hAfter2 = & $baselineDiff
    [void](Wait-Job $job2 -Timeout 30); Remove-Job $job2 -Force
    $hRun3 = & $runResetOnce
    $hFinal = & $baselineDiff
    $e2eLogs.Add("[T33h] other session held zeekad.analyst_review (ROW EXCLUSIVE) 4 s: reset --once waited $waitMs ms (incl. container start) exit=$($hRun1.ExitCode) $(($hRun1.Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-reset:' }) -join ' '); after: $hAfter1`n       held 15 s: exit=$($hRun2.ExitCode) $(($hRun2.Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-reset:' }) -join ' ')`n       three tables before=$hBefore2 after=$hAfter2`n       next run exit=$($hRun3.ExitCode); now $hFinal")
    Assert-True ($hRun1.ExitCode -eq 0 -and $waitMs -ge 2000 -and (& $isBaseline $hAfter1)) "[T33h] 잠금이 풀리길 기다렸다가 초기화 완료($waitMs ms)"
    Assert-True ($hRun2.ExitCode -ne 0 -and $hRun2.Output -match 'lock timeout' -and $hBefore2 -eq $hAfter2 -and -not (& $isBaseline $hAfter2)) "[T33h] 잠금 시간 초과면 오류·아무것도 안 바뀜"
    Assert-True ($hRun3.ExitCode -eq 0 -and (& $isBaseline $hFinal)) "[T33h] 다음 초기화에서 기준선과 일치"

    # [T33i] 기준선 다시 만들기: 체험 계정 흔적이 있으면 멈춤, 없으면(초기화 뒤·서비스 정지) 다시 만든다
    $i1 = Invoke-Http -Path "/api/incidents/$($inc[5].Job)/rank/$($inc[5].Rank)/transition" -Method POST -Client $tg -Csrf -JsonBody @{ toStatus = "investigating"; reason = "T33 리허설: 기준선 다시 만들기 거부" }
    Assert-Status $i1 200 "[T33i] $trialUser 상태 변경"
    $markerBefore = (Invoke-Psql "zeekad" "SELECT created_at FROM sandbox_baseline.marker").Output.Trim()
    $rb1 = & $runSetup @("--rebuild-baseline")
    $markerMid = (Invoke-Psql "zeekad" "SELECT created_at FROM sandbox_baseline.marker").Output.Trim()
    $iReset = & $runResetOnce
    $rb2 = & $runSetup @("--rebuild-baseline")
    $markerAfter = (Invoke-Psql "zeekad" "SELECT created_at FROM sandbox_baseline.marker").Output.Trim()
    $iFinal = & $baselineDiff
    Save-Evidence "t33-rebuild.txt" "rebuild with traces exit=$($rb1.ExitCode)`n$($rb1.Output)`n--- reset ---`n$($iReset.Output)`n--- rebuild after reset exit=$($rb2.ExitCode) ---`n$($rb2.Output)"
    $e2eLogs.Add("[T33i] rebuild with trial traces: exit=$($rb1.ExitCode) $((@($rb1.Output -split "`r?`n" | Where-Object { $_ -match 'traces|REFUSED' })) -join ' / '); marker created_at kept=$($markerBefore -eq $markerMid)`n       after reset: rebuild exit=$($rb2.ExitCode) $((@($rb2.Output -split "`r?`n" | Where-Object { $_ -match 'baseline rebuilt|RESULT' })) -join ' / '); marker changed=$($markerBefore -ne $markerAfter); now $iFinal")
    Assert-True ($rb1.ExitCode -ne 0 -and $rb1.Output -match 'REFUSED' -and $markerBefore -eq $markerMid) "[T33i] 체험 계정 흔적이 있으면 기준선 다시 만들기 거부"
    Assert-True ($iReset.ExitCode -eq 0 -and $rb2.ExitCode -eq 0 -and $rb2.Output -match 'baseline rebuilt' -and $markerBefore -ne $markerAfter -and (& $isBaseline $iFinal)) "[T33i] 흔적이 없으면 기준선 다시 만들기"

    # [T54c] 체험 계정이 예시를 건드려도 초기화가 기준선(예시 포함)으로 되돌린다: trial-analyst가 다른 신규 건 하나를 분석 중으로 바꾸고
    #        예시 A(종결)에 대응 조치 하나를 덧붙인 뒤 reset --once → 그 건은 신규로, 덧붙인 조치는 지워지고, 예시 셋(상태·판정·이력, demo-analyst의 조치)은 그대로.
    #        초기화 서비스는 [T33g]부터 멈춰 있고 기준선은 [T33i]가 예시를 포함한 채 다시 만들었다.
    $exA54 = @($examples54 | Where-Object { $_.key -eq 'A' })[0]
    $posA54 = @((Invoke-Psql "zeekad" "SELECT job_id || '/' || queue_rank FROM dashboard.latest_incident_queue WHERE incident_id = '$($exA54.incidentId)'").Output.Trim() -split '/')
    $exSnap54 = {
        $z = (Invoke-Psql "zeekad" ("SELECT count(*) || ':' || md5(string_agg(t::text, ',' ORDER BY t::text)) FROM (" +
            "SELECT incident_id, status AS s, resolution AS r, updated_by AS a, updated_at AS at FROM zeekad.incident_status WHERE incident_id IN ($ids54Sql) " +
            "UNION ALL SELECT incident_id, to_status, resolution, actor || ':' || COALESCE(reason, ''), changed_at FROM zeekad.incident_status_history WHERE incident_id IN ($ids54Sql)) t")).Output.Trim()
        $d = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) || '/' || count(*) FILTER (WHERE actor_username = 'demo-analyst') FROM incident_response_actions WHERE incident_id IN ($ids54Sql)").Output.Trim()
        "zeekad rows=$z actions(all/demo-analyst)=$d"
    }
    $s54Before = & $exSnap54
    $t54c = New-Client "198.51.100.240"
    Assert-Status (Login-Api $t54c $trialUser $env:TRIAL_ANALYST_PASSWORD) 200 "[T54c] $trialUser 로그인"
    $c54a = Invoke-Http -Path "/api/incidents/$($inc[2].Job)/rank/$($inc[2].Rank)/transition" -Method POST -Client $t54c -Csrf -JsonBody @{ toStatus = "investigating"; reason = "T54 리허설: 다른 신규 건 착수" }
    $c54b = Invoke-Http -Path "/api/incidents/$($posA54[0])/rank/$($posA54[1])/response-actions" -Method POST -Client $t54c -Csrf -JsonBody @{ action = "monitor"; note = "T54 리허설: 예시에 덧붙인 조치" }
    Assert-Status $c54a 200 "[T54c] $trialUser 다른 신규 건 분석 중으로"
    Assert-Status $c54b 200 "[T54c] $trialUser 예시 A에 대응 조치 덧붙임"
    $s54Mid = & $exSnap54
    $c54Reset = & $runResetOnce
    $s54After = & $exSnap54
    $c54Other = (Invoke-Psql "zeekad" "SELECT count(*) FROM zeekad.incident_status WHERE incident_id = '$($inc[2].Id)'").Output.Trim()
    $e2eLogs.Add("[T54c] examples before=$s54Before; after trial writes=$s54Mid; reset --once exit=$($c54Reset.ExitCode) $(($c54Reset.Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-reset:' }) -join ' '); after reset=$s54After; other incident status rows=$c54Other")
    Assert-True ($s54Mid -ne $s54Before -and $s54Mid -match 'actions\(all/demo-analyst\)=3/2$') "[T54c] 덧붙인 조치가 예시 A에 보임 ($s54Mid)"
    Assert-True ($c54Reset.ExitCode -eq 0 -and $c54Other -eq '0' -and $s54After -eq $s54Before -and $s54After -match 'actions\(all/demo-analyst\)=2/2$') "[T54c] 초기화 뒤 다른 건은 신규, 덧붙인 조치는 지워지고 예시 셋은 그대로 ($s54After)"

    # [T54d] 조회자(demo)가 보는 예시 A: 종결·정탐, 상태 변경 사유의 주소는 가려지고(가려진 꼴을 그대로 적는다), 대응 조치 메모는 응답에 없다.
    #        큐의 종결 필터(status=closed&period=all)에 예시 셋이 나온다. WAF를 거친 응답이다(출력 규칙에 걸리면 200이 아니다).
    $v54 = New-Client "198.51.100.241"
    Assert-Status (Login-Api $v54 "demo" $env:DEMO_PASSWORD) 200 "[T54d] demo 로그인"
    $dA54 = Invoke-Http -Path "/api/incidents/$($posA54[0])/rank/$($posA54[1])" -Client $v54
    Assert-Status $dA54 200 "[T54d] demo 예시 A 상세"
    $ip54 = [System.Collections.Generic.List[string]]::new()
    Find-UnmaskedIpv4 $dA54.Json "detail[A]" $ip54
    $hist54 = @($dA54.Json.detail.statusHistory)
    $closeH54 = @($hist54 | Where-Object { $_.toStatus -eq 'closed' })
    $notes54 = @($dA54.Json.responseActions | Where-Object { $null -ne $_.note })
    $closedQ54 = Get-AllQueueItems $v54 "status=closed&period=all" 100
    $pos54 = @($examples54 | ForEach-Object { (Invoke-Psql "zeekad" "SELECT job_id || '/' || queue_rank FROM dashboard.latest_incident_queue WHERE incident_id = '$($_.incidentId)'").Output.Trim() })
    $closedPos54 = @($closedQ54.Items | ForEach-Object { "$($_.jobId)/$($_.queueRank)" })
    $missing54 = @($pos54 | Where-Object { $closedPos54 -notcontains $_ })
    $e2eLogs.Add("[T54d] demo example A detail: maskedView=$($dA54.Json.maskedView) currentStatus=$($dA54.Json.detail.currentStatus) resolution=$($dA54.Json.detail.currentResolution) incidentNo=$($dA54.Json.incidentNo); unmasked IPv4 JSON paths=$($ip54.Count)$(if ($ip54.Count) { ' ' + (($ip54 | Select-Object -First 10) -join ', ') })`n       close reason as the viewer sees it: $(@($closeH54 | ForEach-Object { $_.reason }) -join ' / ')`n       response actions (action|note is null): $(@($dA54.Json.responseActions | ForEach-Object { "$($_.action)|$($null -eq $_.note)" }) -join ', ')`n       closed filter (period=all) total=$($closedQ54.First.Json.total) example positions=[$($pos54 -join ', ')] missing=[$($missing54 -join ', ')]")
    Assert-True ($dA54.Json.maskedView -eq $true -and $dA54.Json.detail.currentStatus -eq 'closed' -and $dA54.Json.detail.currentResolution -eq 'true_positive' -and $closeH54.Count -eq 1) "[T54d] demo 예시 A: 종결·정탐, 종결 이력 하나"
    Assert-True ($ip54.Count -eq 0 -and $closeH54[0].reason -match '10\.10\.\*\.\*') "[T54d] demo 예시 A 응답에 가려지지 않은 IPv4 없음, 종결 사유의 주소는 가려짐 ($($ip54 -join ', '))"
    Assert-True (@($dA54.Json.responseActions).Count -ge 1 -and $notes54.Count -eq 0) "[T54d] demo에게 대응 조치 메모가 내려가지 않음 (기록 $(@($dA54.Json.responseActions).Count), 메모 $($notes54.Count))"
    Assert-True ($pos54.Count -eq 3 -and $missing54.Count -eq 0) "[T54d] 큐 종결 필터(전체 기간)에 예시 셋 (빠진 것 $($missing54 -join ', '))"

    # ───────── [T53a]~[T53d] 다시 열기(종결 건 재개, zeek_AD migration 018의 dashboard.reopen_incident) ─────────
    # 이 시점은 [T33i]·[T54c] 뒤라 세 표 = 기준선(T54 예시 셋 포함)이고 상주 sandbox-reset은 멈춰 있다. 끝에 한 번 초기화해 기준선으로 되돌린다.
    # 대상은 체험 계정이 볼 수 있는 첫 종결 건이다(T54 예시일 수 있다. 초기화가 예시도 기준선으로 되돌린다).
    # [T53a] 권한 목록: dashboard_rw에 EXECUTE가 명시된 함수는 정확히 셋(transition_incident·decide_review·reopen_incident).
    #        reopen_incident는 하나이고 소유 zeekad_owner, SECURITY DEFINER, PUBLIC·초기화 계정은 실행할 수 없다.
    $rwFns53 = (Invoke-Psql "zeekad" ("SELECT count(*) || '|' || string_agg(n.nspname || '.' || p.proname, ',' ORDER BY n.nspname || '.' || p.proname) " +
        "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace CROSS JOIN LATERAL aclexplode(p.proacl) a " +
        "WHERE a.grantee = 'dashboard_rw'::regrole AND a.privilege_type = 'EXECUTE'")).Output.Trim()
    $reopenFn53 = (Invoke-Psql "zeekad" ("SELECT count(*) OVER () || ' owner=' || pg_get_userbyid(p.proowner) || ' secdef=' || p.prosecdef || " +
        "' public_exec=' || COALESCE((SELECT bool_or(a.grantee = 0) FROM aclexplode(p.proacl) a WHERE a.privilege_type = 'EXECUTE'), false) || " +
        "' reset_exec=' || has_function_privilege('zeekad_sandbox_reset', p.oid, 'EXECUTE') || ' rw_exec=' || has_function_privilege('dashboard_rw', p.oid, 'EXECUTE') " +
        "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'dashboard' AND p.proname = 'reopen_incident'")).Output.Trim()
    $e2eLogs.Add("[T53a] functions with an explicit EXECUTE grant to dashboard_rw (count|names): $rwFns53`n       dashboard.reopen_incident: $reopenFn53")
    Assert-True ($rwFns53 -eq '3|dashboard.decide_review,dashboard.reopen_incident,dashboard.transition_incident') "[T53a] dashboard_rw가 실행할 수 있는 함수는 정확히 셋 ($rwFns53)"
    Assert-True ($reopenFn53 -eq '1 owner=zeekad_owner secdef=true public_exec=false reset_exec=false rw_exec=true') "[T53a] reopen_incident: 하나, 소유 zeekad_owner, SECURITY DEFINER, PUBLIC·초기화 계정 실행 불가 ($reopenFn53)"

    # [T53b] 체험 분석가가 종결 건을 다시 연다. 체험 계정이 볼 수 있는(공개 캡처) 종결 건이 있으면 그것을 쓰고, 없으면 신규 건 하나를
    #        먼저 종결해 쓴다(어느 쪽인지 로그에 적는다). 틀린 판정은 409(아무것도 안 바뀜, 응답에 DB 문구 없음), 맞는 판정은 200
    #        (분석 중·판정 없음·이력 한 행: closed → investigating, 행위자, 사유). [T53c] 조회자(demo)는 상세의 canReopen이 false이고 요청은 403.
    $like53 = ($demoPatterns | ForEach-Object { "'" + ($_ -replace '\*', '%') + "'" }) -join ', '
    $closed53 = (Invoke-Psql "zeekad" ("SELECT lq.job_id || '|' || lq.queue_rank || '|' || s.resolution || '|' || lq.incident_id " +
        "FROM dashboard.latest_incident_queue lq JOIN zeekad.incident_status s ON s.incident_id = lq.incident_id " +
        "WHERE s.status = 'closed' AND lq.capture_id LIKE ANY (ARRAY[$like53]) ORDER BY lq.job_id, lq.queue_rank LIMIT 1")).Output.Trim()
    $t53 = New-Client "198.51.100.243"
    Assert-Status (Login-Api $t53 $trialUser $env:TRIAL_ANALYST_PASSWORD) 200 "[T53b] $trialUser 로그인"
    if ($closed53) {
        $p53 = $closed53 -split '\|', 4
        $r53 = [pscustomobject]@{ Job = $p53[0]; Rank = $p53[1]; Resolution = $p53[2]; Id = $p53[3]; Source = "closed incident already in the baseline" }
    } else {
        $r53 = [pscustomobject]@{ Job = $inc[5].Job; Rank = $inc[5].Rank; Resolution = "benign"; Id = $inc[5].Id; Source = "no visible closed incident; $trialUser closed an open one first" }
    }
    $id53 = $r53.Id -replace "'", "''"
    $state53Sql = "SELECT COALESCE((SELECT s.status || '|' || COALESCE(s.resolution, 'null') FROM zeekad.incident_status s WHERE s.incident_id = '$id53'), 'open|null') || '|' || (SELECT count(*) FROM zeekad.incident_status_history h WHERE h.incident_id = '$id53')"
    $base53 = (Invoke-Psql "zeekad" $state53Sql).Output.Trim()
    if (-not $closed53) {
        $c53a = Invoke-Http -Path "/api/incidents/$($r53.Job)/rank/$($r53.Rank)/transition" -Method POST -Client $t53 -Csrf -JsonBody @{ toStatus = "investigating"; reason = "T53 리허설: 조사 시작" }
        $c53b = Invoke-Http -Path "/api/incidents/$($r53.Job)/rank/$($r53.Rank)/transition" -Method POST -Client $t53 -Csrf -JsonBody @{ toStatus = "closed"; resolution = "benign"; reason = "T53 리허설: 정상으로 종결" }
        Assert-Status $c53a 200 "[T53b] $trialUser 신규 → 분석 중"
        Assert-Status $c53b 200 "[T53b] $trialUser 분석 중 → 종결(정상)"
    }
    $before53 = (Invoke-Psql "zeekad" $state53Sql).Output.Trim()
    $detailPath53 = "/api/incidents/$($r53.Job)/rank/$($r53.Rank)"
    $tDetail53 = Invoke-Http -Path $detailPath53 -Client $t53
    $v53 = New-Client "198.51.100.244"
    Assert-Status (Login-Api $v53 "demo" $env:DEMO_PASSWORD) 200 "[T53c] demo 로그인"
    $vDetail53 = Invoke-Http -Path $detailPath53 -Client $v53
    $wrong53 = if ($r53.Resolution -eq "true_positive") { "false_positive" } else { "true_positive" }
    $x53a = Invoke-Http -Path "$detailPath53/reopen" -Method POST -Client $t53 -Csrf -JsonBody @{ reason = "T53 리허설: 틀린 판정"; expectedResolution = $wrong53 }
    $mid53 = (Invoke-Psql "zeekad" $state53Sql).Output.Trim()
    $x53v = Invoke-Http -Path "$detailPath53/reopen" -Method POST -Client $v53 -Csrf -JsonBody @{ reason = "T53 리허설: 조회자"; expectedResolution = $r53.Resolution }
    $midV53 = (Invoke-Psql "zeekad" $state53Sql).Output.Trim()
    $x53b = Invoke-Http -Path "$detailPath53/reopen" -Method POST -Client $t53 -Csrf -JsonBody @{ reason = "T53 리허설: 다시 열기"; expectedResolution = $r53.Resolution }
    $after53 = (Invoke-Psql "zeekad" $state53Sql).Output.Trim()
    $last53 = (Invoke-Psql "zeekad" "SELECT h.from_status || '>' || h.to_status || '|' || COALESCE(h.resolution, 'null') || '|' || h.actor || '|' || h.reason FROM zeekad.incident_status_history h WHERE h.incident_id = '$id53' ORDER BY h.changed_at DESC, h.history_id DESC LIMIT 1").Output.Trim()
    $histN53 = [int](($before53 -split '\|')[2])
    $e2eLogs.Add("[T53b] target: job $($r53.Job) rank $($r53.Rank) ($($r53.Source)); state (status|resolution|history rows) baseline=$base53 before=$before53 after wrong expected=$mid53 after viewer=$midV53 after reopen=$after53`n       detail canReopen: $trialUser=$($tDetail53.Json.canReopen) demo=$($vDetail53.Json.canReopen)`n       wrong expectedResolution ($wrong53): $(Format-Resp $x53a 200)`n       demo: $(Format-Resp $x53v 200)`n       reopen: $(Format-Resp $x53b 200)`n       last history row: $last53")
    Assert-True ($before53 -match '^closed\|(true_positive|false_positive|benign)\|\d+$' -and ($before53 -split '\|')[1] -eq $r53.Resolution) "[T53b] 대상은 종결 건 ($before53)"
    Assert-True ($tDetail53.Json.canReopen -eq $true -and $vDetail53.Json.canReopen -eq $false) "[T53b] 상세의 canReopen: $trialUser true, demo false"
    Assert-ApiError $x53a 409 "CONFLICT" "[T53b] 화면의 판정이 지금과 다르면 409"
    Assert-True ($x53a.Json.message -eq "다른 사람이 먼저 상태나 판정을 바꿨습니다. 새로고침한 뒤 다시 확인하세요." -and $x53a.Body -notmatch '지금 결론|true_positive|false_positive|benign') "[T53b] 409 응답은 고정 문장이고 DB 문구·판정 코드가 없다" $x53a
    Assert-True ($mid53 -eq $before53) "[T53b] 틀린 판정의 요청은 아무것도 바꾸지 않음 ($before53 -> $mid53)"
    Assert-Status $x53v 403 "[T53c] 조회자(demo)의 다시 열기는 403"
    Assert-True ($midV53 -eq $before53) "[T53c] 조회자의 요청은 아무것도 바꾸지 않음 ($midV53)"
    Assert-Status $x53b 200 "[T53b] $trialUser 다시 열기"
    Assert-True ($x53b.Json.message -like "인시던트를 다시 열었습니다. 상태는 분석 중입니다.*") "[T53b] 다시 열기 응답 문장" $x53b
    Assert-True ($after53 -eq "investigating|null|$($histN53 + 1)") "[T53b] 다시 연 뒤 분석 중·판정 없음·이력 한 행 더 ($before53 -> $after53)"
    Assert-True ($last53 -eq "closed>investigating|null|${trialUser}|T53 리허설: 다시 열기") "[T53b] 이력 행: closed → investigating, 판정 없음, 행위자·사유 ($last53)"

    # [T53d] 초기화(한 번 실행) 뒤 그 건이 기준선의 상태·판정·이력 행 수로 돌아오고 세 표 = 기준선이다.
    $rst53 = & $runResetOnce
    $final53 = (Invoke-Psql "zeekad" $state53Sql).Output.Trim()
    $diff53 = & $baselineDiff
    $e2eLogs.Add("[T53d] reset --once exit=$($rst53.ExitCode) $(($rst53.Output -split "`r?`n" | Where-Object { $_ -match 'sandbox-reset:' }) -join ' ')`n       target state after reset=$final53 (baseline $base53); three tables: $diff53")
    Assert-True ($rst53.ExitCode -eq 0 -and $final53 -eq $base53) "[T53d] 초기화 뒤 그 건이 기준선 상태로 ($after53 -> $final53, 기준선 $base53)"
    Assert-True (& $isBaseline $diff53) "[T53d] 초기화 뒤 세 표 = 기준선 ($diff53)"

    # [T33j] trial-analyst 잠금 없음(요청마다 다른 클라이언트 IP, 로그인 속도 제한 회피)
    $auditBase33 = [long](Invoke-Psql "zeekad_dashboard" "SELECT COALESCE(MAX(id),0) FROM audit_logs").Output.Trim()
    $codes33 = @()
    for ($k = 1; $k -le 6; $k++) { $codes33 += (Login-Api (New-Client "198.51.100.$(210 + $k)") $trialUser "wrong-password-t33-$k").Status }
    $ok33 = Login-Api (New-Client "198.51.100.220") $trialUser $env:TRIAL_ANALYST_PASSWORD
    $state33 = (Invoke-Psql "zeekad_dashboard" "SELECT failed_attempts, locked_until IS NULL FROM users WHERE username = '$trialUser'").Output.Trim()
    $aud33 = (Invoke-Psql "zeekad_dashboard" "SELECT action_type, count(*), count(*) FILTER (WHERE (detail_json::jsonb ->> 'lockoutExempt') = 'true') FROM audit_logs WHERE id > $auditBase33 AND actor_username = '$trialUser' GROUP BY action_type ORDER BY action_type").Output.Trim()
    $e2eLogs.Add("[T33j] $trialUser wrong x6 -> [$($codes33 -join ', ')]; correct -> HTTP $($ok33.Status); failed_attempts|unlocked=$state33; audit: $($aud33 -replace "`r?`n", '; ')")
    Assert-True (($codes33 -join ',') -eq '401,401,401,401,401,401' -and $ok33.Status -eq 200 -and $state33 -eq '0|t') "[T33j] $trialUser 6번 틀려도 잠기지 않음"
    Assert-True ($aud33 -match '(?m)^LOGIN_FAILURE\|6\|6\s*$' -and $aud33 -notmatch 'ACCOUNT_LOCKED') "[T33j] 실패 감사 6건(lockoutExempt), 잠금 감사 없음"

    # [T33k] 쓰기 속도 제한: 여섯 경로(T56: 대응 조치 기록, T53: 다시 열기가 더해졌다) 각각 새 클라이언트 IP에서 12번(DB를 바꾸지 않는 입력) → 429. GET은 제한 밖.
    #        다시 열기 탐침은 화면의 판정(expectedResolution)이 세 값 밖이라 서비스가 400으로 끝낸다(DB 함수를 부르지 않는다).
    $rl = New-Client "198.51.100.230"
    Assert-Status (Login-Api $rl $trialUser $env:TRIAL_ANALYST_PASSWORD) 200 "[T33k] $trialUser 로그인"
    $rlPaths = @(
        @{ Label = "transition"; Ip = "198.51.100.231"; Path = "/api/incidents/$($inc[0].Job)/rank/$($inc[0].Rank)/transition"; Body = @{ toStatus = "rate-limit-probe"; reason = "x" } },
        @{ Label = "assignment"; Ip = "198.51.100.232"; Path = "/api/incidents/$($inc[0].Job)/rank/$($inc[0].Rank)/assignment"; Body = @{ assignee = $trialUser; expected = "rate-limit-probe-nobody" } },
        @{ Label = "review-decision"; Ip = "198.51.100.233"; Path = "/api/incidents/$($inc[0].Job)/rank/$($inc[0].Rank)/review-decision"; Body = @{ action = "rate-limit-probe" } },
        @{ Label = "reviews/decide"; Ip = "198.51.100.234"; Path = "/api/reviews/decide"; Body = @{ jobId = $rev[1].Job; incidentId = $rev[1].Id; action = "rate-limit-probe" } },
        @{ Label = "response-actions"; Ip = "198.51.100.235"; Path = "/api/incidents/$($inc[0].Job)/rank/$($inc[0].Rank)/response-actions"; Body = @{ action = "rate-limit-probe"; note = "x" } },
        @{ Label = "reopen"; Ip = "198.51.100.236"; Path = "/api/incidents/$($inc[0].Job)/rank/$($inc[0].Rank)/reopen"; Body = @{ reason = "x"; expectedResolution = "rate-limit-probe" } }
    )
    $raBeforeProbes = (Invoke-Psql "zeekad_dashboard" $raCountSql).Output.Trim()
    $rlBefore = & $baselineDiff
    foreach ($p in $rlPaths) {
        $st = @()
        for ($k = 1; $k -le 12; $k++) { $st += (Invoke-Http -Path $p.Path -Method POST -Client $rl -Xff $p.Ip -Csrf -JsonBody $p.Body).Status }
        $f429 = [Array]::IndexOf($st, 429) + 1
        $e2eLogs.Add("[T33k] 12 x POST $($p.Label) from $($p.Ip) -> [$($st -join ', ')] (first 429 at #$f429)")
        Assert-True ($f429 -ge 2 -and $f429 -le 8 -and @($st | Where-Object { $_ -notin @(400, 404, 409, 429) }).Count -eq 0) "[T33k] 쓰기 경로 $($p.Label) 한도 초과 시 429"
    }
    $gets = @(); for ($k = 1; $k -le 12; $k++) { $gets += (Invoke-Http -Path "/api/incidents/$($inc[0].Job)/rank/$($inc[0].Rank)" -Client $rl -Xff "198.51.100.231").Status }
    $e2eLogs.Add("[T33k] (대조) 같은 IP 198.51.100.231 GET 상세 12번 -> [$($gets -join ', ')]; three tables unchanged by probes=$($rlBefore -eq (& $baselineDiff))")
    Assert-True (@($gets | Where-Object { $_ -ne 200 }).Count -eq 0) "[T33k] GET은 쓰기 제한 밖"
    $raAfterProbes = (Invoke-Psql "zeekad_dashboard" $raCountSql).Output.Trim()
    Assert-True ($raBeforeProbes -eq $raAfterProbes) "[T33k] 속도 제한 시험 요청은 대응 조치 행을 만들지 않음 ($raBeforeProbes -> $raAfterProbes)"

    # [T33l] 로그인 안내 문구: 두 계정과 정각 초기화 안내, 비밀번호 없음
    $notice33 = (Invoke-Http -Path "/api/auth/login-notice").Json.notice
    $e2eLogs.Add("[T33l] login notice: $notice33")
    Assert-True ($notice33 -match 'demo' -and $notice33 -match [regex]::Escape($trialUser) -and $notice33 -match '매시 정각에 되돌립니다' -and -not $notice33.Contains($env:DEMO_PASSWORD) -and -not $notice33.Contains($env:TRIAL_ANALYST_PASSWORD)) "[T33l] 로그인 안내에 두 계정·정각 초기화, 비밀번호 없음"

    # [T33x] (선택) 노출 확인: 공개 실습망 캡처의 모든 인시던트에 대해 화면이 부르는 API 응답을 demo와 trial-analyst로 받아 JSON 경로 단위로 비교
    if ($ExposureFullDir) { Invoke-T33Exposure $tc }

    # 리허설 일회용 DB 정리: 뒤 단계([T25c]는 모든 인시던트 담당을 ON CONFLICT DO NOTHING으로 넣는다)가 영향받지 않게 해제된 담당 행(NULL 행)을 지운다.
    # T54: T33이 만든 해제 행(sandbox-reset)뿐 아니라 예시 셋의 해제 행(demo-analyst가 종결 전에 해제)도 지운다(남으면 [T25c]가 그 셋을 건너뛴다).
    # 담당 이력(추가만)은 그대로 둔다. 초기화 서비스는 멈춘 채 둔다(뒤 단계의 리허설 쓰기를 되돌리지 않게).
    $cleanup33 = (Invoke-Psql "zeekad_dashboard" "DELETE FROM incident_assignments WHERE assignee_user_id IS NULL").Output.Trim()
    $e2eLogs.Add("[T33] rehearsal cleanup: $cleanup33 (released rows removed from the disposable rehearsal DB; sandbox-reset stays stopped for later steps)")

    Write-Host "=== [T25] 담당·착수 지연·처리 시간(V2 적용·독립 SQL·모든 인시던트 담당 성능·T24 이미지 되돌리기) ==="
    $t25 = New-Client "198.51.100.95"
    Assert-Status (Login-Api $t25 "demo" $env:DEMO_PASSWORD) 200 "[T25] demo 로그인"
    $t25Bodies = [System.Collections.Generic.List[string]]::new()
    $t25IpHits = [System.Collections.Generic.List[string]]::new()

    # [T25a] 앱 DB에 Flyway V2(담당 표 둘)가 적용됐다
    $fwRows = (Invoke-Psql "zeekad_dashboard" "SELECT version, description, success FROM flyway_schema_history ORDER BY installed_rank").Output.Trim()
    $t25Tables = (Invoke-Psql "zeekad_dashboard" "SELECT string_agg(table_name, ',' ORDER BY table_name) FROM information_schema.tables WHERE table_name IN ('incident_assignments', 'incident_assignment_history')").Output.Trim()
    $e2eLogs.Add("[T25a] flyway_schema_history (version|description|success):`n       $($fwRows -replace "`r?`n", "`n       ")`n       tables=$t25Tables")
    Assert-True ($fwRows -match '(?m)^2\|incident assignments\|t?$' -and $t25Tables -eq 'incident_assignment_history,incident_assignments') "[T25a] 앱 DB에 V2 적용"

    # [T25b] handlingTimes(period=all·7d) = 독립 SQL(percentile_disc), workload.ackOverdue = 큐 overdue=true total = summary.overdue = 독립 SQL
    #        (고정 스냅샷이라 정확히 같아야 한다). 구현 SQL을 복사하지 않고 T25 정의대로 다시 쓴다.
    function Get-T25HandlingSql([string]$Period) {
        $range = if ($Period -eq 'all') { { param($x) "TRUE" } } else { { param($x) "($x > $anchorExpr - interval '7 days' AND $x <= $anchorExpr)" } }
        return @"
WITH lq AS (SELECT * FROM dashboard.latest_incident_queue WHERE capture_id = ANY($publicArr)),
fs AS (SELECT q.incident_id, MIN(j.finished_at) AS det FROM dashboard.incident_queue q
       JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL
       WHERE q.capture_id = ANY($publicArr) GROUP BY q.incident_id),
h AS (SELECT incident_id, MIN(changed_at) AS ack FROM dashboard.incident_status_history WHERE LOWER(TRIM(to_status)) = 'investigating' GROUP BY incident_id),
b AS (SELECT lq.incident_id, lq.capture_id LIKE 'lab-%' AS live, lq.event_start, fs.det, h.ack,
             CASE WHEN LOWER(TRIM(COALESCE(lq.zeekad_status, ''))) = 'closed' THEN lq.status_updated_at END AS closed_at,
             COALESCE(NULLIF(LOWER(TRIM(lq.zeekad_resolution)), ''), 'none') AS res
      FROM lq LEFT JOIN fs ON fs.incident_id = lq.incident_id LEFT JOIN h ON h.incident_id = lq.incident_id),
v AS (SELECT 'detection' AS m, FLOOR(EXTRACT(EPOCH FROM (det - event_start)))::bigint AS s FROM b WHERE live AND det IS NOT NULL AND $(& $range 'det')
      UNION ALL SELECT 'acknowledge', FLOOR(EXTRACT(EPOCH FROM (ack - det)))::bigint FROM b WHERE ack IS NOT NULL AND $(& $range 'ack')
      UNION ALL SELECT 'acknowledge', NULL FROM b WHERE closed_at IS NOT NULL AND ack IS NULL AND $(& $range 'closed_at')
      UNION ALL SELECT 'resolve', FLOOR(EXTRACT(EPOCH FROM (closed_at - det)))::bigint FROM b WHERE closed_at IS NOT NULL AND $(& $range 'closed_at')
      UNION ALL SELECT 'resolve:' || res, FLOOR(EXTRACT(EPOCH FROM (closed_at - det)))::bigint FROM b WHERE closed_at IS NOT NULL AND $(& $range 'closed_at'))
SELECT m, COUNT(*) FILTER (WHERE s >= 0),
       COALESCE((percentile_disc(0.5) WITHIN GROUP (ORDER BY s) FILTER (WHERE s >= 0))::text, ''),
       COALESCE((percentile_disc(0.9) WITHIN GROUP (ORDER BY s) FILTER (WHERE s >= 0))::text, ''),
       COUNT(*) FILTER (WHERE s IS NULL OR s < 0)
FROM v GROUP BY m ORDER BY m
"@
    }
    $t25Fail = [System.Collections.Generic.List[string]]::new()
    foreach ($period in @('all', '7d')) {
        $ops = Invoke-Http -Path "/api/operations?period=$period" -Client $t25
        Assert-Status $ops 200 "[T25b] demo operations period=$period"
        $t25Bodies.Add($ops.Body)
        Find-UnmaskedIpv4 $ops.Json "operations[$period]" $t25IpHits
        $sql = @{}
        foreach ($l in @((Invoke-Psql "zeekad" (Get-T25HandlingSql $period)).Output.Trim() -split "`r?`n" | Where-Object { $_ })) { $p = $l -split '\|'; $sql[$p[0]] = $p }
        $api = @{ detection = $ops.Json.handlingTimes.detection; acknowledge = $ops.Json.handlingTimes.acknowledge; resolve = $ops.Json.handlingTimes.resolve.all }
        foreach ($r in @($ops.Json.handlingTimes.resolve.byResolution)) { $api["resolve:$($r.resolution)"] = $r.stat }
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($k in @(@($api.Keys) + @($sql.Keys) | Sort-Object -Unique)) {
            $a = $api[$k]
            $aText = if ($a) { "n=$($a.n) median=$($a.medianSeconds) p90=$($a.p90Seconds) excluded=$($a.excluded)" } else { "(없음)" }
            $s = $sql[$k]
            $sText = if ($s) { "n=$($s[1]) median=$($s[2]) p90=$($s[3]) excluded=$($s[4])" } else { "n=0 median= p90= excluded=0" }
            $lines.Add("$k api[$aText] sql[$sText]")
            if ($aText -ne $sText) { $t25Fail.Add("period=$period $k") }
        }
        $e2eLogs.Add("[T25b] demo handlingTimes period=$period vs 독립 SQL (percentile_disc):`n       $($lines -join "`n       ")")
    }
    $overdueSql = @"
WITH lq AS (SELECT * FROM dashboard.latest_incident_queue WHERE capture_id = ANY($publicArr)),
fs AS (SELECT q.incident_id, MIN(j.finished_at) AS det FROM dashboard.incident_queue q
       JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL
       WHERE q.capture_id = ANY($publicArr) GROUP BY q.incident_id),
p AS (SELECT lq.capture_id, fs.det,
             (TRIM(COALESCE(lq.zeekad_status, '')) = '' OR LOWER(TRIM(lq.zeekad_status)) = 'open') AS is_open,
             CASE WHEN COALESCE(lq.zeekad_would_send, FALSE) OR COALESCE(lq.zeekad_review_pending, FALSE) THEN interval '30 minutes'
                  WHEN COALESCE(CARDINALITY(lq.zeekad_also_flagged_by), 0) >= 1 OR lq.zeekad_report_job_id IS NOT NULL THEN interval '4 hours'
                  ELSE interval '24 hours' END AS target
      FROM lq LEFT JOIN fs ON fs.incident_id = lq.incident_id)
SELECT count(*) FROM p WHERE capture_id LIKE 'lab-%' AND is_open AND det IS NOT NULL AND det + target < $anchorExpr
"@
    $sqlOverdue = [int](Invoke-Psql "zeekad" $overdueSql).Output.Trim()
    $odQ = Invoke-Http -Path "/api/incidents/queue?period=all&overdue=true&size=25" -Client $t25
    $allQ = Invoke-Http -Path "/api/incidents/queue?period=all&size=25" -Client $t25
    $w7 = (Invoke-Http -Path "/api/operations?period=7d" -Client $t25).Json.workload
    $wSum = 0; foreach ($l in @($w7.byAssignee)) { $wSum += [int]$l.open + [int]$l.investigating }
    $t25Bodies.Add($odQ.Body)
    Find-UnmaskedIpv4 $odQ.Json "queue[overdue]" $t25IpHits
    $e2eLogs.Add("[T25b] ackOverdue: independent SQL=$sqlOverdue; queue overdue=true total=$($odQ.Json.total); queue(period=all).summary.overdue=$($allQ.Json.summary.overdue); workload=$($w7 | ConvertTo-Json -Compress -Depth 4)")
    if (-not ($sqlOverdue -eq [int]$odQ.Json.total -and $sqlOverdue -eq [int]$allQ.Json.summary.overdue -and $sqlOverdue -eq [int]$w7.ackOverdue)) { $t25Fail.Add("ackOverdue sql=$sqlOverdue queue=$($odQ.Json.total) summary=$($allQ.Json.summary.overdue) workload=$($w7.ackOverdue)") }
    if ([int]$w7.unclosed -ne [int]$w7.assigned + [int]$w7.unassigned -or [int]$w7.assigned -ne $wSum) { $t25Fail.Add("workload invariants") }
    # 공개 데모에는 담당 기록이 없다(지어 넣지 않음): 큐 assignee 모두 null, byAssignee 비어 있음
    if (@($allQ.Json.items | Where-Object { $null -ne $_.assignee }).Count -ne 0 -or @($w7.byAssignee).Count -ne 0) { $t25Fail.Add("seeded assignments visible before perf step") }
    Assert-True ($t25Fail.Count -eq 0) "[T25b] handlingTimes·ackOverdue·summary.overdue = 독립 SQL, workload 불변식 (실패 $($t25Fail -join '; '))"

    # [T25c] 성능: 리허설 앱 DB(일회용)에 SQL로 모든 인시던트(모든 캡처의 최신 큐)의 담당 행을 analyst1로 넣는다.
    #        방법: postgres 컨테이너 안 스크립트가 zeekad에서 incident_id·capture_id를 CSV로 꺼내 임시 표로 \copy 한 뒤 INSERT ... ON CONFLICT DO NOTHING.
    #        analyst1(리허설 비밀번호, 공개 시드는 비활성)을 SQL로 잠시 활성화해 assignee=me를 잰다. 데우기 1번 뒤 3번, 최댓값 1초 이하.
    $pgC = Get-ServiceContainer "postgres"
    $perfSh = "set -e`n" +
        "psql -v ON_ERROR_STOP=1 -U postgres -d zeekad -At -c ""COPY (SELECT incident_id, capture_id FROM dashboard.latest_incident_queue) TO STDOUT WITH CSV"" > /tmp/t25-ids.csv`n" +
        "psql -v ON_ERROR_STOP=1 -U postgres -d zeekad_dashboard -At -c ""CREATE TEMP TABLE t25src (incident_id varchar(255), capture_id varchar(128))"" " +
        "-c ""\copy t25src FROM '/tmp/t25-ids.csv' WITH CSV"" " +
        "-c ""INSERT INTO incident_assignments (incident_id, capture_id, assignee_user_id, assigned_at, assigned_by, version) SELECT s.incident_id, s.capture_id, u.id, now(), 't25-perf', 1 FROM t25src s CROSS JOIN users u WHERE u.username = 'analyst1' ON CONFLICT DO NOTHING"" " +
        "-c ""SELECT count(*) FROM t25src"" -c ""SELECT count(*) FROM incident_assignments WHERE assignee_user_id IS NOT NULL""`n" +
        "rm -f /tmp/t25-ids.csv`n"
    $perfFile = Join-Path $tmpDir "t25-perf.sh"
    [IO.File]::WriteAllText($perfFile, $perfSh, $utf8NoBom)
    [void](Invoke-NativeCapture "docker" @("cp", $perfFile, "${pgC}:/tmp/t25-perf.sh"))
    $perfRes = Invoke-NativeCapture "docker" @("exec", $pgC, "sh", "/tmp/t25-perf.sh")
    [void](Invoke-Psql "zeekad_dashboard" "UPDATE users SET enabled = TRUE WHERE username = 'analyst1'")
    $latestCount = (Invoke-Psql "zeekad" "SELECT count(*) FROM dashboard.latest_incident_queue").Output.Trim()
    $a1 = New-Client "198.51.100.96"
    Assert-Status (Login-Api $a1 "analyst1" $env:BOOTSTRAP_ANALYST1_PASSWORD) 200 "[T25c] analyst1 로그인(리허설에서만 SQL로 활성화)"
    $e2eLogs.Add("[T25c] seeded assignments (t25src rows / assigned rows): $($perfRes.Output.Trim() -replace "`r?`n", ' / '); latest_incident_queue rows (all captures)=$latestCount; analyst1 enabled by SQL for this step")
    $t25Timings = [ordered]@{}
    $t25Slow = [System.Collections.Generic.List[string]]::new()
    $firstPublic = @($allQ.Json.items)[0]
    foreach ($t in @(@{ Name = 'demo queue all none'; Path = "/api/incidents/queue?period=all&assignee=none"; Client = $t25 },
                     @{ Name = 'demo queue 24h none'; Path = "/api/incidents/queue?period=24h&assignee=none"; Client = $t25 },
                     @{ Name = 'analyst1 queue all me'; Path = "/api/incidents/queue?period=all&assignee=me"; Client = $a1 },
                     @{ Name = 'analyst1 queue 24h me'; Path = "/api/incidents/queue?period=24h&assignee=me"; Client = $a1 },
                     @{ Name = 'demo queue all overdue'; Path = "/api/incidents/queue?period=all&overdue=true"; Client = $t25 },
                     @{ Name = 'demo detail'; Path = "/api/incidents/$($firstPublic.jobId)/rank/$($firstPublic.queueRank)"; Client = $t25 },
                     @{ Name = 'demo operations 7d'; Path = "/api/operations?period=7d"; Client = $t25 })) {
        $warm = Invoke-Http -Path $t.Path -Client $t.Client
        Assert-Status $warm 200 "[T25c] $($t.Name) (데우기)"
        $samples = @()
        for ($k = 0; $k -lt 3; $k++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-Http -Path $t.Path -Client $t.Client
            $sw.Stop()
            Assert-Status $r 200 "[T25c] $($t.Name)"
            $samples += [int]$sw.ElapsedMilliseconds
            if ($t.Client -eq $t25) { $t25Bodies.Add($r.Body); Find-UnmaskedIpv4 $r.Json "$($t.Name)" $t25IpHits }
        }
        $max = ($samples | Measure-Object -Maximum).Maximum
        $t25Timings[$t.Name] = "[$($samples -join ', ')] max=$max ms total=$($warm.Json.total)"
        if ($max -gt 1000) { $t25Slow.Add($t.Name) }
    }
    $noneAll = Invoke-Http -Path "/api/incidents/queue?period=all&assignee=none&size=25" -Client $t25
    $meAll = Invoke-Http -Path "/api/incidents/queue?period=all&assignee=me&size=25" -Client $a1
    $a1All = Invoke-Http -Path "/api/incidents/queue?period=all&size=25" -Client $a1
    $demoOpsAfter = Invoke-Http -Path "/api/operations?period=7d" -Client $t25
    $t25Bodies.Add($demoOpsAfter.Body)
    $e2eLogs.Add("[T25c] response times with every incident assigned (warm 1 + 3 samples, includes curl): $(($t25Timings.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')`n       demo none total=$($noneAll.Json.total) (all=$($allQ.Json.total)); analyst1 me total=$($meAll.Json.total) (analyst1 all=$($a1All.Json.total)); demo workload after=$($demoOpsAfter.Json.workload | ConvertTo-Json -Compress -Depth 4)")
    Assert-True ([int]$noneAll.Json.total -eq 0 -and [int]$meAll.Json.total -eq [int]$a1All.Json.total) "[T25c] 모두 담당이면 demo 미배정 0, analyst1 내 담당 = 그 집합 전체"
    Assert-True ([int]$demoOpsAfter.Json.workload.unassigned -eq 0 -and [int]$demoOpsAfter.Json.workload.assigned -eq [int]$demoOpsAfter.Json.workload.unclosed) "[T25c] demo 담당 현황(모두 배정, demo 집합 안에서만 셈)"
    Assert-True ($t25Slow.Count -eq 0) "[T25c] 응답 시간 최댓값 1초 이하 (넘은 것: $($t25Slow -join ', '))"
    [void](Invoke-Psql "zeekad_dashboard" "UPDATE users SET enabled = FALSE WHERE username = 'analyst1'")

    # [T25d] 숨김 캡처 흔적 0, VIEWER 가려지지 않은 IPv4 0(담당 행에는 숨김 캡처 인시던트도 있다)
    $t25Leaks = @()
    foreach ($body in $t25Bodies) { foreach ($hc in $demoHiddenCaptures) { if ($body.Contains($hc)) { $t25Leaks += $hc } } }
    $e2eLogs.Add("[T25d] hidden capture traces in T25 bodies=$($t25Leaks.Count) [$(@($t25Leaks | Select-Object -Unique) -join ', ')]; unmasked IPv4 JSON paths=$($t25IpHits.Count)$(if ($t25IpHits.Count) { ' ' + (($t25IpHits | Select-Object -First 20) -join ', ') })")
    Assert-True ($t25Leaks.Count -eq 0) "[T25d] 숨김 캡처 흔적 0"
    Assert-True ($t25IpHits.Count -eq 0) "[T25d] VIEWER 가려지지 않은 IPv4 0"

    # ───────── [T27] 인시던트 번호(V3·시작 동기화·독립 SQL 순서·재시작·T25 이미지 되돌리기·VIEWER·응답 시간) ─────────
    Write-Host "=== [T27] 인시던트 번호 ==="
    $t27 = New-Client "198.51.100.94"
    Assert-Status (Login-Api $t27 "demo" $env:DEMO_PASSWORD) 200 "[T27] demo 로그인"
    $t27Bodies = [System.Collections.Generic.List[string]]::new()
    $t27IpHits = [System.Collections.Generic.List[string]]::new()

    # [T27a] V3 적용, 시작 동기화 뒤 최신 큐(모든 캡처)의 모든 인시던트에 번호, 걸린 시간(앱 로그)
    $fw27 = (Invoke-Psql "zeekad_dashboard" "SELECT version, description, success FROM flyway_schema_history ORDER BY installed_rank").Output.Trim()
    $latestIds27 = @((Invoke-Psql "zeekad" "SELECT incident_id FROM dashboard.latest_incident_queue ORDER BY incident_id").Output.Trim() -split "`r?`n" | Where-Object { $_ })
    $refIds27 = @((Invoke-Psql "zeekad_dashboard" "SELECT incident_id FROM incident_refs ORDER BY incident_id").Output.Trim() -split "`r?`n" | Where-Object { $_ })
    $refSet27 = @{}; foreach ($r in $refIds27) { $refSet27[$r] = $true }
    $missing27 = @($latestIds27 | Where-Object { -not $refSet27.ContainsKey($_) })
    $appLogs27 = (Invoke-NativeCapture "docker" @("logs", (Get-ServiceContainer "dashboard-app")) -IgnoreExitCode).Output
    $syncLog27 = @($appLogs27 -split "`r?`n" | Where-Object { $_ -match '인시던트 번호' } | ForEach-Object { ($_ -replace '^\S+\s+', '').Trim() } | Select-Object -Last 3)
    $refStats27 = (Invoke-Psql "zeekad_dashboard" "SELECT count(*), min(incident_no), max(incident_no), count(DISTINCT created_at) FROM incident_refs").Output.Trim()
    $e2eLogs.Add("[T27a] flyway_schema_history:`n       $($fw27 -replace "`r?`n", "`n       ")`n       latest_incident_queue (all captures)=$($latestIds27.Count) incident_refs (count|min|max|batches)=$refStats27 missing=$($missing27.Count)`n       app log: $($syncLog27 -join ' / ')")
    Assert-True ($fw27 -match '(?m)^3\|incident refs\|t?$') "[T27a] 앱 DB에 V3 적용"
    Assert-True ($latestIds27.Count -gt 0 -and $missing27.Count -eq 0) "[T27a] 시작 동기화 뒤 최신 큐 모든 인시던트에 번호"

    # [T27b] 첫 묶음(created_at 최소) 번호 순서 = 탐지 시각(NULL 마지막)·capture_id·incident_id 순(독립 SQL, 문자열은 코드 순서 ucs_basic)
    $batch27 = @((Invoke-Psql "zeekad_dashboard" "SELECT incident_id FROM incident_refs WHERE created_at = (SELECT MIN(created_at) FROM incident_refs) ORDER BY incident_no").Output.Trim() -split "`r?`n" | Where-Object { $_ })
    $expected27 = @((Invoke-Psql "zeekad" ("SELECT lq.incident_id FROM dashboard.latest_incident_queue lq LEFT JOIN (SELECT q.capture_id, q.incident_id, MIN(j.finished_at) AS d " +
        "FROM dashboard.incident_queue q JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL " +
        "GROUP BY q.capture_id, q.incident_id) fs ON fs.capture_id = lq.capture_id AND fs.incident_id = lq.incident_id " +
        "ORDER BY fs.d ASC NULLS LAST, lq.capture_id COLLATE ucs_basic ASC, lq.incident_id COLLATE ucs_basic ASC")).Output.Trim() -split "`r?`n" | Where-Object { $_ })
    $bset27 = @{}; foreach ($b in $batch27) { $bset27[$b] = $true }
    $expInBatch27 = @($expected27 | Where-Object { $bset27.ContainsKey($_) })
    $orderOk27 = (($batch27 -join '|') -eq ($expInBatch27 -join '|'))
    $e2eLogs.Add("[T27b] first batch rows=$($batch27.Count) (latest queue $($expected27.Count)); order equals independent SQL=$orderOk27; first 5 by incident_no: $(($batch27 | Select-Object -First 5) -join ' ; ')")
    Assert-True ($batch27.Count -eq $expected27.Count -and $orderOk27) "[T27b] 첫 묶음 = 최신 큐 전체, 번호 순서 = 1절 순서"

    # [T27c] demo 큐 행 번호(모두 있고 겹치지 않음), 번호 API 위치 = 행, 숨긴 캡처 번호 403, 응답에 IPv4·숨김 흔적 없음
    $q27 = Invoke-Http -Path "/api/incidents/queue?period=all&size=100" -Client $t27
    Assert-Status $q27 200 "[T27c] demo 큐"
    $t27Bodies.Add($q27.Body); Find-UnmaskedIpv4 $q27.Json "queue[all]" $t27IpHits
    $items27 = @($q27.Json.items)
    $nos27 = @($items27 | ForEach-Object { $_.incidentNo })
    Assert-True ($items27.Count -gt 0 -and @($nos27 | Where-Object { $null -eq $_ }).Count -eq 0 -and @($nos27 | Select-Object -Unique).Count -eq $nos27.Count) "[T27c] demo 큐 행 모두 번호, 겹침 없음"
    $locBad27 = @()
    foreach ($it in ($items27 | Select-Object -First 10)) {
        $l = Invoke-Http -Path "/api/incidents/no/$($it.incidentNo)" -Client $t27
        $t27Bodies.Add($l.Body); Find-UnmaskedIpv4 $l.Json "no[$($it.incidentNo)]" $t27IpHits
        if ($l.Status -ne 200 -or [long]$l.Json.jobId -ne [long]$it.jobId -or [int]$l.Json.queueRank -ne [int]$it.queueRank -or $l.Json.latest -ne $true) { $locBad27 += "#$($it.incidentNo)" }
    }
    $hiddenList27 = (@($demoHiddenCaptures | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ',')
    $hiddenNo27 = if ($hiddenList27) { (Invoke-Psql "zeekad_dashboard" "SELECT incident_no FROM incident_refs WHERE capture_id IN ($hiddenList27) ORDER BY incident_no LIMIT 1").Output.Trim() } else { "" }
    $h27 = if ($hiddenNo27) { Invoke-Http -Path "/api/incidents/no/$hiddenNo27" -Client $t27 } else { $null }
    if ($h27) { $t27Bodies.Add($h27.Body) }
    $spa27 = Invoke-Http -Path "/incidents/$($items27[0].incidentNo)" -Client $t27
    $e2eLogs.Add("[T27c] demo queue items=$($items27.Count) locate mismatches=[$($locBad27 -join ', ')]; hidden capture number #$hiddenNo27 -> $(if ($h27) { Format-Resp $h27 160 } else { '(숨긴 캡처 없음)' }); GET /incidents/$($items27[0].incidentNo) -> HTTP $($spa27.Status) shell=$(Test-SpaShell $spa27)")
    Assert-True ($locBad27.Count -eq 0) "[T27c] 번호 API 위치 = 큐 행(처음 10개)"
    if ($h27) { Assert-ApiError $h27 403 "FORBIDDEN" "[T27c] demo 숨긴 캡처 번호" }
    Assert-True ($spa27.Status -eq 200 -and (Test-SpaShell $spa27)) "[T27c] /incidents/{번호} SPA 200" $spa27

    # [T27d] 응답 시간(데우기 1번 뒤 3번, 최댓값 1초 이하)
    $t27Times = [ordered]@{}
    $t27Slow = @()
    foreach ($pth in @("/api/incidents/no/$($items27[0].incidentNo)", "/api/incidents/queue?period=24h&size=50", "/api/incidents/queue?period=all&size=50", "/api/incidents/$($items27[0].jobId)/rank/$($items27[0].queueRank)")) {
        $warm = Invoke-Http -Path $pth -Client $t27
        Assert-Status $warm 200 "[T27d] $pth (데우기)"
        $ms = @()
        for ($k = 0; $k -lt 3; $k++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-Http -Path $pth -Client $t27
            $sw.Stop()
            Assert-Status $r 200 "[T27d] $pth"
            $t27Bodies.Add($r.Body); Find-UnmaskedIpv4 $r.Json "t27[$pth]" $t27IpHits
            $ms += [int]$sw.ElapsedMilliseconds
        }
        $max = ($ms | Measure-Object -Maximum).Maximum
        $t27Times[$pth] = "[$($ms -join ', ')] max=$max ms"
        if ($max -gt 1000) { $t27Slow += $pth }
    }
    $e2eLogs.Add("[T27d] response times (demo, warm 1 + 3 samples, includes curl): $(($t27Times.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')")
    Assert-True ($t27Slow.Count -eq 0) "[T27d] 응답 시간 최댓값 1초 이하 (넘은 것: $($t27Slow -join ', '))"

    # [T27e] 숨김 캡처 흔적 0, VIEWER 가려지지 않은 IPv4 0
    $t27Leaks = @()
    foreach ($body in $t27Bodies) { foreach ($hc in $demoHiddenCaptures) { if ($body.Contains($hc)) { $t27Leaks += $hc } } }
    $e2eLogs.Add("[T27e] hidden capture traces=$($t27Leaks.Count) [$(@($t27Leaks | Select-Object -Unique) -join ', ')]; unmasked IPv4 JSON paths=$($t27IpHits.Count)$(if ($t27IpHits.Count) { ' ' + (($t27IpHits | Select-Object -First 20) -join ', ') })")
    Assert-True ($t27Leaks.Count -eq 0) "[T27e] 숨김 캡처 흔적 0"
    Assert-True ($t27IpHits.Count -eq 0) "[T27e] VIEWER 가려지지 않은 IPv4 0"

    Write-Host "=== [T39] 새 실습망 캡처: 스레드 기록·숨김 부모·번호 유지·숨김 흔적 ==="
    $t39 = New-Client "198.51.100.139"
    Assert-Status (Login-Api $t39 "demo" $env:DEMO_PASSWORD) 200 "[T39] demo 로그인"
    $publicIn39 = (@($demoVisibleCaptures | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ',')
    # [T39a] demo로 lab-20261122 상세의 Slack 기록에 스레드 답글(threadParent)·재알림(replyBroadcast) 1건 이상, threadParent·payloadJson 포함 가려지지 않은 IPv4 0
    $t39aRows = @((Invoke-Psql "zeekad" ("SELECT lq.job_id || '/' || lq.queue_rank FROM dashboard.latest_incident_queue lq WHERE lq.capture_id = 'lab-20261122' " +
        "AND EXISTS (SELECT 1 FROM dashboard.slack_deliveries d WHERE d.incident_id = lq.incident_id AND d.zeekad_reply_broadcast) " +
        "AND EXISTS (SELECT 1 FROM dashboard.slack_deliveries d WHERE d.incident_id = lq.incident_id AND d.zeekad_thread_parent IS NOT NULL AND NOT d.zeekad_reply_broadcast) " +
        "ORDER BY lq.job_id, lq.queue_rank LIMIT 3")).Output.Trim() -split "`r?`n" | Where-Object { $_ -match '^\d+/\d+$' })
    $t39aReply = 0; $t39aBroadcast = 0; $t39aIp = [System.Collections.Generic.List[string]]::new(); $t39aLines = @()
    foreach ($row in $t39aRows) {
        $j39, $r39 = $row -split '/'
        $d39 = Invoke-Http -Path "/api/incidents/$j39/rank/$r39" -Client $t39
        Assert-Status $d39 200 "[T39a] demo lab-20261122 상세 $row"
        $sd39 = @($d39.Json.detail.slackDeliveries)
        $rep = @($sd39 | Where-Object { $_.threadParent }).Count
        $bc = @($sd39 | Where-Object { $_.replyBroadcast -eq $true }).Count
        $t39aReply += $rep; $t39aBroadcast += $bc
        Find-UnmaskedIpv4 $d39.Json "t39a[$row]" $t39aIp
        $t39aLines += "$row slack=$($sd39.Count) threadParent=$rep replyBroadcast=$bc maskedView=$($d39.Json.maskedView) sampleParent=$(@($sd39 | Where-Object { $_.threadParent } | Select-Object -First 1 | ForEach-Object { $_.threadParent }))"
    }
    $e2eLogs.Add("[T39a] lab-20261122 incidents with reply+broadcast rows (DB)=[$($t39aRows -join ', ')]`n       $($t39aLines -join "`n       ")`n       unmasked IPv4 JSON paths=$($t39aIp.Count)$(if ($t39aIp.Count) { ' ' + (($t39aIp | Select-Object -First 10) -join ', ') })")
    Assert-True ($t39aRows.Count -ge 1 -and $t39aReply -ge 1 -and $t39aBroadcast -ge 1) "[T39a] lab-20261122 상세 Slack 기록에 스레드 답글 $t39aReply·재알림 $t39aBroadcast (1건 이상)"
    Assert-True ($t39aIp.Count -eq 0) "[T39a] threadParent·payloadJson 포함 가려지지 않은 IPv4 0"
    # [T39b] 공개 인시던트의 Slack 행 가운데 부모가 숨김 캡처에 있는 것 0(숨김 캡처 인시던트 ID가 조회자에게 보이게 된다)
    $hiddenIn39 = (@($demoHiddenCaptures | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ',')
    $t39b = if ($hiddenIn39) { (Invoke-Psql "zeekad" ("SELECT count(*) FROM dashboard.slack_deliveries WHERE zeekad_thread_parent IS NOT NULL " +
        "AND split_part(zeekad_thread_parent, '|', 1) IN ($hiddenIn39) AND split_part(incident_id, '|', 1) IN ($publicIn39)")).Output.Trim() } else { '0' }
    $t39bPairs = (Invoke-Psql "zeekad" "SELECT split_part(zeekad_thread_parent, '|', 1) || ' <- ' || split_part(incident_id, '|', 1) || ' = ' || count(*) FROM dashboard.slack_deliveries WHERE zeekad_thread_parent IS NOT NULL GROUP BY split_part(zeekad_thread_parent, '|', 1), split_part(incident_id, '|', 1) ORDER BY 1").Output.Trim() -replace "`r?`n", '; '
    $e2eLogs.Add("[T39b] public incident rows whose thread parent is in a hidden capture=$t39b; parent capture <- incident capture (all rows): $t39bPairs")
    Assert-True ($t39b -eq '0') "[T39b] 공개 인시던트 Slack 행의 부모가 숨김 캡처인 것 0 ($t39b)"
    # [T39c] 최신 큐에 있는 옛 인시던트의 번호 = 공개 앱 DB(내보낸 목록, 전부). 최신 큐에 없는 번호("행만")는 개수·범위만 적는다.
    if ($ExpectedRefsFile) {
        $exp39 = @{}
        foreach ($ln in [IO.File]::ReadAllLines((Resolve-RepoPath $ExpectedRefsFile))) { if ($ln -match '^(\d+)\|([0-9a-f]{64})$') { $exp39[$Matches[2]] = [long]$Matches[1] } }
        $app39 = @{}
        foreach ($ln in ((Invoke-Psql "zeekad_dashboard" "SELECT incident_no || '|' || encode(sha256(convert_to(incident_id, 'UTF8')), 'hex') FROM incident_refs").Output -split "`r?`n")) { if ($ln.Trim() -match '^(\d+)\|([0-9a-f]{64})$') { $app39[$Matches[2]] = [long]$Matches[1] } }
        $latest39 = @{}
        foreach ($ln in ((Invoke-Psql "zeekad" "SELECT encode(sha256(convert_to(incident_id, 'UTF8')), 'hex') FROM dashboard.latest_incident_queue").Output -split "`r?`n")) { if ($ln.Trim() -match '^[0-9a-f]{64}$') { $latest39[$ln.Trim()] = $true } }
        $inLatest39 = @($exp39.Keys | Where-Object { $latest39.ContainsKey($_) })
        $rowOnly39 = @($exp39.Keys | Where-Object { -not $latest39.ContainsKey($_) } | ForEach-Object { $exp39[$_] } | Sort-Object)
        $diff39 = @($inLatest39 | Where-Object { -not $app39.ContainsKey($_) -or $app39[$_] -ne $exp39[$_] })
        $newNos39 = @($app39.Keys | Where-Object { -not $exp39.ContainsKey($_) } | ForEach-Object { $app39[$_] } | Sort-Object)
        $e2eLogs.Add("[T39c] expected refs=$($exp39.Count) (in latest queue $($inLatest39.Count), row-only $($rowOnly39.Count)$(if ($rowOnly39.Count) { " range $($rowOnly39[0])..$($rowOnly39[-1])" })); app refs=$($app39.Count); mismatched numbers=$($diff39.Count); new numbers=$($newNos39.Count)$(if ($newNos39.Count) { " range $($newNos39[0])..$($newNos39[-1])" })")
        Assert-True ($inLatest39.Count -gt 0 -and $diff39.Count -eq 0) "[T39c] 최신 큐에 있는 옛 인시던트 $($inLatest39.Count)건 번호 = 공개 앱 DB (다름 $($diff39.Count))"
    } else {
        $e2eLogs.Add("[T39c] skipped (no -ExpectedRefsFile)")
    }
    # [T39d] 숨김 캡처 ID(lab-20261123 포함)가 demo의 현황판·운영 현황·검토 목록 응답 본문에 없다
    $t39dLeaks = @(); $t39dIp = [System.Collections.Generic.List[string]]::new(); $t39dLines = @()
    # T47: 호스트 위험도, 같은 호스트 인시던트 한 건, 큐 hostIp=·attack= 한 건씩도 같은 검사를 받는다(T45·T46).
    #      hostIp는 조회자 큐의 첫 가린 주소(A.B.*.*), attack은 현황판 분포의 첫 전술(없으면 credential-access. 0건이어도 본문 검사는 한다)
    $ov39 = Invoke-Http -Path "/api/dashboard/overview?period=all" -Client $t39
    Assert-Status $ov39 200 "[T39d] demo overview(조건 값 고르기)"
    $tac39 = @($ov39.Json.attack.tactics | Where-Object { $_ })
    $attack39 = if ($tac39.Count) { [string]$tac39[0].tactic } else { "credential-access" }
    $q39 = Invoke-Http -Path "/api/incidents/queue?period=all&size=100" -Client $t39
    Assert-Status $q39 200 "[T39d] demo 큐(조건 값 고르기)"
    $first39 = @($q39.Json.items | Where-Object { $_ -and [string]$_.hostIp -match '^\d{1,3}\.\d{1,3}\.\*\.\*$' }) | Select-Object -First 1
    Assert-True ($null -ne $first39) "[T39d] demo 큐에 가린 IPv4 주소 행이 있음"
    $t47Paths39 = @("/api/hosts?period=all&size=100", "/api/incidents/$($first39.jobId)/rank/$($first39.queueRank)/related-host-incidents",
        "/api/incidents/queue?period=all&size=100&hostIp=$($first39.hostIp)", "/api/incidents/queue?period=all&size=100&attack=$attack39")
    foreach ($pth in (@("/api/dashboard/overview", "/api/dashboard/overview?period=all", "/api/operations", "/api/operations?period=all", "/api/reviews", "/api/reviews?pendingOnly=true", "/api/incidents/queue?period=all&size=100") + $t47Paths39)) {
        $r39 = Invoke-Http -Path $pth -Client $t39
        Assert-Status $r39 200 "[T39d] demo $pth"
        Find-UnmaskedIpv4 $r39.Json "t39d[$pth]" $t39dIp
        $hit = @($demoHiddenCaptures | Where-Object { $r39.Body.Contains($_) })
        if ($hit.Count) { $t39dLeaks += "$pth -> $($hit -join ',')" }
        $t39dLines += "$pth HTTP $($r39.Status) bytes=$($r39.Body.Length) hidden=$($hit.Count)"
    }
    $e2eLogs.Add("[T39d] hidden captures=[$($demoHiddenCaptures -join ', ')]`n       $($t39dLines -join "`n       ")`n       leaks=$($t39dLeaks.Count) unmasked IPv4 paths=$($t39dIp.Count)")
    Assert-True ($demoHiddenCaptures -contains 'lab-20261123') "[T39d] lab-20261123이 숨김 캡처(manifest)"
    Assert-True ($t39dLeaks.Count -eq 0) "[T39d] 현황판·운영 현황·검토 목록·큐 응답에 숨김 캡처 ID 없음"
    Assert-True ($t39dIp.Count -eq 0) "[T39d] 가려지지 않은 IPv4 0"

    Write-Host "=== [T40] 알림 묶음 건너가기: 큐 thread·상세 묶음 칸·403·숨김·마스킹·응답 시간 ==="
    # 값(incident_id·IP)은 기록하지 않는다. 묶음 머리는 sha256(incident_id)로만 맞추고 기록에는 번호·개수만 쓴다.
    $t40d = New-Client "198.51.100.140"
    Assert-Status (Login-Api $t40d "demo" $env:DEMO_PASSWORD) 200 "[T40] demo 로그인"
    $t40t = New-Client "198.51.100.141"
    Assert-Status (Login-Api $t40t $trialUser $env:TRIAL_ANALYST_PASSWORD) 200 "[T40] $trialUser 로그인"
    $t40Ip = [System.Collections.Generic.List[string]]::new()
    $t40Leaks = [System.Collections.Generic.List[string]]::new()
    # 읽기 한도(T36)에 걸리면 잠시 뒤 다시 보낸다(판정하지 않는다)
    $get40 = {
        param([string]$P, $C)
        for ($try = 1; $try -le 6; $try++) {
            $r = Invoke-Http -Path $P -Client $C
            if ($r.Status -ne 429) { return $r }
            Start-Sleep -Seconds 5
        }
        return $r
    }
    $check40 = {
        param($R, [string]$Label)
        # 가리지 않은 IPv4 검사는 조회자(demo) 응답에만. trial-analyst는 마스킹 없는 분석가다
        if (-not $Label.Contains($trialUser)) { Find-UnmaskedIpv4 $R.Json "t40[$Label]" $t40Ip }
        foreach ($hc in $demoHiddenCaptures) { if ($R.Body.Contains($hc)) { $t40Leaks.Add("$Label -> $hc") } }
    }
    $sha40 = { param([string]$S) ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($S))) -replace '-', '').ToLowerInvariant() }

    # 독립 SQL: 묶음 열쇠(부모가 있으면 부모, 없으면 자기)마다 구성원(열쇠 ∪ TRIM(부모) = 열쇠인 행) 가운데 공개 캡처·최신 큐에 있는 수와 숨김 캡처 수
    $hiddenIn40 = if ($hiddenIn39) { $hiddenIn39 } else { "''" }
    $exp40Sql = "WITH keys AS (SELECT DISTINCT COALESCE(NULLIF(TRIM(zeekad_thread_parent), ''), incident_id) AS head FROM dashboard.slack_deliveries), " +
        "rep AS (SELECT TRIM(zeekad_thread_parent) AS head, incident_id FROM dashboard.slack_deliveries WHERE NULLIF(TRIM(zeekad_thread_parent), '') IS NOT NULL), " +
        "m AS (SELECT head, head AS id FROM keys UNION SELECT k.head, r.incident_id FROM keys k JOIN rep r ON r.head = k.head) " +
        "SELECT encode(sha256(convert_to(m.head, 'UTF8')), 'hex') || '|' || count(*) FILTER (WHERE lq.capture_id IN ($publicIn39)) || '|' || count(*) FILTER (WHERE lq.capture_id IN ($hiddenIn40)) || '|' || " +
        "(count(DISTINCT m.id) - 1) || '|' || bool_or(m.id <> m.head) " +
        "FROM m LEFT JOIN dashboard.latest_incident_queue lq ON lq.incident_id = m.id GROUP BY m.head"
    $exp40 = @{}
    foreach ($ln in ((Invoke-Psql "zeekad" $exp40Sql).Output -split "`r?`n")) {
        if ($ln.Trim() -match '^([0-9a-f]{64})\|(\d+)\|(\d+)\|(\d+)\|(true|false)$') {
            $exp40[$Matches[1]] = [pscustomobject]@{ Public = [int]$Matches[2]; Hidden = [int]$Matches[3]; Others = ($Matches[5] -eq 'true') }
        }
    }
    $refs40 = @{}
    foreach ($ln in ((Invoke-Psql "zeekad_dashboard" "SELECT encode(sha256(convert_to(incident_id, 'UTF8')), 'hex') || '|' || incident_no || '|' || capture_id FROM incident_refs").Output -split "`r?`n")) {
        if ($ln.Trim() -match '^([0-9a-f]{64})\|(\d+)\|(.+)$') { $refs40[$Matches[1]] = [pscustomobject]@{ No = [long]$Matches[2]; Capture = $Matches[3] } }
    }
    $heads40 = @($exp40.Keys | Where-Object { $exp40[$_].Others })

    # [T40a] 다른 인시던트가 붙은 묶음 머리마다 큐 thread=<번호>&period=all의 total = 독립 SQL(구성원 ∩ 공개 캡처 ∩ 최신 큐). 숨김 캡처 인시던트는 응답에 없다
    $t40aLines = @(); $t40aBad = @(); $t40aHiddenMembers = 0; $t40aSizes = @(); $largest40 = $null
    foreach ($h in $heads40) {
        $ref = $refs40[$h]
        if ($null -eq $ref) { $t40aBad += "head without ref row"; continue }
        $e = $exp40[$h]
        $t40aHiddenMembers += $e.Hidden
        foreach ($pair in @(@("demo", $t40d), @($trialUser, $t40t))) {
            $q40 = & $get40 "/api/incidents/queue?period=all&size=100&thread=$($ref.No)" $pair[1]
            Assert-Status $q40 200 "[T40a] $($pair[0]) thread=$($ref.No)"
            & $check40 $q40 "a:$($pair[0]):$($ref.No)"
            $items40 = @($q40.Json.items)
            if ([int]$q40.Json.total -ne $e.Public -or $items40.Count -ne $e.Public) { $t40aBad += "$($pair[0]) #$($ref.No) total=$($q40.Json.total) items=$($items40.Count) expected=$($e.Public)" }
            if (@($items40 | Where-Object { $demoHiddenCaptures -contains $_.captureId }).Count) { $t40aBad += "$($pair[0]) #$($ref.No) hidden item" }
            if ([int]$q40.Json.summary.total -ne $e.Public) { $t40aBad += "$($pair[0]) #$($ref.No) summary.total=$($q40.Json.summary.total)" }
        }
        $t40aSizes += $e.Public
        $t40aLines += "#$($ref.No) capture=$(if ($demoVisibleCaptures -contains $ref.Capture) { $ref.Capture } else { '<hidden>' }) members(public latest)=$($e.Public) hidden=$($e.Hidden)"
        if ($null -eq $largest40 -or $e.Public -gt $largest40.Size) { $largest40 = [pscustomobject]@{ No = $ref.No; Size = $e.Public } }
    }
    $e2eLogs.Add("[T40a] thread heads with other incidents=$($heads40.Count); sizes=[$((@($t40aSizes | Sort-Object) -join ', '))]; hidden members(latest queue)=$t40aHiddenMembers`n       $($t40aLines -join "`n       ")`n       mismatches=$($t40aBad.Count)$(if ($t40aBad.Count) { ' ' + ($t40aBad -join '; ') })")
    Assert-True ($heads40.Count -ge 1 -and $t40aBad.Count -eq 0) "[T40a] 묶음 머리 $($heads40.Count)개의 큐 thread total = 독립 SQL(demo·$trialUser), 숨김 구성원 제외"
    Assert-True ($t40aHiddenMembers -ge 1) "[T40a] 숨김 캡처 구성원이 실제로 있다($t40aHiddenMembers건, 이 데이터가 곧 시험)"

    # [T40b] lab-20261122 상세 전부: 묶음마다 memberCount = 독립 SQL, headIncidentNo = incident_refs 번호(행이 없으면 null), restricted- 0
    $rows40 = @((Invoke-Psql "zeekad" "SELECT job_id || '/' || queue_rank FROM dashboard.latest_incident_queue WHERE capture_id = 'lab-20261122' ORDER BY job_id, queue_rank").Output -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+/\d+$' })
    $t40bBad = @(); $t40bGroups = 0; $t40bLinks = 0; $t40bRestricted = 0; $t40bSelf = 0
    foreach ($row in $rows40) {
        $j40, $r40 = $row -split '/'
        $dt = & $get40 "/api/incidents/$j40/rank/$r40" $t40t
        $dd = & $get40 "/api/incidents/$j40/rank/$r40" $t40d
        Assert-Status $dt 200 "[T40b] $trialUser 상세 $row"
        Assert-Status $dd 200 "[T40b] demo 상세 $row"
        & $check40 $dd "b:demo:$row"
        foreach ($hc in $demoHiddenCaptures) { if ($dt.Body.Contains($hc)) { $t40Leaks.Add("b:trial:$row -> $hc") } }
        $gt = @($dt.Json.detail.slackThreadGroups); $gd = @($dd.Json.detail.slackThreadGroups)
        if ($gt.Count -ne $gd.Count) { $t40bBad += "$row group count trial=$($gt.Count) demo=$($gd.Count)" ; continue }
        for ($gi = 0; $gi -lt $gt.Count; $gi++) {
            $t40bGroups++
            $g = $gt[$gi]
            if ([string]$g.threadKey -like 'restricted-*' -or [string]$gd[$gi].threadKey -like 'restricted-*') { $t40bRestricted++ }
            $hk = & $sha40 ([string]$g.threadKey)
            $e = $exp40[$hk]
            $ref = $refs40[$hk]
            $expNo = if ($ref -and ($demoVisibleCaptures -contains $ref.Capture)) { $ref.No } else { $null }
            $expCount = if ($null -ne $expNo -or $g.headIsSelf) { if ($e) { $e.Public } else { -1 } } else { 0 }
            if ($g.headIsSelf) { $t40bSelf++ }
            if ($null -ne $g.headIncidentNo -and -not $g.headIsSelf) { $t40bLinks++ }
            $gotNo = if ($null -eq $g.headIncidentNo) { $null } else { [long]$g.headIncidentNo }
            if ($gotNo -ne $expNo) { $t40bBad += "$row g$gi headIncidentNo=$gotNo expected=$expNo" }
            if ([int]$g.memberCount -ne $expCount) { $t40bBad += "$row g$gi memberCount=$($g.memberCount) expected=$expCount" }
            if ([int]$gd[$gi].memberCount -ne [int]$g.memberCount -or "$($gd[$gi].headIncidentNo)" -ne "$($g.headIncidentNo)" -or $gd[$gi].headIsSelf -ne $g.headIsSelf -or @($gd[$gi].deliveries).Count -ne @($g.deliveries).Count) {
                $t40bBad += "$row g$gi demo differs from $trialUser"
            }
        }
    }
    $e2eLogs.Add("[T40b] lab-20261122 details=$($rows40.Count) (demo + $trialUser); groups=$t40bGroups headIsSelf=$t40bSelf with head link=$t40bLinks restricted=$t40bRestricted; mismatches=$($t40bBad.Count)$(if ($t40bBad.Count) { ' ' + (($t40bBad | Select-Object -First 10) -join '; ') })")
    Assert-True ($rows40.Count -eq $expectedCounts['lab-20261122'] -and $t40bBad.Count -eq 0) "[T40b] lab-20261122 상세 $($rows40.Count)건 묶음 칸 = 독립 SQL, demo = $trialUser"
    Assert-True ($t40bRestricted -eq 0 -and $t40bLinks -ge 1) "[T40b] restricted- 0, 최초 알림 링크가 있는 묶음 $t40bLinks개"

    # [T40c] 숨김 캡처(lab-20261123) 인시던트 번호를 thread로 주면 403(두 계정), 형식 오류는 400
    $hiddenNos40 = @((Invoke-Psql "zeekad_dashboard" "SELECT incident_no FROM incident_refs WHERE capture_id = 'lab-20261123' ORDER BY incident_no LIMIT 2").Output -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' })
    $t40cLines = @()
    Assert-True ($hiddenNos40.Count -ge 1) "[T40c] lab-20261123 번호 행이 있다"
    foreach ($hn in $hiddenNos40) {
        foreach ($pair in @(@("demo", $t40d), @($trialUser, $t40t))) {
            $f40 = & $get40 "/api/incidents/queue?period=all&thread=$hn" $pair[1]
            Assert-Status $f40 403 "[T40c] $($pair[0]) 숨김 캡처 번호 thread"
            $t40cLines += "$($pair[0]) thread=<hidden no> -> $($f40.Status)"
        }
    }
    foreach ($bad in @("abc", "0", "1.5")) {
        $b40 = & $get40 "/api/incidents/queue?period=all&thread=$bad" $t40d
        Assert-Status $b40 400 "[T40c] demo thread=$bad"
        $t40cLines += "demo thread=$bad -> $($b40.Status)"
    }
    $e2eLogs.Add("[T40c] $($t40cLines -join '; ')")

    # [T40e] 응답 시간(데우기 1 + 3회, curl 포함 ms): 가장 큰 묶음으로 상세·큐 목록(thread)·이전·다음(thread).
    #        한도 = T39 기준 중앙값의 max(×1.5, +100ms). 기준: 상세 [T27d] 209ms·큐 all size=50 [T27d] 367ms(handoff/T39/evidence/rehearsal-timing.md),
    #        이웃 이동 period=all 221ms(handoff/T39/evidence/neighbors-timing.txt, 그림 스택)
    $q40big = & $get40 "/api/incidents/queue?period=all&size=50&thread=$($largest40.No)" $t40d
    $items40big = @($q40big.Json.items)
    $member40 = if ($items40big.Count -ge 2) { $items40big[1] } else { $items40big[0] }
    $t40eTargets = [ordered]@{
        "detail" = @("/api/incidents/$($member40.jobId)/rank/$($member40.queueRank)", 209)
        "queue-thread" = @("/api/incidents/queue?period=all&size=50&thread=$($largest40.No)", 367)
        "neighbors-thread" = @("/api/incidents/queue/neighbors?jobId=$($member40.jobId)&queueRank=$($member40.queueRank)&period=all&thread=$($largest40.No)", 221)
    }
    $t40eLines = @(); $t40eOver = @()
    foreach ($k in $t40eTargets.Keys) {
        $pth = $t40eTargets[$k][0]; $baseMs = [int]$t40eTargets[$k][1]
        $warm = & $get40 $pth $t40d
        Assert-Status $warm 200 "[T40e] $k (데우기)"
        $ms = @()
        for ($n = 0; $n -lt 3; $n++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-Http -Path $pth -Client $t40d
            $sw.Stop()
            Assert-Status $r 200 "[T40e] $k"
            & $check40 $r "e:$k"
            $ms += [int]$sw.ElapsedMilliseconds
        }
        $median = ($ms | Sort-Object)[1]
        $limit = [Math]::Max([int]($baseMs * 1.5), $baseMs + 100)
        if ($median -gt $limit) { $t40eOver += $k }
        $t40eLines += "$k=[$($ms -join ', ')] median=$median limit=$limit (T39 $baseMs)"
    }
    $e2eLogs.Add("[T40e] largest thread #$($largest40.No) size=$($largest40.Size); $($t40eLines -join '; ')")
    Assert-True ($t40eOver.Count -eq 0) "[T40e] 응답 시간 한도 안 (넘은 것: $($t40eOver -join ', '))"

    # [T40d] 새 요청 전체: demo 가려지지 않은 IPv4 0, 두 계정 응답에 숨김 캡처 ID 0.
    #        타 인시던트 답글 행의 페이로드에서 맨 위 zeekad_thread_parent 말고 다른 자리에 머리 incident_id가 글로 든 행 수(있으면 멈추고 묻는다)
    $t40Payload = (Invoke-Psql "zeekad" ("SELECT count(*) FROM dashboard.slack_deliveries WHERE NULLIF(TRIM(zeekad_thread_parent), '') IS NOT NULL " +
        "AND TRIM(zeekad_thread_parent) <> incident_id AND position(TRIM(zeekad_thread_parent) in (slack_payload::jsonb - 'zeekad_thread_parent')::text) > 0")).Output.Trim()
    $e2eLogs.Add("[T40d] reply rows whose payload carries the head incident_id outside the top-level zeekad_thread_parent=$t40Payload")
    Assert-True ($t40Payload -eq '0') "[T40d] 페이로드 다른 자리의 머리 incident_id 0 ($t40Payload)"
    $e2eLogs.Add("[T40d] unmasked IPv4 JSON paths=$($t40Ip.Count)$(if ($t40Ip.Count) { ' ' + (($t40Ip | Select-Object -First 10) -join ', ') }); hidden capture traces=$($t40Leaks.Count)$(if ($t40Leaks.Count) { ' ' + (($t40Leaks | Select-Object -First 10) -join ', ') })")
    Assert-True ($t40Ip.Count -eq 0) "[T40d] demo 가려지지 않은 IPv4 0"
    Assert-True ($t40Leaks.Count -eq 0) "[T40d] demo·$trialUser 응답에 숨김 캡처 ID 0"

    # [T27f] 앱 컨테이너를 다시 띄워도 번호가 그대로이고 새 행이 0
    $before27 = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) || ':' || md5(string_agg(incident_no || '=' || incident_id, ',' ORDER BY incident_no)) FROM incident_refs").Output.Trim()
    $rs27 = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "--force-recreate", "dashboard-app")) -IgnoreExitCode
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("restart", "nginx-waf")) -IgnoreExitCode)
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "nginx-waf")) -IgnoreExitCode)
    $after27 = (Invoke-Psql "zeekad_dashboard" "SELECT count(*) || ':' || md5(string_agg(incident_no || '=' || incident_id, ',' ORDER BY incident_no)) FROM incident_refs").Output.Trim()
    $restartLog27 = @(((Invoke-NativeCapture "docker" @("logs", (Get-ServiceContainer "dashboard-app")) -IgnoreExitCode).Output) -split "`r?`n" | Where-Object { $_ -match '인시던트 번호' } | ForEach-Object { ($_ -replace '^\S+\s+', '').Trim() } | Select-Object -Last 2)
    $e2eLogs.Add("[T27f] recreate dashboard-app exit=$($rs27.ExitCode); incident_refs (count:md5) before=$before27 after=$after27; app log: $($restartLog27 -join ' / ')")
    Assert-True ($rs27.ExitCode -eq 0 -and $before27 -eq $after27 -and ($restartLog27 -join ' ') -match '새 번호 0건') "[T27f] 재시작 뒤 번호 그대로, 새 행 0"

    # [T27g] 되돌리기 확인: V3가 적용된 앱 DB로 T25 이미지(zeek-ad-dashboard-app:pre-t27, main 0711836)가 정상으로 뜨는지. 확인 뒤 새 이미지로 되돌린다.
    $pre27 = "zeek-ad-dashboard-app:pre-t27"
    $pre27Id = (Invoke-NativeCapture "docker" @("image", "inspect", "--format", "{{.Id}}", $pre27)).Output.Trim()
    $env:PORTFOLIO_APP_IMAGE = $pre27
    $rb27Up = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "dashboard-app")) -IgnoreExitCode
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("restart", "nginx-waf")) -IgnoreExitCode)
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "nginx-waf")) -IgnoreExitCode)
    $rb27C = Get-ServiceContainer "dashboard-app"
    $rb27Img = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{.Image}}", $rb27C)).Output.Trim()
    $rb27Health = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{.State.Health.Status}}", $rb27C)).Output.Trim()
    $rb27Fly = @(((Invoke-NativeCapture "docker" @("logs", $rb27C) -IgnoreExitCode).Output) -split "`r?`n" | Where-Object { $_ -match 'Flyway|flyway|Migrat|Validate|schema history' } | ForEach-Object { ($_ -replace '^\S+\s+', '').Trim() } | Select-Object -Last 8)
    $rb27Cl = New-Client "198.51.100.93"
    $rb27Login = Login-Api $rb27Cl "demo" $env:DEMO_PASSWORD
    $rb27Queue = Invoke-Http -Path "/api/incidents/queue?period=24h&size=25" -Client $rb27Cl
    $rb27Detail = if (@($rb27Queue.Json.items).Count) { Invoke-Http -Path "/api/incidents/$($rb27Queue.Json.items[0].jobId)/rank/$($rb27Queue.Json.items[0].queueRank)" -Client $rb27Cl } else { $null }
    $e2eLogs.Add("[T27g] rollback check: PORTFOLIO_APP_IMAGE=$pre27 ($pre27Id) up exit=$($rb27Up.ExitCode); container image=$rb27Img health=$rb27Health`n       app Flyway log (tail):`n       $($rb27Fly -join "`n       ")`n       demo login: $(Format-Resp $rb27Login 120)`n       demo queue 24h: HTTP $($rb27Queue.Status) total=$($rb27Queue.Json.total) incidentNo present=$($null -ne $rb27Queue.Json.items[0].incidentNo)`n       detail: HTTP $(if ($rb27Detail) { $rb27Detail.Status } else { '-' })")
    Remove-Item env:PORTFOLIO_APP_IMAGE -ErrorAction SilentlyContinue
    $rb27Ok = ($rb27Up.ExitCode -eq 0 -and $rb27Img -eq $pre27Id -and $rb27Health -eq 'healthy' -and $rb27Login.Status -eq 200 -and $rb27Queue.Status -eq 200 -and ($null -eq $rb27Detail -or $rb27Detail.Status -eq 200))
    $fw27Up = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "dashboard-app")) -IgnoreExitCode
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("restart", "nginx-waf")) -IgnoreExitCode)
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "nginx-waf")) -IgnoreExitCode)
    $fw27Cl = New-Client "198.51.100.92"
    $fw27Login = Login-Api $fw27Cl "demo" $env:DEMO_PASSWORD
    $fw27Queue = Invoke-Http -Path "/api/incidents/queue?period=24h&size=25" -Client $fw27Cl
    $e2eLogs.Add("[T27g] back to new image: up exit=$($fw27Up.ExitCode) demo login HTTP $($fw27Login.Status); queue 24h HTTP $($fw27Queue.Status) first incidentNo=$($fw27Queue.Json.items[0].incidentNo)")
    Assert-True $rb27Ok "[T27g] V3가 적용된 DB로 T25 이미지가 정상으로 뜬다(되돌리기 가능)"
    Assert-True ($fw27Up.ExitCode -eq 0 -and $fw27Login.Status -eq 200 -and $fw27Queue.Status -eq 200) "[T27g] 새 이미지로 복귀"

    # [T25e] 되돌리기 확인: V2가 적용된 앱 DB로 T24 이미지(zeek-ad-dashboard-app:pre-t25, main 1d0077a)가 정상으로 뜨는지
    #        (Flyway가 앞선 마이그레이션 V2를 무시하는지). 확인 뒤 새 이미지로 되돌린다.
    $preImg = "zeek-ad-dashboard-app:pre-t25"
    $preId = (Invoke-NativeCapture "docker" @("image", "inspect", "--format", "{{.Id}}", $preImg)).Output.Trim()
    $env:PORTFOLIO_APP_IMAGE = $preImg
    $rbUp = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "dashboard-app")) -IgnoreExitCode
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("restart", "nginx-waf")) -IgnoreExitCode)
    $rbUpWaf = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "nginx-waf")) -IgnoreExitCode
    $rbAppC = Get-ServiceContainer "dashboard-app"
    $rbImg = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{.Image}}", $rbAppC)).Output.Trim()
    $rbHealth = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{.State.Health.Status}}", $rbAppC)).Output.Trim()
    $rbLogs = (Invoke-NativeCapture "docker" @("logs", $rbAppC) -IgnoreExitCode).Output
    $rbFlyway = @($rbLogs -split "`r?`n" | Where-Object { $_ -match 'Flyway|flyway|Migrat|Validate|schema history' } | ForEach-Object { ($_ -replace '^\S+\s+', '').Trim() } | Select-Object -Last 8)
    $rb = New-Client "198.51.100.97"
    $rbLogin = Login-Api $rb "demo" $env:DEMO_PASSWORD
    $rbQueue = Invoke-Http -Path "/api/incidents/queue?period=24h&size=25" -Client $rb
    $rbFw = (Invoke-Psql "zeekad_dashboard" "SELECT string_agg(version || ':' || success, ',' ORDER BY installed_rank) FROM flyway_schema_history").Output.Trim()
    $e2eLogs.Add("[T25e] rollback check: PORTFOLIO_APP_IMAGE=$preImg ($preId) up exit=$($rbUp.ExitCode) waf up exit=$($rbUpWaf.ExitCode); container image=$rbImg health=$rbHealth`n       app Flyway log (tail):`n       $($rbFlyway -join "`n       ")`n       demo login: $(Format-Resp $rbLogin 120)`n       demo queue 24h: HTTP $($rbQueue.Status) total=$($rbQueue.Json.total) summary.overdue present=$($null -ne $rbQueue.Json.summary.overdue)`n       flyway_schema_history after T24 app start=$rbFw")
    Remove-Item env:PORTFOLIO_APP_IMAGE -ErrorAction SilentlyContinue
    $rbOk = ($rbUp.ExitCode -eq 0 -and $rbImg -eq $preId -and $rbHealth -eq 'healthy' -and $rbLogin.Status -eq 200 -and $rbQueue.Status -eq 200 -and $null -eq $rbQueue.Json.summary.overdue)
    # 새 이미지로 되돌린다(뒤의 [9] ZAP은 새 이미지 대상)
    $fwUp = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "dashboard-app")) -IgnoreExitCode
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("restart", "nginx-waf")) -IgnoreExitCode)
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "nginx-waf")) -IgnoreExitCode)
    $fw2 = New-Client "198.51.100.98"
    $fwLogin = Login-Api $fw2 "demo" $env:DEMO_PASSWORD
    $fwQueue = Invoke-Http -Path "/api/incidents/queue?period=24h&size=25" -Client $fw2
    $e2eLogs.Add("[T25e] back to new image: up exit=$($fwUp.ExitCode) image=$((Invoke-NativeCapture "docker" @("inspect", "--format", "{{.Image}}", (Get-ServiceContainer "dashboard-app"))).Output.Trim()); demo login HTTP $($fwLogin.Status); queue 24h HTTP $($fwQueue.Status) summary.overdue=$($fwQueue.Json.summary.overdue)")
    Assert-True $rbOk "[T25e] V2가 적용된 DB로 T24 이미지가 정상으로 뜬다(되돌리기 가능)"
    Assert-True ($fwUp.ExitCode -eq 0 -and $fwLogin.Status -eq 200 -and $fwQueue.Status -eq 200 -and $null -ne $fwQueue.Json.summary.overdue) "[T25e] 새 이미지로 복귀"


    # ───────── [T29] 기간 밖 수(독립 SQL)·수집원 마지막 탐지·공유 조회 계정 잠금 제외·응답 시간 ─────────
    Write-Host "=== [T29] 기간 밖 안내·demo 잠금 제외 ==="
    $t29 = New-Client "198.51.100.120"
    Assert-Status (Login-Api $t29 "demo" $env:DEMO_PASSWORD) 200 "[T29] demo 로그인"
    $t29IpHits = [System.Collections.Generic.List[string]]::new()

    # [T29a] demo 큐 outsidePeriod = 독립 SQL(공개 캡처 최신 큐 중 (기준 − 길이, 기준] 밖, 탐지 시각 없음 포함) = 기간 전체 total − total
    $t29All = Invoke-Http -Path "/api/incidents/queue?period=all&size=25" -Client $t29
    Assert-Status $t29All 200 "[T29a] demo 큐 전체"
    Find-UnmaskedIpv4 $t29All.Json "t29[all]" $t29IpHits
    Assert-True ([long]$t29All.Json.outsidePeriod -eq 0) "[T29a] 기간 전체 outsidePeriod = 0" $t29All
    foreach ($pk in @(@("24h", "24 hours"), @("7d", "7 days"))) {
        $r = Invoke-Http -Path "/api/incidents/queue?period=$($pk[0])&size=25" -Client $t29
        Assert-Status $r 200 "[T29a] demo 큐 $($pk[0])"
        Find-UnmaskedIpv4 $r.Json "t29[$($pk[0])]" $t29IpHits
        $sqlOut = [long](Invoke-Psql "zeekad" ("SELECT count(*) FROM dashboard.latest_incident_queue lq LEFT JOIN (SELECT q.incident_id, MIN(j.finished_at) AS d " +
            "FROM dashboard.incident_queue q JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL GROUP BY q.incident_id) fs " +
            "ON fs.incident_id = lq.incident_id WHERE lq.capture_id = ANY($publicArr) " +
            "AND NOT COALESCE(fs.d > $anchorExpr - interval '$($pk[1])' AND fs.d <= $anchorExpr, FALSE)")).Output.Trim()
        $e2eLogs.Add("[T29a] demo queue period=$($pk[0]): total=$($r.Json.total) outsidePeriod=$($r.Json.outsidePeriod) newestOutsidePeriod=$([regex]::Match($r.Body, '"newestOutsidePeriod":("[^"]*"|null)').Groups[1].Value); independent SQL outside=$sqlOut; all-period total=$($t29All.Json.total) (참고: 2,180 - 52 = 2,128)")
        Assert-True ([long]$r.Json.outsidePeriod -eq $sqlOut) "[T29a] $($pk[0]) outsidePeriod = 독립 SQL ($($r.Json.outsidePeriod) / $sqlOut)" $r
        Assert-True ([long]$r.Json.outsidePeriod -eq ([long]$t29All.Json.total - [long]$r.Json.total)) "[T29a] $($pk[0]) outsidePeriod = 기간 전체 total - total" $r
    }

    # [T29b] sources의 수집원마다 lastDetectedAt = 독립 SQL(캡처별 최신 큐 탐지 시각 최대, epoch 초)
    $src29 = @{}
    foreach ($m in [regex]::Matches($t29All.Body, '"captureId":"([^"]+)","sourceType":"[^"]*","latestJobId":[^,]*,"lastDetectedAt":(null|"([^"]+)")')) {
        $src29[$m.Groups[1].Value] = if ($m.Groups[2].Value -eq 'null') { 'null' } else { [string][long][Math]::Floor([DateTimeOffset]::Parse($m.Groups[3].Value, [Globalization.CultureInfo]::InvariantCulture).ToUnixTimeMilliseconds() / 1000) }
    }
    $ld29 = (Invoke-Psql "zeekad" ("SELECT lq.capture_id, COALESCE(floor(extract(epoch FROM MAX(fs.d)))::bigint::text, 'null') FROM dashboard.latest_incident_queue lq LEFT JOIN (SELECT q.incident_id, MIN(j.finished_at) AS d " +
        "FROM dashboard.incident_queue q JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL GROUP BY q.incident_id) fs " +
        "ON fs.incident_id = lq.incident_id WHERE lq.capture_id = ANY($publicArr) GROUP BY lq.capture_id ORDER BY 1")).Output.Trim()
    $ldLog29 = [System.Collections.Generic.List[string]]::new()
    $ldBad29 = 0
    foreach ($line in @($ld29 -split "`r?`n" | Where-Object { $_ })) {
        $p = $line -split '\|'
        $ldLog29.Add("$($p[0]) api=$($src29[$p[0]]) sql=$($p[1])")
        if ($src29[$p[0]] -ne $p[1]) { $ldBad29++ }
    }
    $e2eLogs.Add("[T29b] demo sources lastDetectedAt (epoch s) vs independent SQL: $($ldLog29 -join '; '); hidden captures in sources=$(@($demoHiddenCaptures | Where-Object { $src29.ContainsKey($_) }).Count)")
    Assert-True ($ldBad29 -eq 0 -and $ldLog29.Count -eq $src29.Count -and $src29.Count -gt 0) "[T29b] 수집원 lastDetectedAt = 독립 SQL"
    Assert-True (@($demoHiddenCaptures | Where-Object { $src29.ContainsKey($_) }).Count -eq 0) "[T29b] 숨긴 캡처는 sources에 없다"

    # [T29c] 응답 시간(데우기 1번 뒤 3번, 최댓값 1초 이하): 큐 24시간·전체·자산 검색, 현황판 큐 호출·overview
    $t29Times = [ordered]@{}
    $t29Slow = @()
    foreach ($pth in @("/api/incidents/queue?period=24h&size=50", "/api/incidents/queue?period=all&size=50", "/api/incidents/queue?period=24h&size=50&asset=10", "/api/incidents/queue?period=24h&sort=detected&dir=desc&size=25", "/api/dashboard/overview?period=24h")) {
        $warm = Invoke-Http -Path $pth -Client $t29
        Assert-Status $warm 200 "[T29c] $pth (데우기)"
        $ms = @()
        for ($k = 0; $k -lt 3; $k++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-Http -Path $pth -Client $t29
            $sw.Stop()
            Assert-Status $r 200 "[T29c] $pth"
            Find-UnmaskedIpv4 $r.Json "t29[$pth]" $t29IpHits
            $ms += [int]$sw.ElapsedMilliseconds
        }
        $max = ($ms | Measure-Object -Maximum).Maximum
        $t29Times[$pth] = "[$($ms -join ', ')] max=$max ms"
        if ($max -gt 1000) { $t29Slow += $pth }
    }
    $e2eLogs.Add("[T29c] response times (demo, warm 1 + 3 samples, includes curl): $(($t29Times.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')")
    Assert-True ($t29Slow.Count -eq 0) "[T29c] 응답 시간 최댓값 1초 이하 (넘은 것: $($t29Slow -join ', '))"
    $e2eLogs.Add("[T29c] demo unmasked IPv4 JSON paths=$($t29IpHits.Count)")
    Assert-True ($t29IpHits.Count -eq 0) "[T29c] VIEWER 가려지지 않은 IPv4 0"

    # [T29d] demo 잠금 제외: 같은 클라이언트 IP에서 틀린 비밀번호 6번 뒤 맞는 비밀번호로 로그인된다.
    #        WAF 로그인 제한(IP당 10r/m, burst 5)에 걸리지 않게 7.5초 간격으로 보내고, 429면 판정하지 않고 12초 뒤 다시 보낸다.
    $exempt29 = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "dashboard-app", "sh", "-c", 'printf "%s" "${DASHBOARD_LOCKOUT_EXEMPT_USERNAMES-<unset>}"')) -IgnoreExitCode).Output.Trim()
    $maxFail29 = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "dashboard-app", "sh", "-c", 'printf "%s" "${DASHBOARD_MAX_FAILED_ATTEMPTS-<unset>}"')) -IgnoreExitCode).Output.Trim()
    $auditBase29 = [long](Invoke-Psql "zeekad_dashboard" "SELECT COALESCE(MAX(id),0) FROM audit_logs").Output.Trim()
    $lockIp29 = "198.51.100.131"
    $codes29 = [System.Collections.Generic.List[string]]::new()
    $final29 = $null
    for ($k = 1; $k -le 7; $k++) {
        $pw = if ($k -le 6) { "wrong-password-t29-$k" } else { $env:DEMO_PASSWORD }
        for ($try = 1; $try -le 4; $try++) {
            if ($k -gt 1 -or $try -gt 1) { Start-Sleep -Milliseconds $(if ($try -gt 1) { 12000 } else { 7500 }) }
            $lc29 = New-Client $lockIp29
            $res = Login-Api $lc29 "demo" $pw
            if ($res.Status -ne 429) { break }
            $codes29.Add("#$k try$try=429(retry)")
        }
        $codes29.Add("#$k=$($res.Status)$(if ($res.Json.code) { "/$($res.Json.code)" })")
        if ($k -le 6) { Assert-ApiError $res 401 "INVALID_CREDENTIALS" "[T29d] demo 틀린 비밀번호 #$k (잠금 없이 401)" }
        else { $final29 = $res }
    }
    $state29 = (Invoke-Psql "zeekad_dashboard" "SELECT failed_attempts, locked_until IS NULL FROM users WHERE username = 'demo'").Output.Trim()
    $audit29 = (Invoke-Psql "zeekad_dashboard" "SELECT action_type, count(*), count(*) FILTER (WHERE (detail_json::jsonb ->> 'lockoutExempt') = 'true') FROM audit_logs WHERE id > $auditBase29 AND actor_username = 'demo' GROUP BY action_type ORDER BY action_type").Output.Trim()
    $e2eLogs.Add("[T29d] app env DASHBOARD_LOCKOUT_EXEMPT_USERNAMES='$exempt29' DASHBOARD_MAX_FAILED_ATTEMPTS='$maxFail29'; same client IP $lockIp29, 7.5 s apart: [$($codes29 -join ', ')]; demo failed_attempts|locked_until IS NULL after=$state29`n       final correct password: $(Format-Resp $final29 160)`n       audit since base (action|count|lockoutExempt=true): $($audit29 -replace "`r?`n", '; ')")
    Assert-True ($exempt29 -eq 'demo,trial-analyst') "[T29d] 공개 스택 앱 설정 DASHBOARD_LOCKOUT_EXEMPT_USERNAMES=demo,trial-analyst"
    Assert-Status $final29 200 "[T29d] 틀린 비밀번호 6번 뒤 demo 정상 로그인"
    Assert-True ($audit29 -match '(?m)^LOGIN_FAILURE\|6\|6\s*$' -and $audit29 -notmatch 'ACCOUNT_LOCKED') "[T29d] LOGIN_FAILURE 6건(모두 lockoutExempt), ACCOUNT_LOCKED 0건"
    Assert-True ($state29 -eq '0|t') "[T29d] demo failed_attempts 0·locked_until 없음"

    # [T29e] 목록 밖 계정은 지금처럼 5번째 실패에 잠긴다. 공개 스택의 다른 계정은 비활성이라(비활성 검사가 먼저) 리허설 DB에서만
    #        viewer1을 잠시 활성화해 시험하고 끝나면 비활성·잠금 해제로 되돌린다. 요청마다 다른 클라이언트 IP(속도 제한 회피).
    $maxEnv29 = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "dashboard-app", "sh", "-c", 'printf "%s" "${DASHBOARD_MAX_FAILED_ATTEMPTS-<unset>}"')) -IgnoreExitCode).Output.Trim()
    [void](Invoke-Psql "zeekad_dashboard" "UPDATE users SET enabled = TRUE, failed_attempts = 0, locked_until = NULL WHERE username = 'viewer1'")
    $auditBase29e = [long](Invoke-Psql "zeekad_dashboard" "SELECT COALESCE(MAX(id),0) FROM audit_logs").Output.Trim()
    $codes29e = [System.Collections.Generic.List[string]]::new()
    for ($k = 1; $k -le 5; $k++) {
        $res = Login-Api (New-Client "198.51.100.$(140 + $k)") "viewer1" "wrong-password-t29e-$k"
        $codes29e.Add("$($res.Status)")
    }
    $ok29e = Login-Api (New-Client "198.51.100.150") "viewer1" $env:BOOTSTRAP_VIEWER1_PASSWORD
    $audit29e = (Invoke-Psql "zeekad_dashboard" "SELECT action_type, count(*) FROM audit_logs WHERE id > $auditBase29e AND actor_username = 'viewer1' GROUP BY action_type ORDER BY action_type").Output.Trim()
    [void](Invoke-Psql "zeekad_dashboard" "UPDATE users SET enabled = FALSE, failed_attempts = 0, locked_until = NULL WHERE username = 'viewer1'")
    $restored29e = (Invoke-Psql "zeekad_dashboard" "SELECT enabled, failed_attempts, locked_until IS NULL FROM users WHERE username = 'viewer1'").Output.Trim()
    $e2eLogs.Add("[T29e] app env DASHBOARD_MAX_FAILED_ATTEMPTS='$maxEnv29'; viewer1(목록 밖 VIEWER, 리허설에서만 잠시 활성) wrong x5 -> HTTP [$($codes29e -join ', ')]; correct password -> $(Format-Resp $ok29e 160); audit: $($audit29e -replace "`r?`n", '; '); restored (enabled|failed|unlocked)=$restored29e")
    Assert-True ($maxEnv29 -eq '5') "[T29e] 공개 스택 앱 설정 DASHBOARD_MAX_FAILED_ATTEMPTS=5"
    Assert-True (($codes29e -join ',') -eq '401,401,401,401,423') "[T29e] 목록 밖 계정 5번째 실패에 423 잠금"
    Assert-ApiError $ok29e 423 "ACCOUNT_LOCKED" "[T29e] 잠긴 뒤 맞는 비밀번호도 423"
    Assert-True ($audit29e -match '(?m)^ACCOUNT_LOCKED\|1\s*$') "[T29e] ACCOUNT_LOCKED 감사 1건"
    Assert-True ($restored29e -eq 'f|0|t') "[T29e] viewer1 비활성·잠금 해제로 되돌림"

    # ───────── [T32] 전달 헤더 신뢰: WAF 고정 주소·게이트웨이만 믿기 ─────────
    # 호스트(DSM 흉내) 경로는 게이트웨이에서 온 연결이라 X-Forwarded-For·Proto를 믿고, 같은 네트워크의 다른 컨테이너가
    # nginx-waf:8080이나 dashboard-app:8080에 직접 보낸 전달 헤더는 믿지 않는다. 로그인 시도는 없는 계정이라 잠금에 영향이 없다.
    # T61: api는 portfolio-data에만 붙어 nginx-waf에 닿지 않는다. WAF 쪽([T32c])은 portfolio-net에 붙인 일회용 컨테이너에서,
    #      앱 직접([T32d])은 지금처럼 api 컨테이너(portfolio-data 주소)에서 보낸다.
    Write-Host "=== [T32] 전달 헤더 신뢰(WAF 고정 주소·게이트웨이) ==="
    $wafIp32 = Get-NetIp "nginx-waf" $networkName
    $apiIp32 = Get-NetIp "api" $dataNetworkName
    $gw32 =(Invoke-NativeCapture "docker" @("network", "inspect", "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}", $networkName)).Output.Trim()
    $appTrusted32 = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "dashboard-app", "sh", "-c", 'printf "%s" "${DASHBOARD_TRUSTED_PROXIES-<unset>}"')) -IgnoreExitCode).Output.Trim()
    $wafRealIp32 = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "nginx-waf", "sh", "-c", 'echo ${SET_REAL_IP_FROM:-unset}+${ZEEKAD_GATEWAY_IP:-unset}')) -IgnoreExitCode).Output.Trim()
    $e2eLogs.Add("[T32a] nginx-waf=$wafIp32 api=$apiIp32 network gateway=$gw32; app DASHBOARD_TRUSTED_PROXIES=$appTrusted32; nginx-waf SET_REAL_IP_FROM+ZEEKAD_GATEWAY_IP=$wafRealIp32")
    Assert-True ($wafIp32 -eq "10.203.48.250" -and $appTrusted32 -eq $wafIp32) "[T32a] nginx-waf 고정 주소 = 앱 신뢰 목록 = 10.203.48.250"
    Assert-True ($wafRealIp32 -eq "127.0.0.1,10.203.48.1+10.203.48.1" -and $gw32 -eq "10.203.48.1") "[T32a] WAF 신뢰 범위 = 127.0.0.1 + 게이트웨이 10.203.48.1"

    function Get-WafAccessLine([string]$Probe) {
        for ($i = 0; $i -lt 10; $i++) {
            $logs = (Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--no-log-prefix", "nginx-waf")) -IgnoreExitCode).Output
            $line = $logs -split "`r?`n" | Where-Object { -not $_.StartsWith('{') -and $_.Contains("probe=$Probe") } | Select-Object -Last 1
            if ($line) { return $line }
            Start-Sleep -Seconds 1
        }
        return ""
    }

    # [T32b] 호스트(DSM 흉내): 게이트웨이에서 온 연결이라 X-Forwarded-For가 감사 로그 IP, X-Forwarded-Proto: https가 https 판정
    $probeHost32 = "t32host$(New-RandomToken 8)"
    $hostAccess32 = Invoke-Http -Path "/login?probe=$probeHost32"
    $hostLine32 = Get-WafAccessLine $probeHost32
    $hostConn32 = ($hostLine32 -split ' ')[0]
    $hostUser32 = "t32_host_$(New-RandomToken 6)"
    $hc32 = New-Client "203.0.113.132"
    $hostCsrf32 = Invoke-Http -Path "/api/auth/csrf" -Client $hc32
    $hostLogin32 = Invoke-Http -Path "/api/auth/login" -Method POST -Client $hc32 -Csrf -JsonBody @{ username = $hostUser32; password = "wrong-t32" }
    $hostIp32 = (Invoke-Psql "zeekad_dashboard" "SELECT COALESCE(client_ip,'') FROM audit_logs WHERE actor_username = '$hostUser32' AND action_type = 'LOGIN_FAILURE' ORDER BY id DESC LIMIT 1").Output.Trim()
    $hostHsts32 = Get-HeaderValue $hostCsrf32 "Strict-Transport-Security"
    $hostNope32 = Invoke-Http -Path "/nope"
    $e2eLogs.Add("[T32b] host (DSM imitation) GET /login?probe -> HTTP $($hostAccess32.Status); WAF access log connection address=$hostConn32`n       login (unknown user, X-Forwarded-For: 203.0.113.132, X-Forwarded-Proto: https) -> HTTP $($hostLogin32.Status); audit client_ip=$hostIp32; csrf Strict-Transport-Security=$hostHsts32; GET /nope Location=$(Get-HeaderValue $hostNope32 'Location')")
    Assert-True ($hostConn32 -eq $gw32) "[T32b] 호스트 경로 연결이 게이트웨이($gw32)에서 옴 (실제 $hostConn32)"
    Assert-True ($hostLogin32.Status -eq 401 -and $hostIp32 -eq "203.0.113.132") "[T32b] 호스트(DSM 흉내) 경로는 X-Forwarded-For가 감사 로그 IP (client_ip=$hostIp32)"
    # T36: 공개 경로에서는 DSM이 HSTS를 붙이므로 WAF 응답에는 HSTS가 없다(앱의 HSTS를 WAF가 숨김). 앱의 https 판정은 아래 Location으로 본다.
    Assert-True (-not $hostHsts32) "[T32b] 호스트(DSM 흉내) WAF 응답에 HSTS 없음(공개에서는 DSM이 붙임)" $hostCsrf32
    Assert-True ((Get-HeaderValue $hostNope32 "Location") -eq "https://$PublicHost/login") "[T32b] 호스트 경로 Location https://$PublicHost/login (T31과 같음)" $hostNope32

    # [T32c] portfolio-net 일회용 컨테이너 -> nginx-waf:8080, [T32d] api 컨테이너 -> dashboard-app:8080 직접. 파이썬 스크립트는 base64로 넘긴다.
    # 첫 줄(self)은 보내는 쪽 주소다: base의 호스트·포트에 연결한 소켓의 getsockname()[0](일회용 컨테이너의 주소는 미리 알 수 없다).
    $py32 = @(
        'import sys, json, re, socket, urllib.parse, urllib.request, urllib.error',
        'base, user, xff, probe = sys.argv[1:5]',
        'u = urllib.parse.urlsplit(base)',
        'so = socket.create_connection((u.hostname, u.port or 80), timeout=10); print("self", so.getsockname()[0]); so.close()',
        'class NoRedirect(urllib.request.HTTPRedirectHandler):',
        '    def redirect_request(self, *args, **kwargs):',
        '        return None',
        'opener = urllib.request.build_opener(NoRedirect)',
        'H = {"X-Forwarded-For": xff, "X-Forwarded-Proto": "https", "X-Forwarded-Port": "443"}',
        'def req(path, method="GET", extra=None, data=None):',
        '    h = dict(H); h.update(extra or {})',
        '    r = urllib.request.Request(base + path, data=data, headers=h, method=method)',
        '    try:',
        '        resp = opener.open(r, timeout=20); return resp.status, resp.headers',
        '    except urllib.error.HTTPError as e:',
        '        return e.code, e.headers',
        's, h = req("/api/auth/csrf?probe=" + probe)',
        'tok = ""',
        'for c in h.get_all("Set-Cookie") or []:',
        '    m = re.match(r"XSRF-TOKEN=([^;]*)", c)',
        '    if m: tok = m.group(1)',
        'print("csrf", s, "hsts=%s" % (h.get("Strict-Transport-Security") is not None), "xsrf=%s" % bool(tok))',
        's2, h2 = req("/api/auth/login", "POST", {"Cookie": "XSRF-TOKEN=" + tok, "X-XSRF-TOKEN": tok, "Content-Type": "application/json"}, json.dumps({"username": user, "password": "wrong-t32"}).encode())',
        'print("login", s2)',
        's3, h3 = req("/nope?probe=" + probe)',
        'print("nope", s3, "location=%s" % h3.get("Location"))'
    ) -join "`n"
    $py32b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($py32))
    # -FromNet: portfolio-net에 붙인 일회용 컨테이너($netProbeArgs)에서, 아니면 api 컨테이너에서 보낸다.
    function Invoke-ApiProbe([string]$Base, [string]$User, [string]$Xff, [string]$Probe, [switch]$FromNet) {
        $code = "import base64;exec(base64.b64decode('$py32b64'))"
        $runArgs = if ($FromNet) { $netProbeArgs + @("-c", $code) } else { $composeArgs + @("exec", "-T", "api", "python", "-c", $code) }
        return (Invoke-NativeCapture "docker" ($runArgs + @($Base, $User, $Xff, $Probe)) -IgnoreExitCode).Output.Trim()
    }

    $viaWafUser32 = "t32_net_waf_$(New-RandomToken 6)"
    $probeWaf32 = "t32netwaf$(New-RandomToken 8)"
    $viaWaf32 = Invoke-ApiProbe "http://nginx-waf:8080" $viaWafUser32 "198.51.100.32" $probeWaf32 -FromNet
    $probeIp32 = [regex]::Match($viaWaf32, '(?m)^self (\S+)').Groups[1].Value
    $viaWafLine32 = Get-WafAccessLine $probeWaf32
    $viaWafConn32 = ($viaWafLine32 -split ' ')[0]
    $viaWafIp32 = (Invoke-Psql "zeekad_dashboard" "SELECT COALESCE(client_ip,'') FROM audit_logs WHERE actor_username = '$viaWafUser32' AND action_type = 'LOGIN_FAILURE' ORDER BY id DESC LIMIT 1").Output.Trim()
    $e2eLogs.Add("[T32c] one-off container on $networkName ($probeIp32) -> nginx-waf:8080 with X-Forwarded-For: 198.51.100.32, X-Forwarded-Proto: https, X-Forwarded-Port: 443:`n       $($viaWaf32 -replace "`r?`n", ' | ')`n       WAF access log connection address=$viaWafConn32; audit LOGIN_FAILURE client_ip=$viaWafIp32")
    Assert-True ($probeIp32 -match '^\d{1,3}(\.\d{1,3}){3}$' -and $probeIp32 -ne $wafIp32 -and $probeIp32 -ne $gw32) "[T32c] 일회용 컨테이너 주소가 portfolio-net의 다른 주소 ($probeIp32)"
    Assert-True ($viaWafConn32 -eq $probeIp32) "[T32c] WAF 로그 접속 주소 = 일회용 컨테이너 ($viaWafConn32)"
    Assert-True ($viaWaf32 -match '(?m)^login 401' -and $viaWafIp32 -eq $probeIp32) "[T32c] 일회용 컨테이너 -> WAF 감사 로그 IP = 그 컨테이너 주소, 198.51.100.32 아님 (client_ip=$viaWafIp32)"
    Assert-True ($viaWaf32 -match '(?m)^csrf 200 hsts=False') "[T32c] 일회용 컨테이너 -> WAF X-Forwarded-Proto: https는 https 판정 아님(HSTS 없음)"
    $loc32c = [regex]::Match($viaWaf32, 'location=(\S+)').Groups[1].Value
    Assert-True ($viaWaf32 -match '(?m)^nope 302' -and $loc32c -notmatch '^https://' -and $loc32c -notmatch ':443') "[T32c] 일회용 컨테이너 -> WAF 리다이렉트가 https/443이 아님 ($loc32c)"

    $directUser32 = "t32_api_app_$(New-RandomToken 6)"
    $direct32 = Invoke-ApiProbe "http://dashboard-app:8080" $directUser32 "198.51.100.33" "t32direct$(New-RandomToken 8)"
    $directIp32 = (Invoke-Psql "zeekad_dashboard" "SELECT COALESCE(client_ip,'') FROM audit_logs WHERE actor_username = '$directUser32' AND action_type = 'LOGIN_FAILURE' ORDER BY id DESC LIMIT 1").Output.Trim()
    $e2eLogs.Add("[T32d] api container ($apiIp32, $dataNetworkName) -> dashboard-app:8080 directly with X-Forwarded-For: 198.51.100.33, X-Forwarded-Proto: https, X-Forwarded-Port: 443:`n       $($direct32 -replace "`r?`n", ' | ')`n       audit LOGIN_FAILURE client_ip=$directIp32")
    Assert-True ($direct32 -match '(?m)^login 401' -and $directIp32 -eq $apiIp32) "[T32d] api -> 앱 직접 감사 로그 IP = api 주소 (client_ip=$directIp32)"
    Assert-True ($direct32 -match '(?m)^csrf 200 hsts=False') "[T32d] api -> 앱 직접 X-Forwarded-Proto: https는 https 판정 아님"
    Assert-True ($direct32 -match 'location=http://dashboard-app:8080/login') "[T32d] api -> 앱 직접 Location은 연결 값"

    # ───────── [T47] E 단계 기능(T44~T46·T45b)을 실제 스냅샷에서 ─────────
    # 덮어쓴 조회 한도(분당 6,000회)가 유효한 [T36] 앞에서 돈다. demo(조회자)와 trial-analyst(분석가)로 큐 hostIp·attack, 묶음 표지,
    # 호스트 위험도, 같은 호스트 인시던트, overview 새 집계를 같은 조건 큐 total과 독립 SQL에 맞춰 본다.
    # 값(주소·호스트 이름·계정 이름·incident_id)은 기록하지 않는다. 수와 가린 값(A.B.*.*), 전술 슬러그·기법 ID, 인시던트 번호만 쓴다.
    # 조건에 맞는 자료가 스냅샷에 없으면 FAIL이 아니라 "자료 없음"으로 적는다.
    Write-Host "=== [T47] 큐 hostIp·attack, 묶음 표지, 호스트 위험도, 같은 호스트 인시던트, overview 새 집계, 응답 시간 비교 ==="
    $t47d = New-Client "198.51.100.147"
    Assert-Status (Login-Api $t47d "demo" $env:DEMO_PASSWORD) 200 "[T47] demo 로그인"
    $t47t = New-Client "198.51.100.148"
    Assert-Status (Login-Api $t47t $trialUser $env:TRIAL_ANALYST_PASSWORD) 200 "[T47] $trialUser 로그인"
    $t47Ip = [System.Collections.Generic.List[string]]::new()
    $t47Leaks = [System.Collections.Generic.List[string]]::new()
    $t47NoData = [System.Collections.Generic.List[string]]::new()
    $t47Pairs = @(@{ Name = "demo"; Client = $t47d; Masked = $true }, @{ Name = $trialUser; Client = $t47t; Masked = $false })
    # 요청 하나: 200 확인, 조회자 응답이면 가리지 않은 IPv4 경로를 모으고, 두 계정 모두 숨김 캡처 ID가 본문에 있는지 본다. $Label에는 값을 넣지 않는다
    $get47 = {
        param([string]$P, $Who, [string]$Label)
        $r = & $get40 $P $Who.Client
        Assert-Status $r 200 "[T47] $($Who.Name) $Label"
        if ($Who.Masked) { Find-UnmaskedIpv4 $r.Json "t47[$Label]" $t47Ip }
        foreach ($hc in $demoHiddenCaptures) { if ($r.Body.Contains($hc)) { $t47Leaks.Add("$($Who.Name) $Label -> $hc") } }
        return $r
    }
    $sql47 = {
        param([string]$S, [string]$What)
        $o = Invoke-Psql "zeekad" $S
        # 이 단계의 SQL 글에는 주소·계정 값이 없다(캡처 ID와 작업·순위 번호만). 오류 글 앞부분만 싣는다
        if ($o.ExitCode -ne 0) { throw "[T47] 독립 SQL 실패($What, exit=$($o.ExitCode)): $(($o.Output -replace '\s+', ' ').Trim().Substring(0, [Math]::Min(300, ($o.Output -replace '\s+', ' ').Trim().Length)))" }
        return $o.Output.Trim()
    }
    $lines47 = { param([string]$T) return @($T -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $pub47 = "l.capture_id IN ($publicIn39)"
    $lq47 = "dashboard.latest_incident_queue l"
    $ipv4Sql47 = '''^[0-9]{1,3}(\.[0-9]{1,3}){3}$'''
    # 조회자에게 보이는 가린 주소(A.B.*.*). IPv4 꼴이 아니면 그대로다(옥텟 범위는 보지 않는다)
    $mask47 = "CASE WHEN l.host_ip ~ $ipv4Sql47 THEN split_part(l.host_ip, '.', 1) || '.' || split_part(l.host_ip, '.', 2) || '.*.*' ELSE l.host_ip END"
    $bandRe47 = '^\d{1,3}\.\d{1,3}\.\*\.\*$'
    $base47 = (& $sql47 "SELECT count(*) || '|' || count(DISTINCT l.host_ip) || '|' || count(DISTINCT $mask47) || '|' || count(DISTINCT l.host_ip) FILTER (WHERE l.host_ip !~ $ipv4Sql47) FROM $lq47 WHERE $pub47" "기준 수") -split '\|'
    $rows47 = [long]$base47[0]; $hosts47 = [long]$base47[1]; $bands47 = [long]$base47[2]; $nonV4Hosts47 = [long]$base47[3]
    $e2eLogs.Add("[T47] public latest queue (independent SQL): rows=$rows47 distinct host_ip=$hosts47 distinct masked ranges=$bands47 distinct non-IPv4 host values=$nonV4Hosts47; public captures=[$($demoVisibleCaptures -join ', ')]")

    # [T47i] IPv6 호스트 주소 조사(읽기만, 수만). 조회자에게 IPv6 주소는 지금 원문으로 나간다(maskIp가 IPv4만 가린다). 가리기 규칙은 여기서 바꾸지 않는다
    $v6 = (& $sql47 "SELECT count(*) FILTER (WHERE l.host_ip LIKE '%:%') || '|' || count(DISTINCT l.host_ip) FILTER (WHERE l.host_ip LIKE '%:%') || '|' || count(*) FILTER (WHERE l.host_ip NOT LIKE '%:%' AND l.host_ip !~ $ipv4Sql47) FROM $lq47 WHERE $pub47" "IPv6 호스트 수") -split '\|'
    $v6ByCap = (& $sql47 "SELECT l.capture_id || '=' || count(*) FROM $lq47 WHERE $pub47 AND l.host_ip LIKE '%:%' GROUP BY l.capture_id ORDER BY 1" "IPv6 호스트 캡처별 수") -replace "`r?`n", ', '
    $v6Text = "# T47 IPv6 host address survey (public captures, latest queue; counts only, no address values)`nlatest queue rows (public)=$rows47`nrows whose host_ip is IPv6 (contains ':')=$($v6[0])`ndistinct IPv6 host_ip values=$($v6[1])`nrows whose host_ip is neither IPv4-shaped nor IPv6=$($v6[2])`nIPv6 rows per capture=[$v6ByCap]`n"
    Save-Evidence "t47-ipv6-hosts.txt" $v6Text
    $e2eLogs.Add("[T47i] IPv6 host_ip in public latest queue: rows=$($v6[0]) distinct=$($v6[1]) per capture=[$v6ByCap]; neither IPv4 nor IPv6 rows=$($v6[2]) (counts only; t47-ipv6-hosts.txt)")

    # [T47a] 큐 hostIp: 분석가의 온전한 주소 = 독립 SQL의 그 호스트 건수, 대역 = 그 대역 건수(두 계정), 조회자의 온전한 주소 요청은 0건, 형식 오류 400
    $hostTop47 = @(& $lines47 (& $sql47 "SELECT l.host_ip || '|' || count(*) FROM $lq47 WHERE $pub47 AND l.host_ip ~ $ipv4Sql47 GROUP BY l.host_ip ORDER BY count(*) DESC, l.host_ip LIMIT 3" "상위 호스트"))
    $bandTop47 = @(& $lines47 (& $sql47 "SELECT x.m || '|' || count(*) FROM (SELECT $mask47 AS m FROM $lq47 WHERE $pub47 AND l.host_ip ~ $ipv4Sql47) x GROUP BY x.m ORDER BY count(*) DESC, x.m LIMIT 3" "상위 대역"))
    $t47aBad = @(); $t47aLines = @(); $hi = 0
    foreach ($ln in $hostTop47) {
        $hi++
        $hp = $ln -split '\|'
        $exp = [long]$hp[1]
        $range = $hp[0] -replace '^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$', '$1.$2.*.*'
        $rt = & $get47 "/api/incidents/queue?period=all&size=25&hostIp=$($hp[0])" $t47Pairs[1] "queue hostIp=<host #$hi>"
        $rd = & $get47 "/api/incidents/queue?period=all&size=25&hostIp=$($hp[0])" $t47Pairs[0] "queue hostIp=<host #$hi full address>"
        if ([long]$rt.Json.total -ne $exp -or [long]$rt.Json.summary.total -ne $exp) { $t47aBad += "$trialUser host #$hi total=$($rt.Json.total) expected=$exp" }
        if ([long]$rd.Json.total -ne 0 -or @($rd.Json.items | Where-Object { $_ }).Count -ne 0) { $t47aBad += "demo host #$hi full address total=$($rd.Json.total) (expected 0)" }
        $t47aLines += "host #$hi (range $range): $trialUser total=$($rt.Json.total) SQL=$exp; demo with the full address total=$($rd.Json.total)"
    }
    foreach ($ln in $bandTop47) {
        $bp = $ln -split '\|'
        $exp = [long]$bp[1]
        $totals = @()
        foreach ($who in $t47Pairs) {
            $r = & $get47 "/api/incidents/queue?period=all&size=25&hostIp=$($bp[0])" $who "queue hostIp=$($bp[0])"
            $totals += "$($who.Name)=$($r.Json.total)"
            if ([long]$r.Json.total -ne $exp -or [long]$r.Json.summary.total -ne $exp) { $t47aBad += "$($who.Name) range $($bp[0]) total=$($r.Json.total) expected=$exp" }
            if ($who.Masked -and @($r.Json.items | Where-Object { $_ -and $_.hostIp -ne $bp[0] }).Count) { $t47aBad += "demo range $($bp[0]) has rows of another range" }
        }
        $t47aLines += "range $($bp[0]): $($totals -join ' ') SQL=$exp"
    }
    $bad47 = & $get40 "/api/incidents/queue?period=all&hostIp=10.0.0" $t47d
    $t47aLines += "demo hostIp=10.0.0 (format error) -> HTTP $($bad47.Status)"
    $e2eLogs.Add("[T47a] queue hostIp (top $($hostTop47.Count) hosts, top $($bandTop47.Count) ranges):`n       $($t47aLines -join "`n       ")`n       mismatches=$($t47aBad.Count)$(if ($t47aBad.Count) { ' ' + ($t47aBad -join '; ') })")
    Assert-True ($hostTop47.Count -ge 1 -and $bandTop47.Count -ge 1 -and $t47aBad.Count -eq 0) "[T47a] 큐 hostIp 건수 = 독립 SQL(demo·$trialUser), 조회자의 온전한 주소는 0건"
    Assert-ApiError $bad47 400 "INVALID_REQUEST" "[T47a] hostIp 형식 오류"

    # [T47b] 큐 attack: 기법 ID·전술 건수 = 독립 SQL(JSON 후보를 jsonb 함수로 직접 센다. 앱 규칙 service/AttackFilter.java와 같은 방법:
    #        최신 큐 행이 가리키는 리포트의 후보만, attack_id는 앞뒤 공백을 떼고 대문자, 전술은 소문자 + [\s_]+ → '-' 뒤 슬러그 꼴·길이 2~64, 기법 ID 꼴 전술은 세지 않음)
    $attackSql47 = @'
WITH base AS (SELECT l.incident_id, l.zeekad_report_job_id FROM dashboard.latest_incident_queue l WHERE @CAP),
lq AS (SELECT DISTINCT b.incident_id, r.zeekad_attack_candidates::jsonb AS c
       FROM base b
       JOIN dashboard.incident_reports r ON r.job_id = b.zeekad_report_job_id AND r.incident_id = b.incident_id
       WHERE jsonb_typeof(r.zeekad_attack_candidates::jsonb) = 'array'),
el AS (SELECT lq.incident_id, e FROM lq CROSS JOIN LATERAL jsonb_array_elements(lq.c) e WHERE jsonb_typeof(e) = 'object'),
tech AS (SELECT DISTINCT incident_id, upper(btrim(e ->> 'attack_id', E' \t\n\r')) AS v FROM el
         WHERE jsonb_typeof(e -> 'attack_id') IN ('string', 'number', 'boolean')
           AND btrim(e ->> 'attack_id', E' \t\n\r') ~ '^[Tt][0-9]{4}(\.[0-9]{3})?$'),
tt AS (SELECT el.incident_id, x #>> '{}' AS t FROM el
       CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(el.e -> 'tactics') = 'array' THEN el.e -> 'tactics'
                                                    WHEN jsonb_typeof(el.e -> 'tactics') IN ('string', 'number', 'boolean') THEN jsonb_build_array(el.e -> 'tactics')
                                                    ELSE '[]'::jsonb END) x
       WHERE jsonb_typeof(x) IN ('string', 'number', 'boolean')),
ts AS (SELECT incident_id, regexp_replace(lower(btrim(t, E' \t\n\r')), '[\s_]+', '-', 'g') AS v FROM tt),
tac AS (SELECT DISTINCT incident_id, v FROM ts
        WHERE v ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND length(v) BETWEEN 2 AND 64 AND v !~ '^t[0-9]{4}(\.[0-9]{3})?$'),
vals AS (SELECT 'technique' AS k, incident_id, v FROM tech UNION ALL SELECT 'tactic', incident_id, v FROM tac)
SELECT vals.k || '|' || vals.v || '|' || count(*) FROM vals JOIN base b ON b.incident_id = vals.incident_id GROUP BY vals.k, vals.v
UNION ALL
SELECT 'any|-|' || count(*) FROM base b WHERE b.incident_id IN (SELECT incident_id FROM vals)
ORDER BY 1
'@
    $att47 = @{ technique = @{}; tactic = @{}; any = [long]0 }
    foreach ($ln in @(& $lines47 (& $sql47 $attackSql47.Replace('@CAP', $pub47) "ATT&CK 후보 분포"))) {
        $ap = $ln -split '\|'
        if ($ap[0] -eq 'any') { $att47.any = [long]$ap[2] } else { $att47[$ap[0]][$ap[1]] = [long]$ap[2] }
    }
    $techTop47 = @($att47.technique.GetEnumerator() | Sort-Object @{ Expression = { $_.Value }; Descending = $true }, @{ Expression = { $_.Key } } | Select-Object -First 3)
    $tacTop47 = @($att47.tactic.GetEnumerator() | Sort-Object @{ Expression = { $_.Value }; Descending = $true }, @{ Expression = { $_.Key } } | Select-Object -First 3)
    $t47bBad = @(); $t47bLines = @()
    if ($att47.technique.Count -eq 0 -and $att47.tactic.Count -eq 0) {
        $t47NoData.Add("[T47b] 공개 캡처 최신 큐의 리포트에 ATT&CK 후보가 없음")
    } else {
        foreach ($entry in ($techTop47 + $tacTop47)) {
            $totals = @()
            foreach ($who in $t47Pairs) {
                $r = & $get47 "/api/incidents/queue?period=all&size=25&attack=$($entry.Key)" $who "queue attack=$($entry.Key)"
                $totals += "$($who.Name)=$($r.Json.total)"
                if ([long]$r.Json.total -ne [long]$entry.Value) { $t47bBad += "$($who.Name) attack=$($entry.Key) total=$($r.Json.total) expected=$($entry.Value)" }
            }
            $t47bLines += "attack=$($entry.Key): $($totals -join ' ') SQL=$($entry.Value)"
        }
        if ($tacTop47.Count) {
            $slug47 = [string]$tacTop47[0].Key
            $title47 = (@($slug47 -split '-' | ForEach-Object { $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1) }) -join '%20')
            $r = & $get47 "/api/incidents/queue?period=all&size=25&attack=$title47" $t47Pairs[0] "queue attack=$title47"
            if ([long]$r.Json.total -ne [long]$tacTop47[0].Value) { $t47bBad += "demo attack=$title47 total=$($r.Json.total) expected=$($tacTop47[0].Value)" }
            $t47bLines += "attack=$title47 (title form of $slug47): demo=$($r.Json.total) SQL=$($tacTop47[0].Value)"
        }
    }
    $badAttack47 = & $get40 "/api/incidents/queue?period=all&attack=bad.value" $t47d
    $e2eLogs.Add("[T47b] ATT&CK candidates in public latest queue (independent SQL, jsonb): techniques=$($att47.technique.Count) tactics=$($att47.tactic.Count) rows with candidates=$($att47.any)`n       $($t47bLines -join "`n       ")`n       demo attack=bad.value (format error) -> HTTP $($badAttack47.Status); mismatches=$($t47bBad.Count)$(if ($t47bBad.Count) { ' ' + ($t47bBad -join '; ') })")
    Assert-True ($t47bBad.Count -eq 0) "[T47b] 큐 attack 건수 = 독립 SQL(demo·$trialUser)"
    Assert-ApiError $badAttack47 400 "INVALID_REQUEST" "[T47b] attack 형식 오류"

    # [T47c] 큐 행 묶음 표지: 표지가 있는 행을 골라(묶음 5개까지) threadMemberCount = 큐 period=all&thread=<threadHeadNo> total = 독립 SQL([T40]의 $exp40).
    #        머리는 sha256(incident_id)로만 맞춘다. 표지 번호의 캡처는 모두 공개 캡처다
    $noToHash47 = @{}
    foreach ($hk in $refs40.Keys) { $noToHash47[[long]$refs40[$hk].No] = $hk }
    $t47cBad = @(); $t47cLines = @()
    foreach ($who in $t47Pairs) {
        $badged = [System.Collections.Generic.List[object]]::new()
        $scanned = 0
        for ($pg = 1; $pg -le 5; $pg++) {
            $q = & $get47 "/api/incidents/queue?period=all&size=100&page=$pg" $who "queue period=all page=$pg"
            foreach ($it in @($q.Json.items | Where-Object { $_ })) { $scanned++; if ($null -ne $it.threadHeadNo) { $badged.Add($it) } }
            if (@($badged | ForEach-Object { [long]$_.threadHeadNo } | Sort-Object -Unique).Count -ge 5 -or $pg -ge [int]$q.Json.pageCount) { break }
        }
        $nos = @($badged | ForEach-Object { [long]$_.threadHeadNo } | Sort-Object -Unique | Select-Object -First 5)
        if ($nos.Count -eq 0) { $t47NoData.Add("[T47c] $($who.Name) 큐 앞 $scanned행에 묶음 표지가 붙는 행이 없음"); continue }
        foreach ($no in $nos) {
            $hk = $noToHash47[$no]
            $e = if ($hk) { $exp40[$hk] } else { $null }
            $ref = if ($hk) { $refs40[$hk] } else { $null }
            $th = & $get47 "/api/incidents/queue?period=all&size=25&thread=$no" $who "queue thread=$no"
            $rowCounts = @($badged | Where-Object { [long]$_.threadHeadNo -eq $no } | ForEach-Object { [long]$_.threadMemberCount } | Sort-Object -Unique)
            $expN = if ($e) { [long]$e.Public } else { -1 }
            if ($rowCounts.Count -ne 1 -or $rowCounts[0] -ne $expN -or [long]$th.Json.total -ne $expN -or $expN -lt 2) { $t47cBad += "$($who.Name) #$no rows=[$($rowCounts -join ',')] thread total=$($th.Json.total) expected=$expN" }
            if ($null -eq $ref -or -not ($demoVisibleCaptures -contains $ref.Capture)) { $t47cBad += "$($who.Name) #$no head capture is not public" }
            $t47cLines += "$($who.Name) #${no}: row threadMemberCount=[$($rowCounts -join ',')] queue thread total=$($th.Json.total) SQL=$expN"
        }
        $t47cLines += "$($who.Name): scanned rows=$scanned with badge=$($badged.Count) heads checked=$($nos.Count)"
    }
    $e2eLogs.Add("[T47c] queue row thread badges:`n       $($t47cLines -join "`n       ")`n       mismatches=$($t47cBad.Count)$(if ($t47cBad.Count) { ' ' + ($t47cBad -join '; ') })")
    Assert-True ($t47cBad.Count -eq 0) "[T47c] 묶음 표지 threadMemberCount = thread total = 독립 SQL"

    # [T47d] GET /api/hosts(period=all): 줄 수 = 독립 SQL(분석가는 고유 host_ip, 조회자는 고유 가린 주소), 줄들의 incidents 합 = 큐 summary.total = 최신 큐 행 수,
    #        상위 3줄 incidents = 큐 hostIp= total, 전환 표시 수 = 독립 SQL(조회자는 0, 전환만 보기는 빈 목록), 조회자 accounts[] 원소에 계정 원문 없음(원소 값으로 견준다)
    # 계정 이름 열은 뷰에 있는 것만 읽는다(앱도 SELECT *로 읽어 있는 열만 쓴다: zeekad_name, 없으면 kerberos_user·ntlm_user). 값이 배열이어도 원소로 편다
    $nameCols47 = @(& $lines47 (& $sql47 "SELECT column_name FROM information_schema.columns WHERE table_schema = 'dashboard' AND table_name = 'asset_names' AND column_name IN ('zeekad_name', 'kerberos_user', 'ntlm_user') ORDER BY 1" "asset_names 열"))
    $hasName47 = [int]($nameCols47 -contains 'zeekad_name')
    $rawNames47 = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if ($nameCols47.Count -gt 0) {
        $nameParts47 = @($nameCols47 | ForEach-Object { "SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(to_jsonb(a.$_)) = 'array' THEN to_jsonb(a.$_) WHEN a.$_ IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(to_jsonb(a.$_)) END) AS v FROM dashboard.asset_names a WHERE a.capture_id IN ($publicIn39)" })
        $rawNameSql47 = "SELECT DISTINCT btrim(s.v) FROM (" + ($nameParts47 -join " UNION ALL ") + ") s WHERE s.v IS NOT NULL AND btrim(s.v) <> ''"
        foreach ($ln in @((& $sql47 $rawNameSql47 "계정 원문") -split "`r?`n")) { $n = $ln.Trim(); if ($n) { [void]$rawNames47.Add($n) } }
    }
    $dismissed47 = "NOT (lower(btrim(@A.zeekad_status)) = 'closed' AND lower(btrim(COALESCE(@A.zeekad_resolution, ''))) IN ('false_positive', 'benign'))"
    $transCount47 = [long](& $sql47 ("SELECT count(DISTINCT l.host_ip) FROM $lq47 JOIN dashboard.latest_incident_queue o ON o.capture_id = l.capture_id AND o.host_ip = l.host_ip " +
        "WHERE $pub47 AND lower(btrim(l.zeekad_role)) = 'responder' AND lower(btrim(o.zeekad_role)) = 'originator' AND o.event_start > l.event_start " +
        "AND $($dismissed47.Replace('@A', 'l')) AND $($dismissed47.Replace('@A', 'o'))") "전환 호스트 수")
    $t47dBad = @(); $t47dLines = @()
    foreach ($who in $t47Pairs) {
        $items = [System.Collections.Generic.List[object]]::new()
        $first = & $get47 "/api/hosts?period=all&size=100&page=1" $who "hosts period=all page=1"
        $pages = [int]$first.Json.pageCount
        for ($pg = 1; $pg -le $pages; $pg++) {
            $res = if ($pg -eq 1) { $first } else { & $get47 "/api/hosts?period=all&size=100&page=$pg" $who "hosts period=all page=$pg" }
            foreach ($it in @($res.Json.items | Where-Object { $_ })) { $items.Add($it) }
        }
        $sum = 0; foreach ($it in $items) { $sum += [long]$it.incidents }
        $qAll = & $get47 "/api/incidents/queue?period=all&size=25" $who "queue period=all"
        $expRows = if ($who.Masked) { $bands47 } else { $hosts47 }
        if ($items.Count -ne $expRows -or [long]$first.Json.total -ne $expRows) { $t47dBad += "$($who.Name) rows=$($items.Count) total=$($first.Json.total) expected=$expRows" }
        if ($sum -ne [long]$qAll.Json.summary.total -or $sum -ne $rows47) { $t47dBad += "$($who.Name) sum(incidents)=$sum queue summary.total=$($qAll.Json.summary.total) SQL rows=$rows47" }
        if ($first.Json.maskedView -ne $who.Masked) { $t47dBad += "$($who.Name) maskedView=$($first.Json.maskedView)" }
        $topChecked = 0
        foreach ($it in @($items | Where-Object { [string]$_.hostIp -match '^\d{1,3}\.\d{1,3}\.(\*\.\*|\d{1,3}\.\d{1,3})$' } | Select-Object -First 3)) {
            $topChecked++
            $qh = & $get47 "/api/incidents/queue?period=all&size=25&hostIp=$($it.hostIp)" $who "queue hostIp=<hosts row #$topChecked>"
            if ([long]$qh.Json.total -ne [long]$it.incidents) { $t47dBad += "$($who.Name) hosts row #$topChecked incidents=$($it.incidents) queue hostIp total=$($qh.Json.total)" }
        }
        $transRows = @($items | Where-Object { $_.roleTransition -eq $true }).Count
        $only = & $get47 "/api/hosts?period=all&size=25&roleTransitionOnly=true" $who "hosts roleTransitionOnly"
        if ($who.Masked) {
            $notBand = @($items | Where-Object { [string]$_.hostIp -notmatch $bandRe47 }).Count
            $accounts = @($items | ForEach-Object { $_.accounts } | Where-Object { $null -ne $_ })
            $rawHits = @($accounts | Where-Object { $rawNames47.Contains([string]$_) }).Count
            $notMasked = @($accounts | Where-Object { [string]$_ -notmatch '^(.\*\*\*|\*\*\*)$' }).Count
            if ($notBand -ne $nonV4Hosts47) { $t47dBad += "demo rows not shaped A.B.*.*=$notBand (non-IPv4 host values in SQL=$nonV4Hosts47)" }
            if ($rawHits -ne 0 -or $notMasked -ne 0) { $t47dBad += "demo accounts[] elements equal to a raw account name=$rawHits, not shaped as first letter + ***=$notMasked" }
            if ($transRows -ne 0 -or [long]$only.Json.total -ne 0 -or @($only.Json.items | Where-Object { $_ }).Count -ne 0) { $t47dBad += "demo roleTransition rows=$transRows roleTransitionOnly total=$($only.Json.total)" }
            $t47dLines += "demo: rows=$($items.Count) (SQL distinct masked=$bands47) pages=$pages sum(incidents)=$sum queue summary.total=$($qAll.Json.summary.total) top rows checked against queue hostIp=$topChecked; rows not shaped A.B.*.*=$notBand; accounts[] elements=$($accounts.Count) equal to a raw name ($($rawNames47.Count) raw values from asset_names columns [$($nameCols47 -join ', ')])=$rawHits not first letter + ***=$notMasked; roleTransition rows=$transRows roleTransitionOnly total=$($only.Json.total)"
        } else {
            if ($transRows -ne $transCount47 -or [long]$only.Json.total -ne $transCount47) { $t47dBad += "$($who.Name) roleTransition rows=$transRows roleTransitionOnly total=$($only.Json.total) SQL=$transCount47" }
            $t47dLines += "$($who.Name): rows=$($items.Count) (SQL distinct host_ip=$hosts47) pages=$pages sum(incidents)=$sum queue summary.total=$($qAll.Json.summary.total) top rows checked against queue hostIp=$topChecked; roleTransition rows=$transRows roleTransitionOnly total=$($only.Json.total) (SQL $transCount47)"
        }
    }
    $e2eLogs.Add("[T47d] /api/hosts period=all:`n       $($t47dLines -join "`n       ")`n       mismatches=$($t47dBad.Count)$(if ($t47dBad.Count) { ' ' + ($t47dBad -join '; ') })")
    Assert-True ($t47dBad.Count -eq 0) "[T47d] /api/hosts 줄 수·합·줄 건수·전환 표시 = 큐·독립 SQL, 조회자 계정 원문 없음"
    if ($transCount47 -eq 0) { $t47NoData.Add("[T47d] 공개 캡처 최신 큐에 전환 표시가 붙는 호스트가 없음(독립 SQL 0)") }

    # [T47e] 같은 호스트 인시던트 API: 자기 자신 없음, total = 독립 SQL(분석가는 같은 주소, 조회자는 같은 대역), 숨김 캡처 인시던트는 403(두 계정)
    $rel47Targets = @(& $lines47 (& $sql47 ("(SELECT l.job_id || '/' || l.queue_rank FROM $lq47 WHERE $pub47 AND l.host_ip = (SELECT l2.host_ip FROM dashboard.latest_incident_queue l2 WHERE l2.capture_id IN ($publicIn39) GROUP BY l2.host_ip ORDER BY count(*) DESC, l2.host_ip LIMIT 1) ORDER BY l.capture_id, l.queue_rank LIMIT 1) " +
        "UNION (SELECT l.job_id || '/' || l.queue_rank FROM $lq47 WHERE l.capture_id = '$exposureLabCapture' ORDER BY l.queue_rank LIMIT 1) " +
        "UNION (SELECT l.job_id || '/' || l.queue_rank FROM $lq47 WHERE $pub47 AND l.capture_id LIKE 'cic17-%' ORDER BY l.capture_id, l.queue_rank LIMIT 1)") "같은 호스트 대상") | Where-Object { $_ -match '^\d+/\d+$' })
    $t47eBad = @(); $t47eLines = @()
    foreach ($row in $rel47Targets) {
        $j47, $r47 = $row -split '/'
        $selfCte = "WITH s AS (SELECT q.incident_id, q.host_ip FROM dashboard.latest_incident_queue q WHERE q.job_id = $j47 AND q.queue_rank = $r47 LIMIT 1) "
        $expRel = (& $sql47 ($selfCte + "SELECT (SELECT count(*) FROM $lq47, s WHERE $pub47 AND l.host_ip = s.host_ip AND l.incident_id <> s.incident_id) || '|' || " +
            "(SELECT count(*) FROM $lq47, s WHERE $pub47 AND $mask47 = (SELECT $($mask47.Replace('l.host_ip', 's.host_ip'))) AND l.incident_id <> s.incident_id)") "같은 호스트 건수") -split '\|'
        foreach ($who in $t47Pairs) {
            $rr = & $get47 "/api/incidents/$j47/rank/$r47/related-host-incidents" $who "related-host $row"
            $relItems = @($rr.Json.items | Where-Object { $_ })
            $expN = if ($who.Masked) { [long]$expRel[1] } else { [long]$expRel[0] }
            $self = @($relItems | Where-Object { "$($_.jobId)" -eq "$j47" -and "$($_.queueRank)" -eq "$r47" }).Count
            $shape = if ($who.Masked) { [string]$rr.Json.hostIp -match $bandRe47 -or [string]$rr.Json.hostIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$' } else { $true }
            if ([long]$rr.Json.total -ne $expN -or $relItems.Count -ne [Math]::Min($expN, 10) -or $self -ne 0 -or -not $shape -or $rr.Json.maskedView -ne $who.Masked) { $t47eBad += "$($who.Name) $row total=$($rr.Json.total) items=$($relItems.Count) self=$self expected=$expN" }
            $t47eLines += "$($who.Name) ${row}: total=$($rr.Json.total) items=$($relItems.Count) self=$self SQL=$expN"
        }
    }
    $hiddenRow47 = if ($hiddenIn39) { (& $sql47 "SELECT l.job_id || '/' || l.queue_rank FROM $lq47 WHERE l.capture_id IN ($hiddenIn39) ORDER BY l.job_id, l.queue_rank LIMIT 1" "숨김 캡처 인시던트") } else { "" }
    if ($hiddenRow47 -match '^\d+/\d+$') {
        $hj47, $hr47 = $hiddenRow47 -split '/'
        foreach ($who in $t47Pairs) {
            $deny = & $get40 "/api/incidents/$hj47/rank/$hr47/related-host-incidents" $who.Client
            if ($deny.Status -ne 403) { $t47eBad += "$($who.Name) hidden capture incident -> HTTP $($deny.Status)" }
            $t47eLines += "$($who.Name) hidden capture incident -> HTTP $($deny.Status)"
        }
    } else { $t47NoData.Add("[T47e] 숨김 캡처의 최신 큐 인시던트가 없어 403 확인을 건너뜀") }
    $e2eLogs.Add("[T47e] related-host-incidents (targets=[$($rel47Targets -join ', ')]):`n       $($t47eLines -join "`n       ")`n       mismatches=$($t47eBad.Count)$(if ($t47eBad.Count) { ' ' + ($t47eBad -join '; ') })")
    Assert-True ($rel47Targets.Count -ge 1 -and $t47eBad.Count -eq 0) "[T47e] 같은 호스트 인시던트 total = 독립 SQL, 자기 자신 없음, 숨김 캡처 403"

    # [T47f] overview 새 집계(period=all·24h): attack 전술·기법 count = 같은 조건 큐 attack= total, topHosts 줄 total = 큐 role=+hostIp= total,
    #        topThreads 줄 totalMemberCount = 큐 period=all&thread= total, periodIncidentCount = 같은 조건 큐 thread= total. 기간 전체의 분포 = [T47b] 독립 SQL
    $t47fBad = @(); $t47fLines = @()
    foreach ($who in $t47Pairs) {
        foreach ($cond in @('period=all', 'period=24h')) {
            $ov = & $get47 "/api/dashboard/overview?$cond" $who "overview $cond"
            $tactics = @($ov.Json.attack.tactics | Where-Object { $_ })
            $techniques = @($ov.Json.attack.techniques | Where-Object { $_ })
            $before = $t47fBad.Count
            foreach ($tc in $tactics) {
                $qt = [long](& $get47 "/api/incidents/queue?$cond&size=25&attack=$($tc.tactic)" $who "queue $cond attack=$($tc.tactic)").Json.total
                if ($qt -ne [long]$tc.count) { $t47fBad += "$($who.Name) $cond tactic $($tc.tactic) overview=$($tc.count) queue=$qt" }
            }
            foreach ($tq in $techniques) {
                $qt = [long](& $get47 "/api/incidents/queue?$cond&size=25&attack=$($tq.attackId)" $who "queue $cond attack=$($tq.attackId)").Json.total
                if ($qt -ne [long]$tq.count) { $t47fBad += "$($who.Name) $cond technique $($tq.attackId) overview=$($tq.count) queue=$qt" }
            }
            $hostRows = 0; $hostSkipped = 0
            foreach ($dir in @('originator', 'responder')) {
                foreach ($hr in @($ov.Json.topHosts.$dir | Where-Object { $_ })) {
                    # IPv4(온전하거나 가린 꼴)가 아닌 호스트 값은 큐 hostIp 조건으로 갈 수 없다(형식 오류 400). 수만 센다
                    if ([string]$hr.hostIp -notmatch '^\d{1,3}\.\d{1,3}\.(\*\.\*|\d{1,3}\.\d{1,3})$') { $hostSkipped++; continue }
                    $hostRows++
                    $qt = [long](& $get47 "/api/incidents/queue?$cond&size=25&role=$dir&hostIp=$($hr.hostIp)" $who "queue $cond role=$dir hostIp=<topHosts row #$hostRows>").Json.total
                    if ($qt -ne [long]$hr.total) { $t47fBad += "$($who.Name) $cond topHosts.$dir row #$hostRows overview=$($hr.total) queue=$qt" }
                }
            }
            $threads = @($ov.Json.topThreads | Where-Object { $_ })
            foreach ($tr in $threads) {
                $qAllT = [long](& $get47 "/api/incidents/queue?period=all&size=25&thread=$($tr.headIncidentNo)" $who "queue period=all thread=$($tr.headIncidentNo)").Json.total
                $qCondT = [long](& $get47 "/api/incidents/queue?$cond&size=25&thread=$($tr.headIncidentNo)" $who "queue $cond thread=$($tr.headIncidentNo)").Json.total
                if ($qAllT -ne [long]$tr.totalMemberCount) { $t47fBad += "$($who.Name) $cond topThreads #$($tr.headIncidentNo) totalMemberCount=$($tr.totalMemberCount) queue(period=all)=$qAllT" }
                if ($qCondT -ne [long]$tr.periodIncidentCount) { $t47fBad += "$($who.Name) $cond topThreads #$($tr.headIncidentNo) periodIncidentCount=$($tr.periodIncidentCount) queue=$qCondT" }
            }
            if ($cond -eq 'period=all') {
                foreach ($tc in $tactics) { if ([long]$att47.tactic[[string]$tc.tactic] -ne [long]$tc.count) { $t47fBad += "$($who.Name) tactic $($tc.tactic) overview=$($tc.count) sql=$($att47.tactic[[string]$tc.tactic])" } }
                foreach ($tq in $techniques) { if ([long]$att47.technique[[string]$tq.attackId] -ne [long]$tq.count) { $t47fBad += "$($who.Name) technique $($tq.attackId) overview=$($tq.count) sql=$($att47.technique[[string]$tq.attackId])" } }
                if ($tactics.Count -ne $att47.tactic.Count -or [int]$ov.Json.attack.techniqueCount -ne $att47.technique.Count -or $techniques.Count -ne [Math]::Min($att47.technique.Count, 10) -or [long]$ov.Json.attack.incidentsWithCandidates -ne [long]$att47.any) {
                    $t47fBad += "$($who.Name) attack totals overview(tactics=$($tactics.Count) techniqueCount=$($ov.Json.attack.techniqueCount) rows=$($techniques.Count) incidentsWithCandidates=$($ov.Json.attack.incidentsWithCandidates)) sql(tactics=$($att47.tactic.Count) techniques=$($att47.technique.Count) any=$($att47.any))"
                }
            }
            if ($ov.Json.topThreadsOmitted -ne $false) { $t47fBad += "$($who.Name) $cond topThreadsOmitted=$($ov.Json.topThreadsOmitted)" }
            $t47fLines += "$($who.Name) ${cond}: incidentsWithCandidates=$($ov.Json.attack.incidentsWithCandidates) tactics=[$(@($tactics | ForEach-Object { "$($_.tactic)=$($_.count)" }) -join ', ')] techniques(top $($techniques.Count) of $($ov.Json.attack.techniqueCount))=[$(@($techniques | ForEach-Object { "$($_.attackId)=$($_.count)" }) -join ', ')] topHosts rows checked=$hostRows (non-IPv4 skipped=$hostSkipped) topThreads=[$(@($threads | ForEach-Object { "#$($_.headIncidentNo) period=$($_.periodIncidentCount) total=$($_.totalMemberCount)" }) -join ', ')] new mismatches=$($t47fBad.Count - $before)"
        }
    }
    $e2eLogs.Add("[T47f] overview new aggregates vs queue totals:`n       $($t47fLines -join "`n       ")`n       mismatches=$($t47fBad.Count)$(if ($t47fBad.Count) { ' ' + (($t47fBad | Select-Object -First 15) -join '; ') })")
    Assert-True ($t47fBad.Count -eq 0) "[T47f] overview 새 집계 = 같은 조건 큐 total·독립 SQL"

    # [T47g] 조회자 상세의 zeekad_name: 스냅샷에서 zeekad_name이 있는 자산의 인시던트를 독립 SQL로 골라 조회자는 첫 글자 + ***, 분석가는 원문인지 본다(값은 적지 않는다)
    if (-not $hasName47) {
        $t47NoData.Add("[T47g] 스냅샷의 dashboard.asset_names에 zeekad_name 열이 없음")
        $e2eLogs.Add("[T47g] dashboard.asset_names has no zeekad_name column in this snapshot (no data)")
    } else {
        $nameRows47 = @(& $lines47 (& $sql47 "SELECT DISTINCT l.job_id || '/' || l.queue_rank FROM $lq47 JOIN dashboard.asset_names a ON a.capture_id = l.capture_id AND a.host_ip = l.host_ip WHERE $pub47 AND a.zeekad_name IS NOT NULL AND btrim(a.zeekad_name::text) NOT IN ('', '{}', '[]') ORDER BY 1 LIMIT 3" "zeekad_name이 있는 인시던트") | Where-Object { $_ -match '^\d+/\d+$' })
        if ($nameRows47.Count -eq 0) {
            $t47NoData.Add("[T47g] 공개 캡처 최신 큐의 호스트 가운데 zeekad_name이 있는 자산이 없음")
            $e2eLogs.Add("[T47g] no public latest-queue host has an asset row with zeekad_name (no data)")
        } else {
            $t47gBad = @(); $t47gLines = @()
            $flat47 = { param($Detail) return @($Detail.Json.detail.assetNames | Where-Object { $_ } | ForEach-Object { $_.extraAttributes.zeekad_name } | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).Trim() }) }
            foreach ($row in $nameRows47) {
                $nj, $nr = $row -split '/'
                $rawOf = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                $rawSql = "SELECT DISTINCT btrim(x.n) FROM (SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(to_jsonb(a.zeekad_name)) = 'array' THEN to_jsonb(a.zeekad_name) ELSE jsonb_build_array(to_jsonb(a.zeekad_name)) END) AS n FROM dashboard.asset_names a JOIN dashboard.latest_incident_queue q ON q.capture_id = a.capture_id AND q.host_ip = a.host_ip WHERE q.job_id = $nj AND q.queue_rank = $nr AND a.zeekad_name IS NOT NULL) x WHERE x.n IS NOT NULL AND btrim(x.n) <> ''"
                foreach ($ln in @((& $sql47 $rawSql "zeekad_name 원문") -split "`r?`n")) { $n = $ln.Trim(); if ($n) { [void]$rawOf.Add($n) } }
                $dv = @(& $flat47 (& $get47 "/api/incidents/$nj/rank/$nr" $t47Pairs[0] "detail $row"))
                $tv = @(& $flat47 (& $get47 "/api/incidents/$nj/rank/$nr" $t47Pairs[1] "detail $row"))
                $dRaw = @($dv | Where-Object { $rawOf.Contains($_) }).Count
                $dShape = @($dv | Where-Object { $_ -notmatch '^(.\*\*\*|\*\*\*)$' }).Count
                $tMissing = @($rawOf | Where-Object { $tv -cnotcontains $_ }).Count
                if ($dv.Count -eq 0 -or $dRaw -ne 0 -or $dShape -ne 0) { $t47gBad += "demo $row zeekad_name values=$($dv.Count) equal to raw=$dRaw not first letter + ***=$dShape" }
                if ($tMissing -ne 0) { $t47gBad += "$trialUser $row raw zeekad_name values missing from response=$tMissing" }
                $t47gLines += "${row}: raw zeekad_name values (SQL)=$($rawOf.Count); demo values=$($dv.Count) equal to raw=$dRaw not first letter + ***=$dShape; $trialUser values=$($tv.Count) raw values missing=$tMissing"
            }
            $e2eLogs.Add("[T47g] detail assetNames[].extraAttributes.zeekad_name (incidents=[$($nameRows47 -join ', ')], values not logged):`n       $($t47gLines -join "`n       ")`n       mismatches=$($t47gBad.Count)$(if ($t47gBad.Count) { ' ' + ($t47gBad -join '; ') })")
            Assert-True ($t47gBad.Count -eq 0) "[T47g] 조회자 상세의 zeekad_name은 첫 글자 + ***, 분석가는 원문"
        }
    }

    # [T47h] 새 요청 전체: demo 응답에 가려지지 않은 IPv4 0, 두 계정 응답에 숨김 캡처 ID 0
    $e2eLogs.Add("[T47h] demo unmasked IPv4 JSON paths=$($t47Ip.Count)$(if ($t47Ip.Count) { ' ' + (($t47Ip | Select-Object -First 10) -join ', ') }); hidden capture traces=$($t47Leaks.Count)$(if ($t47Leaks.Count) { ' ' + (($t47Leaks | Select-Object -First 10) -join ', ') }); no-data notes=$($t47NoData.Count)$(if ($t47NoData.Count) { ' ' + ($t47NoData -join ' / ') })")
    Assert-True ($t47Ip.Count -eq 0) "[T47h] demo 가려지지 않은 IPv4 0"
    Assert-True ($t47Leaks.Count -eq 0) "[T47h] demo·$trialUser 응답에 숨김 캡처 ID 0"

    # [T47j] 응답 시간 기록(데우기 1번 + 3번, curl 포함): 새 엔드포인트와 그 읽기가 더해진 현황판·운영 현황. 한도는 여기서 정하지 않는다(단언하지 않고 적는다)
    $timing47 = [System.Collections.Generic.List[string]]::new()
    $timing47.Add("# T47 rehearsal timing (local Docker stack + real snapshot; includes curl). head=$((Invoke-NativeCapture 'git' @('rev-parse', 'HEAD') -IgnoreExitCode).Output.Trim())")
    $relPath47 = if ($rel47Targets.Count) { "/api/incidents/$(($rel47Targets[0] -split '/')[0])/rank/$(($rel47Targets[0] -split '/')[1])/related-host-incidents" } else { $null }
    foreach ($who in $t47Pairs) {
        foreach ($pth in @("/api/hosts?period=all", $relPath47, "/api/dashboard/overview?period=all", "/api/dashboard/overview?period=24h", "/api/operations") | Where-Object { $_ }) {
            $warm = & $get40 $pth $who.Client
            Assert-Status $warm 200 "[T47j] $($who.Name) $pth (데우기)"
            $ms = @()
            for ($n = 0; $n -lt 3; $n++) {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $r = Invoke-Http -Path $pth -Client $who.Client
                $sw.Stop()
                Assert-Status $r 200 "[T47j] $($who.Name) $pth"
                $ms += [int]$sw.ElapsedMilliseconds
            }
            $timing47.Add("T47TIMING new-image account=$($who.Name) path=$pth ms=[$($ms -join ', ')] median=$(($ms | Sort-Object)[1]) max=$(($ms | Measure-Object -Maximum).Maximum)")
        }
    }
    $e2eLogs.Add("[T47j] response times (warm 1 + 3 samples, includes curl; recorded, not asserted):`n       $(@($timing47 | Select-Object -Skip 1) -join "`n       ")")

    # [T47k] 큐 전체 기간 목록(/api/incidents/queue?period=all&size=50)의 중앙값을 지금 공개 중인 이미지와 새 이미지로 같은 스택에서 잰다([T27g]의 옛 이미지 방식).
    #        두 쪽 모두 앱을 새로 띄운 뒤 demo로 데우기 3번 + 5번. 새 값이 옛 값의 1.5배를 넘으면 실패다(NAS 반영 전에 멈춘다).
    $queuePath47 = "/api/incidents/queue?period=all&size=50"
    $measure47 = {
        param([string]$Ip, [string]$Label)
        $c = New-Client $Ip
        Assert-Status (Login-Api $c "demo" $env:DEMO_PASSWORD) 200 "[T47k] demo 로그인($Label)"
        for ($w = 0; $w -lt 3; $w++) { Assert-Status (Invoke-Http -Path $queuePath47 -Client $c) 200 "[T47k] $Label 데우기" }
        $ms = @(); $total = $null
        for ($n = 0; $n -lt 5; $n++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-Http -Path $queuePath47 -Client $c
            $sw.Stop()
            Assert-Status $r 200 "[T47k] $Label"
            $ms += [int]$sw.ElapsedMilliseconds
            $total = $r.Json.total
        }
        return [pscustomobject]@{ Ms = $ms; Median = [int](($ms | Sort-Object)[2]); Max = [int](($ms | Measure-Object -Maximum).Maximum); Total = $total }
    }
    $appImageOf = { (Invoke-NativeCapture "docker" @("inspect", "--format", "{{.Image}}", (Get-ServiceContainer "dashboard-app"))).Output.Trim() }
    $swapApp47 = {
        $up = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "dashboard-app")) -IgnoreExitCode
        [void](Invoke-NativeCapture "docker" ($composeArgs + @("restart", "nginx-waf")) -IgnoreExitCode)
        [void](Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "nginx-waf")) -IgnoreExitCode)
        return $up.ExitCode
    }
    $newId47 = (Invoke-NativeCapture "docker" @("image", "inspect", "--format", "{{.Id}}", "zeek-ad-dashboard-app:local")).Output.Trim()
    $baseInspect47 = Invoke-NativeCapture "docker" @("image", "inspect", "--format", "{{.Id}}", $BaselineAppImage) -IgnoreExitCode
    $baseId47 = if ($baseInspect47.ExitCode -eq 0) { $baseInspect47.Output.Trim() } else { "" }
    $old47 = $null
    if (-not $baseId47) {
        $timing47.Add("T47QUEUE old-image=$BaselineAppImage not found locally; only the new image is measured")
    } elseif ($baseId47 -eq $newId47) {
        $timing47.Add("T47QUEUE old-image=$BaselineAppImage is the same image as the tested one ($newId47); only the new image is measured")
    } else {
        $env:PORTFOLIO_APP_IMAGE = $BaselineAppImage
        try {
            $oldUp47 = & $swapApp47
            $oldRunning47 = & $appImageOf
            Assert-True ($oldUp47 -eq 0 -and $oldRunning47 -eq $baseId47) "[T47k] 앞 이미지($BaselineAppImage)로 앱을 띄움 (exit=$oldUp47)"
            $old47 = & $measure47 "198.51.100.149" "old image"
        } finally {
            Remove-Item env:PORTFOLIO_APP_IMAGE -ErrorAction SilentlyContinue
            $backUp47 = & $swapApp47
        }
        Assert-True ($backUp47 -eq 0) "[T47k] 새 이미지로 복귀 (exit=$backUp47)"
        $timing47.Add("T47QUEUE old-image=$BaselineAppImage ($baseId47) path=$queuePath47 total=$($old47.Total) ms=[$($old47.Ms -join ', ')] median=$($old47.Median) max=$($old47.Max)")
    }
    if ($null -eq $old47) {
        # 앞 이미지를 재지 않은 경우에도 새 이미지를 같은 조건(앱을 새로 띄운 뒤)으로 잰다
        $freshUp47 = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "--force-recreate", "dashboard-app")) -IgnoreExitCode
        [void](Invoke-NativeCapture "docker" ($composeArgs + @("restart", "nginx-waf")) -IgnoreExitCode)
        [void](Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait", "nginx-waf")) -IgnoreExitCode)
        Assert-True ($freshUp47.ExitCode -eq 0) "[T47k] 새 이미지 앱 다시 띄움"
    }
    $newRunning47 = & $appImageOf
    Assert-True ($newRunning47 -eq $newId47) "[T47k] 앱 컨테이너가 새 이미지($newId47)로 돈다"
    $new47 = & $measure47 "198.51.100.151" "new image"
    $ratio47 = if ($old47 -and $old47.Median -gt 0) { [Math]::Round($new47.Median / $old47.Median, 2) } else { $null }
    $timing47.Add("T47QUEUE new-image=zeek-ad-dashboard-app:local ($newId47) path=$queuePath47 total=$($new47.Total) ms=[$($new47.Ms -join ', ')] median=$($new47.Median) max=$($new47.Max)")
    $timing47.Add("T47QUEUE ratio new/old median=$(if ($null -ne $ratio47) { $ratio47 } else { 'n/a' }) (stop rule: > 1.5)")
    Save-Evidence "t47-timing.txt" (($timing47 -join "`n") + "`n")
    $e2eLogs.Add("[T47k] queue period=all&size=50 median (fresh app, warm 3 + 5 samples, demo): old image $BaselineAppImage=$(if ($old47) { "$($old47.Median) ms [$($old47.Ms -join ', ')]" } else { 'not measured' }); new image=$($new47.Median) ms [$($new47.Ms -join ', ')]; ratio=$(if ($null -ne $ratio47) { $ratio47 } else { 'n/a' }) (t47-timing.txt)")
    if ($old47) {
        Assert-True ([long]$old47.Total -eq [long]$new47.Total) "[T47k] 두 이미지의 큐 total이 같다 (old=$($old47.Total), new=$($new47.Total))"
        Assert-True ($new47.Median -le [Math]::Ceiling($old47.Median * 1.5)) "[T47k] 새 이미지 큐 중앙값이 앞 이미지의 1.5배 이하 (old=$($old47.Median) ms, new=$($new47.Median) ms)"
    }

    # ───────── [T52] 중요 자산: 관리자 API 권한·조회자 응답에 이름 없음·지우기 POST가 WAF를 지남 ─────────
    # [T52a](시드가 자산 목록을 자료 파일과 같게 맞춤)는 재시드 단계 바로 뒤에 있다.
    Write-Host "=== [T52] 중요 자산: 관리자 API 403·조회자 응답에 이름 없음·지우기 POST가 WAF를 지남 ==="
    Assert-True ((Invoke-Psql "zeekad_dashboard" "SELECT to_regclass('public.critical_assets') IS NOT NULL").Output.Trim() -eq 't') "[T52b] 앱 DB에 critical_assets 표(V6)"
    $assetSnap52 = { (Invoke-Psql "zeekad_dashboard" "SELECT count(*) || '|' || COALESCE(string_agg(id || ':' || host_ip || '=' || name || '@' || updated_at, ',' ORDER BY id), '') FROM critical_assets").Output.Trim() }
    $assetAudit52 = { [long](Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM audit_logs WHERE action_type = 'CRITICAL_ASSET_CHANGE'").Output.Trim() }
    $assetRows52 = @((Invoke-Psql "zeekad_dashboard" "SELECT id || '|' || host_ip || '|' || name FROM critical_assets ORDER BY id").Output -split "`r?`n" | Where-Object { $_ } | ForEach-Object {
            $p = $_.Trim() -split '\|', 3
            [pscustomobject]@{ Id = $p[0]; HostIp = $p[1]; Name = $p[2] }
        })
    $targetId52 = if ($assetRows52.Count) { $assetRows52[0].Id } else { '999999' }
    $before52 = & $assetSnap52
    $auditBefore52 = & $assetAudit52
    # 앞 단계에서 앱을 다시 띄웠을 수 있어 새 클라이언트로 로그인한다(쓰기 속도 제한도 주소별이라 새 주소를 쓴다)
    $demo52 = New-Client "198.51.100.152"
    Assert-Status (Login-Api $demo52 "demo" $env:DEMO_PASSWORD) 200 "[T52] demo 로그인"
    $trial52 = New-Client "198.51.100.153"
    Assert-Status (Login-Api $trial52 $trialUser $env:TRIAL_ANALYST_PASSWORD) 200 "[T52] $trialUser 로그인"

    # [T52b] 조회자(demo)·분석가(trial-analyst)의 관리자 API는 유효 CSRF로도 앱의 403이고 자산 목록과 감사 행이 그대로다.
    # [T52c] 그 가운데 지우기 요청(POST …/{id}/delete)은 WAF를 지나 앱이 답한다(ApiErrorResponse JSON, WAF 차단 줄 없음).
    $deleteProbe52 = "t52c-delete-" + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    foreach ($who in @(@($demo52, 'demo'), @($trial52, $trialUser))) {
        $probes52 = @(
            @{ Label = "GET list"; Method = "GET"; Path = "/api/admin/critical-assets"; Body = $null },
            @{ Label = "POST create"; Method = "POST"; Path = "/api/admin/critical-assets"; Body = @{ hostIp = "10.10.0.99"; name = "t52-rehearsal" } },
            @{ Label = "PUT update"; Method = "PUT"; Path = "/api/admin/critical-assets/$targetId52"; Body = @{ name = "t52-rehearsal"; description = $null } },
            @{ Label = "POST delete"; Method = "POST"; Path = "/api/admin/critical-assets/$targetId52/delete"; Body = $null }
        )
        foreach ($p in $probes52) {
            $probeId = if ($p.Label -eq 'POST delete' -and $who[1] -ne 'demo') { $deleteProbe52 } else { "" }
            $r = if ($p.Method -eq 'GET') { Invoke-Http -Path $p.Path -Client $who[0] }
                 else { Invoke-Http -Path $p.Path -Method $p.Method -Client $who[0] -Csrf -JsonBody $p.Body -ProbeId $probeId }
            $e2eLogs.Add("[T52b] $($who[1]) $($p.Label) (valid X-XSRF-TOKEN): $(Format-Resp $r 200)")
            Assert-ApiError $r 403 "FORBIDDEN" "[T52b] $($who[1]) $($p.Label) $($p.Path) 역할 거부(앱의 403)"
        }
    }
    $after52 = & $assetSnap52
    $auditAfter52 = & $assetAudit52
    $e2eLogs.Add("[T52b] critical_assets before=$before52`n       after=$after52; CRITICAL_ASSET_CHANGE audit rows $auditBefore52 -> $auditAfter52")
    Assert-True ($before52 -eq $after52 -and $auditBefore52 -eq $auditAfter52) "[T52b] 거부 뒤 자산 목록·감사 행 그대로"
    $wafLog52 = (Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--no-log-prefix", "nginx-waf")) -IgnoreExitCode).Output
    $blocked52 = @($wafLog52 -split "`r?`n" | Where-Object { $_.StartsWith('{"transaction"') -and (Test-ProbeMark $_ $deleteProbe52) -and $_ -match '"is_interrupted":true' })
    $e2eLogs.Add("[T52c] POST /api/admin/critical-assets/$targetId52/delete (probe=$deleteProbe52) reached the app (JSON 403 above); WAF interrupted lines for the probe=$($blocked52.Count)")
    Assert-True ($blocked52.Count -eq 0) "[T52c] 지우기 POST는 WAF 허용 메서드 안이라 WAF가 끊지 않는다"

    # [T52d] 조회자 응답: 큐 전체(모든 쪽)·상세 queueMeta·같은 호스트 인시던트·호스트 위험도에 criticalAssetName이 늘 null이고
    #        assetCritical·priorityBase 키는 있다. 자산 이름(앱 DB)은 어떤 조회자 응답 글에도 없다. 분석가는 이름을 받는다.
    $demoQueue52 = Get-AllQueueItems $demo52 "period=all" 100
    $badRows52 = @($demoQueue52.Items | Where-Object { $null -ne $_.criticalAssetName -or -not ($_.PSObject.Properties.Name -contains 'assetCritical') -or -not ($_.PSObject.Properties.Name -contains 'priorityBase') })
    $critItems52 = @($demoQueue52.Items | Where-Object { $_.assetCritical -eq $true })
    $bodies52 = [System.Collections.Generic.List[string]]::new()
    $hosts52 = Invoke-Http -Path "/api/hosts?period=all&size=100" -Client $demo52
    Assert-Status $hosts52 200 "[T52d] demo 호스트 위험도"
    $bodies52.Add($hosts52.Body)
    $badHosts52 = @($hosts52.Json.items | Where-Object { $null -ne $_.criticalAssetName })
    $metaBad52 = 0
    foreach ($ci in @($critItems52 | Select-Object -First 3)) {
        $d = Invoke-Http -Path "/api/incidents/$($ci.jobId)/rank/$($ci.queueRank)" -Client $demo52
        $rel = Invoke-Http -Path "/api/incidents/$($ci.jobId)/rank/$($ci.queueRank)/related-host-incidents" -Client $demo52
        Assert-Status $d 200 "[T52d] demo 상세 $($ci.jobId)/$($ci.queueRank)"
        Assert-Status $rel 200 "[T52d] demo 같은 호스트 인시던트 $($ci.jobId)/$($ci.queueRank)"
        $bodies52.Add($d.Body)
        $bodies52.Add($rel.Body)
        if ($d.Json.queueMeta.assetCritical -ne $true -or $null -ne $d.Json.queueMeta.criticalAssetName) { $metaBad52++ }
        if (@($rel.Json.items | Where-Object { $null -ne $_.criticalAssetName }).Count -gt 0) { $metaBad52++ }
    }
    # 이름이 실릴 수 있는 길은 criticalAssetName 값뿐이다: 어떤 응답 글에도 문자열 값이 없어야 한다.
    # 자산 이름 글자 찾기는 자유 글이 없는 호스트 위험도 응답에서만 한다(상세의 AI 리포트 등에 "도메인 서버" 같은 말이 우연히 있을 수 있다).
    $namedKey52 = @($bodies52 | Where-Object { $_ -match '"criticalAssetName"\s*:\s*"' }).Count
    $nameHits52 = @(@(foreach ($a in $assetRows52) { if ($a.Name -and $hosts52.Body.Contains($a.Name)) { $a.Name } }) | Select-Object -Unique)
    if ($namedKey52 -gt 0) { $nameHits52 += "criticalAssetName string value in $namedKey52 body(ies)" }
    # 분석가 응답은 원문 주소라 Get-AllQueueItems(가리지 않은 IPv4를 [T23] 목록에 모음)를 쓰지 않는다
    $trialQueue52 = [pscustomobject]@{ Items = [System.Collections.Generic.List[object]]::new() }
    $trialPages52 = 1
    for ($pg = 1; $pg -le $trialPages52; $pg++) {
        $tq = Invoke-Http -Path "/api/incidents/queue?period=all&size=100&page=$pg" -Client $trial52
        Assert-Status $tq 200 "[T52d] $trialUser 큐 page=$pg"
        $trialPages52 = [int]$tq.Json.pageCount
        foreach ($it in @($tq.Json.items)) { $trialQueue52.Items.Add($it) }
    }
    $trialNamed52 = @($trialQueue52.Items | Where-Object { $_.assetCritical -eq $true -and $_.criticalAssetName })
    $e2eLogs.Add("[T52d] demo queue items=$($demoQueue52.Items.Count) critical=$($critItems52.Count) rows with name or missing keys=$($badRows52.Count); hosts rows with name=$($badHosts52.Count); detail/related checked=$([Math]::Min(3, $critItems52.Count)) bad=$metaBad52; asset names found in demo bodies=[$($nameHits52 -join ', ')]`n       $trialUser critical rows with name=$($trialNamed52.Count)/$(@($trialQueue52.Items | Where-Object { $_.assetCritical -eq $true }).Count)")
    Assert-True ($badRows52.Count -eq 0 -and $badHosts52.Count -eq 0 -and $metaBad52 -eq 0 -and @($nameHits52).Count -eq 0) "[T52d] 조회자 응답에 자산 이름 없음(criticalAssetName null, 키는 있음)"
    if ($assetRows52.Count -gt 0) {
        Assert-True ($critItems52.Count -gt 0 -and $trialNamed52.Count -eq @($trialQueue52.Items | Where-Object { $_.assetCritical -eq $true }).Count) "[T52d] 중요 자산 행이 있고 분석가는 그 행마다 이름을 받는다"
    }

    # ───────── [T36] 운영 정리: 익명 볼륨·조회 한도·HSTS ─────────
    Write-Host "=== [T36] 익명 볼륨 재현·조회 한도·HSTS ==="
    # [T36a] NAS 재현: tmpfs 없는 판(옛 compose)으로 sandbox-reset을 띄워 익명 볼륨을 만든 뒤, 지금 판으로
    # up -d --no-deps --renew-anon-volumes sandbox-reset으로 다시 만든다. 새 컨테이너에 볼륨이 없고 옛 볼륨은 매달린(dangling) 채 남는다.
    # 옛 볼륨이 비었는지는 읽기 전용으로 붙인 일회용 컨테이너(네트워크 없음)로 세고, 비었을 때만 그 이름 하나를 지운다(NAS 절차와 같다).
    $oldCompose36 = Join-Path $tmpDir "compose.portfolio.pre-t36.yml"
    $curCompose36 = [IO.File]::ReadAllText((Join-Path $RepoRoot "compose.portfolio.yml"), $utf8NoBom)
    $oldText36 = $curCompose36.Replace('tmpfs: ["/tmp", "/var/lib/postgresql/data:size=1m"]', 'tmpfs: ["/tmp"]')
    Assert-True ($oldText36 -ne $curCompose36 -and $oldText36 -notmatch 'postgresql/data:size') "[T36a] tmpfs 없는 옛 판 compose 만들기"
    [IO.File]::WriteAllText($oldCompose36, $oldText36, $utf8NoBom)
    $oldArgs36 = @("compose", "-p", $ProjectName, "-f", $oldCompose36, "--project-directory", $RepoRoot, "--env-file", ".env.portfolio.example")
    $volMountsOf = {
        param([string]$Cid)
        $i = @((Invoke-NativeCapture "docker" @("inspect", $Cid)).Output | ConvertFrom-Json)[0]
        return @($i.Mounts | Where-Object { $_.Type -eq 'volume' } | ForEach-Object { "$($_.Name)|$($_.Destination)" })
    }
    $oldUp36 = Invoke-NativeCapture "docker" ($oldArgs36 + @("up", "-d", "--no-deps", "sandbox-reset")) -IgnoreExitCode
    $oldCid36 = Get-ServiceContainer "sandbox-reset"
    $oldVols36 = @(& $volMountsOf $oldCid36)
    $anonVol36 = if ($oldVols36.Count -eq 1) { ($oldVols36[0] -split '\|')[0] } else { "" }
    $newUp36 = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--no-deps", "--renew-anon-volumes", "sandbox-reset")) -IgnoreExitCode
    $newCid36 = Get-ServiceContainer "sandbox-reset"
    $newVols36 = @(& $volMountsOf $newCid36)
    $newRun36 = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{.State.Running}} {{json .HostConfig.Tmpfs}}", $newCid36)).Output.Trim()
    $dangling36 = @((Invoke-NativeCapture "docker" @("volume", "ls", "-q", "--filter", "dangling=true")).Output -split "`r?`n" | Where-Object { $_ })
    $entries36 = if ($anonVol36) { (Invoke-NativeCapture "docker" @("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "-v", "${anonVol36}:/v:ro", "--entrypoint", "sh", "pgvector/pgvector:0.8.1-pg17", "-c", "find /v -mindepth 1 | wc -l") -IgnoreExitCode).Output.Trim() } else { "" }
    $users36 = if ($anonVol36) { (Invoke-NativeCapture "docker" @("ps", "-aq", "--filter", "volume=$anonVol36")).Output.Trim() } else { "" }
    $rm36 = if ($anonVol36 -and $entries36 -eq "0" -and -not $users36 -and $dangling36 -contains $anonVol36) { Invoke-NativeCapture "docker" @("volume", "rm", $anonVol36) -IgnoreExitCode } else { $null }
    $stillThere36 = if ($anonVol36) { (Invoke-NativeCapture "docker" @("volume", "ls", "-q", "--filter", "name=^${anonVol36}$")).Output.Trim() } else { "" }
    [void](Invoke-NativeCapture "docker" ($composeArgs + @("stop", "sandbox-reset")) -IgnoreExitCode)
    $e2eLogs.Add("[T36a] reproduce NAS: old compose (tmpfs /tmp only) up -d --no-deps sandbox-reset exit=$($oldUp36.ExitCode) -> volume mounts=[$($oldVols36 -join ', ')]`n       new compose up -d --no-deps --renew-anon-volumes sandbox-reset exit=$($newUp36.ExitCode) -> volume mounts=[$($newVols36 -join ', ')] running+tmpfs=$newRun36`n       old anonymous volume $anonVol36 dangling=$($dangling36 -contains $anonVol36) used by containers=[$users36] entries (read-only one-off container, --network none)=$entries36; docker volume rm exit=$(if ($rm36) { $rm36.ExitCode } else { 'not run' }) still listed=[$stillThere36]`n       (sandbox-reset stopped again, as after [T33])")
    Assert-True ($oldUp36.ExitCode -eq 0 -and $anonVol36 -and ($oldVols36[0] -like '*|/var/lib/postgresql/data')) "[T36a] 옛 판 sandbox-reset에는 익명 볼륨이 붙는다(재현) ($($oldVols36 -join ', '))"
    Assert-True ($newUp36.ExitCode -eq 0 -and $newVols36.Count -eq 0 -and $newRun36 -like 'true *postgresql/data*') "[T36a] --renew-anon-volumes로 다시 만든 새 컨테이너는 볼륨 없이 tmpfs로 실행 ($newRun36)`n$($newUp36.Output)"
    Assert-True ($dangling36 -contains $anonVol36 -and $entries36 -eq "0" -and -not $users36) "[T36a] 옛 익명 볼륨은 매달린 채 비어 있음 (entries=$entries36)"
    Assert-True ($rm36 -and $rm36.ExitCode -eq 0 -and -not $stillThere36) "[T36a] 빈 옛 익명 볼륨 하나만 지움"
    $projVols36 = @((Invoke-NativeCapture "docker" @("volume", "ls", "-q", "--filter", "label=com.docker.compose.project=$ProjectName")).Output -split "`r?`n" | Where-Object { $_ })
    $e2eLogs.Add("[T36a] project-labelled volumes after: [$($projVols36 -join ', ')]")
    Assert-True ($projVols36.Count -eq 1 -and $projVols36[0] -eq "${ProjectName}_pgdata") "[T36a] 이 프로젝트 볼륨은 pgdata 하나"

    # 조회 거부 감사 행 크기: 덮은 한도에서 demo가 허용 밖 캡처 큐를 300번 조회(모두 403 + ACCESS_DENIED_IDOR 1행씩)
    $hidden36 = $demoHiddenCaptures[0]
    $d36 = New-Client "198.51.100.63"
    Assert-Status (Login-Api $d36 "demo" $env:DEMO_PASSWORD) 200 "[T36b] demo 로그인(감사 행 크기 측정)"
    $sizeSql36 = "SELECT pg_total_relation_size('audit_logs') || '|' || pg_relation_size('audit_logs') || '|' || (SELECT count(*) FROM audit_logs WHERE action_type = 'ACCESS_DENIED_IDOR')"
    $before36 = (Invoke-Psql "zeekad_dashboard" $sizeSql36).Output.Trim() -split '\|'
    $idorCodes36 = @{}
    for ($k = 0; $k -lt 300; $k++) {
        $r = Invoke-Http -Path "/api/incidents/queue?period=all&captureId=$hidden36" -Client $d36
        $idorCodes36[[string]$r.Status] = 1 + [int]$idorCodes36[[string]$r.Status]
    }
    $after36 = (Invoke-Psql "zeekad_dashboard" $sizeSql36).Output.Trim() -split '\|'
    $rowSize36 = (Invoke-Psql "zeekad_dashboard" "SELECT round(avg(pg_column_size(a.*))) || '|' || max(pg_column_size(a.*)) FROM (SELECT * FROM audit_logs WHERE action_type = 'ACCESS_DENIED_IDOR' ORDER BY id DESC LIMIT 300) a").Output.Trim()
    $idorDelta36 = [long]$after36[2] - [long]$before36[2]
    $perRow36 = [Math]::Round(([long]$after36[0] - [long]$before36[0]) / [Math]::Max(1, $idorDelta36))
    $e2eLogs.Add("[T36b] demo GET queue?captureId=$hidden36 x300 (read limit overridden $($readOverride.Rate)/$($readOverride.Burst)) -> codes $(($idorCodes36.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '); ACCESS_DENIED_IDOR rows +$idorDelta36; audit_logs total size $($before36[0]) -> $($after36[0]) bytes (heap $($before36[1]) -> $($after36[1])) = ~$perRow36 bytes per row incl. indexes; row pg_column_size avg|max=$rowSize36")
    Assert-True ([int]$idorCodes36['403'] -eq 300 -and $idorDelta36 -eq 300) "[T36b] 허용 밖 조회 1번에 ACCESS_DENIED_IDOR 1행 (403=$($idorCodes36['403']), +$idorDelta36)"

    # 기본값으로 nginx-waf 다시 만들기(덮은 값 지움)
    Remove-Item env:PORTFOLIO_READ_RATE, env:PORTFOLIO_READ_BURST -ErrorAction SilentlyContinue
    $wafUp36 = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--no-deps", "--wait", "nginx-waf")) -IgnoreExitCode
    $wafEnv36 = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "nginx-waf", "sh", "-c", 'echo read=$ZEEKAD_READ_RATE/$ZEEKAD_READ_BURST login=$ZEEKAD_LOGIN_RATE/$ZEEKAD_LOGIN_BURST write=$ZEEKAD_WRITE_RATE/$ZEEKAD_WRITE_BURST')) -IgnoreExitCode).Output.Trim()
    $e2eLogs.Add("[T36b] nginx-waf recreated with compose defaults (override removed): exit=$($wafUp36.ExitCode) $wafEnv36")
    Assert-True ($wafUp36.ExitCode -eq 0 -and $wafEnv36 -eq "read=200r/m/30 login=10r/m/5 write=10r/m/5") "[T36b] 기본값 조회 200r/m·30, 로그인·쓰기 10r/m·5 그대로 ($wafEnv36)"
    $readRate36 = 200; $readBurst36 = 30
    $readPath36 = "/api/dashboard/overview?period=24h"

    # [T36b] DSM 흉내 경로 한 IP가 rate+burst를 넘기면 429, 그 전에는 인증 없는 401. 인증 없는 GET은 감사 행을 만들지 않는다.
    $auditCnt36 = { (Invoke-Psql "zeekad_dashboard" "SELECT count(*) FROM audit_logs").Output.Trim() }
    $a0 = & $auditCnt36
    $limIp36 = "198.51.100.61"
    $st36 = @()
    for ($k = 1; $k -le ($readRate36 + $readBurst36 + 10); $k++) {
        $st36 += (Invoke-Http -Path $readPath36 -Xff $limIp36).Status
        if (@($st36 | Where-Object { $_ -eq 429 }).Count -ge 3) { break }
    }
    $first429 = [Array]::IndexOf([int[]]$st36, 429) + 1
    $a1 = & $auditCnt36
    $authSame36 = Invoke-Http -Path "/api/auth/csrf" -Xff $limIp36
    $meSame36 = Invoke-Http -Path "/api/auth/me" -Xff $limIp36
    $spaSame36 = Invoke-Http -Path "/incidents" -Xff $limIp36
    $other36 = Invoke-Http -Path $readPath36 -Xff "198.51.100.62"
    $sameAgain36 = Invoke-Http -Path $readPath36 -Xff $limIp36
    $before429 = @($st36 | Select-Object -First ([Math]::Max(0, $first429 - 1)))
    $e2eLogs.Add("[T36b] DSM path, same client $limIp36, unauthenticated GET $readPath36 x$($st36.Count) -> first 429 at #$first429 (burst $readBurst36); statuses before it=[$(($before429 | Select-Object -Unique) -join ',')]; audit_logs rows $a0 -> $a1`n       same client right after: /api/auth/csrf -> $($authSame36.Status), /api/auth/me -> $($meSame36.Status), SPA /incidents -> $($spaSame36.Status), $readPath36 -> $($sameAgain36.Status); other client 198.51.100.62 -> $($other36.Status)")
    Assert-True ($first429 -ge $readBurst36 + 1 -and $first429 -le $readBurst36 + 20 -and @($before429 | Where-Object { $_ -ne 401 }).Count -eq 0) "[T36b] 한 IP가 burst를 넘기면 429 (첫 429 #$first429)"
    Assert-True ($a0 -eq $a1) "[T36b] 인증 없는 GET은 감사 행을 만들지 않음 ($a0 -> $a1)"
    Assert-True ($authSame36.Status -eq 200 -and $meSame36.Status -eq 200 -and $spaSame36.Status -eq 200) "[T36b] 한도 중에도 /api/auth/·SPA 경로는 열림(조회는 요청 사이에 다시 채워질 수 있어 기록만)"
    Assert-True ($other36.Status -eq 401) "[T36b] 다른 IP(X-Forwarded-For)는 영향 없음"

    # [T36b]/[T36c] 스택 안(DSM 경로 아님): portfolio-net 일회용 컨테이너 -> nginx-waf:8443(ZAP 대상), nginx-waf:8080. 한도 없음, 8443 HSTS 하나.
    # T61: api 컨테이너는 portfolio-data에만 붙어 nginx-waf에 닿지 않으므로 [T32c]와 같은 일회용 컨테이너($netProbeArgs)에서 보낸다.
    $py36 = @(
        'import sys, ssl, urllib.request, urllib.error',
        'base, path, n = sys.argv[1], sys.argv[2], int(sys.argv[3])',
        'ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE',
        'codes = {}; hsts = []',
        'for i in range(n):',
        '    r = urllib.request.Request(base + path, headers={"X-Forwarded-For": "198.51.100.64", "X-Forwarded-Proto": "https"})',
        '    try:',
        '        resp = urllib.request.urlopen(r, timeout=20, context=ctx); s = resp.status; h = resp.headers',
        '    except urllib.error.HTTPError as e:',
        '        s = e.code; h = e.headers',
        '    codes[s] = codes.get(s, 0) + 1',
        '    if i == 0: hsts = h.get_all("Strict-Transport-Security") or []',
        'print("codes", " ".join("%s=%s" % kv for kv in sorted(codes.items())), "hsts_count=%d" % len(hsts), "hsts=%s" % " | ".join(hsts))'
    ) -join "`n"
    $py36b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($py36))
    $inner36 = { param($b, $pth, $n) (Invoke-NativeCapture "docker" ($netProbeArgs + @("-c", "import base64;exec(base64.b64decode('$py36b64'))", $b, $pth, "$n")) -IgnoreExitCode).Output.Trim() }
    $n36 = $readRate36 + $readBurst36 + 10
    $tls36 = & $inner36 "https://nginx-waf:8443" $readPath36 $n36
    $tlsCsrf36 = & $inner36 "https://nginx-waf:8443" "/api/auth/csrf" 1
    $tlsRoot36 = & $inner36 "https://nginx-waf:8443" "/" 1
    $int36 = & $inner36 "http://nginx-waf:8080" $readPath36 $n36
    $e2eLogs.Add("[T36b] one-off container on $networkName -> https://nginx-waf:8443$readPath36 x$n36 : $tls36`n       one-off container on $networkName -> http://nginx-waf:8080$readPath36 x$n36 (not DSM path): $int36")
    Assert-True ($tls36 -match '^codes 401=\d+ hsts_count=1' -and $tls36 -notmatch '429') "[T36b] 8443 리스너에는 조회 한도 없음 ($tls36)"
    Assert-True ($int36 -match '^codes 401=\d+' -and $int36 -notmatch '429') "[T36b] 스택 안 8080(다른 출처)에도 조회 한도 없음 ($int36)"

    # [T36c] HSTS: DSM 흉내 경로 WAF 응답에는 없음(공개에서는 DSM이 붙임), 8443 응답에는 하나
    $hc36 = @("/api/auth/csrf", "/", "/login", "/api/auth/login-notice") | ForEach-Object { $r = Invoke-Http -Path $_ -Xff "198.51.100.65"; "$_=$($r.Status):$(@([regex]::Matches($r.Headers, '(?im)^Strict-Transport-Security:')).Count)" }
    $e2eLogs.Add("[T36c] DSM path (path=status:HSTS header count): $($hc36 -join ', ')`n       8443 /api/auth/csrf: $tlsCsrf36`n       8443 /: $tlsRoot36")
    Assert-True (@($hc36 | Where-Object { $_ -notmatch ':0$' }).Count -eq 0) "[T36c] DSM 흉내 경로 WAF 응답에 HSTS 없음 ($($hc36 -join ', '))"
    Assert-True ($tlsCsrf36 -match 'hsts_count=1 hsts=max-age=31536000; includeSubDomains$' -and $tlsRoot36 -match 'hsts_count=1 hsts=max-age=31536000; includeSubDomains$') "[T36c] 8443 응답 HSTS 하나 ($tlsCsrf36 / $tlsRoot36)"

    # [T36d] 빠른 사람 사용 흉내(5분, 기본 한도)와 일부러 낸 429 뒤 회복(실제 SPA, Chrome). 도구가 없으면 건너뛴다.
    if ($UsageScript) {
        Write-Host "=== [T36d] 빠른 사람 사용 흉내(5분)·429 회복 ==="
        $usageDir36 = if ($EvidenceFullDir) { Join-Path $EvidenceFullDir "t36d" } else { Join-Path $tmpDir "t36d" }
        $env:T36_DEMO_PASSWORD = $env:DEMO_PASSWORD
        try {
            $meas36 = Invoke-NativeCapture "node" @((Resolve-RepoPath $UsageScript), "measure", $baseUrl, $usageDir36, "203.0.113.36") -IgnoreExitCode
            $rec36 = Invoke-NativeCapture "node" @((Resolve-RepoPath $UsageScript), "recover", $baseUrl, $usageDir36, "203.0.113.37", "$readRate36", "$readBurst36") -IgnoreExitCode
        } finally { Remove-Item env:T36_DEMO_PASSWORD -ErrorAction SilentlyContinue }
        $measLine36 = [regex]::Match($meas36.Output, 'MEASURE_RESULT[^\r\n]*').Value
        $recLine36 = [regex]::Match($rec36.Output, 'RECOVER_RESULT[^\r\n]*').Value
        $e2eLogs.Add("[T36d] measure (5 min, default limit $readRate36 r/m burst $readBurst36, client 203.0.113.36) exit=$($meas36.ExitCode): $measLine36`n       recover (client 203.0.113.37) exit=$($rec36.ExitCode): $recLine36`n       details and screenshots: t36d/measure.txt, t36d/recover.txt, t36d/0*.png")
        Assert-True ($meas36.ExitCode -eq 0 -and $measLine36 -match 'n429=0 ') "[T36d] 빠른 사람 사용 흉내가 429 없이 끝남 ($measLine36)"
        Assert-True ($rec36.ExitCode -eq 0 -and $recLine36 -match '^RECOVER_RESULT PASS') "[T36d] 429 뒤 오류 안내, 한도 중 새로고침도 현황판, 한도가 풀린 뒤 한 번으로 회복 ($recLine36)"
    } else {
        $e2eLogs.Add("[T36d] skipped (no -UsageScript)")
    }

    # ───────── [T61e] nginx-waf 상태 확인이 감사 줄을 남기지 않는다 ─────────
    # 상태 확인(compose healthcheck)은 이름 Host(localhost)를 보낸다. 숫자 주소 Host는 CRS 920350에 걸려 200이어도 감사 줄이 남았다.
    # [T36]이 nginx-waf를 다시 만들었으므로 먼저 그 컨테이너가 뜬 지 60초 이상이고 상태 확인이 여러 번 돌았는지 본다(창이 짧으면 기다린다).
    # 대조: 호스트에서 숫자 주소 Host(curl 기본 Host 127.0.0.1:<포트>)로 /healthz?probe=<표식>을 한 번 보내 그 감사 줄이 남는지 본다
    # (WAF 규칙을 끄지 않았다는 증거이자 아래 0건이 빈 단언이 아니라는 증거).
    Write-Host "=== [T61e] nginx-waf 상태 확인 감사 줄 ==="
    $wafCid61e = Get-ServiceContainer "nginx-waf"
    $startedOf61e = {
        $s = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{.State.StartedAt}}", $wafCid61e)).Output.Trim()
        $m = [regex]::Match($s, '^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
        if (-not $m.Success) { throw "[T61e] nginx-waf StartedAt을 읽지 못했다 ($s)" }
        return [DateTime]::SpecifyKind([DateTime]::ParseExact($m.Groups[1].Value, "yyyy-MM-ddTHH:mm:ss", [Globalization.CultureInfo]::InvariantCulture), [DateTimeKind]::Utc)
    }
    $started61e = & $startedOf61e
    $age61e = ([DateTime]::UtcNow - $started61e).TotalSeconds
    $waited61e = 0
    if ($age61e -lt 70) { $waited61e = [int][Math]::Ceiling(70 - $age61e); Start-Sleep -Seconds $waited61e }
    $age61e = [Math]::Round(([DateTime]::UtcNow - $started61e).TotalSeconds)
    $health61e = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{json .State.Health}}", $wafCid61e)).Output | ConvertFrom-Json
    $hlog61e = @($health61e.Log | Where-Object { $_ })
    $hcmd61e = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{json .Config.Healthcheck.Test}}", $wafCid61e)).Output.Trim()
    $probe61e = "t61health$(New-RandomToken 8)"
    $code61e = (Invoke-NativeCapture "curl.exe" @("-sS", "--max-time", "20", "-o", "NUL", "-w", "%{http_code}", "http://127.0.0.1:$WafHttpPort/healthz?probe=$probe61e") -IgnoreExitCode).Output.Trim()
    $healthAudit61e = @(); $mark61e = @()
    for ($i = 0; $i -lt 10; $i++) {
        $logs61e = (Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--no-log-prefix", "nginx-waf")) -IgnoreExitCode).Output
        $healthAudit61e = @($logs61e -split "`r?`n" | Where-Object { $_.StartsWith('{"transaction"') -and $_ -match '"uri":"/healthz(\?|")' })
        $mark61e = @($healthAudit61e | Where-Object { Test-ProbeMark $_ $probe61e })
        if ($mark61e.Count) { break }
        Start-Sleep -Seconds 1
    }
    $other61e = @($healthAudit61e | Where-Object { -not (Test-ProbeMark $_ $probe61e) })
    $rules61e = @($mark61e | ForEach-Object { [regex]::Matches($_, '"ruleId":"(\d+)"') | ForEach-Object { $_.Groups[1].Value } } | Select-Object -Unique)
    $e2eLogs.Add("[T61e] nginx-waf container started $($started61e.ToString('yyyy-MM-ddTHH:mm:ssZ')) (age ${age61e}s, waited ${waited61e}s); healthcheck test=$hcmd61e; health status=$($health61e.Status), last $($hlog61e.Count) checks exit=[$(($hlog61e | ForEach-Object { $_.ExitCode }) -join ',')]`n       control: host GET http://127.0.0.1:$WafHttpPort/healthz?probe=<marker> (numeric Host) -> HTTP $code61e; its audit lines=$($mark61e.Count) rules=[$($rules61e -join ', ')]`n       /healthz audit lines in this container's log other than the marker request = $($other61e.Count)$(if ($other61e.Count) { "`n       first: " + $other61e[0].Substring(0, [Math]::Min(400, $other61e[0].Length)) })")
    Assert-True ($age61e -ge 60 -and $hlog61e.Count -ge 3 -and $health61e.Status -eq 'healthy') "[T61e] nginx-waf가 뜬 지 60초 이상이고 상태 확인이 여러 번 돌았다 (age ${age61e}s, checks $($hlog61e.Count), $($health61e.Status))"
    Assert-True ($code61e -eq '200' -and $mark61e.Count -ge 1) "[T61e] (대조) 숫자 주소 Host로 보낸 /healthz?probe= 의 감사 줄이 남음 (HTTP $code61e, lines $($mark61e.Count))"
    Assert-True ($other61e.Count -eq 0) "[T61e] 상태 확인의 /healthz 감사 줄 0건 (표식 요청 것 말고 $($other61e.Count)건)"

    $e2eReport = $e2eLogs -join "`n`n"
    Save-Evidence "portfolio-e2e.txt" $e2eReport
    Write-Host "-> 포트폴리오 리허설 E2E [0]~[8]·[T61a~d]·재시드·[T33]·[T25]·[T27]·[T39]·[T40]·[T29]·[T32]·[T47]·[T36]·[T61e] 통과"

    if (-not $SkipZap) {
        Write-Host "=== [9] OWASP ZAP 베이스라인 (https://nginx-waf:8443/, 리허설 스택의 portfolio-net 안) ==="
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
    foreach ($name in $secretNames + @("BOOTSTRAP_ADMIN_TOTP_SECRET", "SANDBOX_RESET_INTERVAL_MINUTES", "PORTFOLIO_READ_RATE", "PORTFOLIO_READ_BURST", "T36_DEMO_PASSWORD")) { Remove-Item "env:$name" -ErrorAction SilentlyContinue }
}

if ($failed) { exit 1 }
exit 0
