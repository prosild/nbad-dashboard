param(
    [string]$ReportDir = "security-reports",
    [string]$EvidenceDir = "",
    [int]$WafHttpPort = 18080,
    [int]$WafHttpsPort = 18443,
    [switch]$SkipBuild,
    [switch]$SkipTrivy,
    [switch]$SkipE2E,
    [switch]$SkipZap
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

$ReportFullDir = Join-Path $RepoRoot $ReportDir
New-Item -ItemType Directory -Force -Path $ReportFullDir | Out-Null

if ($EvidenceDir) {
    $EvidenceFullDir = if ([IO.Path]::IsPathRooted($EvidenceDir)) { $EvidenceDir } else { Join-Path $RepoRoot $EvidenceDir }
    New-Item -ItemType Directory -Force -Path $EvidenceFullDir | Out-Null
} else {
    $EvidenceFullDir = ""
}

function New-RandomToken([int]$Length = 24) {
    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789".ToCharArray()
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Length; $i++) {
        [void]$sb.Append($chars[$bytes[$i] % $chars.Length])
    }
    return $sb.ToString()
}

function New-RandomBase32([int]$Length = 32) {
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray()
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Length; $i++) {
        [void]$sb.Append($chars[$bytes[$i] % $chars.Length])
    }
    return $sb.ToString()
}

function Get-TotpCode([string]$Base32Secret) {
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $clean = $Base32Secret.Trim().ToUpperInvariant() -replace '[\s=]+', ''
    $bytes = New-Object System.Collections.Generic.List[byte]
    $buffer = 0
    $bitsLeft = 0
    foreach ($ch in $clean.ToCharArray()) {
        $idx = $alphabet.IndexOf($ch)
        if ($idx -lt 0) { throw "잘못된 Base32 문자: $ch" }
        $buffer = ($buffer -shl 5) -bor $idx
        $bitsLeft += 5
        if ($bitsLeft -ge 8) {
            [void]$bytes.Add([byte](($buffer -shr ($bitsLeft - 8)) -band 0xFF))
            $bitsLeft -= 8
        }
    }
    $step = [long][Math]::Floor([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 30)
    $msg = New-Object byte[] 8
    for ($i = 7; $i -ge 0; $i--) {
        $msg[$i] = [byte]($step -band 0xFF)
        $step = $step -shr 8
    }
    $hmac = New-Object System.Security.Cryptography.HMACSHA1 -ArgumentList (,($bytes.ToArray()))
    $hash = $hmac.ComputeHash($msg)
    $offset = $hash[$hash.Length - 1] -band 0x0F
    $binary = (($hash[$offset] -band 0x7F) -shl 24) -bor `
              (($hash[$offset + 1] -band 0xFF) -shl 16) -bor `
              (($hash[$offset + 2] -band 0xFF) -shl 8) -bor `
              ($hash[$offset + 3] -band 0xFF)
    return ($binary % 1000000).ToString("D6")
}

function Save-Evidence([string]$FileName, [string]$Content) {
    if ($EvidenceFullDir) {
        $dest = Join-Path $EvidenceFullDir $FileName
        [IO.File]::WriteAllText($dest, $Content, [Text.UTF8Encoding]::new($false))
    }
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

Write-Host "=== [1/5] CycloneDX SBOM 생성 (gradlew.bat cyclonedxBom) ==="
$bomRes = Invoke-NativeCapture "$RepoRoot\gradlew.bat" @("cyclonedxBom")
if (-not (Test-Path "build/reports/bom.json") -or -not (Test-Path "build/reports/bom.xml")) {
    throw "build/reports/bom.json 또는 bom.xml이 생성되지 않았습니다."
}
Copy-Item "build/reports/bom.json" (Join-Path $ReportFullDir "bom.json") -Force
Copy-Item "build/reports/bom.xml" (Join-Path $ReportFullDir "bom.xml") -Force

if (-not $SkipBuild) {
    Write-Host "=== [2/5] Docker 이미지 빌드 (dashboard-app, nginx-waf) ==="
    [void](Invoke-NativeCapture "docker" @("compose", "-f", "compose.yml", "-f", "docker/verify/compose.verify.yml", "build"))
}

if (-not $SkipTrivy) {
    Write-Host "=== [3/5] Trivy SBOM / FS / 이미지 취약점 스캔 ==="
    $trivySummary = [System.Collections.Generic.List[string]]::new()

    Write-Host "-> Trivy 이미지 준비 (aquasec/trivy:latest)"
    [void](Invoke-NativeCapture "docker" @("pull", "aquasec/trivy:latest"))

    Write-Host "-> Trivy SBOM 스캔 (bom.json)"
    $sbomTable = (Invoke-NativeCapture "docker" @("run", "--rm", "-v", "zeekad-trivy-cache:/root/.cache/", "-v", "${RepoRoot}:/work:ro", "aquasec/trivy:latest", "sbom", "--no-progress", "--exit-code", "0", "--format", "table", "/work/build/reports/bom.json")).Output
    [void](Invoke-NativeCapture "docker" @("run", "--rm", "-v", "zeekad-trivy-cache:/root/.cache/", "-v", "${RepoRoot}:/work:ro", "-v", "${ReportFullDir}:/out", "aquasec/trivy:latest", "sbom", "--no-progress", "--exit-code", "0", "--format", "json", "-o", "/out/trivy-sbom.json", "/work/build/reports/bom.json"))
    $trivySummary.Add("=== TRIVY SBOM (bom.json) ===")
    $trivySummary.Add($sbomTable.Trim())

    Write-Host "-> Trivy FS 스캔 (저장소 설정/의존성)"
    $fsTable = (Invoke-NativeCapture "docker" @("run", "--rm", "-v", "zeekad-trivy-cache:/root/.cache/", "-v", "${RepoRoot}:/work:ro", "aquasec/trivy:latest", "fs", "--no-progress", "--scanners", "vuln,misconfig,secret", "--exit-code", "0", "--skip-dirs", "build,.gradle,security-reports,handoff", "--format", "table", "/work")).Output
    [void](Invoke-NativeCapture "docker" @("run", "--rm", "-v", "zeekad-trivy-cache:/root/.cache/", "-v", "${RepoRoot}:/work:ro", "-v", "${ReportFullDir}:/out", "aquasec/trivy:latest", "fs", "--no-progress", "--scanners", "vuln,misconfig,secret", "--exit-code", "0", "--skip-dirs", "build,.gradle,security-reports,handoff", "--format", "json", "-o", "/out/trivy-fs.json", "/work"))
    $trivySummary.Add("`n=== TRIVY FS ===")
    $trivySummary.Add($fsTable.Trim())

    Write-Host "-> Trivy Image 스캔 (zeek-ad-dashboard-app:local)"
    $appTable = (Invoke-NativeCapture "docker" @("run", "--rm", "-v", "zeekad-trivy-cache:/root/.cache/", "-v", "/var/run/docker.sock:/var/run/docker.sock", "aquasec/trivy:latest", "image", "--no-progress", "--exit-code", "0", "--format", "table", "zeek-ad-dashboard-app:local")).Output
    [void](Invoke-NativeCapture "docker" @("run", "--rm", "-v", "zeekad-trivy-cache:/root/.cache/", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", "${ReportFullDir}:/out", "aquasec/trivy:latest", "image", "--no-progress", "--exit-code", "0", "--format", "json", "-o", "/out/trivy-image-app.json", "zeek-ad-dashboard-app:local"))
    $trivySummary.Add("`n=== TRIVY IMAGE (zeek-ad-dashboard-app:local) ===")
    $trivySummary.Add($appTable.Trim())

    Write-Host "-> Trivy Image 스캔 (zeek-ad-dashboard-waf:local)"
    $wafTable = (Invoke-NativeCapture "docker" @("run", "--rm", "-v", "zeekad-trivy-cache:/root/.cache/", "-v", "/var/run/docker.sock:/var/run/docker.sock", "aquasec/trivy:latest", "image", "--no-progress", "--exit-code", "0", "--format", "table", "zeek-ad-dashboard-waf:local")).Output
    [void](Invoke-NativeCapture "docker" @("run", "--rm", "-v", "zeekad-trivy-cache:/root/.cache/", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", "${ReportFullDir}:/out", "aquasec/trivy:latest", "image", "--no-progress", "--exit-code", "0", "--format", "json", "-o", "/out/trivy-image-waf.json", "zeek-ad-dashboard-waf:local"))
    $trivySummary.Add("`n=== TRIVY IMAGE (zeek-ad-dashboard-waf:local) ===")
    $trivySummary.Add($wafTable.Trim())

    $trivySummaryText = $trivySummary -join "`n"
    [IO.File]::WriteAllText((Join-Path $ReportFullDir "trivy-summary.txt"), $trivySummaryText, [Text.UTF8Encoding]::new($false))
    Save-Evidence "trivy-summary.txt" $trivySummaryText
}

if (-not $SkipE2E -or -not $SkipZap) {
    $projectName = "zeekad-verify-" + (Get-Random -Minimum 1000 -Maximum 9999)
    $networkName = "${projectName}_dashboard-net"

    $env:VERIFY_POSTGRES_SUPER_PASSWORD = New-RandomToken 24
    $env:DASHBOARD_APP_PASSWORD = New-RandomToken 24
    $env:ZEEKAD_RO_PASSWORD = New-RandomToken 24
    $env:ZEEKAD_RW_PASSWORD = New-RandomToken 24
    $bootstrapPwd = New-RandomToken 20
    $env:DASHBOARD_BOOTSTRAP_PASSWORD = $bootstrapPwd
    $adminTotpSecret = New-RandomBase32 32
    $env:BOOTSTRAP_ADMIN_TOTP_SECRET = $adminTotpSecret
    $env:DASHBOARD_COOKIE_SECURE = "true"
    $env:WAF_HTTP_PORT = "$WafHttpPort"
    $env:WAF_HTTPS_PORT = "$WafHttpsPort"
    $env:WAF_SERVER_NAME = "localhost"

    try {
        Write-Host "=== [4/5] 검증용 Docker Compose 스택 기동 ($projectName) ==="
        $upRes = Invoke-NativeCapture "docker" @("compose", "-p", $projectName, "-f", "compose.yml", "-f", "docker/verify/compose.verify.yml", "up", "-d", "--wait") -IgnoreExitCode
        if ($upRes.ExitCode -ne 0) {
            $diagLogs = (Invoke-NativeCapture "docker" @("compose", "-p", $projectName, "-f", "compose.yml", "-f", "docker/verify/compose.verify.yml", "logs", "--tail=120") -IgnoreExitCode).Output
            throw "Docker Compose 검증 스택 기동 실패 (exit=$($upRes.ExitCode)):`n$($upRes.Output)`n--- CONTAINER LOGS ---`n$diagLogs"
        }

        if (-not $SkipE2E) {
            Write-Host "=== WAF + HTTPS + PostgreSQL 17 + RBAC/IDOR 실측 검증 ==="
            $e2eLogs = [System.Collections.Generic.List[string]]::new()
            $baseHttps = "https://127.0.0.1:$WafHttpsPort"
            $baseHttp = "http://127.0.0.1:$WafHttpPort"
            $tmpDir = Join-Path ([IO.Path]::GetTempPath()) "zeekad-e2e-$projectName"
            New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

            try {
                function Invoke-CurlRaw([string[]]$CurlArgs) {
                    $savedEap = $ErrorActionPreference
                    $ErrorActionPreference = 'Continue'
                    $out = & curl.exe -sS -k --max-time 15 @CurlArgs 2>&1 | Out-String
                    $code = $LASTEXITCODE
                    $ErrorActionPreference = $savedEap
                    return [pscustomobject]@{ ExitCode = $code; Output = $out }
                }

                # 0) bootJar 내 H2 / application-test.yml 미포함 확인
                $jarCheck = & docker compose -p $projectName -f compose.yml -f docker/verify/compose.verify.yml exec -T dashboard-app `
                    sh -c "unzip -l /app/app.jar | grep -E 'h2-|application-test\.yml' || echo 'NO_H2_OR_TEST_YML'" 2>&1 | Out-String
                $e2eLogs.Add("[0] bootJar H2/test-yml check: $($jarCheck.Trim())")
                if ($jarCheck -notmatch "NO_H2_OR_TEST_YML") {
                    throw "bootJar에 H2 또는 application-test.yml이 포함되어 있습니다: $jarCheck"
                }

                # 1) HTTP -> HTTPS 리다이렉트 및 HTTPS GET /login 보안 헤더 확인
                $httpRedir = Invoke-CurlRaw @("-I", "$baseHttp/login")
                $e2eLogs.Add("[1a] HTTP -> HTTPS redirect:`n$($httpRedir.Output.Trim())")
                if ($httpRedir.Output -notmatch "301" -or $httpRedir.Output -notmatch "Location:\s*https://") {
                    throw "HTTP -> HTTPS 301 리다이렉트 확인 실패"
                }

                $loginGet = Invoke-CurlRaw @("-i", "$baseHttps/login")
                $e2eLogs.Add("[1b] HTTPS GET /login:`n$(($loginGet.Output -split "`r?`n" | Select-Object -First 30) -join "`n")")
                if ($loginGet.Output -notmatch "HTTP/[\d.]+ 200") { throw "GET /login 200 실패" }
                if ($loginGet.Output -notmatch "Content-Security-Policy:.*frame-ancestors 'none'") { throw "CSP frame-ancestors 'none' 누락" }
                if ($loginGet.Output -notmatch "X-Content-Type-Options:\s*nosniff") { throw "X-Content-Type-Options: nosniff 누락" }
                if ($loginGet.Output -notmatch "Referrer-Policy:") { throw "Referrer-Policy 누락" }
                if ($loginGet.Output -match "(?im)^Server:\s*nginx") { throw "Server: nginx 헤더가 노출되었습니다" }
                if ($loginGet.Output -match "(?im)^Access-Control-Allow-Origin:\s*\*") { throw "와일드카드 CORS 헤더가 노출되었습니다" }

                # 2) WAF 공격 차단 확인 (SQLi, XSS, Path Traversal) & /actuator/** 비노출
                $sqliResp = Invoke-CurlRaw @("-i", "$baseHttps/incidents?asset=%27%20OR%201%3D1--")
                $e2eLogs.Add("[2a] WAF SQLi probe:`n$(($sqliResp.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                if ($sqliResp.Output -notmatch "HTTP/[\d.]+ 403") { throw "WAF SQLi 차단(403) 실패" }

                $xssResp = Invoke-CurlRaw @("-i", "$baseHttps/incidents?asset=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
                $e2eLogs.Add("[2b] WAF XSS probe:`n$(($xssResp.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                if ($xssResp.Output -notmatch "HTTP/[\d.]+ 403") { throw "WAF XSS 차단(403) 실패" }

                $ptResp = Invoke-CurlRaw @("-i", "--path-as-is", "$baseHttps/../../etc/passwd")
                $e2eLogs.Add("[2c] WAF Path Traversal probe (/../../etc/passwd):`n$(($ptResp.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                $ptQueryResp = Invoke-CurlRaw @("-i", "$baseHttps/incidents?asset=../../etc/passwd")
                $e2eLogs.Add("[2d] WAF Path Traversal query probe (?asset=../../etc/passwd):`n$(($ptQueryResp.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                if ($ptQueryResp.Output -notmatch "HTTP/[\d.]+ 403") {
                    throw "WAF Path Traversal 차단(403) 실패: path=$($ptResp.Output) query=$($ptQueryResp.Output)"
                }

                $actHealth = Invoke-CurlRaw @("-i", "$baseHttps/actuator/health")
                $actEnv = Invoke-CurlRaw @("-i", "$baseHttps/actuator/env")
                $e2eLogs.Add("[3] /actuator/health & /actuator/env:`n$($actHealth.Output.Trim())`n---`n$($actEnv.Output.Trim())")
                if ($actHealth.Output -notmatch "HTTP/[\d.]+ (403|404)" -or $actEnv.Output -notmatch "HTTP/[\d.]+ (403|404)") {
                    throw "/actuator/** 차단 실패"
                }

                # Helper: 로그인 후 쿠키 저장
                function Extract-Csrf([string]$Html) {
                    if ($Html -match '<input[^>]*name="_csrf"[^>]*value="([^"]+)"') {
                        return $Matches[1]
                    }
                    if ($Html -match '<input[^>]*value="([^"]+)"[^>]*name="_csrf"') {
                        return $Matches[1]
                    }
                    throw "HTML에서 CSRF 토큰 추출 실패"
                }

                function Login-Dashboard([string]$Username, [string]$CookieFile) {
                    $page = Invoke-CurlRaw @("-c", $CookieFile, "$baseHttps/login")
                    $csrf = Extract-Csrf $page.Output
                    $loginPost = Invoke-CurlRaw @(
                        "-i", "-b", $CookieFile, "-c", $CookieFile,
                        "-X", "POST", "$baseHttps/login",
                        "--data-urlencode", "username=$Username",
                        "--data-urlencode", "password=$bootstrapPwd",
                        "--data-urlencode", "_csrf=$csrf"
                    )
                    return $loginPost.Output
                }

                # 4) viewer1 로그인, 쿠키 속성, 마스킹, IDOR 403, transition 403 확인
                $viewerCookies = Join-Path $tmpDir "viewer.cookies"
                $viewerLoginOut = Login-Dashboard "viewer1" $viewerCookies
                $e2eLogs.Add("[4a] viewer1 login Set-Cookie & redirect:`n$($viewerLoginOut.Trim())")
                if ($viewerLoginOut -notmatch "HTTP/[\d.]+ 302" -or $viewerLoginOut -match "/login\?error") {
                    throw "viewer1 로그인 실패"
                }
                if ($viewerLoginOut -notmatch "Set-Cookie:\s*ZEEKAD_SESSION=" -or
                    $viewerLoginOut -notmatch "(?i)Set-Cookie:\s*ZEEKAD_SESSION=[^\r\n]*\bSecure\b" -or
                    $viewerLoginOut -notmatch "(?i)Set-Cookie:\s*ZEEKAD_SESSION=[^\r\n]*\bHttpOnly\b" -or
                    $viewerLoginOut -notmatch "(?i)Set-Cookie:\s*ZEEKAD_SESSION=[^\r\n]*\bSameSite=Lax\b") {
                    throw "ZEEKAD_SESSION 쿠키 속성(Secure/HttpOnly/SameSite=Lax) 확인 실패"
                }

                $viewerQueue = Invoke-CurlRaw @("-i", "-b", $viewerCookies, "$baseHttps/incidents?captureId=cic17-wed")
                $e2eLogs.Add("[4b] viewer1 GET /incidents?captureId=cic17-wed (status + masked check): HTTP $((($viewerQueue.Output -split "`r?`n")[0]))")
                if ($viewerQueue.Output -notmatch "HTTP/[\d.]+ 200") { throw "viewer1 조사 큐 조회 실패" }
                if ($viewerQueue.Output -notmatch "192\.168\.\*\.\*") { throw "viewer1 조사 큐 IP 마스킹 확인 실패" }

                $viewerDetail = Invoke-CurlRaw @("-i", "-b", $viewerCookies, "$baseHttps/incidents/101/rank/1")
                if ($viewerDetail.Output -notmatch "HTTP/[\d.]+ 200") { throw "viewer1 사건 상세 조회 실패" }
                if ($viewerDetail.Output -notmatch "192\.168\.\*\.\*" -or $viewerDetail.Output -match "192\.168\.10\.50") {
                    throw "viewer1 사건 상세 IP 마스킹 확인 실패"
                }

                $viewerIdor = Invoke-CurlRaw @("-i", "-b", $viewerCookies, "$baseHttps/incidents/201/rank/1")
                $e2eLogs.Add("[4c] viewer1 IDOR syn1-tue (/incidents/201/rank/1):`n$(($viewerIdor.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                if ($viewerIdor.Output -notmatch "HTTP/[\d.]+ 403") { throw "viewer1 미허용 캡처 IDOR 403 차단 실패" }

                $viewerCsrf = Extract-Csrf $viewerDetail.Output
                $viewerTransition = Invoke-CurlRaw @(
                    "-i", "-b", $viewerCookies,
                    "-X", "POST", "$baseHttps/incidents/101/rank/1/transition",
                    "--data-urlencode", "toStatus=investigating",
                    "--data-urlencode", "reason=unauthorized-test",
                    "--data-urlencode", "_csrf=$viewerCsrf"
                )
                $e2eLogs.Add("[4d] viewer1 POST transition:`n$(($viewerTransition.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                if ($viewerTransition.Output -notmatch "HTTP/[\d.]+ 403") { throw "VIEWER 상태 전이 403 차단 실패" }

                # 5) analyst1 로그인, 원문 조회, IDOR 403(syn1-tue), PostgreSQL transition_incident 정방향 전이 확인
                $analystCookies = Join-Path $tmpDir "analyst1.cookies"
                $analystLoginOut = Login-Dashboard "analyst1" $analystCookies
                if ($analystLoginOut -notmatch "HTTP/[\d.]+ 302" -or $analystLoginOut -match "/login\?error") {
                    throw "analyst1 로그인 실패"
                }

                $analystIdor = Invoke-CurlRaw @("-i", "-b", $analystCookies, "$baseHttps/incidents?captureId=syn1-tue")
                $e2eLogs.Add("[5a] analyst1 IDOR syn1-tue:`n$(($analystIdor.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                if ($analystIdor.Output -notmatch "HTTP/[\d.]+ 403") { throw "analyst1 미허용 캡처 IDOR 403 차단 실패" }

                $analystDetail = Invoke-CurlRaw @("-i", "-b", $analystCookies, "$baseHttps/incidents/101/rank/1")
                if ($analystDetail.Output -notmatch "HTTP/[\d.]+ 200" -or $analystDetail.Output -notmatch "192\.168\.10\.50") {
                    throw "analyst1 사건 상세 원문 조회 실패"
                }
                $analystCsrf = Extract-Csrf $analystDetail.Output

                $analystTransition = Invoke-CurlRaw @(
                    "-i", "-b", $analystCookies, "-c", $analystCookies,
                    "-X", "POST", "$baseHttps/incidents/101/rank/1/transition",
                    "--data-urlencode", "toStatus=investigating",
                    "--data-urlencode", "reason=PostgreSQL WAF E2E check",
                    "--data-urlencode", "_csrf=$analystCsrf"
                )
                $e2eLogs.Add("[5b] analyst1 POST transition (open -> investigating):`n$(($analystTransition.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                if ($analystTransition.Output -notmatch "HTTP/[\d.]+ 302") { throw "analyst1 상태 전이 리다이렉트 실패" }

                $analystDetailAfter = Invoke-CurlRaw @("-i", "-b", $analystCookies, "$baseHttps/incidents/101/rank/1")
                if ($analystDetailAfter.Output -notmatch "investigating") {
                    throw "PostgreSQL 17 dashboard.transition_incident 전이 반영 확인 실패"
                }

                $analystLabIdor = Invoke-CurlRaw @("-i", "-b", $analystCookies, "$baseHttps/incidents?captureId=lab-20261118")
                $e2eLogs.Add("[5c] analyst1 IDOR lab-20261118:`n$(($analystLabIdor.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                if ($analystLabIdor.Output -notmatch "HTTP/[\d.]+ 403") { throw "analyst1 미허용 lab-20261118 IDOR 403 차단 실패" }

                # 6) admin TOTP 로그인 + v2.1 (lab-20261118 다중 작업/보고서 작업 불일치/보고서 없음/incident_id 상태 승계·이력 합산) 실측
                $adminCookies = Join-Path $tmpDir "admin.cookies"
                $adminLoginOut = Login-Dashboard "admin" $adminCookies
                if ($adminLoginOut -notmatch "HTTP/[\d.]+ 302" -or $adminLoginOut -notmatch "/login/totp") {
                    throw "admin 1차 로그인(TOTP 이동) 실패"
                }
                $totpPage = Invoke-CurlRaw @("-i", "-b", $adminCookies, "-c", $adminCookies, "$baseHttps/login/totp")
                $totpCsrf = Extract-Csrf $totpPage.Output
                $totpCode = Get-TotpCode $adminTotpSecret
                $totpPost = Invoke-CurlRaw @(
                    "-i", "-b", $adminCookies, "-c", $adminCookies,
                    "-X", "POST", "$baseHttps/login/totp",
                    "--data-urlencode", "code=$totpCode",
                    "--data-urlencode", "_csrf=$totpCsrf"
                )
                $e2eLogs.Add("[6a] admin TOTP verify:`n$(($totpPost.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                if ($totpPost.Output -notmatch "HTTP/[\d.]+ 302" -or $totpPost.Output -match "/login/totp\?error") {
                    throw "admin TOTP 2차 인증 실패"
                }

                $labQueue = Invoke-CurlRaw @("-i", "-b", $adminCookies, "$baseHttps/incidents?captureId=lab-20261118")
                $e2eLogs.Add("[6b] admin GET /incidents?captureId=lab-20261118: HTTP $((($labQueue.Output -split "`r?`n")[0]))")
                if ($labQueue.Output -notmatch "HTTP/[\d.]+ 200" -or
                    $labQueue.Output -notmatch "job #502" -or
                    $labQueue.Output -notmatch "보고 작업 #501" -or
                    $labQueue.Output -notmatch "검토 대기" -or
                    $labQueue.Output -notmatch "보고서 없음") {
                    throw "v2.1 lab-20261118 latest_incident_queue 화면 검증 실패"
                }

                $labRank1 = Invoke-CurlRaw @("-i", "-b", $adminCookies, "$baseHttps/incidents/502/rank/1")
                if ($labRank1.Output -notmatch "HTTP/[\d.]+ 200" -or
                    $labRank1.Output -notmatch "10\.20\.0\.25" -or
                    $labRank1.Output -notmatch "보고서 없음") {
                    throw "v2.1 zeekad_report_job_id NULL 보고서 없음 검증 실패"
                }

                $labRank2 = Invoke-CurlRaw @("-i", "-b", $adminCookies, "$baseHttps/incidents/502/rank/2")
                if ($labRank2.Output -notmatch "HTTP/[\d.]+ 200" -or
                    $labRank2.Output -notmatch "보고 작업 job #501" -or
                    $labRank2.Output -notmatch "5 / 6" -or
                    $labRank2.Output -notmatch "현재 상태: investigating" -or
                    $labRank2.Output -notmatch "실습망 초기 조사 시작") {
                    throw "v2.1 다중 작업 조인 및 상태 승계 검증 실패"
                }

                $adminCsrf = Extract-Csrf $labRank2.Output
                $labTransition = Invoke-CurlRaw @(
                    "-i", "-b", $adminCookies, "-c", $adminCookies,
                    "-X", "POST", "$baseHttps/incidents/502/rank/2/transition",
                    "--data-urlencode", "toStatus=closed",
                    "--data-urlencode", "resolution=true_positive",
                    "--data-urlencode", "reason=PG17 v2.1 multi-job transition check",
                    "--data-urlencode", "_csrf=$adminCsrf"
                )
                $e2eLogs.Add("[6c] admin POST transition on job 502 rank 2 (investigating -> closed):`n$(($labTransition.Output -split "`r?`n" | Select-Object -First 15) -join "`n")")
                if ($labTransition.Output -notmatch "HTTP/[\d.]+ 302") { throw "admin v2.1 상태 전이 리다이렉트 실패" }

                $labRank2After = Invoke-CurlRaw @("-i", "-b", $adminCookies, "$baseHttps/incidents/502/rank/2")
                if ($labRank2After.Output -notmatch "현재 상태: closed" -or
                    $labRank2After.Output -notmatch "job #501" -or
                    $labRank2After.Output -notmatch "job #502") {
                    throw "v2.1 incident_id 기준 상태 종료 및 이력 합산(501+502) 확인 실패"
                }

                # 7) PostgreSQL audit_logs 불변 트리거 실증 (UPDATE 시도 실패)
                $immutableRes = Invoke-NativeCapture "docker" @("compose", "-p", $projectName, "-f", "compose.yml", "-f", "docker/verify/compose.verify.yml", "exec", "-T", "verify-postgres", "psql", "-U", "postgres", "-d", "zeekad_dashboard", "-c", "UPDATE audit_logs SET action_type = 'TAMPERED' WHERE id = (SELECT MIN(id) FROM audit_logs);") -IgnoreExitCode
                $immutableCheck = $immutableRes.Output
                $e2eLogs.Add("[7] PostgreSQL audit_logs immutable trigger check:`n$($immutableCheck.Trim())")
                if ($immutableCheck -notmatch "audit_logs is append-only") {
                    throw "PostgreSQL audit_logs 불변 트리거 검증 실패"
                }

                $e2eReport = $e2eLogs -join "`n`n"
                [IO.File]::WriteAllText((Join-Path $ReportFullDir "waf-e2e-verification.txt"), $e2eReport, [Text.UTF8Encoding]::new($false))
                Save-Evidence "waf-e2e-verification.txt" $e2eReport
                Write-Host "-> WAF + PostgreSQL 17 E2E 실측 검증 모두 통과!"
            } finally {
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmpDir
            }
        }

        if (-not $SkipZap) {
            Write-Host "=== [5/5] OWASP ZAP 베이스라인 스캔 (https://nginx-waf:8443/) ==="
            [void](Invoke-NativeCapture "docker" @("pull", "ghcr.io/zaproxy/zaproxy:stable"))
            $zapRes = Invoke-NativeCapture "docker" @("run", "--rm", "--network", $networkName, "-v", "${ReportFullDir}:/zap/wrk:rw", "ghcr.io/zaproxy/zaproxy:stable", "zap-baseline.py", "-t", "https://nginx-waf:8443/", "-J", "zap-baseline.json", "-r", "zap-baseline.html", "-w", "zap-baseline.md") -IgnoreExitCode
            $zapOut = $zapRes.Output
            $zapExit = $zapRes.ExitCode

            $zapSummary = "ZAP_EXIT_CODE=$zapExit`n`n$($zapOut.Trim())"
            [IO.File]::WriteAllText((Join-Path $ReportFullDir "zap-baseline-output.txt"), $zapSummary, [Text.UTF8Encoding]::new($false))
            if (Test-Path (Join-Path $ReportFullDir "zap-baseline.md")) {
                $md = [IO.File]::ReadAllText((Join-Path $ReportFullDir "zap-baseline.md"), [Text.UTF8Encoding]::new($false))
                Save-Evidence "zap-baseline-summary.md" ("ZAP_EXIT_CODE=$zapExit`n`n" + $md)
            } else {
                Save-Evidence "zap-baseline-summary.md" $zapSummary
            }
            Write-Host "-> OWASP ZAP 종료 코드: $zapExit (0=PASS, 2=WARN, 1/3=FAIL)"
            if ($zapExit -eq 1 -or $zapExit -eq 3) {
                throw "OWASP ZAP 스캔 실패 (exit=$zapExit)"
            }
        }
    } finally {
        Write-Host "=== 검증용 Docker Compose 스택 정리 (down -v) ==="
        [void](Invoke-NativeCapture "docker" @("compose", "-p", $projectName, "-f", "compose.yml", "-f", "docker/verify/compose.verify.yml", "down", "-v") -IgnoreExitCode)
    }
}

Write-Host "보안 검증 스크립트 완료. 원본 리포트 경로: $ReportFullDir"
