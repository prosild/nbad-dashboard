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

    Write-Host "-> Trivy FS 스캔 (저장소 설정/의존성, frontend/package-lock.json 포함)"
    $fsSkipDirs = "build,.gradle,security-reports,handoff,frontend/node_modules,frontend/dist"
    $fsTable = (Invoke-NativeCapture "docker" @("run", "--rm", "-v", "zeekad-trivy-cache:/root/.cache/", "-v", "${RepoRoot}:/work:ro", "aquasec/trivy:latest", "fs", "--no-progress", "--scanners", "vuln,misconfig,secret", "--exit-code", "0", "--skip-dirs", $fsSkipDirs, "--format", "table", "/work")).Output
    [void](Invoke-NativeCapture "docker" @("run", "--rm", "-v", "zeekad-trivy-cache:/root/.cache/", "-v", "${RepoRoot}:/work:ro", "-v", "${ReportFullDir}:/out", "aquasec/trivy:latest", "fs", "--no-progress", "--scanners", "vuln,misconfig,secret", "--exit-code", "0", "--skip-dirs", $fsSkipDirs, "--format", "json", "-o", "/out/trivy-fs.json", "/work"))
    $fsJson = [IO.File]::ReadAllText((Join-Path $ReportFullDir "trivy-fs.json"), [Text.UTF8Encoding]::new($false)) | ConvertFrom-Json
    $fsTargets = @($fsJson.Results | ForEach-Object { "$($_.Target) ($($_.Type))" })
    $npmTarget = @($fsJson.Results | Where-Object { $_.Target -eq "frontend/package-lock.json" -and $_.Type -eq "npm" })
    if ($npmTarget.Count -eq 0) {
        throw "Trivy FS 결과에 frontend/package-lock.json(npm) 스캔 대상이 없습니다. 대상: $($fsTargets -join ', ')"
    }
    $trivySummary.Add("`n=== TRIVY FS ===")
    $trivySummary.Add("FS scan targets (trivy-fs.json Results): $($fsTargets -join ', ')")
    $trivySummary.Add("frontend/package-lock.json (npm) vulnerabilities: $(@($npmTarget[0].Vulnerabilities).Where({ $_ }).Count)")
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
    $composeArgs = @("compose", "-p", $projectName, "-f", "compose.yml", "-f", "docker/verify/compose.verify.yml")

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
        $upRes = Invoke-NativeCapture "docker" ($composeArgs + @("up", "-d", "--wait")) -IgnoreExitCode
        if ($upRes.ExitCode -ne 0) {
            $diagLogs = (Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--tail=120")) -IgnoreExitCode).Output
            throw "Docker Compose 검증 스택 기동 실패 (exit=$($upRes.ExitCode)):`n$($upRes.Output)`n--- CONTAINER LOGS ---`n$diagLogs"
        }

        if (-not $SkipE2E) {
            Write-Host "=== WAF + HTTPS + SPA + JSON API + PostgreSQL 17 + RBAC/IDOR 실측 검증 ==="
            $e2eLogs = [System.Collections.Generic.List[string]]::new()
            $allBodies = [System.Collections.Generic.List[string]]::new()
            $baseHttps = "https://127.0.0.1:$WafHttpsPort"
            $baseHttp = "http://127.0.0.1:$WafHttpPort"
            $tmpDir = Join-Path ([IO.Path]::GetTempPath()) "zeekad-e2e-$projectName"
            New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
            $script:httpSeq = 0
            $utf8NoBom = [Text.UTF8Encoding]::new($false)

            try {
                # Helper: curl 요청 1건. 응답 헤더·본문을 파일로 나눠 받고 본문은 UTF-8로 읽어 JSON 파싱을 시도한다.
                function Invoke-Http {
                    param(
                        [string]$Url,
                        [string]$Method = "GET",
                        [string]$CookieJar = "",
                        [switch]$SaveCookies,
                        [switch]$Csrf,
                        $JsonBody = $null,
                        [string]$RawCookie = "",
                        [string]$ProbeId = "",
                        [switch]$PathAsIs,
                        [string[]]$ExtraHeaders = @()
                    )
                    $script:httpSeq++
                    $hdrFile = Join-Path $tmpDir "resp-$($script:httpSeq).hdr"
                    $bodyFile = Join-Path $tmpDir "resp-$($script:httpSeq).body"
                    $curlArgs = @("-sS", "-k", "--max-time", "20", "-X", $Method, "-D", $hdrFile, "-o", $bodyFile, "-w", "%{http_code}")
                    if ($PathAsIs) { $curlArgs += "--path-as-is" }
                    if ($CookieJar) {
                        $curlArgs += @("-b", $CookieJar)
                        if ($SaveCookies) { $curlArgs += @("-c", $CookieJar) }
                    }
                    if ($RawCookie) { $curlArgs += @("-b", $RawCookie) }
                    if ($ProbeId) { $curlArgs += @("-H", "X-E2E-Probe: $ProbeId") }
                    $curlArgs += @("-H", "Accept: application/json, text/html;q=0.9, */*;q=0.8")
                    foreach ($h in $ExtraHeaders) { $curlArgs += @("-H", $h) }
                    if ($Csrf) {
                        $token = Get-JarCookie $CookieJar "XSRF-TOKEN"
                        if (-not $token) { throw "쿠키 파일에 XSRF-TOKEN이 없습니다: $Url" }
                        $curlArgs += @("-H", "X-XSRF-TOKEN: $token")
                    }
                    if ($null -ne $JsonBody) {
                        $reqFile = Join-Path $tmpDir "req-$($script:httpSeq).json"
                        $jsonText = if ($JsonBody -is [string]) { $JsonBody } else { $JsonBody | ConvertTo-Json -Depth 6 -Compress }
                        [IO.File]::WriteAllText($reqFile, $jsonText, $utf8NoBom)
                        $curlArgs += @("-H", "Content-Type: application/json", "--data-binary", "@$reqFile")
                    } elseif ($Method -ne "GET") {
                        # 브라우저 fetch처럼 본문 없는 POST에도 Content-Length: 0을 보낸다(curl -X POST 단독은 헤더를 생략한다).
                        $curlArgs += @("-H", "Content-Length: 0")
                    }
                    $curlArgs += $Url

                    $savedEap = $ErrorActionPreference
                    $ErrorActionPreference = 'Continue'
                    $statusText = & curl.exe @curlArgs 2>&1 | Out-String
                    $curlExit = $LASTEXITCODE
                    $ErrorActionPreference = $savedEap
                    if ($curlExit -ne 0) { throw "curl 실패 (exit=$curlExit) $Method $Url : $statusText" }

                    $headers = if (Test-Path $hdrFile) { [IO.File]::ReadAllText($hdrFile, $utf8NoBom) } else { "" }
                    $body = if (Test-Path $bodyFile) { [IO.File]::ReadAllText($bodyFile, $utf8NoBom) } else { "" }
                    $json = $null
                    if ($body.TrimStart().StartsWith("{") -or $body.TrimStart().StartsWith("[")) {
                        try { $json = $body | ConvertFrom-Json } catch { $json = $null }
                    }
                    $allBodies.Add($body)
                    return [pscustomobject]@{
                        Method = $Method; Url = $Url; Status = [int]($statusText.Trim()); Headers = $headers; Body = $body; Json = $json
                    }
                }

                function Get-JarCookie([string]$Jar, [string]$Name) {
                    $value = $null
                    if (-not (Test-Path $Jar)) { return $null }
                    foreach ($line in [IO.File]::ReadAllLines($Jar)) {
                        $l = $line -replace '^#HttpOnly_', ''
                        if (-not $l -or $l.StartsWith("#")) { continue }
                        $parts = $l -split "`t"
                        if ($parts.Count -ge 7 -and $parts[5] -eq $Name) { $value = $parts[6] }
                    }
                    return $value
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
                    return "$($Resp.Method) $($Resp.Url -replace '^https?://[^/]+', '') -> HTTP $($Resp.Status) [$ct] $snippet"
                }

                function Assert-Status($Resp, [int]$Expected, [string]$What) {
                    if ($Resp.Status -ne $Expected) {
                        throw "$What : 기대 HTTP $Expected, 실제 $(Format-Resp $Resp 600)"
                    }
                }

                function Assert-True([bool]$Condition, [string]$What, $Resp = $null) {
                    if (-not $Condition) {
                        $detail = if ($Resp) { "`n$(Format-Resp $Resp 1200)" } else { "" }
                        throw "$What 확인 실패$detail"
                    }
                }

                function Test-SpaShell($Resp) {
                    return ($Resp.Body -match '<div id="root"></div>' -and $Resp.Body -match 'src="/assets/')
                }

                function Assert-ApiError($Resp, [int]$Status, [string]$Code, [string]$What) {
                    Assert-Status $Resp $Status $What
                    Assert-True ($null -ne $Resp.Json -and $Resp.Json.code -eq $Code) "$What (JSON code=$Code)" $Resp
                    Assert-True (-not (Test-SpaShell $Resp)) "$What (SPA index.html 폴백 아님)" $Resp
                }

                # WAF 차단 판정: 403 + 앱 ApiErrorResponse JSON 아님 + nginx-waf 로그에 그 요청(X-E2E-Probe)의 ModSecurity 차단 기록(규칙 ID)
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
                    $uniqueId = [regex]::Match($logLine, '"unique_id":"([^"]+)"').Groups[1].Value
                    $logClientIp = [regex]::Match($logLine, '"client_ip":"([^"]+)"').Groups[1].Value
                    Assert-True ($ruleIds.Count -gt 0 -and $interrupted -and $logCode -eq "403") "$What (WAF 로그 차단 규칙 ID·interrupted·403)"
                    return "WAF log: unique_id=$uniqueId client_ip=$logClientIp is_interrupted=true http_code=$logCode ruleIds=[$($ruleIds -join ', ')]"
                }

                function Redact-Cookies([string]$Text) {
                    return ($Text -replace '(ZEEKAD_SESSION|XSRF-TOKEN)=[^;\s]+', '$1=<redacted>')
                }

                function Login-Api([string]$Username, [string]$CookieJar) {
                    $csrfRes = Invoke-Http -Url "$baseHttps/api/auth/csrf" -CookieJar $CookieJar -SaveCookies
                    Assert-Status $csrfRes 200 "$Username GET /api/auth/csrf"
                    Assert-True ($csrfRes.Json.headerName -eq "X-XSRF-TOKEN" -and [bool](Get-JarCookie $CookieJar "XSRF-TOKEN")) "$Username XSRF-TOKEN 쿠키 발급" $csrfRes
                    return Invoke-Http -Url "$baseHttps/api/auth/login" -Method POST -CookieJar $CookieJar -SaveCookies -Csrf `
                        -JsonBody @{ username = $Username; password = $bootstrapPwd }
                }

                # [0] bootJar 구성(H2·application-test.yml 없음, SPA 번들 포함)과 최종 앱 이미지(Node 없음, non-root)
                $execPrefix = $composeArgs + @("exec", "-T", "dashboard-app", "sh", "-c")
                $jarCheck = (Invoke-NativeCapture "docker" ($execPrefix + @("unzip -l /app/app.jar | grep -E 'h2-|application-test\.yml' || echo 'NO_H2_OR_TEST_YML'")) -IgnoreExitCode).Output
                $e2eLogs.Add("[0a] bootJar H2/test-yml check: $($jarCheck.Trim())")
                Assert-True ($jarCheck -match "NO_H2_OR_TEST_YML") "bootJar H2·application-test.yml 미포함"

                $staticCheck = (Invoke-NativeCapture "docker" ($execPrefix + @("unzip -l /app/app.jar | grep -E 'BOOT-INF/classes/static/' | awk '{print `$4}'")) -IgnoreExitCode).Output
                $e2eLogs.Add("[0b] bootJar SPA static entries:`n$($staticCheck.Trim())")
                Assert-True ($staticCheck -match "(?m)^BOOT-INF/classes/static/index\.html\s*$") "bootJar BOOT-INF/classes/static/index.html 포함"
                Assert-True ($staticCheck -match "(?m)^BOOT-INF/classes/static/assets/[^/\s]+\.js\s*$") "bootJar BOOT-INF/classes/static/assets/*.js 포함"

                $runtimeCheck = (Invoke-NativeCapture "docker" ($execPrefix + @("echo uid=`$(id -u) user=`$(id -un); (command -v node || echo NO_NODE); (command -v npm || echo NO_NPM); (ls -d /app/node_modules /usr/local/lib/node_modules /usr/lib/node_modules 2>/dev/null || echo NO_NODE_MODULES); . /etc/os-release; echo os=`$ID-`$VERSION_ID; (test -e /opt/java/openjdk/bin/javac && echo HAS_JAVAC || echo NO_JAVAC); java -version 2>&1 | head -1")) -IgnoreExitCode).Output
                $e2eLogs.Add("[0c] app runtime image (user / Node.js absence / base):`n$($runtimeCheck.Trim())")
                $uidMatch = [regex]::Match($runtimeCheck, "uid=(\d+)")
                Assert-True ($uidMatch.Success -and $uidMatch.Groups[1].Value -ne "0") "앱 컨테이너 non-root(id -u != 0)"
                Assert-True ($runtimeCheck -match "NO_NODE" -and $runtimeCheck -match "NO_NPM" -and $runtimeCheck -match "NO_NODE_MODULES") "최종 앱 이미지에 Node.js·npm·node_modules 없음"
                Assert-True ($runtimeCheck -match "NO_JAVAC") "최종 앱 이미지가 JRE(javac 없음)"
                $imageEnv = (Invoke-NativeCapture "docker" @("image", "inspect", "zeek-ad-dashboard-app:local", "--format", "{{range .Config.Env}}{{println .}}{{end}}") -IgnoreExitCode).Output
                $e2eLogs.Add("[0d] app image Config.Env (JRE base check):`n$($imageEnv.Trim())")
                Assert-True ($imageEnv -match "(?m)^JAVA_VERSION=jdk-?17" -and $imageEnv -notmatch "(?m)^NODE_VERSION=") "최종 앱 이미지가 Temurin 17 JRE 기반이고 NODE_VERSION 없음"

                # [1] HTTP -> HTTPS, SPA 셸·보안 헤더, 비인증 보호 경로 302 /login, 정적 자산
                $httpRedir = Invoke-Http -Url "$baseHttp/login"
                $e2eLogs.Add("[1a] HTTP -> HTTPS redirect: HTTP $($httpRedir.Status) Location=$(Get-HeaderValue $httpRedir 'Location')")
                Assert-Status $httpRedir 301 "HTTP -> HTTPS 리다이렉트"
                Assert-True ((Get-HeaderValue $httpRedir "Location") -match "^https://") "HTTP -> HTTPS Location" $httpRedir

                $loginGet = Invoke-Http -Url "$baseHttps/login"
                $e2eLogs.Add("[1b] HTTPS GET /login (unauthenticated SPA shell):`n$(Redact-Cookies $loginGet.Headers.Trim())`n$(Format-Resp $loginGet 600)")
                Assert-Status $loginGet 200 "비인증 GET /login"
                Assert-True (Test-SpaShell $loginGet) "GET /login SPA 셸 표지(<div id=`"root`"></div>, src=`"/assets/)" $loginGet
                $csp = Get-HeaderValue $loginGet "Content-Security-Policy"
                Assert-True ($csp -and $csp.Contains("script-src 'self'") -and $csp.Contains("style-src 'self'") -and $csp.Contains("frame-ancestors 'none'")) "CSP script-src/style-src 'self', frame-ancestors 'none'" $loginGet
                Assert-True ($csp -notmatch "unsafe-inline" -and $csp -notmatch "unsafe-eval") "CSP unsafe-inline·unsafe-eval 없음" $loginGet
                Assert-True ((Get-HeaderValue $loginGet "X-Content-Type-Options") -eq "nosniff") "X-Content-Type-Options: nosniff" $loginGet
                Assert-True ([bool](Get-HeaderValue $loginGet "Referrer-Policy")) "Referrer-Policy" $loginGet
                Assert-True ($loginGet.Headers -notmatch "(?im)^Server:\s*nginx") "Server: nginx 헤더 비노출" $loginGet
                Assert-True ($loginGet.Headers -notmatch "(?im)^Access-Control-Allow-Origin:\s*\*") "와일드카드 CORS 헤더 비노출" $loginGet

                foreach ($protectedPath in @("/", "/incidents/101/rank/1")) {
                    $protectedRes = Invoke-Http -Url "$baseHttps$protectedPath"
                    $loc = Get-HeaderValue $protectedRes "Location"
                    $e2eLogs.Add("[1c] unauthenticated GET $protectedPath -> HTTP $($protectedRes.Status) Location=$loc")
                    Assert-Status $protectedRes 302 "비인증 GET $protectedPath"
                    Assert-True ($loc -match "^(https://[^/]+)?/login$") "비인증 GET $protectedPath Location /login" $protectedRes
                }

                $jsAssets = @([regex]::Matches($loginGet.Body, 'src="(/assets/[^"]+\.js)"') | ForEach-Object { $_.Groups[1].Value })
                $cssAssets = @([regex]::Matches($loginGet.Body, 'href="(/assets/[^"]+\.css)"') | ForEach-Object { $_.Groups[1].Value })
                Assert-True ($jsAssets.Count -gt 0 -and $cssAssets.Count -gt 0) "index.html의 /assets/*.js·/assets/*.css 참조" $loginGet
                $bundleText = ""
                foreach ($asset in $jsAssets) {
                    $assetRes = Invoke-Http -Url "$baseHttps$asset"
                    $ct = Get-HeaderValue $assetRes "Content-Type"
                    $e2eLogs.Add("[1d] unauthenticated GET $asset -> HTTP $($assetRes.Status) Content-Type=$ct nosniff=$(Get-HeaderValue $assetRes 'X-Content-Type-Options') bytes=$($assetRes.Body.Length)")
                    Assert-Status $assetRes 200 "비인증 GET $asset"
                    Assert-True ($ct -match "^(text|application)/javascript") "$asset JavaScript Content-Type" $assetRes
                    $bundleText += $assetRes.Body
                }
                foreach ($asset in $cssAssets) {
                    $assetRes = Invoke-Http -Url "$baseHttps$asset"
                    $ct = Get-HeaderValue $assetRes "Content-Type"
                    $e2eLogs.Add("[1d] unauthenticated GET $asset -> HTTP $($assetRes.Status) Content-Type=$ct nosniff=$(Get-HeaderValue $assetRes 'X-Content-Type-Options') bytes=$($assetRes.Body.Length)")
                    Assert-Status $assetRes 200 "비인증 GET $asset"
                    Assert-True ($ct -match "^text/css") "$asset text/css Content-Type" $assetRes
                }
                # 운영 화면의 고정 안내 문구는 SSR HTML이 아니라 SPA 번들에 있다(데이터 필드 아님).
                $bundleNotices = @("현황판", "분석가 판정 집계", "미탐(재현율)은 이 집계로 알 수 없음", "모든 모델 합계", "표본 부족")
                foreach ($notice in $bundleNotices) {
                    Assert-True ($bundleText.Contains($notice)) "SPA 번들 운영 화면 문구 '$notice'"
                }
                Assert-True (-not $bundleText.Contains("정확도")) "SPA 번들에 '정확도' 문구 없음"
                Assert-True (-not $bundleText.Contains("정밀도")) "SPA 번들에 옛 표기 '정밀도' 없음(T20 정탐률로 바꿈)"
                $e2eLogs.Add("[1e] SPA bundle operations notices present: $($bundleNotices -join ' | '); '정확도'·'정밀도' absent")

                # [2] /api/** 는 SPA로 폴백하지 않는다
                $unauthApi = Invoke-Http -Url "$baseHttps/api/incidents"
                $unauthMissing = Invoke-Http -Url "$baseHttps/api/does-not-exist/e2e"
                $e2eLogs.Add("[2a] $(Format-Resp $unauthApi)`n[2b] $(Format-Resp $unauthMissing)")
                Assert-ApiError $unauthApi 401 "UNAUTHENTICATED" "비인증 GET /api/incidents"
                Assert-ApiError $unauthMissing 401 "UNAUTHENTICATED" "비인증 GET /api/does-not-exist/e2e"

                # [3] WAF 차단 (쿼리 SQLi·XSS·경로 탐색, CSRF 토큰을 붙인 JSON 본문 SQLi·XSS)
                $wafProbes = @(
                    @{ Id = "e2e-q-sqli"; Label = "query SQLi (?asset=' OR 1=1--)"; Url = "$baseHttps/api/incidents?asset=%27%20OR%201%3D1--" },
                    @{ Id = "e2e-q-xss"; Label = "query XSS (?asset=<script>alert(1)</script>)"; Url = "$baseHttps/api/incidents?asset=%3Cscript%3Ealert(1)%3C%2Fscript%3E" },
                    @{ Id = "e2e-q-traversal"; Label = "query path traversal (?asset=../../etc/passwd)"; Url = "$baseHttps/api/incidents?asset=../../etc/passwd" }
                )
                foreach ($probe in $wafProbes) {
                    $probeRes = Invoke-Http -Url $probe.Url -ProbeId $probe.Id
                    $wafEvidence = Assert-WafBlocked $probeRes $probe.Id "WAF $($probe.Label)"
                    $e2eLogs.Add("[3] WAF $($probe.Label): $(Format-Resp $probeRes 120)`n    $wafEvidence")
                }
                $ptPath = Invoke-Http -Url "$baseHttps/../../etc/passwd" -PathAsIs
                $e2eLogs.Add("[3] (참고) raw path traversal /../../etc/passwd: $(Format-Resp $ptPath 120)")

                $wafCookies = Join-Path $tmpDir "waf.cookies"
                $wafCsrf = Invoke-Http -Url "$baseHttps/api/auth/csrf" -CookieJar $wafCookies -SaveCookies
                Assert-Status $wafCsrf 200 "WAF JSON 본문 시험용 GET /api/auth/csrf"
                $jsonProbes = @(
                    @{ Id = "e2e-body-sqli"; Label = "JSON body SQLi (username=admin' OR 1=1--)"; Body = '{"username":"admin'' OR 1=1--","password":"x"}' },
                    @{ Id = "e2e-body-xss"; Label = "JSON body XSS (username=<script>alert(1)</script>)"; Body = '{"username":"<script>alert(1)</script>","password":"x"}' }
                )
                foreach ($probe in $jsonProbes) {
                    $probeRes = Invoke-Http -Url "$baseHttps/api/auth/login" -Method POST -CookieJar $wafCookies -Csrf -JsonBody $probe.Body -ProbeId $probe.Id
                    $wafEvidence = Assert-WafBlocked $probeRes $probe.Id "WAF $($probe.Label)"
                    $e2eLogs.Add("[3] WAF $($probe.Label) with XSRF-TOKEN cookie + X-XSRF-TOKEN header: $(Format-Resp $probeRes 120)`n    $wafEvidence")
                }
                $benignLogin = Invoke-Http -Url "$baseHttps/api/auth/login" -Method POST -CookieJar $wafCookies -Csrf -JsonBody @{ username = "nobody-e2e"; password = "x" }
                $e2eLogs.Add("[3] (대조) benign JSON login with same CSRF: $(Format-Resp $benignLogin 200)")
                Assert-ApiError $benignLogin 401 "INVALID_CREDENTIALS" "WAF 대조용 정상 JSON 로그인 요청(앱 도달)"

                $actHealth = Invoke-Http -Url "$baseHttps/actuator/health"
                $actEnv = Invoke-Http -Url "$baseHttps/actuator/env"
                $e2eLogs.Add("[3] /actuator/health & /actuator/env: $(Format-Resp $actHealth 80) | $(Format-Resp $actEnv 80)")
                Assert-True (@(403, 404) -contains $actHealth.Status -and @(403, 404) -contains $actEnv.Status) "/actuator/** 차단(403/404)"

                # [4] viewer1: 세션 쿠키 속성, 마스킹, Slack 스레드, IDOR 403, 운영 집계 격리, 쓰기 403
                $viewerCookies = Join-Path $tmpDir "viewer.cookies"
                $viewerLogin = Login-Api "viewer1" $viewerCookies
                $e2eLogs.Add("[4a] viewer1 POST /api/auth/login:`n$(Redact-Cookies $viewerLogin.Headers.Trim())`n$(Format-Resp $viewerLogin 400)")
                Assert-Status $viewerLogin 200 "viewer1 JSON 로그인"
                Assert-True ($viewerLogin.Json.authenticated -eq $true -and $viewerLogin.Json.user.role -eq "VIEWER" -and $viewerLogin.Json.nextRoute -eq "/") "viewer1 로그인 응답 필드" $viewerLogin
                $sessionCookieLine = [regex]::Match($viewerLogin.Headers, "(?im)^Set-Cookie:\s*ZEEKAD_SESSION=[^\r\n]*").Value
                Assert-True ($sessionCookieLine -and $sessionCookieLine -match "(?i)\bSecure\b" -and $sessionCookieLine -match "(?i)\bHttpOnly\b" -and $sessionCookieLine -match "(?i)\bSameSite=Lax\b") "ZEEKAD_SESSION 쿠키 속성(Secure/HttpOnly/SameSite=Lax)" $viewerLogin

                $viewerMissing = Invoke-Http -Url "$baseHttps/api/does-not-exist/e2e" -CookieJar $viewerCookies
                $e2eLogs.Add("[2c] authenticated(viewer1) $(Format-Resp $viewerMissing)")
                Assert-ApiError $viewerMissing 404 "NOT_FOUND" "인증 세션 GET /api/does-not-exist/e2e"

                $viewerQueue = Invoke-Http -Url "$baseHttps/api/incidents?captureId=cic17-wed" -CookieJar $viewerCookies
                $viewerHosts = @($viewerQueue.Json.incidents | ForEach-Object { $_.hostIp })
                $e2eLogs.Add("[4b] viewer1 GET /api/incidents?captureId=cic17-wed -> HTTP $($viewerQueue.Status) maskedView=$($viewerQueue.Json.maskedView) hostIp=[$($viewerHosts -join ', ')]")
                Assert-Status $viewerQueue 200 "viewer1 인시던트 목록 조회"
                Assert-True ($viewerQueue.Json.maskedView -eq $true -and ($viewerHosts -contains "192.168.*.*") -and -not $viewerQueue.Body.Contains("192.168.10.50")) "viewer1 인시던트 목록 IP 마스킹" $viewerQueue

                $viewerDetail = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/1" -CookieJar $viewerCookies
                Assert-Status $viewerDetail 200 "viewer1 인시던트 상세(101/rank/1)"
                $vd1 = $viewerDetail.Json.detail
                $vd1Labels = @($vd1.slackDeliveries | ForEach-Object { $_.threadRoleLabel })
                $vd1Broadcast = @($vd1.slackDeliveries | Where-Object { $_.replyBroadcast -eq $true })
                $e2eLogs.Add("[4b] viewer1 GET /api/incidents/101/rank/1 -> HTTP $($viewerDetail.Status) hostIp=$($vd1.incident.hostIp) slack threadRoleLabel=[$($vd1Labels -join ', ')] replyBroadcast=$($vd1Broadcast.Count) threadGroups=$(@($vd1.slackThreadGroups).Count)")
                Assert-True ($vd1.incident.hostIp -eq "192.168.*.*" -and -not $viewerDetail.Body.Contains("192.168.10.50")) "viewer1 인시던트 상세 IP 마스킹" $viewerDetail
                Assert-True (($vd1Labels -contains "최초 알림") -and ($vd1Labels -contains "후속 알림") -and $vd1Broadcast.Count -gt 0 -and @($vd1.slackThreadGroups).Count -gt 0) "viewer1 Slack 스레드 묶음·재알림(broadcast)" $viewerDetail

                $viewerDetail2 = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2" -CookieJar $viewerCookies
                Assert-Status $viewerDetail2 200 "viewer1 인시던트 상세(101/rank/2)"
                $vd2Replies = @($viewerDetail2.Json.detail.slackDeliveries | Where-Object { $_.threadRoleLabel -eq "타 인시던트 후속 알림" })
                $e2eLogs.Add("[4b] viewer1 GET /api/incidents/101/rank/2 -> HTTP $($viewerDetail2.Status) thread replies=$($vd2Replies.Count) threadParent=[$(@($vd2Replies | ForEach-Object { $_.threadParent }) -join ', ')]")
                Assert-True ($vd2Replies.Count -gt 0 -and @($vd2Replies | Where-Object { $_.threadParent -match "192\.168\.\*\.\*" }).Count -gt 0 -and -not $viewerDetail2.Body.Contains("192.168.10.50")) "viewer1 Slack zeekad_thread_parent IP 마스킹" $viewerDetail2

                $viewerIdor = Invoke-Http -Url "$baseHttps/api/incidents/201/rank/1" -CookieJar $viewerCookies
                $e2eLogs.Add("[4c] viewer1 IDOR syn1-tue: $(Format-Resp $viewerIdor)")
                Assert-Status $viewerIdor 403 "viewer1 미허용 캡처(201/rank/1) IDOR 차단"

                $viewerOps = Invoke-Http -Url "$baseHttps/api/operations" -CookieJar $viewerCookies
                Assert-Status $viewerOps 200 "viewer1 /api/operations"
                $vFeedback = @($viewerOps.Json.feedbackSummaries)
                $vCaptures = @($vFeedback | ForEach-Object { $_.captureId } | Select-Object -Unique)
                $vAllRow = @($vFeedback | Where-Object { $_.allModel -eq $true -and $_.captureId -eq "cic17-wed" })
                $e2eLogs.Add("[4c-ops] viewer1 GET /api/operations -> HTTP $($viewerOps.Status) allowedCaptures=[$(@($viewerOps.Json.allowedCaptures) -join ', ')] feedback captures=[$($vCaptures -join ', ')] all-row precisionSummaryText=[$(@($vAllRow | ForEach-Object { $_.precisionSummaryText }) -join ' | ')]")
                Assert-True ($vFeedback.Count -gt 0 -and $vCaptures.Count -eq 1 -and $vCaptures[0] -eq "cic17-wed") "viewer1 feedback_summary 허용 캡처(cic17-wed)만 노출" $viewerOps
                # T20: 판정 1건(10건 미만)이라 정탐률 대신 표본 부족(docs/ui-terminology.md '운영 지표 정의')
                Assert-True (@($vAllRow | Where-Object { $_.precisionSummaryText -eq "표본 부족 · 판정 1/3건(33.3%)" }).Count -eq 1) "viewer1 feedback_summary '표본 부족 · 판정 1/3건(33.3%)'" $viewerOps
                foreach ($forbidden in @("syn1-tue", "lab-20261118", "lab-fusion-v2", "정확도")) {
                    Assert-True (-not $viewerOps.Body.Contains($forbidden)) "viewer1 /api/operations에 '$forbidden' 없음" $viewerOps
                }

                $viewerTransition = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/1/transition" -Method POST -CookieJar $viewerCookies -SaveCookies -Csrf `
                    -JsonBody @{ toStatus = "investigating"; reason = "unauthorized-test" }
                $viewerReview1 = Invoke-Http -Url "$baseHttps/api/reviews/decide" -Method POST -CookieJar $viewerCookies -SaveCookies -Csrf `
                    -JsonBody @{ jobId = 101; incidentId = "cic17-wed|10.20.30.40|responder|1700000300"; action = "confirm" }
                $viewerReview2 = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2/review-decision" -Method POST -CookieJar $viewerCookies -SaveCookies -Csrf `
                    -JsonBody @{ action = "confirm" }
                $viewerAdmin = Invoke-Http -Url "$baseHttps/api/admin/users" -CookieJar $viewerCookies
                $e2eLogs.Add("[4d] viewer1 POST transition: $(Format-Resp $viewerTransition)`n[4e] viewer1 POST /api/reviews/decide: $(Format-Resp $viewerReview1)`n[4e] viewer1 POST /api/incidents/101/rank/2/review-decision: $(Format-Resp $viewerReview2)`n[4f] viewer1 GET /api/admin/users: $(Format-Resp $viewerAdmin)")
                Assert-Status $viewerTransition 403 "VIEWER 상태 전이 차단"
                Assert-Status $viewerReview1 403 "VIEWER /api/reviews/decide 차단"
                Assert-Status $viewerReview2 403 "VIEWER 상세 review-decision 차단"
                Assert-Status $viewerAdmin 403 "VIEWER /api/admin/users 차단"

                # [5] analyst1: 미허용 캡처 403, 원문 조회, 전이·검토 결정(PostgreSQL 함수), 22023 중복 결정, 운영 집계 격리
                $analystCookies = Join-Path $tmpDir "analyst1.cookies"
                $analystLogin = Login-Api "analyst1" $analystCookies
                Assert-Status $analystLogin 200 "analyst1 JSON 로그인"
                Assert-True ($analystLogin.Json.user.role -eq "ANALYST") "analyst1 로그인 역할" $analystLogin

                $analystIdor = Invoke-Http -Url "$baseHttps/api/incidents?captureId=syn1-tue" -CookieJar $analystCookies
                $analystLabIdor = Invoke-Http -Url "$baseHttps/api/incidents?captureId=lab-20261118" -CookieJar $analystCookies
                $analystRevIdor = Invoke-Http -Url "$baseHttps/api/reviews/decide" -Method POST -CookieJar $analystCookies -SaveCookies -Csrf `
                    -JsonBody @{ jobId = 201; incidentId = "syn1-tue|10.99.88.77|originator|1700001000"; action = "confirm" }
                $e2eLogs.Add("[5a] analyst1 IDOR syn1-tue: $(Format-Resp $analystIdor)`n[5a] analyst1 IDOR lab-20261118: $(Format-Resp $analystLabIdor)`n[5a] analyst1 review decide job 201 (syn1-tue): $(Format-Resp $analystRevIdor)")
                Assert-Status $analystIdor 403 "analyst1 미허용 캡처 syn1-tue 차단"
                Assert-Status $analystLabIdor 403 "analyst1 미허용 캡처 lab-20261118 차단"
                Assert-Status $analystRevIdor 403 "analyst1 미허용 캡처 검토 결정(job 201) 차단"

                $analystDetail = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/1" -CookieJar $analystCookies
                Assert-Status $analystDetail 200 "analyst1 인시던트 상세(101/rank/1)"
                Assert-True ($analystDetail.Json.detail.incident.hostIp -eq "192.168.10.50" -and $analystDetail.Json.maskedView -eq $false) "analyst1 허용 인시던트 원문(192.168.10.50) 조회" $analystDetail
                $statusBefore = $analystDetail.Json.detail.currentStatus

                # T21: 시드의 101/rank1은 반영된 승인(zeek_AD 계약)이라 이미 분석 중이다. 분석 중 -> 종결(판정 필수)로 전이를 시험한다.
                $analystTransition = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/1/transition" -Method POST -CookieJar $analystCookies -SaveCookies -Csrf `
                    -JsonBody @{ toStatus = "closed"; resolution = "true_positive"; reason = "PostgreSQL WAF E2E check" }
                $analystDetailAfter = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/1" -CookieJar $analystCookies
                $e2eLogs.Add("[5b] analyst1 POST transition (investigating -> closed): $(Format-Resp $analystTransition)`n     currentStatus before=$statusBefore after=$($analystDetailAfter.Json.detail.currentStatus) resolution=$($analystDetailAfter.Json.detail.currentResolution)")
                Assert-Status $analystTransition 200 "analyst1 상태 전이(investigating -> closed)"
                Assert-True ($statusBefore -eq "investigating" -and $analystTransition.Json.succeeded -eq $true -and $analystDetailAfter.Json.detail.currentStatus -eq "closed" -and $analystDetailAfter.Json.detail.currentResolution -eq "true_positive") "PostgreSQL 17 dashboard.transition_incident 전이 반영" $analystDetailAfter

                $analystRevConfirm = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2/review-decision" -Method POST -CookieJar $analystCookies -SaveCookies -Csrf `
                    -JsonBody @{ action = "confirm"; note = "PG17 decide_review confirm E2E" }
                $analystRank2After = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2" -CookieJar $analystCookies
                $ar2 = $analystRank2After.Json.detail.analystReview
                $e2eLogs.Add("[5d] analyst1 POST /api/incidents/101/rank/2/review-decision (confirm): $(Format-Resp $analystRevConfirm)`n     analystReview.reviewAction=$($ar2.reviewAction) resumeStatusLabel=$($ar2.resumeStatusLabel)")
                Assert-Status $analystRevConfirm 200 "analyst1 검토 결정(confirm)"
                Assert-True ($analystRevConfirm.Json.succeeded -eq $true -and $ar2.reviewAction -eq "confirm" -and $ar2.resumeStatusLabel -eq "반영 중") "PostgreSQL 17 dashboard.decide_review confirm 반영(결정: confirm, 반영 중)" $analystRank2After

                $analystRevDup = Invoke-Http -Url "$baseHttps/api/reviews/decide" -Method POST -CookieJar $analystCookies -SaveCookies -Csrf `
                    -JsonBody @{ jobId = 101; incidentId = "cic17-wed|10.20.30.40|responder|1700000300"; action = "dismiss" }
                $e2eLogs.Add("[5e] analyst1 duplicate POST /api/reviews/decide (SQLSTATE 22023): $(Format-Resp $analystRevDup 400)")
                Assert-ApiError $analystRevDup 409 "CONFLICT" "PostgreSQL 17 decide_review 중복 결정(SQLSTATE 22023) 거부"
                Assert-True ($analystRevDup.Json.succeeded -eq $false -and $analystRevDup.Json.message.Contains("새로고침")) "중복 결정 오류 메시지(새로고침 안내)" $analystRevDup

                $analystOps = Invoke-Http -Url "$baseHttps/api/operations" -CookieJar $analystCookies
                $aCaptures = @($analystOps.Json.feedbackSummaries | ForEach-Object { $_.captureId } | Select-Object -Unique)
                $e2eLogs.Add("[5c-ops] analyst1 GET /api/operations -> HTTP $($analystOps.Status) allowedCaptures=[$(@($analystOps.Json.allowedCaptures) -join ', ')] feedback captures=[$($aCaptures -join ', ')]")
                Assert-Status $analystOps 200 "analyst1 /api/operations"
                Assert-True ($aCaptures.Count -eq 1 -and $aCaptures[0] -eq "cic17-wed") "analyst1 feedback_summary 허용 캡처 격리" $analystOps
                foreach ($forbidden in @("syn1-tue", "lab-20261118", "lab-fusion-v2")) {
                    Assert-True (-not $analystOps.Body.Contains($forbidden)) "analyst1 /api/operations에 '$forbidden' 없음" $analystOps
                }

                # [6] admin: TOTP 전 403, TOTP 뒤 v2.1 다중 작업·상태 승계, 운영 집계 전체, fusion/3, dismiss, PUT 사용자 수정, SPA 셸
                $adminCookies = Join-Path $tmpDir "admin.cookies"
                $adminLogin = Login-Api "admin" $adminCookies
                $e2eLogs.Add("[6a] admin POST /api/auth/login: $(Format-Resp $adminLogin 400)")
                Assert-Status $adminLogin 200 "admin 1차 JSON 로그인"
                Assert-True ($adminLogin.Json.nextRoute -eq "/login/totp" -and $adminLogin.Json.user.totpVerified -eq $false) "admin 1차 로그인 뒤 TOTP 이동(nextRoute=/login/totp)" $adminLogin

                $adminPreTotp = Invoke-Http -Url "$baseHttps/api/incidents" -CookieJar $adminCookies
                $e2eLogs.Add("[6a] admin GET /api/incidents before TOTP: $(Format-Resp $adminPreTotp)")
                Assert-ApiError $adminPreTotp 403 "TOTP_VERIFICATION_REQUIRED" "admin TOTP 전 업무 API"

                $totpCode = Get-TotpCode $adminTotpSecret
                $totpPost = Invoke-Http -Url "$baseHttps/api/auth/totp/verify" -Method POST -CookieJar $adminCookies -SaveCookies -Csrf -JsonBody @{ code = $totpCode }
                $e2eLogs.Add("[6a] admin POST /api/auth/totp/verify: $(Format-Resp $totpPost 300)")
                Assert-Status $totpPost 200 "admin TOTP 2차 인증"
                Assert-True ($totpPost.Json.succeeded -eq $true -and $totpPost.Json.user.totpVerified -eq $true) "admin TOTP 검증 응답" $totpPost

                $labQueue = Invoke-Http -Url "$baseHttps/api/incidents?captureId=lab-20261118" -CookieJar $adminCookies
                Assert-Status $labQueue 200 "admin lab-20261118 인시던트 목록"
                $labItems = @($labQueue.Json.incidents)
                $labR1 = $labItems | Where-Object { $_.queueRank -eq 1 } | Select-Object -First 1
                $labR2 = $labItems | Where-Object { $_.queueRank -eq 2 } | Select-Object -First 1
                $e2eLogs.Add("[6b] admin GET /api/incidents?captureId=lab-20261118 -> HTTP $($labQueue.Status) selectedJob=$($labQueue.Json.selectedJob.jobId) captureJobs=[$(@($labQueue.Json.captureJobs | ForEach-Object { $_.jobId }) -join ', ')] rank1(hasReport=$($labR1.hasReport) reportJob=$($labR1.zeekadReportJobId)) rank2(hasReport=$($labR2.hasReport) reportJob=$($labR2.zeekadReportJobId) reviewPending=$($labR2.zeekadReviewPending) status=$($labR2.zeekadStatus))")
                Assert-True ($labQueue.Json.selectedJob.jobId -eq 502 -and (@($labQueue.Json.captureJobs | ForEach-Object { $_.jobId }) -contains 501)) "v2.1 lab-20261118 최신 큐 job 502" $labQueue
                Assert-True ($labR2.zeekadReportJobId -eq 501 -and $labR2.zeekadReviewPending -eq $true -and $labR1.hasReport -eq $false -and $null -eq $labR1.zeekadReportJobId) "v2.1 보고 작업 501·검토 대기·보고서 없음" $labQueue

                $labRank1 = Invoke-Http -Url "$baseHttps/api/incidents/502/rank/1" -CookieJar $adminCookies
                Assert-Status $labRank1 200 "admin 502/rank/1"
                $e2eLogs.Add("[6b] admin GET /api/incidents/502/rank/1 -> hostIp=$($labRank1.Json.detail.incident.hostIp) report.present=$($labRank1.Json.detail.report.present) zeekadReportJobId=$($labRank1.Json.detail.incident.zeekadReportJobId)")
                Assert-True ($labRank1.Json.detail.incident.hostIp -eq "10.20.0.25" -and $labRank1.Json.detail.report.present -eq $false) "v2.1 zeekad_report_job_id NULL 보고서 없음" $labRank1

                $labRank2 = Invoke-Http -Url "$baseHttps/api/incidents/502/rank/2" -CookieJar $adminCookies
                Assert-Status $labRank2 200 "admin 502/rank/2"
                $lr2 = $labRank2.Json.detail
                $lr2Ratios = @($lr2.modelScores | ForEach-Object { $_.windowRatioLabel })
                $lr2Reasons = @($lr2.statusHistory | ForEach-Object { $_.reason })
                $e2eLogs.Add("[6b] admin GET /api/incidents/502/rank/2 -> zeekadReportJobId=$($lr2.incident.zeekadReportJobId) windowRatioLabel=[$($lr2Ratios -join ', ')] currentStatus=$($lr2.currentStatus) statusHistory=[$(@($lr2.statusHistory | ForEach-Object { "$($_.jobId):$($_.fromStatus)->$($_.toStatus) $($_.reason)" }) -join ' | ')]")
                Assert-True ($lr2.incident.zeekadReportJobId -eq 501 -and ($lr2Ratios -contains "5 / 6") -and $lr2.currentStatus -eq "investigating" -and ($lr2Reasons -contains "실습망 초기 조사 시작")) "v2.1 다중 작업 조인(보고 작업 501, 5 / 6) 및 상태 승계(investigating)" $labRank2

                $labTransition = Invoke-Http -Url "$baseHttps/api/incidents/502/rank/2/transition" -Method POST -CookieJar $adminCookies -SaveCookies -Csrf `
                    -JsonBody @{ toStatus = "closed"; resolution = "true_positive"; reason = "PG17 v2.1 multi-job transition check" }
                $labRank2After = Invoke-Http -Url "$baseHttps/api/incidents/502/rank/2" -CookieJar $adminCookies
                $lr2a = $labRank2After.Json.detail
                $lr2aJobs = @($lr2a.statusHistory | ForEach-Object { $_.jobId } | Select-Object -Unique)
                $e2eLogs.Add("[6c] admin POST /api/incidents/502/rank/2/transition (investigating -> closed, true_positive): $(Format-Resp $labTransition)`n     after currentStatus=$($lr2a.currentStatus) resolution=$($lr2a.currentResolution) statusHistory jobs=[$($lr2aJobs -join ', ')]")
                Assert-Status $labTransition 200 "admin v2.1 상태 전이"
                Assert-True ($lr2a.currentStatus -eq "closed" -and $lr2a.currentResolution -eq "true_positive" -and ($lr2aJobs -contains 501) -and ($lr2aJobs -contains 502)) "v2.1 incident_id 기준 종료 및 이력 합산(501+502)" $labRank2After

                $opsPage = Invoke-Http -Url "$baseHttps/api/operations" -CookieJar $adminCookies
                Assert-Status $opsPage 200 "admin /api/operations"
                $oFeedback = @($opsPage.Json.feedbackSummaries)
                $oCaptures = @($oFeedback | ForEach-Object { $_.captureId } | Select-Object -Unique)
                $oTexts = @($oFeedback | ForEach-Object { $_.precisionSummaryText })
                $oBundles = @($opsPage.Json.bundles | ForEach-Object { $_.bundleId })
                $e2eLogs.Add("[6d-ops] admin GET /api/operations -> HTTP $($opsPage.Status) bundles=[$($oBundles -join ', ')] feedback captures=[$($oCaptures -join ', ')] all rows=$(@($oFeedback | Where-Object { $_.allModel -eq $true }).Count)`n     precisionSummaryText: $(@($oFeedback | ForEach-Object { "$($_.captureId)/$($_.zeekadPickedBy)=$($_.precisionSummaryText)" }) -join ' | ')")
                Assert-True ($oBundles -contains "zeekad-fusion/3") "운영 상태 zeekad-fusion/3 번들" $opsPage
                Assert-True (@($oFeedback | Where-Object { $_.allModel -eq $true -and $_.zeekadPickedBy -eq "all" }).Count -gt 0) "admin feedback_summary 'all' 행" $opsPage
                foreach ($cap in @("cic17-wed", "syn1-tue", "lab-20261118", "lab-fusion-v2")) {
                    Assert-True ($oCaptures -contains $cap) "admin feedback_summary 전체 캡처($cap)" $opsPage
                }
                Assert-True (($oTexts -contains "표본 부족 · 판정 1/2건(50.0%)") -and ($oTexts -contains "표본 부족 · 판정 1/1건(100.0%)")) "admin 정탐률 문장('표본 부족 · 판정 1/2건(50.0%)', '표본 부족 · 판정 1/1건(100.0%)')" $opsPage
                Assert-True (-not $opsPage.Body.Contains("정확도")) "admin /api/operations에 '정확도' 없음" $opsPage

                $fusionDetail = Invoke-Http -Url "$baseHttps/api/incidents/602/rank/1" -CookieJar $adminCookies
                Assert-Status $fusionDetail 200 "admin 602/rank/1"
                $fd = $fusionDetail.Json.detail
                $fdSlackJobs = @($fd.slackDeliveries | ForEach-Object { $_.jobId })
                $e2eLogs.Add("[6d] admin GET /api/incidents/602/rank/1 -> bundleId=$($fd.job.bundleId) zeekadReportJobId=$($fd.incident.zeekadReportJobId) eventStart=$($fd.incident.eventStart) eventEnd=$($fd.incident.eventEnd) slack jobIds=[$($fdSlackJobs -join ', ')]")
                Assert-True ($fd.job.bundleId -eq "zeekad-fusion/3" -and $fd.incident.zeekadReportJobId -eq 602 -and ([string]$fd.incident.eventEnd).StartsWith("2026-11-19T01:45") -and ($fdSlackJobs -contains 601)) "zeekad-fusion/3 45분 사건(보고 작업 602) 및 incident_id 단독 Slack(601)" $fusionDetail

                $adminRevDismiss = Invoke-Http -Url "$baseHttps/api/reviews/decide" -Method POST -CookieJar $adminCookies -SaveCookies -Csrf `
                    -JsonBody @{ jobId = 602; incidentId = "lab-fusion-v2|10.40.0.10|originator|1763514000"; action = "dismiss"; note = "PG17 admin dismiss E2E" }
                $adminRevAfter = Invoke-Http -Url "$baseHttps/api/reviews?captureId=lab-fusion-v2" -CookieJar $adminCookies
                $revItems = @($adminRevAfter.Json.reviews)
                $dismissed = $revItems | Where-Object { $_.incidentId -eq "lab-fusion-v2|10.40.0.10|originator|1763514000" }
                $revLabels = @($revItems | ForEach-Object { $_.resumeStatusLabel })
                $e2eLogs.Add("[6d] admin POST /api/reviews/decide (dismiss): $(Format-Resp $adminRevDismiss)`n     GET /api/reviews?captureId=lab-fusion-v2: $(@($revItems | ForEach-Object { "job=$($_.reviewJobId) rank=$($_.queueRank) action=$($_.zeekadReviewAction) label=$($_.resumeStatusLabel)" }) -join ' | ')")
                Assert-Status $adminRevDismiss 200 "admin /api/reviews/decide dismiss"
                Assert-True (@($dismissed).Count -eq 1 -and $dismissed.zeekadReviewAction -eq "dismiss" -and $dismissed.reviewJobId -eq 602) "admin dismiss 결정 반영(최신 작업 602 한 건)" $adminRevAfter
                Assert-True (($revLabels -contains "반영 중") -and ($revLabels -contains "반영 실패(관리자 확인 필요)")) "검토 반영 상태 라벨(반영 중, 반영 실패(관리자 확인 필요))" $adminRevAfter
                Assert-True (@($revItems | Where-Object { $_.reviewJobId -eq 601 -or $_.jobId -eq 601 }).Count -eq 0 -and -not $adminRevAfter.Body.Contains("구 작업(601) 중복 검토 요청")) "구 작업(601) 중복 검토 요청 제거" $adminRevAfter

                # WAF를 거친 PUT /api/admin/users/{id}: GET 결과의 id·role·capturePatterns를 그대로 쓰고 displayName만 바꾼다.
                $usersRes = Invoke-Http -Url "$baseHttps/api/admin/users" -CookieJar $adminCookies
                Assert-Status $usersRes 200 "admin GET /api/admin/users"
                $analyst2 = @($usersRes.Json.users | Where-Object { $_.username -eq "analyst2" }) | Select-Object -First 1
                Assert-True ($null -ne $analyst2 -and @($analyst2.capturePatterns).Count -gt 0) "analyst2 사용자·capturePatterns 조회" $usersRes
                $newDisplayName = "분석가 2 (E2E $(Get-Random -Minimum 100 -Maximum 999))"
                $putBody = [ordered]@{ displayName = $newDisplayName; role = $analyst2.role; capturePatterns = @($analyst2.capturePatterns) }
                $putRes = Invoke-Http -Url "$baseHttps/api/admin/users/$($analyst2.id)" -Method PUT -CookieJar $adminCookies -SaveCookies -Csrf -JsonBody $putBody -ProbeId "e2e-put-user"
                $e2eLogs.Add("[6e] admin PUT /api/admin/users/$($analyst2.id) via WAF (role=$($analyst2.role) capturePatterns=[$(@($analyst2.capturePatterns) -join ', ')]): $(Format-Resp $putRes 400)")
                Assert-Status $putRes 200 "WAF를 거친 PUT /api/admin/users/{id}"
                Assert-True ($putRes.Json.user.displayName -eq $newDisplayName -and $putRes.Json.user.role -eq $analyst2.role) "PUT 사용자 수정 응답" $putRes
                $auditRes = Invoke-Http -Url "$baseHttps/api/admin/audit-logs?actionType=USER_ADMIN_CHANGE&limit=20" -CookieJar $adminCookies
                $userAudit = @($auditRes.Json.logs | Where-Object { $_.actionType -eq "USER_ADMIN_CHANGE" -and $_.actorUsername -eq "admin" -and $_.detailJson -match '"targetUsername":"analyst2"' -and $_.detailJson -match '"operation":"UPDATE_USER"' })
                $e2eLogs.Add("[6e] admin GET /api/admin/audit-logs?actionType=USER_ADMIN_CHANGE -> HTTP $($auditRes.Status) matching=$($userAudit.Count) latest=$(if ($userAudit.Count) { "$($userAudit[0].occurredAt) $($userAudit[0].detailJson)" })")
                Assert-Status $auditRes 200 "admin 감사 로그 조회"
                Assert-True ($userAudit.Count -gt 0) "감사 로그 USER_ADMIN_CHANGE(UPDATE_USER analyst2)" $auditRes

                foreach ($spaPath in @("/", "/incidents/101/rank/1", "/admin/users")) {
                    $spaRes = Invoke-Http -Url "$baseHttps$spaPath" -CookieJar $adminCookies
                    $e2eLogs.Add("[6f] admin(TOTP verified) GET $spaPath -> HTTP $($spaRes.Status) Content-Type=$(Get-HeaderValue $spaRes 'Content-Type') SPA shell=$(Test-SpaShell $spaRes)")
                    Assert-Status $spaRes 200 "admin GET $spaPath"
                    Assert-True (Test-SpaShell $spaRes) "admin GET $spaPath SPA 셸 표지" $spaRes
                }

                # [7] 로그아웃 뒤 서버 쪽 세션 무효화: 로그아웃 전 세션 값을 직접 보내 401 확인
                $savedSession = Get-JarCookie $adminCookies "ZEEKAD_SESSION"
                Assert-True ([bool]$savedSession) "로그아웃 전 ZEEKAD_SESSION 값 저장"
                $logoutRes = Invoke-Http -Url "$baseHttps/api/auth/logout" -Method POST -CookieJar $adminCookies -SaveCookies -Csrf
                $replayRes = Invoke-Http -Url "$baseHttps/api/incidents" -RawCookie "ZEEKAD_SESSION=$savedSession"
                $e2eLogs.Add("[7] admin POST /api/auth/logout: $(Format-Resp $logoutRes)`n[7] replay saved ZEEKAD_SESSION (value redacted) GET /api/incidents: $(Format-Resp $replayRes)")
                Assert-Status $logoutRes 200 "POST /api/auth/logout"
                Assert-ApiError $replayRes 401 "UNAUTHENTICATED" "로그아웃 뒤 이전 세션 재사용"

                # [8] PostgreSQL audit_logs 불변 트리거 실증 (UPDATE 시도 실패)
                $immutableRes = Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "verify-postgres", "psql", "-U", "postgres", "-d", "zeekad_dashboard", "-c", "UPDATE audit_logs SET action_type = 'TAMPERED' WHERE id = (SELECT MIN(id) FROM audit_logs);")) -IgnoreExitCode
                $immutableCheck = $immutableRes.Output
                $e2eLogs.Add("[8] PostgreSQL audit_logs immutable trigger check:`n$($immutableCheck.Trim())")
                Assert-True ($immutableCheck -match "audit_logs is append-only") "PostgreSQL audit_logs 불변 트리거"

                # [9] 클라이언트 IP·전달 헤더 위조(T14): 방문자가 붙인 X-Real-IP·X-Forwarded-For·Forwarded·X-Forwarded-Host/Prefix가
                #     감사 로그 client_ip, 리다이렉트 Location, ModSecurity 기록 IP를 바꾸지 못해야 한다.
                #     감사 로그는 verify-postgres에서 읽기 전용 SELECT로 보고, 기준 id 뒤의 viewer1 행을 id 순으로 각 요청과 짝짓는다.
                #     관측값을 모두 기록한 다음에 단언한다(실패해도 어떤 헤더가 통했는지 남는다).
                function Invoke-AuditSelect([string]$Sql) {
                    return (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "verify-postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "zeekad_dashboard", "-AtF", "|", "-c", $Sql))).Output.Trim()
                }
                function Test-DocRangeIp([string]$Ip) { return ($Ip -match '^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$') }
                $script:auditCursor = [long](Invoke-AuditSelect "SELECT COALESCE(MAX(id),0) FROM audit_logs")
                $e2eLogs.Add("[9] audit_logs base id (before [9]) = $($script:auditCursor)")
                function Get-NewViewerAudit {
                    $out = Invoke-AuditSelect "SELECT id, action_type, COALESCE(client_ip,'') FROM audit_logs WHERE id > $($script:auditCursor) AND actor_username = 'viewer1' ORDER BY id"
                    $rows = @($out -split "`r?`n" | Where-Object { $_ } | ForEach-Object {
                        $p = $_ -split '\|'
                        [pscustomobject]@{ Id = [long]$p[0]; Action = $p[1]; ClientIp = $p[2] }
                    })
                    if ($rows.Count) { $script:auditCursor = $rows[-1].Id }
                    return $rows
                }
                $script:ip9Seq = 0
                function Invoke-Ip9Login([string]$Label, [string[]]$Headers, [string]$Password) {
                    $script:ip9Seq++
                    $jar = Join-Path $tmpDir "ip9-$($script:ip9Seq).cookies"
                    # CSRF 토큰은 전달 헤더 없이 받는다(위조 헤더가 쿠키 경로 등을 바꿔 로그인 자체를 막는 일을 피한다).
                    $csrfRes = Invoke-Http -Url "$baseHttps/api/auth/csrf" -CookieJar $jar -SaveCookies
                    $res = Invoke-Http -Url "$baseHttps/api/auth/login" -Method POST -CookieJar $jar -SaveCookies -Csrf `
                        -JsonBody @{ username = "viewer1"; password = $Password } -ExtraHeaders $Headers
                    $rows = @(Get-NewViewerAudit)
                    return [pscustomobject]@{ Label = $Label; Headers = $Headers; CsrfStatus = $csrfRes.Status; Status = $res.Status; Rows = $rows }
                }
                function Format-Ip9Rows($Rows) {
                    if (-not $Rows.Count) { return "(no viewer1 audit row)" }
                    return (($Rows | ForEach-Object { "#$($_.Id) $($_.Action) client_ip=$($_.ClientIp)" }) -join "; ")
                }

                # 9a 기준
                $ip9Base = Invoke-Ip9Login "9a baseline (no forwarding headers)" @() $bootstrapPwd
                $ip9BaseRow = @($ip9Base.Rows | Where-Object { $_.Action -eq "LOGIN_SUCCESS" }) | Select-Object -Last 1
                $ipB = if ($ip9BaseRow) { $ip9BaseRow.ClientIp } else { "" }
                $e2eLogs.Add("[9a] viewer1 login without forwarding headers -> HTTP $($ip9Base.Status); audit: $(Format-Ip9Rows $ip9Base.Rows); B=$ipB")

                # 9b 헤더 하나씩(IP 계열) + 조합
                $ip9Combined = @("X-Real-IP: 203.0.113.7", "X-Forwarded-For: 198.51.100.8", "Forwarded: for=192.0.2.9", "X-Forwarded-Host: evil.example", "X-Forwarded-Prefix: /evil")
                $ip9Cases = @(
                    @{ Label = "9b X-Real-IP only"; Headers = @("X-Real-IP: 203.0.113.7"); Single = $true },
                    @{ Label = "9b X-Forwarded-For only"; Headers = @("X-Forwarded-For: 198.51.100.8"); Single = $true },
                    @{ Label = "9b Forwarded: for= only"; Headers = @("Forwarded: for=192.0.2.9"); Single = $true },
                    @{ Label = "9b combined (3 IP headers + X-Forwarded-Host + X-Forwarded-Prefix)"; Headers = $ip9Combined; Single = $false }
                )
                $ip9Results = [System.Collections.Generic.List[object]]::new()
                $ip9SpoofWorked = 0
                $ip9Undecided = 0
                foreach ($case in $ip9Cases) {
                    $r = Invoke-Ip9Login $case.Label $case.Headers $bootstrapPwd
                    $okRow = @($r.Rows | Where-Object { $_.Action -eq "LOGIN_SUCCESS" }) | Select-Object -Last 1
                    $ip = if ($okRow) { $okRow.ClientIp } else { "" }
                    $verdict = if ($r.Status -ne 200) { "UNDECIDED(login HTTP $($r.Status))" }
                        elseif (-not $okRow) { "UNDECIDED(no LOGIN_SUCCESS row)" }
                        elseif ($ip -eq $ipB) { "NOT_SPOOFED(=B)" }
                        elseif (Test-DocRangeIp $ip) { "SPOOFED($ip)" }
                        else { "DIFFERENT_FROM_B($ip)" }
                    if ($case.Single -and $verdict.StartsWith("SPOOFED")) { $ip9SpoofWorked++ }
                    if ($case.Single -and $verdict.StartsWith("UNDECIDED")) { $ip9Undecided++ }
                    $ip9Results.Add([pscustomobject]@{ Label = $case.Label; Status = $r.Status; Ip = $ip; Verdict = $verdict })
                    $e2eLogs.Add("[$($case.Label)] headers=[$($case.Headers -join ' | ')] -> csrf HTTP $($r.CsrfStatus), login HTTP $($r.Status); audit: $(Format-Ip9Rows $r.Rows); verdict=$verdict")
                }
                $e2eLogs.Add("[9b] summary: IP-header single requests spoofed=$ip9SpoofWorked undecided=$ip9Undecided (of 3)")

                # 9c 위조 헤더 + 틀린 비밀번호 1회(잠금 한도 5회에 닿지 않게)
                $ip9Fail = Invoke-Ip9Login "9c combined headers, wrong password" $ip9Combined "wrong-$(New-RandomToken 8)"
                $failRow = @($ip9Fail.Rows | Where-Object { $_.Action -eq "LOGIN_FAILURE" }) | Select-Object -Last 1
                $failIp = if ($failRow) { $failRow.ClientIp } else { "" }
                $e2eLogs.Add("[9c] viewer1 wrong password with combined headers -> HTTP $($ip9Fail.Status); audit: $(Format-Ip9Rows $ip9Fail.Rows)")

                # 9d 비인증 리다이렉트 Location(호스트·경로 위조 단독)
                $redirBase = Invoke-Http -Url "$baseHttps/incidents"
                $redirBaseLoc = Get-HeaderValue $redirBase "Location"
                $e2eLogs.Add("[9d] unauthenticated GET /incidents (no forwarding headers) -> HTTP $($redirBase.Status) Location=$redirBaseLoc")
                $redirResults = [System.Collections.Generic.List[object]]::new()
                foreach ($h in @("X-Forwarded-Host: evil.example", "Forwarded: host=evil.example;proto=http", "X-Forwarded-Prefix: /evil")) {
                    $rr = Invoke-Http -Url "$baseHttps/incidents" -ExtraHeaders @($h)
                    $rrLoc = Get-HeaderValue $rr "Location"
                    $redirResults.Add([pscustomobject]@{ Header = $h; Status = $rr.Status; Location = $rrLoc })
                    $e2eLogs.Add("[9d] unauthenticated GET /incidents with '$h' -> HTTP $($rr.Status) Location=$rrLoc")
                }

                # 9e 조합 헤더를 붙인 WAF 차단 요청의 ModSecurity 기록 IP
                $wafIpEvidence = ""
                $wafIpError = ""
                try {
                    $wafIpRes = Invoke-Http -Url "$baseHttps/api/incidents?asset=%27%20OR%201%3D1--" -ProbeId "e2e-ip9-sqli" -ExtraHeaders $ip9Combined
                    $wafIpEvidence = Assert-WafBlocked $wafIpRes "e2e-ip9-sqli" "WAF query SQLi with forged forwarding headers"
                } catch { $wafIpError = $_.Exception.Message }
                $wafLogIp = [regex]::Match($wafIpEvidence, 'client_ip=(\S+)').Groups[1].Value
                $e2eLogs.Add("[9e] WAF block with combined forged headers: $(if ($wafIpEvidence) { $wafIpEvidence } else { "ERROR $wafIpError" }); ModSecurity client_ip=$wafLogIp")

                # 단언(관측값 기록 뒤)
                Assert-Status $ip9Base 200 "[9a] 전달 헤더 없는 viewer1 로그인"
                Assert-True ([bool]$ipB -and -not (Test-DocRangeIp $ipB)) "[9a] 기준 IP B가 있고 문서용 대역이 아님 (B=$ipB)"
                foreach ($res9 in $ip9Results) {
                    Assert-True ($res9.Status -eq 200 -and $res9.Ip -eq $ipB) "[$($res9.Label)] 로그인 200이고 감사 로그 client_ip=B (실제 HTTP $($res9.Status), client_ip=$($res9.Ip), B=$ipB)"
                }
                Assert-True ($ip9Fail.Status -eq 401 -and $failIp -eq $ipB) "[9c] 위조 헤더 실패 로그인 401이고 LOGIN_FAILURE client_ip=B (실제 HTTP $($ip9Fail.Status), client_ip=$failIp)"
                Assert-Status $redirBase 302 "[9d] 비인증 GET /incidents"
                foreach ($rr in $redirResults) {
                    Assert-True ($rr.Status -eq 302 -and $rr.Location -eq $redirBaseLoc -and $rr.Location -notmatch 'evil') "[9d] '$($rr.Header)' Location이 헤더 없는 Location과 같고 evil 없음 (실제 $($rr.Status) $($rr.Location))"
                }
                Assert-True (-not $wafIpError) "[9e] 조합 헤더 WAF 차단 확인 ($wafIpError)"
                Assert-True ($wafLogIp -eq $ipB) "[9e] ModSecurity 감사 로그 client_ip=B (실제 $wafLogIp, B=$ipB)"

                # [10] 통합 인시던트 큐(T23): 허용 캡처만, VIEWER 마스킹·자산 검색(가려진 값에만, PostgreSQL 실측),
                #      허용 밖 captureId·jobId 403, 쪽 이음 = 정렬 결과, 서버 우선순위 = 옛 규칙(PostgreSQL cardinality),
                #      new-count·neighbors·time-context 200. 기존 절은 작업 단위 API(/api/incidents?captureId=…)로 그대로 돈다.
                function Get-UnmaskedIpv4([string]$Text) {
                    return @([regex]::Matches($Text, '(?<![0-9.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![0-9.])') | Where-Object {
                        [int]$_.Groups[1].Value -le 255 -and [int]$_.Groups[2].Value -le 255 -and [int]$_.Groups[3].Value -le 255 -and [int]$_.Groups[4].Value -le 255
                    } | ForEach-Object { $_.Value })
                }
                function Get-RefPriority($It) {
                    $s = ([string]$It.zeekadStatus).Trim().ToLowerInvariant()
                    if (-not $s) { $s = 'open' }
                    if ($s -eq 'closed') { return '' }
                    if ($It.zeekadWouldSend -eq $true -or $It.zeekadReviewPending -eq $true) { return 'high' }
                    if (@($It.zeekadAlsoFlaggedBy | Where-Object { $_ }).Count -ge 1 -or $It.hasReport -eq $true) { return 'medium' }
                    return 'low'
                }
                function Get-QueueKeys([string]$Jar, [string]$Query, [int]$Size) {
                    $keys = [System.Collections.Generic.List[string]]::new()
                    $first = Invoke-Http -Url "$baseHttps/api/incidents/queue?$Query&size=$Size&page=1" -CookieJar $Jar
                    Assert-Status $first 200 "queue $Query size=$Size page=1"
                    $pages = [int]$first.Json.pageCount
                    for ($p = 1; $p -le $pages; $p++) {
                        $res = if ($p -eq 1) { $first } else { Invoke-Http -Url "$baseHttps/api/incidents/queue?$Query&size=$Size&page=$p" -CookieJar $Jar }
                        Assert-Status $res 200 "queue $Query size=$Size page=$p"
                        foreach ($it in @($res.Json.items)) { $keys.Add("$($it.jobId)/$($it.queueRank)") }
                    }
                    return [pscustomobject]@{ Keys = $keys; Total = [int]$first.Json.total }
                }

                $q10Viewer = Join-Path $tmpDir "q10-viewer.cookies"
                Assert-Status (Login-Api "viewer1" $q10Viewer) 200 "[10] viewer1 로그인"
                $q10Analyst = Join-Path $tmpDir "q10-analyst.cookies"
                Assert-Status (Login-Api "analyst1" $q10Analyst) 200 "[10] analyst1 로그인"

                $vq = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&size=100" -CookieJar $q10Viewer
                $vqCaps = @($vq.Json.items | ForEach-Object { $_.captureId } | Select-Object -Unique)
                $vqSources = @($vq.Json.sources | ForEach-Object { "$($_.captureId):$($_.sourceType):$($_.latestJobId)" })
                $vqUnmasked = Get-UnmaskedIpv4 $vq.Body
                $e2eLogs.Add("[10a] viewer1 GET /api/incidents/queue?period=all&size=100 -> HTTP $($vq.Status) total=$($vq.Json.total) items=$(@($vq.Json.items).Count) captures=[$($vqCaps -join ', ')] sources=[$($vqSources -join ', ')] maskedView=$($vq.Json.maskedView) anchorMode=$($vq.Json.anchorMode) snapshot=$($vq.Json.snapshot) unmaskedIPv4=$($vqUnmasked.Count) hostIp=[$(@($vq.Json.items | ForEach-Object { $_.hostIp }) -join ', ')]")
                Assert-Status $vq 200 "[10a] viewer1 통합 큐"
                Assert-True ($vq.Json.maskedView -eq $true -and @($vq.Json.items).Count -eq [int]$vq.Json.total -and [int]$vq.Json.total -gt 0) "[10a] viewer1 통합 큐 마스킹·건수" $vq
                Assert-True (@($vqCaps | Where-Object { $_ -notlike 'cic17-*' }).Count -eq 0 -and @($vq.Json.sources | Where-Object { $_.captureId -notlike 'cic17-*' }).Count -eq 0) "[10a] viewer1 통합 큐에 허용 캡처(cic17-*)만" $vq
                Assert-True ($vqUnmasked.Count -eq 0) "[10a] viewer1 통합 큐 응답에 가려지지 않은 IPv4 0건 (찾음: $($vqUnmasked -join ', '))" $vq
                Assert-True ($vq.Json.anchorMode -eq 'now' -and $vq.Json.snapshot -eq $false) "[10a] VMware 스택 기준 시각 now" $vq

                $vAssetTail = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&asset=10.50" -CookieJar $q10Viewer
                $vAssetTail2 = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&asset=.10.50" -CookieJar $q10Viewer
                $vAssetHead = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&asset=192.168" -CookieJar $q10Viewer
                $vAssetName = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&asset=dc01.corp" -CookieJar $q10Viewer
                $vNewTail = Invoke-Http -Url "$baseHttps/api/incidents/queue/new-count?since=2000-01-01T00:00:00Z&asset=10.50" -CookieJar $q10Viewer
                $aAssetTail = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&asset=10.50" -CookieJar $q10Analyst
                $e2eLogs.Add("[10b] viewer1 asset=10.50 (real tail octets of 192.168.10.50) -> HTTP $($vAssetTail.Status) total=$($vAssetTail.Json.total); asset=.10.50 -> total=$($vAssetTail2.Json.total); new-count asset=10.50 -> count=$($vNewTail.Json.count)`n      viewer1 asset=192.168 (masked head) -> total=$($vAssetHead.Json.total) hostIp=[$(@($vAssetHead.Json.items | ForEach-Object { $_.hostIp }) -join ', ')]; asset=dc01.corp (host name) -> total=$($vAssetName.Json.total)`n      analyst1 asset=10.50 (unmasked) -> total=$($aAssetTail.Json.total)")
                Assert-True ($vAssetTail.Status -eq 200 -and [int]$vAssetTail.Json.total -eq 0) "[10b] viewer1 실제 IP 뒤 두 옥텟(10.50) 검색 0건 (PostgreSQL)" $vAssetTail
                Assert-True ($vAssetTail2.Status -eq 200 -and [int]$vAssetTail2.Json.total -eq 0) "[10b] viewer1 .10.50 검색 0건" $vAssetTail2
                Assert-True ($vNewTail.Status -eq 200 -and [int]$vNewTail.Json.count -eq 0) "[10b] viewer1 new-count 자산 검색도 가려진 값에만" $vNewTail
                Assert-True ($vAssetHead.Status -eq 200 -and [int]$vAssetHead.Json.total -ge 1 -and @($vAssetHead.Json.items | Where-Object { $_.hostIp -notlike '192.168.*' }).Count -eq 0 -and (Get-UnmaskedIpv4 $vAssetHead.Body).Count -eq 0) "[10b] viewer1 가려진 앞부분(192.168) 검색" $vAssetHead
                Assert-True ($vAssetName.Status -eq 200 -and [int]$vAssetName.Json.total -eq 1) "[10b] viewer1 호스트 이름(dc01.corp) 검색" $vAssetName
                Assert-True ($aAssetTail.Status -eq 200 -and [int]$aAssetTail.Json.total -ge 1) "[10b] analyst1 원문 IP 뒤 두 옥텟 검색은 찾아짐" $aAssetTail

                $vDenyQ = Invoke-Http -Url "$baseHttps/api/incidents/queue?captureId=syn1-tue" -CookieJar $q10Viewer
                $vDenyN = Invoke-Http -Url "$baseHttps/api/incidents/queue/new-count?captureId=syn1-tue&since=2000-01-01T00:00:00Z" -CookieJar $q10Viewer
                $vDenyNb = Invoke-Http -Url "$baseHttps/api/incidents/queue/neighbors?jobId=201&queueRank=1" -CookieJar $q10Viewer
                $aDenyQ = Invoke-Http -Url "$baseHttps/api/incidents/queue?captureId=lab-20261118" -CookieJar $q10Analyst
                $e2eLogs.Add("[10c] viewer1 queue captureId=syn1-tue: $(Format-Resp $vDenyQ 120)`n      viewer1 new-count captureId=syn1-tue: $(Format-Resp $vDenyN 120)`n      viewer1 neighbors jobId=201 (syn1-tue): $(Format-Resp $vDenyNb 120)`n      analyst1 queue captureId=lab-20261118: $(Format-Resp $aDenyQ 120)")
                Assert-Status $vDenyQ 403 "[10c] viewer1 통합 큐 허용 밖 captureId"
                Assert-Status $vDenyN 403 "[10c] viewer1 new-count 허용 밖 captureId"
                Assert-Status $vDenyNb 403 "[10c] viewer1 neighbors 허용 밖 jobId"
                Assert-Status $aDenyQ 403 "[10c] analyst1 통합 큐 허용 밖 captureId"
                $idor10 = Invoke-AuditSelect "SELECT COUNT(*) FROM audit_logs WHERE action_type = 'ACCESS_DENIED_IDOR' AND id > $($script:auditCursor) AND actor_username IN ('viewer1','analyst1')"
                $e2eLogs.Add("[10c] ACCESS_DENIED_IDOR audit rows since [9] for viewer1/analyst1 = $idor10")
                Assert-True ([int]$idor10 -ge 4) "[10c] 허용 밖 요청 4건 IDOR 감사 기록 (실제 $idor10)"

                $aq = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&size=100" -CookieJar $q10Analyst
                $prioRows = @($aq.Json.items | ForEach-Object { "$($_.jobId)/$($_.queueRank) status=$($_.zeekadStatus) send=$($_.zeekadWouldSend) pending=$($_.zeekadReviewPending) also=$(@($_.zeekadAlsoFlaggedBy).Count) report=$($_.hasReport) -> server=$($_.priority) ref=$(Get-RefPriority $_)" })
                $prioMismatch = @($aq.Json.items | Where-Object { ([string]$_.priority) -ne (Get-RefPriority $_) })
                $e2eLogs.Add("[10d] analyst1 GET /api/incidents/queue?period=all -> HTTP $($aq.Status) total=$($aq.Json.total) summary=$($aq.Json.summary | ConvertTo-Json -Compress)`n      server priority vs old rule (PostgreSQL cardinality):`n      $($prioRows -join "`n      ")")
                Assert-Status $aq 200 "[10d] analyst1 통합 큐"
                Assert-True (@($aq.Json.items | Where-Object { $_.captureId -notlike 'cic17-*' }).Count -eq 0) "[10d] analyst1 통합 큐 허용 캡처만" $aq
                Assert-True ($prioMismatch.Count -eq 0) "[10d] PostgreSQL 서버 우선순위 = 옛 화면 규칙 (불일치 $($prioMismatch.Count))" $aq
                Assert-True ([int]$aq.Json.summary.total -eq [int]$aq.Json.total) "[10d] 띠 거르기 없으면 summary.total = total" $aq
                foreach ($sort in @('priority', 'detected', 'start', 'connections', 'status')) {
                    foreach ($dir in @('asc', 'desc')) {
                        $small = Get-QueueKeys $q10Analyst "period=all&sort=$sort&dir=$dir" 25
                        $big = Get-QueueKeys $q10Analyst "period=all&sort=$sort&dir=$dir" 100
                        $same = (($small.Keys -join ',') -eq ($big.Keys -join ','))
                        $dups = @($small.Keys | Group-Object | Where-Object { $_.Count -gt 1 }).Count
                        $e2eLogs.Add("[10d] page join sort=$sort dir=$dir size25=[$($small.Keys -join ',')] size100=[$($big.Keys -join ',')] total=$($small.Total) same=$same dups=$dups")
                        Assert-True ($same -and $dups -eq 0 -and $small.Keys.Count -eq $small.Total) "[10d] 쪽 이음 = 정렬 결과 (sort=$sort dir=$dir)"
                    }
                }

                foreach ($who in @(@{ Name = 'viewer1'; Jar = $q10Viewer }, @{ Name = 'analyst1'; Jar = $q10Analyst })) {
                    $nc = Invoke-Http -Url "$baseHttps/api/incidents/queue/new-count?since=2000-01-01T00:00:00Z" -CookieJar $who.Jar
                    $tc = Invoke-Http -Url "$baseHttps/api/time-context" -CookieJar $who.Jar
                    $firstItem = @((Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&size=25" -CookieJar $who.Jar).Json.items)[0]
                    $nb = Invoke-Http -Url "$baseHttps/api/incidents/queue/neighbors?jobId=$($firstItem.jobId)&queueRank=$($firstItem.queueRank)&period=all" -CookieJar $who.Jar
                    $e2eLogs.Add("[10e] $($who.Name) new-count: $(Format-Resp $nc 200)`n      time-context: $(Format-Resp $tc 200)`n      neighbors($($firstItem.jobId)/$($firstItem.queueRank)): $(Format-Resp $nb 300)")
                    Assert-Status $nc 200 "[10e] $($who.Name) new-count"
                    Assert-Status $tc 200 "[10e] $($who.Name) time-context"
                    Assert-Status $nb 200 "[10e] $($who.Name) neighbors"
                    Assert-True ([int]$nb.Json.position -eq 1 -and $null -eq $nb.Json.prev -and [int]$nb.Json.current.jobId -eq [int]$firstItem.jobId) "[10e] $($who.Name) neighbors 첫 행 위치 1" $nb
                    if ($who.Name -eq 'viewer1') {
                        Assert-True ((Get-UnmaskedIpv4 $nb.Body).Count -eq 0 -and (Get-UnmaskedIpv4 $nc.Body).Count -eq 0) "[10e] viewer1 neighbors·new-count 응답에 가려지지 않은 IPv4 없음" $nb
                    }
                }

                # [11] 현황판 overview·운영 현황 기간·수집원(T24): 기간 다섯 × 수집원 조건에서 불변식(구간 합 + unbucketed = 큐 total = 캡처 행 합,
                #      센서 = 그 캡처 합)을 PostgreSQL에서 확인한다. 허용 밖 captureId 403·감사, VIEWER 응답(overview·operations·큐)에
                #      숨긴 캡처 문자열·가려지지 않은 IPv4 없음, /api/operations?period= 거르기.
                #      작업 오류 글 마스킹을 실제로 보려고 검증 스택 DB(zeekad, 검증용 시드)에 IP가 든 실패 작업 하나를 넣는다(지금-10분).
                $t24Job = 9100
                $insJob = Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "verify-postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "zeekad", "-c",
                    "INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) VALUES ($t24Job, 'cic17-wed', 'zeekad-fusion/1', 'failed', now() - interval '11 minutes', now() - interval '10 minutes', 'connect to 192.168.10.50:5432 refused', 0)"))
                $e2eLogs.Add("[11] inserted failed job $t24Job (cic17-wed, error with IP) into verify zeekad DB: $($insJob.Output.Trim())")
                $q11Viewer = Join-Path $tmpDir "q11-viewer.cookies"
                Assert-Status (Login-Api "viewer1" $q11Viewer) 200 "[11] viewer1 로그인"
                $q11Analyst = Join-Path $tmpDir "q11-analyst.cookies"
                Assert-Status (Login-Api "analyst1" $q11Analyst) 200 "[11] analyst1 로그인"
                $hiddenMarkers = @('syn1-', 'lab-', 'zeekad-fusion/2', 'zeekad-fusion/3')

                # [11a] 불변식: 기간 다섯 × 수집원(all·live·imported·캡처 하나), viewer1·analyst1
                $invLines = [System.Collections.Generic.List[string]]::new()
                $invFail = [System.Collections.Generic.List[string]]::new()
                foreach ($who in @(@{ Name = 'viewer1'; Jar = $q11Viewer }, @{ Name = 'analyst1'; Jar = $q11Analyst })) {
                    foreach ($period in @('1h', '24h', '7d', '30d', 'all')) {
                        foreach ($cond in @('', '&source=live', '&source=imported', '&captureId=cic17-wed')) {
                            $q = "period=$period$cond"
                            $ov = Invoke-Http -Url "$baseHttps/api/dashboard/overview?$q" -CookieJar $who.Jar
                            $qq = Invoke-Http -Url "$baseHttps/api/incidents/queue?$q&size=25" -CookieJar $who.Jar
                            Assert-Status $ov 200 "[11a] $($who.Name) overview $q"
                            Assert-Status $qq 200 "[11a] $($who.Name) queue $q"
                            $bucketSum = 0
                            foreach ($b in @($ov.Json.trend.buckets)) {
                                $parts = [int]$b.high + [int]$b.medium + [int]$b.low + [int]$b.none
                                if ($parts -ne [int]$b.total) { $invFail.Add("$($who.Name) $q bucket $($b.end) parts=$parts total=$($b.total)") }
                                $bucketSum += $parts
                            }
                            $unb = [int]$ov.Json.trend.unbucketed.noDetectedAt + [int]$ov.Json.trend.unbucketed.afterAnchor
                            $capSum = 0
                            $bySensor = @{}
                            foreach ($c in @($ov.Json.captures)) {
                                $capSum += [int]$c.total
                                if ($c.sensorKey) { $bySensor[$c.sensorKey] = [int]$bySensor[$c.sensorKey] + [int]$c.total }
                            }
                            $qTotal = [int]$qq.Json.summary.total
                            $sensorText = @($ov.Json.sensors | ForEach-Object { "$($_.sensorKey)=$($_.total)/$($_.health)" }) -join ','
                            foreach ($s in @($ov.Json.sensors)) {
                                if ([int]$s.total -ne [int]$bySensor[$s.sensorKey]) { $invFail.Add("$($who.Name) $q sensor $($s.sensorKey) $($s.total) != $($bySensor[$s.sensorKey])") }
                            }
                            if (($bucketSum + $unb) -ne $qTotal -or $capSum -ne $qTotal) { $invFail.Add("$($who.Name) $q buckets=$bucketSum unbucketed=$unb captures=$capSum queue=$qTotal") }
                            $invLines.Add("$($who.Name) $q -> buckets=$(@($ov.Json.trend.buckets).Count)($($ov.Json.trend.bucket)) sum=$bucketSum unbucketed=$unb captures=$capSum queue.summary.total=$qTotal sensors=[$sensorText] anchorMode=$($ov.Json.anchorMode)")
                            if ($who.Name -eq 'viewer1') {
                                foreach ($body in @($ov.Body, $qq.Body)) {
                                    foreach ($m in $hiddenMarkers) { if ($body.Contains($m)) { $invFail.Add("viewer1 $q response contains hidden marker '$m'") } }
                                    $ipHit = Get-UnmaskedIpv4 $body
                                    if ($ipHit.Count) { $invFail.Add("viewer1 $q unmasked IPv4: $($ipHit -join ', ')") }
                                }
                            }
                        }
                    }
                }
                $e2eLogs.Add("[11a] overview invariants (PostgreSQL):`n      $($invLines -join "`n      ")`n      failures=$($invFail.Count)$(if ($invFail.Count) { "`n      " + ($invFail -join "`n      ") })")
                Assert-True ($invFail.Count -eq 0) "[11a] 구간 합 + unbucketed = 큐 total = 캡처 행 합, 센서 = 캡처 합, viewer1 숨김·IPv4 0 (실패 $($invFail.Count))"

                # [11b] 허용 밖 captureId 403·IDOR 감사, 잘못된 period 400
                $idorBase11 = [int](Invoke-AuditSelect "SELECT count(*) FROM audit_logs WHERE action_type = 'ACCESS_DENIED_IDOR' AND actor_username IN ('viewer1','analyst1')")
                $d1 = Invoke-Http -Url "$baseHttps/api/dashboard/overview?period=24h&captureId=syn1-tue" -CookieJar $q11Viewer
                $d2 = Invoke-Http -Url "$baseHttps/api/operations?period=7d&captureId=lab-20261118" -CookieJar $q11Viewer
                $d3 = Invoke-Http -Url "$baseHttps/api/dashboard/overview?period=all&captureId=lab-fusion-v2" -CookieJar $q11Analyst
                $bad = Invoke-Http -Url "$baseHttps/api/dashboard/overview?period=2d" -CookieJar $q11Viewer
                $idorAfter11 = [int](Invoke-AuditSelect "SELECT count(*) FROM audit_logs WHERE action_type = 'ACCESS_DENIED_IDOR' AND actor_username IN ('viewer1','analyst1')")
                $e2eLogs.Add("[11b] viewer1 overview captureId=syn1-tue: $(Format-Resp $d1 120)`n      viewer1 operations captureId=lab-20261118: $(Format-Resp $d2 120)`n      analyst1 overview captureId=lab-fusion-v2: $(Format-Resp $d3 120)`n      viewer1 overview period=2d: $(Format-Resp $bad 160)`n      ACCESS_DENIED_IDOR rows viewer1/analyst1 before=$idorBase11 after=$idorAfter11")
                Assert-Status $d1 403 "[11b] viewer1 overview 허용 밖 captureId"
                Assert-Status $d2 403 "[11b] viewer1 operations 허용 밖 captureId"
                Assert-Status $d3 403 "[11b] analyst1 overview 허용 밖 captureId"
                Assert-Status $bad 400 "[11b] overview 잘못된 period"
                Assert-True (($idorAfter11 - $idorBase11) -ge 3) "[11b] 허용 밖 요청 3건 IDOR 감사 기록 (증가 $($idorAfter11 - $idorBase11))"

                # [11c] VIEWER 작업 오류 글 마스킹(overview·operations), 응답에 숨긴 캡처·IPv4 없음
                $vOv = Invoke-Http -Url "$baseHttps/api/dashboard/overview?period=1h" -CookieJar $q11Viewer
                $vOps = Invoke-Http -Url "$baseHttps/api/operations?period=1h" -CookieJar $q11Viewer
                $vOpsAll = Invoke-Http -Url "$baseHttps/api/operations" -CookieJar $q11Viewer
                $aOps = Invoke-Http -Url "$baseHttps/api/operations?period=1h" -CookieJar $q11Analyst
                $vCapErr = @($vOv.Json.captures | Where-Object { $_.captureId -eq 'cic17-wed' } | ForEach-Object { $_.latestJob.error })
                $vJobErr = @($vOps.Json.jobs | Where-Object { [int]$_.jobId -eq $t24Job } | ForEach-Object { $_.error })
                $aJobErr = @($aOps.Json.jobs | Where-Object { [int]$_.jobId -eq $t24Job } | ForEach-Object { $_.error })
                $leak11 = [System.Collections.Generic.List[string]]::new()
                foreach ($pair in @(@('overview', $vOv), @('operations?period=1h', $vOps), @('operations', $vOpsAll))) {
                    foreach ($m in $hiddenMarkers) { if ($pair[1].Body.Contains($m)) { $leak11.Add("$($pair[0]) contains '$m'") } }
                    $ipHit = Get-UnmaskedIpv4 $pair[1].Body
                    if ($ipHit.Count) { $leak11.Add("$($pair[0]) unmasked IPv4: $($ipHit -join ', ')") }
                }
                $e2eLogs.Add("[11c] viewer1 overview cic17-wed latestJob.error=[$($vCapErr -join ' | ')] state=$(@($vOv.Json.captures | ForEach-Object { "$($_.captureId):$($_.state)" }) -join ','); viewer1 operations?period=1h jobs=[$(@($vOps.Json.jobs | ForEach-Object { $_.jobId }) -join ',')] job $t24Job error=[$($vJobErr -join ' | ')]; analyst1 job $t24Job error=[$($aJobErr -join ' | ')]`n      viewer1 bundles=[$(@($vOpsAll.Json.bundles | ForEach-Object { $_.bundleId }) -join ', ')] sources=[$(@($vOpsAll.Json.sources | ForEach-Object { "$($_.captureId):$($_.sourceType)" }) -join ', ')]; leaks=$($leak11.Count)$(if ($leak11.Count) { ' ' + ($leak11 -join '; ') })")
                Assert-True ($vCapErr.Count -eq 1 -and $vCapErr[0] -eq 'connect to 192.168.*.*:5432 refused') "[11c] viewer1 overview 작업 오류 글 마스킹 (PostgreSQL)" $vOv
                Assert-True ($vJobErr.Count -eq 1 -and $vJobErr[0] -eq 'connect to 192.168.*.*:5432 refused') "[11c] viewer1 operations 작업 오류 글 마스킹" $vOps
                Assert-True ($aJobErr.Count -eq 1 -and $aJobErr[0] -eq 'connect to 192.168.10.50:5432 refused') "[11c] analyst1은 원문" $aOps
                Assert-True ($leak11.Count -eq 0) "[11c] viewer1 overview·operations에 숨긴 캡처 문자열·가려지지 않은 IPv4 없음 ($($leak11 -join '; '))"

                # [11d] /api/operations?period= 거르기: 1h는 방금 넣은 작업만, all은 허용 캡처 작업 전체, latestJobs·판정 집계는 기간과 무관
                $aOpsAll = Invoke-Http -Url "$baseHttps/api/operations?period=all" -CookieJar $q11Analyst
                $aOpsLegacy = Invoke-Http -Url "$baseHttps/api/operations" -CookieJar $q11Analyst
                $jobs1h = @($aOps.Json.jobs | ForEach-Object { [int]$_.jobId })
                $jobsAll = @($aOpsAll.Json.jobs | ForEach-Object { [int]$_.jobId })
                $jobsLegacy = @($aOpsLegacy.Json.jobs | ForEach-Object { [int]$_.jobId })
                $sameLatest = ($aOps.Json.latestJobs | ConvertTo-Json -Depth 6 -Compress) -eq ($aOpsAll.Json.latestJobs | ConvertTo-Json -Depth 6 -Compress)
                $sameFeedback = ($aOps.Json.feedbackSummaries | ConvertTo-Json -Depth 6 -Compress) -eq ($aOpsAll.Json.feedbackSummaries | ConvertTo-Json -Depth 6 -Compress)
                $e2eLogs.Add("[11d] analyst1 operations period=1h jobs=[$($jobs1h -join ',')] total=$($aOps.Json.jobsTotal) truncated=$($aOps.Json.jobsTruncated) slack=$(@($aOps.Json.slackSummaries).Count); period=all jobs=[$($jobsAll -join ',')] slack=$(@($aOpsAll.Json.slackSummaries).Count); no period jobs=[$($jobsLegacy -join ',')] period=$($aOpsLegacy.Json.period); latestJobs same=$sameLatest feedbackSummaries same=$sameFeedback")
                Assert-True (($jobs1h -join ',') -eq "$t24Job") "[11d] operations period=1h는 기간 안 작업만" $aOps
                Assert-True (($jobsAll -join ',') -eq "$t24Job,101,100" -and ($jobsLegacy -join ',') -eq ($jobsAll -join ',')) "[11d] operations period=all = period 없음 = 허용 캡처 작업 전체(job_id 내림)" $aOpsAll
                Assert-True ($sameLatest -and $sameFeedback) "[11d] latestJobs·판정 집계는 기간과 무관"

                # [11e] 응답 시간(curl 포함, 3회)
                $t11 = @()
                foreach ($p in @("/api/dashboard/overview?period=all", "/api/dashboard/overview?period=24h", "/api/operations?period=7d")) {
                    $ms = @()
                    for ($k = 0; $k -lt 3; $k++) {
                        $sw = [Diagnostics.Stopwatch]::StartNew()
                        $r = Invoke-Http -Url "$baseHttps$p" -CookieJar $q11Analyst
                        $sw.Stop()
                        Assert-Status $r 200 "[11e] $p"
                        $ms += [int]$sw.ElapsedMilliseconds
                    }
                    $t11 += "$p=[$($ms -join ', ')] ms"
                }
                $e2eLogs.Add("[11e] response times (analyst1, 3 samples, includes curl): $($t11 -join '; ')")

                $accuracyHits = @($allBodies | Where-Object { $_ -and $_.Contains("정확도") })
                $e2eLogs.Add("[*] responses checked for '정확도': $($allBodies.Count) bodies, hits=$($accuracyHits.Count)")
                Assert-True ($accuracyHits.Count -eq 0) "모든 응답에 '정확도' 문구 없음"

                $e2eReport = $e2eLogs -join "`n`n"
                [IO.File]::WriteAllText((Join-Path $ReportFullDir "waf-e2e-verification.txt"), $e2eReport, $utf8NoBom)
                Save-Evidence "waf-e2e-verification.txt" $e2eReport
                Write-Host "-> WAF + SPA + JSON API + PostgreSQL 17 E2E 실측 검증 모두 통과!"
            } catch {
                if ($e2eLogs.Count -gt 0) {
                    $partial = ($e2eLogs -join "`n`n") + "`n`n[FAILED] $($_.Exception.Message)"
                    [IO.File]::WriteAllText((Join-Path $ReportFullDir "waf-e2e-verification.txt"), $partial, $utf8NoBom)
                    Save-Evidence "waf-e2e-verification.txt" $partial
                }
                throw
            } finally {
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmpDir
            }
        }

        if (-not $SkipZap) {
            Write-Host "=== [5/5] OWASP ZAP 베이스라인 스캔 (https://nginx-waf:8443/) ==="
            [void](Invoke-NativeCapture "docker" @("pull", "ghcr.io/zaproxy/zaproxy:stable"))
            $zapJsonPath = Join-Path $ReportFullDir "zap-baseline.json"
            Remove-Item -Force -ErrorAction SilentlyContinue $zapJsonPath
            $zapRes = Invoke-NativeCapture "docker" @("run", "--rm", "--network", $networkName, "-v", "${ReportFullDir}:/zap/wrk:rw", "ghcr.io/zaproxy/zaproxy:stable", "zap-baseline.py", "-t", "https://nginx-waf:8443/", "-J", "zap-baseline.json", "-r", "zap-baseline.html", "-w", "zap-baseline.md") -IgnoreExitCode
            $zapOut = $zapRes.Output
            $zapExit = $zapRes.ExitCode

            # ZAP은 정보성 경고만 있어도 exit 2가 되므로 판정은 zap-baseline.json의 위험 등급별 경고 수로 한다.
            # 유일한 예외(SPEC.md '결정' 2026-11-20): 모든 인스턴스의 param이 정확히 XSRF-TOKEN인 Low 10010(Cookie No HttpOnly Flag)만 허용한다.
            # SPA 이중 제출 CSRF 방식상 JS가 XSRF-TOKEN 쿠키를 읽어야 한다. ZAP 설정으로 10010을 끄지 않고 여기서 판정한다.
            $riskCounts = [ordered]@{ High = 0; Medium = 0; Low = 0; Informational = 0 }
            $allowedLines = [System.Collections.Generic.List[string]]::new()
            $alertLines = [System.Collections.Generic.List[string]]::new()
            $zapJsonOk = Test-Path $zapJsonPath
            if ($zapJsonOk) {
                $zapJson = [IO.File]::ReadAllText($zapJsonPath, [Text.UTF8Encoding]::new($false)) | ConvertFrom-Json
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
            $zapHeader = "ZAP_EXIT_CODE=$zapExit`n$riskLine (allowed exceptions excluded)`n$allowedText`nzap-baseline.json parsed=$zapJsonOk`n`nAlerts by risk (zap-baseline.json):`n$(if ($alertLines.Count) { $alertLines -join "`n" } else { '(none)' })"

            $zapSummary = "$zapHeader`n`n$($zapOut.Trim())"
            [IO.File]::WriteAllText((Join-Path $ReportFullDir "zap-baseline-output.txt"), $zapSummary, [Text.UTF8Encoding]::new($false))
            if (Test-Path (Join-Path $ReportFullDir "zap-baseline.md")) {
                $md = [IO.File]::ReadAllText((Join-Path $ReportFullDir "zap-baseline.md"), [Text.UTF8Encoding]::new($false))
                Save-Evidence "zap-baseline-summary.md" ("$zapHeader`n`n" + $md)
            } else {
                Save-Evidence "zap-baseline-summary.md" $zapSummary
            }
            Write-Host "-> OWASP ZAP 종료 코드: $zapExit / $riskLine"
            if ($zapExit -eq 1 -or $zapExit -eq 3) {
                throw "OWASP ZAP 스캔 실패 (exit=$zapExit)"
            }
            if (-not $zapJsonOk) {
                throw "OWASP ZAP 결과 zap-baseline.json이 생성되지 않았습니다 (exit=$zapExit)"
            }
            if ($riskCounts.High -gt 0 -or $riskCounts.Medium -gt 0 -or $riskCounts.Low -gt 0) {
                throw "OWASP ZAP 베이스라인 경고 존재: $riskLine"
            }
        }
    } finally {
        Write-Host "=== 검증용 Docker Compose 스택 정리 (down -v) ==="
        [void](Invoke-NativeCapture "docker" ($composeArgs + @("down", "-v")) -IgnoreExitCode)
    }
}

Write-Host "보안 검증 스크립트 완료. 원본 리포트 경로: $ReportFullDir"
