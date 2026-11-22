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
        # T32: compose.yml의 dashboard-net은 고정 서브넷(DASHBOARD_SUBNET, 기본 10.203.49.0/24)이라 같은 서브넷 네트워크가 남아 있으면
        # 기동이 "Pool overlaps"로 실패한다. 앞선 검증 실행(zeekad-verify-*)의 것이면 그 프로젝트를 내리고, 다른 네트워크면 이름을 알리고 멈춘다.
        $verifySubnet = if ($env:DASHBOARD_SUBNET) { $env:DASHBOARD_SUBNET } else { "10.203.49.0/24" }
        $netIds = @((Invoke-NativeCapture "docker" @("network", "ls", "-q")).Output -split "`r?`n" | Where-Object { $_.Trim() })
        foreach ($netId in $netIds) {
            $netInfo = (Invoke-NativeCapture "docker" @("network", "inspect", "--format", '{{.Name}}|{{index .Labels "com.docker.compose.project"}}|{{range .IPAM.Config}}{{.Subnet}} {{end}}', $netId.Trim()) -IgnoreExitCode).Output.Trim()
            $parts = $netInfo -split '\|', 3
            if ($parts.Count -lt 3 -or -not (@($parts[2] -split '\s+') -contains $verifySubnet)) { continue }
            if ($parts[1] -like "zeekad-verify-*") {
                Write-Host "-> 앞선 검증 스택 $($parts[1])이 서브넷 $verifySubnet 을 쓰고 있어 내립니다 (down -v)"
                [void](Invoke-NativeCapture "docker" @("compose", "-p", $parts[1], "-f", "compose.yml", "-f", "docker/verify/compose.verify.yml", "down", "-v") -IgnoreExitCode)
                $left = (Invoke-NativeCapture "docker" @("network", "inspect", $netId.Trim()) -IgnoreExitCode).ExitCode
                if ($left -eq 0) { throw "앞선 검증 스택 네트워크 $($parts[0])이 남아 있습니다. 수동으로 확인하세요." }
            } else {
                throw "서브넷 $verifySubnet 을 다른 네트워크 $($parts[0]) (프로젝트 '$($parts[1])')가 쓰고 있습니다. 그 네트워크는 지우지 않습니다. 내리거나 DASHBOARD_SUBNET·DASHBOARD_IP_RANGE·DASHBOARD_WAF_IP를 바꾸세요."
            }
        }

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
                        [string[]]$ExtraHeaders = @(),
                        [string]$RawBody = $null,
                        [string]$RawContentType = ""
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
                    if ($RawBody) {
                        # JSON이 아닌 본문(T31 [15] XML). 파일로 넘겨 셸 인용에 영향받지 않게 한다.
                        $reqFile = Join-Path $tmpDir "req-$($script:httpSeq).raw"
                        [IO.File]::WriteAllText($reqFile, $RawBody, $utf8NoBom)
                        $curlArgs += @("-H", "Content-Type: $RawContentType", "--data-binary", "@$reqFile")
                    } elseif ($null -ne $JsonBody) {
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

                # T27: 화면 경로를 새로 연 비인증 GET은 302 대신 SPA 셸 200(no-store, 데이터 없음). 화면이 원래 주소를 싣고 로그인으로 보낸다.
                #      그 경로의 API는 401 JSON 그대로, 화면 경로가 아닌 곳은 지금처럼 302 /login.
                foreach ($pair in @(@("/", "/api/auth/me-not-public"), @("/incidents/101/rank/1", "/api/incidents/101/rank/1"), @("/incidents/1", "/api/incidents/no/1"))) {
                    $protectedPath = $pair[0]
                    $protectedRes = Invoke-Http -Url "$baseHttps$protectedPath"
                    $cc = Get-HeaderValue $protectedRes "Cache-Control"
                    $bodyIp = @([regex]::Matches($protectedRes.Body, '\b(?:\d{1,3}\.){3}\d{1,3}\b') | ForEach-Object { $_.Value })
                    $e2eLogs.Add("[1c] unauthenticated GET $protectedPath -> HTTP $($protectedRes.Status) Cache-Control=$cc shell=$(Test-SpaShell $protectedRes) bytes=$($protectedRes.Body.Length) ipv4=[$($bodyIp -join ', ')]")
                    Assert-Status $protectedRes 200 "비인증 GET $protectedPath (셸)"
                    Assert-True (Test-SpaShell $protectedRes) "비인증 GET $protectedPath SPA 셸" $protectedRes
                    Assert-True ($cc -match "no-store") "비인증 GET $protectedPath Cache-Control no-store" $protectedRes
                    Assert-True ($null -eq $protectedRes.Json -and $bodyIp.Count -eq 0 -and $protectedRes.Body -notmatch '"(incidentId|username|items|hostIp)"') "비인증 GET $protectedPath 본문에 API 데이터·사용자 정보 없음" $protectedRes
                    Assert-True ([bool](Get-HeaderValue $protectedRes "Content-Security-Policy")) "비인증 GET $protectedPath 보안 헤더(CSP)" $protectedRes
                    if ($pair[1] -ne "/api/auth/me-not-public") {
                        $apiRes = Invoke-Http -Url "$baseHttps$($pair[1])"
                        $e2eLogs.Add("[1c] unauthenticated GET $($pair[1]) -> $(Format-Resp $apiRes 200)")
                        Assert-ApiError $apiRes 401 "UNAUTHENTICATED" "비인증 GET $($pair[1])"
                    }
                }
                $nopeRes = Invoke-Http -Url "$baseHttps/nope"
                $e2eLogs.Add("[1c] unauthenticated GET /nope (화면 경로 아님) -> HTTP $($nopeRes.Status) Location=$(Get-HeaderValue $nopeRes 'Location')")
                Assert-Status $nopeRes 302 "비인증 GET /nope(화면 경로 아님)"
                Assert-True ((Get-HeaderValue $nopeRes "Location") -match "^(https://[^/]+)?/login$") "비인증 GET /nope Location /login" $nopeRes

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

                # 9d 비인증 리다이렉트 Location(호스트·경로 위조 단독). T27부터 화면 경로(/incidents)는 302 대신 셸 200이라
                #    아직 302 /login으로 가는 화면 경로 아닌 곳(/nope)으로 같은 위조를 본다.
                $redirBase = Invoke-Http -Url "$baseHttps/nope"
                $redirBaseLoc = Get-HeaderValue $redirBase "Location"
                $e2eLogs.Add("[9d] unauthenticated GET /nope (no forwarding headers) -> HTTP $($redirBase.Status) Location=$redirBaseLoc")
                $redirResults = [System.Collections.Generic.List[object]]::new()
                foreach ($h in @("X-Forwarded-Host: evil.example", "Forwarded: host=evil.example;proto=http", "X-Forwarded-Prefix: /evil")) {
                    $rr = Invoke-Http -Url "$baseHttps/nope" -ExtraHeaders @($h)
                    $rrLoc = Get-HeaderValue $rr "Location"
                    $redirResults.Add([pscustomobject]@{ Header = $h; Status = $rr.Status; Location = $rrLoc })
                    $e2eLogs.Add("[9d] unauthenticated GET /nope with '$h' -> HTTP $($rr.Status) Location=$rrLoc")
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
                Assert-Status $redirBase 302 "[9d] 비인증 GET /nope"
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

                # [12] 담당자·착수 지연·처리 시간 지표(T25). 검증 시드: cic17-wed(작업 101) 1·3위 종결, 2위 조사 중 / syn1-wed(작업 211) 1위 종결·2위 신규 / syn1-tue(작업 201) 1위 신규.
                #      viewer1·analyst1 = cic17-*, analyst2 = syn1-*. 지정 규칙(권한·IDOR·담당 가능·종결·충돌·CSRF), 자동 지정, 이력 추가만(psql),
                #      사용자별 불변식(none + 그 집합 안 담당 있음 = total), handlingTimes = 독립 SQL(percentile_disc), workload.ackOverdue ≈ 큐 overdue total,
                #      VIEWER 응답 IPv4, 응답 시간(데우기 1번 뒤 3번, 최댓값 1초 이하).
                function Invoke-ZeekadSelect([string]$Sql) {
                    return (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "verify-postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "zeekad", "-AtF", "|", "-c", $Sql))).Output.Trim()
                }
                function Get-WafInterrupted([string]$ProbeId) {
                    $wafLogs = (Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--no-log-prefix", "nginx-waf")) -IgnoreExitCode).Output
                    return @($wafLogs -split "`r?`n" | Where-Object { $_.Contains($ProbeId) -and $_ -match '"is_interrupted":true' })
                }
                $q12A1 = Join-Path $tmpDir "q12-a1.cookies"
                $q12A2 = Join-Path $tmpDir "q12-a2.cookies"
                $q12V = Join-Path $tmpDir "q12-v.cookies"
                Assert-Status (Login-Api "analyst1" $q12A1) 200 "[12] analyst1 로그인"
                Assert-Status (Login-Api "analyst2" $q12A2) 200 "[12] analyst2 로그인"
                Assert-Status (Login-Api "viewer1" $q12V) 200 "[12] viewer1 로그인"
                $iid1012 = 'cic17-wed|10.20.30.40|responder|1700000300'
                $auditBase12 = [long](Invoke-AuditSelect "SELECT COALESCE(MAX(id),0) FROM audit_logs")
                $idorA1 = { [int](Invoke-AuditSelect "SELECT count(*) FROM audit_logs WHERE id > $auditBase12 AND action_type = 'ACCESS_DENIED_IDOR' AND actor_username = 'analyst1'") }
                $idorV1 = { [int](Invoke-AuditSelect "SELECT count(*) FROM audit_logs WHERE id > $auditBase12 AND action_type = 'ACCESS_DENIED_IDOR' AND actor_username = 'viewer1'") }

                # [12a] analyst1이 허용 캡처 인시던트(101/2, 조사 중)를 자기에게 지정: 200, 감사·이력, 큐 assignee=me = 1, nginx-waf 통과
                $a12 = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2/assignment" -Method POST -CookieJar $q12A1 -SaveCookies -Csrf `
                    -JsonBody ([ordered]@{ assignee = 'analyst1'; expected = $null }) -ProbeId "e2e-t25-assign"
                $assignAudit = Invoke-AuditSelect "SELECT action_type, actor_username, target_capture_id, target_job_id, target_incident_id, detail_json FROM audit_logs WHERE id > $auditBase12 AND action_type = 'INCIDENT_ASSIGNMENT' ORDER BY id"
                $histRows = Invoke-AuditSelect "SELECT h.incident_id, h.capture_id, h.job_id, COALESCE(f.username,'-'), COALESCE(t.username,'-'), h.actor_username, h.reason FROM incident_assignment_history h LEFT JOIN users f ON f.id = h.from_user_id LEFT JOIN users t ON t.id = h.to_user_id ORDER BY h.id"
                $meQ = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&assignee=me&size=25" -CookieJar $q12A1
                $wafHits12 = Get-WafInterrupted "e2e-t25-assign"
                $e2eLogs.Add("[12a] analyst1 POST /api/incidents/101/rank/2/assignment (self): $(Format-Resp $a12 400)`n      audit INCIDENT_ASSIGNMENT rows:`n      $($assignAudit -replace "`n", "`n      ")`n      incident_assignment_history:`n      $($histRows -replace "`n", "`n      ")`n      analyst1 queue assignee=me total=$($meQ.Json.total) items=[$(@($meQ.Json.items | ForEach-Object { "$($_.jobId)/$($_.queueRank):$($_.assignee.username)" }) -join ', ')]`n      nginx-waf interrupted lines for probe e2e-t25-assign = $($wafHits12.Count)")
                Assert-Status $a12 200 "[12a] analyst1 자기 지정"
                Assert-True ($a12.Json.assignment.assignee.username -eq 'analyst1') "[12a] 응답 담당자 analyst1" $a12
                Assert-True ($assignAudit -match "INCIDENT_ASSIGNMENT\|analyst1\|cic17-wed\|101\|$([regex]::Escape($iid1012))\|" -and $assignAudit -match '"to":"analyst1"' -and $assignAudit -match '"reason":"manual"') "[12a] 감사 기록 INCIDENT_ASSIGNMENT(from·to·reason·대상)"
                Assert-True ($histRows -match "$([regex]::Escape($iid1012))\|cic17-wed\|101\|-\|analyst1\|analyst1\|manual") "[12a] 이력 행(미배정 → analyst1, manual)"
                Assert-True ([int]$meQ.Json.total -eq 1) "[12a] 큐 assignee=me = 1" $meQ
                Assert-True ($wafHits12.Count -eq 0) "[12a] 지정 POST가 nginx-waf(CRS)에 차단되지 않음"

                # [12b] analyst1이 허용 밖 캡처(syn1-wed 211/1) 지정 → 403 + ACCESS_DENIED_IDOR
                $b12 = Invoke-Http -Url "$baseHttps/api/incidents/211/rank/1/assignment" -Method POST -CookieJar $q12A1 -SaveCookies -Csrf -JsonBody ([ordered]@{ assignee = 'analyst1'; expected = $null })
                $idorA1After = & $idorA1
                $e2eLogs.Add("[12b] analyst1 POST 211/1 assignment (허용 밖): $(Format-Resp $b12 200); analyst1 IDOR rows since [12] = $idorA1After")
                Assert-Status $b12 403 "[12b] analyst1 허용 밖 지정"
                Assert-True ($idorA1After -eq 1) "[12b] 허용 밖 지정 IDOR 감사 기록 1건"

                # [12c] 그 캡처를 볼 수 없는 analyst2를 지정 → 400 ASSIGNEE_NOT_ELIGIBLE
                $c12 = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2/assignment" -Method POST -CookieJar $q12A1 -SaveCookies -Csrf -JsonBody ([ordered]@{ assignee = 'analyst2'; expected = 'analyst1' })
                $e2eLogs.Add("[12c] analyst1 POST 101/2 assignee=analyst2(syn1-*만): $(Format-Resp $c12 300)")
                Assert-ApiError $c12 400 "ASSIGNEE_NOT_ELIGIBLE" "[12c] 담당 가능 아님"

                # [12d] viewer1: 허용 캡처면 403(IDOR 감사 없음), 허용 밖이면 403 + IDOR(인시던트 접근 검사가 먼저)
                $v12p = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2/assignment" -Method POST -CookieJar $q12V -SaveCookies -Csrf -JsonBody ([ordered]@{ assignee = 'viewer1'; expected = 'analyst1' })
                $v12g = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2/assignees" -CookieJar $q12V
                $idorV1Mid = & $idorV1
                $v12p2 = Invoke-Http -Url "$baseHttps/api/incidents/211/rank/1/assignment" -Method POST -CookieJar $q12V -SaveCookies -Csrf -JsonBody ([ordered]@{ assignee = 'viewer1'; expected = $null })
                $v12g2 = Invoke-Http -Url "$baseHttps/api/incidents/211/rank/1/assignees" -CookieJar $q12V
                $idorV1End = & $idorV1
                $e2eLogs.Add("[12d] viewer1 POST 101/2: $(Format-Resp $v12p 200)`n      viewer1 GET 101/2/assignees: $(Format-Resp $v12g 200)`n      viewer1 IDOR rows after 허용 캡처 요청 = $idorV1Mid`n      viewer1 POST 211/1: $(Format-Resp $v12p2 200)`n      viewer1 GET 211/1/assignees: $(Format-Resp $v12g2 200)`n      viewer1 IDOR rows after 허용 밖 요청 = $idorV1End")
                Assert-Status $v12p 403 "[12d] viewer1 지정(허용 캡처)"
                Assert-Status $v12g 403 "[12d] viewer1 담당 가능자 목록(허용 캡처)"
                Assert-True ($idorV1Mid -eq 0) "[12d] viewer1 허용 캡처 요청은 IDOR 감사 없음"
                Assert-Status $v12p2 403 "[12d] viewer1 지정(허용 밖)"
                Assert-Status $v12g2 403 "[12d] viewer1 담당 가능자 목록(허용 밖)"
                Assert-True ($idorV1End -eq 2) "[12d] viewer1 허용 밖 요청 2건 IDOR 감사"

                # [12e] CSRF 없는 POST → 403(바뀌지 않음)
                $e12 = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2/assignment" -Method POST -CookieJar $q12A1 -JsonBody ([ordered]@{ assignee = $null; expected = 'analyst1' })
                $e2eLogs.Add("[12e] analyst1 POST without X-XSRF-TOKEN: $(Format-Resp $e12 200)")
                Assert-Status $e12 403 "[12e] CSRF 없는 지정"

                # [12f] expected 어긋남 → 409 ASSIGNMENT_CONFLICT, 종결(101/3) → 409 INCIDENT_CLOSED
                $f12 = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2/assignment" -Method POST -CookieJar $q12A1 -SaveCookies -Csrf -JsonBody ([ordered]@{ assignee = $null; expected = $null })
                $f12c = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/3/assignment" -Method POST -CookieJar $q12A1 -SaveCookies -Csrf -JsonBody ([ordered]@{ assignee = 'analyst1'; expected = $null })
                $e2eLogs.Add("[12f] analyst1 POST 101/2 expected=null(서버 analyst1): $(Format-Resp $f12 300)`n      analyst1 POST 101/3(종결): $(Format-Resp $f12c 300)")
                Assert-ApiError $f12 409 "ASSIGNMENT_CONFLICT" "[12f] expected 어긋남"
                Assert-ApiError $f12c 409 "INCIDENT_CLOSED" "[12f] 종결된 인시던트"

                # [12g] 미배정 인시던트(211/2, 신규)를 analyst2가 조사 시작 → 자동 지정(auto_on_start). 201/1(신규)은 analyst2가 직접 지정
                $g12 = Invoke-Http -Url "$baseHttps/api/incidents/211/rank/2/transition" -Method POST -CookieJar $q12A2 -SaveCookies -Csrf -JsonBody @{ toStatus = "investigating"; reason = "T25 E2E 조사 시작" }
                $g12d = Invoke-Http -Url "$baseHttps/api/incidents/211/rank/2" -CookieJar $q12A2
                $g12m = Invoke-Http -Url "$baseHttps/api/incidents/201/rank/1/assignment" -Method POST -CookieJar $q12A2 -SaveCookies -Csrf -JsonBody ([ordered]@{ assignee = 'analyst2'; expected = $null })
                $e2eLogs.Add("[12g] analyst2 POST 211/2 transition investigating: $(Format-Resp $g12 300)`n      211/2 detail assignment=$($g12d.Json.assignment | ConvertTo-Json -Compress -Depth 4) history=$($g12d.Json.assignmentHistory | ConvertTo-Json -Compress -Depth 4)`n      analyst2 POST 201/1 assignment(self): $(Format-Resp $g12m 300)")
                Assert-Status $g12 200 "[12g] 조사 시작"
                Assert-True (-not ([string]$g12.Json.message).Contains('자동 지정은 실패')) "[12g] 자동 지정 실패 안내 없음" $g12
                Assert-True ($g12d.Json.assignment.assignee.username -eq 'analyst2' -and @($g12d.Json.assignmentHistory)[0].reason -eq 'auto_on_start') "[12g] 조사 시작한 사람이 담당자(auto_on_start)" $g12d
                Assert-Status $g12m 200 "[12g] analyst2 자기 지정"

                # [12h] 이력 표 UPDATE·DELETE 거부(psql)
                $histCount = Invoke-AuditSelect "SELECT count(*) FROM incident_assignment_history"
                $upd = Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "verify-postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "zeekad_dashboard", "-c", "UPDATE incident_assignment_history SET reason = 'manual'")) -IgnoreExitCode
                $del = Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "verify-postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "zeekad_dashboard", "-c", "DELETE FROM incident_assignment_history")) -IgnoreExitCode
                $histCount2 = Invoke-AuditSelect "SELECT count(*) FROM incident_assignment_history"
                $e2eLogs.Add("[12h] psql UPDATE incident_assignment_history: $($upd.Output.Trim())`n      psql DELETE incident_assignment_history: $($del.Output.Trim())`n      rows before=$histCount after=$histCount2")
                Assert-True ($upd.Output -match "append-only" -and $del.Output -match "append-only" -and $histCount -eq $histCount2) "[12h] 이력 표 UPDATE·DELETE 거부(PostgreSQL 트리거)"

                # [12i] 사용자별 불변식: none + (그 사용자가 보는 집합 안 담당 있음) = total, me + 다른 사람 담당 + none = total
                $inv12 = [System.Collections.Generic.List[string]]::new()
                foreach ($who in @(@{ Name = 'analyst1'; Jar = $q12A1 }, @{ Name = 'analyst2'; Jar = $q12A2 }, @{ Name = 'viewer1'; Jar = $q12V })) {
                    foreach ($q in @('period=all', 'period=24h', 'period=all&source=imported', 'period=all&status=investigating')) {
                        $all = Invoke-Http -Url "$baseHttps/api/incidents/queue?$q&size=100" -CookieJar $who.Jar
                        $none = Invoke-Http -Url "$baseHttps/api/incidents/queue?$q&assignee=none&size=100" -CookieJar $who.Jar
                        $me = Invoke-Http -Url "$baseHttps/api/incidents/queue?$q&assignee=me&size=100" -CookieJar $who.Jar
                        $assignedInSet = @($all.Json.items | Where-Object { $null -ne $_.assignee }).Count
                        $line = "$($who.Name) $q total=$($all.Json.total) none=$($none.Json.total) assignedInSet=$assignedInSet me=$($me.Json.total) summary(none)=$($none.Json.summary.total)"
                        $e2eLogs.Add("[12i] $line")
                        if ([int]$none.Json.total + $assignedInSet -ne [int]$all.Json.total) { $inv12.Add($line) }
                        if ([int]$none.Json.summary.total -ne [int]$none.Json.total) { $inv12.Add("summary $line") }
                        if ($who.Name -eq 'viewer1' -and [int]$me.Json.total -ne 0) { $inv12.Add("viewer me $line") }
                    }
                }
                Assert-True ($inv12.Count -eq 0) "[12i] 사용자별 담당 불변식 (실패 $($inv12.Count): $($inv12 -join '; '))"

                # [12j] /api/operations?period=all handlingTimes = 독립 SQL(PostgreSQL percentile_disc). admin(실습망 포함)·analyst1·analyst2
                function Get-HandlingSql([string[]]$Patterns) {
                    $cond = if ($Patterns -contains '*') { 'TRUE' } else { '(' + (@($Patterns | ForEach-Object { "{0}.capture_id LIKE '" + ($_ -replace '\*$', '%') + "'" }) -join ' OR ') + ')' }
                    $lqCond = $cond -replace '\{0\}', 'l'
                    $qCond = $cond -replace '\{0\}', 'q'
                    return @"
WITH lq AS (SELECT * FROM dashboard.latest_incident_queue l WHERE $lqCond),
fs AS (SELECT q.incident_id, MIN(j.finished_at) AS det FROM dashboard.incident_queue q
       JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL
       WHERE $qCond GROUP BY q.incident_id),
h AS (SELECT incident_id, MIN(changed_at) AS ack FROM dashboard.incident_status_history WHERE LOWER(TRIM(to_status)) = 'investigating' GROUP BY incident_id),
b AS (SELECT lq.incident_id, lq.capture_id LIKE 'lab-%' AS live, lq.event_start, fs.det, h.ack,
             CASE WHEN LOWER(TRIM(COALESCE(lq.zeekad_status, ''))) = 'closed' THEN lq.status_updated_at END AS closed_at,
             COALESCE(NULLIF(LOWER(TRIM(lq.zeekad_resolution)), ''), 'none') AS res
      FROM lq LEFT JOIN fs ON fs.incident_id = lq.incident_id LEFT JOIN h ON h.incident_id = lq.incident_id),
v AS (SELECT 'detection' AS m, FLOOR(EXTRACT(EPOCH FROM (det - event_start)))::bigint AS s FROM b WHERE live AND det IS NOT NULL
      UNION ALL SELECT 'acknowledge', FLOOR(EXTRACT(EPOCH FROM (ack - det)))::bigint FROM b WHERE ack IS NOT NULL
      UNION ALL SELECT 'acknowledge', NULL FROM b WHERE closed_at IS NOT NULL AND ack IS NULL
      UNION ALL SELECT 'resolve', FLOOR(EXTRACT(EPOCH FROM (closed_at - det)))::bigint FROM b WHERE closed_at IS NOT NULL
      UNION ALL SELECT 'resolve:' || res, FLOOR(EXTRACT(EPOCH FROM (closed_at - det)))::bigint FROM b WHERE closed_at IS NOT NULL)
SELECT m, COUNT(*) FILTER (WHERE s >= 0),
       COALESCE((percentile_disc(0.5) WITHIN GROUP (ORDER BY s) FILTER (WHERE s >= 0))::text, ''),
       COALESCE((percentile_disc(0.9) WITHIN GROUP (ORDER BY s) FILTER (WHERE s >= 0))::text, ''),
       COUNT(*) FILTER (WHERE s IS NULL OR s < 0)
FROM v GROUP BY m ORDER BY m
"@
                }
                function Compare-Handling([string]$Name, [string]$Jar, [string[]]$Patterns) {
                    $ops = Invoke-Http -Url "$baseHttps/api/operations?period=all" -CookieJar $Jar
                    Assert-Status $ops 200 "[12j] $Name operations?period=all"
                    $sqlOut = Invoke-ZeekadSelect (Get-HandlingSql $Patterns)
                    $sql = @{}
                    foreach ($l in @($sqlOut -split "`r?`n" | Where-Object { $_ })) { $p = $l -split '\|'; $sql[$p[0]] = $p }
                    $api = @{ detection = $ops.Json.handlingTimes.detection; acknowledge = $ops.Json.handlingTimes.acknowledge; resolve = $ops.Json.handlingTimes.resolve.all }
                    foreach ($r in @($ops.Json.handlingTimes.resolve.byResolution)) { $api["resolve:$($r.resolution)"] = $r.stat }
                    $diff = [System.Collections.Generic.List[string]]::new()
                    $lines = [System.Collections.Generic.List[string]]::new()
                    foreach ($k in @(@($api.Keys) + @($sql.Keys) | Sort-Object -Unique)) {
                        $a = $api[$k]
                        $aText = if ($a) { "n=$($a.n) median=$($a.medianSeconds) p90=$($a.p90Seconds) excluded=$($a.excluded)" } else { "(없음)" }
                        $s = $sql[$k]
                        $sText = if ($s) { "n=$($s[1]) median=$($s[2]) p90=$($s[3]) excluded=$($s[4])" } else { "n=0 median= p90= excluded=0" }
                        $lines.Add("$k api[$aText] sql[$sText]")
                        if ($aText -ne $sText) { $diff.Add($k) }
                    }
                    $e2eLogs.Add("[12j] $Name handlingTimes(period=all) vs 독립 SQL (percentile_disc):`n      $($lines -join "`n      ")`n      diff=[$($diff -join ', ')]")
                    Assert-True ($diff.Count -eq 0) "[12j] $Name handlingTimes = 독립 SQL (차이 $($diff -join ', '))"
                    return $ops
                }
                $null = Compare-Handling 'analyst1' $q12A1 @('cic17-*')
                $null = Compare-Handling 'analyst2' $q12A2 @('syn1-*')
                $q12Adm = Join-Path $tmpDir "q12-admin.cookies"
                Assert-Status (Login-Api "admin" $q12Adm) 200 "[12j] admin 1차 로그인"
                $admTotp = $null
                for ($try = 0; $try -lt 3; $try++) {
                    $admTotp = Invoke-Http -Url "$baseHttps/api/auth/totp/verify" -Method POST -CookieJar $q12Adm -SaveCookies -Csrf -JsonBody @{ code = (Get-TotpCode $adminTotpSecret) }
                    if ($admTotp.Status -eq 200) { break }
                    Start-Sleep -Seconds 31
                }
                Assert-Status $admTotp 200 "[12j] admin TOTP"
                $null = Compare-Handling 'admin' $q12Adm @('*')

                # [12k] workload: unclosed = assigned + unassigned, assigned = byAssignee 합, ackOverdue ≈ 큐 overdue=true total(실시간 기준 시각, 차이 1 이하)
                foreach ($who in @(@{ Name = 'analyst1'; Jar = $q12A1 }, @{ Name = 'analyst2'; Jar = $q12A2 }, @{ Name = 'admin'; Jar = $q12Adm }, @{ Name = 'viewer1'; Jar = $q12V })) {
                    $w = (Invoke-Http -Url "$baseHttps/api/operations?period=7d" -CookieJar $who.Jar).Json.workload
                    $od = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&overdue=true&size=25" -CookieJar $who.Jar
                    $sum = 0; foreach ($l in @($w.byAssignee)) { $sum += [int]$l.open + [int]$l.investigating }
                    $e2eLogs.Add("[12k] $($who.Name) workload=$($w | ConvertTo-Json -Compress -Depth 4) queue overdue=true total=$($od.Json.total) summary.overdue=$($od.Json.summary.overdue)")
                    Assert-True ([int]$w.unclosed -eq [int]$w.assigned + [int]$w.unassigned -and [int]$w.assigned -eq $sum) "[12k] $($who.Name) workload 불변식"
                    Assert-True ([math]::Abs([int]$w.ackOverdue - [int]$od.Json.total) -le 1) "[12k] $($who.Name) workload.ackOverdue ≈ 큐 overdue total"
                }

                # [12l] VIEWER 응답(큐·상세·운영 현황)에 가려지지 않은 IPv4 없음, 담당자 이름은 보인다
                $vq = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&size=100" -CookieJar $q12V
                $vd = Invoke-Http -Url "$baseHttps/api/incidents/101/rank/2" -CookieJar $q12V
                $vo = Invoke-Http -Url "$baseHttps/api/operations?period=all" -CookieJar $q12V
                $vIp = @(Get-UnmaskedIpv4 $vq.Body) + @(Get-UnmaskedIpv4 $vd.Body) + @(Get-UnmaskedIpv4 $vo.Body)
                $e2eLogs.Add("[12l] viewer1 queue/detail/operations unmasked IPv4=[$($vIp -join ', ')] detail assignment=$($vd.Json.assignment | ConvertTo-Json -Compress -Depth 4) canAssign=$($vd.Json.canAssign) workload.byAssignee=$($vo.Json.workload.byAssignee | ConvertTo-Json -Compress -Depth 4)")
                Assert-True ($vIp.Count -eq 0) "[12l] viewer1 큐·상세·운영 현황 IPv4 가림"
                Assert-True ($vd.Json.assignment.assignee.username -eq 'analyst1' -and $vd.Json.canAssign -eq $false) "[12l] viewer1 담당자 이름은 보이고 바꿀 수 없음" $vd

                # [12m] 응답 시간: 데우기 1번 뒤 3번, 최댓값 1초 이하(curl 포함)
                $t12 = [System.Collections.Generic.List[string]]::new()
                $slow12 = [System.Collections.Generic.List[string]]::new()
                foreach ($p in @("/api/incidents/queue?period=24h&assignee=none", "/api/incidents/queue?period=all&assignee=me", "/api/incidents/queue?period=7d&overdue=true", "/api/incidents/101/rank/2", "/api/operations?period=7d")) {
                    $null = Invoke-Http -Url "$baseHttps$p" -CookieJar $q12A1
                    $ms = @()
                    for ($k = 0; $k -lt 3; $k++) {
                        $sw = [Diagnostics.Stopwatch]::StartNew()
                        $r = Invoke-Http -Url "$baseHttps$p" -CookieJar $q12A1
                        $sw.Stop()
                        Assert-Status $r 200 "[12m] $p"
                        $ms += [int]$sw.ElapsedMilliseconds
                    }
                    $max = ($ms | Measure-Object -Maximum).Maximum
                    $t12.Add("$p=[$($ms -join ', ')] max=$max ms")
                    if ($max -gt 1000) { $slow12.Add($p) }
                }
                $e2eLogs.Add("[12m] response times (analyst1, warm 1 + 3 samples, includes curl): $($t12 -join '; ')")
                Assert-True ($slow12.Count -eq 0) "[12m] 응답 시간 최댓값 1초 이하 ($($slow12 -join ', '))"

                # [13] 인시던트 번호·고정 주소(T27). 앱 시작 동기화로 새 DB에 매긴 번호, 번호 API 위치·403 감사·400, VIEWER, 추가만(psql),
                #      /incidents/{번호}·옛 주소 nginx-waf 통과 SPA 200, 응답 시간.
                $q13A1 = Join-Path $tmpDir "q13-a1.cookies"
                $q13V = Join-Path $tmpDir "q13-v.cookies"
                Assert-Status (Login-Api "analyst1" $q13A1) 200 "[13] analyst1 로그인"
                Assert-Status (Login-Api "viewer1" $q13V) 200 "[13] viewer1 로그인"
                $auditBase13 = [long](Invoke-AuditSelect "SELECT COALESCE(MAX(id),0) FROM audit_logs")

                # [13a] analyst1 큐 행에 모두 번호가 있고 겹치지 않는다
                $q13 = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&size=100" -CookieJar $q13A1
                Assert-Status $q13 200 "[13a] analyst1 큐"
                $items13 = @($q13.Json.items)
                $nos13 = @($items13 | ForEach-Object { $_.incidentNo })
                $e2eLogs.Add("[13a] analyst1 queue period=all items=$($items13.Count) total=$($q13.Json.total) incidentNo=[$((@($items13 | ForEach-Object { "$($_.jobId)/$($_.queueRank)=#$($_.incidentNo)" })) -join ', ')]")
                Assert-True ($items13.Count -gt 0 -and @($nos13 | Where-Object { $null -eq $_ }).Count -eq 0) "[13a] 큐 행 모두 번호 있음"
                Assert-True (@($nos13 | Select-Object -Unique).Count -eq $nos13.Count) "[13a] 번호 겹침 없음"

                # [13b] 번호 API 위치 = 큐 행의 작업·순위, 그 위치 상세의 incident_id = 행의 incident_id
                foreach ($it in $items13) {
                    $loc13 = Invoke-Http -Url "$baseHttps/api/incidents/no/$($it.incidentNo)" -CookieJar $q13A1
                    $det13 = Invoke-Http -Url "$baseHttps/api/incidents/$($loc13.Json.jobId)/rank/$($loc13.Json.queueRank)" -CookieJar $q13A1
                    $e2eLogs.Add("[13b] #$($it.incidentNo) -> $(Format-Resp $loc13 200); detail incidentId=$($det13.Json.detail.incident.incidentId) incidentNo=$($det13.Json.incidentNo)")
                    Assert-Status $loc13 200 "[13b] 번호 API #$($it.incidentNo)"
                    Assert-True ([long]$loc13.Json.jobId -eq [long]$it.jobId -and [int]$loc13.Json.queueRank -eq [int]$it.queueRank -and $loc13.Json.latest -eq $true) "[13b] #$($it.incidentNo) 위치 = 큐 행 작업·순위(latest)" $loc13
                    Assert-True ($det13.Json.detail.incident.incidentId -eq $it.incidentId -and [long]$det13.Json.incidentNo -eq [long]$it.incidentNo) "[13b] #$($it.incidentNo) 위치 상세의 incident_id·번호 = 행" $det13
                }

                # [13c] 새 DB 첫 동기화 묶음이 1절 순서(독립 SQL, 상대 순서). 첫 묶음 = created_at이 가장 이른 행들(한 묶음은 같은 시각으로 넣는다)
                $batch13 = @((Invoke-AuditSelect "SELECT incident_id FROM incident_refs WHERE created_at = (SELECT MIN(created_at) FROM incident_refs) ORDER BY incident_no") -split "`r?`n" | Where-Object { $_ })
                $refsCount13 = Invoke-AuditSelect "SELECT count(*), min(incident_no), max(incident_no), count(DISTINCT created_at) FROM incident_refs"
                $expected13 = @((Invoke-ZeekadSelect ("SELECT lq.incident_id FROM dashboard.latest_incident_queue lq LEFT JOIN (SELECT q.capture_id, q.incident_id, MIN(j.finished_at) AS d " +
                    "FROM dashboard.incident_queue q JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL " +
                    "GROUP BY q.capture_id, q.incident_id) fs ON fs.capture_id = lq.capture_id AND fs.incident_id = lq.incident_id " +
                    "ORDER BY fs.d ASC NULLS LAST, lq.capture_id COLLATE ucs_basic ASC, lq.incident_id COLLATE ucs_basic ASC")) -split "`r?`n" | Where-Object { $_ })
                $batchSet13 = @{}; foreach ($b in $batch13) { $batchSet13[$b] = $true }
                $expectedInBatch13 = @($expected13 | Where-Object { $batchSet13.ContainsKey($_) })
                $e2eLogs.Add("[13c] incident_refs (count, min, max, batches) = $refsCount13`n      first batch ($($batch13.Count)) by incident_no: $($batch13 -join ' ; ')`n      independent order (latest queue $($expected13.Count)): $($expectedInBatch13 -join ' ; ')")
                Assert-True ($batch13.Count -gt 0 -and $batch13.Count -eq $expected13.Count) "[13c] 첫 묶음 = 최신 큐 전체"
                Assert-True (($batch13 -join '|') -eq ($expectedInBatch13 -join '|')) "[13c] 첫 묶음 번호 순서 = 탐지 시각·캡처·incident_id 순(독립 SQL)"

                # [13d] 허용 밖 캡처 번호·없는 번호는 같은 403 + ACCESS_DENIED_IDOR(사유 구분), 숫자가 아니면 400(감사 없음)
                $hiddenNo13 = Invoke-AuditSelect "SELECT incident_no FROM incident_refs WHERE capture_id NOT LIKE 'cic17-%' ORDER BY incident_no LIMIT 1"
                $maxNo13 = [long](Invoke-AuditSelect "SELECT COALESCE(MAX(incident_no),0) FROM incident_refs")
                $d13a = Invoke-Http -Url "$baseHttps/api/incidents/no/$hiddenNo13" -CookieJar $q13A1
                $d13b = Invoke-Http -Url "$baseHttps/api/incidents/no/$($maxNo13 + 1000)" -CookieJar $q13A1
                $d13c = Invoke-Http -Url "$baseHttps/api/incidents/no/abc" -CookieJar $q13A1
                $reasons13 = Invoke-AuditSelect "SELECT action_type, detail_json FROM audit_logs WHERE id > $auditBase13 AND actor_username = 'analyst1' ORDER BY id"
                $e2eLogs.Add("[13d] analyst1 #$hiddenNo13(허용 밖): $(Format-Resp $d13a 200)`n      #$($maxNo13 + 1000)(없음): $(Format-Resp $d13b 200)`n      abc: $(Format-Resp $d13c 200)`n      audit since [13]: $($reasons13 -replace "`n", "`n      ")")
                Assert-ApiError $d13a 403 "FORBIDDEN" "[13d] 허용 밖 캡처 번호"
                Assert-ApiError $d13b 403 "FORBIDDEN" "[13d] 없는 번호"
                Assert-True ($d13a.Body -eq $d13b.Body) "[13d] 허용 밖·없는 번호 응답이 같다"
                Assert-ApiError $d13c 400 "INVALID_REQUEST" "[13d] 숫자가 아닌 번호"
                Assert-True ($reasons13 -match 'incident_no_capture_denied' -and $reasons13 -match 'incident_no_not_found' -and @($reasons13 -split "`r?`n" | Where-Object { $_ -match '^ACCESS_DENIED_IDOR' }).Count -eq 2) "[13d] IDOR 감사 2건(사유 구분), 400은 감사 없음"

                # [13e] viewer1: 허용 캡처 번호 200, 응답에 가리지 않은 IPv4 없음
                $vNo13 = Invoke-AuditSelect "SELECT incident_no FROM incident_refs WHERE capture_id LIKE 'cic17-%' ORDER BY incident_no LIMIT 1"
                $v13 = Invoke-Http -Url "$baseHttps/api/incidents/no/$vNo13" -CookieJar $q13V
                $v13d = Invoke-Http -Url "$baseHttps/api/incidents/$($v13.Json.jobId)/rank/$($v13.Json.queueRank)" -CookieJar $q13V
                $vIp13 = @(Get-UnmaskedIpv4 ($v13.Body + $v13d.Body))
                $e2eLogs.Add("[13e] viewer1 #$vNo13 -> $(Format-Resp $v13 200); detail incidentNo=$($v13d.Json.incidentNo) unmasked IPv4=[$($vIp13 -join ', ')]")
                Assert-Status $v13 200 "[13e] viewer1 허용 캡처 번호"
                Assert-True ($vIp13.Count -eq 0 -and [long]$v13d.Json.incidentNo -eq [long]$vNo13) "[13e] viewer1 번호 API·상세 IPv4 가림, 번호 같음"

                # [13f] incident_refs UPDATE·DELETE 거부(psql)
                $u13 = Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "verify-postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "zeekad_dashboard", "-c", "UPDATE incident_refs SET capture_id = capture_id WHERE incident_no = $vNo13")) -IgnoreExitCode
                $x13 = Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "verify-postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "zeekad_dashboard", "-c", "DELETE FROM incident_refs WHERE incident_no = $vNo13")) -IgnoreExitCode
                $e2eLogs.Add("[13f] psql UPDATE incident_refs: exit=$($u13.ExitCode) $($u13.Output.Trim())`n      psql DELETE incident_refs: exit=$($x13.ExitCode) $($x13.Output.Trim())")
                Assert-True ($u13.ExitCode -ne 0 -and $u13.Output -match 'append-only') "[13f] incident_refs UPDATE 거부"
                Assert-True ($x13.ExitCode -ne 0 -and $x13.Output -match 'append-only') "[13f] incident_refs DELETE 거부"

                # [13g] /incidents/{번호}·옛 주소가 nginx-waf를 지나 SPA 200(로그인 세션)
                $first13 = $items13[0]
                foreach ($pth in @("/incidents/$($first13.incidentNo)", "/incidents/$($first13.incidentNo)?tab=history", "/incidents/$($first13.jobId)/rank/$($first13.queueRank)")) {
                    $g13 = Invoke-Http -Url "$baseHttps$pth" -CookieJar $q13A1
                    $e2eLogs.Add("[13g] analyst1 GET $pth -> HTTP $($g13.Status) shell=$(Test-SpaShell $g13)")
                    Assert-Status $g13 200 "[13g] GET $pth"
                    Assert-True (Test-SpaShell $g13) "[13g] GET $pth SPA 셸" $g13
                }

                # [13h] 응답 시간: 데우기 1번 뒤 3번, 최댓값 1초 이하
                $t13 = [System.Collections.Generic.List[string]]::new()
                $slow13 = [System.Collections.Generic.List[string]]::new()
                foreach ($p in @("/api/incidents/no/$($first13.incidentNo)", "/api/incidents/queue?period=all", "/api/incidents/queue?period=24h", "/api/incidents/$($first13.jobId)/rank/$($first13.queueRank)")) {
                    $null = Invoke-Http -Url "$baseHttps$p" -CookieJar $q13A1
                    $ms = @()
                    for ($k = 0; $k -lt 3; $k++) {
                        $sw = [Diagnostics.Stopwatch]::StartNew()
                        $r = Invoke-Http -Url "$baseHttps$p" -CookieJar $q13A1
                        $sw.Stop()
                        Assert-Status $r 200 "[13h] $p"
                        $ms += [int]$sw.ElapsedMilliseconds
                    }
                    $max = ($ms | Measure-Object -Maximum).Maximum
                    $t13.Add("$p=[$($ms -join ', ')] max=$max ms")
                    if ($max -gt 1000) { $slow13.Add($p) }
                }
                $e2eLogs.Add("[13h] response times (analyst1, warm 1 + 3 samples, includes curl): $($t13 -join '; ')")
                Assert-True ($slow13.Count -eq 0) "[13h] 응답 시간 최댓값 1초 이하 ($($slow13 -join ', '))"

                # [14] 기간 밖 안내·공유 조회 계정 잠금 제외(T29). 큐 outsidePeriod = 독립 SQL(허용 캡처 최신 큐 중 기간 (기준-길이, 기준] 밖, 탐지 시각 없음 포함),
                #      수집원 lastDetectedAt = 독립 SQL(캡처별 최신 큐 탐지 시각 최대), VIEWER IPv4 가림, 응답 시간, 기본 설정(목록 비움)에서는 계정이 잠긴다.
                $q14A1 = Join-Path $tmpDir "q14-a1.cookies"
                $q14V = Join-Path $tmpDir "q14-v.cookies"
                Assert-Status (Login-Api "analyst1" $q14A1) 200 "[14] analyst1 로그인"
                Assert-Status (Login-Api "viewer1" $q14V) 200 "[14] viewer1 로그인"
                function Get-Anchor14($Resp) {
                    $m = [regex]::Match($Resp.Body, '"anchor":"([^"]+)"')
                    if (-not $m.Success) { throw "[14] 응답에 anchor 없음" }
                    return $m.Groups[1].Value
                }
                function Get-Sources14($Resp) {
                    $out = @{}
                    foreach ($m in [regex]::Matches($Resp.Body, '"captureId":"([^"]+)","sourceType":"[^"]*","latestJobId":[^,]*,"lastDetectedAt":(null|"([^"]+)")')) {
                        $out[$m.Groups[1].Value] = if ($m.Groups[2].Value -eq 'null') { $null } else { $m.Groups[3].Value }
                    }
                    return $out
                }
                function Get-Outside14Sql([string[]]$Captures, [string]$Anchor, [string]$Interval) {
                    $in = ($Captures | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ","
                    $a = $Anchor -replace "'", "''"
                    return Invoke-ZeekadSelect ("SELECT count(*) FROM dashboard.latest_incident_queue lq LEFT JOIN (SELECT q.capture_id, q.incident_id, MIN(j.finished_at) AS d " +
                        "FROM dashboard.incident_queue q JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL " +
                        "GROUP BY q.capture_id, q.incident_id) fs ON fs.capture_id = lq.capture_id AND fs.incident_id = lq.incident_id " +
                        "WHERE lq.capture_id IN ($in) AND NOT COALESCE(fs.d > TIMESTAMPTZ '$a' - INTERVAL '$Interval' AND fs.d <= TIMESTAMPTZ '$a', FALSE)")
                }
                $periods14 = @{ "1h" = "1 hour"; "24h" = "24 hours"; "7d" = "7 days"; "30d" = "30 days" }
                foreach ($who in @(@{ Name = "analyst1"; Jar = $q14A1 }, @{ Name = "viewer1"; Jar = $q14V })) {
                    $all14 = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=all&size=25" -CookieJar $who.Jar
                    Assert-Status $all14 200 "[14a] $($who.Name) 큐 전체"
                    $src14 = Get-Sources14 $all14
                    $caps14 = @($src14.Keys | Sort-Object)
                    Assert-True ($caps14.Count -gt 0) "[14a] $($who.Name) sources에 lastDetectedAt 있음" $all14
                    Assert-True ([long]$all14.Json.outsidePeriod -eq 0) "[14a] $($who.Name) 기간 전체 outsidePeriod = 0" $all14
                    foreach ($pk in @("24h", "7d")) {
                        $cases14 = @(@{ Q = "period=$pk"; Caps = $caps14 }, @{ Q = "period=$pk&captureId=$($caps14[0])"; Caps = @($caps14[0]) })
                        foreach ($c in $cases14) {
                            $r14 = Invoke-Http -Url "$baseHttps/api/incidents/queue?$($c.Q)&size=25" -CookieJar $who.Jar
                            Assert-Status $r14 200 "[14a] $($who.Name) $($c.Q)"
                            $anchor14 = Get-Anchor14 $r14
                            $sql14 = [long](Get-Outside14Sql $c.Caps $anchor14 $periods14[$pk])
                            $allQ14 = $c.Q -replace "period=$pk", 'period=all'
                            $allC = Invoke-Http -Url "$baseHttps/api/incidents/queue?$allQ14&size=25" -CookieJar $who.Jar
                            $e2eLogs.Add("[14a] $($who.Name) $($c.Q): total=$($r14.Json.total) outsidePeriod=$($r14.Json.outsidePeriod) newestOutsidePeriod=$($r14.Json.newestOutsidePeriod) anchor=$anchor14; independent SQL outside=$sql14; all-period total=$($allC.Json.total)")
                            Assert-True ([long]$r14.Json.outsidePeriod -eq $sql14) "[14a] $($who.Name) $($c.Q) outsidePeriod = 독립 SQL" $r14
                            Assert-True ([long]$r14.Json.outsidePeriod -eq ([long]$allC.Json.total - [long]$r14.Json.total)) "[14a] $($who.Name) $($c.Q) outsidePeriod = 기간 전체 total - total" $r14
                        }
                    }
                    # 수집원 마지막 탐지 = 독립 SQL(캡처별 최신 큐 탐지 시각 최대, epoch 초)
                    $in14 = ($caps14 | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ","
                    $ld14 = Invoke-ZeekadSelect ("SELECT lq.capture_id, COALESCE(floor(extract(epoch FROM MAX(fs.d)))::bigint::text, 'null') FROM dashboard.latest_incident_queue lq LEFT JOIN (SELECT q.capture_id, q.incident_id, MIN(j.finished_at) AS d " +
                        "FROM dashboard.incident_queue q JOIN dashboard.scoring_jobs j ON j.job_id = q.job_id AND j.status = 'succeeded' AND j.finished_at IS NOT NULL " +
                        "GROUP BY q.capture_id, q.incident_id) fs ON fs.capture_id = lq.capture_id AND fs.incident_id = lq.incident_id WHERE lq.capture_id IN ($in14) GROUP BY lq.capture_id")
                    $ldOk14 = $true
                    $ldLog14 = [System.Collections.Generic.List[string]]::new()
                    foreach ($line in @($ld14 -split "`r?`n" | Where-Object { $_ })) {
                        $p = $line -split '\|'
                        $api = $src14[$p[0]]
                        $apiEpoch = if ($api) { [string][long][Math]::Floor([DateTimeOffset]::Parse($api, [Globalization.CultureInfo]::InvariantCulture).ToUnixTimeMilliseconds() / 1000) } else { 'null' }
                        $ldLog14.Add("$($p[0]) api=$api ($apiEpoch) sql=$($p[1])")
                        if ($apiEpoch -ne $p[1]) { $ldOk14 = $false }
                    }
                    $e2eLogs.Add("[14b] $($who.Name) sources lastDetectedAt vs independent SQL: $($ldLog14 -join '; ')")
                    Assert-True ($ldOk14 -and $ldLog14.Count -eq $caps14.Count) "[14b] $($who.Name) 수집원 lastDetectedAt = 독립 SQL"
                }
                $v14 = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=24h&size=100" -CookieJar $q14V
                $v14b = Invoke-Http -Url "$baseHttps/api/incidents/queue?period=7d&size=100&asset=10" -CookieJar $q14V
                $vIp14 = @(Get-UnmaskedIpv4 ($v14.Body + $v14b.Body))
                $e2eLogs.Add("[14c] viewer1 queue 24h / 7d asset=10 -> HTTP $($v14.Status)/$($v14b.Status) outsidePeriod=$($v14.Json.outsidePeriod)/$($v14b.Json.outsidePeriod) unmasked IPv4=[$($vIp14 -join ', ')]")
                Assert-True ($v14.Status -eq 200 -and $v14b.Status -eq 200 -and $vIp14.Count -eq 0) "[14c] viewer1 응답에 가리지 않은 IPv4 없음"

                # [14d] 응답 시간: 데우기 1번 뒤 3번, 최댓값 1초 이하(큐 24시간·전체·자산 검색, 현황판 큐 호출, 현황판 overview)
                $t14 = [System.Collections.Generic.List[string]]::new()
                $slow14 = [System.Collections.Generic.List[string]]::new()
                foreach ($p in @("/api/incidents/queue?period=24h", "/api/incidents/queue?period=all", "/api/incidents/queue?period=24h&asset=10", "/api/incidents/queue?period=24h&sort=detected&dir=desc&size=25", "/api/dashboard/overview?period=24h")) {
                    $null = Invoke-Http -Url "$baseHttps$p" -CookieJar $q14A1
                    $ms = @()
                    for ($k = 0; $k -lt 3; $k++) {
                        $sw = [Diagnostics.Stopwatch]::StartNew()
                        $r = Invoke-Http -Url "$baseHttps$p" -CookieJar $q14A1
                        $sw.Stop()
                        Assert-Status $r 200 "[14d] $p"
                        $ms += [int]$sw.ElapsedMilliseconds
                    }
                    $max = ($ms | Measure-Object -Maximum).Maximum
                    $t14.Add("$p=[$($ms -join ', ')] max=$max ms")
                    if ($max -gt 1000) { $slow14.Add($p) }
                }
                $e2eLogs.Add("[14d] response times (analyst1, warm 1 + 3 samples, includes curl): $($t14 -join '; ')")
                Assert-True ($slow14.Count -eq 0) "[14d] 응답 시간 최댓값 1초 이하 ($($slow14 -join ', '))"

                # [14e] 기본 설정(DASHBOARD_LOCKOUT_EXEMPT_USERNAMES 비움)에서는 지금처럼 5번째 실패에 잠긴다(analyst2, 마지막 단계라 뒤 단계에 영향 없음)
                $exempt14 = (Invoke-NativeCapture "docker" ($execPrefix + @('printf "%s" "${DASHBOARD_LOCKOUT_EXEMPT_USERNAMES-<unset>}"')) -IgnoreExitCode).Output.Trim()
                $auditBase14 = [long](Invoke-AuditSelect "SELECT COALESCE(MAX(id),0) FROM audit_logs")
                $lockCodes14 = [System.Collections.Generic.List[string]]::new()
                for ($k = 1; $k -le 5; $k++) {
                    $jar = Join-Path $tmpDir "q14-lock-$k.cookies"
                    $null = Invoke-Http -Url "$baseHttps/api/auth/csrf" -CookieJar $jar -SaveCookies
                    $lr = Invoke-Http -Url "$baseHttps/api/auth/login" -Method POST -CookieJar $jar -SaveCookies -Csrf -JsonBody @{ username = "analyst2"; password = "wrong-$(New-RandomToken 8)" }
                    $lockCodes14.Add("$($lr.Status)")
                }
                $jarOk = Join-Path $tmpDir "q14-lock-ok.cookies"
                $okRes14 = Login-Api "analyst2" $jarOk
                $audit14 = Invoke-AuditSelect "SELECT action_type, count(*) FROM audit_logs WHERE id > $auditBase14 AND actor_username = 'analyst2' GROUP BY action_type ORDER BY action_type"
                $e2eLogs.Add("[14e] app env DASHBOARD_LOCKOUT_EXEMPT_USERNAMES='$exempt14'; analyst2 wrong x5 -> HTTP [$($lockCodes14 -join ', ')]; correct password -> $(Format-Resp $okRes14 200); audit: $($audit14 -replace "`r?`n", '; ')")
                Assert-True (($lockCodes14 -join ',') -eq '401,401,401,401,423') "[14e] 기본 설정 5번째 실패에 423 잠금"
                Assert-ApiError $okRes14 423 "ACCOUNT_LOCKED" "[14e] 잠긴 뒤 맞는 비밀번호도 423"
                Assert-True ($audit14 -match '(?m)^ACCOUNT_LOCKED\|1\s*$') "[14e] ACCOUNT_LOCKED 감사 1건"

                # [15] XML 본문 경로(T31). 기반 규칙 200000이 XML Content-Type 본문을 libxml2로 파싱하고, 200002가 파싱 오류를 400으로 막는다.
                #      로그인 경로가 아닌 POST /api/...에 인증 없이 보낸다(로그인 실패·잠금 계수가 생기지 않게). 외부 엔터티·서비스 거부 페이로드는 보내지 않는다.
                $xmlPath15 = "/api/incidents/101/rank/2/assignment"
                $auditBase15 = [long](Invoke-AuditSelect "SELECT COALESCE(MAX(id),0) FROM audit_logs")
                # [15a] 깨진 XML -> 400, WAF 로그에 그 요청의 규칙 200002·http_code 400·"XML parsing error"
                $probe15a = "e2e-t31-xml-bad-$(New-RandomToken 8)"
                $bad15 = Invoke-Http -Url "$baseHttps$xmlPath15" -Method POST -ProbeId $probe15a -RawBody "<a><b></a>" -RawContentType "application/xml"
                $line15a = $null
                for ($i = 0; $i -lt 10 -and -not $line15a; $i++) {
                    $wafLogs15 = (Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--no-log-prefix", "nginx-waf")) -IgnoreExitCode).Output
                    $line15a = $wafLogs15 -split "`r?`n" | Where-Object { $_.StartsWith('{"transaction"') -and $_.Contains($probe15a) } | Select-Object -Last 1
                    if (-not $line15a) { Start-Sleep -Seconds 1 }
                }
                $rules15a = @([regex]::Matches([string]$line15a, '"ruleId":"(\d+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
                $code15a = [regex]::Match([string]$line15a, '"http_code":(\d+)').Groups[1].Value
                $data15a = [regex]::Match([string]$line15a, '"data":"(XML parsing error[^"]*)"').Groups[1].Value
                $msg15a = [regex]::Match([string]$line15a, '"message":"(Failed to parse request body[^"]*)"').Groups[1].Value
                $e2eLogs.Add("[15a] unauthenticated POST $xmlPath15 Content-Type: application/xml body '<a><b></a>': $(Format-Resp $bad15 120)`n      WAF log: http_code=$code15a ruleIds=[$($rules15a -join ', ')] message='$msg15a' data='$data15a'")
                Assert-Status $bad15 400 "[15a] 깨진 XML 본문"
                Assert-True ([bool]$line15a) "[15a] nginx-waf 감사 로그에 probe=$probe15a 기록"
                Assert-True ($rules15a -contains "200002" -and $code15a -eq "400" -and $data15a.StartsWith("XML parsing error")) "[15a] WAF 로그 규칙 200002·http_code 400·XML parsing error"
                # [15b] 잘 짜인 XML -> WAF를 지나 앱이 답한다(5xx 아님, WAF 차단 기록 없음)
                $probe15b = "e2e-t31-xml-ok-$(New-RandomToken 8)"
                $ok15 = Invoke-Http -Url "$baseHttps$xmlPath15" -Method POST -ProbeId $probe15b -RawBody "<a><b>1</b></a>" -RawContentType "application/xml"
                Start-Sleep -Seconds 1
                $wafLogs15b = (Invoke-NativeCapture "docker" ($composeArgs + @("logs", "--no-log-prefix", "nginx-waf")) -IgnoreExitCode).Output
                $lines15b = @($wafLogs15b -split "`r?`n" | Where-Object { $_.StartsWith('{"transaction"') -and $_.Contains($probe15b) })
                $interrupted15b = @($lines15b | Where-Object { $_ -match '"is_interrupted":true' })
                $rules15b = @($lines15b | ForEach-Object { [regex]::Matches($_, '"ruleId":"(\d+)"') | ForEach-Object { $_.Groups[1].Value } } | Select-Object -Unique)
                $logins15 = Invoke-AuditSelect "SELECT COUNT(*) FROM audit_logs WHERE id > $auditBase15 AND action_type IN ('LOGIN_FAILURE','ACCOUNT_LOCKED')"
                $health15 = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{.State.Health.Status}}", "$projectName-nginx-waf-1") -IgnoreExitCode).Output.Trim()
                $e2eLogs.Add("[15b] unauthenticated POST $xmlPath15 Content-Type: application/xml body '<a><b>1</b></a>': $(Format-Resp $ok15 200)`n      WAF audit lines for probe=$($lines15b.Count) interrupted=$($interrupted15b.Count) ruleIds=[$($rules15b -join ', ')]`n      LOGIN_FAILURE/ACCOUNT_LOCKED audit rows since [15] = $logins15`n      nginx-waf health after [15] = $health15")
                Assert-True ($ok15.Status -ge 400 -and $ok15.Status -lt 500) "[15b] 잘 짜인 XML 본문은 앱 4xx(5xx 아님)" $ok15
                Assert-True ($null -ne $ok15.Json -and $null -ne $ok15.Json.code) "[15b] 응답이 앱 ApiErrorResponse JSON(WAF가 막지 않음)" $ok15
                Assert-True ($interrupted15b.Count -eq 0) "[15b] nginx-waf 차단 기록 없음"
                Assert-True ([int]$logins15 -eq 0) "[15] 로그인 실패·잠금 감사 0"
                Assert-True ($health15 -eq "healthy") "[15] nginx-waf healthy ($health15)"

                # [16] 전달 헤더 신뢰(T32). 앱은 nginx-waf 고정 주소에서 온 연결의 X-Forwarded-*만 믿는다.
                #      (a) WAF 경유: 클라이언트가 붙인 X-Forwarded-For는 여전히 무시되고 https 판정(HSTS)·쿠키 속성은 그대로다.
                #      (b) 리다이렉트 Location이 T31까지(framework 전략)와 같다: HTTP->HTTPS, 화면 아닌 경로 /login, 스택 안 8443 경로, T27 화면 경로 셸.
                #      (c) 앱 직접: WAF가 아닌 컨테이너(verify-postgres, busybox wget)가 dashboard-app:8080에 전달 헤더를 붙여도
                #          감사 로그 IP는 그 컨테이너 주소이고 https로 판정하지 않으며 Location도 연결 값 그대로다. 새 이미지를 받지 않는다.
                #      로그인 시도는 없는 계정이라 잠금 계수에 영향이 없다.
                $wafIp16 = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "$projectName-nginx-waf-1")).Output.Trim()
                $appTrusted16 = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "dashboard-app", "sh", "-c", 'printf "%s" "${DASHBOARD_TRUSTED_PROXIES-<unset>}"')) -IgnoreExitCode).Output.Trim()
                $pgIp16 = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "$projectName-verify-postgres-1")).Output.Trim()
                $e2eLogs.Add("[16] nginx-waf address=$wafIp16, dashboard-app DASHBOARD_TRUSTED_PROXIES=$appTrusted16, verify-postgres address=$pgIp16")
                Assert-True ($wafIp16 -eq "10.203.49.250" -and $appTrusted16 -eq $wafIp16) "[16] nginx-waf 고정 주소 = 앱 신뢰 목록 = 10.203.49.250"

                # (a) WAF 경유
                $user16a = "t32_waf_$(New-RandomToken 6)"
                $jar16 = Join-Path $tmpDir "t32-a.cookies"
                $csrf16a = Invoke-Http -Url "$baseHttps/api/auth/csrf" -CookieJar $jar16 -SaveCookies
                $login16a = Invoke-Http -Url "$baseHttps/api/auth/login" -Method POST -CookieJar $jar16 -SaveCookies -Csrf `
                    -JsonBody @{ username = $user16a; password = "wrong-t32" } -ExtraHeaders @("X-Forwarded-For: 203.0.113.16", "X-Forwarded-Proto: http", "X-Forwarded-Port: 80")
                $ip16a = Invoke-AuditSelect "SELECT COALESCE(client_ip,'') FROM audit_logs WHERE actor_username = '$user16a' AND action_type = 'LOGIN_FAILURE' ORDER BY id DESC LIMIT 1"
                $hsts16a = Get-HeaderValue $csrf16a "Strict-Transport-Security"
                $e2eLogs.Add("[16a] via WAF: GET /api/auth/csrf -> HTTP $($csrf16a.Status) Strict-Transport-Security=$hsts16a; POST /api/auth/login (unknown user, X-Forwarded-For: 203.0.113.16, X-Forwarded-Proto: http, X-Forwarded-Port: 80) -> HTTP $($login16a.Status); audit LOGIN_FAILURE client_ip=$ip16a (B=$ipB)")
                Assert-True ($login16a.Status -eq 401 -and $ip16a -eq $ipB) "[16a] WAF 경유 감사 로그 IP = B, 위조 X-Forwarded-For 무시 (client_ip=$ip16a, B=$ipB)"
                Assert-True ([bool]$hsts16a) "[16a] WAF 경유 https 요청은 https 판정(HSTS 있음)" $csrf16a
                $xsrfCookie16 = [regex]::Match($csrf16a.Headers, '(?im)^Set-Cookie:\s*XSRF-TOKEN=[^\r\n]*').Value
                $e2eLogs.Add("[16a] XSRF-TOKEN Set-Cookie: $(Redact-Cookies $xsrfCookie16)")
                Assert-True ($xsrfCookie16 -match '(?i);\s*Secure' -and $xsrfCookie16 -match '(?i)SameSite=Lax') "[16a] XSRF-TOKEN 쿠키 Secure·SameSite=Lax"

                # (b) Location
                $redir16 = [ordered]@{}
                $r16 = Invoke-Http -Url "$baseHttp/login"; $redir16["http /login"] = "$($r16.Status) $(Get-HeaderValue $r16 'Location')"
                $r16 = Invoke-Http -Url "$baseHttps/nope"; $redir16["https /nope"] = "$($r16.Status) $(Get-HeaderValue $r16 'Location')"
                $r16 = Invoke-Http -Url "$baseHttps/nope" -ExtraHeaders @("X-Forwarded-Proto: http", "X-Forwarded-Port: 80", "X-Forwarded-Host: evil.example")
                $redir16["https /nope + forged proto/port/host"] = "$($r16.Status) $(Get-HeaderValue $r16 'Location')"
                $r16 = Invoke-Http -Url "$baseHttps/incidents/1"; $redir16["https /incidents/1 (T27 shell)"] = "$($r16.Status) shell=$(Test-SpaShell $r16) location=$(Get-HeaderValue $r16 'Location')"
                $in8443 = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "nginx-waf", "curl", "-sk", "-o", "/dev/null", "-D", "-", "https://nginx-waf:8443/nope")) -IgnoreExitCode).Output
                $loc8443 = [regex]::Match($in8443, '(?im)^Location:\s*(\S+)').Groups[1].Value
                $status8443 = [regex]::Match($in8443, '(?im)^HTTP/\S+\s+(\d+)').Groups[1].Value
                $redir16["in-network https://nginx-waf:8443/nope"] = "$status8443 $loc8443"
                foreach ($k in $redir16.Keys) { $e2eLogs.Add("[16b] $k -> $($redir16[$k])") }
                Assert-True ($redir16["http /login"] -eq "301 https://127.0.0.1:$WafHttpsPort/login") "[16b] HTTP->HTTPS Location ($($redir16['http /login']))"
                Assert-True ($redir16["https /nope"] -eq "302 https://127.0.0.1:$WafHttpsPort/login") "[16b] /nope Location이 T31과 같음 ($($redir16['https /nope']))"
                Assert-True ($redir16["https /nope + forged proto/port/host"] -eq "302 https://127.0.0.1:$WafHttpsPort/login") "[16b] 위조 전달 헤더를 붙여도 Location 같음 ($($redir16['https /nope + forged proto/port/host']))"
                Assert-True ($redir16["https /incidents/1 (T27 shell)"] -eq "200 shell=True location=") "[16b] T27 화면 경로는 셸 200(Location 없음)"
                Assert-True ($redir16["in-network https://nginx-waf:8443/nope"] -eq "302 https://nginx-waf:8443/login") "[16b] 스택 안 8443 경로 Location(T12) ($($redir16['in-network https://nginx-waf:8443/nope']))"

                # (c) 앱 직접(verify-postgres 안 busybox wget). 스크립트는 base64로 넘겨 인용 문제를 피한다.
                $user16c = "t32_direct_$(New-RandomToken 6)"
                $sh16 = @(
                    'B=http://dashboard-app:8080',
                    'F1="X-Forwarded-For: 203.0.113.17"; F2="X-Forwarded-Proto: https"; F3="X-Forwarded-Port: 443"',
                    'HDR=$(wget -S -q -O /dev/null --header "$F1" --header "$F2" --header "$F3" "$B/api/auth/csrf" 2>&1)',
                    'echo "== csrf"',
                    'echo "$HDR" | grep -i -E "HTTP/|strict-transport|set-cookie" | sed -E "s/(XSRF-TOKEN=)[^;]*/\1<redacted>/"',
                    'T=$(echo "$HDR" | sed -n "s/.*[Ss]et-[Cc]ookie: XSRF-TOKEN=\([^;]*\).*/\1/p" | head -n1)',
                    'echo "== login"',
                    'wget -S -q -O /dev/null --header "$F1" --header "$F2" --header "$F3" --header "Cookie: XSRF-TOKEN=$T" --header "X-XSRF-TOKEN: $T" --header "Content-Type: application/json" --post-data "{\"username\":\"__USER__\",\"password\":\"wrong-t32\"}" "$B/api/auth/login" 2>&1 | grep -E "HTTP/|wget:"',
                    'echo "== nope"',
                    'wget -S -q -O /dev/null --header "$F1" --header "$F2" --header "$F3" "$B/nope" 2>&1 | grep -i -E "HTTP/|location:" | head -n2'
                ) -join "`n"
                $sh16 = $sh16.Replace("__USER__", $user16c)
                $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sh16))
                $direct16 = (Invoke-NativeCapture "docker" ($composeArgs + @("exec", "-T", "verify-postgres", "sh", "-c", "echo $b64 | base64 -d | sh")) -IgnoreExitCode).Output
                $ip16c = Invoke-AuditSelect "SELECT COALESCE(client_ip,'') FROM audit_logs WHERE actor_username = '$user16c' AND action_type = 'LOGIN_FAILURE' ORDER BY id DESC LIMIT 1"
                $csrfPart16 = ($direct16 -split "== login")[0]
                $loginPart16 = (($direct16 -split "== login")[1] -split "== nope")[0]
                $nopeLoc16 = [regex]::Match($direct16, '(?im)^\s*Location:\s*(\S+)').Groups[1].Value
                $e2eLogs.Add("[16c] direct from verify-postgres ($pgIp16) to dashboard-app:8080 with X-Forwarded-For: 203.0.113.17, X-Forwarded-Proto: https, X-Forwarded-Port: 443:`n$($direct16.Trim())`n      audit LOGIN_FAILURE ($user16c) client_ip=$ip16c")
                Assert-True ($csrfPart16 -match 'HTTP/1\.1 200' -and $csrfPart16 -notmatch '(?i)strict-transport-security') "[16c] 앱 직접 + X-Forwarded-Proto: https -> https 판정 아님(HSTS 없음)"
                Assert-True ($loginPart16 -match '401') "[16c] 앱 직접 로그인(없는 계정) 401"
                Assert-True ($ip16c -eq $pgIp16 -and $ip16c -ne "203.0.113.17") "[16c] 앱 직접 감사 로그 IP = verify-postgres 주소 (client_ip=$ip16c, 기대 $pgIp16)"
                Assert-True ($nopeLoc16 -eq "http://dashboard-app:8080/login") "[16c] 앱 직접 Location은 연결 값(http, 8080) ($nopeLoc16)"

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
            # 유일한 예외(2026-11-20 결정, docs/security-verification-report.md 남은 위험): 모든 인스턴스의 param이 정확히 XSRF-TOKEN인 Low 10010(Cookie No HttpOnly Flag)만 허용한다.
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
