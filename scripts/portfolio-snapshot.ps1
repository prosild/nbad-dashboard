param(
    [string]$OutDir = "build/portfolio",
    [string]$SourceContainer = "zeekad-postgres-1",
    [string]$Database = "zeekad",
    [string]$RestoreImage = "pgvector/pgvector:0.8.1-pg17",
    [string]$PipelineImage = "zeekad-pipeline:dev",
    [switch]$SkipSecretScan
)

# 포트폴리오 배포용 zeek_AD DB 스냅샷 내보내기(읽기 전용).
# - 원본 컨테이너 안의 로컬 소켓 인증(psql/pg_dump -U postgres)만 쓴다. zeek_AD의 .env나 비밀번호는 읽지 않는다.
# - 원본 컨테이너에는 아무것도 쓰지 않는다(덤프는 표준 출력으로 받아 이 PC 파일에 쓴다).
# - 결과: <OutDir>/zeekad.dump(pg_dump -Fc), zeekad.dump.sha256(sha256sum -c 형식), manifest.json,
#   source-globals.sql(pg_dumpall --globals-only --no-role-passwords, 역할 비교용),
#   secret-scan.txt(덤프·근거 API 이미지의 비밀값 패턴 위치·건수, 값은 남기지 않음). OutDir 기본값은 Git 제외 경로다.

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot
$OutFullDir = if ([IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $RepoRoot $OutDir }
New-Item -ItemType Directory -Force -Path $OutFullDir | Out-Null
$utf8NoBom = [Text.UTF8Encoding]::new($false)

function Invoke-NativeCapture([string]$Command, [string[]]$CommandArgs) {
    $savedEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Command @CommandArgs 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedEap
    }
    if ($code -ne 0) { throw "$Command $($CommandArgs -join ' ') 실패 (exit=$code)`n$output" }
    return $output
}

# 바이너리 표준 출력을 그대로 파일에 쓴다(PowerShell 파이프는 바이트를 문자열로 바꿔 덤프를 깨뜨린다).
function Invoke-NativeToFile([string]$Command, [string[]]$CommandArgs, [string]$Destination) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Command
    $psi.Arguments = ($CommandArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $errTask = $proc.StandardError.ReadToEndAsync()
    $fs = [IO.File]::Create($Destination)
    try {
        $proc.StandardOutput.BaseStream.CopyTo($fs)
    } finally {
        $fs.Close()
    }
    $proc.WaitForExit()
    $stderr = $errTask.Result
    if ($proc.ExitCode -ne 0) { throw "$Command $($psi.Arguments) 실패 (exit=$($proc.ExitCode))`n$stderr" }
    return $stderr
}

function Get-CaptureCounts {
    $sql = "SELECT capture_id, count(*) FROM dashboard.latest_incident_queue GROUP BY capture_id ORDER BY capture_id"
    $out = Invoke-NativeCapture "docker" @("exec", $SourceContainer, "psql", "-U", "postgres", "-d", $Database, "-v", "ON_ERROR_STOP=1", "-AtF", "|", "-c", $sql)
    $counts = [ordered]@{}
    foreach ($line in ($out -split "`r?`n")) {
        if ($line -match '^([^|]+)\|(\d+)$') { $counts[$Matches[1]] = [int]$Matches[2] }
    }
    if ($counts.Count -eq 0) { throw "dashboard.latest_incident_queue 캡처별 건수를 읽지 못했습니다:`n$out" }
    return $counts
}

$state = (Invoke-NativeCapture "docker" @("inspect", "--format", "{{.State.Running}}", $SourceContainer)).Trim()
if ($state -ne "true") { throw "원본 컨테이너 $SourceContainer 가 실행 중이 아닙니다 (State.Running=$state)" }

$serverVersion = (Invoke-NativeCapture "docker" @("exec", $SourceContainer, "psql", "-U", "postgres", "-d", $Database, "-Atc", "SHOW server_version")).Trim()
$pgDumpVersion = (Invoke-NativeCapture "docker" @("exec", $SourceContainer, "pg_dump", "--version")).Trim()

Write-Host "=== [1/5] 캡처별 조사 큐 건수(덤프 전) ==="
$countsBefore = Get-CaptureCounts
$countsBefore.GetEnumerator() | ForEach-Object { Write-Host "  $($_.Key) = $($_.Value)" }

Write-Host "=== [2/5] pg_dump -Fc $Database ==="
$dumpPath = Join-Path $OutFullDir "zeekad.dump"
$tmpDump = "$dumpPath.partial"
Remove-Item -Force -ErrorAction SilentlyContinue $tmpDump
$exportedAt = [DateTimeOffset]::Now
[void](Invoke-NativeToFile "docker" @("exec", $SourceContainer, "pg_dump", "-U", "postgres", "-Fc", $Database) $tmpDump)
Move-Item -Force $tmpDump $dumpPath

Write-Host "=== [3/5] 캡처별 조사 큐 건수(덤프 후) — 덤프 전과 같아야 같은 시점 건수로 인정 ==="
$countsAfter = Get-CaptureCounts
$beforeText = ($countsBefore.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ","
$afterText = ($countsAfter.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ","
if ($beforeText -ne $afterText) {
    throw "덤프 전후 캡처별 건수가 다릅니다(원본이 바뀌는 중). 파이프라인이 멈춘 뒤 다시 실행하세요.`n전: $beforeText`n후: $afterText"
}

Write-Host "=== [4/5] 전역 객체(역할) 비교용 덤프와 매니페스트 ==="
$globalsPath = Join-Path $OutFullDir "source-globals.sql"
[void](Invoke-NativeToFile "docker" @("exec", $SourceContainer, "pg_dumpall", "-U", "postgres", "--globals-only", "--no-role-passwords") $globalsPath)

$sha = (Get-FileHash -Algorithm SHA256 $dumpPath).Hash.ToLowerInvariant()
$bytes = (Get-Item $dumpPath).Length
[IO.File]::WriteAllText((Join-Path $OutFullDir "zeekad.dump.sha256"), "$sha  zeekad.dump`n", $utf8NoBom)

$manifest = [ordered]@{
    database             = $Database
    sourceContainer      = $SourceContainer
    serverVersion        = $serverVersion
    pgDumpVersion        = $pgDumpVersion
    format               = "pg_dump -Fc (owners and privileges included)"
    exportedAt           = $exportedAt.ToString("yyyy-MM-ddTHH:mm:sszzz")
    dumpFile             = "zeekad.dump"
    dumpBytes            = $bytes
    dumpSha256           = $sha
    countSource          = "dashboard.latest_incident_queue GROUP BY capture_id (counted before and after pg_dump; equal)"
    captureIncidentCounts = $countsAfter
}
$manifestJson = $manifest | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText((Join-Path $OutFullDir "manifest.json"), $manifestJson, $utf8NoBom)

Write-Host $manifestJson

if (-not $SkipSecretScan) {
    Write-Host "=== [5/5] 비밀값 패턴 검사(덤프 내용, $PipelineImage 이미지) — 값은 남기지 않고 위치·패턴·건수만 기록 ==="
    $patterns = [ordered]@{
        "slack_webhook(hooks.slack.com)" = 'hooks\.slack\.com'
        "slack_bot_token(xoxb-)"         = 'xoxb-'
        "slack_user_token(xoxp-)"        = 'xoxp-'
        "sk-(token prefix)"              = '(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{8,}'
        "google_api_key(AIza)"           = 'AIza[0-9A-Za-z_-]{30,}'
        "api_key"                        = '(?i)api[_-]?key'
        "password"                       = '(?i)password'
        "private_key_block"              = 'BEGIN [A-Z ]*PRIVATE KEY'
    }
    $report = [System.Collections.Generic.List[string]]::new()
    $report.Add("# portfolio secret scan ($([DateTimeOffset]::Now.ToString('yyyy-MM-ddTHH:mm:sszzz')))")
    $report.Add("# 찾은 값은 기록하지 않는다. 형식: 위치 | 패턴 | 건수")
    $report.Add("patterns: $(($patterns.GetEnumerator() | ForEach-Object { "$($_.Key)=/$($_.Value)/" }) -join '  ')")

    # (1) 덤프: 일회용 컨테이너(네트워크 없음)에서 pg_restore -f - 로 SQL 텍스트를 만들어 COPY 블록의 표·열 단위로 센다.
    $sqlPath = Join-Path $OutFullDir "zeekad.dump.scan.sql"
    $snapMount = "${OutFullDir}:/snap:ro"
    [void](Invoke-NativeToFile "docker" @("run", "--rm", "--network", "none", "-v", $snapMount, "--entrypoint", "pg_restore", $RestoreImage, "-f", "-", "/snap/zeekad.dump") $sqlPath)
    $hits = @{}
    $copyTable = $null
    $copyCols = @()
    $lineNo = 0
    $reader = New-Object IO.StreamReader($sqlPath, $utf8NoBom)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $lineNo++
            if ($copyTable) {
                if ($line -eq '\.') { $copyTable = $null; continue }
                $fields = $line -split "`t"
                for ($i = 0; $i -lt $fields.Count; $i++) {
                    foreach ($p in $patterns.GetEnumerator()) {
                        $n = [regex]::Matches($fields[$i], $p.Value).Count
                        if ($n -gt 0) {
                            $col = if ($i -lt $copyCols.Count) { $copyCols[$i] } else { "col$i" }
                            $key = "dump:$copyTable.$col | $($p.Key)"
                            $hits[$key] = [int]$hits[$key] + $n
                        }
                    }
                }
                continue
            }
            if ($line -match '^COPY ([^ ]+) \((.*)\) FROM stdin;$') {
                $copyTable = $Matches[1]
                $copyCols = @($Matches[2] -split ',\s*' | ForEach-Object { $_.Trim('"') })
                continue
            }
            foreach ($p in $patterns.GetEnumerator()) {
                $n = [regex]::Matches($line, $p.Value).Count
                if ($n -gt 0) {
                    $key = "dump:DDL(line $lineNo) | $($p.Key)"
                    $hits[$key] = [int]$hits[$key] + $n
                }
            }
        }
    } finally {
        $reader.Close()
        Remove-Item -Force -ErrorAction SilentlyContinue $sqlPath
    }
    $report.Add("")
    $report.Add("## dump zeekad.dump (sha256 $sha)")
    if ($hits.Count -eq 0) { $report.Add("(no matches)") } else { $hits.Keys | Sort-Object | ForEach-Object { $report.Add("$_ | $($hits[$_])") } }

    # (2) 근거 API 이미지: 비밀 파일 이름(파일 시스템 전체)과 프로젝트 코드(/app, 홈)의 패턴 건수. grep -c는 건수만 낸다.
    $grepPatterns = [ordered]@{
        "slack_webhook(hooks.slack.com)" = 'hooks\.slack\.com'
        "slack_bot_token(xoxb-)"         = 'xoxb-'
        "slack_user_token(xoxp-)"        = 'xoxp-'
        "sk-(token prefix)"              = '(^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{8,}'
        "google_api_key(AIza)"           = 'AIza[0-9A-Za-z_-]{30,}'
        "api_key"                        = '[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]'
        "password"                       = '[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]'
        "private_key_block"              = 'BEGIN [A-Z ]*PRIVATE KEY'
    }
    $shLines = @(
        "echo '## secret-like file names (find / -xdev, excluding /proc /sys)'",
        "find / -xdev \( -path /proc -o -path /sys \) -prune -o -type f \( -name .env -o -name '*.env' -o -name '.env.*' -o -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name 'id_ed25519*' -o -name '*.p12' -o -name '*.pfx' -o -name '.netrc' -o -name '.pgpass' -o -name '.git-credentials' -o -name 'credentials*' \) -print 2>/dev/null | sort || true"
    )
    foreach ($p in $grepPatterns.GetEnumerator()) {
        $shLines += "echo '## content /app /home/zeekad | $($p.Key)'"
        $shLines += "grep -rIcE -- '$($p.Value)' /app /home/zeekad 2>/dev/null | grep -v ':0`$' || echo '(no matches)'"
    }
    $imageOut = Invoke-NativeCapture "docker" @("run", "--rm", "--network", "none", "--entrypoint", "sh", $PipelineImage, "-c", ($shLines -join "`n"))
    $imageId = (Invoke-NativeCapture "docker" @("image", "inspect", "--format", "{{.Id}}", $PipelineImage)).Trim()
    $report.Add("")
    $report.Add("## image $PipelineImage ($imageId) — 형식: 파일경로:건수")
    $report.Add($imageOut.Trim())

    $scanText = ($report -join "`n") + "`n"
    [IO.File]::WriteAllText((Join-Path $OutFullDir "secret-scan.txt"), $scanText, $utf8NoBom)
    Write-Host $scanText
}

Write-Host "스냅샷 완료: $OutFullDir"
