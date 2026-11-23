param(
    [string]$OutDir = "build/portfolio",
    [string]$SourceContainer = "zeekad-postgres-1",
    [string]$Database = "zeekad",
    [string]$RestoreImage = "pgvector/pgvector:0.8.1-pg17",
    [string]$PipelineImage = "zeekad-pipeline:dev",
    # 원본 선택(T22): 비어 있으면 로컬 Docker의 $SourceContainer. 값이 있으면 WSL($WslDistro)의 ssh로
    # 그 호스트(예: <배포 VM>)의 $SourceContainer를 읽는다. 원격에는 docker ps/inspect/exec(psql 조회,
    # pg_dump, pg_dumpall --globals-only)만 보내고 파일을 남기지 않는다(덤프는 ssh 표준 출력으로 받는다).
    [string]$SshHost = "",
    [string]$WslDistro = "Ubuntu",
    # 공개할 캡처(demo 허용 패턴과 같은 형식: 정확한 ID 또는 접두사*). 덤프 전후 건수는 이 캡처들만 같으면 된다.
    [string]$PublicCaptures = "cic17-*,syn1-*,lab-20261119,lab-20261122",
    [switch]$SkipSecretScan
)

# 포트폴리오 배포용 zeek_AD DB 스냅샷 내보내기(읽기 전용).
# - 원본 컨테이너 안의 로컬 소켓 인증(psql/pg_dump -U postgres)만 쓴다. zeek_AD의 .env나 비밀번호는 읽지 않는다.
# - 원본 컨테이너에는 아무것도 쓰지 않는다(덤프는 표준 출력으로 받아 로컬 파일에 쓴다).
# - 원본에 보낸 명령은 <OutDir>/source-commands.txt에 그대로 남는다(원격이면 보낸 스크립트 원문).
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

# --- 원본 명령 실행(로컬 docker 또는 WSL ssh 원격) ---------------------------------------
$sourceLog = [System.Collections.Generic.List[string]]::new()
$sourceLabel = if ($SshHost) { "ssh:$SshHost/$SourceContainer" } else { "local:$SourceContainer" }
$remoteDir = Join-Path $OutFullDir "source-remote"
$remoteSeq = 0
if ($SshHost) {
    if ($SshHost -notmatch '^[A-Za-z0-9._-]+$') { throw "SshHost 형식이 올바르지 않습니다: $SshHost" }
    if ($WslDistro -notmatch '^[A-Za-z0-9._-]+$') { throw "WslDistro 형식이 올바르지 않습니다: $WslDistro" }
    New-Item -ItemType Directory -Force -Path $remoteDir | Out-Null
    Get-ChildItem -Path $remoteDir -Filter '*.sh' -ErrorAction SilentlyContinue | Remove-Item -Force
}

# 명령을 보낼 때마다 기록 파일을 다시 써서, 중간에 멈춰도 그때까지 보낸 명령이 남는다.
function Add-SourceLog([string]$Entry) {
    $script:sourceLog.Add($Entry)
    [IO.File]::WriteAllText((Join-Path $OutFullDir "source-commands.txt"), "# $script:sourceLabel`n" + ($script:sourceLog -join "`n") + "`n", $utf8NoBom)
}

function ConvertTo-ShQuoted([string]$Value) { return "'" + $Value.Replace("'", "'\''") + "'" }

function ConvertTo-WslPath([string]$WinPath) {
    $full = [IO.Path]::GetFullPath($WinPath)
    if ($full -notmatch '^([A-Za-z]):\\(.*)$') { throw "WSL 경로로 바꿀 수 없습니다: $full" }
    $p = "/mnt/" + $Matches[1].ToLowerInvariant() + "/" + ($Matches[2] -replace '\\', '/')
    if ($p -match "[\s'`"]") { throw "WSL 경로에 공백·따옴표가 있으면 안 됩니다: $p" }
    return $p
}

# 원격 명령은 스크립트 파일로 만들어 `ssh <host> bash -s < 파일`로 보낸다(PowerShell→wsl→ssh→원격 셸 인용 문제를 피한다).
function New-RemoteScript([string[]]$DockerArgs) {
    $script:remoteSeq++
    $name = "{0:D2}.sh" -f $script:remoteSeq
    $line = "docker " + (($DockerArgs | ForEach-Object { ConvertTo-ShQuoted $_ }) -join ' ')
    $file = Join-Path $remoteDir $name
    [IO.File]::WriteAllText($file, "set -eu`n$line`n", $utf8NoBom)
    Add-SourceLog ("[$($script:remoteSeq)] ssh $SshHost bash -s < source-remote/${name}: $line")
    return $file
}

function Invoke-SourceCapture([string[]]$DockerArgs) {
    if (-not $SshHost) {
        Add-SourceLog ("local: docker $($DockerArgs -join ' ')")
        return Invoke-NativeCapture "docker" $DockerArgs
    }
    $file = New-RemoteScript $DockerArgs
    $cmd = "ssh -o BatchMode=yes -o ConnectTimeout=15 $SshHost bash -s < $(ConvertTo-WslPath $file)"
    return Invoke-NativeCapture "wsl" @("-d", $WslDistro, "--exec", "bash", "-c", $cmd)
}

function Invoke-SourceToFile([string[]]$DockerArgs, [string]$Destination) {
    if (-not $SshHost) {
        Add-SourceLog ("local: docker $($DockerArgs -join ' ') > $(Split-Path -Leaf $Destination)")
        return Invoke-NativeToFile "docker" $DockerArgs $Destination
    }
    # 바이너리는 PowerShell을 거치지 않고 WSL bash가 바로 Windows 파일(/mnt/...)에 쓴다.
    $file = New-RemoteScript $DockerArgs
    $cmd = "set -o pipefail; ssh -o BatchMode=yes -o ConnectTimeout=15 $SshHost bash -s < $(ConvertTo-WslPath $file) > $(ConvertTo-WslPath $Destination)"
    return Invoke-NativeCapture "wsl" @("-d", $WslDistro, "--exec", "bash", "-c", $cmd)
}

function Invoke-SourceSql([string]$Sql) {
    return Invoke-SourceCapture @("exec", $SourceContainer, "psql", "-U", "postgres", "-d", $Database, "-v", "ON_ERROR_STOP=1", "-AtF", "|", "-c", $Sql)
}

$publicPatterns = @($PublicCaptures -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
function Test-PublicCapture([string]$CaptureId) {
    foreach ($p in $publicPatterns) {
        if ($p.EndsWith('*')) { if ($CaptureId.StartsWith($p.Substring(0, $p.Length - 1), [StringComparison]::Ordinal)) { return $true } }
        elseif ($CaptureId -ceq $p) { return $true }
    }
    return $false
}

function Get-CaptureCounts {
    $sql = "SELECT capture_id, count(*) FROM dashboard.latest_incident_queue GROUP BY capture_id ORDER BY capture_id"
    $out = Invoke-SourceSql $sql
    $counts = [ordered]@{}
    foreach ($line in ($out -split "`r?`n")) {
        if ($line -match '^([^|]+)\|(\d+)$') { $counts[$Matches[1]] = [int]$Matches[2] }
    }
    if ($counts.Count -eq 0) { throw "dashboard.latest_incident_queue 캡처별 건수를 읽지 못했습니다:`n$out" }
    return $counts
}

function Get-MajorMinor([string]$VersionText) {
    if ($VersionText -notmatch '(\d+)\.(\d+)') { throw "버전을 읽지 못했습니다: $VersionText" }
    return [version]"$($Matches[1]).$($Matches[2])"
}

Write-Host "원본: $sourceLabel  공개 캡처: $($publicPatterns -join ',')"

$state = (Invoke-SourceCapture @("inspect", "--format", "{{.State.Running}}", $SourceContainer)).Trim()
if ($state -ne "true") { throw "원본 컨테이너 $SourceContainer 가 실행 중이 아닙니다 (State.Running=$state)" }

$serverVersion = (Invoke-SourceSql "SELECT current_setting('server_version')").Trim()
$pgDumpVersion = (Invoke-SourceCapture @("exec", $SourceContainer, "pg_dump", "--version")).Trim()
# 복원 이미지 서버보다 높은 pg_dump로 뜬 덤프는 복원되지 않을 수 있다(T22: 높으면 멈춘다).
$restoreVersion = (Invoke-NativeCapture "docker" @("run", "--rm", "--network", "none", "--entrypoint", "postgres", $RestoreImage, "--version")).Trim()
if ((Get-MajorMinor $pgDumpVersion) -gt (Get-MajorMinor $restoreVersion)) {
    throw "원본 pg_dump($pgDumpVersion)가 복원 이미지 $RestoreImage($restoreVersion)보다 높습니다. 멈춥니다."
}

Write-Host "=== [1/5] 캡처별 조사 큐 건수(덤프 전) ==="
$countsBefore = Get-CaptureCounts
$countsBefore.GetEnumerator() | ForEach-Object { Write-Host "  $($_.Key) = $($_.Value)" }

Write-Host "=== [2/5] pg_dump -Fc $Database ==="
$dumpPath = Join-Path $OutFullDir "zeekad.dump"
$tmpDump = "$dumpPath.partial"
Remove-Item -Force -ErrorAction SilentlyContinue $tmpDump
$exportedAt = [DateTimeOffset]::Now
[void](Invoke-SourceToFile @("exec", $SourceContainer, "pg_dump", "-U", "postgres", "-Fc", $Database) $tmpDump)
Move-Item -Force $tmpDump $dumpPath

Write-Host "=== [3/5] 캡처별 조사 큐 건수(덤프 후) — 공개 캡처는 덤프 전과 같아야 같은 시점 건수로 인정 ==="
$countsAfter = Get-CaptureCounts
$allCaptures = @(@($countsBefore.Keys) + @($countsAfter.Keys) | Sort-Object -Unique)
$publicChanged = @()
$otherChanged = @()
foreach ($c in $allCaptures) {
    $b = if ($countsBefore.Contains($c)) { $countsBefore[$c] } else { $null }
    $a = if ($countsAfter.Contains($c)) { $countsAfter[$c] } else { $null }
    if ($b -ne $a) {
        $entry = "$c=$b->$a"
        if (Test-PublicCapture $c) { $publicChanged += $entry } else { $otherChanged += $entry }
    }
}
if ($publicChanged.Count -gt 0) {
    throw "덤프 전후 공개 캡처 건수가 다릅니다(원본이 바뀌는 중). 멈춥니다: $($publicChanged -join ', ')"
}
if ($otherChanged.Count -gt 0) { Write-Host "  (정보) 비공개 캡처 건수 변화: $($otherChanged -join ', ')" }
$publicCaptureIds = @($countsAfter.Keys | Where-Object { Test-PublicCapture $_ })
$hiddenCaptureIds = @($countsAfter.Keys | Where-Object { -not (Test-PublicCapture $_) })

# 캡처별 최신 작업(계약: latest_incident_queue는 캡처마다 가장 큰 성공 job_id의 사건만). 한 캡처에 작업이 둘 이상이면 멈춘다.
$detailSql = "SELECT q.capture_id, count(DISTINCT q.job_id), string_agg(DISTINCT q.job_id::text, ','), string_agg(DISTINCT q.bundle_id, ','), count(*), " +
    "(min(q.event_start) AT TIME ZONE 'UTC')::timestamp(0)::text, (max(q.event_start) AT TIME ZONE 'UTC')::timestamp(0)::text, (max(q.event_end) AT TIME ZONE 'UTC')::timestamp(0)::text, " +
    "(SELECT count(*) FROM dashboard.feedback_summary f WHERE f.capture_id = q.capture_id AND f.zeekad_picked_by = 'all'), " +
    "(SELECT string_agg(j.job_id::text || ':' || j.status, ',' ORDER BY j.job_id) FROM dashboard.scoring_jobs j WHERE j.capture_id = q.capture_id) " +
    "FROM dashboard.latest_incident_queue q GROUP BY q.capture_id ORDER BY q.capture_id"
$detailOut = Invoke-SourceSql $detailSql
$captureDetails = [ordered]@{}
foreach ($line in ($detailOut -split "`r?`n")) {
    if (-not $line) { continue }
    $f = $line -split '\|'
    if ($f.Count -lt 10) { throw "캡처 상세 행을 읽지 못했습니다: $line" }
    if ([int]$f[1] -ne 1) { throw "latest_incident_queue에서 캡처 $($f[0])의 작업이 $($f[1])개입니다(계약상 1개). 멈춥니다." }
    $captureDetails[$f[0]] = [ordered]@{
        public             = (Test-PublicCapture $f[0])
        latestJobId        = [long]$f[2]
        bundleId           = $f[3]
        incidents          = [int]$f[4]
        firstEventStartUtc = $f[5] + "Z"
        lastEventStartUtc  = $f[6] + "Z"
        lastEventEndUtc    = $f[7] + "Z"
        feedbackAllRows    = [int]$f[8]
        scoringJobs        = $f[9]
    }
}

Write-Host "=== [4/5] 전역 객체(역할) 비교용 덤프와 매니페스트 ==="
$globalsPath = Join-Path $OutFullDir "source-globals.sql"
[void](Invoke-SourceToFile @("exec", $SourceContainer, "pg_dumpall", "-U", "postgres", "--globals-only", "--no-role-passwords") $globalsPath)

$sha = (Get-FileHash -Algorithm SHA256 $dumpPath).Hash.ToLowerInvariant()
$bytes = (Get-Item $dumpPath).Length
[IO.File]::WriteAllText((Join-Path $OutFullDir "zeekad.dump.sha256"), "$sha  zeekad.dump`n", $utf8NoBom)

$manifest = [ordered]@{
    database              = $Database
    sourceHost            = $(if ($SshHost) { $SshHost } else { "local" })
    sourceTransport       = $(if ($SshHost) { "wsl -d $WslDistro ssh $SshHost bash -s (docker exec, read-only)" } else { "docker exec (this PC)" })
    sourceContainer       = $SourceContainer
    serverVersion         = $serverVersion
    pgDumpVersion         = $pgDumpVersion
    restoreImage          = $RestoreImage
    restoreImageVersion   = $restoreVersion
    format                = "pg_dump -Fc (owners and privileges included)"
    exportedAt            = $exportedAt.ToString("yyyy-MM-ddTHH:mm:sszzz")
    dumpFile              = "zeekad.dump"
    dumpBytes             = $bytes
    dumpSha256            = $sha
    publicCapturePatterns = $publicPatterns
    publicCaptures        = $publicCaptureIds
    hiddenCaptures        = $hiddenCaptureIds
    countSource           = "dashboard.latest_incident_queue GROUP BY capture_id (counted before and after pg_dump; public captures equal)"
    nonPublicCountChanges = $otherChanged
    captureIncidentCounts = $countsAfter
    captureLatestJobs     = $captureDetails
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
