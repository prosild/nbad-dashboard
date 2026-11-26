param(
    # 결과 파일(PASS·FAIL 줄)
    [string]$OutFile = "build/waf-audit-log-check/result.txt",
    # 시험할 WAF 이미지 태그. -NoBuild가 없으면 -BuildContext로 이 태그를 만든다.
    [string]$Image = "zeekad-t59-waf:after",
    # WAF 이미지의 빌드 문맥(Dockerfile과 templates/). 상대 경로는 저장소 루트 기준이다.
    [string]$BuildContext = "docker/nginx-waf",
    # 이미 만든 이미지(-Image)를 그대로 쓴다(고치기 전 이미지를 볼 때).
    [switch]$NoBuild,
    # 렌더된 설정에 있어야 하는 SecAuditLogParts 값
    [string]$ExpectedParts = "AHZ",
    # 대역 서버와 요청 보내는 쪽으로 쓰는 이미지. 로컬에 없으면 받지 않고 멈춘다.
    [string]$BackendImage = "node:22-bookworm-slim"
)

# WAF(ModSecurity) 감사 로그에 세션 쿠키·CSRF 토큰·요청 본문·응답 Set-Cookie·응답 본문이 남는지 표식으로 잰다(T59).
# - 전용 네트워크 zeekad-t59-net(internal)에 대역 서버 zeekad-t59-backend와 WAF zeekad-t59-waf를 띄운다. 호스트 포트를 열지 않고
#   볼륨을 만들지 않는다. 끝나면 이 이름들만 지운다. 다른 컨테이너·compose 프로젝트·네트워크·볼륨은 건드리지 않는다.
# - WAF의 환경 값은 공개 스택(compose.portfolio.yml)의 WAF와 같게 준다. 포트폴리오용 http 문맥 설정(속도 제한, DSM 신뢰 범위)은
#   붙이지 않는다(로그인 꼴 요청이 429로 바뀐다). 그래서 429 경로는 보지 않는다. 감사 로그의 부분 설정은 응답 코드와 무관하게 전역이다.
# - 표식은 실행마다 무작위로 만든 글자열이고 실제 비밀값이 아니다. 결과 파일에는 표식의 이름과 개수만 적는다.
#   실패할 때도 로그 원문을 적지 않는다(개수와 줄 종류만).
# - 표식의 개수는 줄 종류와 상관없이 컨테이너의 전체 출력(stdout + stderr)에서 센다(큰 감사 줄이 나뉘어 기록되어도 놓치지 않게).
# - 결과: -OutFile(줄마다 PASS 또는 FAIL, 끝에 RESULT 줄). FAIL이 있으면 종료 코드 1.

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([IO.Path]::IsPathRooted($OutFile)) { $OutFullPath = $OutFile } else { $OutFullPath = Join-Path $RepoRoot $OutFile }
[void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFullPath))
if ([IO.Path]::IsPathRooted($BuildContext)) { $ContextDir = $BuildContext } else { $ContextDir = Join-Path $RepoRoot $BuildContext }
$Dockerfile = Join-Path $ContextDir "Dockerfile"
if (-not (Test-Path $Dockerfile)) { throw "Dockerfile이 없습니다: $Dockerfile" }

$NetworkName = "zeekad-t59-net"
$BackendName = "zeekad-t59-backend"
$WafName = "zeekad-t59-waf"
$HostHeader = "waf.t59.test"

# docker를 띄우고 stdout과 stderr를 따로 받는다(PowerShell 5.1의 2>&1은 두 흐름을 섞고 인자의 따옴표를 바꾼다).
function ConvertTo-NativeArg([string]$Value) {
    if ($Value -eq '') { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}
function Invoke-Docker([string[]]$DockerArgs, [string]$StdIn = $null, [switch]$IgnoreExitCode) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = "docker"
    $psi.Arguments = (@($DockerArgs | ForEach-Object { ConvertTo-NativeArg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.StandardOutputEncoding = $utf8NoBom
    $psi.StandardErrorEncoding = $utf8NoBom
    $p = [System.Diagnostics.Process]::new()
    $p.StartInfo = $psi
    [void]$p.Start()
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if ($null -ne $StdIn) {
        $bytes = $utf8NoBom.GetBytes(($StdIn -replace "`r`n", "`n"))
        $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $p.StandardInput.BaseStream.Flush()
    }
    $p.StandardInput.Close()
    $p.WaitForExit()
    $result = [pscustomobject]@{ Code = $p.ExitCode; Out = $outTask.Result; Err = $errTask.Result }
    $p.Dispose()
    # 오류 글에는 docker 자신의 stderr 끝부분만 넣는다. 인자에는 표식이 실릴 수 있어 넣지 않는다.
    if (-not $IgnoreExitCode -and $result.Code -ne 0) {
        $tail = (@($result.Err -split "`r?`n" | Where-Object { $_ }) | Select-Object -Last 3) -join ' / '
        throw "docker $($DockerArgs[0]) $($DockerArgs[1]) 실패 (exit=$($result.Code)) $tail"
    }
    return $result
}
function ConvertTo-Base64([string]$Text) { return [Convert]::ToBase64String($utf8NoBom.GetBytes(($Text -replace "`r`n", "`n"))) }
function Get-Lines([string]$Text) { return @($Text -split "`r?`n" | Where-Object { $_ -ne '' }) }
function Get-Count([string]$Text, [string]$Needle) {
    if (-not $Text -or -not $Needle) { return 0 }
    return [regex]::Matches($Text, [regex]::Escape($Needle)).Count
}
function New-Marker([string]$Label) {
    $bytes = New-Object byte[] 12
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return $Label + (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

$script:lines = [System.Collections.Generic.List[string]]::new()
$script:fails = 0
$script:checks = 0
function Add-Line([string]$Text) { $script:lines.Add($Text); Write-Host $Text }
function Assert-Check([string]$Name, [bool]$Ok, [string]$Detail) {
    $script:checks++
    $shown = ($Detail -replace "\s*`r?`n\s*", ' / ')
    if ($Ok) { Add-Line "PASS $Name | $shown" } else { $script:fails++; Add-Line "FAIL $Name | $shown" }
}

# 이미지의 설정(.Config)에서 선언된 볼륨 경로와 환경 값을 읽는다(BuildKit이 만든 이미지는 Volumes 키가 아예 없다).
function Get-ImageConfig([string]$Ref) {
    $r = Invoke-Docker @("image", "inspect", "--format", "{{.Id}}|{{json .Config}}", $Ref) -IgnoreExitCode
    if ($r.Code -ne 0) { return $null }
    $text = $r.Out.Trim()
    $sep = $text.IndexOf('|')
    $config = $text.Substring($sep + 1) | ConvertFrom-Json
    $volumes = @()
    if ($config.PSObject.Properties.Name -contains 'Volumes' -and $config.Volumes) { $volumes = @($config.Volumes.PSObject.Properties.Name) }
    $envMap = @{}
    foreach ($e in @($config.Env)) { $i = "$e".IndexOf('='); if ($i -gt 0) { $envMap["$e".Substring(0, $i)] = "$e".Substring($i + 1) } }
    return [pscustomobject]@{ Id = $text.Substring(0, $sep); Volumes = $volumes; Env = $envMap }
}

# --- 사전 조건: 기반 이미지와 대역 서버 이미지가 로컬에 있어야 한다(받지 않는다) ---
$fromLine = @(Get-Content -LiteralPath $Dockerfile -Encoding UTF8 | Where-Object { $_ -match '^\s*FROM\s+\S+' }) | Select-Object -First 1
if (-not $fromLine) { throw "Dockerfile에 FROM 줄이 없습니다: $Dockerfile" }
$BaseRef = ($fromLine -replace '^\s*FROM\s+(\S+).*$', '$1')
$baseConfig = Get-ImageConfig $BaseRef
if (-not $baseConfig) { throw "기반 이미지 $BaseRef 가 로컬에 없습니다. 받지 않고 멈춥니다." }
$backendConfig = Get-ImageConfig $BackendImage
if (-not $backendConfig) { throw "이미지 $BackendImage 가 로컬에 없습니다. 받지 않고 멈춥니다." }

if (-not $NoBuild) {
    $b = Invoke-Docker @("build", "--pull=false", "-q", "-t", $Image, $ContextDir) -IgnoreExitCode
    if ($b.Code -ne 0) { throw "WAF 이미지 빌드 실패 (exit=$($b.Code)) $((@(Get-Lines $b.Err) | Select-Object -Last 3) -join ' / ')" }
}
$wafConfig = Get-ImageConfig $Image
if (-not $wafConfig) { throw "이미지 $Image 가 없습니다(-NoBuild면 먼저 만들어 둔다)." }

# --- 대역 서버: 경로 /t59/<json|html>/<코드>에 그 코드로 답한다. 모든 응답에 Set-Cookie(표식 5)와 본문의 표식 6을 싣는다 ---
$serverJs = @'
const http = require('http');
const m5 = process.env.T59_M5, m6 = process.env.T59_M6;
http.createServer((req, res) => {
  req.on('data', () => {});
  req.on('end', () => {
    const u = new URL(req.url, 'http://x');
    const m = /^\/t59\/(json|html)\/(\d{3})$/.exec(u.pathname);
    if (!m) { res.writeHead(404, { 'Content-Type': 'application/json; charset=UTF-8' }); res.end('{"error":"no route"}'); return; }
    const html = m[1] === 'html';
    const body = html ? '<html><body><p>' + m6 + '</p></body></html>' : JSON.stringify({ status: +m[2], detail: m6 });
    res.writeHead(+m[2], { 'Content-Type': (html ? 'text/html' : 'application/json') + '; charset=UTF-8', 'Set-Cookie': 'ZEEKAD_SESSION=' + m5 + '; Path=/; HttpOnly; SameSite=Lax' });
    res.end(body);
  });
}).listen(8080, '0.0.0.0');
'@
# --- 요청 보내는 쪽(대역 서버 컨테이너 안에서 실행): 마지막 인자의 base64 JSON을 읽어 차례로 보내고 "<id> <응답 코드> <Set-Cookie 유무> <응답 종류>"를 적는다 ---
$clientJs = @'
const http = require('http');
const spec = JSON.parse(Buffer.from(process.argv[process.argv.length - 1], 'base64').toString());
(async () => {
  for (const c of spec.cases) {
    const line = await new Promise((resolve) => {
      const headers = Object.assign({ Host: spec.hostHeader, 'User-Agent': 't59-check/1.0', Accept: 'application/json' }, c.headers || {});
      if (c.body != null) headers['Content-Length'] = Buffer.byteLength(c.body);
      const req = http.request({ host: spec.host, port: spec.port, method: c.method, path: c.path, headers }, (res) => {
        res.on('data', () => {});
        res.on('end', () => resolve(c.id + ' ' + res.statusCode + ' ' + (res.headers['set-cookie'] ? 1 : 0) + ' ' + String(res.headers['content-type'] || '-').split(';')[0]));
      });
      req.on('error', (e) => resolve(c.id + ' ERR 0 ' + e.code));
      if (c.body != null) req.write(c.body);
      req.end();
    });
    console.log(line);
  }
})();
'@

# 렌더된 ModSecurity 설정을 읽는다: setup.conf의 Include 순서대로 파일을 펼쳐 지시어의 자리(파일:줄)와 값을 적는다. 뒤에 읽힌 줄이 이긴다.
$renderedSh = @'
cd /etc/modsecurity.d || exit 3
echo "@@INCLUDES"
grep -E '^[[:space:]]*Include[[:space:]]' setup.conf
echo "@@DIRECTIVES"
for inc in $(grep -E '^[[:space:]]*Include[[:space:]]' setup.conf | awk '{print $2}'); do
  for f in $inc; do
    [ -f "$f" ] || continue
    grep -n -E '^[[:space:]]*(SecAuditLogParts|SecAuditEngine|SecAuditLog|SecAuditLogFormat|SecAuditLogRelevantStatus|SecRuleEngine|SecResponseBodyMimeType)[[:space:]]' "$f" | sed "s|^|$f:|"
  done
done
echo "@@CTL"
n=0
for inc in $(grep -E '^[[:space:]]*Include[[:space:]]' setup.conf | awk '{print $2}'); do
  for f in $inc; do
    [ -f "$f" ] || continue
    c=$(grep -v -E '^[[:space:]]*#' "$f" | grep -c -i 'auditLogParts' || true)
    case "$f" in */modsecurity.conf|*/modsecurity-override.conf) c=0 ;; esac
    n=$((n + c))
  done
done
echo "$n"
'@
# 템플릿 폴더의 파일 목록(이름, 크기, sha256)과 감사 로그 지시어가 든 줄. 컨테이너를 띄우지 않고 이미지에서 바로 읽는다.
$templatesSh = @'
cd /etc/nginx/templates/modsecurity.d || exit 3
for f in *; do
  [ -f "$f" ] || continue
  echo "FILE $f $(wc -c < "$f") $(sha256sum "$f" | cut -d' ' -f1)"
done
grep -n -E '^[[:space:]]*SecAudit' *.template | sed 's/^/LINE /'
'@
# 환경 값이 지시어로 옮겨지는지: 진입 스크립트가 템플릿을 렌더하게 한 뒤(nginx -t) 렌더된 줄을 읽는다.
$envProbeSh = @'
/docker-entrypoint.sh nginx -t >/dev/null 2>&1
echo "nginx_t_exit=$?"
grep -E '^[[:space:]]*SecAuditLogParts[[:space:]]' /etc/modsecurity.d/modsecurity.conf /etc/modsecurity.d/modsecurity-override.conf
'@

function Remove-Leftovers {
    foreach ($name in @($WafName, $BackendName)) {
        $left = Invoke-Docker @("ps", "-aq", "--filter", "name=^/$name`$") -IgnoreExitCode
        if ($left.Out.Trim()) { [void](Invoke-Docker @("rm", "-f", $name) -IgnoreExitCode) }
    }
    $net = Invoke-Docker @("network", "ls", "-q", "--filter", "name=^$NetworkName`$") -IgnoreExitCode
    if ($net.Out.Trim()) { [void](Invoke-Docker @("network", "rm", $NetworkName) -IgnoreExitCode) }
}
function Get-Volumes { return @(Get-Lines (Invoke-Docker @("volume", "ls", "-q")).Out | Sort-Object) }

Remove-Leftovers
$volumesBefore = Get-Volumes
# 이미지가 선언한 볼륨 경로마다 --tmpfs를 준다(익명 볼륨이 생기지 않게).
function Get-TmpfsArgs($Config) {
    $a = @()
    foreach ($v in $Config.Volumes) { $a += @("--tmpfs", $v) }
    return $a
}

try {
    Add-Line "# T59 WAF 감사 로그에 남는 값: 재현 환경에서 표식으로 잰 결과"
    Add-Line "# 실행 시각(UTC) $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    Add-Line "# 대상: WAF 이미지 $Image ($($wafConfig.Id)) + 대역 서버 $BackendImage ($($backendConfig.Id)). 모의가 아니라 실제 nginx + ModSecurity + CRS다."
    Add-Line "# 기반 이미지 $BaseRef ($($baseConfig.Id))"
    Add-Line "# 선언된 볼륨(.Config.Volumes): WAF=[$($wafConfig.Volumes -join ', ')] 기반=[$($baseConfig.Volumes -join ', ')] 대역 서버=[$($backendConfig.Volumes -join ', ')] (있으면 그 경로에 --tmpfs를 준다)"
    Add-Line "# 이미지 환경 값 MODSEC_AUDIT_LOG_PARTS: WAF=$($wafConfig.Env['MODSEC_AUDIT_LOG_PARTS']) 기반=$($baseConfig.Env['MODSEC_AUDIT_LOG_PARTS'])"
    Add-Line "# 보지 않은 것: 429(속도 제한) 경로. 감사 로그의 부분 설정은 응답 코드와 무관하게 전역으로 걸린다."

    # --- 템플릿 폴더: 기반 이미지와 만든 이미지 ---
    $tplBase = Invoke-Docker @("run", "--rm", "-i", "--pull", "never", "--network", "none", "--entrypoint", "sh", $BaseRef, "-s") -StdIn $templatesSh
    $tplWaf = Invoke-Docker @("run", "--rm", "-i", "--pull", "never", "--network", "none", "--entrypoint", "sh", $Image, "-s") -StdIn $templatesSh
    foreach ($pair in @(@("기반", $tplBase), @("WAF", $tplWaf))) {
        foreach ($l in (Get-Lines $pair[1].Out)) { Add-Line "INFO [템플릿 $($pair[0])] /etc/nginx/templates/modsecurity.d/ $l" }
    }
    $tplWafFiles = @(Get-Lines $tplWaf.Out | Where-Object { $_ -match '^FILE ' })
    $mainTplBase = @(Get-Lines $tplBase.Out | Where-Object { $_ -match '^FILE modsecurity\.conf\.template ' })
    $mainTplWaf = @($tplWafFiles | Where-Object { $_ -match '^FILE modsecurity\.conf\.template ' })
    Assert-Check "[템플릿] 만든 이미지에 기반의 modsecurity.conf.template이 그대로 있다(환경 값을 지시어로 옮기는 파일)" `
        ($mainTplWaf.Count -eq 1 -and $mainTplBase.Count -eq 1 -and $mainTplWaf[0] -eq $mainTplBase[0]) "기반 $($mainTplBase.Count)개, WAF $($mainTplWaf.Count)개, 같은 sha256=$($mainTplWaf.Count -eq 1 -and $mainTplBase.Count -eq 1 -and $mainTplWaf[0] -eq $mainTplBase[0])"

    # --- 환경 값이 지시어로 옮겨지는지(값을 바꿔 띄우면 렌더된 값이 바뀐다) ---
    $probeValue = "AZ"
    $envProbe = Invoke-Docker @("run", "--rm", "-i", "--pull", "never", "--network", "none", "-e", "MODSEC_AUDIT_LOG_PARTS=$probeValue", "--entrypoint", "sh", $Image, "-s") -StdIn $envProbeSh -IgnoreExitCode
    $envProbeLines = @(Get-Lines $envProbe.Out | Where-Object { $_ -match 'SecAuditLogParts' })
    $envProbeLast = ""
    if ($envProbeLines.Count -gt 0) { $envProbeLast = (($envProbeLines[-1] -replace '^.*SecAuditLogParts\s+', '').Trim()) }
    Assert-Check "[환경 값 → 지시어] MODSEC_AUDIT_LOG_PARTS=$probeValue 로 띄우면 렌더된 SecAuditLogParts가 $probeValue 다" ($envProbeLast -eq $probeValue) `
        "렌더된 줄 $($envProbeLines.Count)개, 마지막 값=$envProbeLast $((Get-Lines $envProbe.Out | Where-Object { $_ -match '^nginx_t_exit=' }) -join '')"

    # --- 띄운다 ---
    $markers = [ordered]@{
        M1 = New-Marker "T59M1"; M2 = New-Marker "T59M2"; M3 = New-Marker "T59M3"
        M4 = New-Marker "T59M4"; M5 = New-Marker "T59M5"; M6 = New-Marker "T59M6"
    }
    $markerNames = [ordered]@{
        M1 = "표식 1 세션 쿠키(요청 Cookie: ZEEKAD_SESSION)"
        M2 = "표식 2 CSRF 토큰(요청 Cookie: XSRF-TOKEN, 헤더 X-XSRF-TOKEN)"
        M3 = "표식 3 요청 본문의 username"
        M4 = "표식 4 요청 본문의 password"
        M5 = "표식 5 응답 Set-Cookie: ZEEKAD_SESSION"
        M6 = "표식 6 응답 본문"
    }
    [void](Invoke-Docker @("network", "create", "--internal", $NetworkName))
    $runBackend = @("run", "-d", "--rm", "--pull", "never", "--name", $BackendName, "--network", $NetworkName) + @(Get-TmpfsArgs $backendConfig) +
        @("-e", "T59_M5=$($markers.M5)", "-e", "T59_M6=$($markers.M6)", $BackendImage, "node", "-e", "eval(Buffer.from('$(ConvertTo-Base64 $serverJs)','base64').toString())")
    [void](Invoke-Docker $runBackend)
    # 공개 스택(compose.portfolio.yml)의 WAF와 같은 값. MODSEC_AUDIT_LOG_PARTS는 주지 않는다(이미지의 값을 본다).
    $wafEnv = [ordered]@{
        BACKEND = "http://${BackendName}:8080"; PORT = "8080"; SSL_PORT = "8443"; SERVER_NAME = "localhost"
        NGINX_ALWAYS_TLS_REDIRECT = "off"; SSL_OCSP_STAPLING = "off"; SERVER_TOKENS = "off"; SERVER_HEADER = ""
        PROXY_HOST_HEADER = '$http_host'; REAL_IP_HEADER = "X-Forwarded-For"; REAL_IP_RECURSIVE = "on"; SET_REAL_IP_FROM = "127.0.0.1"
        MODSEC_RULE_ENGINE = "on"; ALLOWED_METHODS = "GET HEAD POST PUT OPTIONS"; PARANOIA = "1"; BLOCKING_PARANOIA = "1"
        ANOMALY_INBOUND = "5"; ANOMALY_OUTBOUND = "4"; MODSEC_AUDIT_ENGINE = "RelevantOnly"; MODSEC_AUDIT_LOG = "/dev/stdout"
    }
    $runWaf = @("run", "-d", "--rm", "--pull", "never", "--name", $WafName, "--network", $NetworkName) + @(Get-TmpfsArgs $wafConfig)
    foreach ($k in $wafEnv.Keys) { $runWaf += @("-e", "$k=$($wafEnv[$k])") }
    [void](Invoke-Docker ($runWaf + @($Image)))

    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        $h = Invoke-Docker @("exec", $WafName, "wget", "-q", "--spider", "http://127.0.0.1:8080/healthz") -IgnoreExitCode
        if ($h.Code -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw "WAF 컨테이너가 준비되지 않았습니다(60초)." }
    $backendIp = (Invoke-Docker @("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", $BackendName)).Out.Trim()
    $mounts = (Invoke-Docker @("inspect", "--format", "{{range .Mounts}}{{.Type}}:{{.Destination}} {{end}}", $WafName, $BackendName)).Out.Trim()
    Add-Line "# 네트워크 $NetworkName(internal, 호스트 포트 없음). 요청은 $BackendName($backendIp)에서 http://${WafName}:8080 으로 보낸다(Host: $HostHeader). 두 컨테이너의 마운트=[$(($mounts -replace '\s+', ' ').Trim())]"

    # --- 렌더된 설정: 실제로 읽히는 파일과 지시어 값 ---
    $rendered = Invoke-Docker @("exec", "-i", $WafName, "sh", "-s") -StdIn $renderedSh
    $section = ""
    $directiveLines = [System.Collections.Generic.List[string]]::new()
    $ctlCount = -1
    foreach ($l in (Get-Lines $rendered.Out)) {
        if ($l -match '^@@(\w+)$') { $section = $Matches[1]; continue }
        if ($section -eq 'INCLUDES') { Add-Line "INFO [렌더된 설정] /etc/modsecurity.d/setup.conf: $($l.Trim())" }
        elseif ($section -eq 'DIRECTIVES') { $directiveLines.Add($l); Add-Line "INFO [렌더된 설정] $l" }
        elseif ($section -eq 'CTL') { $ctlCount = [int]$l.Trim() }
    }
    $partsLines = @($directiveLines | Where-Object { $_ -match ':\s*SecAuditLogParts\s' })
    $effectiveParts = ""
    if ($partsLines.Count -gt 0) { $effectiveParts = (($partsLines[-1] -replace '^.*SecAuditLogParts\s+', '').Trim()) }
    Assert-Check "[설정] 렌더된 설정에서 마지막에 읽히는 SecAuditLogParts가 $ExpectedParts 다" ($effectiveParts -ceq $ExpectedParts) `
        "값=$effectiveParts, SecAuditLogParts 줄 $($partsLines.Count)개(뒤에 읽힌 줄이 이긴다)"
    Assert-Check "[설정] 그 값에 요청 헤더(B)·요청 본문(C, I)·응답 본문(E)·응답 헤더(F)가 없다" ([bool]$effectiveParts -and $effectiveParts -notmatch '[BCIEF]') "값=$effectiveParts"
    Assert-Check "[설정] 읽히는 규칙 파일에 감사 로그 부분을 요청마다 바꾸는 동작(ctl:auditLogParts)이 없다" ($ctlCount -eq 0) "주석이 아닌 줄 $($ctlCount)개"

    # --- 요청 ---
    $cookie = "ZEEKAD_SESSION=$($markers.M1); XSRF-TOKEN=$($markers.M2)"
    $loginBody = '{"username":"' + $markers.M3 + '","password":"' + $markers.M4 + '"}'
    $secretHeaders = [ordered]@{ Cookie = $cookie; "X-XSRF-TOKEN" = $markers.M2; "Content-Type" = "application/json" }
    $attack = "' OR 1=1--"
    $cases = @(
        [pscustomobject]@{ Id = "t59json401"; Method = "POST"; Path = "/t59/json/401"; Expect = 401; Audited = $true; Blocked = $false; Type = "application/json"; Secrets = $true }
        [pscustomobject]@{ Id = "t59json403"; Method = "POST"; Path = "/t59/json/403"; Expect = 403; Audited = $true; Blocked = $false; Type = "application/json"; Secrets = $true }
        [pscustomobject]@{ Id = "t59json409"; Method = "POST"; Path = "/t59/json/409"; Expect = 409; Audited = $true; Blocked = $false; Type = "application/json"; Secrets = $true }
        [pscustomobject]@{ Id = "t59json500"; Method = "POST"; Path = "/t59/json/500"; Expect = 500; Audited = $true; Blocked = $false; Type = "application/json"; Secrets = $true }
        [pscustomobject]@{ Id = "t59html401"; Method = "POST"; Path = "/t59/html/401"; Expect = 401; Audited = $true; Blocked = $false; Type = "text/html"; Secrets = $true }
        [pscustomobject]@{ Id = "t59json200"; Method = "POST"; Path = "/t59/json/200"; Expect = 200; Audited = $false; Blocked = $false; Type = "application/json"; Secrets = $true }
        [pscustomobject]@{ Id = "t59json404"; Method = "POST"; Path = "/t59/json/404"; Expect = 404; Audited = $false; Blocked = $false; Type = "application/json"; Secrets = $true }
        # CRS가 막는 요청: 공격 꼴 글은 쿼리에, 표식 1~4는 쿠키와 본문에 그대로 싣는다.
        [pscustomobject]@{ Id = "t59crsquery"; Method = "POST"; Path = "/t59/json/200"; Query = "&asset=" + [uri]::EscapeDataString($attack); Expect = 403; Audited = $true; Blocked = $true; Type = "text/html"; Secrets = $true }
        # 규칙 메시지의 matched data에 무엇이 찍히는지 볼 요청: 표식 없이, 공격 꼴 글을 본문의 password 칸에 둔다.
        [pscustomobject]@{ Id = "t59crsbody"; Method = "POST"; Path = "/t59/json/200"; Expect = 403; Audited = $true; Blocked = $true; Type = "text/html"; Secrets = $false
            Body = '{"username":"t59-user","password":"' + $attack + '"}' }
    )
    $specCases = @()
    foreach ($c in $cases) {
        $query = ""
        if ($c.PSObject.Properties.Name -contains 'Query') { $query = $c.Query }
        $entry = [ordered]@{ id = $c.Id; method = $c.Method; path = "$($c.Path)?probe=$($c.Id)$query" }
        if ($c.Secrets) { $entry.headers = $secretHeaders; $entry.body = $loginBody }
        else { $entry.headers = [ordered]@{ "Content-Type" = "application/json" }; $entry.body = $c.Body }
        $specCases += $entry
    }
    $spec = [ordered]@{ host = $WafName; port = 8080; hostHeader = $HostHeader; cases = $specCases } | ConvertTo-Json -Depth 6 -Compress
    $sent = Invoke-Docker @("exec", "-i", $BackendName, "node", "-", (ConvertTo-Base64 $spec)) -StdIn $clientJs -IgnoreExitCode
    $responses = @{}
    foreach ($l in (Get-Lines $sent.Out)) { $parts = $l -split ' '; if ($parts.Count -ge 4) { $responses[$parts[0]] = [pscustomobject]@{ Code = $parts[1]; SetCookie = $parts[2]; Type = $parts[3] } } }
    foreach ($c in $cases) {
        $r = $responses[$c.Id]
        $got = "응답 없음"
        if ($r) { $got = "$($r.Code), Set-Cookie=$($r.SetCookie), $($r.Type)" }
        # 대역 서버가 답한 것은 Set-Cookie가 있고, WAF가 막은 것은 없다(WAF의 403 쪽).
        $ok = [bool]$r -and $r.Code -eq "$($c.Expect)" -and $r.Type -eq $c.Type -and (($c.Blocked -and $r.SetCookie -eq '0') -or (-not $c.Blocked -and $r.SetCookie -eq '1'))
        Assert-Check "[요청] $($c.Id) $($c.Method) $($c.Path) → $($c.Expect)$(if ($c.Blocked) { '(WAF 차단)' } else { '(대역 서버 응답)' })" $ok $got
    }

    # --- 컨테이너 출력을 stdout과 stderr로 따로 받는다(감사 대상 요청의 감사 줄이 다 나올 때까지 잠깐 기다린다) ---
    $auditedIds = @($cases | Where-Object { $_.Audited } | ForEach-Object { $_.Id })
    $stdout = ""; $stderr = ""
    for ($i = 0; $i -lt 20; $i++) {
        $logs = Invoke-Docker @("logs", $WafName)
        $stdout = $logs.Out; $stderr = $logs.Err
        $auditNow = @(Get-Lines $stdout | Where-Object { $_.StartsWith('{"transaction"') })
        $missing = @($auditedIds | Where-Object { $id = $_; -not ($auditNow | Where-Object { $_.Contains("probe=$id") }) })
        if ($missing.Count -eq 0 -and $i -ge 1) { break }
        Start-Sleep -Milliseconds 500
    }
    $outLines = Get-Lines $stdout
    $errLines = Get-Lines $stderr
    $auditLines = @($outLines | Where-Object { $_.StartsWith('{"transaction"') })
    $accessLines = @($outLines | Where-Object { -not $_.StartsWith('{') -and $_ -match '" \d{3} \d+ "' })
    $otherOut = @($outLines | Where-Object { -not $_.StartsWith('{"transaction"') -and -not ($_ -match '" \d{3} \d+ "') })
    $healthAudit = @($auditLines | Where-Object { $_.Contains('"uri":"/healthz"') })
    Add-Line "INFO [출력] stdout $($outLines.Count)줄(감사 줄 $($auditLines.Count), 접근 줄 $($accessLines.Count), 그 밖 $($otherOut.Count)), stderr $($errLines.Count)줄(그중 ModSecurity 차단 줄 $(@($errLines | Where-Object { $_ -match 'ModSecurity: Access denied' }).Count))"
    Add-Line "INFO [출력] /healthz 감사 줄 $($healthAudit.Count)건(상태 확인 요청의 Host가 숫자 주소라 CRS 920350이 붙어 200인데도 감사 대상이 된다. 표식과 무관한 별도 발견)"

    function Get-AuditLine([string]$Id) { return @($auditLines | Where-Object { $_.Contains("probe=$Id") }) }
    function Get-Field([string]$Line, [string]$Pattern) { $m = [regex]::Match($Line, $Pattern); if ($m.Success) { return $m.Groups[1].Value } return "" }

    foreach ($c in $cases) {
        $found = @(Get-AuditLine $c.Id)
        $access = @($accessLines | Where-Object { $_.Contains("probe=$($c.Id)") })
        if (-not $c.Audited) {
            Assert-Check "[감사 범위] $($c.Id) 응답 코드 $($c.Expect): 감사 줄이 없다(RelevantOnly는 404가 아닌 4xx와 5xx만 적는다)" ($found.Count -eq 0) "감사 줄 $($found.Count)건, 접근 줄 $($access.Count)건"
            continue
        }
        $line = ""
        if ($found.Count -gt 0) { $line = $found[-1] }
        $ip = Get-Field $line '"client_ip":"([^"]*)"'
        $uri = Get-Field $line '"uri":"([^"]*)"'
        $code = Get-Field $line '"http_code":(\d+)'
        $method = Get-Field $line '"method":"([^"]*)"'
        $stamp = Get-Field $line '"time_stamp":"([^"]*)"'
        $ok = $found.Count -eq 1 -and $ip -eq $backendIp -and $uri.StartsWith("$($c.Path)?probe=$($c.Id)") -and $code -eq "$($c.Expect)" -and $method -eq $c.Method -and [bool]$stamp
        Assert-Check "[감사 줄] $($c.Id): 접속 주소·시각·메서드·요청 주소·응답 코드가 있다" $ok `
            "감사 줄 $($found.Count)건, client_ip=$(if ($ip -eq $backendIp) { '요청 보낸 컨테이너 주소와 같음' } else { '다름 또는 없음' }), method=$method, uri에 경로와 probe=$($uri.StartsWith("$($c.Path)?probe=$($c.Id)")), http_code=$code, time_stamp 있음=$([bool]$stamp), 접근 줄 $($access.Count)건"
        if ($c.Blocked) {
            $interrupted = $line -match '"is_interrupted":true'
            $uniqueId = Get-Field $line '"unique_id":"([^"]*)"'
            $ruleIds = @([regex]::Matches($line, '"ruleId":"(\d+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
            $dataValues = @([regex]::Matches($line, '"data":"((?:[^"\\]|\\.)*)"') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ })
            $ok = $interrupted -and [bool]$uniqueId -and ($ruleIds -contains '949110') -and $ruleIds.Count -ge 2 -and $dataValues.Count -ge 1
            Assert-Check "[차단 줄] $($c.Id): is_interrupted·unique_id·ruleId·메시지의 data가 있다" $ok `
                "is_interrupted=$interrupted, unique_id 있음=$([bool]$uniqueId), ruleIds=[$($ruleIds -join ', ')], 빈 값이 아닌 data $($dataValues.Count)개"
            if (-not $c.Secrets) {
                # 이 요청에는 표식이 없다(본문은 이 스크립트가 정한 글이다). 규칙 메시지에 요청의 어느 부분이 찍히는지 보고용으로 적는다.
                foreach ($d in $dataValues) { Add-Line "INFO [규칙 메시지] $($c.Id)의 data: $d" }
                $errBlock = @($errLines | Where-Object { $_ -match 'ModSecurity: Access denied' }).Count
                Add-Line "INFO [규칙 메시지] 본문의 password 칸에 든 공격 꼴 글은 감사 줄의 data에 그대로 찍힌다(줄이지 않는다). nginx 오류 로그의 차단 줄 $($errBlock)건"
            }
        }
    }

    # --- 접근 로그는 바꾸지 않았다: 요청마다 접근 줄이 하나 있고, 감사 줄에서 빠진 User-Agent는 여기서 찾는다 ---
    $accessOk = 0
    foreach ($c in $cases) {
        $access = @($accessLines | Where-Object { $_.Contains("probe=$($c.Id)") })
        if ($access.Count -eq 1 -and $access[0].StartsWith("$backendIp ") -and $access[0].Contains('"t59-check/1.0"') -and $access[0].Contains(" $($c.Expect) ")) { $accessOk++ }
    }
    Assert-Check "[접근 줄] 요청마다 접근 줄이 하나 있고 접속 주소·요청 줄·응답 코드·User-Agent가 있다" ($accessOk -eq $cases.Count) "맞는 요청 $accessOk/$($cases.Count)"

    # --- 감사 줄의 키(값은 적지 않는다) ---
    $probeAudit = @($auditLines | Where-Object { $_ -match 'probe=t59' })
    $keys = @($probeAudit | ForEach-Object { [regex]::Matches($_, '(?<!\\)"([A-Za-z0-9_-]+)":') | ForEach-Object { $_.Groups[1].Value } } | Sort-Object -Unique)
    Add-Line "INFO [감사 줄의 키] 이 실행의 요청 $($probeAudit.Count)줄에 나온 키: $($keys -join ' ')"
    $hasHeaders = @($probeAudit | Where-Object { $_ -match '"headers":\{' }).Count
    $hasBody = @($probeAudit | Where-Object { $_ -match '"body":"' }).Count
    Assert-Check "[감사 줄] 요청·응답의 headers와 body 키가 없다" ($hasHeaders -eq 0 -and $hasBody -eq 0) "headers가 든 줄 $hasHeaders, body가 든 줄 $hasBody (전체 $($probeAudit.Count)줄)"

    # --- 표식: 전체 출력(stdout + stderr)에서 센다 ---
    $auditText = $auditLines -join "`n"
    $accessText = $accessLines -join "`n"
    $otherText = $otherOut -join "`n"
    $leakOutsideAudit = 0
    foreach ($k in $markers.Keys) {
        $total = (Get-Count $stdout $markers[$k]) + (Get-Count $stderr $markers[$k])
        $inAudit = Get-Count $auditText $markers[$k]
        $inAccess = Get-Count $accessText $markers[$k]
        $inOther = Get-Count $otherText $markers[$k]
        $inErr = Get-Count $stderr $markers[$k]
        $leakOutsideAudit += $inAccess + $inOther + $inErr
        Assert-Check "[표식] $($markerNames[$k]): 컨테이너 전체 출력에 0번" ($total -eq 0) "전체 $($total)번(감사 줄 $inAudit, 접근 줄 $inAccess, stdout의 그 밖 $inOther, stderr $inErr)"
    }
    # 응답 본문(표식 6)은 응답 종류에 따라 다르다(ModSecurity가 본문을 읽는 종류는 SecResponseBodyMimeType이 정한다).
    foreach ($type in @("application/json", "text/html")) {
        $typeCases = @($cases | Where-Object { $_.Audited -and -not $_.Blocked -and $_.Type -eq $type })
        $typeCount = 0
        foreach ($tc in $typeCases) { $typeCount += Get-Count ((Get-AuditLine $tc.Id) -join "`n") $markers.M6 }
        Add-Line "INFO [표식 6 응답 종류별] $type 응답 $($typeCases.Count)건의 감사 줄에 $($typeCount)번"
    }
    Assert-Check "[표식] 접근 줄과 오류 줄(감사 줄 밖)에는 어떤 표식도 없다" ($leakOutsideAudit -eq 0) "감사 줄 밖 합계 $($leakOutsideAudit)번"
}
finally {
    Remove-Leftovers
}

$volumesAfter = Get-Volumes
$newVolumes = @($volumesAfter | Where-Object { $volumesBefore -notcontains $_ })
$leftContainers = (Invoke-Docker @("ps", "-aq", "--filter", "name=^/zeekad-t59-") -IgnoreExitCode).Out.Trim()
$leftNetwork = (Invoke-Docker @("network", "ls", "-q", "--filter", "name=^$NetworkName`$") -IgnoreExitCode).Out.Trim()
Assert-Check "[정리] 새 볼륨이 없고 이 시험의 컨테이너·네트워크가 남지 않았다" ($newVolumes.Count -eq 0 -and -not $leftContainers -and -not $leftNetwork) `
    "새 볼륨 $($newVolumes.Count)개, 남은 컨테이너 $(@(Get-Lines $leftContainers).Count)개, 남은 네트워크 $(@(Get-Lines $leftNetwork).Count)개"

Add-Line "RESULT: PASS=$($script:checks - $script:fails) FAIL=$($script:fails)"
[IO.File]::WriteAllText($OutFullPath, (($script:lines -join "`n") + "`n"), $utf8NoBom)
if ($script:fails -gt 0) { exit 1 }
exit 0
