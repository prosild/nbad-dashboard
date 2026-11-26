param(
    # 결과 파일(pg-check.txt, reset-once.txt, once-a-day.txt)을 쓸 폴더
    [string]$OutDir = "build/audit-retention-check",
    # 공개 스택과 같은 PostgreSQL 이미지. 로컬에 없으면 받지 않고 멈춘다.
    [string]$Image = "pgvector/pgvector:0.8.1-pg17",
    [string]$ContainerName = "zeekad-t58-pg"
)

# 감사 로그 보관 기한(T58)과 대응 조치 기록(T56)의 SQL을 PostgreSQL에서 직접 시험한다(Java 시험은 H2라 이 로직을 못 본다).
# - 일회용 PostgreSQL 컨테이너 하나(-ContainerName)를 네트워크 없이, 데이터 경로는 tmpfs로 띄운다(볼륨을 만들지 않는다).
#   docker exec로만 쓰고 끝나면 그 이름의 컨테이너만 지운다. 다른 컨테이너·compose 프로젝트·네트워크·볼륨은 건드리지 않는다.
# - 실제와 같게 적용한다: 슈퍼유저가 아닌 역할 dashboard_app이 소유한 DB에 저장소의 V1~V5 파일을 그대로,
#   파일마다 한 트랜잭션(psql -1 -v ON_ERROR_STOP=1)으로 그 역할로 적용한다.
# - 이어서 저장소의 docker/portfolio/sandbox/sandbox-setup.sh와 sandbox-reset.sh --once를 그대로 같은 컨테이너에서 돌린다
#   (zeek_AD 표 다섯은 열만 맞춘 빈 표로 둔다. 초기화 함수 셋·기준선·전용 역할·권한은 설정 도구가 실제로 만든다).
#   설정 도구가 V4 전에는 멈추는지, 삭제 함수의 EXECUTE만 주는지, 한 줄 로그의 감사 칸이 상태마다 어떻게 나오는지 본다.
#   T56: V5 전에도 멈추는지, 대응 조치 표의 트리거(UPDATE·TRUNCATE 거부, 표식 없는 DELETE 거부), 기준선 표식이 zeek_AD 기준선과 따로
#   정해지는지(NAS 갱신 경우), 체험 계정의 행이 있으면 표식을 만들지 않는지, 초기화가 기준선 뒤의 행만 지우는지,
#   함수나 표식이 없을 때의 responses 칸(NOT_CONFIGURED / ERROR)을 본다.
#   scripts/sandbox-reset-daily-test.sh(하루 한 번 판정)는 컨테이너의 bash로 돌린다.
# - 컨테이너 안 접속은 유닉스 소켓(이미지 기본 trust)이다. 슈퍼유저 비밀번호는 무작위로 만들어 환경 변수로만 넘기고 출력·기록하지 않는다.
# - 결과: <OutDir>/pg-check.txt, reset-once.txt, response-actions.txt, once-a-day.txt(줄마다 PASS 또는 FAIL). FAIL이 있으면 종료 코드 1.

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([IO.Path]::IsPathRooted($OutDir)) { $OutFullDir = $OutDir } else { $OutFullDir = Join-Path $RepoRoot $OutDir }
[void](New-Item -ItemType Directory -Force -Path $OutFullDir)

$MigrationDir = Join-Path $RepoRoot "src/main/resources/db/migration/postgresql"
$Migrations = @("V1__init_dashboard_auth_audit.sql", "V2__incident_assignments.sql", "V3__incident_refs.sql", "V4__audit_retention.sql",
    "V5__incident_response_actions.sql")
$ResetScript = Join-Path $RepoRoot "docker/portfolio/sandbox/sandbox-reset.sh"
$SetupScript = Join-Path $RepoRoot "docker/portfolio/sandbox/sandbox-setup.sh"
$DailyTest = Join-Path $RepoRoot "scripts/sandbox-reset-daily-test.sh"
foreach ($f in @($Migrations | ForEach-Object { Join-Path $MigrationDir $_ }) + @($ResetScript, $SetupScript, $DailyTest)) {
    if (-not (Test-Path $f)) { throw "파일이 없습니다: $f" }
}

function Invoke-Docker([string[]]$DockerArgs, [switch]$IgnoreExitCode) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = (& docker @DockerArgs 2>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" } }) -join "`n"
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if (-not $IgnoreExitCode -and $code -ne 0) { throw "docker $($DockerArgs -join ' ') 실패 (exit=$code)`n$out" }
    return [pscustomobject]@{ Code = $code; Out = "$out".Trim() }
}

# SQL을 표준 입력으로 넘긴다(따옴표를 명령줄에 싣지 않는다). 오류 글도 출력에 함께 담는다(컨테이너 안에서 2>&1).
# -StopOnError가 없으면 오류가 나도 다음 문장을 이어 돌린다(트랜잭션 안에서 거부되는지 볼 때 쓴다).
function Invoke-Sql([string]$User, [string]$Db, [string]$Sql, [switch]$StopOnError) {
    $stop = 0
    if ($StopOnError) { $stop = 1 }
    $cmd = "psql -X -q -At -v ON_ERROR_STOP=$stop -U $User -d $Db -f - 2>&1"
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = ($Sql | & docker exec -i --user postgres $ContainerName sh -c $cmd | ForEach-Object { "$_" }) -join "`n"
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    return [pscustomobject]@{ Code = $code; Out = "$out".Trim() }
}
function Get-Scalar([string]$Db, [string]$Sql) {
    $r = Invoke-Sql "postgres" $Db $Sql -StopOnError
    if ($r.Code -ne 0) { throw "조회 실패: $Sql`n$($r.Out)" }
    return $r.Out
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
function Save-Lines([string]$FileName) {
    $summary = "RESULT: PASS=$($script:checks - $script:fails) FAIL=$($script:fails)"
    Add-Line $summary
    [IO.File]::WriteAllText((Join-Path $OutFullDir $FileName), (($script:lines -join "`n") + "`n"), $utf8NoBom)
    $failed = $script:fails
    $script:lines = [System.Collections.Generic.List[string]]::new()
    $script:fails = 0
    $script:checks = 0
    return $failed
}

# --- 사전 조건: 이미지가 로컬에 있어야 한다(받지 않는다) ---
$img = Invoke-Docker @("image", "inspect", "--format", "{{.Id}}", $Image) -IgnoreExitCode
if ($img.Code -ne 0) { throw "이미지 $Image 가 로컬에 없습니다. 받지 않고 멈춥니다." }
$imageId = $img.Out

# 같은 이름의 남은 컨테이너(앞선 실행이 중단된 경우)만 지운다.
$left = Invoke-Docker @("ps", "-aq", "--filter", "name=^/$ContainerName`$") -IgnoreExitCode
if ($left.Out) { [void](Invoke-Docker @("rm", "-f", $ContainerName) -IgnoreExitCode) }

$volumesBefore = @((Invoke-Docker @("volume", "ls", "-q")).Out -split "`r?`n" | Where-Object { $_ })
$totalFailed = 0
$started = $false
try {
    $env:POSTGRES_PASSWORD = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
    $env:SANDBOX_RESET_DB_PASSWORD_T58 = [Guid]::NewGuid().ToString('N')
    [void](Invoke-Docker @("run", "-d", "--rm", "--pull", "never", "--name", $ContainerName, "--network", "none",
            "--tmpfs", "/var/lib/postgresql/data", "-e", "POSTGRES_PASSWORD", $Image))
    $started = $true
    $env:POSTGRES_PASSWORD = $null

    # 초기화가 끝나면 TCP(127.0.0.1)로도 받는다(초기화 중의 임시 서버는 소켓만 연다).
    $ready = $false
    for ($i = 0; $i -lt 90; $i++) {
        $r = Invoke-Docker @("exec", "--user", "postgres", $ContainerName, "pg_isready", "-h", "127.0.0.1", "-U", "postgres") -IgnoreExitCode
        if ($r.Code -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw "PostgreSQL 컨테이너가 준비되지 않았습니다.`n$((Invoke-Docker @('logs', '--tail', '30', $ContainerName) -IgnoreExitCode).Out)" }

    $pgVersion = Get-Scalar "postgres" "SHOW server_version;"
    Add-Line "# T58 감사 로그 보관 기한: PostgreSQL에서 직접 본 결과"
    Add-Line "# 실행 시각(UTC) $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')), 이미지 $Image ($imageId), PostgreSQL $pgVersion"
    Add-Line "# 대상: 일회용 컨테이너 $ContainerName(네트워크 없음, 데이터 경로 tmpfs). 모의가 아니라 실제 PostgreSQL이다."

    # --- 역할과 DB(공개 스택의 01-roles-databases.sh와 같은 꼴: 앱 DB의 소유자는 슈퍼유저가 아닌 dashboard_app) ---
    $r = Invoke-Sql "postgres" "postgres" @'
CREATE ROLE dashboard_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE zeekad_owner NOLOGIN;
CREATE ROLE t58_exec_only LOGIN NOSUPERUSER NOINHERIT;
CREATE ROLE t58_public_only LOGIN NOSUPERUSER NOINHERIT;
CREATE DATABASE zeekad OWNER zeekad_owner;
CREATE DATABASE zeekad_dashboard OWNER dashboard_app;
REVOKE ALL ON DATABASE zeekad FROM PUBLIC;
REVOKE ALL ON DATABASE zeekad_dashboard FROM PUBLIC;
GRANT CONNECT ON DATABASE zeekad_dashboard TO t58_exec_only, t58_public_only;
'@ -StopOnError
    if ($r.Code -ne 0) { throw "역할·DB 만들기 실패`n$($r.Out)" }
    # zeek_AD 스냅샷 대신: 설정 도구와 초기화 함수가 읽는 표 다섯을 같은 열로 빈 채 둔다(초기화 계정 zeekad_sandbox_reset은 설정 도구가 만든다).
    $r = Invoke-Sql "postgres" "zeekad" @'
CREATE SCHEMA zeekad AUTHORIZATION zeekad_owner;
CREATE TABLE zeekad.incident (incident_id text PRIMARY KEY);
CREATE TABLE zeekad.scoring_job (job_id bigint PRIMARY KEY);
CREATE TABLE zeekad.incident_status (last_job_id bigint, incident_id text PRIMARY KEY, status text, resolution text, updated_at timestamptz, updated_by text);
CREATE TABLE zeekad.incident_status_history (history_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, job_id bigint, incident_id text, from_status text, to_status text, resolution text, actor text, reason text, changed_at timestamptz);
CREATE TABLE zeekad.analyst_review (job_id bigint, incident_id text, requested_at timestamptz, reason text, action text, analyst text, note text, decided_at timestamptz, resumed_at timestamptz, resume_error text, PRIMARY KEY (job_id, incident_id));
ALTER TABLE zeekad.incident OWNER TO zeekad_owner;
ALTER TABLE zeekad.scoring_job OWNER TO zeekad_owner;
ALTER TABLE zeekad.incident_status OWNER TO zeekad_owner;
ALTER TABLE zeekad.incident_status_history OWNER TO zeekad_owner;
ALTER TABLE zeekad.analyst_review OWNER TO zeekad_owner;
'@ -StopOnError
    if ($r.Code -ne 0) { throw "zeekad 빈 표 만들기 실패`n$($r.Out)" }

    # --- migration 파일을 그대로 넣고 dashboard_app으로 하나씩(파일마다 한 트랜잭션) 적용한다 ---
    [void](Invoke-Docker @("exec", $ContainerName, "mkdir", "-p", "/t58/mig"))
    foreach ($m in $Migrations) { [void](Invoke-Docker @("cp", (Join-Path $MigrationDir $m), "${ContainerName}:/t58/mig/$m")) }
    [void](Invoke-Docker @("cp", $ResetScript, "${ContainerName}:/t58/sandbox-reset.sh"))
    [void](Invoke-Docker @("cp", $SetupScript, "${ContainerName}:/t58/sandbox-setup.sh"))
    [void](Invoke-Docker @("cp", $DailyTest, "${ContainerName}:/t58/sandbox-reset-daily-test.sh"))
    [void](Invoke-Docker @("exec", $ContainerName, "chmod", "-R", "a+rX", "/t58"))

    function Invoke-Migration([string]$File) {
        return Invoke-Docker @("exec", "--user", "postgres", $ContainerName, "sh", "-c",
            "psql -X -q -1 -v ON_ERROR_STOP=1 -U dashboard_app -d zeekad_dashboard -f /t58/mig/$File 2>&1") -IgnoreExitCode
    }
    # sandbox-reset.sh --once를 초기화 계정으로(소켓). 기한 값은 인자로 준다(-NoDaysVariable이면 변수 자체를 주지 않는다).
    # 소켓 접속은 trust라 SANDBOX_RESET_DB_PASSWORD는 인증에 쓰이지 않는다. 스크립트가 빈 값이면 돌지 않으므로 무작위 값을 넣는다.
    function Invoke-ResetOnce([string]$Days, [switch]$NoDaysVariable) {
        $a = @("exec", "--user", "postgres", "-e", "PGHOST=/var/run/postgresql", "-e", "SANDBOX_RESET_DB_PASSWORD=$($env:SANDBOX_RESET_DB_PASSWORD_T58)")
        if (-not $NoDaysVariable) { $a += @("-e", "SANDBOX_AUDIT_RETENTION_DAYS=$Days") }
        $a += @($ContainerName, "sh", "-c", "bash /t58/sandbox-reset.sh --once 2>&1")
        return Invoke-Docker $a -IgnoreExitCode
    }

    # sandbox-setup.sh를 슈퍼유저로(소켓). 소켓 접속은 trust라 두 비밀번호 값은 인증에 쓰이지 않는다(스크립트가 빈 값을 거부해서 넣는다).
    # -SetupArgs: 설정 도구에 줄 인자(고정 글 "--rebuild-baseline"만 쓴다).
    function Invoke-Setup([string]$SetupArgs = "") {
        if ($SetupArgs -ne "" -and $SetupArgs -ne "--rebuild-baseline") { throw "Invoke-Setup: 모르는 인자 $SetupArgs" }
        return Invoke-Docker @("exec", "--user", "postgres", "-e", "PGUSER=postgres", "-e", "PGPASSWORD=$($env:SANDBOX_RESET_DB_PASSWORD_T58)",
            "-e", "SANDBOX_RESET_DB_PASSWORD=$($env:SANDBOX_RESET_DB_PASSWORD_T58)", "-e", "SANDBOX_TRIAL_USERNAME=trial-analyst",
            $ContainerName, "sh", "-c", "bash /t58/sandbox-setup.sh $SetupArgs 2>&1") -IgnoreExitCode
    }
    function Get-SetupLines($Result) { return (@($Result.Out -split "`r?`n" | Where-Object { $_ -match 'sandbox-setup: ' }) -join ' / ') }

    foreach ($m in $Migrations[0..2]) {
        $r = Invoke-Migration $m
        Assert-Check "[적용] $m (dashboard_app, 한 트랜잭션)" ($r.Code -eq 0) "exit=$($r.Code) $($r.Out)"
    }

    # V4 전(앱이 아직 V4를 적용하지 않음): 설정 도구는 멈추고 아무것도 만들지 않는다. 초기화 한 번은 역할이 없어 미설정이다. 뒤의 reset-once.txt에 적는다.
    $setupBeforeV4 = Invoke-Setup
    $afterRefusedSetup = Get-Scalar "postgres" "SELECT 'role=' || (SELECT count(*) FROM pg_roles WHERE rolname = 'zeekad_sandbox_reset');"
    $afterRefusedSetup += " " + (Get-Scalar "zeekad" "SELECT 'zeekad_schemas=' || (SELECT count(*) FROM pg_namespace WHERE nspname IN ('sandbox', 'sandbox_baseline'));")
    $afterRefusedSetup += " " + (Get-Scalar "zeekad_dashboard" "SELECT 'app_schemas=' || (SELECT count(*) FROM pg_namespace WHERE nspname = 'sandbox');")
    $resetBeforeSetup = Invoke-ResetOnce "90"

    $r = Invoke-Migration $Migrations[3]
    Assert-Check "[적용] $($Migrations[3]) (dashboard_app, 한 트랜잭션)" ($r.Code -eq 0) "exit=$($r.Code) $($r.Out)"

    # T56: V4는 있고 V5가 없을 때(앱이 아직 V5를 적용하지 않음) 설정 도구는 멈춘다. 뒤의 response-actions.txt에 적는다.
    $setupBeforeV5 = Invoke-Setup
    $afterRefusedSetupV5 = Get-Scalar "postgres" "SELECT 'role=' || (SELECT count(*) FROM pg_roles WHERE rolname = 'zeekad_sandbox_reset');"
    $afterRefusedSetupV5 += " " + (Get-Scalar "zeekad" "SELECT 'zeekad_schemas=' || (SELECT count(*) FROM pg_namespace WHERE nspname IN ('sandbox', 'sandbox_baseline'));")
    $afterRefusedSetupV5 += " " + (Get-Scalar "zeekad_dashboard" "SELECT 'app_schemas=' || (SELECT count(*) FROM pg_namespace WHERE nspname = 'sandbox');")
    $r = Invoke-Migration $Migrations[4]
    Assert-Check "[적용] $($Migrations[4]) (dashboard_app, 한 트랜잭션)" ($r.Code -eq 0) "exit=$($r.Code) $($r.Out)"
    # T56: 대응 조치의 기준선이 될 행 둘(체험 계정이 아닌 분석가). 설정 도구 1차가 이 둘의 최대 id를 표식으로 잡는다.
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" @'
INSERT INTO incident_response_actions (incident_id, capture_id, job_id, action_type, note, actor_username, recorded_at) VALUES
  ('t56-inc', 't56-cap', 1, 'block_ip', 'baseline 1', 'analyst-a', now() - interval '2 days'),
  ('t56-inc', 't56-cap', 1, 'none', 'baseline 2', 'analyst-a', now() - interval '1 day');
'@ -StopOnError
    if ($r.Code -ne 0) { throw "대응 조치 기준선 행 넣기 실패`n$($r.Out)" }

    # --- 적용 뒤 함수의 소유자·정의자 권한·설정·PUBLIC 실행 권한(pg_proc에서 읽는다) ---
    $metaSql = "SELECT p.oid::regprocedure || ' owner=' || pg_get_userbyid(p.proowner) || ' prosecdef=' || p.prosecdef || ' proconfig=' || COALESCE(array_to_string(p.proconfig, ','), '(none)') || ' public_execute=' || EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) x WHERE x.grantee = 0) FROM pg_proc p WHERE p.oid = '{0}'::regprocedure;"
    $purgeMeta = Get-Scalar "zeekad_dashboard" ($metaSql -f "public.purge_expired_audit_logs(integer)")
    $trigMeta = Get-Scalar "zeekad_dashboard" ($metaSql -f "public.prevent_audit_log_mutation()")
    $triggers = Get-Scalar "zeekad_dashboard" "SELECT string_agg(tgname || ':' || pg_get_triggerdef(oid), ' ; ' ORDER BY tgname) FROM pg_trigger WHERE tgrelid = 'public.audit_logs'::regclass AND NOT tgisinternal;"
    Add-Line "# 삭제 함수: $purgeMeta"
    Add-Line "# 트리거 함수: $trigMeta"
    Add-Line "# audit_logs 트리거: $triggers"
    Assert-Check "[6a] 삭제 함수: 소유 dashboard_app, SECURITY DEFINER, search_path·lock_timeout 고정, PUBLIC 실행 불가" `
        ($purgeMeta -eq "purge_expired_audit_logs(integer) owner=dashboard_app prosecdef=true proconfig=search_path=pg_catalog, pg_temp,lock_timeout=5s public_execute=false") $purgeMeta
    Assert-Check "[6a] 트리거 함수: search_path 고정, 정의자 권한 아님" `
        ($trigMeta -eq "prevent_audit_log_mutation() owner=dashboard_app prosecdef=false proconfig=search_path=pg_catalog, pg_temp public_execute=true") $trigMeta
    Assert-Check "[1] audit_logs 트리거 둘: 행 수준 UPDATE·DELETE, 문장 수준 TRUNCATE" `
        ($triggers -match 'trg_audit_logs_immutable:.*BEFORE DELETE OR UPDATE ON public\.audit_logs FOR EACH ROW' -and $triggers -match 'trg_audit_logs_no_truncate:.*BEFORE TRUNCATE ON public\.audit_logs FOR EACH STATEMENT') $triggers

    # --- 시험 행: occurred_at을 직접 넣는다(100일 전, 31일 전, 30일 1시간 전, 30일에 1시간 모자람, 29일 전, 지금) ---
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" @'
INSERT INTO audit_logs (occurred_at, actor_username, actor_role, action_type, client_ip) VALUES
  (now() - interval '100 days', 't58-100d', 'VIEWER', 'LOGIN_SUCCESS', '203.0.113.10'),
  (now() - interval '31 days', 't58-31d', 'VIEWER', 'LOGIN_SUCCESS', '203.0.113.11'),
  (now() - interval '30 days 1 hour', 't58-30d-over', 'VIEWER', 'LOGIN_SUCCESS', '203.0.113.12'),
  (now() - interval '30 days' + interval '1 hour', 't58-30d-under', 'VIEWER', 'LOGIN_SUCCESS', '203.0.113.13'),
  (now() - interval '29 days', 't58-29d', 'VIEWER', 'LOGIN_SUCCESS', '203.0.113.14'),
  (now(), 't58-now', 'VIEWER', 'LOGIN_SUCCESS', '203.0.113.15');
'@ -StopOnError
    if ($r.Code -ne 0) { throw "시험 행 넣기 실패`n$($r.Out)" }
    $countSql = "SELECT count(*) FROM audit_logs;"
    $actorsSql = "SELECT COALESCE(string_agg(actor_username, ',' ORDER BY occurred_at, id), '(none)') FROM audit_logs WHERE actor_username LIKE 't58-%';"
    $allActors = "t58-100d,t58-31d,t58-30d-over,t58-30d-under,t58-29d,t58-now"
    Assert-Check "[준비] 시험 행 여섯" ((Get-Scalar "zeekad_dashboard" $actorsSql) -eq $allActors) (Get-Scalar "zeekad_dashboard" $actorsSql)

    # --- 1. 표식 없이: DELETE는 오래된 행도 거부, UPDATE는 어떤 행도 거부, TRUNCATE 거부 (앱 계정 = 표 소유자) ---
    foreach ($actor in @("t58-100d", "t58-31d", "t58-now")) {
        $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "DELETE FROM audit_logs WHERE actor_username = '$actor';"
        Assert-Check "[1] 표식 없이 DELETE 거부 ($actor)" ($r.Out -match 'ERROR:\s+audit_logs is append-only: DELETE is forbidden') $r.Out
    }
    foreach ($actor in @("t58-100d", "t58-29d", "t58-now")) {
        $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "UPDATE audit_logs SET action_type = 'TAMPERED' WHERE actor_username = '$actor';"
        Assert-Check "[1] UPDATE 거부 ($actor)" ($r.Out -match 'ERROR:\s+audit_logs is append-only: UPDATE is forbidden') $r.Out
    }
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "SET dashboard.audit_retention_purge = 'on'; UPDATE audit_logs SET action_type = 'TAMPERED' WHERE actor_username = 't58-100d';"
    Assert-Check "[1] 표식을 켜도 UPDATE 거부 (t58-100d)" ($r.Out -match 'ERROR:\s+audit_logs is append-only: UPDATE is forbidden') $r.Out
    foreach ($stmt in @("TRUNCATE audit_logs;", "TRUNCATE TABLE public.audit_logs RESTART IDENTITY CASCADE;", "SET dashboard.audit_retention_purge = 'on'; TRUNCATE audit_logs;")) {
        $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" $stmt
        Assert-Check "[1] TRUNCATE 거부 (dashboard_app: $stmt)" ($r.Out -match 'ERROR:\s+audit_logs is append-only: TRUNCATE is forbidden') $r.Out
    }
    # E2E [8]과 같은 꼴: 슈퍼유저의 UPDATE·TRUNCATE도 트리거가 거부한다.
    $r = Invoke-Sql "postgres" "zeekad_dashboard" "UPDATE audit_logs SET action_type = 'TAMPERED' WHERE id = (SELECT MIN(id) FROM audit_logs);"
    Assert-Check "[1] 슈퍼유저 UPDATE 거부 (E2E [8]과 같은 문장)" ($r.Out -match 'audit_logs is append-only') $r.Out
    $r = Invoke-Sql "postgres" "zeekad_dashboard" "TRUNCATE audit_logs;"
    Assert-Check "[1] 슈퍼유저 TRUNCATE 거부" ($r.Out -match 'ERROR:\s+audit_logs is append-only: TRUNCATE is forbidden') $r.Out
    Assert-Check "[1] 거부 뒤 행이 그대로(여섯, 값도 그대로)" (((Get-Scalar "zeekad_dashboard" $actorsSql) -eq $allActors) -and ((Get-Scalar "zeekad_dashboard" "SELECT count(*) FROM audit_logs WHERE action_type = 'TAMPERED';") -eq "0")) (Get-Scalar "zeekad_dashboard" $actorsSql)

    # --- 2. 표식을 손으로 켠 세션: 30일 안의 행은 그래도 거부, 30일 지난 행은 통과(표식은 권한 경계가 아니라 실수 방지) ---
    foreach ($actor in @("t58-now", "t58-29d", "t58-30d-under")) {
        $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "SET dashboard.audit_retention_purge = 'on'; DELETE FROM audit_logs WHERE actor_username = '$actor';"
        Assert-Check "[2] 표식을 켜도 30일 안의 행 DELETE 거부 ($actor)" ($r.Out -match 'ERROR:\s+audit_logs is append-only: DELETE is forbidden') $r.Out
    }
    foreach ($actor in @("t58-30d-over", "t58-31d", "t58-100d")) {
        $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "BEGIN; SET LOCAL dashboard.audit_retention_purge = 'on'; DELETE FROM audit_logs WHERE actor_username = '$actor' RETURNING 'deleted ' || actor_username; ROLLBACK;"
        Assert-Check "[2] 표식을 켜면 30일 지난 행 DELETE 통과 ($actor, 되돌림)" ($r.Out -eq "deleted $actor") $r.Out
    }
    foreach ($value in @("off", "ON", "true", "1")) {
        $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "SET dashboard.audit_retention_purge = '$value'; DELETE FROM audit_logs WHERE actor_username = 't58-100d';"
        Assert-Check "[2] 표식 값이 정확히 'on'이 아니면 거부 (값 '$value')" ($r.Out -match 'ERROR:\s+audit_logs is append-only: DELETE is forbidden') $r.Out
    }
    Assert-Check "[2] 되돌린 뒤 행이 그대로(여섯)" ((Get-Scalar "zeekad_dashboard" $actorsSql) -eq $allActors) (Get-Scalar "zeekad_dashboard" $actorsSql)

    # --- 4. 바닥값보다 작은 기한: 예외, 행 수 그대로 (3보다 먼저 본다: 100일 전 행이 아직 있어서 잘못 지우면 드러난다) ---
    $before4 = Get-Scalar "zeekad_dashboard" $countSql
    foreach ($arg in @("29", "0", "NULL", "-5", "1")) {
        $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "SELECT * FROM public.purge_expired_audit_logs($arg);"
        Assert-Check "[4] purge_expired_audit_logs($arg) 예외" ($r.Out -match 'ERROR:\s+audit retention must be at least 30 days') $r.Out
    }
    $after4 = Get-Scalar "zeekad_dashboard" $countSql
    Assert-Check "[4] 예외 뒤 행 수 그대로, 삭제 기록 행 없음" (($before4 -eq $after4) -and ((Get-Scalar "zeekad_dashboard" $actorsSql) -eq $allActors) -and ((Get-Scalar "zeekad_dashboard" "SELECT count(*) FROM audit_logs WHERE action_type = 'AUDIT_RETENTION_PURGE';") -eq "0")) "$before4 -> $after4"

    # --- 6. 권한: PUBLIC은 실행 불가, 실행 권한만 받은 역할은 함수는 부르지만 표는 못 읽고 못 지운다 ---
    $r = Invoke-Sql "t58_public_only" "zeekad_dashboard" "SELECT * FROM public.purge_expired_audit_logs(90);"
    Assert-Check "[6b] 권한을 받지 않은 역할(PUBLIC)은 삭제 함수를 못 부른다" ($r.Out -match 'ERROR:\s+permission denied for function purge_expired_audit_logs') $r.Out
    Assert-Check "[6b] 거부된 호출 뒤 행이 그대로(여섯)" ((Get-Scalar "zeekad_dashboard" $actorsSql) -eq $allActors) (Get-Scalar "zeekad_dashboard" $actorsSql)
    $r = Invoke-Sql "postgres" "zeekad_dashboard" "GRANT EXECUTE ON FUNCTION public.purge_expired_audit_logs(integer) TO t58_exec_only;" -StopOnError
    if ($r.Code -ne 0) { throw "실행 권한 주기 실패`n$($r.Out)" }
    foreach ($probe in @(
            @("SELECT count(*) FROM public.audit_logs;", "permission denied for table audit_logs"),
            @("DELETE FROM public.audit_logs WHERE actor_username = 't58-100d';", "permission denied for table audit_logs"),
            @("SET dashboard.audit_retention_purge = 'on'; DELETE FROM public.audit_logs WHERE actor_username = 't58-100d';", "permission denied for table audit_logs"),
            @("UPDATE public.audit_logs SET action_type = 'TAMPERED';", "permission denied for table audit_logs"),
            @("TRUNCATE public.audit_logs;", "permission denied for table audit_logs"),
            @("INSERT INTO public.audit_logs (action_type) VALUES ('FORGED');", "permission denied for table audit_logs"),
            @("SELECT * FROM public.purge_expired_audit_logs(29);", "audit retention must be at least 30 days"))) {
        $r = Invoke-Sql "t58_exec_only" "zeekad_dashboard" $probe[0]
        Assert-Check "[6c] 실행 권한만 받은 역할 거부: $($probe[0])" ($r.Out -match "ERROR:\s+$([regex]::Escape($probe[1]))") $r.Out
    }

    # --- 3. purge_expired_audit_logs(90): 100일 전 행만 지워지고 삭제 기록 행 하나가 남는다. 다시 부르면 0 ---
    $r = Invoke-Sql "t58_exec_only" "zeekad_dashboard" "SELECT deleted || '|' || (cutoff BETWEEN now() - interval '90 days 1 minute' AND now() - interval '90 days' + interval '1 minute') FROM public.purge_expired_audit_logs(90);"
    Assert-Check "[3] purge(90)을 실행 권한만 받은 역할이 부른다: 지운 수 1, 기준 시각 = 지금 - 90일" ($r.Code -eq 0 -and $r.Out -eq "1|true") "exit=$($r.Code) $($r.Out)"
    $left3 = Get-Scalar "zeekad_dashboard" $actorsSql
    Assert-Check "[3] 100일 전 행만 지워짐(31일 전·30일 앞뒤·29일 전·지금 행은 남음)" ($left3 -eq "t58-31d,t58-30d-over,t58-30d-under,t58-29d,t58-now") $left3
    $purgeRow = Get-Scalar "zeekad_dashboard" "SELECT count(*) || '|' || COALESCE(max(actor_username), '') || '|' || COALESCE(max(actor_role), '') || '|' || COALESCE(max(client_ip), '(null)') || '|' || COALESCE(max(detail_json), '') || '|' || bool_and(occurred_at BETWEEN now() - interval '5 minutes' AND now()) FROM audit_logs WHERE action_type = 'AUDIT_RETENTION_PURGE';"
    Assert-Check "[3] 삭제 기록 행 하나: 행위자 audit-retention, 역할 SYSTEM, 접속 주소 없음, 상세에 지운 수·기준 시각·기한" `
        ($purgeRow -match '^1\|audit-retention\|SYSTEM\|\(null\)\|\{"deleted" : 1, "cutoff" : "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", "retentionDays" : 90\}\|true$') $purgeRow
    $detailCutoff = Get-Scalar "zeekad_dashboard" "SELECT (((detail_json::json ->> 'cutoff')::timestamptz) BETWEEN now() - interval '90 days 1 minute' AND now() - interval '90 days' + interval '1 minute')::text FROM audit_logs WHERE action_type = 'AUDIT_RETENTION_PURGE';"
    Assert-Check "[3] 상세의 기준 시각이 UTC로 지금 - 90일" ($detailCutoff -eq "true") $detailCutoff
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "SELECT deleted FROM public.purge_expired_audit_logs(90);"
    $purgeRows2 = Get-Scalar "zeekad_dashboard" "SELECT count(*) FROM audit_logs WHERE action_type = 'AUDIT_RETENTION_PURGE';"
    Assert-Check "[3] 다시 부르면 0이고 새 삭제 기록 행이 없다" ($r.Out -eq "0" -and $purgeRows2 -eq "1" -and (Get-Scalar "zeekad_dashboard" $actorsSql) -eq $left3) "deleted=$($r.Out) purge rows=$purgeRows2"

    # --- 5. 함수가 끝난 뒤 같은 트랜잭션 안에서 표식이 꺼져 있다 ---
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" @'
INSERT INTO audit_logs (occurred_at, actor_username, actor_role, action_type) VALUES
  (now() - interval '100 days', 't58-tx-a', 'VIEWER', 'LOGIN_SUCCESS'),
  (now() - interval '100 days', 't58-tx-b', 'VIEWER', 'LOGIN_SUCCESS');
'@ -StopOnError
    if ($r.Code -ne 0) { throw "5번 시험 행 넣기 실패`n$($r.Out)" }
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" @'
BEGIN;
SELECT 'purged=' || deleted FROM public.purge_expired_audit_logs(90);
SELECT 'marker=' || current_setting('dashboard.audit_retention_purge', true);
INSERT INTO audit_logs (occurred_at, actor_username, actor_role, action_type) VALUES (now() - interval '100 days', 't58-tx-c', 'VIEWER', 'LOGIN_SUCCESS');
DELETE FROM audit_logs WHERE actor_username = 't58-tx-c' RETURNING 'deleted ' || actor_username;
ROLLBACK;
'@
    Assert-Check "[5] 같은 트랜잭션: 함수가 둘을 지운 뒤 표식은 off이고 그사이 넣은 100일 전 행의 DELETE는 거부" `
        ($r.Out -match '(?s)^purged=2\s+marker=off\s+.*ERROR:\s+audit_logs is append-only: DELETE is forbidden' -and $r.Out -notmatch 'deleted t58-tx-c') $r.Out
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" @'
BEGIN;
SET LOCAL dashboard.audit_retention_purge = 'on';
INSERT INTO audit_logs (occurred_at, actor_username, actor_role, action_type) VALUES (now() - interval '100 days', 't58-tx-c', 'VIEWER', 'LOGIN_SUCCESS');
DELETE FROM audit_logs WHERE actor_username = 't58-tx-c' RETURNING 'deleted ' || actor_username;
ROLLBACK;
'@
    Assert-Check "[5] (대조) 표식이 켜진 채였다면 같은 DELETE가 통과한다(위 거부가 표식이 꺼져서임을 보인다)" ($r.Out -eq "deleted t58-tx-c") $r.Out
    # 세션에서 미리 켜 둔 표식: 함수가 끝나면 그 트랜잭션에서는 꺼져 있다.
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" @'
SET dashboard.audit_retention_purge = 'on';
BEGIN;
SELECT 'purged=' || deleted FROM public.purge_expired_audit_logs(3650);
SELECT 'marker=' || current_setting('dashboard.audit_retention_purge', true);
ROLLBACK;
'@
    Assert-Check "[5] 세션에서 미리 켠 표식도 함수 뒤 그 트랜잭션에서는 off" ($r.Out -match '(?s)^purged=0\s+marker=off$') $r.Out
    $txRows = Get-Scalar "zeekad_dashboard" "SELECT string_agg(actor_username, ',' ORDER BY actor_username) FROM audit_logs WHERE actor_username LIKE 't58-tx-%';"
    Assert-Check "[5] 되돌린 뒤 100일 전 행 둘이 그대로" ($txRows -eq "t58-tx-a,t58-tx-b") $txRows

    # --- 3b. 기한을 바닥값(30)으로 주면 30일 지난 행까지만 지운다 ---
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "SELECT deleted FROM public.purge_expired_audit_logs(30);"
    $left30 = Get-Scalar "zeekad_dashboard" $actorsSql
    Assert-Check "[3b] purge(30): 100일 전 둘·31일 전·30일 1시간 전 행을 지우고 30일 안의 행은 남긴다" ($r.Out -eq "4" -and $left30 -eq "t58-30d-under,t58-29d,t58-now") "deleted=$($r.Out) left=$left30"
    $purgeRows3 = Get-Scalar "zeekad_dashboard" "SELECT count(*) || '|' || string_agg(detail_json::json ->> 'deleted', ',' ORDER BY id) || '|' || string_agg(detail_json::json ->> 'retentionDays', ',' ORDER BY id) FROM audit_logs WHERE action_type = 'AUDIT_RETENTION_PURGE';"
    Assert-Check "[3b] 삭제 기록 행이 둘(지운 수 1과 4, 기한 90과 30)" ($purgeRows3 -eq "2|1,4|90,30") $purgeRows3

    $volumesMid = @((Invoke-Docker @("volume", "ls", "-q")).Out -split "`r?`n" | Where-Object { $_ })
    Add-Line "# docker volume 수: 실행 전 $($volumesBefore.Count), 지금 $($volumesMid.Count) (다른 작업이 같은 기기에서 볼륨을 만들 수 있으므로 단언하지 않는다. 이 컨테이너는 tmpfs만 쓴다)"
    $mounts = (Invoke-Docker @("inspect", "--format", "{{range .Mounts}}{{.Type}}:{{.Name}}:{{.Destination}} {{end}}|tmpfs={{json .HostConfig.Tmpfs}}|net={{.HostConfig.NetworkMode}}", $ContainerName)).Out
    Assert-Check "[환경] 컨테이너에 볼륨 마운트가 없고 데이터 경로는 tmpfs, 네트워크 없음" ($mounts -match '^\|tmpfs=\{"/var/lib/postgresql/data":""\}\|net=none$') $mounts
    $totalFailed += Save-Lines "pg-check.txt"

    # ================= 설정 도구와 초기화 서비스(저장소의 두 스크립트 그대로) =================
    Add-Line "# T58 설정 도구(sandbox-setup.sh)와 초기화 서비스(sandbox-reset.sh --once): 저장소의 두 스크립트를 그대로 같은 일회용 PostgreSQL 컨테이너에서 실행"
    Add-Line "# 실행 시각(UTC) $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')), 이미지 $Image. zeek_AD 표 다섯은 열만 맞춘 빈 표다. 초기화 함수 셋·기준선·역할·권한은 설정 도구가 만든 실제 것이다."
    $lineRx = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z sandbox-reset: '
    # T56: assignments 칸 다음에 responses 칸이 온다(설계 변경으로 줄의 꼴이 바뀌었다). 이 구간에서는 기준선 뒤의 대응 조치 행이 없어 늘 removed=0이다.
    $base = 'pipeline\[OK\] analyst_review\(-0 \+0 ~0\) incident_status\(-0 \+0 ~0\) incident_status_history\(-0 \+0 ~0\); assignments\[OK\] released=0 history\+=0; responses\[OK\] removed=0'
    $purgeFnRx = 'public\.purge_expired_audit_logs\(integer\)'
    $resetPrivSql = "SELECT 'table_grants=' || (SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'zeekad_sandbox_reset') || ' purge_execute=' || COALESCE(has_function_privilege('zeekad_sandbox_reset', to_regprocedure('public.purge_expired_audit_logs(integer)')::oid, 'EXECUTE')::text, '(no function)') || ' reset_assignments_execute=' || has_function_privilege('zeekad_sandbox_reset', 'sandbox.reset_assignments()', 'EXECUTE') || ' public_create=' || has_schema_privilege('zeekad_sandbox_reset', 'public', 'CREATE');"

    Add-Line "[S1] V4 적용 전의 sandbox-setup: exit=$($setupBeforeV4.Code) $(Get-SetupLines $setupBeforeV4) | 뒤 상태: $afterRefusedSetup"
    Assert-Check "[S1] 삭제 함수가 없으면(앱이 V4를 적용하기 전) 설정 도구는 건너뛰지 않고 멈춘다. 역할·스키마를 만들지 않는다" `
        ($setupBeforeV4.Code -eq 1 -and $setupBeforeV4.Out -match ("function $purgeFnRx is missing in zeekad_dashboard; start dashboard-app with migration V4") -and $setupBeforeV4.Out -notmatch 'RESULT: OK' -and $afterRefusedSetup -eq "role=0 zeekad_schemas=0 app_schemas=0") "exit=$($setupBeforeV4.Code) $(Get-SetupLines $setupBeforeV4) | $afterRefusedSetup"
    Add-Line "[S2] 설정 전(초기화 계정 없음)의 sandbox-reset --once, 기한 90: exit=$($resetBeforeSetup.Code) $($resetBeforeSetup.Out)"
    Assert-Check "[S2] 설정 전에는 네 칸 모두 미설정이고 ERROR 줄이 아니다(종료 코드 0)" `
        ($resetBeforeSetup.Code -eq 0 -and $resetBeforeSetup.Out -match ($lineRx + 'NOT_CONFIGURED_OR_LOGIN_FAILED pipeline\[NOT_CONFIGURED_OR_LOGIN_FAILED\] .*; assignments\[NOT_CONFIGURED_OR_LOGIN_FAILED\] .*; responses\[NOT_CONFIGURED\] .*; audit\[NOT_CONFIGURED\] ') -and $resetBeforeSetup.Out -notmatch ' ERROR ') $resetBeforeSetup.Out

    # V4가 적용된 지금(위 pg-check가 끝난 상태) 설정 도구를 두 번 돌린다.
    $setup1 = Invoke-Setup
    Add-Line "[S3] V4 적용 뒤 sandbox-setup 1차: exit=$($setup1.Code) $(Get-SetupLines $setup1)"
    Assert-Check "[S3] 설정 도구 1차: 기준선 생성, 삭제 함수 EXECUTE 부여, 권한 점검 통과(표 권한 0, PUBLIC 실행 불가)" `
        ($setup1.Code -eq 0 -and $setup1.Out -match 'baseline created' -and $setup1.Out -match ("EXECUTE on $purgeFnRx granted to zeekad_sandbox_reset") -and $setup1.Out -match 'zeekad_dashboard\[public_create=false sandbox_create=false db_create=false db_temp=false table_grants=0 purge_public_execute=false\]' -and $setup1.Out -match 'RESULT: OK') "exit=$($setup1.Code) $(Get-SetupLines $setup1)"
    $setup2 = Invoke-Setup
    Add-Line "[S4] sandbox-setup 2차: exit=$($setup2.Code) $(Get-SetupLines $setup2)"
    Assert-Check "[S4] 설정 도구 2차(멱등): 기준선 유지, 같은 권한 점검 통과" ($setup2.Code -eq 0 -and $setup2.Out -match 'baseline kept' -and $setup2.Out -match 'purge_public_execute=false' -and $setup2.Out -match 'RESULT: OK') "exit=$($setup2.Code) $(Get-SetupLines $setup2)"
    $priv = Get-Scalar "zeekad_dashboard" $resetPrivSql
    Assert-Check "[S4] 초기화 계정(앱 DB): 표 권한 0, 삭제 함수와 담당 해제 함수 EXECUTE, public CREATE 없음" ($priv -eq "table_grants=0 purge_execute=true reset_assignments_execute=true public_create=false") $priv

    # 시험 행: 100일 전·91일 전·89일 전(앞 시험이 남긴 30일 안의 행 셋과 삭제 기록 둘은 그대로 있다).
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" @'
INSERT INTO audit_logs (occurred_at, actor_username, actor_role, action_type) VALUES
  (now() - interval '100 days', 't58-reset-old-1', 'VIEWER', 'LOGIN_SUCCESS'),
  (now() - interval '91 days', 't58-reset-old-2', 'VIEWER', 'LOGIN_SUCCESS'),
  (now() - interval '89 days', 't58-reset-keep', 'VIEWER', 'LOGIN_SUCCESS');
'@ -StopOnError
    if ($r.Code -ne 0) { throw "초기화 시험 행 넣기 실패`n$($r.Out)" }
    $resetActorsSql = "SELECT COALESCE(string_agg(actor_username, ',' ORDER BY actor_username), '(none)') FROM audit_logs WHERE actor_username LIKE 't58-reset-%';"
    $countBefore = Get-Scalar "zeekad_dashboard" $countSql

    # NAS에 반영할 때의 틈을 흉내 낸다: 초기화 계정과 초기화 함수 둘은 이미 있고(옛 설정) 삭제 함수만 아직 없다(앱이 V4를 적용하기 전).
    # 슈퍼유저로 삭제 함수를 없앤 뒤 본다. 이어서 V4 파일을 다시 적용한다(되돌린 뒤 V4가 다시 도는 경우와 같다).
    $r = Invoke-Sql "postgres" "zeekad_dashboard" "DROP FUNCTION public.purge_expired_audit_logs(integer);" -StopOnError
    if ($r.Code -ne 0) { throw "삭제 함수 없애기(틈 흉내) 실패`n$($r.Out)" }
    $r0 = Invoke-ResetOnce "90"
    Add-Line "[R0] 초기화 계정은 있고 삭제 함수가 없을 때(앱 V4 전), 기한 90: exit=$($r0.Code) $($r0.Out)"
    Assert-Check "[R0] 삭제 함수가 없으면 audit[NOT_CONFIGURED], 전체는 OK(ERROR 아님), 종료 코드 0, 지운 행 없음" `
        ($r0.Code -eq 0 -and $r0.Out -match ($lineRx + 'OK ' + $base + "; audit\[NOT_CONFIGURED\] $purgeFnRx is missing \(start the app with migration V4 first\)`$") -and (Get-Scalar "zeekad_dashboard" $countSql) -eq $countBefore) $r0.Out
    $setupNoFn = Invoke-Setup
    Add-Line "[S5] 같은 상태의 sandbox-setup: exit=$($setupNoFn.Code) $(Get-SetupLines $setupNoFn)"
    Assert-Check "[S5] 이미 설정된 스택에서도 삭제 함수가 없으면 설정 도구는 멈춘다" ($setupNoFn.Code -eq 1 -and $setupNoFn.Out -match ("function $purgeFnRx is missing") -and $setupNoFn.Out -notmatch 'RESULT: OK') "exit=$($setupNoFn.Code) $(Get-SetupLines $setupNoFn)"

    $reapply = Invoke-Migration $Migrations[3]
    $purgeMeta2 = Get-Scalar "zeekad_dashboard" ($metaSql -f "public.purge_expired_audit_logs(integer)")
    $triggers2 = Get-Scalar "zeekad_dashboard" "SELECT string_agg(tgname, ',' ORDER BY tgname) FROM pg_trigger WHERE tgrelid = 'public.audit_logs'::regclass AND NOT tgisinternal;"
    Add-Line "[V4 다시] $($Migrations[3])을 dashboard_app으로 다시 적용: exit=$($reapply.Code) $($reapply.Out) | $purgeMeta2 | triggers=$triggers2"
    Assert-Check "[V4 다시] V4 파일은 다시 적용해도 된다(CREATE OR REPLACE): 함수 설정이 처음과 같고 트리거는 둘 그대로" `
        ($reapply.Code -eq 0 -and $purgeMeta2 -eq $purgeMeta -and $triggers2 -eq "trg_audit_logs_immutable,trg_audit_logs_no_truncate") "exit=$($reapply.Code) $($reapply.Out) | $purgeMeta2 | $triggers2"

    $r1 = Invoke-ResetOnce "90"
    Add-Line "[R1] 앱이 V4를 적용한 뒤, sandbox-setup이 실행 권한을 주기 전, 기한 90: exit=$($r1.Code) $($r1.Out)"
    Assert-Check "[R1] 실행 권한이 없으면 audit[NOT_CONFIGURED], 전체는 OK(ERROR 아님), 종료 코드 0, 지운 행 없음" `
        ($r1.Code -eq 0 -and $r1.Out -match ($lineRx + 'OK ' + $base + "; audit\[NOT_CONFIGURED\] no EXECUTE on $purgeFnRx \(run sandbox-setup\)`$") -and (Get-Scalar "zeekad_dashboard" $countSql) -eq $countBefore) $r1.Out
    $r = Invoke-Sql "zeekad_sandbox_reset" "zeekad_dashboard" "SELECT * FROM public.purge_expired_audit_logs(90);"
    Assert-Check "[R1] 그때 초기화 계정이 함수를 직접 불러도 거부된다" ($r.Out -match 'ERROR:\s+permission denied for function purge_expired_audit_logs' -and (Get-Scalar "zeekad_dashboard" $countSql) -eq $countBefore) $r.Out

    $setup3 = Invoke-Setup
    $priv3 = Get-Scalar "zeekad_dashboard" $resetPrivSql
    Add-Line "[S6] sandbox-setup을 다시 실행: exit=$($setup3.Code) $(Get-SetupLines $setup3) | $priv3"
    Assert-Check "[S6] 설정 도구를 다시 돌리면 실행 권한이 붙는다(기준선 유지, 표 권한 0)" ($setup3.Code -eq 0 -and $setup3.Out -match 'baseline kept' -and $setup3.Out -match 'RESULT: OK' -and $priv3 -eq "table_grants=0 purge_execute=true reset_assignments_execute=true public_create=false") "exit=$($setup3.Code) $(Get-SetupLines $setup3) | $priv3"

    $r2 = Invoke-ResetOnce "" -NoDaysVariable
    Add-Line "[R2] 기한 변수 없음: exit=$($r2.Code) $($r2.Out)"
    Assert-Check "[R2] 기한 값이 없으면 audit[OFF], 지운 행 없음" ($r2.Code -eq 0 -and $r2.Out -match ($lineRx + 'OK ' + $base + '; audit\[OFF\]$') -and (Get-Scalar "zeekad_dashboard" $countSql) -eq $countBefore) $r2.Out
    $r2b = Invoke-ResetOnce "0"
    Add-Line "[R2] 기한 0: exit=$($r2b.Code) $($r2b.Out)"
    Assert-Check "[R2] 기한 0이면 audit[OFF], 지운 행 없음" ($r2b.Code -eq 0 -and $r2b.Out -match ($lineRx + 'OK ' + $base + '; audit\[OFF\]$') -and (Get-Scalar "zeekad_dashboard" $countSql) -eq $countBefore) $r2b.Out

    $r3 = Invoke-ResetOnce "90"
    Add-Line "[R3] 실행 권한 있음, 기한 90: exit=$($r3.Code) $($r3.Out)"
    $m3 = [regex]::Match($r3.Out, $lineRx + 'OK ' + $base + '; audit\[OK\] purged=(\d+) cutoff=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$')
    $resetLeft = Get-Scalar "zeekad_dashboard" $resetActorsSql
    Assert-Check "[R3] 실행 권한이 있으면 audit[OK] purged=2 cutoff=<UTC>, 90일 지난 행 둘만 지워짐" ($r3.Code -eq 0 -and $m3.Success -and $m3.Groups[1].Value -eq "2" -and $resetLeft -eq "t58-reset-keep") "$($r3.Out) | left=$resetLeft"
    if ($m3.Success) {
        $cutoffOk = Get-Scalar "zeekad_dashboard" "SELECT ('$($m3.Groups[2].Value)'::timestamptz BETWEEN now() - interval '90 days 1 minute' AND now() - interval '90 days' + interval '1 minute')::text;"
        Assert-Check "[R3] 로그의 cutoff가 UTC로 지금 - 90일" ($cutoffOk -eq "true") $m3.Groups[2].Value
    }
    $r4 = Invoke-ResetOnce "90"
    Add-Line "[R4] 다시 한 번: exit=$($r4.Code) $($r4.Out)"
    Assert-Check "[R4] 다시 부르면 audit[OK] purged=0" ($r4.Code -eq 0 -and $r4.Out -match ($lineRx + 'OK ' + $base + '; audit\[OK\] purged=0 cutoff=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')) $r4.Out
    $r5 = Invoke-ResetOnce "29"
    Add-Line "[R5] 기한 29(바닥값 아래): exit=$($r5.Code) $($r5.Out)"
    Assert-Check "[R5] 기한 값이 정수 30~3650이 아니면 exit 2, 로그 줄 없음, 지운 행 없음" ($r5.Code -eq 2 -and $r5.Out -notmatch 'sandbox-reset: (OK|ERROR)' -and (Get-Scalar "zeekad_dashboard" $resetActorsSql) -eq "t58-reset-keep") "exit=$($r5.Code) $($r5.Out)"

    # 초기화 계정은 삭제 함수를 부를 뿐 표는 못 읽고 못 지운다(표 권한 0).
    foreach ($stmt in @("SELECT count(*) FROM public.audit_logs;", "DELETE FROM public.audit_logs;", "TRUNCATE public.audit_logs;", "UPDATE public.audit_logs SET action_type = 'TAMPERED';")) {
        $r = Invoke-Sql "zeekad_sandbox_reset" "zeekad_dashboard" $stmt
        Assert-Check "[R6] 초기화 계정 거부: $stmt" ($r.Out -match 'ERROR:\s+permission denied for table audit_logs') $r.Out
    }
    $grants = Get-Scalar "zeekad_dashboard" $resetPrivSql
    $grantsZ = Get-Scalar "zeekad" "SELECT 'table_grants=' || (SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'zeekad_sandbox_reset') || ' baseline_usage=' || has_schema_privilege('zeekad_sandbox_reset', 'sandbox_baseline', 'USAGE');"
    Assert-Check "[R6] 초기화 계정: 두 DB 모두 표 권한 0, 함수 EXECUTE만" ($grants -eq "table_grants=0 purge_execute=true reset_assignments_execute=true public_create=false" -and $grantsZ -eq "table_grants=0 baseline_usage=false") "zeekad_dashboard[$grants] zeekad[$grantsZ]"

    # 실패 경로(실제 DB 오류): 삭제 함수가 잠금을 5초 안에 못 잡으면 audit[ERROR]이고 전체가 ERROR다. 다른 연결이 표를 ACCESS EXCLUSIVE로 잡는다.
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "INSERT INTO audit_logs (occurred_at, actor_username, actor_role, action_type) VALUES (now() - interval '100 days', 't58-reset-locked', 'VIEWER', 'LOGIN_SUCCESS');" -StopOnError
    # 잠금은 컨테이너 안에서 따로 도는 psql이 잡는다(-c 하나는 한 트랜잭션이라 pg_sleep이 끝날 때까지 잠금을 쥔다).
    [void](Invoke-Docker @("exec", "-d", "--user", "postgres", $ContainerName, "psql", "-X", "-q", "-U", "postgres", "-d", "zeekad_dashboard",
            "-c", "LOCK TABLE public.audit_logs IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(12);"))
    $held = $false
    for ($i = 0; $i -lt 40; $i++) {
        if ((Get-Scalar "zeekad_dashboard" "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation WHERE c.relname = 'audit_logs' AND l.mode = 'AccessExclusiveLock' AND l.granted;") -ne "0") { $held = $true; break }
        Start-Sleep -Milliseconds 250
    }
    $r7 = Invoke-ResetOnce "90"
    for ($i = 0; $i -lt 80; $i++) {
        if ((Get-Scalar "zeekad_dashboard" "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation WHERE c.relname = 'audit_logs' AND l.mode = 'AccessExclusiveLock';") -eq "0") { break }
        Start-Sleep -Milliseconds 250
    }
    Add-Line "[R7] 다른 연결이 audit_logs를 잠근 동안(12초), 기한 90: exit=$($r7.Code) $($r7.Out)"
    Assert-Check "[R7] 잠금 시간(5초)을 넘기면 audit[ERROR]이고 전체 ERROR, 종료 코드 1, 행은 그대로" `
        ($held -and $r7.Code -eq 1 -and $r7.Out -match ($lineRx + 'ERROR ' + $base + '; audit\[ERROR\] .*canceling statement due to lock timeout') -and (Get-Scalar "zeekad_dashboard" "SELECT count(*) FROM audit_logs WHERE actor_username = 't58-reset-locked';") -eq "1") "held=$held $($r7.Out)"
    $r8 = Invoke-ResetOnce "90"
    Add-Line "[R8] 잠금이 풀린 뒤: exit=$($r8.Code) $($r8.Out)"
    Assert-Check "[R8] 잠금이 풀리면 다음 실행이 지운다(audit[OK] purged=1)" ($r8.Code -eq 0 -and $r8.Out -match ($lineRx + 'OK ' + $base + '; audit\[OK\] purged=1 cutoff=')) $r8.Out
    $totalFailed += Save-Lines "reset-once.txt"

    # ================= T56 대응 조치 기록: V5의 트리거, 기준선 표식, 초기화 함수(저장소의 두 스크립트 그대로) =================
    Add-Line "# T56 대응 조치 기록: V5(incident_response_actions)의 트리거와 설정 도구의 기준선 표식·초기화 함수를 같은 일회용 PostgreSQL 컨테이너에서 직접 본 결과"
    Add-Line "# 실행 시각(UTC) $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')), 이미지 $Image. 모의가 아니라 실제 PostgreSQL이다. 기준선 행 둘(analyst-a)은 설정 도구 1차 전에 넣었다."
    $raTable = "incident_response_actions"
    $raRowsSql = "SELECT COALESCE(string_agg(note, ',' ORDER BY id), '(none)') FROM public.incident_response_actions;"
    # 표식의 지금 값: 표가 없으면 'no table', 행이 없으면 'no row', 있으면 'max_id=N'(없는 표를 가리키는 문장은 분석 단계에서 실패하므로 둘로 나눠 묻는다)
    function Get-RaMarker {
        if ((Get-Scalar "zeekad_dashboard" "SELECT (to_regclass('sandbox.response_action_baseline') IS NOT NULL)::text;") -ne "true") { return "no table" }
        return (Get-Scalar "zeekad_dashboard" "SELECT COALESCE((SELECT 'max_id=' || max_id FROM sandbox.response_action_baseline WHERE id = 1), 'no row');")
    }
    $raMaxSql = "SELECT COALESCE(max(id), 0) FROM public.incident_response_actions;"
    $raInsert = "INSERT INTO incident_response_actions (incident_id, capture_id, job_id, action_type, note, actor_username, recorded_at) VALUES ('t56-inc', 't56-cap', 1, '{0}', '{1}', '{2}', now());"
    # 운영자가 체험 계정의 행을 손으로 지우는 방법(docs/portfolio-deployment.md의 안내와 같은 문장). 표식을 트랜잭션 안에서만 켠다.
    $raOperatorDelete = "BEGIN; SET LOCAL dashboard.response_actions_reset = 'on'; DELETE FROM public.incident_response_actions WHERE actor_username = 'trial-analyst'; COMMIT;"
    $head = 'pipeline\[OK\] analyst_review\(-0 \+0 ~0\) incident_status\(-0 \+0 ~0\) incident_status_history\(-0 \+0 ~0\); assignments\[OK\] released=0 history\+=0'
    $raFnRx = 'sandbox\.reset_response_actions\(\)'

    # --- V5 전(앱이 아직 V5를 적용하지 않음): 설정 도구는 멈춘다 ---
    Add-Line "[T56-0] V5 적용 전의 sandbox-setup: exit=$($setupBeforeV5.Code) $(Get-SetupLines $setupBeforeV5) | 뒤 상태: $afterRefusedSetupV5"
    Assert-Check "[T56-0] 대응 조치 표가 없으면(앱이 V5를 적용하기 전) 설정 도구는 건너뛰지 않고 멈춘다. 역할·스키마를 만들지 않는다" `
        ($setupBeforeV5.Code -eq 1 -and $setupBeforeV5.Out -match 'table public\.incident_response_actions is missing in zeekad_dashboard; start dashboard-app with migration V5' -and $setupBeforeV5.Out -notmatch 'RESULT: OK' -and $afterRefusedSetupV5 -eq "role=0 zeekad_schemas=0 app_schemas=0") "exit=$($setupBeforeV5.Code) $(Get-SetupLines $setupBeforeV5) | $afterRefusedSetupV5"

    # --- 1. 트리거와 CHECK ---
    $raTrigMeta = Get-Scalar "zeekad_dashboard" ($metaSql -f "public.prevent_response_action_mutation()")
    $raTriggers = Get-Scalar "zeekad_dashboard" "SELECT string_agg(tgname || ':' || pg_get_triggerdef(oid), ' ; ' ORDER BY tgname) FROM pg_trigger WHERE tgrelid = 'public.incident_response_actions'::regclass AND NOT tgisinternal;"
    $raOwner = Get-Scalar "zeekad_dashboard" "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.incident_response_actions'::regclass;"
    Add-Line "# 트리거 함수: $raTrigMeta"
    Add-Line "# $raTable 트리거: $raTriggers"
    Assert-Check "[T56-1] 표 소유자는 슈퍼유저가 아닌 dashboard_app, 트리거 함수는 search_path 고정이고 정의자 권한이 아니다" `
        ($raOwner -eq "dashboard_app" -and $raTrigMeta -eq "prevent_response_action_mutation() owner=dashboard_app prosecdef=false proconfig=search_path=pg_catalog, pg_temp public_execute=true") "table owner=$raOwner | $raTrigMeta"
    Assert-Check "[T56-1] 트리거 둘: 행 수준 UPDATE·DELETE, 문장 수준 TRUNCATE" `
        ($raTriggers -match 'trg_incident_response_actions_immutable:.*BEFORE DELETE OR UPDATE ON public\.incident_response_actions FOR EACH ROW' -and $raTriggers -match 'trg_incident_response_actions_no_truncate:.*BEFORE TRUNCATE ON public\.incident_response_actions FOR EACH STATEMENT') $raTriggers
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" ($raInsert -f "shutdown", "bad kind", "analyst-a")
    Assert-Check "[T56-1] 종류가 일곱 값 밖이면 CHECK가 거부한다" ($r.Out -match 'ERROR:.*violates check constraint') $r.Out
    $raBaseRows = "baseline 1,baseline 2"
    Assert-Check "[T56-준비] 기준선 행 둘(설정 도구 1차 전에 넣음)" ((Get-Scalar "zeekad_dashboard" $raRowsSql) -eq $raBaseRows) (Get-Scalar "zeekad_dashboard" $raRowsSql)

    # --- 2. 고칠 수 없다: UPDATE·TRUNCATE는 늘 거부, DELETE는 표식 없이는 거부 (앱 계정 = 표 소유자, 슈퍼유저도) ---
    foreach ($stmt in @(
            "UPDATE incident_response_actions SET note = 'tampered';",
            "UPDATE incident_response_actions SET action_type = 'none' WHERE note = 'baseline 1';",
            "SET dashboard.response_actions_reset = 'on'; UPDATE incident_response_actions SET note = 'tampered';")) {
        $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" $stmt
        Assert-Check "[T56-2] UPDATE 거부 (dashboard_app: $stmt)" ($r.Out -match 'ERROR:\s+incident_response_actions is append-only: UPDATE is forbidden') $r.Out
    }
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "DELETE FROM incident_response_actions;"
    Assert-Check "[T56-2] 표식 없는 DELETE 거부 (dashboard_app)" ($r.Out -match 'ERROR:\s+incident_response_actions is append-only: DELETE is forbidden') $r.Out
    foreach ($value in @("off", "ON", "true", "1")) {
        $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "SET dashboard.response_actions_reset = '$value'; DELETE FROM incident_response_actions;"
        Assert-Check "[T56-2] 표식 값이 정확히 'on'이 아니면 DELETE 거부 (값 '$value')" ($r.Out -match 'ERROR:\s+incident_response_actions is append-only: DELETE is forbidden') $r.Out
    }
    foreach ($stmt in @("TRUNCATE incident_response_actions;", "TRUNCATE TABLE public.incident_response_actions RESTART IDENTITY CASCADE;", "SET dashboard.response_actions_reset = 'on'; TRUNCATE incident_response_actions;")) {
        $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" $stmt
        Assert-Check "[T56-2] TRUNCATE 거부 (dashboard_app: $stmt)" ($r.Out -match 'ERROR:\s+incident_response_actions is append-only: TRUNCATE is forbidden') $r.Out
    }
    foreach ($probe in @(
            @("UPDATE public.incident_response_actions SET note = 'tampered';", "UPDATE"),
            @("DELETE FROM public.incident_response_actions;", "DELETE"),
            @("TRUNCATE public.incident_response_actions;", "TRUNCATE"))) {
        $r = Invoke-Sql "postgres" "zeekad_dashboard" $probe[0]
        Assert-Check "[T56-2] 슈퍼유저도 거부: $($probe[0])" ($r.Out -match "ERROR:\s+incident_response_actions is append-only: $($probe[1]) is forbidden") $r.Out
    }
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" "BEGIN; SET LOCAL dashboard.response_actions_reset = 'on'; DELETE FROM incident_response_actions WHERE note = 'baseline 1' RETURNING 'deleted ' || note; ROLLBACK;"
    Assert-Check "[T56-2] (대조) 표식을 켠 트랜잭션에서는 DELETE가 통과한다(되돌림). 표식은 권한 경계가 아니라 실수 방지다" ($r.Out -eq "deleted baseline 1") $r.Out
    Assert-Check "[T56-2] 거부·되돌림 뒤 행이 그대로(둘, 값도 그대로)" ((Get-Scalar "zeekad_dashboard" $raRowsSql) -eq $raBaseRows) (Get-Scalar "zeekad_dashboard" $raRowsSql)

    # --- 3. 설정 도구가 만든 것: 기준선 표식(설정 시점의 최대 id), 초기화 함수, 권한 ---
    $raFnMeta = Get-Scalar "zeekad_dashboard" ($metaSql -f "sandbox.reset_response_actions()")
    $raMarkerMeta = Get-Scalar "zeekad_dashboard" "SELECT 'owner=' || pg_get_userbyid(c.relowner) || ' rows=' || (SELECT count(*) FROM sandbox.response_action_baseline) || ' ' || (SELECT 'max_id=' || max_id FROM sandbox.response_action_baseline WHERE id = 1) || ' grants=' || (SELECT count(*) FROM information_schema.role_table_grants g WHERE g.table_schema = 'sandbox' AND g.table_name = 'response_action_baseline' AND g.grantee <> 'dashboard_app') FROM pg_class c WHERE c.oid = 'sandbox.response_action_baseline'::regclass;"
    Add-Line "# 초기화 함수: $raFnMeta"
    Add-Line "# 기준선 표식: $raMarkerMeta"
    Add-Line "[T56-3] sandbox-setup 1차의 대응 조치 줄: $(@($setup1.Out -split "`r?`n" | Where-Object { $_ -match 'response' }) -join ' / ')"
    Assert-Check "[T56-3] 설정 도구 1차: 기준선 표식 생성(max_id = 그때의 최대 id 2), 초기화 함수 준비, 권한 점검 줄" `
        ($setup1.Out -match 'response action baseline created: max_id=2' -and $setup1.Out -match "zeekad_dashboard: $raFnRx ready" -and $setup1.Out -match 'response_actions\[actions_select=false marker_select=false reset_public_execute=false\]') (@($setup1.Out -split "`r?`n" | Where-Object { $_ -match 'response' }) -join ' / ')
    Assert-Check "[T56-3] 설정 도구 2차(멱등): 표식을 그대로 둔다" ($setup2.Out -match 'response action baseline kept: max_id=2 ') (@($setup2.Out -split "`r?`n" | Where-Object { $_ -match 'response action baseline' }) -join ' / ')
    Assert-Check "[T56-3] 기준선 표식 표: 소유 dashboard_app, 한 행, 다른 역할에 준 권한 0" ($raMarkerMeta -eq "owner=dashboard_app rows=1 max_id=2 grants=0") $raMarkerMeta
    Assert-Check "[T56-3] 초기화 함수: 소유 dashboard_app, SECURITY DEFINER, search_path·lock_timeout 고정, PUBLIC 실행 불가" `
        ($raFnMeta -eq "sandbox.reset_response_actions() owner=dashboard_app prosecdef=true proconfig=search_path=pg_catalog, pg_temp,lock_timeout=5s public_execute=false") $raFnMeta
    $raPriv = Get-Scalar "zeekad_dashboard" "SELECT 'table_grants=' || (SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'zeekad_sandbox_reset') || ' reset_execute=' || has_function_privilege('zeekad_sandbox_reset', 'sandbox.reset_response_actions()', 'EXECUTE') || ' actions_any=' || has_table_privilege('zeekad_sandbox_reset', 'public.incident_response_actions', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE') || ' marker_any=' || has_table_privilege('zeekad_sandbox_reset', 'sandbox.response_action_baseline', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE');"
    Assert-Check "[T56-3] 초기화 계정: 표 권한 0, 초기화 함수 EXECUTE만(대응 조치 표와 표식 표의 어떤 권한도 없음)" ($raPriv -eq "table_grants=0 reset_execute=true actions_any=false marker_any=false") $raPriv
    foreach ($probe in @(
            @("SELECT count(*) FROM public.incident_response_actions;", "permission denied for table incident_response_actions"),
            @("INSERT INTO public.incident_response_actions (incident_id, capture_id, job_id, action_type, actor_username, recorded_at) VALUES ('x', 'x', 1, 'none', 'forged', now());", "permission denied for table incident_response_actions"),
            @("UPDATE public.incident_response_actions SET note = 'tampered';", "permission denied for table incident_response_actions"),
            @("DELETE FROM public.incident_response_actions;", "permission denied for table incident_response_actions"),
            @("SET dashboard.response_actions_reset = 'on'; DELETE FROM public.incident_response_actions;", "permission denied for table incident_response_actions"),
            @("TRUNCATE public.incident_response_actions;", "permission denied for table incident_response_actions"),
            @("SELECT max_id FROM sandbox.response_action_baseline;", "permission denied for table response_action_baseline"),
            @("UPDATE sandbox.response_action_baseline SET max_id = 0;", "permission denied for table response_action_baseline"),
            @("DELETE FROM sandbox.response_action_baseline;", "permission denied for table response_action_baseline"),
            @("DROP TABLE sandbox.response_action_baseline;", "must be owner of table response_action_baseline"))) {
        $r = Invoke-Sql "zeekad_sandbox_reset" "zeekad_dashboard" $probe[0]
        Assert-Check "[T56-3] 초기화 계정 거부: $($probe[0])" ($r.Out -match "ERROR:\s+$([regex]::Escape($probe[1]))") $r.Out
    }
    $r = Invoke-Sql "t58_public_only" "zeekad_dashboard" "SELECT removed FROM sandbox.reset_response_actions();"
    Assert-Check "[T56-3] 권한을 받지 않은 역할(PUBLIC)은 초기화 함수를 못 부른다" ($r.Out -match 'ERROR:\s+permission denied') $r.Out
    Assert-Check "[T56-3] 거부 뒤 행과 표식이 그대로" ((Get-Scalar "zeekad_dashboard" $raRowsSql) -eq $raBaseRows -and (Get-RaMarker) -eq "max_id=2") "$(Get-Scalar 'zeekad_dashboard' $raRowsSql) | $(Get-RaMarker)"

    # --- 4. 초기화: 기준선 뒤에 덧붙은 행만 지운다. 감사 로그의 기록은 남는다 ---
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" ((($raInsert -f "block_ip", "trial 1", "trial-analyst"), ($raInsert -f "none", "trial 2", "trial-analyst"), ($raInsert -f "monitor", "analyst after baseline", "analyst-b"),
            "INSERT INTO audit_logs (actor_username, actor_role, action_type, target_incident_id, detail_json) VALUES ('trial-analyst', 'ANALYST', 'INCIDENT_RESPONSE_ACTION', 't56-inc', '{`"action`":`"block_ip`",`"note`":`"trial 1`"}');") -join "`n") -StopOnError
    if ($r.Code -ne 0) { throw "T56 시험 행 넣기 실패`n$($r.Out)" }
    $raAuditSql = "SELECT count(*) FROM audit_logs WHERE action_type = 'INCIDENT_RESPONSE_ACTION';"
    Assert-Check "[T56-4 준비] 기준선 뒤에 세 행(체험 계정 둘, 다른 분석가 하나)과 감사 행 하나" ((Get-Scalar "zeekad_dashboard" $raRowsSql) -eq "$raBaseRows,trial 1,trial 2,analyst after baseline" -and (Get-Scalar "zeekad_dashboard" $raAuditSql) -eq "1") (Get-Scalar "zeekad_dashboard" $raRowsSql)
    $t1 = Invoke-ResetOnce "" -NoDaysVariable
    Add-Line "[T56-4] 기준선 뒤에 세 행이 있을 때 sandbox-reset --once: exit=$($t1.Code) $($t1.Out)"
    Assert-Check "[T56-4] 로그 줄의 responses[OK] removed=3(assignments 칸과 audit 칸 사이), 전체 OK" `
        ($t1.Code -eq 0 -and $t1.Out -match ($lineRx + 'OK ' + $head + '; responses\[OK\] removed=3; audit\[OFF\]$')) $t1.Out
    Assert-Check "[T56-4] 기준선 뒤의 행만 지워지고 기준선 안의 행 둘은 남는다. 감사 로그의 기록도 남는다" `
        ((Get-Scalar "zeekad_dashboard" $raRowsSql) -eq $raBaseRows -and (Get-Scalar "zeekad_dashboard" $raAuditSql) -eq "1") "$(Get-Scalar 'zeekad_dashboard' $raRowsSql) | audit=$(Get-Scalar 'zeekad_dashboard' $raAuditSql)"
    $t2 = Invoke-ResetOnce "" -NoDaysVariable
    Add-Line "[T56-4] 다시 한 번: exit=$($t2.Code) $($t2.Out)"
    Assert-Check "[T56-4] 다시 부르면 responses[OK] removed=0" ($t2.Code -eq 0 -and $t2.Out -match ($lineRx + 'OK ' + $base + '; audit\[OFF\]$')) $t2.Out
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" @'
BEGIN;
INSERT INTO incident_response_actions (incident_id, capture_id, job_id, action_type, note, actor_username, recorded_at) VALUES ('t56-inc', 't56-cap', 1, 'other', 'tx row', 'trial-analyst', now());
SELECT 'removed=' || removed FROM sandbox.reset_response_actions();
SELECT 'marker=' || current_setting('dashboard.response_actions_reset', true);
DELETE FROM incident_response_actions WHERE note = 'baseline 1' RETURNING 'deleted ' || note;
ROLLBACK;
'@
    Assert-Check "[T56-4] 같은 트랜잭션: 함수가 지운 뒤 표식은 off이고 이어지는 DELETE는 거부된다" `
        ($r.Out -match '(?s)^removed=1\s+marker=off\s+.*ERROR:\s+incident_response_actions is append-only: DELETE is forbidden' -and $r.Out -notmatch 'deleted baseline') $r.Out
    Assert-Check "[T56-4] 되돌린 뒤 행이 그대로(둘)" ((Get-Scalar "zeekad_dashboard" $raRowsSql) -eq $raBaseRows) (Get-Scalar "zeekad_dashboard" $raRowsSql)

    # --- 5. 설정 도구를 다시 돌려도 표식은 움직이지 않는다(그 뒤의 행은 여전히 기준선 뒤다) ---
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" ($raInsert -f "handover", "after rerun", "analyst-b") -StopOnError
    $setupKeep = Invoke-Setup
    Add-Line "[T56-5] 기준선 뒤에 행이 있을 때 sandbox-setup: exit=$($setupKeep.Code) $(@($setupKeep.Out -split "`r?`n" | Where-Object { $_ -match 'baseline' }) -join ' / ')"
    Assert-Check "[T56-5] 표식이 있으면 설정 도구는 그대로 둔다(max_id=2). zeek_AD 기준선도 그대로다" `
        ($setupKeep.Code -eq 0 -and $setupKeep.Out -match 'sandbox-setup: baseline kept' -and $setupKeep.Out -match 'response action baseline kept: max_id=2 ' -and (Get-RaMarker) -eq "max_id=2") "exit=$($setupKeep.Code) $(Get-RaMarker)"
    $t3 = Invoke-ResetOnce "" -NoDaysVariable
    Assert-Check "[T56-5] 그 행은 다음 초기화가 지운다(responses[OK] removed=1)" ($t3.Code -eq 0 -and $t3.Out -match ($lineRx + 'OK ' + $head + '; responses\[OK\] removed=1; audit\[OFF\]$') -and (Get-Scalar "zeekad_dashboard" $raRowsSql) -eq $raBaseRows) $t3.Out

    # --- 6. NAS 갱신 경우: zeek_AD 기준선은 있고 대응 조치 표식은 없다(설정 뒤 슈퍼유저로 표식 표만 지움) ---
    $r = Invoke-Sql "postgres" "zeekad_dashboard" "DROP TABLE sandbox.response_action_baseline;" -StopOnError
    if ($r.Code -ne 0) { throw "표식 표 지우기(NAS 갱신 흉내) 실패`n$($r.Out)" }
    $zBaselineBefore = Get-Scalar "zeekad" "SELECT created_at::text FROM sandbox_baseline.marker WHERE id = 1;"
    $t4 = Invoke-ResetOnce "" -NoDaysVariable
    Add-Line "[T56-6] 표식이 없는데 함수가 불릴 때: exit=$($t4.Code) $($t4.Out)"
    Assert-Check "[T56-6] 표식이 없으면 0건이 아니라 responses[ERROR]이고 전체 ERROR, 종료 코드 1" `
        ($t4.Code -eq 1 -and $t4.Out -match ($lineRx + 'ERROR ' + $head + '; responses\[ERROR\] ERROR: +relation "sandbox\.response_action_baseline" does not exist.*; audit\[OFF\]$')) $t4.Out
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" ((($raInsert -f "block_ip", "visitor before setup", "trial-analyst"), ($raInsert -f "isolate_host", "analyst before setup", "analyst-b")) -join "`n") -StopOnError
    $setupRefused = Invoke-Setup
    Add-Line "[T56-6] 체험 계정의 행이 있을 때 sandbox-setup: exit=$($setupRefused.Code) $(Get-SetupLines $setupRefused)"
    Assert-Check "[T56-6] 체험 계정의 행이 하나라도 있으면 표식을 만들지 않고 멈춘다(방문자 글을 기준선으로 굳히지 않는다)" `
        ($setupRefused.Code -eq 1 -and $setupRefused.Out -match "REFUSED: 1 response action rows recorded by 'trial-analyst' exist" -and $setupRefused.Out -notmatch 'RESULT: OK' -and (Get-RaMarker) -eq "no table") "exit=$($setupRefused.Code) marker=$(Get-RaMarker)"
    Assert-Check "[T56-6] 거부된 실행은 행도 zeek_AD 기준선도 바꾸지 않는다" `
        ((Get-Scalar "zeekad_dashboard" $raRowsSql) -eq "$raBaseRows,visitor before setup,analyst before setup" -and (Get-Scalar "zeekad" "SELECT created_at::text FROM sandbox_baseline.marker WHERE id = 1;") -eq $zBaselineBefore) (Get-Scalar "zeekad_dashboard" $raRowsSql)
    $r = Invoke-Sql "postgres" "zeekad_dashboard" $raOperatorDelete -StopOnError
    Assert-Check "[T56-6] 운영자가 체험 계정의 행을 지운다(슈퍼유저, 트랜잭션 안에서만 표식을 켬)" ($r.Code -eq 0 -and (Get-Scalar "zeekad_dashboard" $raRowsSql) -eq "$raBaseRows,analyst before setup") "exit=$($r.Code) $($r.Out) | $(Get-Scalar 'zeekad_dashboard' $raRowsSql)"
    $raMaxNow = Get-Scalar "zeekad_dashboard" $raMaxSql
    $setupNas = Invoke-Setup
    Add-Line "[T56-6] 그 행을 지운 뒤 sandbox-setup: exit=$($setupNas.Code) $(Get-SetupLines $setupNas)"
    Assert-Check "[T56-6] zeek_AD 기준선은 그대로 두고(baseline kept) 대응 조치 표식만 새로 만든다(max_id = 지금의 최대 id $raMaxNow)" `
        ($setupNas.Code -eq 0 -and $setupNas.Out -match 'sandbox-setup: baseline kept' -and $setupNas.Out -match "response action baseline created: max_id=$raMaxNow(\s|`$)" -and $setupNas.Out -match 'RESULT: OK' -and (Get-RaMarker) -eq "max_id=$raMaxNow" -and (Get-Scalar "zeekad" "SELECT created_at::text FROM sandbox_baseline.marker WHERE id = 1;") -eq $zBaselineBefore) "exit=$($setupNas.Code) marker=$(Get-RaMarker)"
    $t5 = Invoke-ResetOnce "" -NoDaysVariable
    Assert-Check "[T56-6] 그 뒤 초기화는 responses[OK] removed=0이고 표식 안의 행(셋)은 남는다" ($t5.Code -eq 0 -and $t5.Out -match ($lineRx + 'OK ' + $base + '; audit\[OFF\]$') -and (Get-Scalar "zeekad_dashboard" $raRowsSql) -eq "$raBaseRows,analyst before setup") "$($t5.Out) | $(Get-Scalar 'zeekad_dashboard' $raRowsSql)"
    # 표식 표는 있는데 행이 없을 때도 표식이 없는 것이다(함수는 오류, 설정 도구는 만든다).
    $r = Invoke-Sql "postgres" "zeekad_dashboard" "DROP TABLE sandbox.response_action_baseline; CREATE TABLE sandbox.response_action_baseline (id integer PRIMARY KEY CHECK (id = 1), max_id bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT now()); ALTER TABLE sandbox.response_action_baseline OWNER TO dashboard_app; REVOKE ALL ON TABLE sandbox.response_action_baseline FROM PUBLIC;" -StopOnError
    $t6 = Invoke-ResetOnce "" -NoDaysVariable
    Add-Line "[T56-6] 표식 표는 있고 행이 없을 때: exit=$($t6.Code) $($t6.Out)"
    Assert-Check "[T56-6] 표식 행이 없으면 함수가 예외를 낸다(responses[ERROR], 전체 ERROR, 행은 그대로)" `
        ($t6.Code -eq 1 -and $t6.Out -match ($lineRx + 'ERROR ' + $head + '; responses\[ERROR\] ERROR: +sandbox response action baseline is missing; run sandbox-setup.*; audit\[OFF\]$') -and (Get-Scalar "zeekad_dashboard" $raRowsSql) -eq "$raBaseRows,analyst before setup") $t6.Out
    $setupEmpty = Invoke-Setup
    Assert-Check "[T56-6] 그 상태의 설정 도구는 표식을 만든다" ($setupEmpty.Code -eq 0 -and $setupEmpty.Out -match "response action baseline created: max_id=$raMaxNow" -and (Get-RaMarker) -eq "max_id=$raMaxNow") "exit=$($setupEmpty.Code) $(Get-RaMarker)"

    # --- 7. 옛 설정 + 새 스크립트: 초기화 함수가 아직 없거나 실행 권한이 없다(sandbox-setup을 다시 돌리기 전) ---
    $r = Invoke-Sql "postgres" "zeekad_dashboard" "DROP FUNCTION sandbox.reset_response_actions();" -StopOnError
    if ($r.Code -ne 0) { throw "초기화 함수 없애기(옛 설정 흉내) 실패`n$($r.Out)" }
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" ($raInsert -f "block_ip", "visitor in the gap", "trial-analyst") -StopOnError
    $t7 = Invoke-ResetOnce "" -NoDaysVariable
    Add-Line "[T56-7] 초기화 함수가 없을 때(옛 설정 + 새 스크립트): exit=$($t7.Code) $($t7.Out)"
    Assert-Check "[T56-7] 함수가 없으면 responses[NOT_CONFIGURED]이고 전체는 OK(ERROR 아님), 종료 코드 0, 지운 행 없음" `
        ($t7.Code -eq 0 -and $t7.Out -match ($lineRx + 'OK ' + $head + "; responses\[NOT_CONFIGURED\] $raFnRx is missing \(run sandbox-setup\); audit\[OFF\]`$") -and (Get-Scalar "zeekad_dashboard" $raRowsSql) -eq "$raBaseRows,analyst before setup,visitor in the gap") $t7.Out
    $setupGap = Invoke-Setup
    Add-Line "[T56-7] 그 틈에 방문자 기록이 생긴 뒤의 sandbox-setup(표식은 이미 있음): exit=$($setupGap.Code) $(@($setupGap.Out -split "`r?`n" | Where-Object { $_ -match 'response' }) -join ' / ')"
    Assert-Check "[T56-7] 표식이 이미 있으면 설정 도구는 함수와 권한만 다시 만든다(표식 그대로)" ($setupGap.Code -eq 0 -and $setupGap.Out -match "response action baseline kept: max_id=$raMaxNow " -and $setupGap.Out -match 'RESULT: OK') "exit=$($setupGap.Code)"
    $t8 = Invoke-ResetOnce "" -NoDaysVariable
    Assert-Check "[T56-7] 그 뒤 초기화가 틈에 생긴 방문자 기록을 지운다(responses[OK] removed=1)" ($t8.Code -eq 0 -and $t8.Out -match ($lineRx + 'OK ' + $head + '; responses\[OK\] removed=1; audit\[OFF\]$') -and (Get-Scalar "zeekad_dashboard" $raRowsSql) -eq "$raBaseRows,analyst before setup") $t8.Out
    $r = Invoke-Sql "postgres" "zeekad_dashboard" "REVOKE EXECUTE ON FUNCTION sandbox.reset_response_actions() FROM zeekad_sandbox_reset;" -StopOnError
    $t9 = Invoke-ResetOnce "" -NoDaysVariable
    Add-Line "[T56-7] 실행 권한이 없을 때: exit=$($t9.Code) $($t9.Out)"
    Assert-Check "[T56-7] 실행 권한이 없으면 responses[NOT_CONFIGURED]이고 전체는 OK, 종료 코드 0" `
        ($t9.Code -eq 0 -and $t9.Out -match ($lineRx + 'OK ' + $head + "; responses\[NOT_CONFIGURED\] no EXECUTE on $raFnRx \(run sandbox-setup\); audit\[OFF\]`$")) $t9.Out
    $r = Invoke-Sql "zeekad_sandbox_reset" "zeekad_dashboard" "SELECT removed FROM sandbox.reset_response_actions();"
    Assert-Check "[T56-7] 그때 초기화 계정이 함수를 직접 불러도 거부된다" ($r.Out -match 'ERROR:\s+permission denied for function reset_response_actions') $r.Out
    $setupRegrant = Invoke-Setup
    Assert-Check "[T56-7] 설정 도구를 다시 돌리면 실행 권한이 붙는다" ($setupRegrant.Code -eq 0 -and (Get-Scalar "zeekad_dashboard" "SELECT has_function_privilege('zeekad_sandbox_reset', 'sandbox.reset_response_actions()', 'EXECUTE')::text;") -eq "true") "exit=$($setupRegrant.Code)"

    # --- 8. --rebuild-baseline: 표식을 다시 잡는다. 체험 계정의 행이 있으면 아무것도 바꾸지 않고 멈춘다 ---
    $r = Invoke-Sql "dashboard_app" "zeekad_dashboard" ((($raInsert -f "monitor", "analyst new baseline", "analyst-b"), ($raInsert -f "block_ip", "visitor at rebuild", "trial-analyst")) -join "`n") -StopOnError
    $rebuildRefused = Invoke-Setup "--rebuild-baseline"
    Add-Line "[T56-8] 체험 계정의 행이 있을 때 sandbox-setup --rebuild-baseline: exit=$($rebuildRefused.Code) $(Get-SetupLines $rebuildRefused)"
    Assert-Check "[T56-8] 다시 잡을 때도 체험 계정의 행이 있으면 멈추고 zeek_AD 기준선과 표식을 바꾸지 않는다" `
        ($rebuildRefused.Code -eq 1 -and $rebuildRefused.Out -match "REFUSED: 1 response action rows recorded by 'trial-analyst' exist" -and $rebuildRefused.Out -notmatch 'baseline rebuilt' -and (Get-RaMarker) -eq "max_id=$raMaxNow" -and (Get-Scalar "zeekad" "SELECT created_at::text FROM sandbox_baseline.marker WHERE id = 1;") -eq $zBaselineBefore) "exit=$($rebuildRefused.Code) marker=$(Get-RaMarker)"
    $r = Invoke-Sql "postgres" "zeekad_dashboard" $raOperatorDelete -StopOnError
    $raMaxRebuild = Get-Scalar "zeekad_dashboard" $raMaxSql
    $rebuildOk = Invoke-Setup "--rebuild-baseline"
    Add-Line "[T56-8] 그 행을 지운 뒤 sandbox-setup --rebuild-baseline: exit=$($rebuildOk.Code) $(@($rebuildOk.Out -split "`r?`n" | Where-Object { $_ -match 'baseline' }) -join ' / ')"
    Assert-Check "[T56-8] --rebuild-baseline이면 zeek_AD 기준선과 함께 표식을 다시 잡는다(max_id $raMaxNow → $raMaxRebuild)" `
        ($rebuildOk.Code -eq 0 -and $raMaxRebuild -ne $raMaxNow -and $rebuildOk.Out -match 'sandbox-setup: baseline rebuilt' -and $rebuildOk.Out -match "response action baseline rebuilt: max_id=$raMaxRebuild" -and $rebuildOk.Out -match 'RESULT: OK' -and (Get-RaMarker) -eq "max_id=$raMaxRebuild") "exit=$($rebuildOk.Code) marker=$(Get-RaMarker)"
    $t10 = Invoke-ResetOnce "" -NoDaysVariable
    Assert-Check "[T56-8] 다시 잡은 뒤 초기화는 responses[OK] removed=0이고 새 기준선 안의 행(넷)이 남는다" ($t10.Code -eq 0 -and $t10.Out -match ($lineRx + 'OK ' + $base + '; audit\[OFF\]$') -and (Get-Scalar "zeekad_dashboard" $raRowsSql) -eq "$raBaseRows,analyst before setup,analyst new baseline") "$($t10.Out) | $(Get-Scalar 'zeekad_dashboard' $raRowsSql)"
    $totalFailed += Save-Lines "response-actions.txt"

    # ================= 하루 한 번 판정(컨테이너의 bash) =================
    $daily = Invoke-Docker @("exec", "--user", "postgres", $ContainerName, "sh", "-c", "bash --version | head -n 1; bash /t58/sandbox-reset-daily-test.sh /t58/sandbox-reset.sh 2>&1") -IgnoreExitCode
    $dailyText = "# T58·T56 sandbox-reset.sh의 하루 한 번 판정과 한 줄 로그 시험(scripts/sandbox-reset-daily-test.sh). DB 없이 돈다(psql은 함수로 흉내).`n# 실행 시각(UTC) $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')), 실행한 곳: 일회용 컨테이너 $ContainerName($Image)의 bash, exit=$($daily.Code)`n$($daily.Out)`n"
    [IO.File]::WriteAllText((Join-Path $OutFullDir "once-a-day.txt"), $dailyText, $utf8NoBom)
    Write-Host $daily.Out
    if ($daily.Code -ne 0 -or $daily.Out -notmatch 'RESULT: PASS' -or $daily.Out -match '(?m)^FAIL ') { $totalFailed++ }
} finally {
    $env:POSTGRES_PASSWORD = $null
    $env:SANDBOX_RESET_DB_PASSWORD_T58 = $null
    if ($started) { [void](Invoke-Docker @("rm", "-f", $ContainerName) -IgnoreExitCode) }
}

$gone = (Invoke-Docker @("ps", "-aq", "--filter", "name=^/$ContainerName`$") -IgnoreExitCode).Out
if ($gone) { Write-Host "경고: 컨테이너 $ContainerName 가 남아 있습니다."; $totalFailed++ }
Write-Host "결과 파일: $OutFullDir (pg-check.txt, reset-once.txt, response-actions.txt, once-a-day.txt)"
if ($totalFailed -gt 0) {
    Write-Host "RESULT: FAIL ($totalFailed)"
    exit 1
}
Write-Host "RESULT: PASS"
exit 0
