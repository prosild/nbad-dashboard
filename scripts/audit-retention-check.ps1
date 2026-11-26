param(
    # 결과 파일(pg-check.txt, reset-once.txt, once-a-day.txt)을 쓸 폴더
    [string]$OutDir = "build/audit-retention-check",
    # 공개 스택과 같은 PostgreSQL 이미지. 로컬에 없으면 받지 않고 멈춘다.
    [string]$Image = "pgvector/pgvector:0.8.1-pg17",
    [string]$ContainerName = "zeekad-t58-pg"
)

# 감사 로그 보관 기한(T58)의 SQL을 PostgreSQL에서 직접 시험한다(Java 시험은 H2라 이 로직을 못 본다).
# - 일회용 PostgreSQL 컨테이너 하나(-ContainerName)를 네트워크 없이, 데이터 경로는 tmpfs로 띄운다(볼륨을 만들지 않는다).
#   docker exec로만 쓰고 끝나면 그 이름의 컨테이너만 지운다. 다른 컨테이너·compose 프로젝트·네트워크·볼륨은 건드리지 않는다.
# - 실제와 같게 적용한다: 슈퍼유저가 아닌 역할 dashboard_app이 소유한 DB에 저장소의 V1~V4 파일을 그대로,
#   파일마다 한 트랜잭션(psql -1 -v ON_ERROR_STOP=1)으로 그 역할로 적용한다.
# - 이어서 저장소의 docker/portfolio/sandbox/sandbox-setup.sh와 sandbox-reset.sh --once를 그대로 같은 컨테이너에서 돌린다
#   (zeek_AD 표 다섯은 열만 맞춘 빈 표로 둔다. 초기화 함수 둘·기준선·전용 역할·권한은 설정 도구가 실제로 만든다).
#   설정 도구가 V4 전에는 멈추는지, 삭제 함수의 EXECUTE만 주는지, 한 줄 로그의 감사 칸이 상태마다 어떻게 나오는지 본다.
#   scripts/sandbox-reset-daily-test.sh(하루 한 번 판정)는 컨테이너의 bash로 돌린다.
# - 컨테이너 안 접속은 유닉스 소켓(이미지 기본 trust)이다. 슈퍼유저 비밀번호는 무작위로 만들어 환경 변수로만 넘기고 출력·기록하지 않는다.
# - 결과: <OutDir>/pg-check.txt, reset-once.txt, once-a-day.txt(줄마다 PASS 또는 FAIL). FAIL이 있으면 종료 코드 1.

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([IO.Path]::IsPathRooted($OutDir)) { $OutFullDir = $OutDir } else { $OutFullDir = Join-Path $RepoRoot $OutDir }
[void](New-Item -ItemType Directory -Force -Path $OutFullDir)

$MigrationDir = Join-Path $RepoRoot "src/main/resources/db/migration/postgresql"
$Migrations = @("V1__init_dashboard_auth_audit.sql", "V2__incident_assignments.sql", "V3__incident_refs.sql", "V4__audit_retention.sql")
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
    function Invoke-Setup {
        return Invoke-Docker @("exec", "--user", "postgres", "-e", "PGUSER=postgres", "-e", "PGPASSWORD=$($env:SANDBOX_RESET_DB_PASSWORD_T58)",
            "-e", "SANDBOX_RESET_DB_PASSWORD=$($env:SANDBOX_RESET_DB_PASSWORD_T58)", "-e", "SANDBOX_TRIAL_USERNAME=trial-analyst",
            $ContainerName, "sh", "-c", "bash /t58/sandbox-setup.sh 2>&1") -IgnoreExitCode
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
    Add-Line "# 실행 시각(UTC) $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')), 이미지 $Image. zeek_AD 표 다섯은 열만 맞춘 빈 표다. 초기화 함수 둘·기준선·역할·권한은 설정 도구가 만든 실제 것이다."
    $lineRx = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z sandbox-reset: '
    $base = 'pipeline\[OK\] analyst_review\(-0 \+0 ~0\) incident_status\(-0 \+0 ~0\) incident_status_history\(-0 \+0 ~0\); assignments\[OK\] released=0 history\+=0'
    $purgeFnRx = 'public\.purge_expired_audit_logs\(integer\)'
    $resetPrivSql = "SELECT 'table_grants=' || (SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'zeekad_sandbox_reset') || ' purge_execute=' || COALESCE(has_function_privilege('zeekad_sandbox_reset', to_regprocedure('public.purge_expired_audit_logs(integer)')::oid, 'EXECUTE')::text, '(no function)') || ' reset_assignments_execute=' || has_function_privilege('zeekad_sandbox_reset', 'sandbox.reset_assignments()', 'EXECUTE') || ' public_create=' || has_schema_privilege('zeekad_sandbox_reset', 'public', 'CREATE');"

    Add-Line "[S1] V4 적용 전의 sandbox-setup: exit=$($setupBeforeV4.Code) $(Get-SetupLines $setupBeforeV4) | 뒤 상태: $afterRefusedSetup"
    Assert-Check "[S1] 삭제 함수가 없으면(앱이 V4를 적용하기 전) 설정 도구는 건너뛰지 않고 멈춘다. 역할·스키마를 만들지 않는다" `
        ($setupBeforeV4.Code -eq 1 -and $setupBeforeV4.Out -match ("function $purgeFnRx is missing in zeekad_dashboard; start dashboard-app with migration V4") -and $setupBeforeV4.Out -notmatch 'RESULT: OK' -and $afterRefusedSetup -eq "role=0 zeekad_schemas=0 app_schemas=0") "exit=$($setupBeforeV4.Code) $(Get-SetupLines $setupBeforeV4) | $afterRefusedSetup"
    Add-Line "[S2] 설정 전(초기화 계정 없음)의 sandbox-reset --once, 기한 90: exit=$($resetBeforeSetup.Code) $($resetBeforeSetup.Out)"
    Assert-Check "[S2] 설정 전에는 세 칸 모두 미설정이고 ERROR 줄이 아니다(종료 코드 0)" `
        ($resetBeforeSetup.Code -eq 0 -and $resetBeforeSetup.Out -match ($lineRx + 'NOT_CONFIGURED_OR_LOGIN_FAILED pipeline\[NOT_CONFIGURED_OR_LOGIN_FAILED\] .*; assignments\[NOT_CONFIGURED_OR_LOGIN_FAILED\] .*; audit\[NOT_CONFIGURED\] ') -and $resetBeforeSetup.Out -notmatch ' ERROR ') $resetBeforeSetup.Out

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

    # ================= 하루 한 번 판정(컨테이너의 bash) =================
    $daily = Invoke-Docker @("exec", "--user", "postgres", $ContainerName, "sh", "-c", "bash --version | head -n 1; bash /t58/sandbox-reset-daily-test.sh /t58/sandbox-reset.sh 2>&1") -IgnoreExitCode
    $dailyText = "# T58 sandbox-reset.sh의 하루 한 번 판정과 한 줄 로그 시험(scripts/sandbox-reset-daily-test.sh). DB 없이 돈다(psql은 함수로 흉내).`n# 실행 시각(UTC) $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')), 실행한 곳: 일회용 컨테이너 $ContainerName($Image)의 bash, exit=$($daily.Code)`n$($daily.Out)`n"
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
Write-Host "결과 파일: $OutFullDir (pg-check.txt, reset-once.txt, once-a-day.txt)"
if ($totalFailed -gt 0) {
    Write-Host "RESULT: FAIL ($totalFailed)"
    exit 1
}
Write-Host "RESULT: PASS"
exit 0
