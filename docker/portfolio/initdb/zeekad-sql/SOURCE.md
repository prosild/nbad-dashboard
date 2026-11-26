# zeek_AD SQL 사본의 출처

이 폴더의 `.sql`은 탐지 파이프라인 저장소 [`prosild/network-behavior-anomaly-detection`](https://github.com/prosild/network-behavior-anomaly-detection)(NBAD, 처음 이름 zeek_AD)의 migration 파일을 바이트 그대로 옮긴 사본이다. 머리말이나 주석을 덧붙이지 않았다. 고칠 일이 생기면 zeek_AD에서 고친 파일을 다시 옮기고 아래 값을 바꾼다.

| 사본 | 원본 경로 | zeek_AD commit | sha256(LF 바이트) |
|---|---|---|---|
| `018_incident_reopen.sql` | `db/migrations/018_incident_reopen.sql` | `aa91e3dc5a1ffa6b0eee26e071167fb05732f8af` (2026-11-26) | `d599ddc9700476abb4c18236cc04ddffd18ef81c8f232f7cdacfb077619564dd` |

- 내용: 종결한 사건을 다시 여는 함수 `dashboard.reopen_incident`(zeek_AD DD-022). 계약은 zeek_AD `docs/data-contract-v2.md`의 "쓰기: 종결한 사건 다시 열기"에 있다.
- 쓰는 곳: `../03-zeekad-functions.sh`가 볼륨을 처음 만들 때(스냅샷 복원 뒤) `zeekad` DB에 한 번 실행한다. 스냅샷에 그 이름의 함수가 이미 있으면 건너뛴다. 이미 볼륨이 있는 스택에 넣는 순서는 `docs/portfolio-deployment.md` 3.8의 `T53` 절에 있다.
- 2026-11-23 스냅샷에는 이 함수가 없었다. 2026-11-26 스냅샷(`T66`, 배포 VM에서 다시 뜸)에는 zeek_AD가 적용한 함수가 있어(소유 `zeekad_owner`, 실행 권한 `dashboard_rw`) `03`은 건너뛴다. 사본과 `03`을 지우는 것은 다음 작업에서 정한다.
- 하위 폴더에 두는 까닭: `postgres` 공식 이미지는 `/docker-entrypoint-initdb.d` 맨 위의 `*.sql`을 `POSTGRES_DB`(`postgres` DB)에 자동으로 실행한다. 하위 폴더는 보지 않는다.
- 줄바꿈: `.gitattributes`가 이 폴더의 `*.sql`을 LF로 고정한다. 위 sha256은 LF 바이트 값이다. 정적 시험(`T53ReopenStaticTest`)이 아래 sha256 줄의 값을 사본과 대조한다.

018_incident_reopen.sql zeek_AD commit: `aa91e3dc5a1ffa6b0eee26e071167fb05732f8af`
018_incident_reopen.sql sha256: `d599ddc9700476abb4c18236cc04ddffd18ef81c8f232f7cdacfb077619564dd`
