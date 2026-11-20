# 화면 용어 변경 기록

zeek_AD와 공유하는 화면 표기 변경 기록이다(`SPEC.md` '결정' 2026-11-20 화면 개편 순서). 표시 문구를 바꾸는 작업은 이 표에 한 줄씩 더한다.

| 날짜 | 작업 | 화면 | 이전 표기 | 새 표기 | 출처(프론트엔드/API/zeek_AD 값) | 이유 | zeek_AD 공유 필요 |
|---|---|---|---|---|---|---|---|
| 2026-11-21 | T16 | 사건 상세 · 근거 요약 | 송신 바이트 (orig_bytes) | 자산 송신 바이트 | 프론트엔드 라벨(값: zeek_AD `evidence.network.bytes.sent`) | `bytes.sent`는 연결 방향(orig)이 아니라 사건 대상 자산 기준 IP 바이트다(responder면 `resp_ip_bytes`). 내부 이름을 뺐다 | 아니요(zeek_AD 키 의미를 그대로 따름) |
| 2026-11-21 | T16 | 사건 상세 · 근거 요약 | 수신 바이트 (resp_bytes) | 자산 수신 바이트 | 프론트엔드 라벨(값: zeek_AD `evidence.network.bytes.received`) | 위와 같음 | 아니요 |
| 2026-11-21 | T16 | 사건 상세 · 근거 요약 | 전송 계층 / 프로토콜 분포 | 전송 계층 분포 | 프론트엔드 라벨(값: `evidence.network.transport`) | 서비스 프로토콜 분포를 별도 칸으로 나눠 이 칸은 tcp/udp만 보여 준다 | 아니요 |
| 2026-11-21 | T16 | 사건 상세 · 근거 요약 | (없음) | 서비스 프로토콜 분포 | 프론트엔드 라벨(값: `evidence.network.protocol`) | 새 정형 칸 | 아니요 |
| 2026-11-21 | T16 | 사건 상세 · 근거 요약 | (없음) | 고유 상대 IP 수 / 고유 목적지 포트 수 | 프론트엔드 라벨(값: `evidence.peers.unique`, `evidence.destination_ports.unique`) | 새 정형 칸 | 아니요 |
| 2026-11-21 | T16 | 사건 상세 · 근거 요약 | (없음) | 페이로드 바이트가 부푼 연결 수 | 프론트엔드 라벨(값: `evidence.network.zeekad_payload_bytes_inflated`) | 새 정형 칸. zeek_AD `limits` 문장의 설명과 같은 뜻 | 아니요 |
| 2026-11-21 | T16 | 사건 상세 · 근거 요약 | `-`(키 없음), 프로토콜 로그는 0 또는 `[object Object]` | 값 없음 | 프론트엔드 | 키가 없는 값(null)과 관측한 0을 구분한다 | 아니요 |
| 2026-11-21 | T16 | 사건 상세 · 근거 요약 | 근거 API 연결 불가(DB 뷰 정보만 표시) — 근거 행이 없을 때도 같은 문구 | 이 사건의 근거 요약 없음(근거 API는 정상, 근거 행 없음) | API(`EvidenceData.NO_EVIDENCE_MESSAGE`) | API 연결 실패와 근거 행 없음(`"evidence": null`)을 구분한다. 연결 실패 문구는 그대로 | 아니요 |
