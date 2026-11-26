-- T52 중요 자산: 관리자가 등록한 주소(IPv4 하나)가 호스트인 미종결 인시던트는 자동 분류 우선순위를 한 단계 올린다
-- (Low → Medium, Medium → High). 대시보드 사용자가 정하는 운영 값이라 대시보드 자체 DB에 둔다(zeekad DB는 바꾸지 않는다).
-- - 주소는 앱이 IPv4 한 주소의 정확한 꼴만 받는다(대역·범위·IPv6·호스트 이름은 받지 않는다). 같은 주소는 한 행이다.
-- - 이름(100자)과 설명(300자) 상한은 PostgreSQL VARCHAR가 코드 포인트로 센다. 앱도 같은 상한을 먼저 본다.
-- - 지우면 행이 사라지고 변경은 감사 로그(CRITICAL_ASSET_CHANGE)에 남는다.

CREATE TABLE critical_assets (
    id BIGSERIAL PRIMARY KEY,
    host_ip VARCHAR(15) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(300),
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_by VARCHAR(100) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);
