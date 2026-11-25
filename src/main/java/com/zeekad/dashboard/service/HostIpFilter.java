package com.zeekad.dashboard.service;

import java.util.regex.Pattern;

/**
 * T45 큐 hostIp 조건 값의 형식. 온전한 IPv4(A.B.C.D)와 조회자에게 보이는 가려진 IPv4(A.B.*.*)만 받는다.
 * 옥텟은 0~255이고 앞에 0을 붙인 꼴(01)은 받지 않는다. IPv6·포트·A.*.*.*·A.B.C.*·빈 옥텟은 형식 오류다.
 * 화면(frontend/src/utils/ipScope.ts의 hostIpKind)이 같은 규칙을 쓴다.
 */
public final class HostIpFilter {

    public enum Kind { EXACT, MASKED }

    private static final String OCTET = "(?:0|[1-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-5])";
    private static final Pattern EXACT = Pattern.compile("^" + OCTET + "(?:\\." + OCTET + "){3}$");
    private static final Pattern MASKED = Pattern.compile("^" + OCTET + "\\." + OCTET + "\\.\\*\\.\\*$");

    private HostIpFilter() {
    }

    /** trim() 뒤의 값을 본다. 어느 형식도 아니면 null */
    public static Kind kindOf(String value) {
        if (value == null) {
            return null;
        }
        if (EXACT.matcher(value).matches()) {
            return Kind.EXACT;
        }
        return MASKED.matcher(value).matches() ? Kind.MASKED : null;
    }
}
