package com.zeekad.dashboard.security;

import com.zeekad.dashboard.config.DashboardProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * T32 전달 헤더를 믿을 프록시 주소 목록(dashboard.security.trusted-proxies).
 * <ul>
 *   <li>IPv4·IPv6 주소 그대로만 받는다. 대역(CIDR)·호스트 이름·정규식·영역 ID(%)는 시작을 막는다.</li>
 *   <li>주소 형식은 문자열만 보고 바이트로 바꾼다. 호스트 이름 해석(DNS)을 하는 API는 쓰지 않는다
 *       ({@link InetAddress#getByAddress(byte[])}는 이미 정한 바이트로 객체만 만든다).</li>
 *   <li>정규형은 Tomcat {@code getRemoteAddr()} 표기와 같다(IPv6 예: {@code 0:0:0:0:0:0:0:1}).</li>
 *   <li>앞뒤 공백은 지우고 빈 항목은 버린다. 결과가 비면 아무도 믿지 않는다.</li>
 * </ul>
 */
@Component
public class TrustedProxies {

    private static final Logger log = LoggerFactory.getLogger(TrustedProxies.class);

    /** 아무 주소와도 맞지 않는 패턴(목록이 비었을 때). */
    static final String MATCH_NOTHING = "(?!)";

    private final List<String> addresses;

    public TrustedProxies(DashboardProperties properties) {
        this.addresses = parse(properties.getSecurity().getTrustedProxies());
        if (addresses.isEmpty()) {
            log.warn("전달 헤더를 믿을 프록시가 없습니다(dashboard.security.trusted-proxies 비어 있음). "
                    + "X-Forwarded-*를 모두 무시하므로 감사 로그 IP는 연결 주소(WAF 주소)가 됩니다.");
        } else {
            log.info("전달 헤더를 믿을 프록시 주소: {}", String.join(", ", addresses));
        }
    }

    /** 정규형 주소 목록(중복 제거, 입력 순서). */
    public List<String> addresses() {
        return addresses;
    }

    /** RemoteIpValve internalProxies에 넣을 정확 일치 패턴. 주소마다 {@link Pattern#quote}. */
    public String internalProxiesPattern() {
        if (addresses.isEmpty()) {
            return MATCH_NOTHING;
        }
        return addresses.stream().map(Pattern::quote).collect(Collectors.joining("|"));
    }

    static List<String> parse(List<String> raw) {
        Set<String> result = new LinkedHashSet<>();
        if (raw == null) {
            return List.of();
        }
        List<String> invalid = new ArrayList<>();
        for (String item : raw) {
            if (item == null) {
                continue;
            }
            // 바인딩이 쉼표를 나누지 않은 경우(단일 문자열)도 같게 다룬다.
            for (String part : item.split(",", -1)) {
                String value = part.trim();
                if (value.isEmpty()) {
                    continue;
                }
                String canonical = canonicalize(value);
                if (canonical == null) {
                    invalid.add(value);
                } else {
                    result.add(canonical);
                }
            }
        }
        if (!invalid.isEmpty()) {
            throw new IllegalStateException("dashboard.security.trusted-proxies에 주소가 아닌 항목이 있습니다: " + invalid
                    + " (IPv4·IPv6 주소 그대로만 씁니다. 대역·호스트 이름·정규식은 받지 않습니다)");
        }
        return List.copyOf(result);
    }

    /** 리터럴 주소를 정규형으로. 주소가 아니면 null. DNS를 쓰지 않는다. */
    public static String canonicalize(String value) {
        byte[] bytes = value.indexOf(':') >= 0 ? parseIpv6(value) : parseIpv4(value);
        if (bytes == null) {
            return null;
        }
        try {
            return InetAddress.getByAddress(bytes).getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /** 점 넷으로 나뉜 0~255 십진수(앞자리 0 금지). */
    static byte[] parseIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3 || !p.chars().allMatch(c -> c >= '0' && c <= '9')
                    || (p.length() > 1 && p.charAt(0) == '0')) {
                return null;
            }
            int n = Integer.parseInt(p);
            if (n > 255) {
                return null;
            }
            out[i] = (byte) n;
        }
        return out;
    }

    /** RFC 4291 텍스트 표기(:: 생략, 끝의 IPv4 표기 포함). 영역 ID·대괄호·접두 길이는 받지 않는다. */
    static byte[] parseIpv6(String value) {
        if (!value.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
                || c == ':' || c == '.')) {
            return null;
        }
        int dbl = value.indexOf("::");
        if (dbl >= 0 && value.indexOf("::", dbl + 1) >= 0) {
            return null;
        }
        String head = dbl >= 0 ? value.substring(0, dbl) : value;
        String tail = dbl >= 0 ? value.substring(dbl + 2) : "";
        // IPv4 표기는 맨 끝 조각에만 올 수 있다(:: 앞부분에는 없다).
        List<Integer> headGroups = groups(head, dbl < 0);
        List<Integer> tailGroups = dbl >= 0 ? groups(tail, true) : List.of();
        if (headGroups == null || tailGroups == null) {
            return null;
        }
        int total = headGroups.size() + tailGroups.size();
        if (dbl < 0 ? total != 8 : total > 7) {
            return null;
        }
        byte[] out = new byte[16];
        int idx = 0;
        for (int g : headGroups) {
            out[idx++] = (byte) (g >> 8);
            out[idx++] = (byte) g;
        }
        idx = 16 - tailGroups.size() * 2;
        for (int g : tailGroups) {
            out[idx++] = (byte) (g >> 8);
            out[idx++] = (byte) g;
        }
        return out;
    }

    /** 콜론으로 나뉜 16비트 그룹. allowIpv4Last면 마지막 조각이 IPv4 표기일 수 있다(두 그룹). */
    private static List<Integer> groups(String text, boolean allowIpv4Last) {
        List<Integer> out = new ArrayList<>();
        if (text.isEmpty()) {
            return out;
        }
        String[] parts = text.split(":", -1);
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i];
            if (p.contains(".")) {
                if (!allowIpv4Last || i != parts.length - 1) {
                    return null;
                }
                byte[] v4 = parseIpv4(p);
                if (v4 == null) {
                    return null;
                }
                out.add(((v4[0] & 0xff) << 8) | (v4[1] & 0xff));
                out.add(((v4[2] & 0xff) << 8) | (v4[3] & 0xff));
                continue;
            }
            if (p.isEmpty() || p.length() > 4) {
                return null;
            }
            out.add(Integer.parseInt(p, 16));
        }
        return out;
    }
}
