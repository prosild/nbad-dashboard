package com.zeekad.dashboard.config;

import com.zeekad.dashboard.security.TrustedProxies;
import org.apache.catalina.Valve;
import org.apache.catalina.valves.RemoteIpValve;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatWebServer;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.context.ServletWebServerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * T32 전달 헤더 신뢰. {@code server.forward-headers-strategy: native}에서 Spring Boot가 붙이는 RemoteIpValve 하나를
 * 그대로 고쳐 쓴다(새 valve를 더 붙이면 Boot 기본 valve가 먼저 돌아 사설망 전체를 믿는다).
 * <ul>
 *   <li>internalProxies: 신뢰 목록의 주소마다 정확 일치(Pattern.quote). 목록이 비면 아무것도 맞지 않는 패턴.</li>
 *   <li>trustedProxies: 쓰지 않는다(null). 연결 주소가 신뢰 목록에 없으면 X-Forwarded-*를 모두 무시한다.</li>
 * </ul>
 * Boot 커스터마이저(order 0) 뒤에 돌도록 가장 낮은 우선순위로 둔다.
 * 서버를 띄우지 않는 문맥(MockMvc 시험)에서도 팩토리는 만들어지고 valve가 없을 수 있으므로, 개수 확인은 실제 Tomcat이
 * 시작된 뒤 엔진 valve 목록으로 한다: RemoteIpValve가 정확히 하나이고 패턴이 신뢰 목록과 같지 않으면 시작을 막는다.
 */
@Component
public class TrustedProxyValveCustomizer implements WebServerFactoryCustomizer<TomcatServletWebServerFactory>, Ordered {

    private final TrustedProxies trustedProxies;

    public TrustedProxyValveCustomizer(TrustedProxies trustedProxies) {
        this.trustedProxies = trustedProxies;
    }

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        List<RemoteIpValve> valves = remoteIpValves(factory.getEngineValves());
        if (valves.size() > 1) {
            throw new IllegalStateException("RemoteIpValve가 " + valves.size() + "개입니다. 하나만 있어야 합니다.");
        }
        for (RemoteIpValve valve : valves) {
            valve.setInternalProxies(trustedProxies.internalProxiesPattern());
            valve.setTrustedProxies(null);
        }
    }

    /** 실제로 시작된 Tomcat 엔진에서 valve 하나·정확 패턴을 확인한다. 아니면 예외로 시작을 막는다. */
    @EventListener
    public void verifyRunningServer(ServletWebServerInitializedEvent event) {
        if (!(event.getWebServer() instanceof TomcatWebServer tomcat)) {
            return;
        }
        List<RemoteIpValve> valves = remoteIpValves(
                Arrays.asList(tomcat.getTomcat().getEngine().getPipeline().getValves()));
        if (valves.size() != 1) {
            throw new IllegalStateException("Tomcat 엔진의 RemoteIpValve가 정확히 하나여야 합니다(지금 " + valves.size()
                    + "개). server.forward-headers-strategy가 native인지 확인하세요.");
        }
        RemoteIpValve valve = valves.get(0);
        if (!Objects.equals(valve.getInternalProxies(), trustedProxies.internalProxiesPattern())
                || valve.getTrustedProxies() != null) {
            throw new IllegalStateException("RemoteIpValve의 신뢰 프록시 설정이 dashboard.security.trusted-proxies와 다릅니다.");
        }
    }

    private static List<RemoteIpValve> remoteIpValves(Collection<Valve> valves) {
        return valves.stream().filter(RemoteIpValve.class::isInstance).map(RemoteIpValve.class::cast).toList();
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
