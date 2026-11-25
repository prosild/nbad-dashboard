package com.zeekad.dashboard.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** T45 큐 hostIp 조건 형식: 온전한 IPv4와 가려진 IPv4(A.B.*.*)만 */
class HostIpFilterTest {

    @Test
    void acceptsFullAndMaskedIpv4Only() {
        for (String ok : new String[]{"0.0.0.0", "10.45.1.1", "192.168.0.255", "255.255.255.255", "1.2.3.4"}) {
            assertThat(HostIpFilter.kindOf(ok)).as(ok).isEqualTo(HostIpFilter.Kind.EXACT);
        }
        for (String ok : new String[]{"10.45.*.*", "0.0.*.*", "255.255.*.*"}) {
            assertThat(HostIpFilter.kindOf(ok)).as(ok).isEqualTo(HostIpFilter.Kind.MASKED);
        }
    }

    @Test
    void rejectsEverythingElse() {
        for (String bad : new String[]{null, "", " ", "10.45.1", "10.45.1.1.1", "10.45.1.1:80", "10.*.*.*", "10.45.1.*",
                "10.45.*.1", "*.*.*.*", "10..1.1", "10.45.1.", ".10.45.1.1", "01.2.3.4", "1.02.3.4", "1.2.3.04",
                "256.1.1.1", "1.2.3.256", "1.2.3.1000", "::1", "fe80::1", "abc", "10.45.1.1 ", " 10.45.1.1",
                "10.45.1.1\n", "10.45.**.*", "10.45.*.*.*", "１０.45.1.1", "10.45.1.1/24", "10.45.%.%", "10.45._._"}) {
            assertThat(HostIpFilter.kindOf(bad)).as(String.valueOf(bad)).isNull();
        }
    }
}
