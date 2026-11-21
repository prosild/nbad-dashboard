package com.zeekad.dashboard.testsupport;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** 테스트에서 현재 시각을 바꿀 수 있는 Clock(T23 기간 경계·진행 중 시험). */
public class MutableTestClock extends Clock {

    private volatile Instant instant;

    public MutableTestClock(Instant initial) {
        this.instant = initial;
    }

    public void set(Instant next) {
        this.instant = next;
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return instant;
    }
}
