package com.zeekad.dashboard.service;

import com.zeekad.dashboard.mapper.app.IncidentRefMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.IncidentRef;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 인시던트 번호(T27). 인시던트마다 바뀌지 않는 번호를 대시보드 DB incident_refs에 추가만 한다.
 *
 * <ul>
 *   <li>번호 범위: 모든 캡처에 걸친 하나의 순서. 보는 사람·권한과 상관없이 매긴다(숨긴 캡처도 번호를 받는다).</li>
 *   <li>매기는 순서: 한 묶음 안에서 탐지 시각 오름차순(NULL은 마지막) → capture_id → incident_id(문자열 코드 순서).
 *       Java에서 정렬하고 한 행씩 그 순서로 넣는다(INSERT … SELECT … ORDER BY는 번호 순서를 보장하지 않는다).</li>
 *   <li>매기는 때: 앱 시작 직후 전체 동기화, 그리고 읽기 중 번호 없는 행을 만났을 때({@link #numbersFor}).
 *       예약 작업은 없다.</li>
 *   <li>실패: 전체 동기화가 실패하면 30초 동안 다시 시도하지 않는다. 읽기 API는 실패하지 않고 그 행의 번호만 null이다.</li>
 *   <li>동시성: 한 JVM 안에서는 동기화(전체·행만)가 한 번에 하나만 돈다. 같은 incident_id 충돌은 ON CONFLICT DO NOTHING.</li>
 *   <li>한 묶음은 한 행씩 정한 순서로 넣되 트랜잭션 하나로 커밋한다(NAS처럼 커밋마다 WAL fsync가 느린 곳에서 행마다 커밋하면
 *       2,192행에 약 12분 걸렸다, T27 NAS 1회차). 읽기는 돌고 있는 동기화를 최대 {@link #READ_WAIT}만 기다리고,
 *       넘으면 그 행의 번호를 null로 두고 응답한다(읽기 API가 동기화 때문에 느려지거나 실패하지 않게).</li>
 * </ul>
 * zeekad DB에는 쓰지 않는다(zeekad 값을 읽어 대시보드 DB에만 쓴다).
 */
@Service
public class IncidentRefService {

    private static final Logger log = LoggerFactory.getLogger(IncidentRefService.class);

    /** 실패한 전체 동기화 뒤 다시 시도하지 않는 시간 */
    public static final Duration FAILURE_BACKOFF = Duration.ofSeconds(30);
    /** 번호 조회 바인드 한 번의 최대 incident_id 수 */
    static final int READ_CHUNK = 1000;
    /** 읽기 중 번호 없는 행을 만났을 때 돌고 있는 동기화를 기다리는 최대 시간 */
    public static final Duration READ_WAIT = Duration.ofSeconds(5);

    /** 매기는 순서: 탐지 시각 오름차순(NULL 마지막) → capture_id → incident_id */
    static final Comparator<IncidentRef> ORDER = Comparator
            .comparing(IncidentRef::getDetectedAt, Comparator.nullsLast(Comparator.comparing(OffsetDateTime::toInstant)))
            .thenComparing(IncidentRef::getCaptureId, Comparator.nullsLast(Comparator.naturalOrder()))
            .thenComparing(IncidentRef::getIncidentId, Comparator.nullsLast(Comparator.naturalOrder()));

    private final IncidentRefMapper refMapper;
    private final ZeekadReadMapper zeekadReadMapper;
    private final Clock clock;
    private final TransactionTemplate tx;

    private final ReentrantLock lock = new ReentrantLock();
    /** 실패한 전체 동기화 뒤 이 시각 전까지는 동기화(전체·행만)를 하지 않는다 */
    private volatile Instant failedUntil;
    /** 끝난 전체 동기화 수(성공·실패 모두). 기다리는 동안 다른 동기화가 끝났는지 보는 데 쓴다 */
    private volatile long completedSyncs;
    /** 마지막으로 성공한 전체 동기화가 읽은 최신 큐의 incident_id */
    private volatile Set<String> lastLatestIds = Set.of();
    /** 마지막 전체 동기화가 성공했는지 */
    private volatile boolean lastSyncSucceeded;

    public IncidentRefService(IncidentRefMapper refMapper, ZeekadReadMapper zeekadReadMapper, Clock clock,
                              @Qualifier("appTransactionManager") PlatformTransactionManager appTransactionManager) {
        this.tx = new TransactionTemplate(appTransactionManager);
        this.refMapper = refMapper;
        this.zeekadReadMapper = zeekadReadMapper;
        this.clock = clock;
    }

    /** 전체 동기화 결과. inserted = 새로 넣은 행 수(충돌로 0행인 것은 빼고), candidates = 최신 큐 인시던트 수 */
    public record SyncResult(boolean succeeded, int candidates, int inserted, long millis) {
    }

    /** 앱 시작 직후 전체 동기화. 실패해도 앱은 뜬다(경고 로그만, 접속 정보는 쓰지 않는다). */
    @EventListener(ApplicationReadyEvent.class)
    public void syncOnStartup() {
        SyncResult r = syncAll();
        if (r.succeeded()) {
            log.info("인시던트 번호 시작 동기화: 최신 큐 {}건, 새 번호 {}건, {}ms", r.candidates(), r.inserted(), r.millis());
        }
    }

    /** 전체 동기화(이미 돌고 있으면 끝나기를 기다린 뒤 한 번 더 돈다). 실패 뒤 30초 제한과 상관없이 돈다. */
    public SyncResult syncAll() {
        lock.lock();
        try {
            return runFullSyncLocked();
        } finally {
            lock.unlock();
        }
    }

    /** 번호 하나로 찾는다(없으면 null). 읽기 실패는 예외 그대로(번호 API가 500 대신 처리하지 않게 호출 쪽이 정한다). */
    public IncidentRef findByNo(long incidentNo) {
        return refMapper.findByNo(incidentNo);
    }

    /**
     * incident_id들의 번호. 번호가 없는 것이 있으면 먼저 전체 동기화를 하고(이미 돌고 있으면 끝나기를 기다림) 다시 읽는다.
     * 그래도 없는 것 가운데 그 전체 동기화가 읽은 최신 큐에 없는 것(옛 작업에만 있는 인시던트)만 행만 넣는다.
     * 최신 큐에 있는데 번호가 없는 것은 이번에는 결과에 없다(다음 전체 동기화가 매긴다).
     * 어떤 실패도 예외로 올리지 않는다. 번호를 못 구한 incident_id는 결과 맵에 없다.
     */
    public Map<String, Long> numbersFor(Collection<String> incidentIds) {
        Set<String> wanted = new LinkedHashSet<>();
        if (incidentIds != null) {
            for (String id : incidentIds) {
                if (id != null && !id.isBlank()) {
                    wanted.add(id);
                }
            }
        }
        Map<String, Long> found = new HashMap<>();
        if (wanted.isEmpty()) {
            return found;
        }
        try {
            found.putAll(readNumbers(wanted));
        } catch (RuntimeException e) {
            log.warn("인시던트 번호 읽기 실패({})", e.getClass().getSimpleName());
            return found;
        }
        Set<String> missing = new LinkedHashSet<>(wanted);
        missing.removeAll(found.keySet());
        if (missing.isEmpty() || inBackoff()) {
            return found;
        }

        long seen = completedSyncs;
        try {
            if (!lock.tryLock(READ_WAIT.toMillis(), TimeUnit.MILLISECONDS)) {
                // 동기화가 오래 돈다: 이번 응답은 번호 없이(null) 보낸다
                return found;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return found;
        }
        try {
            // 기다리는 동안 다른 동기화가 매겼을 수 있다
            Map<String, Long> again = readNumbers(missing);
            found.putAll(again);
            missing.removeAll(again.keySet());
            if (missing.isEmpty() || inBackoff()) {
                return found;
            }
            if (completedSyncs == seen || !lastSyncSucceeded) {
                // 기다리는 동안 끝난(성공한) 전체 동기화가 없다: 이번에 한다
                if (!runFullSyncLocked().succeeded()) {
                    return found;
                }
                again = readNumbers(missing);
                found.putAll(again);
                missing.removeAll(again.keySet());
            }
            // 여기까지 오면 마지막 전체 동기화는 성공이고, 그 동기화가 읽은 최신 큐와 비교한다
            Set<String> latest = lastLatestIds;
            List<String> rowOnly = missing.stream().filter(id -> !latest.contains(id)).toList();
            if (!rowOnly.isEmpty()) {
                insertRowsOnly(rowOnly);
                again = readNumbers(rowOnly);
                found.putAll(again);
            }
            return found;
        } catch (RuntimeException e) {
            log.warn("인시던트 번호 매기기 실패({})", e.getClass().getSimpleName());
            return found;
        } finally {
            lock.unlock();
        }
    }

    /**
     * T40: incident_id들의 번호 행을 읽기만 한다(동기화·대기·쓰기 없음). 행이 없는 incident_id는 결과에 없다.
     * 읽기 실패는 예외로 올리지 않고 빈 맵이다(호출 쪽은 "볼 수 없음"으로 막는다).
     */
    public Map<String, IncidentRef> readRefsOnly(Collection<String> incidentIds) {
        Map<String, IncidentRef> out = new HashMap<>();
        if (incidentIds == null) {
            return out;
        }
        List<String> list = new ArrayList<>(new LinkedHashSet<>(incidentIds));
        list.removeIf(id -> id == null || id.isBlank());
        try {
            for (int i = 0; i < list.size(); i += READ_CHUNK) {
                List<String> part = list.subList(i, Math.min(list.size(), i + READ_CHUNK));
                for (IncidentRef r : refMapper.findByIncidentIds(part.toArray(new String[0]))) {
                    if (r.getIncidentId() != null && r.getIncidentNo() != null) {
                        out.put(r.getIncidentId(), r);
                    }
                }
            }
        } catch (RuntimeException e) {
            log.warn("인시던트 번호 읽기 실패({})", e.getClass().getSimpleName());
            return new HashMap<>();
        }
        return out;
    }

    /** 하나의 번호(없으면 null) */
    public Long numberFor(String incidentId) {
        if (incidentId == null) {
            return null;
        }
        return numbersFor(List.of(incidentId)).get(incidentId);
    }

    /* ───────────────────────── 내부 ───────────────────────── */

    private boolean inBackoff() {
        Instant until = failedUntil;
        return until != null && clock.instant().isBefore(until);
    }

    private SyncResult runFullSyncLocked() {
        long started = System.nanoTime();
        try {
            List<IncidentRef> candidates = zeekadReadMapper.findLatestIncidentRefCandidates();
            Map<String, IncidentRef> byId = new LinkedHashMap<>();
            for (IncidentRef c : candidates) {
                if (c.getIncidentId() != null && c.getCaptureId() != null) {
                    byId.putIfAbsent(c.getIncidentId(), c);
                }
            }
            Set<String> existing = readNumbers(byId.keySet()).keySet();
            List<IncidentRef> missing = new ArrayList<>();
            for (IncidentRef c : byId.values()) {
                if (!existing.contains(c.getIncidentId())) {
                    missing.add(c);
                }
            }
            int inserted = insertInOrder(missing);
            lastLatestIds = Set.copyOf(byId.keySet());
            lastSyncSucceeded = true;
            failedUntil = null;
            return new SyncResult(true, byId.size(), inserted, elapsedMillis(started));
        } catch (RuntimeException e) {
            lastSyncSucceeded = false;
            failedUntil = clock.instant().plus(FAILURE_BACKOFF);
            log.warn("인시던트 번호 전체 동기화 실패({}). {}초 동안 다시 시도하지 않습니다.",
                    e.getClass().getSimpleName(), FAILURE_BACKOFF.toSeconds());
            return new SyncResult(false, 0, 0, elapsedMillis(started));
        } finally {
            completedSyncs++;
        }
    }

    private void insertRowsOnly(List<String> incidentIds) {
        List<IncidentRef> candidates = new ArrayList<>();
        for (int i = 0; i < incidentIds.size(); i += READ_CHUNK) {
            List<String> part = incidentIds.subList(i, Math.min(incidentIds.size(), i + READ_CHUNK));
            candidates.addAll(zeekadReadMapper.findIncidentRefCandidatesByIds(part.toArray(new String[0])));
        }
        insertInOrder(candidates.stream()
                .filter(c -> c.getIncidentId() != null && c.getCaptureId() != null)
                .toList());
    }

    /** 정렬한 뒤 한 행씩 넣는다. 넣은 행 수(충돌로 0행인 것은 빼고) */
    private int insertInOrder(List<IncidentRef> rows) {
        if (rows.isEmpty()) {
            return 0;
        }
        List<IncidentRef> sorted = new ArrayList<>(rows);
        sorted.sort(ORDER);
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        // 한 행씩 이 순서로 넣고(번호 = 순서) 커밋은 한 번만 한다
        Integer inserted = tx.execute(status -> {
            int n = 0;
            for (IncidentRef r : sorted) {
                n += refMapper.insertIfAbsent(r.getIncidentId(), r.getCaptureId(), r.getDetectedAt(), now);
            }
            return n;
        });
        return inserted == null ? 0 : inserted;
    }

    private Map<String, Long> readNumbers(Collection<String> incidentIds) {
        Map<String, Long> out = new HashMap<>();
        List<String> list = new ArrayList<>(new HashSet<>(incidentIds));
        for (int i = 0; i < list.size(); i += READ_CHUNK) {
            List<String> part = list.subList(i, Math.min(list.size(), i + READ_CHUNK));
            for (IncidentRef r : refMapper.findByIncidentIds(part.toArray(new String[0]))) {
                if (r.getIncidentId() != null && r.getIncidentNo() != null) {
                    out.put(r.getIncidentId(), r.getIncidentNo());
                }
            }
        }
        return out;
    }

    private static long elapsedMillis(long startedNanos) {
        return Duration.ofNanos(System.nanoTime() - startedNanos).toMillis();
    }

    /** 시험용: 실패 뒤 제한이 걸려 있는지 */
    boolean isInBackoff() {
        return inBackoff();
    }

    /** 시험용: 마지막 성공 전체 동기화가 읽은 최신 큐 incident_id 수 */
    int lastLatestSize() {
        return Objects.requireNonNullElse(lastLatestIds, Set.<String>of()).size();
    }
}
