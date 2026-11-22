package com.zeekad.dashboard.model.zeekad;

/**
 * T35 이전·다음 창 질의 한 행: 통합 큐 행 + 같은 조건·정렬에서의 순번(1부터)과 조건에 맞는 전체 수.
 */
public class UnifiedQueueNeighborRecord extends UnifiedQueueRecord {

    private Long queuePos;
    private Long queueTotal;

    public Long getQueuePos() {
        return queuePos;
    }

    public void setQueuePos(Long queuePos) {
        this.queuePos = queuePos;
    }

    public Long getQueueTotal() {
        return queueTotal;
    }

    public void setQueueTotal(Long queueTotal) {
        this.queueTotal = queueTotal;
    }
}
