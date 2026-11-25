package com.zeekad.dashboard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** T45 ATT&amp;CK 조건 값 정규화(기법 ID 먼저, 그다음 전술 슬러그)와 리포트 후보 맞추기 */
class AttackFilterTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void techniqueIdIsRecognizedFirstAndUppercased() {
        assertThat(AttackFilter.parse("t1059")).isEqualTo(new AttackFilter.Value(AttackFilter.Kind.TECHNIQUE, "T1059"));
        assertThat(AttackFilter.parse(" T1059.001 "))
                .isEqualTo(new AttackFilter.Value(AttackFilter.Kind.TECHNIQUE, "T1059.001"));
        assertThat(AttackFilter.parse("t1059.001").value()).isEqualTo("T1059.001");
        // 기법 ID 꼴이 아니면 기법으로 읽지 않는다
        for (String notTechnique : new String[]{"T105", "T10591", "T1059.1", "T1059.0001", "X1059", "T1059.", "1059"}) {
            assertThat(AttackFilter.techniqueId(notTechnique)).as(notTechnique).isNull();
        }
    }

    @Test
    void tacticSlugNormalizesCaseSpacesAndUnderscores() {
        for (String same : new String[]{"Credential Access", "credential_access", "credential-access",
                "  CREDENTIAL   ACCESS ", "credential _ access", "Credential\tAccess"}) {
            assertThat(AttackFilter.parse(same)).as(same)
                    .isEqualTo(new AttackFilter.Value(AttackFilter.Kind.TACTIC, "credential-access"));
        }
        assertThat(AttackFilter.tacticSlug("Command and Control")).isEqualTo("command-and-control");
        assertThat(AttackFilter.tacticSlug("execution")).isEqualTo("execution");
        assertThat(AttackFilter.tacticSlug("ta0006")).isEqualTo("ta0006");
    }

    @Test
    void invalidValuesAreRejected() {
        String tooLong = "a".repeat(65);
        for (String bad : new String[]{null, "", "   ", "a", "-x", "x-", "x--y", "credential/access", "T1059.1",
                "T1059.0001", "자격 증명", "a.b", "x;y", "' OR 1=1", tooLong}) {
            assertThat(AttackFilter.parse(bad)).as(String.valueOf(bad)).isNull();
        }
        assertThat(AttackFilter.tacticSlug("a".repeat(64))).hasSize(64);
        assertThat(AttackFilter.tacticSlug("ab")).isEqualTo("ab");
    }

    @Test
    void techniqueMatchesExactlyIncludingSubTechnique() throws Exception {
        JsonNode parent = JSON.readTree("[{\"attack_id\":\"T1059\",\"name\":\"n\",\"tactics\":[\"Execution\"]}]");
        JsonNode sub = JSON.readTree("[{\"attack_id\":\" t1059.001 \",\"tactics\":[\"execution\"]}]");
        AttackFilter.Value t1059 = AttackFilter.parse("t1059");
        AttackFilter.Value t1059001 = AttackFilter.parse("T1059.001");
        assertThat(AttackFilter.matches(t1059, parent)).isTrue();
        assertThat(AttackFilter.matches(t1059, sub)).isFalse();
        assertThat(AttackFilter.matches(t1059001, sub)).isTrue();
        assertThat(AttackFilter.matches(t1059001, parent)).isFalse();
    }

    @Test
    void tacticMatchesTitleAndSlugSpellings() throws Exception {
        JsonNode title = JSON.readTree("[{\"attack_id\":\"T1558\",\"tactics\":[\"Credential Access\"]}]");
        JsonNode mixed = JSON.readTree(
                "[{\"attack_id\":\"T1021\",\"tactics\":[\"Lateral Movement\"]},"
                        + "{\"attack_id\":\"T1110\",\"tactics\":[\"credential_access\",\"Command and Control\"]}]");
        AttackFilter.Value credential = AttackFilter.parse("credential-access");
        assertThat(AttackFilter.matches(credential, title)).isTrue();
        assertThat(AttackFilter.matches(credential, mixed)).isTrue();
        assertThat(AttackFilter.matches(AttackFilter.parse("Command And Control"), mixed)).isTrue();
        assertThat(AttackFilter.matches(AttackFilter.parse("impact"), mixed)).isFalse();
        // 전술 조건은 기법 ID 칸을 보지 않는다
        assertThat(AttackFilter.matches(AttackFilter.parse("t1558x"), title)).isFalse();
    }

    @Test
    void brokenShapesNeverMatchOrThrow() throws Exception {
        AttackFilter.Value t = AttackFilter.parse("T1059");
        AttackFilter.Value tactic = AttackFilter.parse("execution");
        for (String json : new String[]{"null", "{}", "\"T1059\"", "[]", "[null, 1, \"T1059\", []]",
                "[{\"attack_id\":null,\"tactics\":null}]", "[{\"attack_id\":{\"x\":\"T1059\"},\"tactics\":{\"a\":\"execution\"}}]",
                "[{\"tactics\":[null, {}, [\"execution\"]]}]"}) {
            JsonNode node = JSON.readTree(json);
            assertThat(AttackFilter.matches(t, node)).as(json).isFalse();
            assertThat(AttackFilter.matches(tactic, node)).as(json).isFalse();
        }
        assertThat(AttackFilter.matches(t, null)).isFalse();
        assertThat(AttackFilter.matches(null, JSON.readTree("[{\"attack_id\":\"T1059\"}]"))).isFalse();
        // tactics가 배열이 아닌 글 하나여도 읽는다(상세의 extractTextArray와 같다)
        assertThat(AttackFilter.matches(tactic, JSON.readTree("[{\"attack_id\":\"T1\",\"tactics\":\"Execution\"}]"))).isTrue();
    }

    /** T45b: visit이 알리는 값은 큐 attack 조건으로 갈 수 있는 값뿐이고, 알린 값은 모두 matches가 참이다 */
    @Test
    void visitReportsOnlyValuesTheQueueFilterCanReach() throws Exception {
        JsonNode node = JSON.readTree("[{\"attack_id\":\" t1059.001 \",\"name\":\"  PowerShell \",\"tactics\":[\"Execution\",\"execution\"]},"
                + "{\"attack_id\":\"T1110\",\"name\":\" \",\"tactics\":[\"credential_access\",\"t1059\",\"x\",\"Bad/Tactic\",null,{}]},"
                + "{\"attack_id\":\"TA0001\",\"name\":\"n\",\"tactics\":\"Initial Access\"},"
                + "{\"attack_id\":null,\"tactics\":null}, null, 1, \"T1059\", []]");
        java.util.List<String> techniques = new java.util.ArrayList<>();
        java.util.List<String> tactics = new java.util.ArrayList<>();
        AttackFilter.visit(node, new AttackFilter.CandidateVisitor() {
            @Override
            public void technique(String attackId, String name) {
                techniques.add(attackId + "|" + name);
                assertThat(AttackFilter.matches(AttackFilter.parse(attackId), node)).as(attackId).isTrue();
            }

            @Override
            public void tactic(String slug) {
                tactics.add(slug);
                assertThat(AttackFilter.parse(slug)).isEqualTo(new AttackFilter.Value(AttackFilter.Kind.TACTIC, slug));
                assertThat(AttackFilter.matches(AttackFilter.parse(slug), node)).as(slug).isTrue();
            }
        });
        // 이름은 다듬고 빈 글은 null. ID 꼴이 아닌 attack_id(TA0001)는 기법으로 알리지 않는다
        assertThat(techniques).containsExactly("T1059.001|PowerShell", "T1110|null");
        // 같은 전술이 두 번 나오면 두 번 알린다(세는 쪽이 한 번으로 묶는다). 기법 ID 꼴 전술(t1059)·슬러그가 안 되는 값은 빠진다
        assertThat(tactics).containsExactly("execution", "execution", "credential-access", "initial-access");
        // 큐가 기법으로 읽는 값은 전술로 맞출 수 없다(그래서 전술로 세지 않는다)
        assertThat(AttackFilter.parse("t1059").kind()).isEqualTo(AttackFilter.Kind.TECHNIQUE);

        for (String json : new String[]{"null", "{}", "\"T1059\"", "[]", "[null, 1, []]"}) {
            AttackFilter.visit(JSON.readTree(json), new AttackFilter.CandidateVisitor() {
                @Override
                public void technique(String attackId, String name) {
                    throw new AssertionError(attackId);
                }

                @Override
                public void tactic(String slug) {
                    throw new AssertionError(slug);
                }
            });
        }
        AttackFilter.visit(null, null);
    }
}
