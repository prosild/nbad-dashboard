package com.zeekad.dashboard.mybatis;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * PostgreSQL jsonb 및 H2 JSON/TEXT 컬럼을 Jackson JsonNode로 매핑하는 MyBatis TypeHandler.
 */
public class JsonNodeTypeHandler extends BaseTypeHandler<JsonNode> {

    private static final ObjectMapper DEFAULT_MAPPER = new ObjectMapper().findAndRegisterModules();

    private final ObjectMapper objectMapper;

    public JsonNodeTypeHandler() {
        this(DEFAULT_MAPPER);
    }

    public JsonNodeTypeHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper != null ? objectMapper : DEFAULT_MAPPER;
    }

    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, JsonNode parameter, JdbcType jdbcType)
            throws SQLException {
        try {
            ps.setString(i, objectMapper.writeValueAsString(parameter));
        } catch (JsonProcessingException e) {
            throw new SQLException("JsonNode 직렬화 실패", e);
        }
    }

    @Override
    public JsonNode getNullableResult(ResultSet rs, String columnName) throws SQLException {
        return parse(rs.getObject(columnName));
    }

    @Override
    public JsonNode getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        return parse(rs.getObject(columnIndex));
    }

    @Override
    public JsonNode getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        return parse(cs.getObject(columnIndex));
    }

    private JsonNode parse(Object raw) throws SQLException {
        if (raw == null) {
            return null;
        }
        String json;
        if (raw instanceof byte[] bytes) {
            json = new String(bytes, StandardCharsets.UTF_8);
        } else if (raw instanceof Clob clob) {
            json = readClob(clob);
        } else {
            // PostgreSQL PGobject.toString()은 JSON 원문 문자열을 반환한다.
            json = raw.toString();
        }
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(json);
        } catch (JsonProcessingException e) {
            throw new SQLException("JSON 컬럼 파싱 실패", e);
        }
    }

    private String readClob(Clob clob) throws SQLException {
        StringBuilder sb = new StringBuilder();
        try (Reader reader = clob.getCharacterStream()) {
            char[] buf = new char[1024];
            int len;
            while ((len = reader.read(buf)) != -1) {
                sb.append(buf, 0, len);
            }
            return sb.toString();
        } catch (IOException e) {
            throw new SQLException("CLOB 읽기 실패", e);
        }
    }
}
