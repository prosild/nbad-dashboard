package com.zeekad.dashboard.mybatis;

import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;

import java.sql.Array;
import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * PostgreSQL text[] 및 H2 ARRAY 컬럼을 List&lt;String&gt;으로 안전하게 매핑하는 MyBatis TypeHandler.
 */
public class StringListTypeHandler extends BaseTypeHandler<List<String>> {

    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, List<String> parameter, JdbcType jdbcType)
            throws SQLException {
        Array sqlArray = ps.getConnection().createArrayOf("text", parameter.toArray(new String[0]));
        ps.setArray(i, sqlArray);
    }

    @Override
    public List<String> getNullableResult(ResultSet rs, String columnName) throws SQLException {
        return convert(rs.getObject(columnName));
    }

    @Override
    public List<String> getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        return convert(rs.getObject(columnIndex));
    }

    @Override
    public List<String> getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        return convert(cs.getObject(columnIndex));
    }

    private List<String> convert(Object raw) throws SQLException {
        if (raw == null) {
            return Collections.emptyList();
        }
        if (raw instanceof Array sqlArray) {
            try {
                return extractFromObject(sqlArray.getArray());
            } finally {
                try {
                    sqlArray.free();
                } catch (SQLException ignored) {
                    // H2 등 일부 드라이버는 free() 미지원 가능
                }
            }
        }
        return extractFromObject(raw);
    }

    private List<String> extractFromObject(Object value) {
        if (value == null) {
            return Collections.emptyList();
        }
        if (value instanceof String[] strArr) {
            return Arrays.stream(strArr)
                    .filter(Objects::nonNull)
                    .toList();
        }
        if (value instanceof Object[] objArr) {
            List<String> list = new ArrayList<>(objArr.length);
            for (Object elem : objArr) {
                if (elem != null) {
                    list.add(elem.toString());
                }
            }
            return Collections.unmodifiableList(list);
        }
        if (value instanceof Collection<?> col) {
            List<String> list = new ArrayList<>(col.size());
            for (Object elem : col) {
                if (elem != null) {
                    list.add(elem.toString());
                }
            }
            return Collections.unmodifiableList(list);
        }
        if (value instanceof String str) {
            return parsePgArrayString(str);
        }
        return List.of(value.toString());
    }

    private List<String> parsePgArrayString(String raw) {
        String trimmed = raw.trim();
        if (trimmed.isEmpty() || "{}".equals(trimmed)) {
            return Collections.emptyList();
        }
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
        }
        if (trimmed.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> result = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        boolean escaped = false;
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (escaped) {
                current.append(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                addToken(result, current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        addToken(result, current.toString());
        return Collections.unmodifiableList(result);
    }

    private void addToken(List<String> result, String token) {
        String trimmed = token.trim();
        if (!trimmed.isEmpty() && !"NULL".equalsIgnoreCase(trimmed)) {
            result.add(trimmed);
        }
    }
}
