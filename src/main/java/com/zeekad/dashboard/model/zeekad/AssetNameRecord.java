package com.zeekad.dashboard.model.zeekad;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * dashboard.asset_names 뷰 DTO (고정 열 및 부가 열 수용).
 */
public class AssetNameRecord {

    private String captureId;
    private String hostIp;
    private String kerberosUser;
    private String ntlmUser;
    private Map<String, Object> extraAttributes = Collections.emptyMap();

    public static AssetNameRecord fromRawMap(Map<String, Object> raw) {
        AssetNameRecord record = new AssetNameRecord();
        if (raw == null || raw.isEmpty()) {
            return record;
        }
        Map<String, Object> extras = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : raw.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            String keyLower = entry.getKey().toLowerCase(Locale.ROOT);
            Object val = entry.getValue();
            switch (keyLower) {
                case "capture_id" -> record.setCaptureId(asString(val));
                case "host_ip" -> record.setHostIp(asString(val));
                case "kerberos_user" -> record.setKerberosUser(asString(val));
                case "ntlm_user" -> record.setNtlmUser(asString(val));
                default -> extras.put(keyLower, val);
            }
        }
        record.setExtraAttributes(Collections.unmodifiableMap(extras));
        return record;
    }

    private static String asString(Object val) {
        return val == null ? null : val.toString();
    }

    public String getCaptureId() {
        return captureId;
    }

    public void setCaptureId(String captureId) {
        this.captureId = captureId;
    }

    public String getHostIp() {
        return hostIp;
    }

    public void setHostIp(String hostIp) {
        this.hostIp = hostIp;
    }

    public String getKerberosUser() {
        return kerberosUser;
    }

    public void setKerberosUser(String kerberosUser) {
        this.kerberosUser = kerberosUser;
    }

    public String getNtlmUser() {
        return ntlmUser;
    }

    public void setNtlmUser(String ntlmUser) {
        this.ntlmUser = ntlmUser;
    }

    public Map<String, Object> getExtraAttributes() {
        return extraAttributes;
    }

    public void setExtraAttributes(Map<String, Object> extraAttributes) {
        this.extraAttributes = extraAttributes == null ? Collections.emptyMap() : extraAttributes;
    }
}
