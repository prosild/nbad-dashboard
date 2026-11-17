package com.zeekad.dashboard.security;

import com.zeekad.dashboard.config.DashboardProperties;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;

/**
 * RFC 6238 기반 6자리 TOTP 생성 및 검증 서비스.
 */
@Service
public class TotpService {

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int[] BASE32_LOOKUP = new int[128];
    private static final int SECRET_BYTES = 20;
    private static final long TIME_STEP_SECONDS = 30L;
    private static final int CODE_DIGITS = 6;
    private static final int WINDOW_STEPS = 1;

    static {
        Arrays.fill(BASE32_LOOKUP, -1);
        for (int i = 0; i < BASE32_ALPHABET.length(); i++) {
            BASE32_LOOKUP[BASE32_ALPHABET.charAt(i)] = i;
        }
    }

    private final SecureRandom secureRandom = new SecureRandom();
    private final DashboardProperties properties;
    private final Clock clock;

    public TotpService(DashboardProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        secureRandom.nextBytes(bytes);
        return encodeBase32(bytes);
    }

    public String normalizeSecret(String secret) {
        if (secret == null) {
            return "";
        }
        return secret.replaceAll("[\\s=]+", "").toUpperCase(Locale.ROOT);
    }

    public boolean verifyCode(String base32Secret, String submittedCode) {
        return verifyCode(base32Secret, submittedCode, clock.instant());
    }

    public boolean verifyCode(String base32Secret, String submittedCode, Instant atTime) {
        if (base32Secret == null || base32Secret.isBlank() || submittedCode == null) {
            return false;
        }
        String sanitizedCode = submittedCode.trim();
        if (!sanitizedCode.matches("^\\d{6}$")) {
            return false;
        }
        byte[] key = decodeBase32(base32Secret);
        if (key.length == 0) {
            return false;
        }
        long currentStep = Math.floorDiv(atTime.getEpochSecond(), TIME_STEP_SECONDS);
        byte[] submittedBytes = sanitizedCode.getBytes(StandardCharsets.US_ASCII);
        for (int offset = -WINDOW_STEPS; offset <= WINDOW_STEPS; offset++) {
            String expected = computeTotp(key, currentStep + offset);
            if (MessageDigest.isEqual(submittedBytes, expected.getBytes(StandardCharsets.US_ASCII))) {
                return true;
            }
        }
        return false;
    }

    public String generateCode(String base32Secret, Instant atTime) {
        byte[] key = decodeBase32(base32Secret);
        if (key.length == 0) {
            throw new IllegalArgumentException("유효하지 않은 TOTP 시크릿입니다.");
        }
        long step = Math.floorDiv(atTime.getEpochSecond(), TIME_STEP_SECONDS);
        return computeTotp(key, step);
    }

    public String buildOtpAuthUri(String username, String base32Secret) {
        String issuer = properties.getSecurity().getTotpIssuer();
        String encodedIssuer = urlEncode(issuer);
        String encodedAccount = urlEncode(username);
        String label = encodedIssuer + ":" + encodedAccount;
        return "otpauth://totp/" + label
                + "?secret=" + urlEncode(normalizeSecret(base32Secret))
                + "&issuer=" + encodedIssuer
                + "&algorithm=SHA1&digits=6&period=30";
    }

    private String computeTotp(byte[] key, long timeStep) {
        try {
            byte[] data = ByteBuffer.allocate(8).putLong(timeStep).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int otp = binary % 1_000_000;
            return String.format(Locale.ROOT, "%0" + CODE_DIGITS + "d", otp);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("TOTP 계산 중 오류가 발생했습니다.", e);
        }
    }

    private String encodeBase32(byte[] bytes) {
        StringBuilder sb = new StringBuilder((bytes.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : bytes) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                bitsLeft -= 5;
                sb.append(BASE32_ALPHABET.charAt(index));
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            sb.append(BASE32_ALPHABET.charAt(index));
        }
        return sb.toString();
    }

    private byte[] decodeBase32(String input) {
        String normalized = normalizeSecret(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;
        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);
            if (c >= BASE32_LOOKUP.length || BASE32_LOOKUP[c] < 0) {
                return new byte[0];
            }
            buffer = (buffer << 5) | BASE32_LOOKUP[c];
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
