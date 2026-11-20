# syntax=docker/dockerfile:1
# 1단계: React SPA 번들 빌드 (Node.js는 이 단계에서만 사용하고 최종 이미지에는 넣지 않는다)
FROM node:24-alpine AS frontend
WORKDIR /workspace/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
RUN npm run build

# 2단계: 1단계 번들을 frontend/dist에 넣어 bootJar 생성 (Gradle은 Node·npm을 호출하지 않는다)
FROM eclipse-temurin:17-jdk-alpine AS builder
WORKDIR /workspace

COPY gradlew settings.gradle build.gradle ./
COPY gradle ./gradle
COPY src/main ./src/main
COPY --from=frontend /workspace/frontend/dist ./frontend/dist

RUN sed -i 's/\r$//' gradlew \
    && chmod +x gradlew \
    && ./gradlew bootJar --no-daemon \
    && find build/libs -maxdepth 1 -name '*.jar' ! -name '*-plain.jar' -exec cp {} /workspace/app.jar \;

# 3단계: 런타임 (JRE만, non-root)
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

RUN apk upgrade --no-cache \
    && addgroup -S appgroup \
    && adduser -S -G appgroup -H appuser

COPY --from=builder --chown=appuser:appgroup /workspace/app.jar /app/app.jar

USER appuser:appgroup
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
    CMD wget -q --spider http://127.0.0.1:8080/login || exit 1

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]
