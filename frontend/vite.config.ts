import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: true,
    // 시험 하나의 제한 시간(기본 5초). 시험 수가 늘었고(27파일 468건) 개발 PC는 다른 작업과 함께 돌아서
    // 평소 3~5초 걸리는 화면 시험이 부하가 있을 때 제한에 걸렸다. 기다리는 시간만 늘린다(단언은 그대로다).
    testTimeout: 15000,
  },
});
