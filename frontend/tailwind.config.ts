import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          'Pretendard Variable',
          'Pretendard',
          'Inter',
          'Segoe UI',
          'Apple SD Gothic Neo',
          'Noto Sans KR',
          'Malgun Gothic',
          'system-ui',
          'sans-serif',
        ],
        mono: [
          'JetBrains Mono',
          'Cascadia Code',
          'SFMono-Regular',
          'Consolas',
          'Liberation Mono',
          'Menlo',
          'monospace',
        ],
      },
      colors: {
        soc: {
          bg: '#070b14',
          surface: '#0d1424',
          panel: '#111a2e',
          elevated: '#17223b',
          border: '#1e293b',
          borderStrong: '#334155',
          cyan: '#22d3ee',
          blue: '#38bdf8',
          emerald: '#34d399',
          amber: '#fbbf24',
          rose: '#fb7185',
          purple: '#a78bfa',
        },
      },
    },
  },
  plugins: [],
} satisfies Config;
