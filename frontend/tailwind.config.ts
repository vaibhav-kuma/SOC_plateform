import type { Config } from 'tailwindcss'

export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0a0e17',
          surface: '#111827',
          border: '#1e293b',
          accent: '#06b6d4',
          'accent-dim': '#0891b2',
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#22c55e',
          info: '#3b82f6',
          text: '#e2e8f0',
          'text-dim': '#94a3b8',
          sidebar: '#0f172a',
          'sidebar-hover': '#1e293b',
          topbar: '#0c1222',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
    },
  },
  plugins: [],
} satisfies Config
