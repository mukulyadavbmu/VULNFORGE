/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#060A14',
        surface: '#0D1117',
        'surface-2': '#161B22',
        border: '#21262D',
        primary: '#58A6FF',
        danger: '#F85149',
        warning: '#D29922',
        success: '#3FB950',
        textMain: '#E6EDF3',
        textMuted: '#8B949E',
        textSubtle: '#484F58',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': '0.625rem',
        'xs': '0.75rem',
      },
      animation: {
        'fadeInUp': 'fadeInUp 0.2s ease-out forwards',
        'pulse-slow': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        fadeInUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
      },
    },
  },
  plugins: [],
}
