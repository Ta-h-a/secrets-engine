/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./src/renderer/**/*.{js,ts,jsx,tsx}",
    "./src/renderer/index.html",
  ],
  theme: {
    extend: {
      colors: {
        'swiss-bg': '#F9F9FB',
        'swiss-black': '#000000',
        'swiss-gray': '#E5E5E5',
        'swiss-text-muted': '#666666',
        'critical': '#ec1313',
        'high': '#ff8a00',
        'medium': '#ffd600',
        'low': '#007aff',
        'primary': '#10b981',
      },
      fontFamily: {
        sans: ['Inter', 'Helvetica', 'Arial', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      borderRadius: {
        'none': '0',
      },
    },
  },
  plugins: [],
};
