/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: '#1e2433',
        'surface-2': '#252d3d',
        border: '#2e3a4e',
        accent: '#3b82d4',
      },
    },
  },
  plugins: [],
}
