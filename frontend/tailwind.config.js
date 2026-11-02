/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          darker: "#0B0F17",
          dark: "#111827",
          card: "#1F2937",
          border: "#374151",
          accent: "#3B82F6",
          danger: "#EF4444",
          warning: "#F59E0B",
          success: "#10B981"
        }
      }
    },
  },
  plugins: [],
}

