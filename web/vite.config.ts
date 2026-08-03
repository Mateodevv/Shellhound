import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Dev mode proxies API + WebSocket to the FastAPI server (default port 8710).
// Production build is served BY the FastAPI server itself (web/dist).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': { target: 'http://127.0.0.1:8710', changeOrigin: true },
      '/ws': { target: 'ws://127.0.0.1:8710', ws: true },
    },
  },
  build: {
    chunkSizeWarningLimit: 1200,
  },
})
