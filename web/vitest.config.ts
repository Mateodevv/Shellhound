// vitest.config.ts -- the test runner for web/src.
//
// Separate from vite.config.ts rather than merged into it: the dev config
// carries a proxy to the FastAPI server, and a test run that could reach a
// real backend is a test run whose result depends on what happens to be
// listening. The network is mocked at the api layer instead.
//
// No `globals`. `describe`/`it`/`expect` are imported in every test file,
// because the type-check runs over `src` with a fixed `types` list that this
// config is in no position to extend.
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
