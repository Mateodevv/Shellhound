import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
// Länderflaggen als lokal gebündelte SVGs: Windows rendert Flaggen-Emojis
// nicht, und ein Forensik-Werkzeug lädt nichts von CDNs.
import 'flag-icons/css/flag-icons.min.css'
import App from './App'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
