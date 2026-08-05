import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
// Country flags as locally bundled SVGs: Windows does not render flag
// emoji, and a forensic tool loads nothing from CDNs.
import 'flag-icons/css/flag-icons.min.css'
import { I18nProvider } from './i18n'
import App from './App'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <I18nProvider>
      <App />
    </I18nProvider>
  </StrictMode>,
)
