import { setActiveTimeMode, storedTimeMode } from './format'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'
import { reportClientError } from './api'

window.addEventListener('error', event => {
  reportClientError('browser-exception', event.error ?? event.message)
})
window.addEventListener('unhandledrejection', event => {
  reportClientError('unhandled-promise', event.reason)
})

setActiveTimeMode(storedTimeMode())

createRoot(document.getElementById('root')!, {
  onUncaughtError: error => reportClientError('react-render', error),
  onCaughtError: error => reportClientError('react-boundary', error),
  onRecoverableError: error => reportClientError('react-recovery', error),
}).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
