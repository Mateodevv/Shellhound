import { Timeline } from './Timeline'
import type { Navigate } from '../App'

export function Dashboard(props: { slug: string; gotoView: Navigate }) {
  return <Timeline {...props} />
}
