import { DirectEnrichment } from './DirectEnrichment'

export function ArtifactEnrichment({ slug, ids }: { slug: string; ids: number[] }) {
  return <DirectEnrichment slug={slug} ids={ids} />
}
