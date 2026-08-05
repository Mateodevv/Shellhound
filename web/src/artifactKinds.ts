// artifactKinds.ts — how an artifact kind looks everywhere in the interface.
//
// Its own file rather than an export from ArtifactWindow: constants next to
// a component break Fast Refresh for the whole file, and these are needed
// where that window is not open at all (findings rows, suggestion window).
//
// The label lives in the catalogue under `kind.<kind>`, not here — a
// module-level constant would freeze the language at module load.
import { Bug, FileCode2, ServerCog, Table2, Users } from 'lucide-react'

export const KIND_ICON: Record<string, typeof Bug> = {
  file: FileCode2, table: Table2, client: Users, dump: ServerCog,
}
