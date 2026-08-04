// artifactKinds.ts — wie eine Artefakt-Art überall aussieht und heißt.
//
// Eigene Datei statt Export aus ArtifactWindow: Konstanten neben einer
// Komponente brechen Fast Refresh für die ganze Datei, und gebraucht werden
// sie auch dort, wo das Fenster gar nicht offen ist (Findings-Zeilen,
// Vorschlagsfenster).
import { Bug, FileCode2, ServerCog, Table2, Users } from 'lucide-react'

export const KIND_ICON: Record<string, typeof Bug> = {
  file: FileCode2, table: Table2, client: Users, dump: ServerCog,
}

export const KIND_LABEL: Record<string, string> = {
  file: 'Datei', table: 'Tabelle', client: 'Client', dump: 'Dump',
}
