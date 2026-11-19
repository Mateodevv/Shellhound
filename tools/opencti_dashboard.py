"""Generate the native OpenCTI dashboard and its prerequisite label catalogue.

Run from the repository root: python -m tools.opencti_dashboard
No network access, credentials or case data are used.
"""
import base64
import json
import uuid
from pathlib import Path

from server.casework.profile_options import (CONTEXT_OPTIONS, HOSTING_PROVIDERS, PROFILE_LABEL_PREFIX,
                                             CASE_LABEL, display_label)

VERSION = '7.261103.0'
OUTPUT = Path(__file__).resolve().parents[1] / 'docs' / 'opencti-dashboard'
LABEL_NAMESPACE = uuid.UUID('00abedb4-aa42-466c-9c01-fed23315a9b7')
ARTIFACT_NAMESPACE = uuid.UUID('9d78a3c4-f641-46bf-8702-d60aebee5496')
TITLES = {
    'employee_count': 'Unternehmensgröße · Mitarbeitende',
    'hosting_model': 'Hostingmodell',
    'hosting_providers': 'Hosting-/Cloudanbieter · Mehrfachnennungen',
    'it_operating_model': 'IT-Betriebsmodell',
    'initial_access': 'Initialer Zugangsweg',
    'initial_access_status': 'Sicherheit der Zugangsbewertung',
    'spread': 'Ausbreitung · Mehrfachnennungen',
    'data_exfiltration': 'Datenabfluss',
    'attacker_encryption': 'Verschlüsselung durch Angreifer',
    'discovered_by': 'Entdeckende Partei',
    'discovery_method': 'Entdeckungsweg',
}


def label_value(field, value):
    return PROFILE_LABEL_PREFIX + field + ':' + value.strip().casefold()


def label_id(field, value, display=True):
    # OpenCTI Label.generate_id: UUIDv5 of the canonical {"value": ...} JSON.
    canonical = json.dumps({'value': (display_label(field, value) if display else label_value(field, value)).strip().lower()}, ensure_ascii=False,
                           sort_keys=True, separators=(',', ':'))
    return 'label--' + str(uuid.uuid5(LABEL_NAMESPACE, canonical))


def options():
    return {**CONTEXT_OPTIONS, 'spread': (*CONTEXT_OPTIONS['spread'], 'unknown'),
            'hosting_providers': (*HOSTING_PROVIDERS, 'unknown')}


def filter_group(filters=()):
    return {'mode': 'and', 'filters': list(filters), 'filterGroups': []}


def eq(key, values):
    return {'key': [key], 'values': values, 'operator': 'eq', 'mode': 'or'}


def selection(name='Fälle', *categories):
    filters = [eq('entity_type', ['Case-Incident']),
               eq('objectLabel', [label_id('employee_count', v) for v in CONTEXT_OPTIONS['employee_count']])]
    filters.extend(eq('objectLabel', [label_id(field, value)]) for field, value in categories)
    return {'label': name, 'number': 20, 'attribute': 'entity_type', 'date_attribute': 'created',
            'perspective': 'entities', 'isTo': True, 'filters': filter_group(filters),
            'dynamicFrom': filter_group(), 'dynamicTo': filter_group()}


def distribution_selection(field, *categories):
    # Aggregate the label edge targets: entity-label distributions would also
    # return every other label attached to each matching case.
    return {'label': 'Fälle je Profil-Label', 'number': len(options()[field]),
            'attribute': 'internal_id', 'date_attribute': 'created_at',
            'perspective': 'relationships', 'isTo': True,
            'filters': filter_group([eq('entity_type', ['object-label']),
                                     eq('fromTypes', ['Case-Incident']),
                                     eq('toId', [label_id(field, value, display=True) for value in options()[field]])]),
            'dynamicFrom': selection('Fälle', *categories)['filters'],
            'dynamicTo': filter_group()}


def build_dashboard():
    widgets = {}

    def add(key, kind, title, data, x, y, w, h, **parameters):
        widget_id = str(uuid.uuid5(ARTIFACT_NAMESPACE, key))
        widgets[widget_id] = {
            'id': widget_id, 'type': kind, 'perspective': data[0]['perspective'] if data else None,
            'dataSelection': data, 'parameters': {'title': title, **parameters},
            'layout': {'i': widget_id, 'x': x, 'y': y, 'w': w, 'h': h, 'moved': False, 'static': False},
        }

    add('intro', 'text', 'Shellhound · Fallprofile', [], 0, 0, 12, 3, content=(
        '**Datenbasis:** erfolgreich übertragene Shellhound-Fälle mit Profil-Labels. '
        'Gezählt werden Fälle, keine Unternehmen und kein Versicherungsbestand. '
        '**Balken:** aktuelle Fallzahlen je Profil-Label, absteigend nach Häufigkeit; keine Zeitverläufe. '
        '**Standardzeitraum:** alle Zeiten. Bitte für den Gesamtvergleich den Datumsfilter leer lassen: '
        'Eine Datumswahl filtert Balken nach Anlage der Label-Zuordnung in OpenCTI, '
        'Kennzahlen und Fallliste dagegen nach Anlage des Falls in Shellhound. '
        'Statuswerte beschreiben den zuletzt übertragenen Stand des Falls.'))
    counters = [
        ('total', 'Übertragene Shellhound-Fälle', ()),
        ('exfil', 'Datenabfluss · bestätigt', (('data_exfiltration', 'confirmed'),)),
        ('encryption', 'Verschlüsselung · bestätigt', (('attacker_encryption', 'confirmed'),)),
        ('unknown-access', 'Zugangsweg · unbekannt', (('initial_access', 'unknown'),)),
        ('unexamined-exfil', 'Datenabfluss · nicht untersucht', (('data_exfiltration', 'not_investigated'),)),
        ('unexamined-encryption', 'Verschlüsselung · nicht untersucht', (('attacker_encryption', 'not_investigated'),)),
    ]
    for index, (key, title, categories) in enumerate(counters):
        add(key, 'number', title, [selection(title, *categories)], index % 3 * 4,
            3 + index // 3 * 2, 4, 2)
    for index, (field, title) in enumerate(TITLES.items()):
        add(field, 'horizontal-bar', title, [distribution_selection(field)],
            index % 2 * 6, 7 + index // 2 * 3, 6, 3, distributed=False)
    add('exfil-hosting', 'horizontal-bar', 'Bestätigter Datenabfluss nach Hostingmodell · Fallzahlen',
        [distribution_selection('hosting_model', ('data_exfiltration', 'confirmed'))],
        6, 22, 6, 3, distributed=False)
    cases = selection()
    cases.update(sort_by='created', sort_mode='desc', columns=[
        {'attribute': 'name', 'label': 'Fall'},
        {'attribute': 'created', 'label': 'Fall angelegt'},
        {'attribute': 'objectLabel', 'label': 'Labels'},
        {'attribute': 'objectMarking', 'label': 'Markierung'},
    ])
    add('case-list', 'list', 'Neueste Fälle · maximal 20', [cases], 0, 25, 12, 6)
    add('limits', 'text', 'Auswertung richtig einordnen', [], 0, 31, 12, 3, content=(
        '**Mehrfachnennungen:** Ausbreitung und Anbieter können pro Fall mehrfach vorkommen; '
        'ihre Summen sind keine Fallgesamtzahl. Anbieterdiagramm: nur Katalogwerte und unbekannt; '
        'frei eingegebene Anbieter bleiben über die Fall-Labels filterbar. '
        '**Unbekannt / nicht untersucht / nicht beobachtet / vermutet / bestätigt** sind unterschiedliche Angaben. '
        'Nicht beobachtet beweist keine Abwesenheit. Kategorien ohne Treffer werden nicht angezeigt. '
        'Die Balken verwenden kurze SH-Labels. Bestehende Fälle erneut übertragen oder die kurzen Labels manuell ergänzen. '
        '**Grenzen:** keine Schadenkosten, Entdeckungsdauer, Patchverläufe oder Bestandsquoten. '
        'Fallzahlen belegen weder Schadenwahrscheinlichkeit noch die Wirksamkeit von Präventionsmaßnahmen.'))
    manifest = {'widgets': widgets, 'config': {'startDate': None, 'endDate': None, 'relativeDate': None}}
    return {'openCTI_version': VERSION, 'type': 'dashboard', 'configuration': {
        'name': 'Shellhound · Fallprofile · Kurzlabels',
        'manifest': base64.b64encode(json.dumps(manifest, ensure_ascii=False,
                                              separators=(',', ':')).encode()).decode(),
    }}


def build_catalogue():
    timestamp = '2026-11-19T00:00:00.000Z'
    identity_id = 'identity--' + str(uuid.uuid5(ARTIFACT_NAMESPACE, 'catalogue-system'))
    grouping_id = 'grouping--' + str(uuid.uuid5(ARTIFACT_NAMESPACE, 'catalogue-grouping'))
    common = {'spec_version': '2.1', 'created': timestamp, 'modified': timestamp}
    return {'type': 'bundle', 'id': 'bundle--' + str(uuid.uuid5(ARTIFACT_NAMESPACE, 'catalogue-bundle')),
            'objects': [
                {'type': 'identity', 'id': identity_id, **common, 'name': 'Shellhound Dashboard',
                 'identity_class': 'system', 'description': 'Technischer Labelkatalog; keine Kundendaten.'},
                {'type': 'grouping', 'id': grouping_id, **common,
                 'name': 'Shellhound Dashboard · Labelkatalog', 'context': 'unspecified',
                 'description': 'Technischer Katalog für portable Dashboard-Filter. Kein Vorfall, kein Kunde.',
                 'object_refs': [identity_id],
                 'labels': sorted({CASE_LABEL} | {display_label(field, value)
                                  for field, values in options().items() for value in values})},
            ]}


def write_artifacts():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, data in [('01-shellhound-label-catalogue.stix.json', build_catalogue()),
                       ('02-shellhound-dashboard-' + VERSION + '.json', build_dashboard())]:
        target = OUTPUT / name
        target.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(target)
    mapping = ['# Labels manuell zuordnen', '',
               'Die passenden kurzen Labels am selben Case ergänzen, prüfen und danach die alten technischen Zuordnungen entfernen.',
               'Zusätzlich jedem Shellhound-Case `Webserver Compromise` geben. Das Label allein ist kein technischer Nachweis.',
               'Vor dem Dashboard den aktualisierten Labelkatalog importieren; danach das neue Dashboard importieren.', '',
               '| Vorhandenes technisches Label | Zusätzliches kurzes Label |', '|---|---|']
    for field, values in {**options(), 'initial_cve': ('unknown', 'CVE-2026-12345')}.items():
        mapping.extend(f'| `{label_value(field, value)}` | `{display_label(field, value)}` |' for value in values)
    mapping.extend(['', 'Initial-CVE: die konkrete CVE einsetzen. Eigene Anbieter: `SH Anbieter: <Name>` verwenden.',
                    'Den Bereich `SH ` für Shellhound reservieren. Änderungen im Case Profile ersetzen alte SH-Labels beim nächsten Transfer.',
                    'Datumsfilter für den Vergleich aller Kennzahlen leer lassen.'])
    (OUTPUT / 'LABELS.md').write_text('\n'.join(mapping) + '\n', encoding='utf-8')


if __name__ == '__main__':
    write_artifacts()
