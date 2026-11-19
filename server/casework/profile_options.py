"""Local profile validation data and the fixed sector catalogue."""
import json
from functools import lru_cache
from pathlib import Path

SUBSECTORS = {
    'Public administration': ('National government', 'Regional government', 'Local government', 'Public agencies'),
    'Healthcare': ('Hospitals', 'Medical practices', 'Care services', 'Laboratories', 'Pharmacies'),
    'Financial services': ('Banking', 'Insurance', 'Investment services', 'Payment services'),
    'Energy': ('Electricity', 'Gas', 'Oil', 'Renewable energy'),
    'Water and wastewater': ('Drinking water supply', 'Wastewater treatment', 'Water infrastructure'),
    'Technology': ('Software', 'IT services', 'Cloud and data centres', 'Cybersecurity', 'Hardware'),
    'Telecommunications': ('Fixed networks', 'Mobile networks', 'Internet service providers', 'Satellite communications'),
    'Transport and logistics': ('Road transport', 'Rail transport', 'Aviation', 'Shipping', 'Logistics'),
    'Manufacturing': ('Machinery', 'Automotive', 'Electronics', 'Chemicals', 'Pharmaceutical manufacturing'),
    'Retail': ('Physical retail', 'Online retail', 'Wholesale'),
    'Food and agriculture': ('Agriculture', 'Food processing', 'Food distribution', 'Forestry', 'Fisheries'),
    'Education and research': ('Schools', 'Higher education', 'Research institutes', 'Vocational training'),
    'Media and culture': ('News media', 'Broadcasting', 'Publishing', 'Cultural institutions'),
    'Professional services': ('Legal services', 'Accounting and tax', 'Consulting', 'Engineering and architecture'),
    'Construction and real estate': ('Construction', 'Property management', 'Real estate services', 'Building services'),
    'Hospitality and tourism': ('Hotels', 'Food services', 'Travel and tourism', 'Event services'),
    'Non-profit organisations': ('Charities', 'Associations', 'Foundations', 'Religious organisations'),
    'Other': ('Other services', 'Private individuals', 'Unclassified'),
}
SECTORS = tuple(SUBSECTORS)

OUTCOME_OPTIONS = ('unknown', 'not_investigated', 'not_observed', 'suspected', 'confirmed')
HOSTING_PROVIDERS = ('Amazon Web Services (AWS)', 'Microsoft Azure', 'Google Cloud', 'Hetzner', 'IONOS',
                     'OVHcloud', 'Host Europe', 'Strato', 'ALL-INKL', 'netcup', 'DigitalOcean',
                     'Akamai / Linode', 'Cloudflare', 'Vercel', 'Netlify')
PROFILE_LABEL_PREFIX = 'shellhound:profile:'
DISPLAY_LABEL_PREFIX = 'SH '
CASE_LABEL = 'Webserver Compromise'
DISPLAY_FIELDS = {
    'employee_count': 'Größe', 'hosting_model': 'Hosting', 'hosting_providers': 'Anbieter',
    'it_operating_model': 'IT', 'initial_access': 'Zugang', 'initial_access_status': 'Bewertung',
    'spread': 'Ausbreitung', 'data_exfiltration': 'Abfluss', 'attacker_encryption': 'Verschlüss.',
    'discovered_by': 'Entdecker', 'discovery_method': 'Entdeckung', 'initial_cve': 'Initial-CVE',
}
DISPLAY_VALUES = {
    'unknown': 'unbekannt', 'on_premises': 'vor Ort', 'colocation': 'Colocation',
    'dedicated_vps': 'Server/VPS', 'shared_hosting': 'Shared', 'managed_hosting': 'Managed',
    'cloud': 'Cloud', 'mixed': 'gemischt', 'other': 'sonstige', 'internal': 'intern', 'external': 'extern',
    'no_dedicated_support': 'keine Betreuung', 'software_vulnerability': 'Schwachstelle',
    'stolen_credentials': 'Zugangsdaten', 'phishing': 'Phishing', 'misconfiguration': 'Fehlkonfig.',
    'third_party': 'Drittpartei', 'suspected': 'vermutet', 'confirmed': 'bestätigt',
    'not_investigated': 'nicht untersucht', 'not_observed': 'nicht beobachtet',
    'web_application': 'Webanwendung', 'web_server': 'Webserver', 'other_servers': 'weitere Server',
    'endpoints': 'Endgeräte', 'identity_services': 'Identität', 'cloud_saas': 'Cloud/SaaS',
    'internal_it': 'interne IT', 'employee': 'Mitarbeitende', 'it_provider': 'IT-Dienstleister',
    'soc_mdr': 'SOC/MDR', 'customer': 'Kunde', 'authority': 'Behörde', 'attacker': 'Angreifer',
    'monitoring': 'Monitoring', 'user_report': 'Nutzermeldung', 'external_notification': 'extern',
    'ransom_note': 'Erpresserbrief', 'incidental': 'Zufallsfund',
}


def display_label(field, value):
    value = value.strip() or 'unknown'
    if field == 'hosting_providers':
        value = {name.casefold(): name for name in HOSTING_PROVIDERS}.get(value.casefold(), value.casefold())
        value = {'Amazon Web Services (AWS)': 'AWS', 'Microsoft Azure': 'Azure',
                 'Google Cloud': 'GCP', 'Akamai / Linode': 'Linode', 'aws': 'AWS'}.get(value, value)
    elif field == 'employee_count':
        value = value.replace('-', '–')
    text = value if field == 'hosting_providers' and value != 'unknown' else DISPLAY_VALUES.get(value, value)
    return DISPLAY_LABEL_PREFIX + DISPLAY_FIELDS[field] + ': ' + text


def managed_case_label(value):
    return value.casefold().startswith((PROFILE_LABEL_PREFIX, DISPLAY_LABEL_PREFIX.casefold())) or value.casefold() == CASE_LABEL.casefold()
CONTEXT_OPTIONS = {
    'employee_count': ('unknown', '0', '1-9', '10-49', '50-249', '250-999', '1000+'),
    'hosting_model': ('unknown', 'on_premises', 'colocation', 'dedicated_vps', 'shared_hosting', 'managed_hosting', 'cloud', 'mixed', 'other'),
    'it_operating_model': ('unknown', 'internal', 'external', 'mixed', 'no_dedicated_support'),
    'initial_access': ('unknown', 'software_vulnerability', 'stolen_credentials', 'phishing', 'misconfiguration', 'third_party', 'other'),
    'initial_access_status': ('unknown', 'suspected', 'confirmed'),
    'spread': ('web_application', 'web_server', 'other_servers', 'endpoints', 'identity_services', 'cloud_saas'),
    'data_exfiltration': OUTCOME_OPTIONS,
    'attacker_encryption': OUTCOME_OPTIONS,
    'discovered_by': ('unknown', 'internal_it', 'employee', 'it_provider', 'soc_mdr', 'customer', 'authority', 'attacker', 'other'),
    'discovery_method': ('unknown', 'monitoring', 'user_report', 'external_notification', 'ransom_note', 'incidental', 'other'),
}


def context_defaults():
    return {**{key: 'unknown' for key in CONTEXT_OPTIONS if key != 'spread'},
            'hosting_providers': [], 'spread': [], 'initial_cve': ''}


def context_labels(context):
    labels = {CASE_LABEL}
    for key, default in context_defaults().items():
        value = context.get(key, default)
        values = value if isinstance(value, list) else [value or 'unknown']
        for item in values or ['unknown']:
            labels.add(PROFILE_LABEL_PREFIX + key + ':' + item.strip().casefold())
            labels.add(display_label(key, item))
    return sorted(labels)


@lru_cache(maxsize=1)
def geography():
    root = Path(__file__).resolve().parents[1] / 'data'
    countries = [{"code": item['alpha_2'], "name": item.get('common_name', item['name'])}
                 for item in json.loads((root / 'iso3166-1.json').read_text(encoding='utf-8'))['3166-1']]
    countries.sort(key=lambda item: (0 if item['code'] == 'DE' else 1 if item['code'] == 'AT' else 2, item['name']))
    states = {}
    for item in json.loads((root / 'iso3166-2.json').read_text(encoding='utf-8'))['3166-2']:
        if not item.get('parent'):
            states.setdefault(item['code'].split('-')[0], []).append({'code': item['code'], 'name': item['name']})
    for entries in states.values():
        entries.sort(key=lambda item: item['name'])
    return {'countries': countries, 'states': states}
