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
