"""Local profile validation data and the fixed main-sector catalogue."""
import json
from functools import lru_cache
from pathlib import Path

SECTORS = (
    'Public administration', 'Healthcare', 'Financial services', 'Energy',
    'Water and wastewater', 'Technology', 'Telecommunications',
    'Transport and logistics', 'Manufacturing', 'Retail', 'Food and agriculture',
    'Education and research', 'Media and culture', 'Professional services',
    'Construction and real estate', 'Hospitality and tourism',
    'Non-profit organisations', 'Other',
)


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
