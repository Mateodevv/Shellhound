"""Local geographic choices and read-only OpenCTI sector taxonomy."""
import hashlib
import json
import threading
import time
from functools import lru_cache
from pathlib import Path

from server import settings
from server.opencti_client import OpenCTIClient, OpenCTIError

_CACHE = {}
_LOCK = threading.Lock()


@lru_cache(maxsize=1)
def geography():
    root = Path(__file__).with_name('data')
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


def sectors(workspace):
    config = settings.opencti_config(workspace)
    if not config.get('url') or not config.get('token'):
        return {'sectors': [], 'stale': False}
    key = hashlib.sha256(json.dumps([config.get('url'), config.get('token')]).encode()).hexdigest()
    with _LOCK:
        cached = _CACHE.get(key)
        if cached and time.monotonic() - cached[0] < 900:
            return {'sectors': cached[1], 'stale': False}
        try:
            entries = OpenCTIClient(config).sectors()
        except OpenCTIError:
            if cached:
                return {'sectors': cached[1], 'stale': True}
            raise
        _CACHE[key] = (time.monotonic(), entries)
        return {'sectors': entries, 'stale': False}
