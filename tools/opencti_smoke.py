"""Offline verification of the reduced OpenCTI export; never sends data."""
import argparse
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

from server import db, workspace
from server.integrations.opencti import graph


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true', required=True)
    parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix='shellhound-export-check-') as temporary:
        case = workspace.create_case(Path(temporary), 'Synthetic export', 'QA-EXPORT',
            profile={'organization_name': 'Manually entered QA organisation',
                     'summary': 'Synthetic data only', 'sectors': ['Technology'], 'countries': ['DE']})
        conn = db.connect(case)
        try:
            db.add_ioc(conn, '198.51.100.4', 'ip', ['manual-tag'])
            db.add_ioc(conn, 'CVE-2026-12345', 'vulnerability')
            db.add_ioc(conn, 'a' * 64, 'hash')
            db.add_ioc(conn, 'example.invalid', 'domain')
            conn.commit()
        finally:
            conn.close()
        with patch.object(graph, '_snapshot', side_effect=AssertionError('Unexpected file read')):
            result = graph.build_preview(case)
        assert not result['errors'], result['errors']
        assert {item['type'] for item in result['iocs']} == {'ip', 'vulnerability', 'hash'}
        assert not {'indicator', 'artifact', 'malware', 'domain-name'} & {obj['type'] for obj in result['objects']}
        assert any(obj.get('labels') == ['manual-tag'] for obj in result['objects'])
        print(json.dumps({'offline': True, 'objects': len(result['objects']), 'iocs': len(result['iocs']), 'errors': result['errors']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
