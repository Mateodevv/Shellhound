import json
import tempfile
import unittest
from pathlib import Path
from fastapi import HTTPException
from server import db, workspace
from server.app import create_app
from server.config import Config
from server.ioc import model
from server.ioc.software import collect, sync_inventory
from server.integrations.opencti.graph import build_preview

class SoftwareIocTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = workspace.create_case(self.root, 'Software test', 'SOFT-001')
        self.conn = db.connect(self.case)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO cms_installs(root,cms,version,version_source) VALUES ('/evidence/site','WordPress','6.5','version.php')")
        self.install = self.conn.execute('SELECT id FROM cms_installs').fetchone()[0]
        self.conn.execute("INSERT INTO cms_items(install_id,type,name,slug,version,path,version_source) VALUES (?,'Plugin','Example plugin','example','1.2','/evidence/site/plugins/example','header')", (self.install,))
        self.conn.commit()

    def test_cms_is_unassessed_deduplicated_and_deletion_is_respected(self):
        sync_inventory(self.conn)
        sync_inventory(self.conn)
        rows = db.rows(self.conn, 'SELECT * FROM iocs')
        self.assertEqual(1, len(rows))
        self.assertEqual(('software', 'WordPress', 'unassessed'), (rows[0]['type'], rows[0]['value'], rows[0]['assessment']))
        self.assertEqual('6.5', json.loads(rows[0]['context'])['version'])
        self.assertEqual(0, self.conn.execute('SELECT count(*) FROM ioc_assessments').fetchone()[0])
        self.conn.execute('DELETE FROM iocs WHERE id=?', (rows[0]['id'],))
        sync_inventory(self.conn)
        self.assertEqual(0, self.conn.execute('SELECT count(*) FROM iocs').fetchone()[0])

    def test_plugin_explicit_collection_uses_corrected_version_and_checks_source(self):
        app = create_app(Config(workspace=self.root, token='synthetic'))
        endpoint = next(r.endpoint for r in app.routes if getattr(r,'path','') == '/api/cases/{slug}/cms/items/{item_id}/ioc')
        body = endpoint.__annotations__['body']
        item = self.conn.execute('SELECT id FROM cms_items').fetchone()[0]
        self.conn.execute("INSERT INTO cms_version_overrides(scope,key,version,note,set_at) VALUES ('item','/evidence/site|Plugin|example','1.3','','')")
        self.conn.commit()
        with self.assertRaises(HTTPException):
            endpoint(self.case.name, item, body(expected_path='/wrong'))
        first = endpoint(self.case.name, item, body(expected_path='/evidence/site/plugins/example'))
        self.assertEqual(first, endpoint(self.case.name, item, body(expected_path='/evidence/site/plugins/example')))
        row = db.one(self.conn, 'SELECT * FROM iocs WHERE id=?', (first['id'],))
        self.assertEqual('1.3', json.loads(row['context'])['version'])
        self.assertEqual('unassessed', row['assessment'])
        self.assertEqual(1, self.conn.execute('SELECT count(*) FROM ioc_observations').fetchone()[0])

    def test_software_export_obeys_ioc_selection_without_indicator(self):
        identifier = collect(self.conn, 'Joomla', '5.2')
        self.conn.commit()
        full = build_preview(self.case, {'ioc_ids':[identifier]})
        obj = next(o for o in full['objects'] if o['type']=='software')
        self.assertEqual(('Joomla','5.2'), (obj['name'],obj['version']))
        self.assertFalse(full['iocs'][0]['indicator_supported'])
        self.assertFalse(any(o['type']=='software' for o in build_preview(self.case, {'ioc_ids':[]})['objects']))

    def test_legacy_profile_migrates_once_and_preserves_context(self):
        profile = {'software':[{'name':'Legacy CMS','version':'2'}], 'vulnerabilities':[{'name':'CVE-2025-12345','status':'suspected','description':'Review required'}]}
        identity = json.loads((self.case / 'case.json').read_text(encoding='utf-8'))
        identity['profile'] = profile
        (self.case / 'case.json').write_text(json.dumps(identity), encoding='utf-8')
        self.conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES ('profile',?)", (json.dumps(profile),))
        self.conn.execute("UPDATE meta SET value='20' WHERE key='schema_version'")
        self.conn.commit()
        reopened = db.connect(self.case)
        try:
            rows = db.rows(reopened, 'SELECT * FROM iocs')
            self.assertEqual({'software','vulnerability'}, {r['type'] for r in rows})
            self.assertIn('Review required', next(r['note'] for r in rows if r['type']=='vulnerability'))
            self.assertEqual(1, sum(r['value']=='Legacy CMS' for r in rows))
        finally:
            reopened.close()
