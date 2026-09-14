"""Review evidence remains scoped, bounded and read-only."""
import gzip
import sqlite3
import unittest
from unittest.mock import patch
from fastapi import HTTPException
from server import db
from server.artifact_review import successful_accesses, sql_preview
from server.engines import logindex
from tests import test_artifact_preview


class ReviewWorkspaceTests(unittest.TestCase):
    setUp = test_artifact_preview.ArtifactPreviewTests.setUp

    def make_index(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript("""CREATE TABLE requests(ip INTEGER,uri INTEGER,status INTEGER,epoch INTEGER);
            CREATE TABLE ips(id INTEGER,ip TEXT); CREATE TABLE strings(id INTEGER,text TEXT);
            INSERT INTO ips VALUES (1,'192.0.2.1'),(2,'192.0.2.2');
            INSERT INTO strings VALUES(1,'/example.txt?a=1'),(2,'/example.txt?a=2'),(3,'/other/example.txt'),(4,'/not-collected.txt');
            INSERT INTO requests VALUES(1,1,200,10),(1,2,206,20),(1,1,404,30),(2,1,200,40),(1,3,200,15),(1,4,200,16);""")
        return conn

    def test_successes_group_query_variants_filter_ip_and_status_and_link_exact_file(self):
        with patch.object(logindex, '_open_ro', return_value=self.make_index()):
            result = successful_accesses(self.case, '192.0.2.1')
        self.assertEqual(result['total'], 3)
        row = result['rows'][0]
        self.assertEqual((row['path'], row['hits'], row['last_epoch'], row['statuses']), ('/example.txt', 2, 20, [200,206]))
        self.assertEqual([file['path'] for file in row['files']], [str(self.file)])
        self.assertFalse(next(r for r in result['rows'] if r['path']=='/other/example.txt')['files'])
        self.assertFalse(next(r for r in result['rows'] if r['path']=='/not-collected.txt')['files'])

    def test_successes_paginate_without_losing_total(self):
        with patch.object(logindex, '_open_ro', return_value=self.make_index()):
            result = successful_accesses(self.case, '192.0.2.1', 1, 1)
        self.assertEqual(result['total'], 3)
        self.assertEqual(len(result['rows']), 1)
        with patch.object(logindex, '_open_ro', return_value=None):
            self.assertFalse(successful_accesses(self.case, '192.0.2.1')['available'])

    def test_ambiguous_local_paths_are_all_offered_not_silently_chosen(self):
        other = self.evidence.parent / 'second-root'
        other.mkdir()
        (other / self.file.name).write_text('Another harmless file', encoding='utf-8')
        conn = db.connect(self.case)
        conn.execute('INSERT INTO evidence(kind,path,added) VALUES(?,?,?)', ('webroot',str(other),db.now()))
        conn.commit(); conn.close()
        with patch.object(logindex, '_open_ro', return_value=self.make_index()):
            result = successful_accesses(self.case, '192.0.2.1')
        self.assertEqual(len(result['rows'][0]['files']), 2)

    def test_sql_compressed_preview_is_bounded_and_has_true_line_numbers(self):
        path = self.evidence / 'example.sql.gz'
        with gzip.open(path, 'wt', encoding='utf-8') as stream:
            stream.write('\n'.join(f'-- Safe SQL comment {i}' for i in range(1,301)))
        result = sql_preview(path, 120)
        self.assertEqual(result['focus'], 120)
        self.assertEqual(result['lines'][120-result['from_line']], '-- Safe SQL comment 120')
        self.assertEqual(len(result['lines']), 80)
        self.assertTrue(result['truncated'])
        path = self.evidence / 'huge.sql'
        path.write_text('x'*70000, encoding='utf-8')
        self.assertTrue(sql_preview(path)['truncated'])
        self.assertIn('error', sql_preview(self.evidence/'missing.sql'))

    def test_table_row_uses_case_owned_table_and_preserves_findings(self):
        path = self.evidence / 'rows.sql'
        path.write_text("INSERT INTO items(id,label) VALUES(1,'first'),(2,'second');", encoding='utf-8')
        conn = db.connect(self.case)
        dump = conn.execute('INSERT INTO db_dumps(path) VALUES(?)', (str(path),)).lastrowid
        table = conn.execute('INSERT INTO db_tables(dump_id,name,rows) VALUES(?,?,?)', (dump,'items',2)).lastrowid
        before = db.rows(conn, 'SELECT * FROM findings')
        conn.commit(); conn.close()
        endpoint = self.endpoints['/api/cases/{slug}/database/table-row']
        result = endpoint(self.case.name, table, 2, 'en')
        self.assertEqual(result['columns'][1]['value'], 'second')
        self.assertEqual(result['total_rows'], 2)
        for table_id, row, expected in [(table,0,400),(table,3,400),(9999,1,404)]:
            with self.assertRaises(HTTPException) as raised:
                endpoint(self.case.name,table_id,row,'en')
            self.assertEqual(raised.exception.status_code,expected)
        conn=db.connect(self.case)
        self.assertEqual(before,db.rows(conn,'SELECT * FROM findings'))
        conn.close()

    def test_sql_preview_rejects_unregistered_export(self):
        endpoint=self.endpoints['/api/cases/{slug}/database/sql-preview']
        with self.assertRaises(HTTPException) as raised:
            endpoint(self.case.name,str(self.file),None,False,'en')
        self.assertEqual(raised.exception.status_code,404)

    def test_file_enrichment_uses_current_digest_and_never_changed_snapshot(self):
        test_artifact_preview.ArtifactPreviewTests.decide(self,['webshell'])
        endpoint=self.endpoints['/api/cases/{slug}/artifact']
        initial=endpoint(self.case.name,str(self.file),'en')
        self.assertEqual(len(initial['ioc_ids']),1)
        self.file.write_text('Changed harmless content',encoding='utf-8')
        self.assertEqual(endpoint(self.case.name,str(self.file),'en')['ioc_ids'],[])

    def test_successful_access_endpoint_requires_current_registered_logs(self):
        conn = db.connect(self.case)
        conn.execute('INSERT INTO evidence(kind,path,added) VALUES(?,?,?)', ('access_logs', str(self.evidence / 'access.log'), db.now()))
        conn.commit(); conn.close()
        endpoint = self.endpoints['/api/cases/{slug}/artifact/accesses']
        with patch.object(logindex, 'status', return_value={'fresh': False}), patch('server.artifact_review.successful_accesses') as read:
            self.assertFalse(endpoint(self.case.name, '192.0.2.1')['available'])
            read.assert_not_called()
        for offset, limit in [(-1,50),(0,0),(0,101)]:
            with self.assertRaises(HTTPException):
                endpoint(self.case.name, '192.0.2.1', offset, limit)

    def request_index(self):
        conn = sqlite3.connect(':memory:')
        conn.row_factory = sqlite3.Row
        conn.executescript(logindex._LOG_SCHEMA)
        conn.execute("INSERT INTO ips(id,ip) VALUES(1,'192.0.2.1'),(2,'192.0.2.2')")
        conn.execute("INSERT INTO sources(id,path) VALUES(1,'/evidence/access.log')")
        uris = ['/tmp/review.php','/index.php','/wp-login.php','/administrator/index.php?option=com_content']
        for index, uri in enumerate(uris,1):
            conn.execute('INSERT INTO strings VALUES(?,?)',(index,uri))
        rows = [(1,1,200,'GET'),(1,1,404,'GET'),(1,2,200,'GET'),(2,1,200,'GET'),(1,1,206,'POST'),(1,3,200,'GET'),(1,3,403,'POST'),(1,4,200,'GET')]
        for line, (ip,uri,status,method) in enumerate(rows,1):
            conn.execute('INSERT INTO requests(ip,uri,status,method,epoch,tz,size,source,line_no) VALUES(?,?,?,?,?,0,42,1,?)',(ip,uri,status,method,line,line))
        conn.commit()
        return conn

    def test_finding_requests_filter_rule_ip_outcome_and_paginate(self):
        from server.artifact_review import finding_requests
        finding={'artifact':'192.0.2.1','rule_id':'logs.upload_php','source':'logs'}
        with patch.object(logindex,'open_readonly',return_value=self.request_index()):
            result=finding_requests(self.case,finding,1,1)
        self.assertEqual(result['total'],2)
        self.assertEqual(len(result['rows']),1)
        self.assertEqual(result['rows'][0]['status'],206)
        self.assertEqual(result['rows'][0]['line'],5)
        self.assertEqual(result['rows'][0]['source'],'access.log')
        with patch.object(logindex,'open_readonly',return_value=self.request_index()):
            flood=finding_requests(self.case,dict(finding,rule_id='logs.login_flood'))
        self.assertEqual([r['line'] for r in flood['rows']],[7])
        with patch.object(logindex,'open_readonly',return_value=self.request_index()):
            login=finding_requests(self.case,dict(finding,rule_id='logs.login_success'))
        self.assertEqual([r['line'] for r in login['rows']],[7,8])

    def test_finding_requests_do_not_substitute_full_trace_for_unknown_or_retired(self):
        from server.artifact_review import finding_requests
        with patch.object(logindex,'open_readonly') as read:
            self.assertEqual(finding_requests(self.case,{'rule_id':'other.rule'})['reason'],'unsupported')
            self.assertEqual(finding_requests(self.case,{'rule_id':'logs.upload_php','retired':1})['reason'],'retired')
            read.assert_not_called()

    def test_finding_request_endpoint_rejects_non_client_or_foreign_finding(self):
        endpoint=self.endpoints['/api/cases/{slug}/artifact/finding-requests']
        for identifier in (1,99999):
            with self.assertRaises(HTTPException) as raised:
                endpoint(self.case.name,identifier)
            self.assertEqual(raised.exception.status_code,404)

    def test_finding_request_endpoint_preserves_retirement_status(self):
        conn=db.connect(self.case)
        run=db.begin_run(conn,'logindex')
        db.upsert_finding(conn,'logs',0,'Upload rule','client','192.0.2.1',rule_id='logs.upload_php',engine='logindex',run=run)
        identifier=conn.execute("SELECT id FROM findings WHERE artifact_kind='client'").fetchone()[0]
        db.complete_run(conn,'logindex',run+1)
        conn.execute('INSERT INTO evidence(kind,path,added) VALUES(?,?,?)',('access_logs',str(self.evidence/'access.log'),db.now()))
        conn.commit();conn.close()
        with patch.object(logindex,'status',return_value={'fresh':True}),patch.object(logindex,'open_readonly') as read:
            result=self.endpoints['/api/cases/{slug}/artifact/finding-requests'](self.case.name,identifier)
            self.assertEqual(result['reason'],'retired')
            read.assert_not_called()

    def test_trace_finding_marks_cover_all_matching_paths_and_preserve_pagination(self):
        def index():
            conn=self.request_index()
            conn.execute("INSERT INTO strings VALUES(10,'/tmp/second.php')")
            conn.execute("INSERT INTO requests(ip,uri,status,method,epoch) VALUES(1,10,200,'GET',9)")
            conn.commit()
            return conn
        rules={'192.0.2.1':['upload_php']}
        with patch.object(logindex,'_open_ro',return_value=index()):
            result=logindex.trace(self.case,['192.0.2.1'],finding_rules=rules)
        self.assertEqual(sum(r['finding_match'] for r in result['rows']),3)
        self.assertFalse(next(r for r in result['rows'] if r['status']==404)['finding_match'])
        with patch.object(logindex,'_open_ro',return_value=index()):
            page=logindex.trace(self.case,['192.0.2.1'],finding_rules=rules,evidence_only=True,limit=1,offset=2)
        self.assertEqual(page['total'],3)
        self.assertEqual(page['rows'][0]['uri'],'/tmp/second.php')
        self.assertTrue(page['rows'][0]['finding_match'])
        with patch.object(logindex,'_open_ro',return_value=index()):
            empty=logindex.trace(self.case,['192.0.2.2'],finding_rules=rules,evidence_only=True,mark_exact=['/tmp/review.php'])
        self.assertEqual(empty['total'],0)

    def test_trace_finding_scope_rejects_other_clients_and_ignores_retired_findings(self):
        conn=db.connect(self.case)
        run=db.begin_run(conn,'logindex')
        db.upsert_finding(conn,'logs',0,'Upload rule','client','192.0.2.1',rule_id='logs.upload_php',engine='logindex',run=run)
        identifier=conn.execute("SELECT id FROM findings WHERE artifact_kind='client'").fetchone()[0]
        db.complete_run(conn,'logindex',run+1)
        conn.execute('INSERT INTO evidence(kind,path,added) VALUES(?,?,?)',('access_logs',str(self.evidence/'access.log'),db.now()))
        conn.commit();conn.close()
        endpoint=self.endpoints['/api/cases/{slug}/trace']
        body_type=endpoint.__annotations__['body']
        with patch.object(logindex,'status',return_value={'fresh':True}),patch.object(logindex,'index_fingerprint',return_value='current'),patch.object(logindex,'trace',return_value={'rows':[],'total':0}) as trace:
            body=body_type(ips=['192.0.2.1'],finding_ids=[identifier])
            endpoint(self.case.name,body)
            self.assertEqual(trace.call_args.args[-1],{})
            with self.assertRaises(HTTPException) as raised:
                endpoint(self.case.name,body_type(ips=['192.0.2.2'],finding_ids=[identifier]))
            self.assertEqual(raised.exception.status_code,400)
