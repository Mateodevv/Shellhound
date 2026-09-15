"""Provider boundaries: explicit reads, cache integrity and credential handling."""
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch, MagicMock
from server import db
from server.integrations import enrich
from server import settings, workspace

class DirectEnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.ws=Path(self.temp.name);self.case=workspace.create_case(self.ws,'Demo')
        for service in settings.SERVICES:settings.set_key(self.ws,service,'test-private-key')
    def test_reports_are_read_once_then_cached_and_refresh_is_explicit(self):
        data={'data':{'attributes':{'last_analysis_stats':{'malicious':2,'undetected':8},'last_analysis_results':{'Demo':{'category':'malicious','result':'Synthetic'}},'tags':['sample']}}}
        with patch.object(enrich,'_get',return_value=data) as remote:
            one=enrich.lookup(self.ws,self.case,'virustotal','A'*64,kind='file')
            two=enrich.lookup(self.ws,self.case,'virustotal','a'*64,kind='hash')
            self.assertEqual(1,remote.call_count);self.assertTrue(two['cached'])
            self.assertEqual((2,10),(one['result']['score'],one['result']['of']))
            self.assertEqual('hash',one['kind'])
            enrich.lookup(self.ws,self.case,'virustotal','a'*64,True)
            self.assertEqual(2,remote.call_count)
        c=db.connect(self.case)
        self.assertEqual(0,c.execute('SELECT count(*) FROM findings').fetchone()[0]);c.close()
    def test_all_supported_vt_types_and_url_report_id(self):
        for value,kind,path in [('1.1.1.1','ip','ip_addresses/1.1.1.1'),('EXAMPLE.test','domain','domains/example.test'),('https://example.test/Some?x=1','url','urls/')]:
            with self.subTest(kind=kind), patch.object(enrich,'_get',return_value={'data':{'id':'b'*64,'attributes':{}}}) as remote:
                result=enrich.lookup(self.ws,self.case,'virustotal',value,kind=kind)
                self.assertIn(path,remote.call_args.args[0])
                if kind=='url':self.assertTrue(result['result']['permalink'].endswith('b'*64))
    def test_abuse_ipv6_report_and_fixed_window(self):
        with patch.object(enrich,'_get',return_value={'data':{'abuseConfidenceScore':0,'totalReports':0,'numDistinctUsers':0,'isTor':False}}) as remote:
            result=enrich.lookup(self.ws,self.case,'abuseipdb','2001:db8::1')
            self.assertEqual(0,result['result']['score'])
            self.assertIn('maxAgeInDays=90',remote.call_args.args[0]);self.assertIn('ipAddress=2001%3Adb8%3A%3A1',remote.call_args.args[0])
    def test_unsupported_and_invalid_values_never_leave_machine(self):
        with patch.object(enrich,'_get') as remote:
            for service,value,kind in [('abuseipdb','a'*64,'hash'),('virustotal','CVE-2023-1234','vulnerability'),('virustotal','../file.php','file'),('virustotal','bad-ip','ip'),('virustotal','https://user:pass@example.test','url'),('virustotal','example.test/path','domain')]:
                with self.subTest(value=value),self.assertRaises(enrich.EnrichError):enrich.lookup(self.ws,self.case,service,value,kind=kind)
            remote.assert_not_called()
    def test_opencti_prevents_direct_calls_even_with_key(self):
        settings.set_opencti(self.ws,{'url':'https://cti.example','token':'test-token','ingester_id':'dba5717c-b7d1-474f-8aad-bf9c2d61312c'})
        with patch.object(enrich,'_get') as remote,self.assertRaises(enrich.EnrichError) as raised:enrich.lookup(self.ws,self.case,'abuseipdb','1.1.1.1')
        self.assertEqual(409,raised.exception.status);remote.assert_not_called()
    def test_failed_refresh_keeps_last_success(self):
        with patch.object(enrich,'_get',return_value={'data':{'abuseConfidenceScore':15}}):enrich.lookup(self.ws,self.case,'abuseipdb','1.1.1.1')
        with patch.object(enrich,'_get',side_effect=enrich.EnrichError('Limit',429)),self.assertRaises(enrich.EnrichError):enrich.lookup(self.ws,self.case,'abuseipdb','1.1.1.1',True)
        result=enrich.lookup(self.ws,self.case,'abuseipdb','1.1.1.1');self.assertEqual(15,result['result']['score'])
    def test_unknown_vt_report_is_not_a_zero_score(self):
        with patch.object(enrich,'_get',return_value=None):result=enrich.lookup(self.ws,self.case,'virustotal','a'*64)
        self.assertFalse(result['result']['known']);self.assertNotIn('score',result['result'])
    def test_http_errors_do_not_expose_provider_body_or_key(self):
        for status,expected in [(401,403),(403,403),(429,429),(500,502),(302,502)]:
            opener=MagicMock();opener.open.side_effect=urllib.error.HTTPError('https://example.test',status,'test-private-key',{},None)
            with self.subTest(status=status),patch('urllib.request.build_opener',return_value=opener),self.assertRaises(enrich.EnrichError) as raised:enrich._get('https://www.virustotal.com/api/v3/files/test',{'x-apikey':'test-private-key'})
            self.assertEqual(expected,raised.exception.status);self.assertNotIn('test-private-key',str(raised.exception))
    def test_transport_is_get_only_and_redirects_disabled(self):
        opener=MagicMock();opener.open.return_value.__enter__.return_value.read.return_value=b'{"data":{}}'
        with patch('urllib.request.build_opener',return_value=opener) as build:enrich._get('https://www.virustotal.com/api/v3/files/test',{'x-apikey':'test-key'})
        self.assertIsInstance(build.call_args.args[0],enrich._NoRedirect)
        req=opener.open.call_args.args[0];self.assertEqual('GET',req.method);self.assertIsNone(req.data)
        self.assertIsNone(enrich._NoRedirect().redirect_request(None,None,302,'',{},'https://other.example'))
    def test_header_injection_unknown_providers_rejected(self):
        for service,key in [('other','secret'),('virustotal','key\nOther: x')]:
            with self.assertRaises(ValueError):settings.set_key(self.ws,service,key)

if __name__=='__main__':unittest.main()
