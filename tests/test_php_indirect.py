"""Static source-to-call evidence, including negative PHP lexical cases.

All fixtures are inert bytes analysed in memory; nothing is executed.
"""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from server import bundled_rules, db, settings, workspace
from server.app import create_app
from server.config import Config
from server.scan_retries import scanner_signature
from server.engines import php_indirect as indirect, webshell
from tests.test_scan_retry_api import LocalClient


class IndirectPhpTests(unittest.TestCase):
    def ids(self, body):
        return {row.rule_id for row in indirect.analyse(body)}

    def scan_ids(self, body):
        return {row[0] for row in webshell._yara_findings(body, 'content', indirect_php=True)}

    def test_request_copy_reaches_executable_call(self):
        body = b'<?php $value=$_POST["marker"]; system($value);'
        self.assertIn(indirect.INDIRECT, self.ids(body))
        self.assertIn(indirect.INDIRECT, self.scan_ids(body))

    def test_closing_tag_terminates_call_without_semicolon(self):
        for closing in (b'?>', b'?>plain HTML<?php echo "safe";'):
            body = b'<?php $value=$_POST["marker"]; system($value) '+closing
            self.assertIn(indirect.INDIRECT, self.scan_ids(body))
        # A closing tag inside a literal must not terminate PHP early.
        self.assertFalse(self.ids(b'''<?php $text='system($value) ?>';'''))

    def test_extended_detection_is_opt_in_and_skips_the_analyser(self):
        body = b'<?php $value=$_POST["marker"]; system($value);'
        with patch.object(indirect, 'analyse', side_effect=AssertionError('Mode is off')):
            self.assertFalse(set(row[0] for row in webshell._yara_findings(body, 'content')) & indirect.RULE_IDS)

    def test_alias_and_concatenation_preserve_request_origin(self):
        body = b'<?php $a=$_GET["marker"]; $b="prefix".$a; exec($b);'
        result = indirect.analyse(body)
        self.assertEqual([indirect.INDIRECT], [r.rule_id for r in result])
        self.assertEqual(body.index(b'$_GET'), result[0].source)

    def test_silenced_inline_assignment_is_not_missed(self):
        body = b'<?php @eval($value=$_POST["marker"]);'
        self.assertIn(indirect.INDIRECT, self.scan_ids(body))

    def test_request_selected_callable_is_evidence(self):
        body = b'<?php $callback=$_POST["name"]; $callback("marker");'
        self.assertIn(indirect.INDIRECT, self.scan_ids(body))

    def test_literal_executable_name_is_resolved_but_not_executed(self):
        for expression in (b'"sy"."stem"', b'"\\x73ystem"',
                           b'"\\163ystem"', b'base64_decode("c3lzdGVt")',
                           b'str_rot13("flfgrz")', b'strrev("metsys")',
                           b'hex2bin("73797374656d")'):
            with self.subTest(expression_length=len(expression)):
                self.assertIn(indirect.OBFUSCATED, self.scan_ids(
                    b'<?php $callback='+expression+b'; $callback("marker");'))

    def test_literal_name_assembled_through_variables(self):
        body = b'<?php $prefix="sy"; $callback=$prefix."stem"; $callback("marker");'
        self.assertIn(indirect.OBFUSCATED, self.scan_ids(body))

    def test_decoded_variable_used_in_eval(self):
        body = b'<?php\n$content=base64_decode("bWFya2Vy");\neval($content);'
        self.assertIn(indirect.DECODED, self.scan_ids(body))
        result = [r for r in webshell._yara_findings(body,'content', indirect_php=True) if r[0]==indirect.DECODED]
        self.assertEqual(3, result[0][3])
        self.assertIn('decoded at line 2', result[0][4])

    def test_request_decoding_then_eval_has_both_provenances(self):
        body = b'<?php $content=base64_decode($_POST["marker"]); eval($content);'
        self.assertTrue({indirect.DECODED, indirect.INDIRECT} <= self.scan_ids(body))

    def test_http_header_and_raw_body_are_request_sources(self):
        for source in (b'getenv("HTTP_X_MARKER")', b'getenv("QUERY_STRING")',
                       b'file_get_contents("php://input")', b'$HTTP_POST_VARS["marker"]'):
            self.assertIn(indirect.INDIRECT, self.scan_ids(
                b'<?php $value='+source+b'; system($value);'))

    def test_server_configuration_and_local_environment_are_not_request_parameters(self):
        for source in (b'$_SERVER["DOCUMENT_ROOT"]', b'$_ENV["PATH"]',
                       b'getenv("HTTP_X_MARKER", true)', b'$_POST'):
            self.assertNotIn(indirect.INDIRECT, self.ids(
                b'<?php $value='+source+b'; system($value);'))

    def test_stripslashes_does_not_remove_request_provenance(self):
        self.assertIn(indirect.INDIRECT, self.scan_ids(
            b'<?php $value=stripslashes($_POST["marker"]); eval($value);'))

    def test_known_callback_target_is_correlated(self):
        self.assertIn(indirect.INDIRECT, self.scan_ids(
            b'<?php $value=$_POST["marker"]; call_user_func("system", $value);'))
        self.assertIn(indirect.OBFUSCATED, self.scan_ids(
            b'<?php $callback="sy"."stem"; call_user_func($callback,"marker");'))

    def test_ordinary_callback_names_and_data_decoding_are_quiet(self):
        for body in (b'<?php $callback="str"."len"; $callback("marker");',
                     b'<?php $content=base64_decode("bWFya2Vy"); echo $content;',
                     b'<?php $marker="sy"."stem";',
                     b'<?php $value=$_POST["marker"]; call_user_func("strlen",$value);'):
            self.assertFalse(self.ids(body))

    def test_quoted_code_comments_html_and_heredocs_are_not_calls(self):
        examples = (
            b'<?php /* $v=$_POST["marker"]; system($v); */',
            b'<?php // $v=$_POST["marker"]; system($v);',
            b'''<?php $example='$v=$_POST["marker"]; system($v);';''',
            b'''<?php $example="unterminated; $v=$_POST['marker']; system($v);''',
            b'<html>$v=$_POST["marker"]; system($v);</html>',
            b'<?php $example=<<<NOTE\n$v=$_POST["marker"]; system($v);\nNOTE;')
        for body in examples:
            self.assertFalse(self.ids(body))

    def test_reassignment_unknown_call_and_scope_boundaries_discard_state(self):
        for middle in (b'$value="constant";', b'$value=intval($value);',
                       b'unknown_transform($value);', b'unset($value);',
                       b'function helper() {', b'if (true) {', b'$value++;'):
            self.assertNotIn(indirect.INDIRECT, self.ids(
                b'<?php $value=$_POST["marker"]; '+middle+b' system($value);'))

    def test_methods_are_not_builtin_sink_calls(self):
        for call in (b'$object->system($value)', b'Tools::system($value)'):
            self.assertFalse(self.ids(b'<?php $value=$_POST["marker"]; '+call+b';'))

    def test_global_function_prefix_and_invalid_variable_prefix(self):
        self.assertIn(indirect.INDIRECT, self.scan_ids(
            b'<?php $value=$_POST["marker"]; \\system($value);'))
        self.assertFalse(self.ids(
            b'<?php $callback="sy"."stem"; \\$callback("marker");'))

    def test_interpolation_single_quote_escapes_and_invalid_decoders_do_not_invent_names(self):
        for expression in (b"'\\x73ystem'", b'"sys${suffix}"',
                           b'hex2bin("73 797374656d")', b'base64_decode("!invalid!")'):
            self.assertNotIn(indirect.OBFUSCATED, self.ids(
                b'<?php $callback='+expression+b'; $callback("marker");'))

    def test_eval_is_not_a_php_variable_function(self):
        self.assertNotIn(indirect.OBFUSCATED, self.ids(
            b'<?php $callback="ev"."al"; $callback("marker");'))

    def test_limits_refuse_partial_statement_evidence(self):
        enormous = b'<?php $callback="sy"."stem".'+b'"x".'*indirect.MAX_TOKENS+b'"x"; $callback("marker");'
        self.assertFalse(self.ids(enormous))
        self.assertFalse(self.ids(b'<?php $callback="'+b'x'*indirect.MAX_LITERAL+b'"; $callback("marker");'))

    def test_evidence_offsets_and_original_line_numbers_are_retained(self):
        body = b'<?php\n$value=$_POST["marker"];\nsystem($value);'
        evidence = indirect.analyse(body)[0]
        self.assertEqual(body.index(b'system'), evidence.offset)
        result = [r for r in webshell._yara_findings(body,'content', indirect_php=True) if r[0]==indirect.INDIRECT]
        self.assertEqual([3], [r[3] for r in result])
        self.assertIn('request source at line 2', result[0][4])

    def test_rules_are_in_catalogue_and_analysis_is_candidate_gated(self):
        self.assertTrue(indirect.RULE_IDS <= set(bundled_rules.by_id()))
        with patch.object(indirect, 'analyse', side_effect=AssertionError('Unnecessary analysis')):
            self.assertEqual([], list(webshell._yara_findings(b'<?php echo "marker";','content', indirect_php=True)))


class DetectionModeTests(unittest.TestCase):
    def test_setting_is_validated_persisted_and_used_by_real_scans(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        root = Path(tmp)
        config = Config(workspace=root / 'cases', token='synthetic-test')
        case = workspace.create_case(config.workspace, 'Synthetic detection')
        evidence = root / 'evidence'
        evidence.mkdir()
        (evidence / 'marker.php').write_bytes(b'<?php $value=$_POST["marker"]; system($value) ?>')
        client = LocalClient(create_app(config), {'X-Token': config.token})
        self.addCleanup(client.close)
        self.assertFalse(client.get('/api/settings').json()['indirect_php'])
        signature = scanner_signature('webshell', config.workspace)

        def detected():
            webshell.scan(case, [str(evidence)], workspace=config.workspace)
            conn = db.connect(case)
            try:
                return db.rows(conn, "SELECT * FROM findings WHERE rule_id=? AND seen_run="
                               "(SELECT CAST(value AS INTEGER) FROM meta WHERE key='engine_done:webshell')", (indirect.INDIRECT,))
            finally:
                conn.close()

        with patch.object(indirect, 'analyse', side_effect=AssertionError('Disabled mode ran')):
            self.assertFalse(detected())
        self.assertEqual(401, client.post('/api/settings/detection', json={'indirect_php': True}, headers={'X-Token': 'wrong'}).status_code)
        for invalid in ('true', 1, None):
            self.assertEqual(422, client.post('/api/settings/detection', json={'indirect_php': invalid}).status_code)
        response = client.post('/api/settings/detection', json={'indirect_php': True})
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.json()['indirect_php'])
        self.assertTrue(settings.load(config.workspace)['indirect_php'])
        self.assertNotEqual(signature, scanner_signature('webshell', config.workspace))
        self.assertEqual(1, len(detected()))
        settings.set_ack(config.workspace, True)
        self.assertTrue(settings.load(config.workspace)['indirect_php'])
        response = client.post('/api/settings/detection', json={'indirect_php': False})
        self.assertFalse(response.json()['indirect_php'])
        self.assertTrue(response.json()['enrichment_ack'])
        self.assertEqual(signature, scanner_signature('webshell', config.workspace))
        self.assertFalse(detected())

if __name__ == '__main__':
    unittest.main()
