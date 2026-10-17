"""Keep legitimate CMS constructs quiet without trusting CMS paths or guards."""
import tempfile
import unittest
from pathlib import Path

from server.engines import webshell


class CmsDetectionContextTests(unittest.TestCase):
    def findings(self, body, relative='plugin.php'):
        with tempfile.TemporaryDirectory(prefix='shellhound-cms-context-') as directory:
            root = Path(directory)
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            found, skipped, _inert = webshell.scan_file(str(path), root=str(root))
            self.assertIsNone(skipped)
            return {finding[0] for finding in found}

    def test_internal_underscore_variable_is_not_a_request_callback(self):
        self.assertNotIn('webshell.callback_input', self.findings(
            b"<?php call_user_func($_handler['callback'], $value);"))
        self.assertIn('webshell.callback_input', self.findings(
            b"<?php CALL_USER_FUNC($_POST['callback'], $value);"))

    def test_comment_is_not_a_variable_function_call(self):
        self.assertNotIn('webshell.var_func', self.findings(
            b'<?php // combine $_REQUEST ( $_GET + $_POST ).\n'))
        self.assertIn('webshell.var_func', self.findings(
            b"<?php $callback($_POST['value']);"))

    def test_quotes_and_heredocs_do_not_start_comments(self):
        for prefix in (b'$url = "https://example.invalid/"; ',
                       b"$value = '/* documentation */'; ",
                       b'$text = <<<NOTE\n// documentation\nNOTE;\n'):
            with self.subTest(prefix_kind=prefix[:4]):
                self.assertIn('webshell.var_func', self.findings(
                    b'<?php ' + prefix + b"$callback($_POST['value']);"))

    def test_html_urls_and_php_close_tags_preserve_following_code(self):
        for prefix in (b'https://example.invalid/ ',
                       b'<?php // documentation ?> ',
                       b'<?xml version="1.0"?> '):
            self.assertIn('webshell.var_func', self.findings(
                prefix + b"<?php $callback($_POST['value']);"))

    def test_comment_filter_keeps_original_line_numbers(self):
        raw = b'<?php\n// combine $_REQUEST ( $_GET ).\n$callback($_POST["value"]);'
        findings = [row for row in webshell._yara_findings(raw, 'content')
                    if row[0] == 'webshell.var_func']
        self.assertEqual([3], [row[3] for row in findings])

    def test_php_attribute_is_not_a_hash_comment(self):
        self.assertIn('webshell.var_func', self.findings(
            b'<?php #[Marker] function handler() { $callback($_POST["value"]); }'))

    def test_binary_escapes_are_not_text_obfuscation(self):
        binary = ''.join('\\x%02x' % n for n in range(16)).encode()
        self.assertNotIn('webshell.hex_octal', self.findings(
            b'<?php $magic = "' + binary + b'";'))
        encoded = ''.join('\\x%02x' % n for n in b'printable_marker_text').encode()
        self.assertIn('webshell.hex_octal', self.findings(
            b'<?php $marker = "' + encoded + b'";'))

    def test_named_parser_exits_are_not_goto_obfuscation(self):
        ordinary = b'<?php ' + b'goto incomplete; ' * 12
        self.assertNotIn('webshell.goto', self.findings(ordinary))
        descriptive = b'<?php ' + b' '.join(b'goto ' + name + b';' for name in
            (b'in_body_loop', b'after_head', b'incomplete', b'anything_else'))
        self.assertNotIn('webshell.goto', self.findings(descriptive))
        generated = b'<?php goto A01; goto B02; goto C03; goto D04;'
        self.assertIn('webshell.goto', self.findings(generated))

    def test_comment_targets_do_not_correlate_with_real_gotos(self):
        self.assertNotIn('webshell.goto', self.findings(
            b'<?php /* goto A01; goto B02; goto C03; goto D04; */ goto incomplete;'))

    def test_library_command_helper_needs_an_external_source(self):
        helper = b'<?php function helper($command) { return shell_exec($command); }'
        self.assertNotIn('webshell.standalone_exec', self.findings(helper))
        for source in (b'$value = $_POST["value"];',
                       b'$value = $HTTP_POST_VARS["value"];',
                       b'$value = getenv("HTTP_ACCEPT_LANGUAGE");',
                       b'$value = GETENV("HTTP_ACCEPT_LANGUAGE");',
                       b'$stream = fsockopen("example.invalid", 1);'):
            self.assertIn('webshell.standalone_exec', self.findings(helper + source))
        self.assertNotIn('webshell.standalone_exec', self.findings(
            helper + b' // $_POST and fsockopen("example.invalid", 1)'))

    def test_namespace_cache_is_not_storage_but_uploads_remain_storage(self):
        marker = b'<?php $value = $_POST["value"];'
        self.assertNotIn('webshell.upload_php', self.findings(marker, 'src/Cache/Entry.php'))
        for relative in ('cache/entry.php', 'wp-content/cache/entry.php',
                         'uploads/src/Cache/entry.php', 'images/src/Cache/entry.php'):
            with self.subTest(relative=relative):
                self.assertIn('webshell.upload_php', self.findings(marker, relative))

    def test_library_cache_still_receives_content_rules(self):
        self.assertIn('webshell.var_func', self.findings(
            b"<?php $callback($_POST['value']);", 'src/Cache/Entry.php'))

    def test_guard_word_does_not_whitelist_content_inside_core_paths(self):
        self.assertIn('webshell.var_func', self.findings(
            b"<?php /* ABSPATH */ $callback($_POST['value']);",
            'wp-includes/vendor/src/Cache/Entry.php'))


if __name__ == '__main__':
    unittest.main()
