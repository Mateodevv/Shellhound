# tests/test_yara_translation.py
"""The bundled YARA rules against the regexes they replaced.

THE REFERENCE REGEXES BELOW ARE FROZEN COPIES, on purpose. They are what
`server/engines/webshell.py` matched with before the content rules became
YARA, and they are kept here so the translation can be checked against
something rather than against a memory of it. They are a test fixture, not a
second implementation: nothing outside this file imports them.

WHAT THIS ACTUALLY CATCHES. Three differences between a Python regex applied
LINE BY LINE and a YARA rule applied to a WHOLE FILE, in rising order of how
easy they are to miss:

  1. `.` stops at a newline in both. Free.
  2. `[^;]` does not -- a negated class crosses a line break happily.
  3. `\\s` does not either, and it appears in nearly every rule. This is the
     one that hides: `eval(` on one line and `base64_decode($_POST` on the
     next would match a rule that never used to see them together.

So the sample set is not a list of hand-written cases. Every sample is also
re-tested with a newline injected after each opening bracket, quote and
space -- which is precisely the mutation that exposes (2) and (3), and
precisely the one a human writing samples by hand does not think of.
"""
import re
import unittest
from pathlib import Path

try:
    import yara
except ImportError:                        # pragma: no cover - host dependent
    yara = None

RULES_DIR = Path(__file__).resolve().parent.parent / "server" / "rules_bundled"

# --- frozen: what these rules matched before the translation ---------------
REFERENCE = {
    "webshell.eval_input": re.compile(
        r"(?i)\b(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|\$_(POST|GET|REQUEST|COOKIE))"),
    "webshell.var_func": re.compile(
        r"\$\w+\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)"),
    "webshell.cmd_input": re.compile(
        r"(?i)(shell_exec|passthru|proc_open|popen|pcntl_exec|system|exec)\s*\(\s*[^;]{0,40}\$_(POST|GET|REQUEST|COOKIE|SERVER)"),
    "webshell.preg_e": re.compile(
        r"(?i)preg_replace\s*\(\s*(['\"]).*?[/#~|!%@][a-zA-Z]*e[a-zA-Z]*\1"),
    "webshell.create_function": re.compile(
        r"(?i)(create_function\s*\(\s*['\"]|call_user_func(_array)?\s*\(\s*\$_)"),
    "webshell.dropper": re.compile(
        r"(?i)(move_uploaded_file|file_put_contents|fwrite)\s*\(.{0,80}\$_(POST|GET|REQUEST|FILES)"),
    # NO PREDECESSOR. These two rules were carved out of the two above when
    # those turned out to make a claim they could not support; there is no
    # frozen regex to be equivalent to. They stay in this table because the
    # id and severity bookkeeping below must still cover every shipped rule.
    "webshell.callback_input": None,
    "webshell.upload_dest": None,
    "webshell.no_php": None,
    "webshell.obfuscation": re.compile(
        r"(?i)(base64_decode\s*\(\s*(str_rot13|strrev|gzinflate|gzuncompress)|gzinflate\s*\(\s*(base64_decode|str_rot13)|str_rot13\s*\(\s*base64_decode)"),
    "webshell.hex_octal": re.compile(
        r"((\\x[0-9a-fA-F]{2}|\\[0-7]{3})){10,}"),
    "webshell.chr_concat": re.compile(
        r"(?i)(chr\s*\(\s*\d+\s*\)\s*\.\s*){5,}"),
    "webshell.goto": re.compile(r"(?i)\bgoto\s+\w{1,20}\s*;"),
    "webshell.standalone_exec": re.compile(
        r"(?i)\b(shell_exec|passthru|proc_open|pcntl_exec)\s*\("),
    "webshell.htaccess_handler": re.compile(
        r"(?i)(AddHandler|AddType|SetHandler)[^\n]*(php|x-httpd)"),
    "webshell.htaccess_prepend": re.compile(r"(?i)auto_(prepend|append)_file"),
}

BASE_SAMPLES = [
    # eval / assert
    "<?php eval(base64_decode($_POST['x'])); ?>",
    "<?php @eval  ( gzinflate($_GET['c']) );",
    "<?php EVAL(STR_ROT13($_REQUEST['q']));",
    "<?php eval($harmless);",
    "<?php assert(strrev($_COOKIE['z']));",
    # variable function -- case-sensitive on the superglobal
    "<?php $f = 'system'; $f($_POST['cmd']);",
    "<?php $fn($_GET['a']);",
    "<?php $fn($_get['a']);",
    # command execution on request input
    "<?php system('ls -la '.$_GET['d']);",
    "<?php shell_exec($_SERVER['HTTP_X']);",
    "<?php exec($safe);",
    # preg_replace /e
    "<?php preg_replace('/(.*)/e', 'system($1)', $x);",
    '<?php preg_replace("#(.*)#ie", "eval($1)", $y);',
    "<?php preg_replace('/(.*)/', 'plain', $z);",
    "<?php preg_replace('/x/', 'a', $z); // e",
    # create_function / callbacks
    "<?php create_function('$a', 'return 1;');",
    "<?php call_user_func_array($_POST['f'], []);",
    "<?php call_user_func($safe, 1);",
    # droppers
    "<?php file_put_contents('s.php', $_POST['c']);",
    "<?php move_uploaded_file($_FILES['f']['tmp_name'], 'x');",
    "<?php fwrite($h, 'static');",
    # decode chains
    "<?php $s = base64_decode(str_rot13($blob));",
    "<?php $s = gzinflate(base64_decode($b));",
    "<?php $s = base64_decode($plain);",
    # escaped-byte runs
    '<?php $x = "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b";',
    '<?php $x = "\\101\\102\\103\\104\\105\\106\\107\\110\\111\\112\\113";',
    '<?php $x = "\\x41\\x42";',
    # chr() chains
    "<?php $s = chr(72).chr(101).chr(108).chr(108).chr(111).chr(33);",
    "<?php $s = chr(72).chr(101);",
    # goto, standalone exec, and plain text
    "<?php goto cleanup; cleanup: echo 1;",
    "<?php $label = 5;",
    "<?php passthru('id');",
    "<?php echo 'hello world';",
    # .htaccess
    "AddHandler application/x-httpd-php .jpg",
    "AddType text/plain .txt",
    "SetHandler application/x-httpd-php7",
    "php_value auto_prepend_file /tmp/x.php",
    "Options -Indexes",
    # two lines that must never be read as one match
    "<?php system(); \n $_GET['x'];",
    "<?php eval();\nbase64_decode($_POST['p']);",
]


def samples():
    """Every sample, plus the same sample with a newline injected after each
    bracket, quote and space. That mutation is what finds a quantifier still
    allowed to cross a line."""
    out = list(BASE_SAMPLES)
    for text in BASE_SAMPLES:
        for i, char in enumerate(text):
            if char in "( '\"":
                out.append(text[:i + 1] + "\n" + text[i + 1:])
    return out


def reference_hits(rule_id, text):
    """The frozen rule, applied the way it used to be: line by line."""
    return any(REFERENCE[rule_id].search(line) for line in text.splitlines())


@unittest.skipIf(yara is None, "yara-python not installed")
class TranslationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.compiled = [
            yara.compile(source=(RULES_DIR / name).read_text(encoding="utf-8"))
            for name in ("webshell_content.yar", "webshell_htaccess.yar")]

    def _yara_hits(self, text):
        found = set()
        for rules in self.compiled:
            for match in rules.match(data=text.encode()):
                found.add(match.meta.get("id"))
        return found

    def test_every_bundled_file_compiles(self):
        self.assertEqual(2, len(self.compiled))

    def test_every_reference_rule_exists_in_yara(self):
        """A rule that quietly failed to be translated would show up here as
        a rule that never matches anything."""
        declared = set()
        for name in ("webshell_content.yar", "webshell_htaccess.yar"):
            text = (RULES_DIR / name).read_text(encoding="utf-8")
            declared |= set(re.findall(r'id\s*=\s*"([^"]+)"', text))
        self.assertEqual(set(REFERENCE), declared)

    # DELIBERATELY NOT EQUIVALENT. The equivalence table proves each YARA
    # rule kept the meaning of the regex it replaced. These must NOT keep it,
    # because the regex was wrong about what it found -- and a rule that is
    # wrong about what it found is worse than one that finds less. They stay
    # in REFERENCE so the id and severity bookkeeping below still covers
    # them; their behaviour is asserted directly in
    # test_regressions.EngineHonestyTests.
    #
    #   htaccess_handler  fired on every handler line mentioning PHP,
    #                     including the `AddHandler ... .php .php8 .phtml`
    #                     block every shared host ships, and called those
    #                     "non-PHP extensions".
    #   create_function   said "on request input" about `create_function`,
    #                     which names no superglobal.
    #   dropper           said "that is how the next shell arrives" about
    #                     `move_uploaded_file`, the one correct idiom.
    CORRECTED = {"webshell.htaccess_handler", "webshell.create_function",
                 "webshell.dropper"}

    def test_the_translation_matches_the_originals_exactly(self):
        cases = samples()
        self.assertGreater(len(cases), 100, "the mutation step did nothing")
        mismatches = []
        for text in cases:
            found = self._yara_hits(text)
            for rule_id in REFERENCE:
                if rule_id in self.CORRECTED or REFERENCE[rule_id] is None:
                    continue
                want = reference_hits(rule_id, text)
                if want != (rule_id in found):
                    mismatches.append(
                        f"{rule_id}: regex={want} yara={rule_id in found} "
                        f"on {text!r}")
        self.assertEqual([], mismatches[:20])

    def test_the_case_sensitive_rule_stayed_case_sensitive(self):
        """PHP superglobals are case-sensitive. A `nocase` added here by
        tidiness would widen the rule without anybody deciding to."""
        self.assertTrue(self._yara_hits("<?php $fn($_GET['a']);"))
        self.assertNotIn("webshell.var_func",
                         self._yara_hits("<?php $fn($_get['a']);"))

    def test_severities_are_declared_and_known(self):
        text = "".join((RULES_DIR / n).read_text(encoding="utf-8")
                       for n in ("webshell_content.yar", "webshell_htaccess.yar"))
        severities = re.findall(r'severity\s*=\s*"([^"]+)"', text)
        self.assertEqual(len(REFERENCE), len(severities))
        self.assertEqual(set(), set(severities) - {"high", "medium", "low", "info"})


if __name__ == "__main__":
    unittest.main()
