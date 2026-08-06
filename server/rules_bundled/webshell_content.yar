/*
    SHELLHOUND -- content rules for PHP files in the webroot.

    These ship inside the package and are read-only. They are the same on
    every installation of a version, which is what lets a report cite one;
    an entry that could be edited while keeping its id would make the same
    identifier mean two different things on two machines. Switch one off
    under Settings -> Detection instead, by the id in its metadata.

    THE METADATA IS LOAD-BEARING, not decoration:

      id        the stable rule id. The off-switch stores it, and the
                engine reports the finding under it.
      severity  high / medium, read by the engine.
      name      the exact text the finding carries. It is part of the
                triage fingerprint, so changing it orphans every decision
                an analyst has already made about a file this rule hit.

    WHY THE REGEXES LOOK SLIGHTLY DIFFERENT FROM A PYTHON ONE. These used to
    run line by line. YARA runs over the whole file, and the two agree only
    because '.' does not cross a newline -- so '.*?' and '.{0,80}' still stay
    within one line. A NEGATED CLASS does cross one, which is why the
    command-execution rule below carries an explicit \n in [^;\n].

    Case sensitivity is not uniform and must not be made uniform. PHP
    superglobals are case-sensitive, so the variable-function rule has no
    `nocase`; the rules that had it in their previous life keep it, because
    dropping it would silently narrow them.

    These rules apply to PHP files. The .htaccess rules live in their own
    file, because the engine must not run either set on the other's files.
*/

rule Webshell_Eval_On_Request_Input
{
    meta:
        id = "webshell.eval_input"
        severity = "high"
        name = "eval/assert on decoded or request input"
        what = "eval() or assert() is handed something decoded at runtime, or a request parameter straight from the browser."
    strings:
        $a = /\b(eval|assert)[^\S\n]*\([^\S\n]*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|\$_(POST|GET|REQUEST|COOKIE))/ nocase
    condition:
        $a
}

rule Webshell_Variable_Function_On_Request_Input
{
    meta:
        id = "webshell.var_func"
        severity = "high"
        name = "Variable function called on request input"
        what = "A function whose NAME comes out of a variable is called on a request parameter -- the standard way to hide which function runs."
        note = "Deliberately case-sensitive: PHP superglobals are, and $_post is not $_POST."
    strings:
        $a = /\$\w+[^\S\n]*\([^\S\n]*\$_(POST|GET|REQUEST|COOKIE)/
    condition:
        $a
}

rule Webshell_Command_Execution_On_Request_Input
{
    meta:
        id = "webshell.cmd_input"
        severity = "high"
        name = "Command execution on request input"
        what = "A shell command is built from a request parameter."
        note = "[^;\\n] rather than [^;]: a negated class crosses a newline in YARA, and this rule used to be confined to one line."
    strings:
        $a = /(shell_exec|passthru|proc_open|popen|pcntl_exec|system|exec)[^\S\n]*\([^\S\n]*[^;\n]{0,40}\$_(POST|GET|REQUEST|COOKIE|SERVER)/ nocase
    condition:
        $a
}

rule Webshell_PregReplace_E_Modifier
{
    meta:
        id = "webshell.preg_e"
        severity = "high"
        name = "preg_replace with /e modifier (code execution)"
        what = "The removed /e modifier made preg_replace evaluate its replacement as PHP. Present in a file today it is either very old code or a backdoor."
        note = "Two alternatives instead of a backreference -- YARA has none. Requiring the same quote at both ends is exactly what the two branches do."
        note2 = "[^'\n]* rather than .*? -- YARA refuses to mix greedy and lazy quantifiers. The \n is not optional: a negated class crosses a line break and .*? does not."
    strings:
        $single = /preg_replace[^\S\n]*\([^\S\n]*'[^'\n]*[\/#~|!%@][a-zA-Z]*e[a-zA-Z]*'/ nocase
        $double = /preg_replace[^\S\n]*\([^\S\n]*"[^"\n]*[\/#~|!%@][a-zA-Z]*e[a-zA-Z]*"/ nocase
    condition:
        any of them
}

rule Webshell_Create_Function_Or_Callback
{
    meta:
        id = "webshell.create_function"
        severity = "high"
        name = "create_function / callback on request input"
        what = "Code is assembled from a string at runtime, or a callback is taken straight from the request."
    strings:
        $a = /(create_function[^\S\n]*\([^\S\n]*['"]|call_user_func(_array)?[^\S\n]*\([^\S\n]*\$_)/ nocase
    condition:
        $a
}

rule Webshell_File_Dropper
{
    meta:
        id = "webshell.dropper"
        severity = "high"
        name = "File dropper writing request input to disk"
        what = "Something out of the request is written to a file. That is how the next shell arrives."
    strings:
        $a = /(move_uploaded_file|file_put_contents|fwrite)[^\S\n]*\(.{0,80}\$_(POST|GET|REQUEST|FILES)/ nocase
    condition:
        $a
}

rule Webshell_Obfuscation_Decode_Chain
{
    meta:
        id = "webshell.obfuscation"
        severity = "medium"
        name = "Obfuscation decode chain"
        what = "Decoders nested inside one another. Legitimate code decodes once; a chain exists to be unreadable."
    strings:
        $a = /(base64_decode[^\S\n]*\([^\S\n]*(str_rot13|strrev|gzinflate|gzuncompress)|gzinflate[^\S\n]*\([^\S\n]*(base64_decode|str_rot13)|str_rot13[^\S\n]*\([^\S\n]*base64_decode)/ nocase
    condition:
        $a
}

rule Webshell_Hex_Octal_Obfuscation
{
    meta:
        id = "webshell.hex_octal"
        severity = "medium"
        name = "Hex/octal string obfuscation"
        what = "A long run of escaped byte literals -- a string written so it cannot be read."
        note = "Case-sensitive by inheritance; the class already spells out a-fA-F."
    strings:
        $a = /(\\x[0-9a-fA-F]{2}|\\[0-7]{3}){10,}/
    condition:
        $a
}

rule Webshell_Chr_Concatenation
{
    meta:
        id = "webshell.chr_concat"
        severity = "medium"
        name = "chr() concatenation obfuscation"
        what = "A string built character by character out of chr() calls."
    strings:
        $a = /(chr[^\S\n]*\([^\S\n]*\d+[^\S\n]*\)[^\S\n]*\.[^\S\n]*){5,}/ nocase
    condition:
        $a
}

rule Webshell_Goto_Control_Flow
{
    meta:
        id = "webshell.goto"
        severity = "medium"
        name = "goto-based control-flow obfuscation"
        what = "goto is legal PHP and almost nobody writes it. Obfuscators emit it to make control flow unreadable."
    strings:
        $a = /\bgoto[^\S\n]+\w{1,20}[^\S\n]*;/ nocase
    condition:
        $a
}

rule Webshell_Standalone_Command_Execution
{
    meta:
        id = "webshell.standalone_exec"
        severity = "medium"
        name = "Standalone command-execution shell"
        what = "A command-execution function is present at all. On its own weak -- it counts in combination, which is why it is MEDIUM."
    strings:
        $a = /\b(shell_exec|passthru|proc_open|pcntl_exec)[^\S\n]*\(/ nocase
    condition:
        $a
}
