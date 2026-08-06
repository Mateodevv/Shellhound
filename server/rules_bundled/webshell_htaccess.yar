/*
    SHELLHOUND -- rules for .htaccess files.

    Their own file because the engine must not run them on PHP files, nor
    the content rules on an .htaccess. YARA cannot see a file name, so the
    dispatch stays where it can: in the engine.

    See webshell_content.yar for what the metadata means and why it must not
    be edited in place.
*/

rule Htaccess_Maps_Extension_To_PHP
{
    meta:
        id = "webshell.htaccess_handler"
        severity = "high"
        name = ".htaccess maps non-PHP extension to PHP handler"
        what = "An .htaccess tells the server to execute some other extension as PHP -- which is how a .jpg becomes a shell without ever being named .php."
    strings:
        $a = /(AddHandler|AddType|SetHandler)[^\n]*(php|x-httpd)/ nocase
    condition:
        $a
}

rule Htaccess_Auto_Prepend_Append
{
    meta:
        id = "webshell.htaccess_prepend"
        severity = "high"
        name = ".htaccess auto_prepend/append_file backdoor"
        what = "Every PHP request in this directory runs the named file first or last. A backdoor that needs no URL of its own."
    strings:
        $a = /auto_(prepend|append)_file/ nocase
    condition:
        $a
}
