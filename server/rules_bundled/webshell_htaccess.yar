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
        /*
            THE EXTENSION IS THE WHOLE POINT, so the rule has to name it.
            Matching any handler line that mentions PHP fired on the block
            every shared host puts in its default .htaccess --
            `AddHandler application/x-httpd-ea-php81 .php .php8 .phtml` --
            and then said those were "non-PHP extensions", which is the
            opposite of what stands in the line. A rule that is wrong about
            what it found is worse than one that finds less.

            Listed explicitly rather than as "not .php": an extension nobody
            executes is not interesting, and the ones that are -- images,
            documents, archives, plain text -- are a short list.
        */
        $exec = /(AddHandler|AddType|SetHandler)[^\n]*(php|x-httpd)[^\n]*\.(jpe?g|png|gif|bmp|webp|svg|ico|txt|html?|css|js|json|xml|pdf|zip|gz|log|bak|old|ini|conf)\b/ nocase
        /* `SetHandler` needs no extension: it applies to whatever the
           <Files>/<FilesMatch> block around it selects, and a block naming an
           image is the same trick by another route. */
        $set_all = /SetHandler[^\n]*(php|x-httpd)/ nocase
        $files_image = /<Files(Match)?[^>\n]*(jpe?g|png|gif|bmp|webp|ico|txt|pdf|zip)/ nocase
    condition:
        $exec or ($set_all and $files_image)
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
