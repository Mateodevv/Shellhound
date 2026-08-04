#!/usr/bin/env python3
"""Baut einen vollständigen Beispiel-Fall zum Ausprobieren.

    python tools/sample_case.py                    # ~/ShellhoundSample
    python tools/sample_case.py --workspace D:\\Demo
    python tools/sample_case.py --force            # vorhandenes Beispiel ersetzen

Der Fall erzählt EINE Geschichte, damit die Ansichten zusammenpassen: ein
Angreifer klopft ab, findet ein beschreibbares Upload-Verzeichnis, legt dort
eine Shell ab und benutzt sie; ein zweiter probiert es mit Brute-Force auf den
Login. Daneben läuft normaler Besucherverkehr, und ein Scanner meldet sich wie
bei jedem Server im Internet.

WICHTIG: erzeugt werden ECHTE EVIDENCE-DATEIEN, die anschließend durch die
normalen Engines laufen -- keine vorgefertigten Findings in der Datenbank. Was
im Werkzeug erscheint, hat die Erkennung wirklich gefunden. Damit ist das
Beispiel zugleich ein End-to-End-Test.

Alles darin ist erfunden: die IP-Adressen stammen aus den für Dokumentation
reservierten Bereichen (RFC 5737), Domains enden auf .test (RFC 6761), und die
»Webshells« sind die kürzestmöglichen Textdateien, auf die die Regeln
ansprechen -- Prüfmuster wie eine EICAR-Datei, kein funktionsfähiges Werkzeug.
"""
import argparse
import random
import shutil
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server import db, patterns as patternlib, workspace          # noqa: E402
from server.engines import cmsinventory, logindex, sqldump, webshell  # noqa: E402

# --- die Besetzung ----------------------------------------------------------
# RFC-5737-Adressen: für Dokumentation reserviert, gehören niemandem.
ANGREIFER = "203.0.113.42"        # legt die Shell ab und benutzt sie
BRUTE = "198.51.100.77"           # Login-Flood, probiert Shell-Namen durch
SCANNER = "198.51.100.9"          # meldet sich als nikto -- Hintergrundrauschen
BESUCHER = [f"192.0.2.{n}" for n in range(10, 34)]

START = date(2026, 7, 1)
TAGE = 14

SHELL_REL = "wp-content/uploads/2026/07/kb-media.php"

# Kopfzeile in jeder erzeugten PHP-Datei: wer sie später im Dateisystem
# findet, soll auf den ersten Blick sehen, woher sie stammt.
MARKE = "// SHELLHOUND-BEISPIELFALL - erfundene Testdatei, kein echter Code\n"


def schreibe(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def pruefe_lesbar(root: Path) -> list[tuple[Path, str]]:
    """Ist jede erzeugte Datei auch wieder LESBAR?

    Ein Virenscanner greift nicht beim Schreiben ein, sondern beim Zugriff:
    er lässt die Datei anlegen und verweigert danach das Öffnen (unter
    Windows Defender als [Errno 22]) oder schiebt sie in Quarantäne. Der
    Beispielfall wäre dann still unvollständig -- ein paar Findings fehlten,
    ohne dass jemand wüsste warum. Deshalb wird hier einmal alles gelesen."""
    kaputt = []
    for datei in sorted(root.rglob("*")):
        if not datei.is_file():
            continue
        try:
            datei.read_bytes()
        except OSError as e:
            kaputt.append((datei, str(e)))
    return kaputt


# --- Webroot ----------------------------------------------------------------

def baue_webroot(root: Path) -> None:
    """Eine WordPress-Installation mit einem Joomla-Shop daneben."""
    # --- WordPress-Kern ---
    schreibe(root / "wp-includes" / "version.php",
             "<?php\n$wp_version = '6.2.4';\n")
    schreibe(root / "index.php", "<?php\nrequire __DIR__ . '/wp-blog-header.php';\n")
    schreibe(root / "wp-login.php", "<?php\n// Login\n")

    # --- Plugins: zwei gepflegte, eines ohne Manifest ---
    for slug, name, version in (("akismet", "Akismet Anti-Spam", "5.3"),
                                ("wordfence", "Wordfence Security", "7.11.0")):
        schreibe(root / "wp-content" / "plugins" / slug / f"{slug}.php",
                 f"<?php\n/*\nPlugin Name: {name}\nVersion: {version}\n*/\n")
    # Ohne Header -> "(unknown)": genau der Fall, den das Inventar hervorhebt.
    schreibe(root / "wp-content" / "plugins" / "wp-file-optimizer" / "loader.php",
             "<?php\n// kein Plugin-Header\n")

    schreibe(root / "wp-content" / "themes" / "twentytwentythree" / "style.css",
             "/*\nTheme Name: Twenty Twenty-Three\nVersion: 1.2\n*/\n")

    # --- die abgelegte Shell -------------------------------------------------
    # Kürzestmögliche Datei, auf die mehrere Regeln ansprechen: Systembefehl
    # aus dem Request, variabler Funktionsaufruf, Schreiben von Request-Daten,
    # Verschleierungskette -- und sie liegt in einem Upload-Verzeichnis ohne
    # CMS-Startschutz.
    #
    # BEWUSST OHNE `eval(...)` auf Request-Eingaben: Virenscanner blockieren
    # dann das LESEN der Datei (unter Windows Defender mit [Errno 22]), und
    # der Beispielfall wäre kaputt, bevor er anfängt. Die übrigen Muster
    # zeigen dieselben Regeln und laufen ohne Ausnahmeregel im Scanner.
    schreibe(root / SHELL_REL,
             "<?php\n" + MARKE +
             "system($_GET['cmd']);\n"
             "file_put_contents($_POST['name'], $_POST['data']);\n"
             "$rohdaten = gzinflate(base64_decode($paket));\n")
    # Doppelte Endung -- der Klassiker beim Umgehen von Upload-Filtern.
    schreibe(root / "wp-content" / "uploads" / "2026" / "07" / "logo.jpg.php",
             "<?php\n" + MARKE + "@$_REQUEST['f']($_REQUEST['p']);\n")
    # PHP in einer Bilddatei.
    schreibe(root / "wp-content" / "uploads" / "2026" / "06" / "header.png",
             "\x89PNG\n" + MARKE + "<?php echo 'x'; ?>\n")
    # .htaccess, die harmlose Endungen ausführbar macht.
    schreibe(root / "wp-content" / "uploads" / ".htaccess",
             "# " + MARKE + "AddType application/x-httpd-php .gif\n")
    # Eine unauffällige Datei am unpassenden Ort -- nichts für die Regeln,
    # aber etwas für den Datei-Browser und das manuelle Flaggen.
    schreibe(root / "wp-content" / "uploads" / "2026" / "07" / "notiz.txt",
             "Zugangsdaten Hotline: siehe Ticket 4711\n")

    # --- Joomla-Shop daneben --------------------------------------------------
    shop = root / "shop"
    schreibe(shop / "libraries" / "src" / "version.php",
             "<?php\nconst MAJOR_VERSION = 4;\nconst MINOR_VERSION = 4;\n"
             "const PATCH_VERSION = 1;\n")
    erweiterungen = [
        ("administrator/components/com_banners", "com_banners", "Banners", "4.4.1"),
        ("administrator/components/com_jce", "com_jce", "JCE Editor", "2.6.30"),
        ("components/com_content", "com_content", "Content", "4.4.1"),
        ("modules/mod_articles_news", "mod_articles_news", "Articles Newsflash", "4.4.1"),
        ("plugins/system/cache", "cache", "System - Page Cache", "4.4.1"),
        ("plugins/authentication/joomla", "joomla", "Authentication - Joomla", "4.4.1"),
    ]
    for rel, slug, name, version in erweiterungen:
        schreibe(shop / rel / f"{slug}.xml",
                 '<?xml version="1.0" encoding="utf-8"?>\n'
                 f"<extension type=\"component\" version=\"4.0\">\n"
                 f"  <name>{name}</name>\n  <version>{version}</version>\n"
                 f"</extension>\n")
        # Jede Erweiterung bringt ihr Schema-SQL mit -- der Grund, warum die
        # Datenbank-Ansicht echte Exporte von mitgeliefertem SQL trennt.
        schreibe(shop / rel / "sql" / "install.mysql.utf8.sql",
                 f"CREATE TABLE IF NOT EXISTS `#__{slug}` (\n"
                 "  `id` int(11) NOT NULL AUTO_INCREMENT,\n"
                 "  `name` varchar(255) NOT NULL,\n"
                 "  PRIMARY KEY (`id`)\n) DEFAULT CHARSET=utf8;\n")
        schreibe(shop / rel / "sql" / "uninstall.mysql.utf8.sql",
                 f"DROP TABLE IF EXISTS `#__{slug}`;\n")
        for ver in ("2.0.0", "2.0.1"):
            schreibe(shop / rel / "sql" / "updates" / "mysql" / f"{ver}.sql",
                     f"ALTER TABLE `#__{slug}` ADD COLUMN `params` text;\n")
    # Eine Erweiterung ohne Manifest -> Version unbekannt.
    schreibe(shop / "administrator" / "components" / "com_altmodul" / "index.html", "")


# --- Access-Logs ------------------------------------------------------------

def zeile(ip: str, tag: date, stunde: int, minute: int, methode: str,
          uri: str, status: int, groesse: int, agent: str) -> str:
    stempel = f"{tag:%d/%b/%Y}:{stunde:02d}:{minute:02d}:00 +0200"
    return (f'{ip} - - [{stempel}] "{methode} {uri} HTTP/1.1" '
            f'{status} {groesse} "-" "{agent}"')


BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

SEITEN = ["/", "/index.php", "/ueber-uns/", "/kontakt/", "/blog/",
          "/shop/index.php", "/wp-content/themes/twentytwentythree/style.css"]


def baue_logs(pfad: Path) -> int:
    """Zwei Wochen Verkehr mit einem Vorfall in der Mitte."""
    rng = random.Random(20260701)      # fest, damit das Beispiel reproduzierbar ist
    zeilen: list[str] = []

    for n in range(TAGE):
        tag = START + timedelta(days=n)

        # --- Grundrauschen: ganz normale Besucher --------------------------
        for _ in range(rng.randint(70, 110)):
            zeilen.append(zeile(
                rng.choice(BESUCHER), tag, rng.randint(6, 22), rng.randint(0, 59),
                "GET", rng.choice(SEITEN), 200, rng.randint(800, 9000), BROWSER))
        for _ in range(rng.randint(2, 6)):
            zeilen.append(zeile(
                rng.choice(BESUCHER), tag, rng.randint(6, 22), rng.randint(0, 59),
                "GET", "/alte-seite.html", 404, 200, BROWSER))

        # --- Tag 6: ein Scanner meldet sich (INFO, kein Vorfall) -----------
        if n == 5:
            for i in range(25):
                zeilen.append(zeile(SCANNER, tag, 3, i, "GET",
                                    f"/wp-content/plugins/probe{i}/readme.txt",
                                    404, 200, "Mozilla/5.00 (Nikto/2.5.0)"))

        # --- Tag 7: Brute-Force auf den Login, am Ende erfolgreich --------
        if n == 6:
            for i in range(64):
                zeilen.append(zeile(BRUTE, tag, 2, i % 60, "POST",
                                    "/wp-login.php", 200, 1200, "python-requests/2.31"))
            # Die Weiterleitung nach der Serie: so sieht ein geglückter Login aus.
            zeilen.append(zeile(BRUTE, tag, 3, 5, "POST", "/wp-login.php",
                                302, 0, "python-requests/2.31"))
            # Derselbe Client klappert bekannte Shell-Namen ab -- ohne Erfolg.
            # Genau dieser Fall wird beim Bestätigen VORGESCHLAGEN, nicht
            # mitentschieden: angefragt, nie erfolgreich beantwortet.
            for i, name in enumerate(["shell.php", "up.php", "kb-media.php",
                                      "adminer.php", "wso.php"]):
                zeilen.append(zeile(BRUTE, tag, 4, i, "GET",
                                    f"/wp-content/uploads/2026/07/{name}",
                                    404, 200, "python-requests/2.31"))

        # --- Tag 8: der Angreifer legt die Shell ab und benutzt sie -------
        if n == 7:
            zeilen.append(zeile(ANGREIFER, tag, 9, 12, "POST",
                                "/wp-admin/async-upload.php", 200, 340, BROWSER))
            for i in range(14):
                zeilen.append(zeile(ANGREIFER, tag, 9 + i // 6, (13 + i) % 60,
                                    "POST", f"/{SHELL_REL}", 200, 900, "curl/8.5.0"))

        # --- Tag 9-10: er kommt wieder und greift den Shop an -------------
        if n in (8, 9):
            for i in range(9):
                zeilen.append(zeile(ANGREIFER, tag, 22, i * 6, "GET",
                                    f"/{SHELL_REL}?cmd=id", 200, 1500, "curl/8.5.0"))
            for i in range(6):
                zeilen.append(zeile(
                    ANGREIFER, tag, 23, i * 9, "GET",
                    "/shop/index.php?option=com_jce&task=plugin&plugin=imgmanager"
                    "&file=imgmanager&method=form", 200, 2400, "curl/8.5.0"))

        # --- Tag 11: eine SQL-Injection, die der Server beantwortet -------
        if n == 10:
            for i in range(7):
                zeilen.append(zeile(
                    ANGREIFER, tag, 1, i * 4, "GET",
                    f"/shop/index.php?option=com_content&id=1'+UNION+SELECT+"
                    f"{i},concat(user,0x3a,password),3+FROM+jos_users--",
                    200, 3100, "sqlmap/1.8#stable"))

    zeilen.sort(key=lambda z: (z.split("[", 1)[1][:20]))
    schreibe(pfad, "\n".join(zeilen) + "\n")
    return len(zeilen)


# --- Datenbank-Export -------------------------------------------------------

def baue_dump(pfad: Path) -> None:
    """Ein echter Export mit allem, was die Konto-Ansicht zeigen soll.

    Die Spaltenordnung ist die ECHTE von `wp_users` -- ein mysqldump schreibt
    keine Wunschreihenfolge, und die Engine liest die Konten positionsbasiert
    genau so. Ein Beispiel mit erfundener Ordnung würde also nicht das zeigen,
    was ein echter Export zeigt."""
    nutzer = [
        # ID, user_login, user_pass, user_nicename, user_email, user_url,
        # user_registered, user_activation_key, user_status, display_name
        (1, "s.keller",
         "$2y$10$Yb8kQm1s2t3u4v5w6x7y8uAbCdEfGhIjKlMnOpQrStUvWxYz01234",
         "s-keller", "s.keller@example.test", "2019-03-04 09:12:00", 0,
         "Sabine Keller"),
        (2, "redaktion",
         "$2y$10$Zc9lRn2t3u4v5w6x7y8z9vBcDeFgHiJkLmNoPqRsTuVwXyZa12345",
         "redaktion", "redaktion@example.test", "2020-11-18 14:30:00", 0,
         "Redaktion"),
        # Schwacher MD5-Hash UND angelegt mitten im Vorfall -> beides hebt
        # die Konto-Ansicht hervor, und das Konto ist Administrator.
        (3, "support-tmp", "5f4dcc3b5aa765d61d8327deb882cf99",
         "support-tmp", "support-tmp@example.test", "2026-07-08 03:17:00", 0,
         "Support"),
        # user_status = 1: gesperrt.
        (4, "praktikum21",
         "$2y$10$Ad0mSo3u4v5w6x7y8z9a0wCdEfGhIjKlMnOpQrStUvWxYzAb23456",
         "praktikum21", "praktikum21@example.test", "2021-06-01 08:00:00", 1,
         "Alter Praktikant"),
    ]
    werte = ",".join(
        f"({i},'{login}','{pw}','{nice}','{mail}','','{reg}','',{status},'{name}')"
        for i, login, pw, nice, mail, reg, status, name in nutzer)

    schreibe(pfad,
             "-- phpMyAdmin SQL Dump\n"
             "-- version 5.2.1\n"
             "-- Host: localhost:3306\n"
             "-- Server-Version: 10.6.16-MariaDB\n"
             "-- Datenbank: `wp_produktiv`\n"
             "-- Erstellungszeit: 2026-07-15 06:30:00\n"
             "\n"
             "CREATE TABLE `wp_users` (\n"
             "  `ID` bigint(20) UNSIGNED NOT NULL,\n"
             "  `user_login` varchar(60) NOT NULL DEFAULT '',\n"
             "  `user_pass` varchar(255) NOT NULL DEFAULT '',\n"
             "  `user_nicename` varchar(50) NOT NULL DEFAULT '',\n"
             "  `user_email` varchar(100) NOT NULL DEFAULT '',\n"
             "  `user_url` varchar(100) NOT NULL DEFAULT '',\n"
             "  `user_registered` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',\n"
             "  `user_activation_key` varchar(255) NOT NULL DEFAULT '',\n"
             "  `user_status` int(11) NOT NULL DEFAULT 0,\n"
             "  `display_name` varchar(250) NOT NULL DEFAULT ''\n"
             ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
             f"INSERT INTO `wp_users` VALUES {werte};\n"
             "\n"
             "CREATE TABLE `wp_usermeta` (\n"
             "  `umeta_id` bigint(20) NOT NULL,\n"
             "  `user_id` bigint(20) NOT NULL,\n"
             "  `meta_key` varchar(255) NOT NULL,\n"
             "  `meta_value` longtext\n"
             ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
             "INSERT INTO `wp_usermeta` VALUES "
             "(1,1,'wp_capabilities','a:1:{s:13:\"administrator\";b:1;}'),"
             "(2,1,'last_login','2026-07-14 08:02:00'),"
             "(3,2,'wp_capabilities','a:1:{s:6:\"editor\";b:1;}'),"
             # Das frisch angelegte Konto hat volle Rechte -- die Frage, mit
             # der die Konto-Ansicht anfängt. Und es hat eine offene Sitzung.
             "(4,3,'wp_capabilities','a:1:{s:13:\"administrator\";b:1;}'),"
             "(5,3,'last_login','2026-07-10 22:55:00'),"
             "(6,3,'session_tokens','a:1:{s:64:\"aa11bb22\";a:4:{s:10:\"expiration\";i:1784000000;}}'),"
             "(7,4,'wp_capabilities','a:1:{s:10:\"subscriber\";b:1;}');\n"
             "\n"
             "CREATE TABLE `wp_options` (\n"
             "  `option_id` bigint(20) NOT NULL,\n"
             "  `option_name` varchar(191) NOT NULL,\n"
             "  `option_value` longtext NOT NULL\n"
             ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
             "INSERT INTO `wp_options` VALUES "
             "(1,'siteurl','https://shop.example.test'),"
             "(2,'blogname','Beispiel-Shop'),"
             # Eingeschleuster Code in einer Datenspalte: überlebt jedes
             # Aufräumen im Dateisystem. Auch hier ohne `eval` -- siehe die
             # Anmerkung bei der Shell.
             "(3,'wp_cache_prefix','<?php system(\"id\"); ?>');\n"
             "\n"
             "CREATE TABLE `wp_posts` (\n"
             "  `ID` bigint(20) NOT NULL,\n"
             "  `post_title` text NOT NULL,\n"
             "  `post_content` longtext NOT NULL\n"
             ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
             "INSERT INTO `wp_posts` VALUES "
             "(1,'Willkommen','<p>Hallo Welt.</p>'),"
             "(2,'Angebote','<p>Aktuelle Angebote.</p>"
             "<iframe src=\"//zaehler.example.test/t.html\" width=\"0\" "
             "height=\"0\"></iframe>');\n")


# --- Muster-Bibliothek ------------------------------------------------------

MUSTER = [
    ("option=com_jce&task=plugin", "JCE imgmanager RCE",
     "Beispiel: Aufruf des verwundbaren Datei-Managers"),
    ("/wp-content/uploads/*.php", "PHP im Upload-Verzeichnis",
     "Beispiel: jeder direkte Aufruf einer PHP-Datei unter uploads/"),
    ("/administrator/components/com_adsmanager/", "AdsManager LFI",
     "Beispiel für ein Muster ohne Treffer in diesem Fall"),
]


# --- Zusammenbau ------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--workspace", default=str(Path.home() / "ShellhoundSample"))
    parser.add_argument("--force", action="store_true",
                        help="einen vorhandenen Beispiel-Workspace löschen")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if ws.exists():
        if not args.force:
            print(f"[!] {ws} existiert schon. Mit --force ersetzen.")
            return 1
        shutil.rmtree(ws)
    ws.mkdir(parents=True)

    evidence = ws / "evidence"
    root = evidence / "webroot"
    logdir = evidence / "logs"

    print("[*] Schreibe Evidence…")
    baue_webroot(root)
    # Ein im Webroot vergessener Datenbank-Export -- kommt in echten Fällen
    # ständig vor und ist für sich genommen schon ein Befund.
    baue_dump(root / "backup" / "wp_produktiv.sql")
    zeilen = baue_logs(logdir / "access.log")
    print(f"    Webroot, {zeilen:,} Logzeilen, ein SQL-Export")

    kaputt = pruefe_lesbar(evidence)
    if kaputt:
        print("\n[!] Diese Dateien lassen sich nach dem Schreiben nicht lesen:")
        for datei, fehler in kaputt[:5]:
            print(f"      {datei.relative_to(evidence)} — {fehler[:70]}")
        print("    Fast immer ist das der Virenscanner: er lässt die Datei")
        print("    anlegen und verweigert dann den Zugriff. Nimm den Ordner")
        print(f"    {evidence} von der Echtzeitprüfung aus und starte neu —")
        print("    sonst fehlen im Beispiel genau die interessanten Funde.\n")

    case_dir = workspace.create_case(
        ws, "Beispiel — Shop-Kompromittierung", "DEMO-2026-001",
        "Erfundener Fall zum Ausprobieren. Alle Adressen, Namen und Dateien "
        "sind Testdaten.")
    conn = db.connect(case_dir)
    for kind, pfad, label in (
            ("webroot", root, "Webroot-Kopie"),
            ("access_logs", logdir, "Apache Access-Logs"),
            # Derselbe Webroot auch als SQL-Evidence: darin liegen der echte
            # Export UND die Schema-Dateien der Joomla-Erweiterungen -- so
            # zeigt die Datenbank-Ansicht, wie sie beides trennt.
            ("sql_dump", root, "SQL im Webroot")):
        conn.execute("INSERT OR IGNORE INTO evidence (kind, path, added, label) "
                     "VALUES (?,?,?,?)", (kind, str(pfad), db.now(), label))
    conn.commit()
    conn.close()

    print("[*] Analysiere (dieselbe Pipeline wie der »Analysieren«-Knopf)…")
    shell_stats = webshell.scan(case_dir, [str(root)])
    cms_stats = cmsinventory.scan(case_dir, [str(root)])
    sql_stats = sqldump.scan(case_dir, [str(root)])
    log_stats = logindex.build(case_dir, [str(logdir)])

    for muster, label, notiz in MUSTER:
        try:
            patternlib.add(ws, muster, label, notiz)
        except patternlib.PatternError:
            pass

    conn = db.connect(case_dir)
    artefakte = conn.execute(
        "SELECT count(DISTINCT artifact) FROM findings").fetchone()[0]
    findings = conn.execute("SELECT count(*) FROM findings").fetchone()[0]
    conn.close()

    print(f"""
[+] Fertig.

    Workspace : {ws}
    Fall      : {case_dir.name}

    {artefakte} Artefakte aus {findings} Findings · {shell_stats['flagged_files']} auffällige Dateien
    {cms_stats['installs']} CMS-Installationen mit {cms_stats['items']} Erweiterungen
    {sql_stats['dumps']} Export + {sql_stats['schema_files']} mitgelieferte Schema-Dateien
    {log_stats['lines']:,} Logzeilen von {log_stats['clients']} Clients

    Starten:

        python -m server.main --workspace "{ws}"

    Ein Rundgang durch die Geschichte des Falls:

    1. Dashboard — der Verlauf zeigt am 7./8. Juli die Fehlerwelle des
       Abklopfens, danach steigt die Erfolgskurve: da hat etwas funktioniert.
    2. Findings — {SHELL_REL.split('/')[-1]} trägt mehrere Regeln auf EINEM
       Artefakt. Öffnen (Enter), den Dateiinhalt links lesen, dann
       »True Positive«: die Clients, die sie mit 2xx geladen haben, werden
       mitentschieden — wer sie nur erfolglos angefragt hat ({BRUTE}),
       wird vorgeschlagen statt entschieden.
    3. Actors — »Unauffällig« ausblenden lässt drei Clients übrig. Beim
       Trace von {ANGREIFER} ist der auslösende Aufruf rot markiert.
    4. Muster-Jagd — drei Muster liegen bereit; »Alle laufen lassen« findet
       den JCE-Aufruf, das dritte bleibt bewusst ohne Treffer (auch das wird
       im Fall protokolliert).
    5. Database — ein echter Export neben {sql_stats['schema_files']} mitgelieferten
       Schema-Dateien; »support-tmp« ist Administrator, wurde mitten im
       Vorfall angelegt und trägt einen MD5-Hash.
    6. CMS Inventory — die Erweiterung mit der Shell trägt ein Artefakt-Badge,
       zwei Erweiterungen haben keine erkennbare Version.
    7. Dateien — durch den Webroot klicken; notiz.txt unter uploads/2026/07
       ist nichts für die Regeln, aber etwas fürs manuelle Flaggen.
    8. IOC Box — am Ende steht alles Gesammelte, mit fallrelativen Pfaden.
""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
