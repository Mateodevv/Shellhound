"""Offline training data with harmless PHP examples, logs and CMS metadata."""
import os
from datetime import datetime, timedelta
from server import db, workspace as workspaces


PHP_EXAMPLE = r'''<?php
/**
 * SHELLHOUND SYNTHETIC TRAINING FILE
 * Harmless PHP for syntax highlighting and file-review practice.
 * The double extension is intentional training evidence.
 * No request input, network access, commands or file writes.
 */
declare(strict_types=1);

namespace Training\Preview;

const SITE_TITLE = 'Synthetic training dashboard';
const MAX_VISIBLE = 3;

final class DemoRecord
{
    public function __construct(
        public string $title,
        public string $category,
        public int $count = 0,
    ) {}

    public function label(): string
    {
        return sprintf('%s (%d)', $this->title, $this->count);
    }
}

function escapeHtml(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$records = [
    new DemoRecord('Gallery', 'plugin', 12),
    new DemoRecord('Contact form', 'plugin', 4),
    new DemoRecord('Training theme', 'theme', 1),
];
$settings = ['enabled' => true, 'ratio' => 0.75, 'message' => null];
$intro = "This is a fictional site with " . count($records) . " components.";
$notes = <<<TEXT
Review the collected source and its associated requests.
These values are fixed examples, not data from a real organisation.
TEXT;

// Keep the example deterministic and independent of the host environment.
$total = 0;
foreach ($records as $record) {
    $total += $record->count;
}
$summary = $total > 10 ? 'Several sample items' : 'A few sample items';
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title><?= escapeHtml(SITE_TITLE) ?></title></head>
<body>
    <h1><?= escapeHtml(SITE_TITLE) ?></h1>
    <p><?= escapeHtml($intro) ?></p>
    <?php if ($settings['enabled']): ?>
        <ul>
        <?php foreach (array_slice($records, 0, MAX_VISIBLE) as $record): ?>
            <li data-category="<?= escapeHtml($record->category) ?>">
                <?= escapeHtml($record->label()) ?>
            </li>
        <?php endforeach; ?>
        </ul>
    <?php endif; ?>
    <p><?= escapeHtml($summary) ?></p>
    <pre><?= escapeHtml($notes) ?></pre>
</body>
</html>
'''


def generate(workspace, *, analyse=True):
    case = workspaces.create_case(workspace, 'Training case', notes=(
        'SYNTHETIC TRAINING DATA. The registered webroot, access logs and SQL dump are ready for review; '
        'then review findings and run Pattern Hunt. No analyst decisions have been made. '
        'Files contain harmless training markers, not malware.'))
    evidence = case / 'training-evidence'
    webroot = evidence / 'webroot'
    (webroot / 'uploads').mkdir(parents=True)
    files = ['uploads/training-shell.xml.php', 'uploads/training-dropper.xml.php', 'index.html']
    for relative in files:
        path = webroot / relative
        content = PHP_EXAMPLE if relative.endswith('.php') else (
            '<!doctype html><title>Synthetic training site</title>\n'
            '<p>SHELLHOUND SYNTHETIC TRAINING FILE</p>\n')
        if 'dropper' in relative:
            content = content.replace('Synthetic training dashboard', 'Synthetic import preview')
        path.write_text(content, encoding='utf-8')
        os.utime(path, (1788825600, 1788825600))
    cms_files = {
        'wp-includes/version.php': "<?php\n$wp_version = '6.6.2'; // Synthetic inventory fixture\n",
        'wp-content/plugins/training-gallery/gallery.php': "<?php\n/*\nPlugin Name: Training Gallery\nVersion: 1.2.0\nDescription: Synthetic inventory metadata only.\n*/\n",
        'wp-content/plugins/training-forms/forms.php': "<?php\n/*\nPlugin Name: Training Forms\nVersion: 2.1.0\nDescription: Synthetic inventory metadata only.\n*/\n",
        'wp-content/themes/training-theme/style.css': "/*\nTheme Name: Training Theme\nVersion: 1.0.0\n*/\n",
    }
    for relative, content in cms_files.items():
        target = webroot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf-8')
    log = evidence / 'access.log'
    rows = []
    for hour, minute, ip, method, uri, status in [
        (8, 0, '203.0.113.80', 'GET', '/', 200),
        (9, 0, '192.0.2.14', 'GET', '/administrator/', 200),
        (9, 0, '192.0.2.14', 'GET', '/plugins/editors/jce/jce.xml', 200),
        (9, 1, '192.0.2.14', 'POST', '/index.php?option=com_jce&task=profiles.import', 200),
        (9, 2, '192.0.2.14', 'POST', '/uploads/training-shell.xml.php', 200),
        (9, 4, '192.0.2.14', 'GET', '/uploads/training-shell.xml.php', 200),
        (10, 0, '198.51.100.28', 'GET', '/uploads/training-dropper.xml.php', 200),
        (10, 3, '198.51.100.28', 'POST', '/wp-login.php', 403),
        (11, 0, '203.0.113.80', 'GET', '/', 200),
    ]:
        day = datetime(2026, 9, 8) + timedelta(days=0 if hour < 9 else 1 if hour < 10 else 2)
        rows.append(f'{ip} - - [{day.strftime("%d/%b/%Y")}:{hour:02d}:{minute:02d}:00 +0000] "{method} {uri} HTTP/1.1" {status} 128 "-" "Synthetic training client"\n')
    log.write_text(''.join(rows), encoding='utf-8')
    dump = evidence / 'training-wordpress.sql'
    dump.write_text("""-- SHELLHOUND SYNTHETIC TRAINING DATA. Fictional, offline WordPress export.
CREATE TABLE `wp_users` (`ID` bigint, `user_login` varchar(60), `user_pass` varchar(255), `user_nicename` varchar(50), `user_email` varchar(100), `user_url` varchar(100), `user_registered` datetime, `user_status` int, `display_name` varchar(250));
INSERT INTO `wp_users` VALUES (1,'training-admin','NOT-A-REAL-PASSWORD-HASH','training-admin','admin@example.invalid','','2026-09-08 08:00:00',0,'Training administrator'),(2,'training-editor','NOT-A-REAL-PASSWORD-HASH','training-editor','editor@example.invalid','','2026-09-09 09:00:00',0,'Training editor');
CREATE TABLE `wp_usermeta` (`umeta_id` bigint, `user_id` bigint, `meta_key` varchar(255), `meta_value` longtext);
INSERT INTO `wp_usermeta` VALUES (1,1,'wp_capabilities','a:1:{s:13:"administrator";b:1;}'),(2,2,'wp_capabilities','a:1:{s:6:"editor";b:1;}');
CREATE TABLE `wp_options` (`option_id` bigint, `option_name` varchar(191), `option_value` longtext, `autoload` varchar(20));
INSERT INTO `wp_options` VALUES (1,'siteurl','https://example.invalid','yes'),(2,'home','https://example.invalid','yes'),(3,'blogname','Synthetic training site','yes');
CREATE TABLE `wp_posts` (`ID` bigint, `post_author` bigint, `post_date` datetime, `post_content` longtext, `post_title` text, `post_status` varchar(20), `post_type` varchar(20));
INSERT INTO `wp_posts` VALUES (1,1,'2026-09-08 08:00:00','Offline training content. Review this fictional database alongside the access logs.','Welcome','publish','post'),(2,2,'2026-09-10 10:00:00','Synthetic imported content linking to https://example.invalid/promotion','Imported page','draft','page');
""", encoding='utf-8')
    conn = db.connect(case)
    try:
        for kind, path in [('webroot', webroot), ('access_logs', log), ('sql_dump', dump)]:
            conn.execute('INSERT INTO evidence(kind,path,label,added) VALUES (?,?,?,?)',
                         (kind, str(path), 'Synthetic training evidence', db.now()))
        conn.commit()
    finally:
        conn.close()
    if analyse:
        from server.engines import cmsinventory, logindex, sqldump, webshell
        webshell.scan(case, [str(webroot)], workspace=workspace)
        logindex.build(case, [str(log)])
        sqldump.scan(case, [str(dump)], workspace=workspace)
        cmsinventory.scan(case, [str(webroot)])
        conn = db.connect(case)
        try:
            conn.execute('UPDATE evidence SET scanned_at=?', (db.now(),))
            conn.commit()
        finally:
            conn.close()
    return case
