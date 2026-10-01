"""Deterministic, offline performance evidence. Never seeds analyst decisions."""
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import threading
import time

from server import db, workspace as workspaces
from server.casework.testcase import PHP_EXAMPLE

VERSION = 1
SEED = 1701
STAMP = datetime(2026, 9, 1, tzinfo=timezone.utc)
LOCK = threading.Lock()


@dataclass(frozen=True)
class Scale:
    requests: int = 5_000_000
    files: int = 50_000
    clients: int = 10_000
    sql_rows: int = 100_000
    suspicious_files: int = 500
    extensions: int = 100
    days: int = 30


def manifest(case, **changes):
    path = Path(case) / 'testcase-generation.json'
    data = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    data.update(changes)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, indent=2), encoding='utf-8')
    temporary.replace(path)
    return data


def generate(case, ctx, scale=Scale()):
    """Write bounded chunks; publish evidence only after every file is complete."""
    import os
    if scale.files < scale.extensions + 2 + scale.suspicious_files:
        raise ValueError('File count must cover CMS metadata and suspicious examples.')
    started = time.monotonic()
    manifest(case, version=VERSION, seed=SEED, scale=asdict(scale), state='generating')
    root = Path(case) / 'training-evidence'
    root.mkdir(exist_ok=True)
    total_bytes = 0

    def progress(phase, completed, total, base, span):
        if ctx.cancelled():
            raise InterruptedError('Testcase generation cancelled; evidence is incomplete.')
        ctx.phase_progress(base + span * completed / max(1, total),
                           f'{phase}: {completed:,} / {total:,}', phase, completed, total)

    def write(relative, content):
        nonlocal total_bytes
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = content.encode('utf-8')
        path.write_bytes(raw)
        os.utime(path, (STAMP.timestamp(), STAMP.timestamp()))
        total_bytes += len(raw)

    metadata = [
        ('wordpress/wp-includes/version.php', "<?php\n$wp_version = '6.6.2';\n"),
        ('joomla/libraries/src/Version.php', '<?php\nconst MAJOR_VERSION = 5;\nconst MINOR_VERSION = 2;\nconst PATCH_VERSION = 0;\n'),
    ]
    for i in range(scale.extensions):
        if i % 2:
            metadata.append((f'joomla/plugins/content/training-{i}/manifest.xml',
                f'<extension type="plugin"><name>Training extension {i}</name><version>1.{i}.0</version></extension>'))
        else:
            metadata.append((('wordpress/wp-content/plugins/wp2shell_demo/wp2shell_demo.php' if i == 0 else f'wordpress/wp-content/plugins/training-{i}/plugin.php'),
                f'<?php\n/*\nPlugin Name: Training plugin {i}\nVersion: 1.{i}.0\n*/\n'))
    for relative, content in metadata:
        write(relative, content)
    file_count = len(metadata)
    for i in range(scale.suspicious_files):
        site = 'wordpress' if i % 2 == 0 else 'joomla'
        write(f'{site}/uploads/training-{i}.xml.php', PHP_EXAMPLE + f'\n// Synthetic sample {i}\n')
        file_count += 1
    for i in range(scale.files - file_count):
        if i % 128 == 0:
            progress('Files', file_count + i, scale.files, 0, .20)
        site = 'wordpress' if i % 2 == 0 else 'joomla'
        folders = '/'.join(f'd{(i // (n + 1)) % 8}' for n in range(i % 12))
        duplicate_key = i // 10 if i % 10 < 2 else i + scale.files
        if i % 4 == 0:
            # CMS guard plus harmless PHP: no command execution or remote calls.
            content = "<?php\ndefined('ABSPATH') || exit;\n" + f"$record = ['id' => {duplicate_key}, 'site' => 'Synthetic'];\n"
            content += '// Safe deterministic filler.\n' * (8 + (duplicate_key * SEED) % 180)
            extension = 'php'
        else:
            content = f'SYNTHETIC CONTENT {duplicate_key}\n' + ('Sample text for file review.\n' * (4 + (duplicate_key * SEED) % 600))
            extension = 'txt'
        write(f'{site}/content/{folders}/entry-{i}.{extension}', content)
    progress('Files', scale.files, scale.files, 0, .20)

    clients = [f'198.{18 + i // 65536}.{(i // 256) % 256}.{i % 256}' for i in range(scale.clients)]
    agents = ['Synthetic Browser/1.0', 'Synthetic Mobile/2.0', 'Synthetic Crawler/1.0', 'Synthetic CMS updater/3.0']
    logs = root / 'logs'
    logs.mkdir(exist_ok=True)
    suspicious = 0
    for day in range(scale.days):
        lo, hi = scale.requests * day // scale.days, scale.requests * (day + 1) // scale.days
        path = logs / f'access-{day + 1:02}.log'
        date = (STAMP + timedelta(days=day)).strftime('%d/%b/%Y')
        with path.open('w', encoding='utf-8', newline='\n', buffering=1024 * 1024) as stream:
            for row in range(lo, hi):
                if row % 4096 == 0:
                    progress('Access logs', row, scale.requests, .20, .55)
                ip = clients[(row * 7919 + SEED) % scale.clients]
                method, status = ('POST', 403) if row % 37 == 0 else ('GET', 200)
                agent = agents[row % len(agents)]
                uri = ['/', '/index.php', '/assets/site.css', '/news/', '/images/logo.png'][row % 5]
                if row % 100 == 0:
                    suspicious += 1
                    kind = (row // 100) % 5
                    uri = ['/index.php?option=com_jce&task=profiles.import',
                           '/index.php?option=com_ajax&plugin=helix3&format=raw',
                           '/wp-json/batch/v1',
                           '/wp-content/plugins/wp2shell_demo/wp2shell_demo.php',
                           f'/uploads/training-{2 * ((row // 500) % max(1, scale.suspicious_files // 2))}.xml.php'][kind]
                    method, status = 'POST' if kind < 3 else 'GET', 200 if row % 700 else 404
                    if kind == 2:
                        agent = 'wp2shell'
                fraction = (row - lo) / max(1, hi - lo - 1)
                seconds = int(fraction / .8 * 85800) if fraction < .8 else min(86399, int(85800 + (fraction - .8) / .2 * 599))
                stamp = f'{date}:{seconds // 3600:02}:{seconds // 60 % 60:02}:{seconds % 60:02} +0000'
                referer = '-' if row % 3 else 'https://training.example.invalid/news/'
                stream.write(f'{ip} - - [{stamp}] "{method} {uri} HTTP/1.1" {status} {128 + row % 32000} "{referer}" "{agent}"\n')
        os.utime(path, (STAMP.timestamp(), STAMP.timestamp()))
        total_bytes += path.stat().st_size
    progress('Access logs', scale.requests, scale.requests, .20, .55)

    # Exactly sql_rows tuples across two CMS dumps; modest INSERT batches.
    for site, prefix in [('wordpress', 'wp'), ('joomla', 'cms')]:
        count = scale.sql_rows // 2 + (scale.sql_rows % 2 if site == 'wordpress' else 0)
        users = min(1000, max(1, count // 20))
        meta_end = users * 3
        dump = root / f'{site}.sql'
        with dump.open('w', encoding='utf-8', newline='\n') as stream:
            stream.write('-- SYNTHETIC PERFORMANCE EVIDENCE\n')
            if site == 'wordpress':
                user_columns = '`ID` bigint, `user_login` varchar(60), `user_pass` varchar(255), `user_email` varchar(100), `user_registered` datetime'
                table, content_columns = 'posts', '`ID` bigint, `post_author` bigint, `post_date` datetime, `post_content` longtext, `post_title` text, `post_status` varchar(20), `post_type` varchar(20)'
            else:
                user_columns = '`id` bigint, `username` varchar(60), `password` varchar(255), `email` varchar(100), `registerDate` datetime'
                table, content_columns = 'content', '`id` bigint, `created_by` bigint, `created` datetime, `introtext` longtext, `title` text, `state` int, `catid` int'
            stream.write(f'CREATE TABLE `{prefix}_users` ({user_columns});\nCREATE TABLE `{prefix}_{table}` ({content_columns});\n')
            meta_table = 'usermeta' if site == 'wordpress' else 'user_usergroup_map'
            meta_columns = '`umeta_id` bigint, `user_id` bigint, `meta_key` varchar(255), `meta_value` longtext' if site == 'wordpress' else '`user_id` bigint, `group_id` bigint'
            stream.write(f'CREATE TABLE `{prefix}_{meta_table}` ({meta_columns});\n')
            for start in range(0, count, 250):
                progress('SQL dumps', (scale.sql_rows // 2 if site == 'joomla' else 0) + start, scale.sql_rows, .75, .25)
                for begin, end, name in [(start, min(start + 250, users), 'users'), (max(start, users), min(start + 250, meta_end), meta_table), (max(start, meta_end), min(start + 250, count), table)]:
                    if begin >= end:
                        continue
                    rows = []
                    for i in range(begin, end):
                        date = (STAMP + timedelta(days=i % scale.days)).strftime('%Y-%m-%d %H:%M:%S')
                        if name == 'users':
                            rows.append(f"({i + 1},'training-user-{i}','NOT-A-REAL-HASH','user-{i}@example.invalid','{date}')")
                        elif name == meta_table:
                            uid = (i - users) % users + 1
                            if site == 'wordpress':
                                role = 'administrator' if uid % 50 == 1 else 'editor'
                                value = f'a:1:{{s:{len(role)}:"{role}";b:1;}}'
                                rows.append(f"({i + 1},{uid},'wp_capabilities','{value}')")
                            else:
                                rows.append(f"({uid},{8 if uid % 50 == 1 else 2})")
                        else:
                            content = f'Synthetic article {i}. ' + 'Example content. ' * (i % 40)
                            if i % 1000 == 0:
                                content += '<a href="https://promotion.example.invalid/">Synthetic promotion</a>'
                            tail = "'publish','post'" if site == 'wordpress' else '1,1'
                            rows.append(f"({i + 1},{i % users + 1},'{date}','{content}','Training article {i}',{tail})")
                    stream.write(f'INSERT INTO `{prefix}_{name}` VALUES ' + ','.join(rows) + ';\n')
        os.utime(dump, (STAMP.timestamp(), STAMP.timestamp()))
        total_bytes += dump.stat().st_size
    progress('SQL dumps', scale.sql_rows, scale.sql_rows, .75, .25)
    conn = db.connect(case)
    try:
        with conn:
            for kind, path in [('webroot', root / 'wordpress'), ('webroot', root / 'joomla'),
                               ('access_logs', logs), ('sql_dump', root / 'wordpress.sql'), ('sql_dump', root / 'joomla.sql')]:
                conn.execute('INSERT INTO evidence(kind,path,label,added) VALUES (?,?,?,?)',
                             (kind, str(path), 'Synthetic performance evidence', db.now()))
    finally:
        conn.close()
    stats = {'bytes': total_bytes, 'requests': scale.requests, 'files': scale.files,
             'suspicious_requests': suspicious, 'seconds': round(time.monotonic() - started, 3)}
    manifest(case, state='ready', stats=stats)
    return stats


def enqueue(workspace, manager, analyse, *, size='large', run_analysis=True):
    """One generating job per workspace; regular analysis takes over afterwards."""
    from server.jobs import CaseBusy
    if size not in ('small', 'large'):
        raise ValueError('Unknown testcase size.')
    with LOCK:
        with manager._lock:
            if any(c.scan_context.get('mode') == 'testcase' and Path(key[0]).parent == Path(workspace)
                   for key, c in manager.live.items()):
                raise CaseBusy('A testcase is already being generated in this workspace.')
        if shutil.disk_usage(workspace).free < (8 * 1024**3 if size == 'large' else 32 * 1024**2):
            raise ValueError('Not enough free space for this testcase and its estimated analysis index.')
        case = workspaces.create_case(workspace, 'Performance case - Large' if size == 'large' else 'Training case',
            notes='SYNTHETIC TRAINING DATA. Generation and analysis do not make analyst decisions.')
        manifest(case, version=VERSION, seed=SEED, state='queued', size=size, run_analysis=run_analysis)

        def cancelled():
            manifest(case, state='cancelled', message='Generation incomplete; no automatic analysis was started.')

        def run(ctx):
            try:
                if size == 'large':
                    stats = generate(case, ctx)
                else:
                    from server.casework.testcase import generate as small
                    small(workspace, analyse=False, case=case)
                    stats = {'files': 7, 'requests': 9}
                    manifest(case, state='ready', stats=stats)
                if ctx.cancelled():
                    cancelled()
                    return stats
                if run_analysis:
                    # Generator owns this case; normal user operations remain
                    # excluded until it has submitted all regular analysis jobs.
                    with manager._schedule_lock:
                        if not ctx.cancelled():
                            result = analyse(case.name)
                            manifest(case, analysis=result)
                return stats
            except InterruptedError:
                cancelled()
                return {'partial': True}
            except Exception:
                manifest(case, state='failed', message='Generation or analysis submission failed; inspect the job error.')
                raise
        job = manager.submit(case, 'generate_testcase', run, on_cancel=cancelled,
                             scan_context={'mode': 'testcase', 'size': size})
        return {'slug': case.name, 'job_id': job}
