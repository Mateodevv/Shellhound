"""Bounded CMS semantics extracted while a SQL dump is streamed.

The SQL engine remains the parser of record.  This module only receives
decoded INSERT rows and turns well-known WordPress/Joomla structures into a
small, non-secret snapshot for the Database workspace.  Complete values stay
in the evidence file; password hashes and session verifiers never enter the
snapshot.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath

from server import phpserialize


_LIMITS = {
    "configuration": 100,
    "extensions": 1_500,
    "access": 750,
    "persistence": 500,
}
_CONTENT_CANDIDATES = 500
_CONTENT_LIMIT = 250
_URL_RE = re.compile(r"(?i)https?://([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)(?::\d+)?(?:[/\s'\"<]|$)")
_CODE_SIGNALS = (
    ("script", re.compile(r"(?i)<script[\s>]")),
    ("iframe", re.compile(r"(?i)<iframe[\s>]")),
    ("javascript", re.compile(r"(?i)javascript\s*:|document\s*\.\s*write\s*\(")),
    ("php", re.compile(r"<\?php|<\?=")),
    ("encoded", re.compile(r"(?i)(?:base64_decode|gzinflate|str_rot13)\s*\(|[A-Za-z0-9+/]{180,}={0,2}")),
)


_FALLBACK_COLUMNS = {
    "options": ("option_id", "option_name", "option_value", "autoload"),
    "sitemeta": ("meta_id", "site_id", "meta_key", "meta_value"),
    "usermeta": ("umeta_id", "user_id", "meta_key", "meta_value"),
    "postmeta": ("meta_id", "post_id", "meta_key", "meta_value"),
    "session": ("session_id", "client_id", "guest", "time", "data", "userid", "username"),
    "user_usergroup_map": ("user_id", "group_id"),
    "usergroups": ("id", "parent_id", "lft", "rgt", "title"),
}


def _suffix(table: str) -> str:
    low = str(table).lower().strip("`")
    for suffix in (
            "user_usergroup_map", "scheduler_tasks", "template_styles",
            "application_passwords", "action_logs", "usergroups",
            "sitemeta", "postmeta", "usermeta", "extensions", "options",
            "session", "content", "posts"):
        if low.endswith(suffix):
            return suffix
    return low.rsplit("_", 1)[-1]


def _mapping(columns, row, suffix):
    names = [str(name).strip().strip("`").lower() for name in columns or ()]
    if not names:
        names = list(_FALLBACK_COLUMNS.get(suffix, ()))
    return {name: row[index] for index, name in enumerate(names)
            if index < len(row)}


def _first(row, *names, default=""):
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return default


def _integer(value, default=0):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _text(value, limit=300):
    return str(value or "").replace("\x00", "").strip()[:limit]


def _epoch(value):
    raw = _integer(value, -1)
    if raw < 0:
        return ""
    try:
        return datetime.fromtimestamp(raw, tz=timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z")
    except (OSError, OverflowError, ValueError):
        return ""


def _json(value):
    if not isinstance(value, str) or len(value) > 1_048_576:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _structured(value):
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw[:1] in ("{", "["):
        parsed = _json(raw)
        if parsed is not None:
            return parsed
    return phpserialize.safe_loads(raw, max_bytes=1_048_576,
                                   max_depth=16, max_items=5_000)


def _sequence(value):
    parsed = _structured(value)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return list(parsed.values())
    return []


def _domains(value):
    text = _text(value, 20_000)
    return list(dict.fromkeys(match.group(1).lower().rstrip(".")
                              for match in _URL_RE.finditer(text)))[:8]


def _content_signals(value):
    text = _text(value, 200_000)
    signals = [name for name, pattern in _CODE_SIGNALS if pattern.search(text)]
    domains = _domains(text)
    if domains:
        signals.append("external_url")
    return list(dict.fromkeys(signals)), domains


def _manifest_version(value):
    manifest = _json(str(value or ""))
    if not isinstance(manifest, dict):
        return ""
    return _text(manifest.get("version"), 80)


def _plugin_slug(plugin_file):
    path = _text(plugin_file, 500).replace("\\", "/").strip("/")
    if not path or path.startswith(".") or ".." in PurePosixPath(path).parts:
        return ""
    first = path.split("/", 1)[0]
    return first.rsplit(".", 1)[0] if "/" not in path else first


class Collector:
    """Accumulates only bounded, derived observations for one dump."""

    def __init__(self):
        self.out = {key: [] for key in _LIMITS}
        self.content = []
        self.wp_attachments = {}
        self.joomla_groups = {}
        self.joomla_memberships = []

    def _add(self, category, item):
        target = self.out[category]
        if len(target) >= _LIMITS[category]:
            return
        item["source_table"] = _text(item.get("source_table"), 160)
        item["source_row"] = _integer(item.get("source_row"))
        target.append(item)

    def _add_content(self, item):
        self.content.append(item)
        if len(self.content) > _CONTENT_CANDIDATES * 2:
            self._trim_content(_CONTENT_CANDIDATES)

    def _trim_content(self, limit):
        suspicious = sorted(
            (item for item in self.content if item.get("signals")),
            key=lambda item: str(item.get("modified") or item.get("created") or ""),
            reverse=True)
        ordinary = sorted(
            (item for item in self.content if not item.get("signals")),
            key=lambda item: str(item.get("modified") or item.get("created") or ""),
            reverse=True)
        self.content = (suspicious + ordinary)[:limit]

    def collect(self, table, columns, rows, *, row_offset=0):
        suffix = _suffix(table)
        for offset, values in enumerate(rows, row_offset + 1):
            row = _mapping(columns, values, suffix)
            if suffix == "options":
                self._wordpress_option(table, offset, row)
            elif suffix == "sitemeta":
                self._wordpress_sitemeta(table, offset, row)
            elif suffix == "usermeta":
                self._wordpress_usermeta(table, offset, row)
            elif suffix == "posts":
                self._wordpress_post(table, offset, row)
            elif suffix == "postmeta":
                self._wordpress_postmeta(row)
            elif suffix == "extensions":
                self._joomla_extension(table, offset, row)
            elif suffix == "session":
                self._joomla_session(table, offset, row)
            elif suffix == "scheduler_tasks":
                self._joomla_task(table, offset, row)
            elif suffix == "content":
                self._joomla_content(table, offset, row)
            elif suffix == "usergroups":
                group_id = _text(_first(row, "id"), 40)
                if group_id:
                    self.joomla_groups[group_id] = _text(_first(row, "title"), 160)
            elif suffix == "user_usergroup_map":
                self.joomla_memberships.append((
                    _text(_first(row, "user_id"), 40),
                    _text(_first(row, "group_id"), 40), table, offset))
            elif suffix == "action_logs":
                self._joomla_action(table, offset, row)
            elif suffix == "template_styles":
                self._joomla_template(table, offset, row)

    def _wordpress_option(self, table, row_no, row):
        name = _text(_first(row, "option_name"), 190)
        value = _first(row, "option_value")
        if name == "active_plugins":
            for plugin in _sequence(value):
                plugin_file = _text(plugin, 500)
                slug = _plugin_slug(plugin_file)
                if slug:
                    self._add("extensions", {
                        "cms": "WordPress", "key": plugin_file,
                        "name": slug, "type": "plugin", "scope": "site",
                        "enabled": True, "version": "", "folder": "",
                        "source_table": table, "source_row": row_no,
                    })
        elif name in ("template", "stylesheet"):
            slug = _text(value, 190)
            if slug:
                self._add("extensions", {
                    "cms": "WordPress", "key": f"theme:{slug}",
                    "name": slug, "type": "theme",
                    "scope": "parent" if name == "template" else "active",
                    "enabled": True, "version": "", "folder": "",
                    "source_table": table, "source_row": row_no,
                })
        elif name == "cron":
            self._wordpress_cron(table, row_no, value)

        safe_options = {
            "siteurl", "home", "users_can_register", "default_role",
            "template", "stylesheet", "permalink_structure", "blog_public",
            "using_application_passwords", "auto_update_plugins",
        }
        if name in safe_options:
            display = value
            if name == "auto_update_plugins":
                display = ", ".join(_text(item, 160) for item in _sequence(value))
            self._add("configuration", {
                "cms": "WordPress", "key": name,
                "value": _text(display, 500), "autoload": _text(_first(row, "autoload"), 20),
                "source_table": table, "source_row": row_no,
            })

    def _wordpress_sitemeta(self, table, row_no, row):
        key = _text(_first(row, "meta_key"), 190)
        if key != "active_sitewide_plugins":
            return
        parsed = _structured(_first(row, "meta_value"))
        plugins = parsed.keys() if isinstance(parsed, dict) else _sequence(parsed)
        for plugin in plugins:
            plugin_file = _text(plugin, 500)
            slug = _plugin_slug(plugin_file)
            if not slug:
                continue
            activated = ""
            if isinstance(parsed, dict):
                activated = _epoch(parsed.get(plugin))
            self._add("extensions", {
                "cms": "WordPress", "key": plugin_file,
                "name": slug, "type": "plugin", "scope": "network",
                "enabled": True, "version": "", "folder": "",
                "activated": activated,
                "source_table": table, "source_row": row_no,
            })

    def _wordpress_usermeta(self, table, row_no, row):
        user_id = _text(_first(row, "user_id"), 40)
        key = _text(_first(row, "meta_key"), 190).lower()
        value = _first(row, "meta_value")
        if not user_id:
            return
        if key.endswith("capabilities"):
            parsed = _structured(value)
            if isinstance(parsed, dict):
                enabled = sorted(_text(name, 160) for name, state in parsed.items()
                                 if state and not str(name).startswith("__"))
                if enabled:
                    self._add("access", {
                        "cms": "WordPress", "kind": "capabilities",
                        "key": f"user:{user_id}:capabilities", "user_id": user_id,
                        "label": ", ".join(enabled[:12]), "roles": enabled[:50],
                        "source_table": table, "source_row": row_no,
                    })
        elif key.endswith("session_tokens"):
            parsed = _structured(value)
            sessions = parsed.values() if isinstance(parsed, dict) else _sequence(parsed)
            for index, session in enumerate(sessions):
                if not isinstance(session, dict):
                    continue
                self._add("access", {
                    "cms": "WordPress", "kind": "session",
                    "key": f"user:{user_id}:session:{index}", "user_id": user_id,
                    "label": "Active WordPress session",
                    "created": _epoch(session.get("login")),
                    "expires": _epoch(session.get("expiration")),
                    "last_ip": _text(session.get("ip"), 80),
                    "user_agent": _text(session.get("ua"), 300),
                    "source_table": table, "source_row": row_no,
                })
        elif key == "_application_passwords":
            for index, password in enumerate(_sequence(value)):
                if not isinstance(password, dict):
                    continue
                self._add("access", {
                    "cms": "WordPress", "kind": "application_password",
                    "key": f"user:{user_id}:app-password:{index}",
                    "user_id": user_id,
                    "label": _text(password.get("name"), 160) or "Application password",
                    "created": _epoch(password.get("created")),
                    "last_used": _epoch(password.get("last_used")),
                    "last_ip": _text(password.get("last_ip"), 80),
                    "source_table": table, "source_row": row_no,
                })

    def _wordpress_cron(self, table, row_no, value):
        parsed = _structured(value)
        if not isinstance(parsed, dict):
            return
        seen = 0
        for timestamp, hooks in parsed.items():
            if not str(timestamp).isdigit() or not isinstance(hooks, dict):
                continue
            for hook, instances in hooks.items():
                if not isinstance(instances, dict):
                    continue
                for instance in instances.values():
                    if not isinstance(instance, dict):
                        continue
                    args = instance.get("args")
                    domains = _domains(json.dumps(args, ensure_ascii=False, default=str))
                    self._add("persistence", {
                        "cms": "WordPress", "kind": "cron",
                        "key": f"cron:{timestamp}:{hook}:{seen}",
                        "label": _text(hook, 190), "state": "scheduled",
                        "next_run": _epoch(timestamp),
                        "schedule": _text(instance.get("schedule"), 80),
                        "interval": _integer(instance.get("interval")),
                        "domains": domains,
                        "source_table": table, "source_row": row_no,
                    })
                    seen += 1
                    if seen >= _LIMITS["persistence"]:
                        return

    def _wordpress_post(self, table, row_no, row):
        content_id = _text(_first(row, "id"), 40)
        post_type = _text(_first(row, "post_type"), 80) or "post"
        body = "\n".join(_text(_first(row, key), 200_000)
                         for key in ("post_content", "post_excerpt"))
        signals, domains = _content_signals(body)
        self._add_content({
            "cms": "WordPress", "key": f"post:{content_id}", "content_id": content_id,
            "type": post_type, "title": _text(_first(row, "post_title"), 240),
            "status": _text(_first(row, "post_status"), 80),
            "author": _text(_first(row, "post_author"), 40),
            "created": _text(_first(row, "post_date_gmt", "post_date"), 40),
            "modified": _text(_first(row, "post_modified_gmt", "post_modified"), 40),
            "path": "", "signals": signals, "domains": domains,
            "source_table": table, "source_row": row_no,
        })

    def _wordpress_postmeta(self, row):
        if _text(_first(row, "meta_key"), 190) != "_wp_attached_file":
            return
        post_id = _text(_first(row, "post_id"), 40)
        path = _text(_first(row, "meta_value"), 500).replace("\\", "/")
        if post_id and path and ".." not in PurePosixPath(path).parts:
            self.wp_attachments[post_id] = path

    def _joomla_extension(self, table, row_no, row):
        ext_id = _text(_first(row, "extension_id", "id"), 40)
        ext_type = _text(_first(row, "type"), 80) or "extension"
        element = _text(_first(row, "element", "name"), 190)
        name = _text(_first(row, "name", "element"), 190)
        if not element and not name:
            return
        self._add("extensions", {
            "cms": "Joomla", "key": f"extension:{ext_id or element}",
            "name": name or element, "element": element,
            "type": ext_type, "scope": "administrator" if _integer(
                _first(row, "client_id")) else "site",
            "enabled": bool(_integer(_first(row, "enabled", default=1), 1)),
            "protected": bool(_integer(_first(row, "protected"))),
            "folder": _text(_first(row, "folder"), 120),
            "version": _manifest_version(_first(row, "manifest_cache")),
            "source_table": table, "source_row": row_no,
        })

    def _joomla_template(self, table, row_no, row):
        template = _text(_first(row, "template"), 190)
        if not template:
            return
        self._add("extensions", {
            "cms": "Joomla", "key": f"template-style:{_text(_first(row, 'id'), 40)}",
            "name": _text(_first(row, "title"), 190) or template,
            "element": template, "type": "template",
            "scope": "administrator" if _integer(_first(row, "client_id")) else "site",
            "enabled": bool(_integer(_first(row, "home"))),
            "folder": "", "version": "", "style": True,
            "source_table": table, "source_row": row_no,
        })

    def _joomla_session(self, table, row_no, row):
        if _integer(_first(row, "guest"), 1) != 0:
            return
        user_id = _text(_first(row, "userid", "user_id"), 40)
        username = _text(_first(row, "username"), 160)
        if not user_id and not username:
            return
        self._add("access", {
            "cms": "Joomla", "kind": "session",
            "key": f"user:{user_id or username}:session:{row_no}",
            "user_id": user_id, "label": username or "Active Joomla session",
            "created": _epoch(_first(row, "time")),
            "client": "administrator" if _integer(_first(row, "client_id")) else "site",
            "source_table": table, "source_row": row_no,
        })

    def _joomla_task(self, table, row_no, row):
        task_id = _text(_first(row, "id"), 40) or str(row_no)
        rules = _json(str(_first(row, "cron_rules", "execution_rules") or ""))
        schedule = ""
        if isinstance(rules, dict):
            schedule = _text(rules.get("exp") or rules.get("rule-type"), 160)
        params = _text(_first(row, "params"), 20_000)
        self._add("persistence", {
            "cms": "Joomla", "kind": "scheduled_task",
            "key": f"task:{task_id}",
            "label": _text(_first(row, "title", "type"), 190),
            "task_type": _text(_first(row, "type"), 190),
            "state": "enabled" if _integer(_first(row, "state")) else "disabled",
            "last_run": _text(_first(row, "last_execution", "latest_execution"), 40),
            "next_run": _text(_first(row, "next_execution"), 40),
            "schedule": schedule, "domains": _domains(params),
            "priority": _integer(_first(row, "priority")),
            "source_table": table, "source_row": row_no,
        })

    def _joomla_content(self, table, row_no, row):
        content_id = _text(_first(row, "id"), 40)
        body = "\n".join(_text(_first(row, key), 200_000)
                         for key in ("introtext", "fulltext"))
        signals, domains = _content_signals(body)
        self._add_content({
            "cms": "Joomla", "key": f"content:{content_id}",
            "content_id": content_id, "type": "article",
            "title": _text(_first(row, "title"), 240),
            "status": _text(_first(row, "state"), 40),
            "author": _text(_first(row, "created_by"), 40),
            "created": _text(_first(row, "created"), 40),
            "modified": _text(_first(row, "modified"), 40),
            "path": "", "signals": signals, "domains": domains,
            "source_table": table, "source_row": row_no,
        })

    def _joomla_action(self, table, row_no, row):
        user_id = _text(_first(row, "user_id"), 40)
        self._add("access", {
            "cms": "Joomla", "kind": "action_log",
            "key": f"action:{_text(_first(row, 'id'), 40) or row_no}",
            "user_id": user_id,
            "label": _text(_first(row, "message_key", "message_language", "context"), 190),
            "context": _text(_first(row, "context", "type"), 160),
            "created": _text(_first(row, "log_date", "created_date"), 40),
            "last_ip": _text(_first(row, "ip_address"), 80),
            "source_table": table, "source_row": row_no,
        })

    def finish(self, cms_names):
        cms = set(cms_names or ())
        allowed = {name for name in ("WordPress", "Joomla") if name in cms}
        for user_id, group_id, table, row_no in self.joomla_memberships:
            if "Joomla" not in allowed or not user_id or not group_id:
                continue
            title = self.joomla_groups.get(group_id) or f"Group {group_id}"
            self._add("access", {
                "cms": "Joomla", "kind": "group",
                "key": f"user:{user_id}:group:{group_id}", "user_id": user_id,
                "label": title, "group_id": group_id,
                "source_table": table, "source_row": row_no,
            })

        for item in self.content:
            if item.get("cms") == "WordPress":
                item["path"] = self.wp_attachments.get(item.get("content_id", ""), "")
                if item["path"] and item.get("type") == "attachment":
                    suffix = PurePosixPath(item["path"]).suffix.lower()
                    if suffix in (".php", ".phtml", ".phar", ".cgi", ".pl"):
                        item["signals"] = list(dict.fromkeys(
                            [*item.get("signals", []), "executable_attachment"]))
        self._trim_content(_CONTENT_LIMIT)

        result = {}
        for category, rows in self.out.items():
            filtered = [row for row in rows if row.get("cms") in allowed]
            seen = set()
            deduped = []
            for row in filtered:
                identity = (row.get("cms"), row.get("key"), row.get("source_table"),
                            row.get("source_row"))
                if identity in seen:
                    continue
                seen.add(identity)
                deduped.append(row)
            result[category] = deduped
        result["content"] = [row for row in self.content
                             if row.get("cms") in allowed]
        result["cms"] = sorted(allowed)
        result["truncated"] = {
            category: len(self.out[category]) >= limit
            for category, limit in _LIMITS.items()
        }
        result["truncated"]["content"] = len(self.content) >= _CONTENT_LIMIT
        return result
