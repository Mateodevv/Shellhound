# server/engines/cmsinventory.py
"""CMS inventory: WordPress/Joomla installs + every extension with version.

Ported from legacy core/cms.py + modules/cms_inventory.py. One directory walk
finds the installs; each install is then inventoried (plugins, themes,
components, modules, templates). "(unknown)" versions are reported, never
silently dropped -- incomplete or manipulated extensions often lack manifests.
"""
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from server import db

WORDPRESS = "WordPress"
JOOMLA = "Joomla"

_WP_VERSION_RE = re.compile(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]")
_J_CONST_RE = re.compile(
    r"const\s+(MAJOR_VERSION|MINOR_VERSION|PATCH_VERSION)\s*=\s*(\d+)")
_J_RELEASE_RE = re.compile(r"const\s+RELEASE\s*=\s*['\"]([\d.]+)['\"]")
_J_DEVLEVEL_RE = re.compile(r"const\s+DEV_LEVEL\s*=\s*['\"](\d+)['\"]")

_WP_HEADER_RES = {
    "plugin_name": re.compile(r"^[ \t/*#@]*Plugin Name:\s*(.+?)\s*$", re.M | re.I),
    "theme_name": re.compile(r"^[ \t/*#@]*Theme Name:\s*(.+?)\s*$", re.M | re.I),
    "version": re.compile(r"^[ \t/*#@]*Version:\s*(.+?)\s*$", re.M | re.I),
}


def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _read_head(path, size=8192):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(size)
    except OSError:
        return ""


def parse_wp_version(text):
    m = _WP_VERSION_RE.search(text)
    return m.group(1) if m else None


def parse_joomla_version(text):
    consts = dict(_J_CONST_RE.findall(text))
    if {"MAJOR_VERSION", "MINOR_VERSION", "PATCH_VERSION"} <= consts.keys():
        return "{}.{}.{}".format(consts["MAJOR_VERSION"], consts["MINOR_VERSION"],
                                 consts["PATCH_VERSION"])
    release = _J_RELEASE_RE.search(text)
    dev_level = _J_DEVLEVEL_RE.search(text)
    if release and dev_level:
        return f"{release.group(1)}.{dev_level.group(1)}"
    return None


def find_installs(target_dir):
    """All CMS installs under target_dir in a SINGLE walk.

    Every install carries the FILE its version was read from -- a version one
    cannot go back and verify has no place in a report."""
    wordpress, joomla4, joomla3 = {}, {}, {}
    for dirpath, _dirnames, filenames in os.walk(target_dir):
        files = {name.lower(): name for name in filenames}
        d = Path(dirpath)
        name = d.name.lower()
        if name == "wp-includes" and "version.php" in files:
            source = d / files["version.php"]
            wordpress.setdefault(
                d.parent, (parse_wp_version(_read_text(source)), source))
        elif (name == "src" and d.parent.name.lower() == "libraries"
                and "version.php" in files):
            source = d / files["version.php"]
            joomla4.setdefault(
                d.parents[1], (parse_joomla_version(_read_text(source)), source))
        elif (name == "version" and d.parent.name.lower() == "cms"
                and d.parent.parent.name.lower() == "libraries"
                and "version.php" in files):
            source = d / files["version.php"]
            joomla3.setdefault(
                d.parents[2], (parse_joomla_version(_read_text(source)), source))
    installs = [{"type": WORDPRESS, "root": root, "version": found[0],
                 "source": found[1]}
                for root, found in wordpress.items()]
    joomla_roots = {**joomla3, **joomla4}
    installs += [{"type": JOOMLA, "root": root, "version": found[0],
                  "source": found[1]}
                 for root, found in joomla_roots.items()]
    return sorted(installs, key=lambda i: str(i["root"]))


# --- WordPress --------------------------------------------------------------

def _wp_plugin_header(php_path):
    head = _read_head(php_path)
    name = _WP_HEADER_RES["plugin_name"].search(head)
    if not name:
        return None
    version = _WP_HEADER_RES["version"].search(head)
    return name.group(1), version.group(1) if version else "(unknown)"


# Every extension yields (type, name, slug, version, PATH, SOURCE):
#   PATH   -- where the extension sits (directory or single file). The
#             attribution of flagged files hangs on this.
#   SOURCE -- the file the VERSION was read from, or None.
# The two come apart as soon as the manifest sits somewhere other than the
# extension: a WordPress theme IS the directory, its version sits in
# style.css.

def inventory_wordpress(root):
    plugins_dir = root / "wp-content" / "plugins"
    if plugins_dir.is_dir():
        for entry in sorted(plugins_dir.iterdir()):
            if entry.is_file() and entry.suffix == ".php":
                header = _wp_plugin_header(entry)
                if header:
                    yield "Plugin", header[0], entry.stem, header[1], entry, entry
            elif entry.is_dir():
                header = None
                for php in sorted(entry.glob("*.php")):
                    header = _wp_plugin_header(php)
                    if header:
                        yield "Plugin", header[0], entry.name, header[1], php, php
                        break
                if header is None:
                    yield "Plugin", entry.name, entry.name, "(unknown)", entry, None

    themes_dir = root / "wp-content" / "themes"
    if themes_dir.is_dir():
        for entry in sorted(themes_dir.iterdir()):
            if not entry.is_dir():
                continue
            style = entry / "style.css"
            head = _read_head(style)
            name = _WP_HEADER_RES["theme_name"].search(head)
            version = _WP_HEADER_RES["version"].search(head)
            yield ("Theme",
                   name.group(1) if name else entry.name,
                   entry.name,
                   version.group(1) if version else "(unknown)",
                   entry,
                   style if version else None)
            yield from _theme_bundled_plugins(entry)


def _theme_bundled_plugins(theme_dir, max_depth=3):
    """Plugins shipped INSIDE a theme -- found by inference, said so.

    A plugin bundled below wp-content/themes/<slug>/ is invisible to the
    flat plugins/ listing, and that is precisely the distribution channel
    that spread Slider Revolution (CVE-2015-1579): the vulnerable version
    sat in commercial themes long after the plugin itself was fixed, so an
    inventory that cannot see it answers "not installed" about the thing
    the case is about.

    BOUNDED, AND UNDER ITS OWN TYPE. Real themes ship TGM-Plugin-Activation
    stubs, demo installers and vendor trees that carry `Plugin Name:`
    headers legitimately -- so the walk stops three levels below the theme,
    prunes node_modules/vendor before descending (an unbounded walk reads
    thousands of files there), and every hit is typed "Plugin (bundled in
    theme <slug>)" rather than posing as a canonically installed plugin:
    the reader sees these were inferred, not found in the usual place. One
    entry per directory, like the plugins/ listing above."""
    base_depth = len(theme_dir.parts)
    for dirpath, dirnames, filenames in os.walk(theme_dir):
        here = Path(dirpath)
        if len(here.parts) - base_depth >= max_depth:
            # Neither descend NOR read here -- the bound is on what gets
            # opened, not only on how far the walk lists.
            dirnames[:] = []
            continue
        dirnames[:] = sorted(d for d in dirnames
                             if d not in ("node_modules", "vendor"))
        if here == theme_dir:
            # style.css and functions.php live here; a `Plugin Name:` at
            # the theme's own top level would be the theme mislabelling
            # itself, not a bundled plugin.
            continue
        for fname in sorted(filenames):
            if not fname.endswith(".php"):
                continue
            header = _wp_plugin_header(here / fname)
            if header:
                yield (f"Plugin (bundled in theme {theme_dir.name})",
                       header[0], here.name, header[1], here, here / fname)
                break


# --- Joomla -----------------------------------------------------------------

def _joomla_manifest(xml_path):
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, OSError):
        return None
    root = tree.getroot()
    if root.tag not in ("extension", "install"):
        return None
    name = root.findtext("name") or xml_path.stem
    version = root.findtext("version") or "(unknown)"
    return name.strip(), version.strip()


def _joomla_dir_entries(base_dir, ext_type):
    if not base_dir.is_dir():
        return
    for entry in sorted(base_dir.iterdir()):
        if not entry.is_dir():
            continue
        manifest = None
        for xml_file in sorted(entry.glob("*.xml")):
            manifest = _joomla_manifest(xml_file)
            if manifest:
                yield ext_type, manifest[0], entry.name, manifest[1], xml_file, xml_file
                break
        if manifest is None:
            yield ext_type, entry.name, entry.name, "(unknown)", entry, None


def inventory_joomla(root):
    yield from _joomla_dir_entries(root / "administrator" / "components", "Component")
    yield from _joomla_dir_entries(root / "components", "Component (Site)")
    yield from _joomla_dir_entries(root / "modules", "Module")
    yield from _joomla_dir_entries(root / "administrator" / "modules", "Module (Admin)")

    plugins_dir = root / "plugins"
    if plugins_dir.is_dir():
        for group in sorted(plugins_dir.iterdir()):
            if group.is_dir():
                yield from _joomla_dir_entries(group, f"Plugin ({group.name})")

    for tpl_base, label in ((root / "templates", "Template"),
                            (root / "administrator" / "templates", "Template (Admin)")):
        if not tpl_base.is_dir():
            continue
        for entry in sorted(tpl_base.iterdir()):
            if not entry.is_dir() or entry.name == "system":
                continue
            details = entry / "templateDetails.xml"
            manifest = _joomla_manifest(details) if details.is_file() else None
            if manifest:
                yield label, manifest[0], entry.name, manifest[1], details, details
            else:
                yield label, entry.name, entry.name, "(unknown)", entry, None


# --- the engine -------------------------------------------------------------

def scan(case_dir, targets, ctx=None):
    """Inventory every install under `targets` into case.db."""
    stats = {"installs": 0, "items": 0, "unknown_versions": 0}
    conn = db.connect(case_dir)
    try:
        conn.execute("DELETE FROM cms_items")
        conn.execute("DELETE FROM cms_installs")
        for target in targets:
            if ctx is not None and ctx.cancelled():
                break
            if ctx is not None:
                ctx.progress(0.05, f"Searching CMS installations in {target}…")
            installs = find_installs(target)
            for n, install in enumerate(installs):
                root = str(install["root"])
                version = install["version"] or "(unknown)"
                if ctx is not None:
                    ctx.progress(0.2 + 0.75 * (n / max(1, len(installs))),
                                 f"Inventorying {install['type']} — {root}")
                cur = conn.execute(
                    "INSERT OR REPLACE INTO cms_installs (root, cms, version,"
                    " version_source) VALUES (?,?,?,?)",
                    (root, install["type"], version,
                     str(install.get("source") or "")))
                install_id = cur.lastrowid
                stats["installs"] += 1
                if version == "(unknown)":
                    stats["unknown_versions"] += 1
                inventory_fn = (inventory_wordpress if install["type"] == WORDPRESS
                                else inventory_joomla)
                for ext_type, name, slug, ext_version, path, source in inventory_fn(
                        Path(install["root"])):
                    conn.execute(
                        "INSERT INTO cms_items (install_id, type, name, slug,"
                        " version, path, version_source) VALUES (?,?,?,?,?,?,?)",
                        (install_id, ext_type, name, slug, ext_version,
                         str(path), str(source or "")))
                    stats["items"] += 1
                    if ext_version == "(unknown)":
                        stats["unknown_versions"] += 1
        conn.commit()
    finally:
        conn.close()
    return stats
