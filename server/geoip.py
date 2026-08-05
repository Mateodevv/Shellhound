# server/geoip.py
"""Country attribution for IP addresses -- offline, from a local database.

PRINCIPLE: NO ONLINE LOOKUP, EVER. Sending the IPs of a case to a GeoIP web
service would mean leaking evidence to a third party -- exactly what this
tool prevents everywhere else. This module therefore reads nothing but an
MMDB file the analyst obtains and places in the workspace themselves
(GeoLite2-Country from MaxMind or the DB-IP Country Lite; both free, neither
may be redistributed by us).

It is found via SHELLHOUND_GEOIP or as a `*.mmdb` in the workspace. Without a
file there are no flags -- but the SPECIAL RANGES come anyway: whether an
address is private (RFC 1918), loopback or a documentation range is something
the standard library knows without any database, and in a case that is often
the more important statement (a private source IP in an access log means the
traffic came through a proxy or from the local network).

And because GeoIP is readily over-interpreted, every answer says what it is:
an estimate of the REGISTRATION, not a location."""
import ipaddress
import os
import threading
from pathlib import Path

from server.i18n import t

try:
    import maxminddb
except ImportError:                                        # pragma: no cover
    maxminddb = None

_lock = threading.Lock()
_reader = None
_reader_path = ""
_cache = {}
_CACHE_CAP = 50000

# Documentation ranges (RFC 5737 / 3849). "Deliberately unassignable" is a
# better answer than a silent miss in the database.
_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
              "2001:db8::/32")]


def find_db(workspace):
    """The path to the MMDB, or ''. The environment variable wins -- whoever
    sets it has decided; otherwise the first *.mmdb in the workspace."""
    env = os.environ.get("SHELLHOUND_GEOIP", "").strip()
    if env and os.path.isfile(env):
        return env
    try:
        for p in sorted(Path(workspace).glob("*.mmdb")):
            return str(p)
    except OSError:
        pass
    return ""


def _get_reader(workspace):
    """Open the reader lazily and keep it open; anew when the file
    changed."""
    global _reader, _reader_path
    if maxminddb is None:
        return None
    path = find_db(workspace)
    with _lock:
        if path != _reader_path:
            if _reader is not None:
                try:
                    _reader.close()
                except Exception:
                    pass
            _reader, _reader_path = None, path
            _cache.clear()
            if path:
                try:
                    _reader = maxminddb.open_database(path)
                except Exception:
                    _reader, _reader_path = None, ""
        return _reader


def status(workspace, lang="en"):
    """What the interface needs to know: does it work, and out of what."""
    if maxminddb is None:
        return {"available": False, "source": "",
                "why": t(lang, "geo.noPackage")}
    reader = _get_reader(workspace)
    if reader is None:
        return {"available": False, "source": "",
                "why": t(lang, "geo.noDatabase")}
    return {"available": True, "source": os.path.basename(_reader_path),
            "why": ""}


def _special(addr, lang):
    """Special ranges BEFORE the database: the standard library knows these
    for certain, and forensically the statement is often more important than
    a country."""
    for net in _DOC_NETS:
        if addr.version == net.version and addr in net:
            return t(lang, "geo.documentation")
    if addr.is_loopback:
        return t(lang, "geo.loopback")
    if addr.is_link_local:
        return "Link-local"
    if addr.is_multicast:
        return "Multicast"
    if addr.is_private:
        return t(lang, "geo.private")
    if not addr.is_global:
        return t(lang, "geo.reserved")
    return None


# The only place in the entire tool that speaks outward -- and it does so
# only on an explicit click, for exactly one purpose: fetching the freely
# licensed country database from DB-IP (Creative Commons BY 4.0, no account
# required). NOT A BYTE OF CASE DATA GOES OUT -- the request contains nothing
# but the file name of the month.
_DBIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02d}.mmdb.gz"
DB_FILENAME = "dbip-country-lite.mmdb"


def download(workspace):
    """Fetch the DB-IP Country Lite into the workspace. Tries the current
    month, then the previous one (the edition appears monthly, and on the
    first of the month the new one is sometimes not there yet)."""
    global _reader, _reader_path
    import gzip
    import shutil
    import urllib.error
    import urllib.request
    from datetime import date

    if maxminddb is None:
        return {"ok": False, "error": "Python-Paket maxminddb fehlt -- "
                                      "pip install maxminddb"}
    today = date.today()
    months = [(today.year, today.month)]
    months.append((today.year - 1, 12) if today.month == 1
                  else (today.year, today.month - 1))
    target = Path(workspace) / DB_FILENAME
    tmp = target.with_suffix(".mmdb.part")
    last_error = ""
    for y, m in months:
        url = _DBIP_URL.format(y=y, m=m)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "shellhound"})
            with urllib.request.urlopen(req, timeout=60) as resp, \
                    gzip.GzipFile(fileobj=resp) as gz, open(tmp, "wb") as out:
                shutil.copyfileobj(gz, out)
            # Check first, adopt second: half a file replacing a working
            # one would be worse than none at all.
            probe = maxminddb.open_database(str(tmp))
            probe.close()
            with _lock:
                if _reader is not None:
                    try:
                        _reader.close()
                    except Exception:
                        pass
                _reader, _reader_path = None, ""
                _cache.clear()
            os.replace(tmp, target)
            return {"ok": True, "source": target.name,
                    "size": target.stat().st_size, "month": f"{y}-{m:02d}"}
        except (urllib.error.URLError, OSError, ValueError) as e:
            last_error = str(e)
            try:
                tmp.unlink()
            except OSError:
                pass
            continue
    return {"ok": False, "error": f"download failed: {last_error}"}


def lookup(workspace, ip, lang="en"):
    """{'iso': 'de'|None, 'name': str, 'special': bool}, or None for junk.

    The cache is keyed by LANGUAGE AND ADDRESS: the country names and the
    descriptions of the special ranges depend on the language, and a cache
    keyed by address alone would hand out whichever language happened to
    ask first."""
    ip = str(ip).strip()
    key = (lang, ip)
    if key in _cache:
        return _cache[key]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    special = _special(addr, lang)
    if special:
        out = {"iso": None, "name": special, "special": True}
    else:
        out = None
        reader = _get_reader(workspace)
        if reader is not None:
            try:
                rec = reader.get(ip) or {}
            except Exception:
                rec = {}
            country = rec.get("country") or rec.get("registered_country") or {}
            iso = (country.get("iso_code") or "").lower()
            names = country.get("names") or {}
            name = names.get(lang) or names.get("en") or iso.upper()
            if iso:
                out = {"iso": iso, "name": name, "special": False}
            else:
                out = {"iso": None, "name": t(lang, "geo.unlisted"),
                       "special": False}
    if len(_cache) > _CACHE_CAP:
        _cache.clear()
    _cache[key] = out
    return out
