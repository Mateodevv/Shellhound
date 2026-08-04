# server/geoip.py
"""Länderzuordnung für IP-Adressen -- offline, aus einer lokalen Datenbank.

GRUNDSATZ: KEINE ONLINE-ABFRAGE, NIEMALS. Die IPs eines Falls an einen
GeoIP-Webdienst zu schicken hieße, Beweismittel an Dritte zu leaken -- exakt
das, was dieses Werkzeug überall sonst verhindert. Deshalb liest dieser
Modul ausschließlich eine MMDB-Datei, die der Analyst selbst besorgt und in
den Workspace legt (GeoLite2-Country von MaxMind oder das DB-IP Country
Lite; beide kostenlos, beide dürfen nicht von uns mitverteilt werden).

Gefunden wird sie über SHELLHOUND_GEOIP oder als `*.mmdb` im Workspace.
Ohne Datei gibt es keine Flaggen -- aber die SONDERBEREICHE kommen trotzdem:
ob eine Adresse privat (RFC 1918), Loopback oder ein Dokumentations-Bereich
ist, weiß die Standardbibliothek ohne jede Datenbank, und im Fall ist genau
das oft die wichtigere Aussage (eine private Quell-IP im Access-Log heißt:
der Verkehr kam durch einen Proxy oder aus dem eigenen Netz).

Und weil GeoIP gern überinterpretiert wird, sagt jede Antwort dazu, was sie
ist: eine Schätzung der REGISTRIERUNG, kein Aufenthaltsort."""
import ipaddress
import os
import threading
from pathlib import Path

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
    """Der Pfad zur MMDB, oder ''. Umgebungsvariable gewinnt -- wer sie
    setzt, hat sich entschieden; sonst die erste *.mmdb im Workspace."""
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
    """Reader lazily öffnen und offen halten; bei gewechselter Datei neu."""
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


def status(workspace):
    """Was die Oberfläche wissen muss: geht es, und woraus."""
    if maxminddb is None:
        return {"available": False, "source": "",
                "why": "Python-Paket maxminddb ist nicht installiert."}
    reader = _get_reader(workspace)
    if reader is None:
        return {"available": False, "source": "",
                "why": "Keine GeoIP-Datenbank gefunden — eine *.mmdb in den "
                       "Workspace legen (GeoLite2-Country oder DB-IP Lite) "
                       "oder SHELLHOUND_GEOIP setzen."}
    return {"available": True, "source": os.path.basename(_reader_path),
            "why": ""}


def _special(addr):
    """Sonderbereiche VOR der Datenbank: die Standardbibliothek weiß das
    sicher, und die Aussage ist forensisch oft wichtiger als ein Land."""
    for net in _DOC_NETS:
        if addr.version == net.version and addr in net:
            return "Dokumentations-Bereich (RFC 5737/3849) — absichtlich unzuordenbar"
    if addr.is_loopback:
        return "Loopback — der Server selbst"
    if addr.is_link_local:
        return "Link-local"
    if addr.is_multicast:
        return "Multicast"
    if addr.is_private:
        return ("Privates Netz (RFC 1918) — der Verkehr kam durch einen "
                "Proxy/Load-Balancer oder aus dem eigenen Netz")
    if not addr.is_global:
        return "Reservierter Bereich"
    return None


# Die einzige Stelle im ganzen Werkzeug, die nach draußen spricht -- und
# sie tut es nur auf einen expliziten Klick, zu genau einem Zweck: die frei
# lizenzierte Länder-Datenbank von DB-IP holen (Creative Commons BY 4.0,
# kein Konto nötig). ES GEHT KEIN BYTE FALLDATEN HINAUS -- der Request
# enthält nichts als den Dateinamen des Monats.
_DBIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02d}.mmdb.gz"
DB_FILENAME = "dbip-country-lite.mmdb"


def download(workspace):
    """Die DB-IP Country Lite in den Workspace laden. Probiert den
    aktuellen Monat, dann den Vormonat (die Ausgabe erscheint monatlich,
    am Monatsersten gibt es die neue manchmal noch nicht)."""
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
            # Erst prüfen, dann übernehmen: eine halbe Datei, die eine
            # funktionierende ersetzt, wäre schlechter als gar keine.
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
    return {"ok": False, "error": f"Download fehlgeschlagen: {last_error}"}


def lookup(workspace, ip):
    """{'iso': 'de'|None, 'name': str, 'special': bool} oder None bei Müll."""
    ip = str(ip).strip()
    if ip in _cache:
        return _cache[ip]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    special = _special(addr)
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
            name = names.get("de") or names.get("en") or iso.upper()
            if iso:
                out = {"iso": iso, "name": name, "special": False}
            else:
                out = {"iso": None, "name": "in der Datenbank nicht verzeichnet",
                       "special": False}
    if len(_cache) > _CACHE_CAP:
        _cache.clear()
    _cache[ip] = out
    return out
