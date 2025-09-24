# main_feeds.py
import sys, os, re, io, json, csv, time, base64, unicodedata
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from difflib import SequenceMatcher
import random
from contextlib import suppress
from urllib.parse import urlparse

import os, json, time, base64, asyncio, aiohttp, pathlib
from urllib.parse import urljoin
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from aiohttp import web  # <-- para webhook SSLMate

# --- Fix cierre asyncio en Windows (evita NoneType.close tras Ctrl+C)
if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

import aiohttp
from cachetools import TTLCache
from influxdb import InfluxDBClient
from py_console import console

# --- Módulos propios
import utils_functions as uf           # get_virustotal_report_from_url, get_abuseip_report, get_ip_address, clean_domain, is_ip
from email_sender import send_email

# ---- Maltiverse enrichment (optional) ----
try:
    from enrich_maltiverse import enrich_and_store  # you implement this module
    MALTIVERSE_ENABLED = True
except Exception:
    MALTIVERSE_ENABLED = False


# =================== Config ===================
with open('config.json', 'r', encoding='utf-8') as f:
    cfg = json.load(f)

INFLUX = InfluxDBClient(
    cfg["influx_ip"], cfg["influx_port"],
    cfg["influx_username"], cfg["influx_password"],
    cfg["influx_database"]
)

EMAIL_FROM = cfg["gmail_sender_email"]
EMAIL_PASS = cfg["gmail_app_password"]
EMAIL_TO   = cfg["email_recipent"]

# Feeds gratuitos
OPENPHISH_ENABLED = cfg.get("openphish_enabled", True)
OPENPHISH_URL     = cfg.get("openphish_url", "https://openphish.com/feed.txt")

URLHAUS_ENABLED   = cfg.get("urlhaus_enabled", True)
URLHAUS_RECENT    = cfg.get("urlhaus_recent_csv", "https://urlhaus.abuse.ch/downloads/csv_recent/")
URLHAUS_ONLINE    = cfg.get("urlhaus_online_csv", "https://urlhaus.abuse.ch/downloads/csv_online/")

PHISHTANK_ENABLED = cfg.get("phishtank_enabled", True)
PHISHTANK_CSV     = cfg.get("phishtank_csv", "https://data.phishtank.com/data/online-valid.csv")
PHISHTANK_APP_KEY = cfg.get("phishtank_app_key")  # opcional: data/<KEY>/online-valid.csv

SINKING_ENABLED   = cfg.get("sinking_enabled", True)
SINKING_BASE      = cfg.get("sinking_base", "https://phish.sinking.yachts")
SINKING_RECENT_MIN= int(cfg.get("sinking_recent_minutes", 60))

# CT Watcher (crt.sh) hosters
CTWATCH_ENABLED   = cfg.get("ctwatch_enabled", True)
CT_POLL_SEC       = int(cfg.get("ctwatch_poll_seconds", 900))
CT_BRANDS         = [s.strip() for s in cfg.get("ctwatch_brands", ["tenpo","banco","bank"])]
CT_HOSTERS        = [h.lower().strip() for h in cfg.get("ctwatch_hosters", [])]
CT_STATE_FILE     = cfg.get("ctwatch_state_file", "ctwatch_seen.txt")

# ===== SSLMATE (Cert Spotter) =====
SSLM_ENABLED   = bool(cfg.get("sslmate_enabled", False))
SSLM_API_KEY   = (cfg.get("sslmate_api_key") or "").strip()
SSLM_DOMAINS   = [str(s).strip() for s in cfg.get("sslmate_monitored_domains", []) if str(s).strip()]
SSLM_WB_HOST   = cfg.get("sslmate_webhook_host", "0.0.0.0")
SSLM_WB_PORT   = int(cfg.get("sslmate_webhook_port", 8787))
SSLM_WB_PATH   = cfg.get("sslmate_webhook_path", "/sslmate/webhook")
SSLM_WB_USER   = cfg.get("sslmate_webhook_basic_user", "sslmate")
SSLM_WB_PASS   = cfg.get("sslmate_webhook_basic_pass", "")
SSLM_AUTO_AUTH = bool(cfg.get("sslmate_auto_authorize_known", False))
SSLM_BASE      = "https://sslmate.com/api/v3/monitoring"

# Enriquecimientos
SPAMHAUS_ENABLED  = cfg.get("spamhaus_enabled", False) and bool(cfg.get("spamhaus_bearer_jwt"))
SPAMHAUS_URL_DOM  = cfg.get("spamhaus_domain_api_tmpl", "https://api.spamhaus.org/api/intel/v2/byobject/domain/{object}")
SPAMHAUS_URL_IP   = cfg.get("spamhaus_ip_api_tmpl",     "https://api.spamhaus.org/api/intel/v2/byobject/ip/{object}")
SPAMHAUS_JWT      = (cfg.get("spamhaus_bearer_jwt") or "").strip()
SPAMHAUS_KEY      = (cfg.get("spamhaus_api_key") or "").strip()

THREATFOX_ENABLED = cfg.get("threatfox_enabled", False)
THREATFOX_URL     = cfg.get("threatfox_api_url", "https://threatfox.abuse.ch/api/v1/")
THREATFOX_KEY     = (cfg.get("threatfox_api_key") or "").strip()

VT_API            = cfg.get("virustotal_api", "")
ABUSEIP_API       = cfg.get("abuseip_api", "")

# Polling
POLL_EVERY_SEC_OPENPHISH = int(cfg.get("poll_seconds_openphish", 300))
POLL_EVERY_SEC_URLHAUS   = int(cfg.get("poll_seconds_urlhaus", 300))
POLL_EVERY_SEC_PHISHTANK = int(cfg.get("poll_seconds_phishtank", 3600))
POLL_EVERY_SEC_SINKING   = int(cfg.get("poll_seconds_sinking", 120))
POLL_EVERY_SEC_CT        = int(cfg.get("ctwatch_poll_seconds", 900))

# Dedupe
DEDUP_MODE      = (cfg.get("dedupe_mode") or "url").lower()  # url | url_per_source | none
DEDUP_TTL_HOURS = int(cfg.get("dedupe_ttl_hours", 24))
SEEN_URLS       = TTLCache(maxsize=500_000, ttl=DEDUP_TTL_HOURS*3600)

# Notificación (correo)
NOTIFY_BRANDS   = [s.lower() for s in cfg.get("notify_brand_terms", ["tenpo","banco","bank"])]
NOTIFY_EXTS     = [s.lower() for s in cfg.get("notify_malware_exts", ["exe","ps1","msi"])]
BRAND_THR       = float(cfg.get("brand_fuzzy_threshold_domain", 0.80))
BRAND_ALLOW_LEET= bool(cfg.get("brand_allow_leetspeak", True))
NOTIFY_CHECK_URL= bool(cfg.get("notify_check_url", True))
EMAIL_BURST_MAX = int(cfg.get("email_burst_max", 10))
EMAIL_WINDOW_MIN= int(cfg.get("email_window_min", 15))
TENPO_TERMS = [s.lower() for s in cfg.get("notify_terms_tenpo", ["tenpo"])]
BANCO_TERMS = [s.lower() for s in cfg.get("notify_terms_banco", ["banco"])]
CHILE_TERMS = [s.lower() for s in cfg.get("notify_terms_chile", [])]

EMAIL_DEBUG   = bool(cfg.get("email_debug", False))

# Watch (metadatos para guardar en Influx/Grafana; opcional)
WATCH_ENABLED      = cfg.get("watch_enabled", True)
WATCH_TERMS        = [s.strip() for s in cfg.get("watch_terms", ["tenpo","banco","bank"])]
WATCH_TLDS         = set([s.lower() for s in cfg.get("watch_tlds", [])])
WATCH_THRESHOLD    = float(cfg.get("watch_threshold", 0.80))
WATCH_ONLY_MATCHES = bool(cfg.get("watch_only_matches", False))

# Globals para correo (ventana deslizante)
_email_window_hits: List[float] = []
_batch_for_email: List[Dict[str, Any]] = []
_last_email_flush: float = time.time()

console.info("Feeds enabled: openphish=%s urlhaus=%s phishtank=%s sinking=%s ctwatch=%s" %
             (OPENPHISH_ENABLED, URLHAUS_ENABLED, PHISHTANK_ENABLED, SINKING_ENABLED, CTWATCH_ENABLED))
console.info(f"Dedupe: mode={DEDUP_MODE} ttl_h={DEDUP_TTL_HOURS}")
console.info(f"Enrichment: VT={bool(VT_API)} AbuseIPDB={bool(ABUSEIP_API)} ThreatFox={THREATFOX_ENABLED} Spamhaus={SPAMHAUS_ENABLED}")
console.info(f"SSLMate: enabled={SSLM_ENABLED} webhook={SSLM_WB_HOST}:{SSLM_WB_PORT}{SSLM_WB_PATH} monitored={len(SSLM_DOMAINS)}")

# =================== Utils ===================
def now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def to_domain(x: str) -> str:
    s = (x or "").strip()
    if re.match(r'^\w+://', s):
        from urllib.parse import urlparse
        host = urlparse(s).netloc or s
    else:
        host = s
    return uf.clean_domain(host)

EXT_RE = re.compile(r'\.([a-z0-9]{1,6})(?:$|[?#/&])', re.I)
from urllib.parse import urlparse

def url_ext(url: str) -> str:
    try:
        p = urlparse(url or "")
        # último segmento del path (ej: "/a/b/file.exe" -> "file.exe")
        last = (p.path or "").rsplit("/", 1)[-1]
        if "." not in last:
            return ""
        ext = last.rsplit(".", 1)[-1].lower()
        # extensiones de 1..6 chars; evita confundir TLDs del host
        return ext if 1 <= len(ext) <= 6 else ""
    except Exception:
        return ""

def dedup(url: str, source: str) -> bool:
    if DEDUP_MODE == "none":
        return True
    u = (url or "").strip().lower()
    s = (source or "").strip().lower()
    key = u if DEDUP_MODE == "url" else f"{s}|{u}"
    if key in SEEN_URLS:
        return False
    SEEN_URLS[key] = True
    return True

# homigligos y el fyuzzing ... (_HOMO es la variable quien toma las letras o palabras raras)
_HOMO = {
    '0':'o', '1':'l', '3':'e', '4':'a', '5':'s', '7':'t',
    '@':'a', '$':'s', '!':'i', '|':'l',
    'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y','і':'i','к':'k'
}
_HOMO_TR = str.maketrans(_HOMO)

def _normalize(s: str) -> str:
    if not s: return ""
    s = unicodedata.normalize("NFKD", s.casefold())
    s = ''.join(ch for ch in s if not unicodedata.combining(ch))
    s = s.translate(_HOMO_TR)
    return s

_VARIANTS = {
    'a':'[a@4]','b':'[b8]','c':'[c]','e':'[e3€]','i':'[i1!|]','l':'[l1|]',
    'o':'[o0]','s':'[s$5]','t':'[t7+]','u':'[uµ]','y':'[y¥]',
    'p':'[p]','n':'[n]','k':'[k]'
}
def _brand_regex(brand: str) -> re.Pattern:
    parts = [_VARIANTS.get(ch, re.escape(ch)) for ch in brand.lower()]
    return re.compile(r'(?i)' + r'[\W_]{0,1}'.join(parts))  # permite separadores

def _lev(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def brand_hit_on_host(host: str, brands: List[str], threshold: float=0.80, allow_leet: bool=True) -> Optional[dict]:
    h_raw = host or ""
    h_norm = _normalize(h_raw.replace('-', ''))
    best = None
    for b in brands:
        b_norm = _normalize(b)
        if b_norm in h_norm:
            return {"term": b, "score": 1.0, "method": "substr"}
        if allow_leet and _brand_regex(b).search(h_raw):
            best = best or {"term": b, "score": 0.95, "method": "leet_regex"}
        for label in h_norm.split('.'):
            if not label: continue
            r = _lev(label, b_norm)
            if r >= threshold:
                cand = {"term": b, "score": float(r), "method": "fuzzy_domain"}
                if not best or cand["score"] > best["score"]:
                    best = cand
    return best

def brand_match_any(domain: str, url: str, brands: List[str], thr: float, allow_leet: bool=True) -> Optional[dict]:
    hit = brand_hit_on_host(domain or "", brands, thr, allow_leet)
    if hit:
        return hit
    if NOTIFY_CHECK_URL:
        u_norm = _normalize(url or "")
        for b in brands:
            if _normalize(b) in u_norm or _brand_regex(b).search(url or ""):
                return {"term": b, "score": 1.0, "method": "url_substr_or_leet"}
    return None

def should_trigger_email(domain: str, url: str, ext: str) -> Optional[dict]:
    """
    Reglas de envío de correo:
      R1: TENPO -> ENVIAR
      R2: BANCO + extensión maliciosa -> ENVIAR
      R3: TENPO + extensión maliciosa -> ENVIAR (ya cubierto por R1 pero se etiqueta)
      R4: Marca chilena (lista) -> ENVIAR
    Devuelve un dict con info del hit y la regla aplicada, o None si no dispara.
    """
    def _hit(brands: List[str]) -> Optional[dict]:
        return brand_match_any(domain, url, brands, BRAND_THR, BRAND_ALLOW_LEET)

    ext_hit = (ext and ext.lower() in NOTIFY_EXTS) or re.search(
        r'(?i)\.(' + '|'.join(map(re.escape, NOTIFY_EXTS)) + r')($|[?#&/])', url or ""
    )

    tenpo_hit = _hit(TENPO_TERMS)          # R1 / R3
    banco_hit = _hit(BANCO_TERMS)          # R2
    chile_hit = _hit(CHILE_TERMS)          # R4

    # R1: TENPO => ENVIAR
    if tenpo_hit:
        tenpo_hit["rule"] = "R1_TENPO"
        if ext_hit:
            tenpo_hit["rule"] = "R3_TENPO+EXT"
        if EMAIL_DEBUG:
            console.info(f"[Notify] {tenpo_hit['rule']} domain={domain} url={url} ext={ext}")
        return tenpo_hit

    # R2: BANCO + EXT => ENVIAR
    if banco_hit and ext_hit:
        banco_hit["rule"] = "R2_BANCO+EXT"
        if EMAIL_DEBUG:
            console.info(f"[Notify] {banco_hit['rule']} domain={domain} url={url} ext={ext}")
        return banco_hit

    # R4: Marca chilena => ENVIAR
    if chile_hit:
        chile_hit["rule"] = "R4_CHILE_BRAND"
        if EMAIL_DEBUG:
            console.info(f"[Notify] {chile_hit['rule']} domain={domain} url={url} ext={ext}")
        return chile_hit

    # No dispara
    if EMAIL_DEBUG:
        console.info(f"[Notify] no_match domain={domain} url={url} ext={ext} tenpo={bool(tenpo_hit)} banco={bool(banco_hit)} chile={bool(chile_hit)} ext_hit={bool(ext_hit)}")
    return None

def _ensure_dir(p):
    pathlib.Path(p).mkdir(parents=True, exist_ok=True)

def _read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}

def _write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)

def _first_cert_from_extra(extra_b64: str):
    """
    RFC6962: extra_data para X509Entry: vector<ASN.1Cert> con longitudes de 3 bytes.
    Tomamos el primer cert DER.
    """
    if not extra_b64:
        return None
    b = base64.b64decode(extra_b64)
    if len(b) < 3:
        return None
    l = int.from_bytes(b[0:3], "big")
    if len(b) < 3 + l:
        return None
    cert_der = b[3:3+l]
    try:
        return x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception:
        return None

def _domains_from_cert(cert: x509.Certificate):
    out = set()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for d in san.value.get_values_for_type(x509.DNSName):
            d = d.strip(".").lower()
            if d:
                out.add(d)
    except Exception:
        pass
    try:
        cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attr:
            d = cn_attr[0].value.strip(".").lower()
            if d:
                out.add(d)
    except Exception:
        pass
    return list(out)

async def _ct_get_json(session: aiohttp.ClientSession, url: str, timeout: int):
    async with session.get(url, timeout=timeout) as r:
        r.raise_for_status()
        return await r.json()

async def _ct_get(session: aiohttp.ClientSession, url: str, timeout: int):
    async with session.get(url, timeout=timeout) as r:
        r.raise_for_status()
        return await r.json()

def _valid_log_state(state: dict) -> bool:
    # Aceptamos "usable" o "qualified"
    return isinstance(state, dict) and any(k in state for k in ("usable", "qualified"))

def _normalize_log_url(u: str) -> str:
    # Asegura terminar en '/'
    return u if u.endswith("/") else (u + "/")

# ===== CT Logs feeder (directo a logs) =====
async def ctlogs_feeder(cfg, influx_writer, brand_match_any, console):
    if not cfg.get("ctlogs_enabled", False):
        console.info("[CTLOG] deshabilitado.")
        return

    log_list_url = cfg.get("ctlogs_log_list_url") or "https://www.gstatic.com/ct/log_list/v3/log_list.json"
    use_local     = bool(cfg.get("ctlogs_use_local_file", False))
    local_path    = cfg.get("ctlogs_local_file_path") or "./log_list.json"
    ck_dir        = cfg.get("ctlogs_checkpoint_dir") or "./ct_checkpoints"
    batch_size    = int(cfg.get("ctlogs_batch_size", 2048))
    poll_seconds  = int(cfg.get("ctlogs_poll_seconds", 30))
    http_timeout  = int(cfg.get("ctlogs_http_timeout", 20))
    src_label     = cfg.get("ctlogs_sources_label", "ctlog")

    _ensure_dir(ck_dir)

    # 1) Cargar log list
    if use_local:
        log_list = _read_json(local_path, {})
        console.info(f"[CTLOG] usando log_list local: {local_path}")
    else:
        async with aiohttp.ClientSession() as s:
            log_list = await _ct_get_json(s, log_list_url, http_timeout)
            console.info(f"[CTLOG] obtenido log_list desde {log_list_url}")

    # 2) Seleccionar logs "usable/qualified"
    logs = []
    for oper in (log_list.get("operators") or []):
        for lg in (oper.get("logs") or []):
            if _valid_log_state(lg.get("state", {})) and lg.get("url"):
                logs.append({
                    "log_id": lg.get("log_id"),
                    "url": _normalize_log_url(lg.get("url")),
                    "mmd": int(lg.get("mmd", 86400)),
                    "desc": lg.get("description", "")
                })
    console.info(f"[CTLOG] logs seleccionados: {len(logs)}")

    # 3) Loop continuo por cada log (round-robin simple)
    async with aiohttp.ClientSession() as session:
        checkpoints = {}
        # precarga checkpoints
        for lg in logs:
            ck_file = os.path.join(ck_dir, f"{lg['log_id'].replace('/','_')}.json")
            ck = _read_json(ck_file, {})
            checkpoints[lg["log_id"]] = {"file": ck_file, "index": int(ck.get("index", 0))}
        console.info(f"[CTLOG] checkpoints cargados: {sum(1 for _ in checkpoints)}")

        while True:
            for lg in logs:
                base = lg["url"]
                log_id = lg["log_id"]
                ck     = checkpoints[log_id]
                start  = int(ck["index"])

                # get-sth → para saber tree_size
                sth_url = urljoin(base, "ct/v1/get-sth")
                try:
                    sth = await _ct_get(session, sth_url, http_timeout)
                    tree_size = int(sth.get("tree_size", 0))
                except Exception as e:
                    console.warn(f"[CTLOG] get-sth fallo {lg['desc']} {base}: {e}")
                    continue

                if tree_size <= start:
                    # Nada nuevo; espera un poco (respeta MMD, pero hacemos poll_seconds cortos)
                    continue

                # leemos en bloques
                end = min(tree_size - 1, start + batch_size - 1)
                ge_url = urljoin(base, f"ct/v1/get-entries?start={start}&end={end}")

                try:
                    data = await _ct_get(session, ge_url, http_timeout)
                except Exception as e:
                    console.warn(f"[CTLOG] get-entries fallo {lg['desc']} {base}: {e}")
                    continue

                entries = data.get("entries", [])
                if not entries:
                    # edge: log devolvió vacío; no avances
                    continue

                for idx, ent in enumerate(entries, start=start):
                    extra = ent.get("extra_data")
                    cert  = _first_cert_from_extra(extra)
                    if not cert:
                        # TODO: soportar precert decodificando TBSCertificate (ASN.1)
                        continue
                    domains = _domains_from_cert(cert)
                    if not domains:
                        continue

                    # arma un pseudo-URL de alerta (no hay URL real en CT; es un cert)
                    # usamos "dns://example.com" para la columna 'url' de Influx
                    for d in domains:
                        fake_url = f"dns://{d}"
                        # Usa tu marca/fuzzy/notify igual que con otras fuentes
                        bhit = brand_match_any(d, fake_url, NOTIFY_BRANDS, BRAND_THR, BRAND_ALLOW_LEET)
                        # escribe SIEMPRE
                        influx_writer(
                            source=src_label,
                            domain=d,
                            url=fake_url,
                            ip="",                # CT no trae IP
                            spamhaus_score=0      # opcional
                        )
                        # notifica si hay match
                        if bhit:
                            enqueue_notification_from_candidate(
                                source=src_label,
                                domain=d,
                                url=fake_url,
                                ip="",
                                brand_hit=bhit
                            )

                # avanza checkpoint
                new_index = end + 1
                ck["index"] = new_index
                _write_json(ck["file"], {"index": new_index})
                checkpoints[log_id] = ck

            # descanso corto entre rondas (además de MMD por log)
            await asyncio.sleep(poll_seconds)

# ================ Feeds ================
async def fetch_text(session: aiohttp.ClientSession, url: str, headers: Optional[Dict[str,str]]=None, timeout:int=60) -> str:
    async with session.get(url, headers=headers, timeout=timeout) as r:
        r.raise_for_status()
        return await r.text()

async def fetch_json(session: aiohttp.ClientSession, url: str, headers: Optional[Dict[str,str]]=None, timeout:int=60) -> Any:
    async with session.get(url, headers=headers, timeout=timeout) as r:
        r.raise_for_status()
        ct = r.headers.get("content-type","")
        txt = await r.text()
        if "json" in ct:
            try:
                return json.loads(txt)
            except Exception:
                return {"_raw": txt}
        try:
            return json.loads(txt)
        except Exception:
            return {"_raw": txt}

async def pull_openphish(session: aiohttp.ClientSession) -> List[Dict[str,Any]]:
    if not OPENPHISH_ENABLED: return []
    out = []
    for u in [OPENPHISH_URL, "https://openphish.com/feed.txt"]:
        try:
            data = await fetch_json(session, u, timeout=60)
            rows = []
            if isinstance(data, dict) and "data" in data:
                rows = data["data"]
            elif isinstance(data, list):
                rows = data
            else:
                raw = data.get("_raw","")
                for line in raw.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and line.startswith("http"):
                        rows.append({"url": line})
            for r in rows:
                url = r["url"] if isinstance(r, dict) else str(r)
                dom = to_domain(url)
                out.append({"source":"openphish","url":url,"domain":dom,"attrs":r if isinstance(r,dict) else {}, "seen_at": now_iso_utc()})
            if out: break
        except Exception as e:
            console.warn(f"[OpenPhish] {u} -> {e}")
    console.info(f"[OpenPhish] batch={len(out)}")
    return out

async def pull_urlhaus(session: aiohttp.ClientSession) -> List[Dict[str,Any]]:
    if not URLHAUS_ENABLED: return []
    out = []
    for u in [URLHAUS_ONLINE, URLHAUS_RECENT]:
        try:
            txt = await fetch_text(session, u, timeout=60)
            f = io.StringIO(txt)
            reader = csv.reader(f)
            headers = None
            for row in reader:
                if not row or row[0].startswith("#"): continue
                if headers is None and "url" in [c.strip().lower() for c in row]:
                    headers = [c.strip().lower() for c in row]; continue
                if headers is None:
                    if len(row) >= 3 and row[2].startswith("http"):
                        url = row[2].strip()
                    else:
                        continue
                else:
                    try:
                        idx = headers.index("url")
                        url = row[idx].strip()
                    except Exception:
                        continue
                if not url: continue
                dom = to_domain(url)
                out.append({"source":"urlhaus","url":url,"domain":dom,"attrs":{"from":u},"seen_at": now_iso_utc()})
            if out: break
        except Exception as e:
            console.warn(f"[URLHaus] {u} -> {e}")
    console.info(f"[URLHaus] batch={len(out)}")
    return out

async def pull_phishtank(session: aiohttp.ClientSession) -> List[Dict[str,Any]]:
    if not PHISHTANK_ENABLED: return []
    out = []
    urls = []
    if PHISHTANK_APP_KEY:
        urls.append(f"https://data.phishtank.com/data/{PHISHTANK_APP_KEY}/online-valid.csv")
    urls.append(PHISHTANK_CSV)
    for u in urls:
        try:
            txt = await fetch_text(session, u, headers={"User-Agent":"zelcon/1.0"}, timeout=90)
            f = io.StringIO(txt)
            reader = csv.DictReader(f)
            if reader.fieldnames and any("url" == c.lower() for c in reader.fieldnames):
                for row in reader:
                    url = (row.get("url") or row.get("URL") or "").strip()
                    if not url: continue
                    dom = to_domain(url)
                    out.append({"source":"phishtank","url":url,"domain":dom,"attrs":row,"seen_at": now_iso_utc()})
            else:
                f.seek(0)
                reader2 = csv.reader(f)
                headers = next(reader2, [])
                headers = [h.strip().lower() for h in headers]
                idx = headers.index("url") if "url" in headers else (1 if len(headers)>1 else -1)
                for row in reader2:
                    if idx == -1 or len(row) <= idx: continue
                    url = row[idx].strip()
                    if not url: continue
                    out.append({"source":"phishtank","url":url,"domain":to_domain(url),"attrs":{},"seen_at": now_iso_utc()})
            if out: break
        except Exception as e:
            console.warn(f"[PhishTank] {u} -> {e}")
    console.info(f"[PhishTank] batch={len(out)}")
    return out

async def pull_sinking(session: aiohttp.ClientSession) -> List[Dict[str,Any]]:
    if not SINKING_ENABLED: return []
    out = []
    try:
        u = f"{SINKING_BASE.rstrip('/')}/v2/recent/{SINKING_RECENT_MIN}"
        data = await fetch_json(session, u, timeout=60)
        if isinstance(data, list):
            for it in data:
                dom = it if isinstance(it, str) else (it.get("domain") or it.get("host") or "")
                if not dom: continue
                url = dom if str(dom).startsWith("http") else f"http://{dom}"
                out.append({"source":"sinkingyachts","url":url,"domain":to_domain(url),"attrs":{},"seen_at": now_iso_utc()})
        elif isinstance(data, dict):
            rows = data.get("data", [])
            for dom in rows:
                if not dom: continue
                url = dom if str(dom).startswith("http") else f"http://{dom}"
                out.append({"source":"sinkingyachts","url":url,"domain":to_domain(url),"attrs":{},"seen_at": now_iso_utc()})
    except Exception as e:
        console.warn(f"[SinkingYachts] {e}")
    console.info(f"[SinkingYachts] batch={len(out)}")
    return out

# ============ CT Watcher via crt.sh (brands + hosters) ============
CT_SEEN: set = set()

def _ct_state_load(path: str):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s: CT_SEEN.add(s)
    except Exception as e:
        console.warn(f"[CT] state load -> {e}")

def _ct_state_save(path: str):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for k in sorted(CT_SEEN):
                f.write(k + "\n")
        os.replace(tmp, path)
    except Exception as e:
        console.warn(f"[CT] state save -> {e}")

async def _crtsh_search(session: aiohttp.ClientSession, token: str) -> List[Dict[str,Any]]:
    from urllib.parse import quote
    q = quote(f"%{token}%")
    url = f"https://crt.sh/?q={q}&deduplicate=Y&output=json"
    try:
        async with session.get(url, timeout=30, headers={"User-Agent":"ctwatch/1.1"}) as r:
            txt = await r.text()
            data = json.loads(txt)
            return data if isinstance(data, list) else []
    except Exception as e:
        console.warn(f"[CT] crt.sh '{token}' -> {type(e).__name__}: {e}")
        return []

def _host_interesting(host: str, brands: List[str], hosters: List[str]) -> Optional[dict]:
    h = (host or "").strip().lower().rstrip(".")
    if not h or h.startswith("*."): return None
    brand = brand_hit_on_host(h, brands, BRAND_THR, BRAND_ALLOW_LEET)
    hoster_hit = any(h == hs or h.endswith("." + hs) for hs in hosters)
    if not brand and not hoster_hit:
        return None
    return {"host": h, "brand": brand, "hoster_hit": hoster_hit}

async def _page_probe_follow(session: aiohttp.ClientSession, host: str, brands: List[str]) -> dict:
    async def _try(url: str):
        try:
            async with session.get(url, timeout=12, allow_redirects=True, max_redirects=2,
                                   headers={"User-Agent":"ctwatch/1.1"}) as r:
                body = await r.content.read(65536)
                text = _normalize(body.decode("utf-8","ignore"))
                matched = None
                for b in brands:
                    if _normalize(b) in text or _brand_regex(b).search(text):
                        matched = b; break
                return {
                    "start_url": url,
                    "final_url": str(r.url),
                    "status": r.status,
                    "redirects": len(r.history),
                    "html_brand_hit": bool(matched),
                    "matched_brand": matched
                }
        except Exception:
            return None
    https = f"https://{host}/"
    http  = f"http://{host}/"
    res = await _try(https) or await _try(http)
    if not res:
        res = {"start_url": https, "final_url": https, "status": None, "redirects": 0,
               "html_brand_hit": False, "matched_brand": None}
    return res

async def pull_ctwatch(session: aiohttp.ClientSession) -> List[Dict[str,Any]]:
    if not CTWATCH_ENABLED: return []
    _ct_state_load(CT_STATE_FILE)
    out = []
    for brand in CT_BRANDS:
        rows = await _crtsh_search(session, brand)
        new_ct = 0
        for row in rows:
            name_val = str(row.get("name_value", ""))
            for raw in name_val.split("\n"):
                m = _host_interesting(raw, [brand], CT_HOSTERS)
                if not m: continue
                host = m["host"]
                key  = f"{brand}|{host}"
                if key in CT_SEEN: continue
                probe = await _page_probe_follow(session, host, CT_BRANDS)
                brand_term = (m["brand"]["term"] if m["brand"] else (probe.get("matched_brand") or brand))
                url = probe.get("final_url") or probe.get("start_url") or f"https://{host}/"
                out.append({
                    "source":"ctwatch",
                    "domain": host,
                    "url": url,
                    "attrs": {
                        "via":"ctwatch",
                        "brand_term": brand_term or "",
                        "html_brand_hit": bool(probe.get("html_brand_hit")),
                        "http_status": probe.get("status"),
                        "redirects": probe.get("redirects", 0)
                    },
                    "seen_at": now_iso_utc()
                })
                CT_SEEN.add(key)
                new_ct += 1
        if new_ct:
            _ct_state_save(CT_STATE_FILE)
            console.success(f"[CT] {brand}: nuevos={new_ct}")
    console.info(f"[CT] batch={len(out)}")
    return out

async def ctwatch_loop_forever(session: aiohttp.ClientSession):
    """Consulta crt.sh continuamente, procesa y duerme ctwatch_poll_seconds (con jitter)."""
    console.info(f"[CT] loop continuo cada {CT_POLL_SEC}s · brands={CT_BRANDS}")
    while True:
        try:
            rows = await pull_ctwatch(session)
            for c in rows:
                try:
                    await process_candidate(session, c)
                except Exception as e:
                    console.warn(f"[CT] process err: {type(e).__name__}: {e}")
        except Exception as e:
            console.warn(f"[CT] loop fetch err: {type(e).__name__}: {e}")
        sleep_s = max(15, int(CT_POLL_SEC + random.uniform(-0.25, 0.25) * CT_POLL_SEC))
        await asyncio.sleep(sleep_s)

# ===== SSLMate helpers =====
async def sslm_api(session: aiohttp.ClientSession, method: str, url: str, **kw):
    headers = kw.pop("headers", {})
    headers["Authorization"] = f"Bearer {SSLM_API_KEY}"
    if "json" in kw:
        headers["Content-Type"] = "application/json"
    return await session.request(method, url, headers=headers, **kw)

async def sslm_ensure_monitored_domains(session: aiohttp.ClientSession):
    if not (SSLM_ENABLED and SSLM_API_KEY and SSLM_DOMAINS):
        return
    for name in SSLM_DOMAINS:
        url = f"{SSLM_BASE}/monitored_domains/{name}"
        try:
            r = await sslm_api(session, "POST", url, json={"enabled": True})
            if r.status in (200, 201, 204):
                console.info(f"[SSLM] monitoreando {name}")
            else:
                txt = await r.text()
                console.warn(f"[SSLM] no pude monitorear {name} -> {r.status} {txt[:200]}")
        except Exception as e:
            console.warn(f"[SSLM] error al crear {name}: {e}")

def _wb_basic_ok(req: web.Request) -> bool:
    h = req.headers.get("Authorization", "")
    if not h.startswith("Basic "): return False
    try:
        u, p = base64.b64decode(h[6:].encode()).decode().split(":", 1)
        return (u == SSLM_WB_USER) and (p == SSLM_WB_PASS)
    except Exception:
        return False

async def sslm_webhook(request: web.Request):
    """Webhook de Cert Spotter (Unknown Certificate / New Endpoint)."""
    if not _wb_basic_ok(request):
        return web.Response(status=401, text="unauthorized")
    try:
        data = await request.json()
    except Exception:
        return web.Response(status=400, text="invalid json")

    issuance = data.get("issuance", {}) or {}
    dns_names = issuance.get("dns_names") or []
    if not dns_names:
        dns_names = [e.get("dns_name") for e in (data.get("endpoints") or []) if e.get("dns_name")]

    processed = 0
    for d in set([str(x or "").lower().strip(".") for x in dns_names if x]):
        # usamos un pseudo-esquema dns:// para que encaje en el pipeline
        cand = {
            "source": "sslmate",
            "domain": d,
            "url": f"dns://{d}",
            "attrs": {"via":"sslmate"},
            "seen_at": now_iso_utc()
        }
        try:
            await process_candidate(request.app["sslmate_session"], cand)
            processed += 1
        except Exception as e:
            console.warn(f"[SSLM] proc {d} err: {e}")

    # (Opcional) autorizar certificado como "known"
    if SSLM_AUTO_AUTH and issuance.get("cert_der"):
        try:
            r = await sslm_api(request.app["sslmate_session"], "POST",
                               f"{SSLM_BASE}/known_certs",
                               data=base64.b64decode(issuance["cert_der"]),
                               headers={"Content-Type":"application/pkix-cert"})
            console.info(f"[SSLM] auto-authorize cert -> {r.status}")
        except Exception as e:
            console.warn(f"[SSLM] auto-authorize err: {e}")

    return web.json_response({"ok": True, "processed": processed})

# ============ Enriquecimientos ============
async def enrich_spamhaus(session: aiohttp.ClientSession, obj: str) -> Dict[str,Any]:
    if not SPAMHAUS_ENABLED:
        return {}
    try:
        is_ip = uf.is_ip(obj)
        tmpl = SPAMHAUS_URL_IP if is_ip else SPAMHAUS_URL_DOM
        url  = tmpl.format(object=obj)
        headers = {"Accept":"application/json"}
        if SPAMHAUS_JWT and SPAMHAUS_JWT.count(".")==2:
            headers["Authorization"] = f"Bearer {SPAMHAUS_JWT}"
        elif SPAMHAUS_KEY:
            headers["X-Api-Key"] = SPAMHAUS_KEY
        else:
            return {}
        data = await fetch_json(session, url, headers=headers, timeout=20)
        if not isinstance(data, dict): return {}
        score = data.get("score") or (data.get("reputation") or {}).get("score")
        cats  = data.get("categories") or (data.get("reputation") or {}).get("categories")
        return {"spamhaus_score": float(score) if score is not None else 0.0,
                "spamhaus_categories": cats, "spamhaus_raw": data}
    except Exception as e:
        console.warn(f"[Spamhaus] {obj} -> {type(e).__name__}: {e}")
        return {}

async def enrich_threatfox(session: aiohttp.ClientSession, indicator: str) -> Dict[str,Any]:
    if not (THREATFOX_ENABLED and THREATFOX_KEY): return {}
    try:
        payload = {"query": "search_ioc", "search_term": indicator}
        headers = {"Content-Type":"application/json", "API-KEY": THREATFOX_KEY}
        async with session.post(THREATFOX_URL, json=payload, headers=headers, timeout=20) as r:
            r.raise_for_status()
            data = await r.json()
        res = data.get("data") or []
        if not isinstance(res, list) or not res: return {}
        best = None; best_conf = -1
        for it in res:
            conf = int(it.get("confidence_level") or it.get("confidence") or 0)
            if conf > best_conf:
                best_conf = conf; best = it
        if not best: return {}
        return {
            "tfx_confidence": int(best.get("confidence_level") or best.get("confidence") or 0),
            "tfx_malware": best.get("malware") or best.get("malware_printable") or "",
            "tfx_ioc_type": best.get("ioc_type") or "",
            "tfx_tags": best.get("tags") or [],
            "tfx_reference": best.get("reference") or "",
            "tfx_raw": best
        }
    except Exception as e:
        console.warn(f"[ThreatFox] {indicator} -> {type(e).__name__}: {e}")
        return {}

def _parse_vt(vt_raw: Any) -> Dict[str,Any]:
    try:
        obj = json.loads(vt_raw) if isinstance(vt_raw, str) else (vt_raw or {})
        attrs = ((obj.get("data") or {}).get("attributes")) or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious") or 0)
        susp = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        verdict = "MALICIOUS" if (mal > 0 or susp > 0) else "clean"
        return {"mal": mal, "susp": susp, "harmless": harmless, "verdict": verdict}
    except Exception:
        return {"mal":0,"susp":0,"harmless":0,"verdict":"unknown"}

def _parse_abuseip(ab_raw: Any) -> Dict[str,Any]:
    try:
        obj = json.loads(ab_raw) if isinstance(ab_raw, str) else (ab_raw or {})
        data = obj.get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        verdict = "MALICIOUS" if score >= 50 else ("suspicious" if score >= 25 else "clean")
        return {"score": score, "verdict": verdict}
    except Exception:
        return {"score":0,"verdict":"unknown"}

def _enrich_vt_abuse_sync(value: str) -> Dict[str,Any]:
    try:
        ip = uf.get_ip_address(to_domain(value))
    except Exception:
        ip = ""
    try:
        vt = uf.get_virustotal_report_from_url(VT_API, value)
    except Exception as e:
        vt = json.dumps({"error": type(e).__name__, "message": str(e)})
    try:
        abuse = uf.get_abuseip_report(ABUSEIP_API, ip or value)
    except Exception as e:
        abuse = json.dumps({"error": type(e).__name__, "message": str(e)})
    return {"ip": ip, "virustotal": vt, "abuseip": abuse}

async def enrich_all(session: aiohttp.ClientSession, domain: str, url: str, ip_hint: str="") -> Dict[str,Any]:
    spam = await enrich_spamhaus(session, domain) if SPAMHAUS_ENABLED else {}
    vt_ab = await asyncio.to_thread(_enrich_vt_abuse_sync, url)
    tfx   = await (enrich_threatfox(session, domain) or enrich_threatfox(session, url))
    return {**spam, **vt_ab, **(tfx or {})}

# ============ InfluxDB persistencia ============
def influx_writer(source: str, domain: str, url: str, ip: str="", spamhaus_score: float=0.0):
    """Helper para feeders nuevos (CT/SSLMate) que quieran escribir rápido."""
    body = [{
        "measurement": "phishing_candidates",
        "tags": {"source": source, "domain": domain},
        "fields": {
            "url": url,
            "ip": ip,
            "attrs": json.dumps({"quick": True}),
            "success": True,
            "seen_at": now_iso_utc(),
            "spamhaus_score": float(spamhaus_score),
            "vt_raw": json.dumps({}),
            "abuseip_raw": json.dumps({}),
            "tfx_confidence": 0.0,
            "tfx_malware": "",
            "tfx_ioc_type": "",
            "tfx_tags": json.dumps([]),
            "tfx_ref": ""
        }
    }]
    try:
        INFLUX.write_points(body, time_precision='ms')
        console.success(f"[Influx] {source} -> {domain} ok=True")
    except Exception as e:
        console.error(f"[Influx] {e}")

def influx_write(candidate: Dict[str,Any], enrich: Dict[str,Any], ok: bool=True) -> None:
    ext = url_ext(candidate["url"])
    tags = {"source": candidate["source"], "domain": candidate["domain"]}
    if ext: tags["ext"] = ext
    fields = {
        "url": candidate["url"],
        "ip": enrich.get("ip",""),
        "attrs": json.dumps(candidate.get("attrs", {})),
        "success": bool(ok),
        "seen_at": candidate.get("seen_at",""),

        # watch metadata
        "watch": bool(candidate.get("watch", False)),
        "watch_term": candidate.get("watch_term",""),
        "watch_score": float(candidate.get("watch_score",0.0)),
        "watch_method": candidate.get("watch_method",""),

        # enrich
        "spamhaus_score": float(enrich.get("spamhaus_score") or 0.0),
        "vt_raw": json.dumps(enrich.get("virustotal") or {}),
        "abuseip_raw": json.dumps(enrich.get("abuseip") or {}),
        "tfx_confidence": float(enrich.get("tfx_confidence") or 0.0),
        "tfx_malware": enrich.get("tfx_malware",""),
        "tfx_ioc_type": enrich.get("tfx_ioc_type",""),
        "tfx_tags": json.dumps(enrich.get("tfx_tags", [])),
        "tfx_ref": enrich.get("tfx_reference","")
    }
    body = [{
        "measurement": "phishing_candidates",
        "tags": tags,
        "fields": fields
    }]
    try:
        okw = INFLUX.write_points(body, time_precision='ms')
        console.success(f"[Influx] {candidate['source']} -> {candidate['domain']} ok={okw}")
    except Exception as e:
        console.error(f"[Influx] {e}")

def influx_write_notification(channel:str, sent:bool, count:int, subject:str, extra:Optional[dict]=None):
    body = [{
        "measurement": "notifications",
        "tags": {"channel": channel},
        "fields": {
            "sent": bool(sent),
            "count": int(count),
            "recipients": EMAIL_TO or "",
            "subject": subject or "",
            "extra": json.dumps(extra or {})
        }
    }]
    try:
        INFLUX.write_points(body, time_precision='ms')
    except Exception as e:
        console.error(f"[Influx][notif] {e}")

# ============ Email batching & envío ============
def _email_rate_ok() -> bool:
    now = time.time()
    global _email_window_hits
    while _email_window_hits and (now - _email_window_hits[0]) > EMAIL_WINDOW_MIN*60:
        _email_window_hits.pop(0)
    if len(_email_window_hits) >= EMAIL_BURST_MAX:
        return False
    _email_window_hits.append(now)
    return True

def _badge(text: str, color: str) -> str:
    return f'<span style="background:{color};color:#fff;border-radius:4px;padding:1px 6px;font-family:monospace">{text}</span>'

def send_alert_email(batch: List[Dict[str,Any]]) -> Dict[str,Any]:
    result = {"sent": False, "subject": "", "count": 0, "reason": None}
    if not batch:
        result.update({"reason":"empty_batch","subject":"ZELCON: sin datos"}); return result
    if not _email_rate_ok():
        result.update({"reason":"rate_limited","subject":"ZELCON: rate-limited","count":len(batch)}); return result

    from collections import Counter
    counts_src = Counter([c['source'] for c in batch])
    summary_src = " | ".join([f"{k}:{v}" for k,v in counts_src.items()])

    subject = f"⚠️ ZELCON: {len(batch)} brand+malware ({summary_src})"
    rows = []
    for c in batch:
        vt = c.get("_vt") or {}
        ab = c.get("_abuse") or {}
        tfx_conf = c.get("_tfx",{}).get("tfx_confidence",0)
        vt_badge = _badge(vt.get("verdict","?"),
                          "#d9534f" if vt.get("verdict")=="MALICIOUS" else ("#f0ad4e" if vt.get("verdict")=="unknown" else "#5cb85c"))
        ab_badge = _badge(f"{ab.get('score',0)} ({ab.get('verdict','?')})",
                          "#d9534f" if ab.get("score",0)>=50 else ("#f0ad4e" if ab.get("score",0)>=25 else "#5cb85c"))
        tfx_badge = _badge(f"TFX:{int(tfx_conf)}", "#d9534f" if tfx_conf>=80 else ("#f0ad4e" if tfx_conf>=50 else "#5cb85c"))

        rows.append(
            "<tr>"
            f"<td>{c['source']}</td>"
            f"<td>{c['domain']}</td>"
            f"<td><a href=\"{c['url']}\">{c['url']}</a></td>"
            f"<td>{c.get('ip','')}</td>"
            f"<td>{c.get('_ext','')}</td>"
            f"<td>{vt_badge} — M:{vt.get('mal',0)} S:{vt.get('susp',0)} H:{vt.get('harmless',0)}</td>"
            f"<td>{ab_badge}</td>"
            f"<td>{tfx_badge}</td>"
            f"<td>{c.get('seen_at')}</td>"
            "</tr>"
        )
    html = f"""
    <html><body>
      <h2>Posibles phishing (brand + malware)</h2>
      <p> Se han detectado posibles phishing asociados a la banca Chilena o TENPO. </p>
      <table border="1" cellpadding="6" cellspacing="0">
        <tr>
          <th>Fuente</th><th>Dominio</th><th>URL</th><th>IP</th><th>Ext</th>
          <th>VirusTotal</th><th>AbuseIPDB</th><th>ThreatFox</th><th>Detectado</th>
        </tr>
        {''.join(rows)}
      </table>
    <p> Se recomienda las siguientes acciones:</p>
    <p> 1. Verificar URL(s) si afenctan directamente o no al negocio.
    <p> 2. Bloquear IOC correspondientes.
    <p> 3. Notifica a AXUR para el takedown.
    <p> 
    </body></html>
    """
    try:
        ok = send_email(EMAIL_FROM, EMAIL_PASS, EMAIL_TO, subject, html)
        result.update({"sent": bool(ok), "subject": subject, "count": len(batch), "reason": None if ok else "send_failed"})
        console.info(f"[Email] {'enviado' if ok else 'fallo'} batch={len(batch)}")
    except Exception as e:
        result.update({"sent": False, "subject": subject, "count": len(batch), "reason": type(e).__name__})
        console.error(f"[Email] {e}")
    return result

# ============ Pipeline por-candidato ============
def _set_watch(candidate: Dict[str,Any]) -> None:
    if not WATCH_ENABLED:
        candidate.update({"watch": False, "watch_term":"", "watch_score":0.0, "watch_method":""})
        return
    # usar el mismo matcher de marca para watch (sobre dominio)
    w_hit = brand_hit_on_host(candidate["domain"], WATCH_TERMS, WATCH_THRESHOLD, BRAND_ALLOW_LEET)
    # filtro TLD si definiste watch_tlds
    if WATCH_TLDS:
        try:
            suffix = candidate["domain"].split(".",1)[1].lower()
        except Exception:
            suffix = ""
        if suffix not in WATCH_TLDS:
            w_hit = None
    if w_hit:
        candidate.update({"watch": True, "watch_term": w_hit["term"], "watch_score": float(w_hit["score"]), "watch_method": w_hit["method"]})
    else:
        candidate.update({"watch": False, "watch_term":"", "watch_score":0.0, "watch_method":""})

async def process_candidate(session: aiohttp.ClientSession, c: Dict[str,Any]) -> None:
    domain = c.get("domain",""); url = c.get("url",""); src = c.get("source","")
    if not domain or not url: return
    if not dedup(url, src): return

    # Watch metadata
    _set_watch(c)
    if WATCH_ENABLED and WATCH_ONLY_MATCHES and not c.get("watch"):
        return

    # Enriquecimientos
    enrich = await enrich_all(session, domain, url, "")
    vt_summary = _parse_vt(enrich.get("virustotal"))
    ab_summary = _parse_abuseip(enrich.get("abuseip"))
    tfx_summary = {"tfx_confidence": float(enrich.get("tfx_confidence") or 0.0)}
    c["_vt"] = vt_summary
    c["_abuse"] = ab_summary
    c["_tfx"] = tfx_summary
    c["ip"] = enrich.get("ip","")
    c["_ext"] = url_ext(url)
    # --- Optional: Maltiverse enrichment (domain-level); writes to Influx & Slack inside enrich_and_store ---
    if MALTIVERSE_ENABLED and isinstance(cfg.get("maltiverse", {}), dict) and cfg["maltiverse"].get("api_key"):
        try:
            # run sync function in thread to avoid blocking event loop
            await asyncio.to_thread(enrich_and_store, cfg, url)
        except Exception as _e:
            console.warn(f"[Maltiverse] {domain}: {type(_e).__name__}: {_e}")

    # Persistir
    influx_write(c, enrich, ok=True)

    # Notificación por correo (marca + extensión)
    bhit = should_trigger_email(domain, url, c["_ext"])
    if bhit:
        c.setdefault("attrs", {})["brand_hit"] = bhit
        _batch_for_email.append(c)

def enqueue_notification_from_candidate(source: str, domain: str, url: str, ip: str, brand_hit: dict):
    """Utilidad para feeders rápidos (CT/SSLMate) que ya tienen un match de marca."""
    c = {
        "source": source, "domain": domain, "url": url, "ip": ip,
        "attrs": {"brand_hit": brand_hit}, "seen_at": now_iso_utc(),
        "_vt": {"verdict":"unknown","mal":0,"susp":0,"harmless":0},
        "_abuse": {"score":0,"verdict":"unknown"},
        "_tfx": {"tfx_confidence": 0.0},
        "_ext": url_ext(url)
    }
    _batch_for_email.append(c)

def flush_email_if_time() -> None:
    global _batch_for_email, _last_email_flush
    if not _batch_for_email:
        return
    if (time.time() - _last_email_flush) <= EMAIL_WINDOW_MIN*60:
        return
    to_send = _batch_for_email[:EMAIL_BURST_MAX]
    res = send_alert_email(to_send)
    influx_write_notification("email", res.get("sent",False), res.get("count",0), res.get("subject",""), {"reason": res.get("reason")})
    _batch_for_email = []
    _last_email_flush = time.time()

# loooooooooooooooooooooppp
async def run_ingestion() -> None:
    console.info("[*] Ingestor multi-feed iniciado.")
    timeout = aiohttp.ClientTimeout(total=120)
    async with aiohttp.ClientSession(timeout=timeout, trust_env=True) as session:
        # CT watcher - propio loop continuo
        ct_task = None
        if CTWATCH_ENABLED:
            ct_task = asyncio.create_task(ctwatch_loop_forever(session))

        # SSLMate: dominios y prto escucha (NGREK)
        sslm_runner = None
        if SSLM_ENABLED and SSLM_API_KEY:
            await sslm_ensure_monitored_domains(session)
            app = web.Application()
            app["sslmate_session"] = session
            app.router.add_post(SSLM_WB_PATH, sslm_webhook)
            sslm_runner = web.AppRunner(app)
            await sslm_runner.setup()
            site = web.TCPSite(sslm_runner, SSLM_WB_HOST, SSLM_WB_PORT)
            await site.start()
            console.info(f"[SSLM] webhook en http://{SSLM_WB_HOST}:{SSLM_WB_PORT}{SSLM_WB_PATH}")

        try:
            while True:
                tasks = []
                if OPENPHISH_ENABLED: tasks.append(pull_openphish(session))
                if URLHAUS_ENABLED:   tasks.append(pull_urlhaus(session))
                if PHISHTANK_ENABLED: tasks.append(pull_phishtank(session))
                if SINKING_ENABLED:   tasks.append(pull_sinking(session))
                # OJO: ya NO agregamos pull_ctwatch() aquí

                results = []
                try:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                except Exception as e:
                    console.error(f"[gather] {e}")

                # Procesar resultados de los feeds “batch”
                for res in results:
                    if isinstance(res, Exception):
                        console.warn(f"[feed] excepción: {res}"); continue
                    if not isinstance(res, list): continue
                    for c in res:
                        try:
                            await process_candidate(session, c)
                        except Exception as e:
                            console.warn(f"[process] {type(e).__name__}: {e}")

                # Flush de correo
                flush_email_if_time()

                # El ciclo general duerme según el feed más corto (sin afectar al CT ni al webhook SSLM)
                intervals = []
                if OPENPHISH_ENABLED: intervals.append(POLL_EVERY_SEC_OPENPHISH)
                if URLHAUS_ENABLED:   intervals.append(POLL_EVERY_SEC_URLHAUS)
                if PHISHTANK_ENABLED: intervals.append(POLL_EVERY_SEC_PHISHTANK)
                if SINKING_ENABLED:   intervals.append(POLL_EVERY_SEC_SINKING)
                await asyncio.sleep(min(intervals) if intervals else 60)

        finally:
            # cierre limpio de tasks/servidores
            if ct_task:
                ct_task.cancel()
                with suppress(asyncio.CancelledError):
                    await ct_task
            if SSLM_ENABLED and sslm_runner:
                await sslm_runner.cleanup()

if __name__ == "__main__":
    try:
        asyncio.run(run_ingestion())
    except KeyboardInterrupt:
        console.warn("Detenido por usuario.")
