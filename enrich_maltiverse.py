# enrich_maltiverse.py — URL-first lookup with hostname fallback; robust Influx write; mv_raw & mv_raw_b64
import json
import base64
import requests
from datetime import datetime
from urllib.parse import urlparse
from maltiverse_client import MaltiverseClient

HIGH_THRESHOLD = 80

def slack_post(webhook: str, text: str):
    if not webhook:
        return
    try:
        r = requests.post(webhook, json={"text": text}, timeout=8)
        if r.status_code >= 400:
            print("[Slack][ERR] {}: {}".format(r.status_code, r.text[:200]))
        else:
            print("[Slack] OK")
    except Exception as e:
        print("[Slack][ERR] {}: {}".format(type(e).__name__, e))

def _escape_field_value(v):
    s = str(v)
    s = s.replace('\\', '\\\\')  # backslash
    s = s.replace('"', '\\"')      # double-quote
    s = s.replace('\n', ' ')          # newlines
    return s

def write_influx(url: str, db: str, measurement: str, tags: dict, fields: dict, ts: datetime = None):
    # tags
    def esc_tag(v):
        return str(v).replace(' ', '\\ ')
    tag_parts = []
    for k, v in tags.items():
        if v is None:
            continue
        tag_parts.append("{}={}".format(k, esc_tag(v)))
    tag_str = ",".join(tag_parts)

    # fields
    field_parts = []
    for k, v in fields.items():
        if isinstance(v, bool):
            field_parts.append("{}={}".format(k, "true" if v else "false"))
        elif isinstance(v, (int, float)):
            field_parts.append("{}={}".format(k, v))
        else:
            field_parts.append('{}="{}"'.format(k, _escape_field_value(v)))
    field_str = ",".join(field_parts)

    # line protocol
    line = "{},{} {}".format(measurement, tag_str, field_str)
    if ts:
        line = "{} {}".format(line, int(ts.timestamp()))

    try:
        r = requests.post("{}/write".format(url),
                          params={"db": db, "precision": "s"},
                          data=line.encode("utf-8"),
                          timeout=8)
        if r.status_code != 204:
            print("[Influx][ERR] {}: {}".format(r.status_code, r.text[:200]))
        else:
            print("[Influx] OK -> {}".format(measurement))
    except Exception as e:
        print("[Influx][ERR] {}: {}".format(type(e).__name__, e))

def normalize_maltiverse(identifier: str, j: dict) -> dict:
    rep = j.get("reputation", "unknown")
    cats = j.get("classification", []) or j.get("category", [])
    blacklist = bool(j.get("blacklist", False) or j.get("detected", False))
    score_map = {"malicious": 90, "suspicious": 60, "neutral": 10, "unknown": 30, "not_found": 0}
    score = score_map.get(rep, 30)
    return {
        "identifier": identifier,
        "reputation": rep,
        "categories": ",".join(sorted(cats)) if isinstance(cats, (list, tuple)) else str(cats),
        "blacklisted": blacklist,
        "mv_score": score,
        "raw_json": json.dumps(j)[:8000],
    }

def _extract_host(ioc: str) -> str:
    s = ioc.strip()
    p = urlparse(s)
    host = p.hostname if p.hostname else s
    while host.endswith("/"):
        host = host[:-1]
    return host

def enrich_and_store(cfg: dict, ioc: str):
    mv_cfg = cfg.get("maltiverse", {})
    influx_cfg = cfg.get("influxdb", {})
    slack_cfg = cfg.get("slack", {})

    client = MaltiverseClient(
        api_key=mv_cfg.get("api_key", ""),
        base=mv_cfg.get("api_base", "https://api.maltiverse.com"),
        timeout=mv_cfg.get("timeout", 10),
    )

    # Determine URL vs hostname
    is_url = ("://" in ioc) or (ioc.startswith("www.") and "/" in ioc)
    tag_domain = _extract_host(ioc)
    ioc_type = "url" if is_url else "hostname"

    # 1) If URL, try /url first
    if is_url:
        print("[Maltiverse] consultando URL -> {}".format(ioc))
        data = client.url(ioc)
        target_id = ioc
        if data.get("_status") == 404 or data.get("reputation") in (None, "unknown"):
            # Fallback: try hostname
            print("[Maltiverse] URL no indexada / unknown, fallback a hostname -> {}".format(tag_domain))
            data = client.hostname(tag_domain)
    else:
        print("[Maltiverse] consultando hostname -> {}".format(tag_domain))
        data = client.hostname(tag_domain)
        target_id = tag_domain

    norm = normalize_maltiverse(target_id, data)
    print("[Maltiverse][DEBUG] normalizado: {}".format(norm))

    # Raw payloads
    mv_raw_b64 = base64.b64encode(norm["raw_json"].encode("utf-8")).decode("ascii")
    try:
        mv_raw_min = json.dumps(json.loads(norm["raw_json"]), separators=(",", ":"))[:6000]
    except Exception:
        mv_raw_min = norm["raw_json"][:6000]

    # Optional parsed fields from raw for richer tables (best-effort)
    try:
        raw = json.loads(norm["raw_json"])
    except Exception:
        raw = {}
    def g(d, k, default=None):
        return d.get(k, default) if isinstance(d, dict) else default
    bl = raw.get("blacklist") or []
    bl0 = bl[0] if isinstance(bl, list) and bl else {}
    bl_desc  = g(bl0, "description", "")
    bl_count = g(bl0, "count", 0)
    bl_source = g(bl0, "source", "")
    first_seen = g(raw, "first_seen", "")
    last_seen  = g(raw, "last_seen", "")
    registrant = g(raw, "registrant_name", "")
    as_name    = g(raw, "as_name", "")
    ips = raw.get("resolved_ip") or []
    ip0 = ips[0] if isinstance(ips, list) and ips else {}
    ip_addr = g(ip0, "ip_addr", "")

    fields = {
        "mv_score": norm["mv_score"],
        "mv_blacklisted": norm["blacklisted"],
        "mv_categories": norm["categories"],
        "mv_raw_b64": mv_raw_b64,
        "mv_raw": mv_raw_min,
        "mv_desc": bl_desc,
        "mv_bl_count": bl_count,
        "mv_source": bl_source,
        "mv_first_seen": first_seen,
        "mv_last_seen": last_seen,
        "mv_registrant": registrant,
        "mv_as_name": as_name,
        "mv_ip": ip_addr,
    }
    if is_url:
        fields["url"] = target_id

    write_influx(
        url=influx_cfg.get("url", "http://localhost:8086"),
        db=influx_cfg.get("db", "tesis"),
        measurement=influx_cfg.get("measurement", "intel_maltiverse"),
        tags={
            "domain": tag_domain,
            "ioc_type": ioc_type,
            "mv_reputation": norm["reputation"],
        },
        fields=fields,
    )

    if norm["mv_score"] >= HIGH_THRESHOLD:
        ui_base = mv_cfg.get("api_base", "https://api.maltiverse.com").replace("api.", "")
        if is_url:
            link_mv = "{}{}".format(ui_base, "/search;query={}".format(target_id))
        else:
            link_mv = "{}{}".format(ui_base, "/hostname/{}".format(tag_domain))
        slack_post(
            slack_cfg.get("webhook", ""),
            ":rotating_light: *ZELCON v2 – Maltiverse*\n"
            "*IOC:* `{}`\n*Reputation:* {} | *Score:* {}\n"
            "*Categories:* {}\n*Blacklisted:* {}\n{}".format(
                target_id, norm["reputation"], norm["mv_score"],
                norm["categories"], norm["blacklisted"], link_mv
            )
        )

    return norm
