import socket
import base64
import re
import requests
import tldextract
from urllib.parse import urlparse


def extract_tld(domain_or_host: str) -> str:
    """
    Devuelve el registered_domain (e.g., sub.a.b.co.uk -> a.co.uk).
    """
    s = (domain_or_host or "").strip().lower()
    extracted = tldextract.extract(s)
    return extracted.registered_domain or s


def clean_domain(host_or_domain: str) -> str:
    """
    Normaliza un host y retorna el registered_domain.
    - Quita '*.' y 'www.' si vienen.
    - Usa tldextract para obtener el dominio registrable (ej: a.co.uk).
    """
    
    s = (host_or_domain or "").strip().lower()
    # quitar wildcard y www
    s = re.sub(r'^\*\.', '', s)
    s = re.sub(r'^www\.', '', s)
    # si viene una URL completa, quédate con el netloc
    if re.match(r'^\w+://', s):
        s = urlparse(s).netloc or s
    extracted = tldextract.extract(s)
    return extracted.registered_domain or s


def get_ip_address(domain_or_host: str) -> str:
    """
    Resuelve IP del registered_domain. Devuelve "" si no resuelve.
    """
    try:
        registered = extract_tld(domain_or_host)
        return socket.gethostbyname(registered)
    except Exception:
        return ""


def get_url_id(url: str) -> str:
    """
    VT URL ID = base64 urlsafe del string de la URL completa, sin '=' al final.
    """
    url_bytes = (url or "").encode('utf-8')
    encoded_bytes = base64.urlsafe_b64encode(url_bytes)
    return encoded_bytes.decode('utf-8').rstrip('=')


def is_ip(string: str) -> bool:
    """
    Chequeo básico IPv4. (Para IPv6 podrías extender con otra regex.)
    """
    if not string:
        return False
    return re.match(r'^(\d{1,3}\.){3}\d{1,3}$', string) is not None


def _looks_like_url(s: str) -> bool:
    return bool(re.match(r'^(?:https?|ftp)://', s or "", re.IGNORECASE))


def get_virustotal_report_from_url(virustotal_api: str, value: str) -> str:
    """
    Llama al endpoint correcto de VT según 'value':
      - Si es URL (http/https) -> /api/v3/urls/{id_base64}
      - Si es IP               -> /api/v3/ip_addresses/{ip}
      - Si es dominio          -> /api/v3/domains/{domain}
    Devuelve el texto JSON de respuesta (o el error serializado por requests).
    """
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api
    }

    try:
        s = (value or "").strip()

        if _looks_like_url(s):
            # Endpoint de URLs (requiere id base64 de la URL completa)
            url_id = get_url_id(s)
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            resp = requests.get(url, headers=headers, timeout=20)
            return resp.text

        if is_ip(s):
            # Endpoint de IPs
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{s}"
            resp = requests.get(url, headers=headers, timeout=20)
            return resp.text

        # Caso dominio
        domain = extract_tld(s)
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        resp = requests.get(url, headers=headers, timeout=20)
        return resp.text

    except Exception as e:
        # Devuelve error serializado para que el caller lo vea en Influx/email si hace falta
        return f'{{"error":"{type(e).__name__}","message":"{str(e)}"}}'


def get_abuseip_report(api_key: str, ip_or_domain: str) -> str:
    """
    Consulta AbuseIPDB. Si recibe dominio, intenta resolver a IP.
    Devuelve JSON (texto) de respuesta.
    """
    try:
        ip = ip_or_domain.strip()
        if not is_ip(ip):
            ip = get_ip_address(ip_or_domain)
        if not ip:
            return '{"error":"No resolvable IP"}'

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": None
        }
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        resp = requests.get(url, params=params, headers=headers, timeout=20)
        return resp.text
    except Exception as e:
        return f'{{"error":"{type(e).__name__}","message":"{str(e)}"}}'
