import smtplib
import ssl
import re
from typing import Iterable, List, Optional, Union
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from email.header import Header
import mimetypes
from email.mime.base import MIMEBase
from email import encoders
import os


def _normalize_recipients(x: Union[str, Iterable[str]]) -> List[str]:
    if x is None:
        return []
    if isinstance(x, str):
        # admite "a@b.com, c@d.com"
        parts = [p.strip() for p in x.split(",") if p.strip()]
        return parts
    return [str(i).strip() for i in x if str(i).strip()]


def _html_to_text(html: str) -> str:
    """
    Fallback muy simple a texto (no usa librerías externas).
    Solo para que algunos clientes vean algo legible si no renderizan HTML.
    """
    if not html:
        return ""
    text = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)
    text = re.sub(r"</p\s*>", "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _attach_files(msg: MIMEMultipart, attachments: Optional[Iterable[str]] = None) -> None:
    if not attachments:
        return
    for path in attachments:
        if not path or not os.path.isfile(path):
            continue
        ctype, encoding = mimetypes.guess_type(path)
        if ctype is None or encoding is not None:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        with open(path, "rb") as f:
            file_part = MIMEBase(maintype, subtype)
            file_part.set_payload(f.read())
            encoders.encode_base64(file_part)
            file_part.add_header("Content-Disposition", f'attachment; filename="{os.path.basename(path)}"')
            msg.attach(file_part)


def send_email(
    email_from: str,
    email_password: str,
    email_to: Union[str, Iterable[str]],
    email_subject: str,
    email_html_content: str,
    *,
    email_text_content: Optional[str] = None,
    cc: Optional[Union[str, Iterable[str]]] = None,
    bcc: Optional[Union[str, Iterable[str]]] = None,
    from_name: Optional[str] = None,
    reply_to: Optional[str] = None,
    attachments: Optional[Iterable[str]] = None,
    smtp_host: str = "smtp.gmail.com",
    smtp_port: int = 465,
    use_ssl: bool = True,
    timeout: int = 30
) -> bool:
    """
    Envía un correo HTML (con alternativa texto) vía SMTP.
    - Retrocompatible con tu uso actual: send_email(from, pass, to, subject, html)
    - Soporta To/CC/BCC múltiples, adjuntos, Reply-To, y retorna True/False.
    """

    to_list = _normalize_recipients(email_to)
    cc_list = _normalize_recipients(cc)
    bcc_list = _normalize_recipients(bcc)
    all_rcpts = list(dict.fromkeys(to_list + cc_list + bcc_list))  # sin duplicados

    if not all_rcpts:
        # No hay destinatarios válidos
        return False

    # Cabeceras
    msg_root = MIMEMultipart("mixed")
    from_header = formataddr((str(Header(from_name or "", "utf-8")), email_from)) if from_name else email_from
    msg_root["From"] = from_header
    msg_root["To"] = ", ".join(to_list)
    if cc_list:
        msg_root["Cc"] = ", ".join(cc_list)
    if reply_to:
        msg_root["Reply-To"] = reply_to
    msg_root["Subject"] = str(Header(email_subject or "", "utf-8"))
    msg_root["Date"] = formatdate(localtime=True)
    msg_root["Message-ID"] = make_msgid()

    # Parte alternativa (texto + html)
    alt = MIMEMultipart("alternative")
    txt = email_text_content if email_text_content is not None else _html_to_text(email_html_content or "")
    alt.attach(MIMEText(txt, "plain", "utf-8"))
    alt.attach(MIMEText(email_html_content or "", "html", "utf-8"))
    msg_root.attach(alt)

    # Adjuntos opcionales
    _attach_files(msg_root, attachments)

    # Envío SMTP
    context = ssl.create_default_context()
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=timeout) as server:
                server.login(email_from, email_password)
                server.sendmail(email_from, all_rcpts, msg_root.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(email_from, email_password)
                server.sendmail(email_from, all_rcpts, msg_root.as_string())
        return True
    except smtplib.SMTPException:
        # Podrías loggear/registrar más detalle si tienes un logger central
        return False
    except Exception:
        return False
