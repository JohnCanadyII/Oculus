"""Email delivery of the HTML digest over SMTP.

The dashboard HTML is the email body directly (it's built email-safe: no JS/SVG
needed for the charts, which are inline-styled div bars). Credentials come from
config or, preferred, the OCULUS_SMTP_PASSWORD env var.
"""
from __future__ import annotations

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

from .config import Email


class EmailError(RuntimeError):
    pass


def send_digest(cfg: Email, html_body: str, subject: str, text_fallback: str = "") -> None:
    if not cfg.enabled:
        raise EmailError("email delivery is disabled (set email.enabled: true in config.yaml)")
    if not (cfg.host and cfg.sender and cfg.recipients):
        raise EmailError("email needs host, sender, and recipients configured")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"{cfg.subject_prefix} {subject}".strip()
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.recipients)
    msg["Date"] = formatdate(localtime=True)
    msg.attach(MIMEText(text_fallback or "Open in an HTML-capable client.", "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(cfg.host, cfg.port, timeout=30) as s:
            if cfg.use_tls:
                s.starttls()
            if cfg.username:
                s.login(cfg.username, cfg.password)
            s.sendmail(cfg.sender, list(cfg.recipients), msg.as_string())
    except (smtplib.SMTPException, OSError) as e:
        raise EmailError(f"SMTP send failed: {e}") from e


def text_summary(clusters, top: int = 15) -> str:
    lines = []
    for i, c in enumerate(clusters[:top], 1):
        title = c.articles[0].title if c.articles else "(untitled)"
        flags = []
        if c.any_kev:
            flags.append("KEV")
        if c.max_cvss is not None:
            flags.append(f"CVSS {c.max_cvss:.1f}")
        tag = " ".join(f"[{f}]" for f in flags)
        lines.append(f"{i:>2}. {title} {tag}".rstrip())
    return "\n".join(lines)
