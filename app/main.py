import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime
from html import escape
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Cookie, Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Base, engine
from app.deps import get_db
from app.schemas import AuditLogOut, MeOut, UserOut
from app.services import (
    AdminSignerService,
    AdminRecoveryService,
    AuditService,
    AuthorizationService,
    BeneficiarioService,
    BootstrapService,
    CertificateService,
    DocumentService,
    NotificationService,
    PasswordLoginService,
    SignatureLoginService,
    SchemaService,
    UserService,
    role_requires_crypto,
    DOC_TYPE_LABELS,
    DOC_STATUS_LABELS,
    CRYPTO_ROLE_CODES,
)


APP_DIR = Path(__file__).resolve().parent
@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    if settings.seed_demo_data:
        with Session(bind=engine) as db:
            BootstrapService.seed(db)
    else:
        SchemaService.prepare_runtime_schema()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")

# ── WebSocket connection manager for real-time notifications ──────────────
class _WSManager:
    def __init__(self):
        self._connections: dict[int, list[WebSocket]] = {}

    async def connect(self, user_id: int, ws: WebSocket):
        await ws.accept()
        self._connections.setdefault(user_id, []).append(ws)

    def disconnect(self, user_id: int, ws: WebSocket):
        conns = self._connections.get(user_id, [])
        if ws in conns:
            conns.remove(ws)

    async def send_to_user(self, user_id: int, data: dict):
        for ws in self._connections.get(user_id, []):
            try:
                await ws.send_json(data)
            except Exception:
                pass

    async def send_to_admins(self, db: Session, data: dict):
        from app.models import User, Role
        from sqlalchemy import select
        admins = db.scalars(select(User).join(Role).where(Role.code == "ADMIN", User.status_lookup.is_not(None))).all()
        for admin in admins:
            await self.send_to_user(admin.id, data)

_ws_manager = _WSManager()


def _fire_ws(coro):
    """Schedule a coroutine from sync or async context."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
    except RuntimeError:
        try:
            loop = asyncio.get_event_loop()
            asyncio.run_coroutine_threadsafe(coro, loop)
        except Exception:
            pass

# ── Session cookie (signed with HMAC, 8-hour expiry) ──────────────────────
_SESSION_COOKIE = "cm_session"
_SESSION_MAX_AGE = 8 * 3600  # seconds
_signer = URLSafeTimedSerializer(settings.session_secret, salt="cm-session")


def _make_session_cookie(user_id: int, notice: str | None = None) -> str:
    payload = {"uid": user_id}
    if notice:
        payload["notice"] = notice
    return _signer.dumps(payload)


def _latin1_safe(text: str) -> str:
    """Replace common non-latin-1 characters so fpdf Helvetica font doesn't crash."""
    _REPLACEMENTS = {
        "\u2014": "-",   # em dash
        "\u2013": "-",   # en dash
        "\u2018": "'",   # left single quote
        "\u2019": "'",   # right single quote
        "\u201c": '"',   # left double quote
        "\u201d": '"',   # right double quote
        "\u2026": "...", # ellipsis
    }
    for ch, rep in _REPLACEMENTS.items():
        text = text.replace(ch, rep)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _pdf_report(
    title: str,
    subtitle: str,
    col_headers: list[str],
    col_widths: list[int],
    rows: list[tuple],
    generated_by: str,
) -> bytes:
    import hashlib
    from fpdf import FPDF  # noqa: PLC0415 - lazy to avoid startup failure if not installed

    data_lines = ["\t".join(col_headers)]
    for row in rows:
        data_lines.append("\t".join(str(c) for c in row))
    sha256 = hashlib.sha256("\n".join(data_lines).encode()).hexdigest()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_margins(15, 15, 15)

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Casa Monarca", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, _latin1_safe(title), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(0, 5, _latin1_safe(subtitle), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)

    pdf.set_fill_color(26, 35, 50)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    for hdr, w in zip(col_headers, col_widths):
        pdf.cell(w, 8, hdr, border=1, fill=True)
    pdf.ln()

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 8)
    for i, row in enumerate(rows):
        if i % 2 == 0:
            pdf.set_fill_color(248, 247, 244)
        else:
            pdf.set_fill_color(255, 255, 255)
        for cell, w in zip(row, col_widths):
            pdf.cell(w, 7, _latin1_safe(str(cell))[:50], border=1, fill=True)
        pdf.ln()

    pdf.ln(8)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(128, 128, 128)
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    pdf.multi_cell(
        0, 5,
        _latin1_safe(f"Generado por: {generated_by} | {generated_at}\n"
        f"Integridad SHA-256: {sha256}"),
    )

    return bytes(pdf.output())


def _read_session_cookie(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        return _signer.loads(token, max_age=_SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def _login_redirect(response: RedirectResponse, user_id: int, notice: str | None = None) -> RedirectResponse:
    """Set the signed session cookie and return the redirect."""
    token = _make_session_cookie(user_id, notice)
    response.set_cookie(
        _SESSION_COOKIE, token,
        max_age=_SESSION_MAX_AGE,
        httponly=True,
        secure=settings.session_cookie_secure_resolved,
        samesite="lax",
        path="/",
    )
    return response


def _require_session(cm_session: str | None = Cookie(default=None)) -> dict:
    """FastAPI dependency: validates session cookie, returns payload dict."""
    payload = _read_session_cookie(cm_session)
    if not payload:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return payload


def _get_session_actor(db: Session = Depends(get_db), session: dict = Depends(_require_session)):
    """FastAPI dependency: returns the User object for the current session."""
    actor = UserService.get_user(db, session["uid"])
    if not actor:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return actor


def _try_get_session_actor(request: Request, db: Session):
    """Non-dependency helper: returns the User if a valid session exists, else None."""
    token = request.cookies.get(_SESSION_COOKIE)
    payload = _read_session_cookie(token)
    if not payload:
        return None
    return UserService.get_user(db, payload["uid"])


NOTICE_MESSAGES = {
    "user-created": "Usuario creado en estado pending. Debes activarlo para que pueda entrar.",
    "status-updated": "El acceso del usuario fue actualizado.",
    "expiration-updated": "La fecha de expiracion fue actualizada.",
    "role-updated": "El rol del usuario fue actualizado.",
    "recovery-activated": "El administrador espejo ya esta activo. El admin principal fue revocado y debe regenerarse un nuevo respaldo.",
    "certificate-issued": "Las credenciales del usuario fueron generadas correctamente.",
    "crypto-login": "Identidad verificada con los archivos de acceso del usuario.",
    "beneficiario-creado": "Beneficiario registrado correctamente. Ya está visible para el equipo operativo.",
    "registro-enviado": "Solicitud de acceso enviada. Un administrador revisará tu cuenta y te notificará cuando esté activa.",
    "recovery-sent": "Solicitud enviada. Un administrador revisará tu caso y te contactará para verificar tu identidad.",
    "user-unlocked": "La cuenta fue desbloqueada correctamente.",
    "private-key-already-delivered": "El archivo de acceso ya fue descargado una sola vez y fue eliminado del servidor por seguridad. Para obtener uno nuevo, el administrador debe generar nuevas credenciales.",
}


def parse_end_date(value: str) -> datetime | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    return datetime.fromisoformat(cleaned)


_COORD_AREA_MAP = {
    "administracion": "ADMINISTRACION",
    "legal": "LEGAL",
    "psicosocial": "PSICOSOCIAL",
    "humanitario": "HUMANITARIO",
    "comunicacion": "COMUNICACION",
}


def _coordinator_area(email: str) -> str | None:
    """Extract area code from coordinator email, e.g. coord.legal@... -> LEGAL."""
    local = email.split("@")[0]
    parts = local.split(".", 1)
    if len(parts) == 2:
        return _COORD_AREA_MAP.get(parts[1].lower())
    return None


def get_actor_or_404(db: Session, actor_id: int | None):
    actor = UserService.get_actor(db, actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="No actor available")
    return actor


def require_actor_permission(db: Session, actor, resource: str, action: str) -> None:
    if AuthorizationService.authorize(db, actor, resource, action):
        return

    AuditService.log(
        db,
        event_type="access_denied",
        actor_user_id=actor.id,
        target_user_id=actor.id,
        action=action,
        resource=resource,
        result="failure",
    )
    raise HTTPException(status_code=403, detail="Action not allowed for current demo user")


def redirect_home(user_id: int, notice: str | None = None) -> RedirectResponse:
    url = f"/portal?{urlencode({'notice': notice})}" if notice else "/portal"
    resp = RedirectResponse(url=url, status_code=303)
    return _login_redirect(resp, user_id)


def is_active_admin(actor) -> bool:
    return actor.status == "active" and actor.role.code == "ADMIN"


def _require_own_or_admin(actor, user_id: int) -> None:
    """Raise 403 if actor is neither the target user nor an active admin."""
    if actor.id != user_id and not is_active_admin(actor):
        raise HTTPException(status_code=403, detail="No tienes permiso para acceder a este recurso")


WARN_NOTICES = {"private-key-already-delivered"}


def render_notice(notice: str | None) -> str:
    if not notice:
        return ""
    message = NOTICE_MESSAGES.get(notice)
    if not message and notice.startswith("batch-signed-"):
        parts = notice.replace("batch-signed-", "").split("-errors-")
        count = parts[0]
        if len(parts) > 1:
            message = f"Se firmaron {count} documentos en lote. {parts[1]} archivo(s) tuvieron errores."
        else:
            message = f"Se firmaron {count} documentos en lote exitosamente."
    if not message:
        message = notice
    css_class = "warn" if notice in WARN_NOTICES else "ok"
    return f"<div class='{css_class}'>{escape(message)}</div>"


def render_certificate_page(title: str, summary: dict, back_href: str) -> str:
    san_items = "".join(f"<li>{escape(item)}</li>" for item in summary["san_emails"]) or "<li>Sin SAN de correo.</li>"
    return f"""
    <!doctype html>
    <html lang="es">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{escape(title)}</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
          :root {{
            --bg: #f6f2ec;
            --surface: #ffffff;
            --surface-2: #faf7f3;
            --border: #e5ddd3;
            --border-strong: #cfc4b5;
            --text: #1a2332;
            --muted: #6b7280;
            --accent: #e06020;
            --accent-dark: #bf4f10;
            --radius: 10px;
            --radius-lg: 14px;
            --shadow: 0 1px 3px rgba(0,0,0,0.06), 0 4px 16px rgba(0,0,0,0.05);
          }}
          *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
          body {{ background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 15px; line-height: 1.6; -webkit-font-smoothing: antialiased; }}
          main {{ max-width: 780px; margin: 0 auto; padding: 32px 20px 64px; }}
          h1 {{ font-size: 22px; font-weight: 700; letter-spacing: -0.3px; }}
          h2 {{ font-size: 16px; font-weight: 600; margin: 20px 0 10px; }}
          .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); padding: 28px; }}
          .topbar {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; padding-bottom: 18px; border-bottom: 1px solid var(--border); }}
          .back-link {{ display: inline-flex; align-items: center; gap: 6px; color: var(--muted); font-size: 13px; font-weight: 400; text-decoration: none; }}
          .back-link:hover {{ color: var(--accent); text-decoration: none; }}
          dl {{ display: grid; grid-template-columns: 180px 1fr; gap: 0; border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; margin-bottom: 20px; }}
          dt {{ font-weight: 600; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; background: var(--surface-2); padding: 10px 14px; border-bottom: 1px solid var(--border); }}
          dd {{ margin: 0; padding: 10px 14px; border-bottom: 1px solid var(--border); word-break: break-word; font-size: 13px; }}
          dt:last-of-type, dd:last-of-type {{ border-bottom: none; }}
          code {{ background: var(--surface-2); border: 1px solid var(--border); border-radius: 4px; padding: 2px 6px; font-family: 'Courier New', monospace; font-size: 12px; word-break: break-all; }}
          pre {{ background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; font-family: 'Courier New', monospace; font-size: 12px; }}
          ul {{ margin: 0; padding-left: 18px; font-size: 13px; }}
          details {{ margin-top: 16px; }}
          details summary {{ cursor: pointer; font-size: 13px; font-weight: 600; color: var(--accent); padding: 8px 0; }}
          @media (max-width: 600px) {{
            dl {{ grid-template-columns: 1fr; }}
            dt {{ border-bottom: none; padding-bottom: 2px; }}
          }}
        </style>
      </head>
      <body>
        <main>
          <div class="card">
            <div class="topbar">
              <h1>{escape(title)}</h1>
              <a class="back-link" href="{escape(back_href)}">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
                Volver
              </a>
            </div>
            <dl>
              <dt>Sujeto</dt>
              <dd>{escape(summary["subject"])}</dd>
              <dt>Emisor</dt>
              <dd>{escape(summary["issuer"])}</dd>
              <dt>Serie</dt>
              <dd><code>{escape(summary["serial"])}</code></dd>
              <dt>Vigencia inicio</dt>
              <dd>{escape(summary["not_before"].isoformat(sep=" ", timespec="seconds"))}</dd>
              <dt>Vigencia fin</dt>
              <dd>{escape(summary["not_after"].isoformat(sep=" ", timespec="seconds"))}</dd>
              <dt>SHA-256</dt>
              <dd><code>{escape(summary["fingerprint_sha256"])}</code></dd>
            </dl>
            <h2>SAN (Subject Alternative Names)</h2>
            <ul>{san_items}</ul>
            <details>
              <summary>Ver PEM completo</summary>
              <pre>{escape(summary["pem"])}</pre>
            </details>
          </div>
        </main>
      </body>
    </html>
    """


def _crypto_file_link(href: str, label: str) -> str:
    return f'<a href="{escape(href)}">{escape(label)}</a>'


def _crypto_file_state(user, viewer_id: int) -> str:
    query = f"?as_user={viewer_id}"
    items = []

    if CertificateService.private_key_download_available(user):
        items.append(_crypto_file_link(f"/ui/users/{user.id}/private-key.pem{query}", "Archivo de acceso"))
        items.append("<span class='crypto-once'>descarga &uacute;nica</span>")
    elif user.private_key_delivered_at:
        items.append("<span class='crypto-delivered'>Archivo de acceso entregado</span>")
    else:
        items.append("<span class='crypto-missing'>Archivo de acceso pendiente</span>")

    if user.certificate_pem:
        items.append(_crypto_file_link(f"/ui/users/{user.id}/certificate.pem{query}", "Certificado de identidad"))
    else:
        items.append("<span class='crypto-missing'>Certificado pendiente</span>")

    return " &middot; ".join(items)


def _render_crypto_flow(user, viewer_id: int, issuer_name: str | None = None, verified: bool = False) -> str:
    material = CertificateService.describe_crypto_material(user, issuer_name=issuer_name)
    if not material:
        return "<p class='muted'>Acceso con usuario y contrase&ntilde;a.</p>"

    verified_chip = (
        "<span class='crypto-pill crypto-pill-ok'>Identidad verificada en esta sesi&oacute;n</span>" if verified else ""
    )
    query = f"?as_user={viewer_id}"

    # Access file row
    if CertificateService.private_key_download_available(user):
        key_val = f'<a href="/ui/users/{user.id}/private-key.pem{query}">Descargar archivo de acceso</a> <span class="crypto-once">&middot; Descarga &uacute;nica</span>'
    elif user.private_key_delivered_at:
        key_val = "<span class='crypto-delivered'>&#10003; Archivo de acceso entregado</span>"
    else:
        key_val = "<span class='crypto-missing'>Archivo de acceso pendiente</span>"

    # Certificate row
    if user.certificate_pem:
        expiry = ""
        if user.certificate_not_after:
            expiry = f" &middot; <span style='font-size:11px;color:var(--muted);'>V&aacute;lido hasta {user.certificate_not_after.strftime('%d/%m/%Y')}</span>"
        cert_val = f'<a href="/ui/users/{user.id}/certificate.pem{query}">Descargar certificado</a>{expiry}'
        if viewer_id != user.id:
            cert_val = f'<a href="/ui/users/{user.id}/certificate/view?as_user={viewer_id}">Ver certificado de identidad</a> &middot; <a href="/ui/users/{user.id}/certificate.pem{query}">Descargar certificado</a>{expiry}'
    else:
        cert_val = "<span class='crypto-missing'>Certificado de identidad pendiente</span>"

    return f"""
    <div class="crypto-flow">
      <div class="crypto-row">
        <span class="crypto-step-name">Archivo de acceso</span>
        <div class="crypto-step-body">
          <div class="crypto-step-main">{key_val} {verified_chip}</div>
        </div>
      </div>
      <div class="crypto-row">
        <span class="crypto-step-name">Certificado</span>
        <div class="crypto-step-body">
          <div class="crypto-step-main">{cert_val}</div>
        </div>
      </div>
    </div>
    """


def base_page(title: str, body: str, actor=None, portal_sections: list | None = None) -> str:
    # sidebar nav items — determined by who's logged in (optional)
    BUTTERFLY_SVG = """<svg width="32" height="28" viewBox="0 0 80 64" fill="none" xmlns="http://www.w3.org/2000/svg">
      <ellipse cx="20" cy="22" rx="19" ry="14" fill="#d1145a" transform="rotate(-20 20 22)"/>
      <ellipse cx="14" cy="36" rx="12" ry="8" fill="#d1145a" opacity=".7" transform="rotate(15 14 36)"/>
      <ellipse cx="60" cy="22" rx="19" ry="14" fill="#f06b35" transform="rotate(20 60 22)"/>
      <ellipse cx="66" cy="36" rx="12" ry="8" fill="#f06b35" opacity=".7" transform="rotate(-15 66 36)"/>
      <ellipse cx="40" cy="32" rx="3.5" ry="18" fill="#1a2332"/>
      <circle cx="40" cy="13" r="3" fill="#1a2332"/>
      <line x1="40" y1="10" x2="30" y2="4" stroke="#1a2332" stroke-width="1.5" stroke-linecap="round"/>
      <line x1="40" y1="10" x2="50" y2="4" stroke="#1a2332" stroke-width="1.5" stroke-linecap="round"/>
    </svg>"""

    _portal_href = f"/portal?as_user={actor.id}" if actor else "/portal"
    _actor_id = actor.id if actor else ""
    _is_admin = bool(actor and getattr(getattr(actor, 'role', None), 'code', None) == "ADMIN")
    _admin_nav = (
        f'<a href="/dashboard?as_user={_actor_id}" class="sidebar-link">'
        '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>'
        '<rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>'
        '</svg>Panel de administraci&oacute;n</a>'
    ) if _is_admin else ""
    if actor:
        _initials = "".join(p[0].upper() for p in actor.full_name.split() if p)[:2]
        _user_block = (
            f'<div class="sidebar-user">'
            f'<div class="sidebar-avatar">{escape(_initials)}</div>'
            f'<div style="flex:1;min-width:0;">'
            f'<div class="sidebar-user-name">{escape(actor.full_name)}</div>'
            f'<div class="sidebar-user-role">{escape(actor.role.name)}</div>'
            f'</div>'
            f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;opacity:0.5;"><polyline points="6 9 12 15 18 9"/></svg>'
            f'</div>'
        )
    else:
        _user_block = ""

    if portal_sections:
        _sec_items = '<span class="sidebar-section-label">En esta p&aacute;gina</span>'
        for href, label, icon_svg, onclick_js, is_active in portal_sections:
            cls = "sidebar-link active" if is_active else "sidebar-link"
            _onclick = f' onclick="{onclick_js}"' if onclick_js else ""
            _sec_items += f'<a href="{href}" class="{cls}"{_onclick}>{icon_svg}{label}</a>'
        _portal_sections_html = _sec_items
    else:
        _portal_sections_html = ""

    return f"""
    <!doctype html>
    <html lang="es">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{escape(title)}</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
        <style>
          :root {{
            --bg: #f5f0e8;
            --surface: #ffffff;
            --surface-2: #faf7f2;
            --border: #e5ddd3;
            --border-strong: #cfc4b5;
            --text: #1a2332;
            --muted: #6b7280;
            --accent: #e06020;
            --accent-dark: #bf4f10;
            --accent-light: #fff3eb;
            --sidebar-bg: #1a2332;
            --sidebar-text: #e8e4de;
            --sidebar-muted: #8b9ab0;
            --sidebar-active: rgba(224,96,32,0.18);
            --sidebar-active-border: #e06020;
            --ok: #166534;
            --ok-bg: #dcfce7;
            --ok-border: #86efac;
            --warn: #92400e;
            --warn-bg: #fef3c7;
            --warn-border: #fcd34d;
            --bad: #991b1b;
            --bad-bg: #fee2e2;
            --bad-border: #fca5a5;
            --radius: 10px;
            --radius-lg: 14px;
            --shadow: 0 1px 3px rgba(0,0,0,0.06), 0 4px 16px rgba(0,0,0,0.05);
          }}
          *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
          html, body {{ height: 100%; }}
          body {{ background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 15px; line-height: 1.6; -webkit-font-smoothing: antialiased; display: flex; min-height: 100vh; }}

          /* ─── Watermark ───────────────────────────────── */
          .page-bg-watermark {{
            position: fixed; top: -60px; right: -80px;
            width: 900px; pointer-events: none; opacity: 0.15; z-index: 0;
          }}
          .page-bg-watermark-2 {{
            position: fixed; bottom: -80px; right: -60px;
            width: 700px; pointer-events: none; opacity: 0.11; z-index: 0;
            transform: rotate(-15deg);
          }}
          .sidebar-watermark {{
            position: absolute; bottom: 40px; right: -40px;
            width: 310px; pointer-events: none; opacity: 0.12;
            transform: scaleX(-1) rotate(20deg);
          }}

          /* ─── Sidebar ─────────────────────────────────── */
          .sidebar {{
            width: 290px; flex-shrink: 0;
            background: var(--sidebar-bg);
            display: flex; flex-direction: column;
            position: fixed; top: 0; left: 0; bottom: 0;
            z-index: 100; overflow-y: auto; overflow-x: hidden;
          }}
          .sidebar-brand {{
            padding: 20px 18px 16px;
            border-bottom: 1px solid rgba(255,255,255,0.07);
          }}
          .sidebar-brand-logo {{
            display: flex; align-items: center; gap: 10px; margin-bottom: 6px;
          }}
          .sidebar-brand-text {{ line-height: 1.2; }}
          .sidebar-brand-name {{
            font-size: 17px; font-weight: 800; color: #fff; letter-spacing: -0.3px;
          }}
          .sidebar-brand-sub {{
            font-size: 11px; color: var(--sidebar-muted); text-transform: uppercase; letter-spacing: .08em; font-weight: 500;
          }}
          .sidebar-tagline {{
            font-size: 12px; color: var(--sidebar-muted); line-height: 1.4; margin-top: 6px;
          }}
          .sidebar-user {{
            display: flex; align-items: center; gap: 10px;
            padding: 14px 16px; border-bottom: 1px solid rgba(255,255,255,0.07);
          }}
          .sidebar-avatar {{
            width: 36px; height: 36px; border-radius: 50%;
            background: #2d5a3d; color: #fff;
            display: flex; align-items: center; justify-content: center;
            font-weight: 700; font-size: 13px; flex-shrink: 0; letter-spacing: 0.5px;
          }}
          .sidebar-user-name {{ font-size: 15px; font-weight: 600; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
          .sidebar-user-role {{ font-size: 12px; color: var(--sidebar-muted); margin-top: 1px; }}
          .sidebar-nav {{
            flex: 1; padding: 14px 10px;
            display: flex; flex-direction: column; gap: 2px;
          }}
          .sidebar-section-label {{
            font-size: 11px; font-weight: 700; color: var(--sidebar-muted); text-transform: uppercase;
            letter-spacing: .1em; padding: 10px 8px 4px; margin-top: 4px;
          }}
          .sidebar-link {{
            display: flex; align-items: center; gap: 9px;
            padding: 9px 10px; border-radius: 8px;
            color: var(--sidebar-text); font-size: 15px; font-weight: 500;
            text-decoration: none; transition: background .15s, color .15s;
            border-left: 2px solid transparent;
          }}
          .sidebar-link:hover {{ background: rgba(255,255,255,0.07); color: #fff; text-decoration: none; }}
          .sidebar-link.active {{
            background: var(--sidebar-active);
            border-left-color: var(--sidebar-active-border);
            color: #fff;
          }}
          .sidebar-link svg {{ flex-shrink: 0; opacity: .75; }}
          .sidebar-link.active svg {{ opacity: 1; }}
          .sidebar-footer {{
            padding: 14px 10px;
            border-top: 1px solid rgba(255,255,255,0.07);
          }}
          .sidebar-logout {{
            display: flex; align-items: center; gap: 8px;
            color: var(--sidebar-muted); font-size: 13px; font-weight: 500;
            text-decoration: none; padding: 7px 10px; border-radius: 7px;
            transition: color .15s, background .15s;
          }}
          .sidebar-logout:hover {{ color: #fff; background: rgba(255,255,255,0.07); text-decoration: none; }}

          /* ─── Main content ────────────────────────────── */
          .page-wrapper {{
            margin-left: 290px; flex: 1; min-width: 0;
            position: relative; z-index: 1;
          }}
          main {{ max-width: 1400px; margin: 0 auto; padding: 36px 48px 80px; position: relative; z-index: 1; }}
          h1 {{ font-size: 22px; font-weight: 700; letter-spacing: -0.3px; line-height: 1.3; }}
          h2 {{ font-size: 16px; font-weight: 600; letter-spacing: -0.1px; line-height: 1.4; }}
          p {{ margin: 0; }}
          .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); position: relative; z-index: 2; }}
          .panel {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); padding: 24px; position: relative; z-index: 2; }}
          .stack {{ display: flex; flex-direction: column; gap: 14px; }}
          .grid {{ display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }}
          label {{ display: flex; flex-direction: column; gap: 5px; font-size: 14px; font-weight: 500; color: var(--text); }}
          input, select {{ font: inherit; font-size: 15px; padding: 9px 12px; border-radius: var(--radius); border: 1px solid var(--border-strong); background: var(--surface); color: var(--text); transition: border-color .15s, box-shadow .15s; outline: none; width: 100%; }}
          input:focus, select:focus {{ border-color: var(--accent); box-shadow: 0 0 0 3px rgba(224,96,32,0.12); }}
          input[type="file"] {{ padding: 7px 10px; cursor: pointer; background: var(--surface-2); }}
          button {{ font: inherit; font-size: 14px; font-weight: 600; padding: 9px 18px; border-radius: var(--radius); border: none; cursor: pointer; transition: background .15s; }}
          .btn-primary, button[type="submit"] {{ background: var(--accent); color: #fff; }}
          .btn-primary:hover, button[type="submit"]:hover {{ background: var(--accent-dark); }}
          .danger-button {{ background: #dc2626; color: #fff; }}
          .danger-button:hover {{ background: #b91c1c; }}
          .btn-ghost {{ background: var(--accent-light); color: var(--accent); border: 1px solid #f0d4c5; }}
          .btn-ghost:hover {{ background: #fce0d1; }}
          a {{ color: var(--accent); font-weight: 500; text-decoration: none; }}
          a:hover {{ text-decoration: underline; }}
          .badge {{ display: inline-flex; align-items: center; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; border: 1px solid; }}
          .badge-active, .status-active {{ background: var(--ok-bg); color: var(--ok); border-color: var(--ok-border); }}
          .badge-pending, .status-pending {{ background: var(--warn-bg); color: var(--warn); border-color: var(--warn-border); }}
          .badge-revoked, .badge-expired, .status-revoked, .status-expired {{ background: var(--bad-bg); color: var(--bad); border-color: var(--bad-border); }}
          .status {{ display: inline-flex; align-items: center; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; border: 1px solid; }}
          .ok {{ background: var(--ok-bg); border: 1px solid var(--ok-border); color: var(--ok); border-radius: var(--radius); padding: 10px 14px; font-size: 13px; }}
          .error {{ background: var(--bad-bg); border: 1px solid var(--bad-border); color: var(--bad); border-radius: var(--radius); padding: 10px 14px; font-size: 13px; }}
          .muted {{ color: var(--muted); font-size: 13px; }}
          code {{ background: var(--surface-2); border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; font-family: 'Courier New', monospace; font-size: 12px; word-break: break-all; }}
          hr {{ border: none; border-top: 1px solid var(--border); margin: 16px 0; }}
          .crypto-flow {{ display: flex; flex-direction: column; border-top: 1px solid var(--border); }}
          .crypto-row {{ display: grid; grid-template-columns: 132px 1fr; gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border); }}
          .crypto-step-name {{ font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }}
          .crypto-step-body {{ display: flex; flex-direction: column; gap: 4px; min-width: 0; }}
          .crypto-step-main {{ font-size: 13px; color: var(--text); display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
          .crypto-step-meta {{ font-size: 12px; color: var(--muted); display: flex; gap: 10px; flex-wrap: wrap; }}
          .crypto-pill {{ display: inline-flex; align-items: center; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; border: 1px solid; }}
          .crypto-pill-ok {{ background: var(--ok-bg); color: var(--ok); border-color: var(--ok-border); }}
          .crypto-missing {{ color: var(--muted); font-size: 12px; }}
          .crypto-once {{ color: var(--warn); font-size: 11px; font-weight: 600; }}
          .crypto-delivered {{ color: var(--muted); font-size: 12px; }}
          /* ─── File drop zone ────────────────────────── */
          .file-zone {{ position:relative; display:flex; align-items:center; gap:14px; border:1.5px solid #f0d4c5; border-radius:10px; padding:13px 16px; cursor:pointer; background:#fff8f5; transition:border-color .15s,background .15s; overflow:hidden; }}
          .file-zone:hover {{ border-color:#e06020; background:#fff3eb; }}
          .file-zone input[type="file"] {{ position:absolute; inset:0; opacity:0; width:100%; height:100%; cursor:pointer; }}
          .file-zone-icon {{ width:36px; height:36px; border-radius:8px; background:#fff3eb; border:1px solid #f0d4c5; display:flex; align-items:center; justify-content:center; flex-shrink:0; }}
          .file-zone-text {{ font-size:13px; font-weight:600; color:#1a2332; }}
          .file-zone-sub {{ font-size:11px; color:#e06020; font-weight:500; }}
          .file-zone.has-file {{ border-color:#22c55e; background:#f0fdf4; }}
          .file-zone.has-file .file-zone-icon {{ background:#dcfce7; border-color:#86efac; }}
          .file-zone.has-file .file-zone-text {{ color:#166534; }}
          .file-zone.has-file .file-zone-sub {{ color:#16a34a; }}
          /* ─── Searchable combobox ───────────────────── */
          .combo-wrap {{ position:relative; }}
          .combo-wrap input {{ width:100%; }}
          .combo-list {{ display:none; position:absolute; top:100%; left:0; right:0; max-height:200px; overflow-y:auto; background:#fff; border:1px solid var(--border-strong); border-top:none; border-radius:0 0 var(--radius) var(--radius); box-shadow:0 4px 12px rgba(0,0,0,.1); z-index:50; }}
          .combo-list.open {{ display:block; }}
          .combo-item {{ padding:8px 12px; font-size:14px; cursor:pointer; }}
          .combo-item:hover, .combo-item.active {{ background:var(--accent-light); color:var(--accent); }}
          .combo-item.hidden {{ display:none; }}
          /* Page title style */
          .page-title {{ font-size: 30px; font-weight: 800; letter-spacing: -0.6px; line-height: 1.2; color: var(--text); }}
          .page-title-accent {{ width: 42px; height: 3px; background: var(--accent); border-radius: 2px; margin: 8px 0 6px; }}

          /* ─── Responsive ──────────────────────────────── */
          @media (max-width: 700px) {{
            .sidebar {{ display: none; }}
            .page-wrapper {{ margin-left: 0; }}
            main {{ padding: 20px 14px 60px; }}
            .crypto-row {{ grid-template-columns: 1fr; gap: 6px; }}
            .page-bg-watermark {{ display: none; }}
          }}
        </style>
      </head>
      <body>
        <img src="/static/nuevamariposa.png" class="page-bg-watermark" alt="" aria-hidden="true">

        <aside class="sidebar">
          <div class="sidebar-brand">
            <img src="/static/Logoenblanco.png" alt="Casa Monarca" style="width:100%;max-width:200px;height:auto;display:block;margin:0 auto 6px;">
            <p class="sidebar-tagline" style="text-align:center;">Gestor de Identidades</p>
          </div>
          {_user_block}
          <nav class="sidebar-nav">
            <span class="sidebar-section-label">Navegaci&oacute;n</span>
            <a href="{_portal_href}" class="sidebar-link">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
              Portal de usuario
            </a>
            {_admin_nav}
            {_portal_sections_html}
          </nav>
          <img src="/static/mariposa.png" class="sidebar-watermark" alt="" aria-hidden="true">
          <div class="sidebar-footer">
            <a href="/logout" class="sidebar-logout">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
              Salir / cambiar usuario
            </a>
          </div>
        </aside>
        <div class="page-wrapper">
          <main>{body}</main>
        </div>
        <div id="ws-toast" style="position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;"></div>
        <script>
        (function(){{
          var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
          var ws = new WebSocket(proto + '//' + location.host + '/ws/notifications');
          ws.onmessage = function(e){{
            var d = JSON.parse(e.data);
            var toast = document.createElement('div');
            toast.style.cssText = 'pointer-events:auto;background:#1a2332;color:#fff;padding:14px 18px;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.25);max-width:380px;font-size:13px;line-height:1.5;animation:slideIn .3s ease;border-left:4px solid ' + (d.level === 'danger' ? '#dc2626' : d.level === 'warning' ? '#f59e0b' : '#22c55e');
            toast.innerHTML = '<strong>' + (d.title||'Notificaci\\u00f3n') + '</strong><br>' + (d.message||'');
            document.getElementById('ws-toast').appendChild(toast);
            setTimeout(function(){{ toast.style.opacity='0'; toast.style.transition='opacity .3s'; setTimeout(function(){{ toast.remove(); }}, 300); }}, 6000);
            var badge = document.querySelector('.ws-notif-badge');
            if(badge){{ var c = parseInt(badge.textContent||'0')+1; badge.textContent = c; badge.style.display='inline'; }}
          }};
          ws.onclose = function(){{ setTimeout(arguments.callee, 5000); }};
        }})();
        </script>
        <style>@keyframes slideIn{{ from{{ transform:translateX(100%);opacity:0; }} to{{ transform:translateX(0);opacity:1; }} }}</style>
      </body>
    </html>
    """


def render_login_page(error: str | None = None, notice: str | None = None) -> str:
    error_html = f'<div class="alert-error">{escape(error)}</div>' if error else ""
    notice_html = render_notice(notice)
    password_hint = "Contrase&ntilde;a de los archivos de acceso"
    if not settings.seed_demo_data:
        password_hint = "Contrase&ntilde;a de los archivos de acceso o clave inicial del administrador"
    demo_panel = ""
    if settings.seed_demo_data:
        demo_panel = """
        <details style="margin-bottom:16px;">
          <summary style="cursor:pointer;list-style:none;font-size:12px;font-weight:600;color:#6b7280;display:flex;align-items:center;gap:6px;">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
            Credenciales demo
          </summary>
          <div style="margin-top:8px;padding:10px 12px;background:#faf7f3;border:1px solid #e5ddd3;border-radius:8px;font-size:12px;color:#6b7280;display:grid;gap:4px;">
            <span><code>admin / admin</code> &mdash; acceso directo sin archivos</span>
            <span><code>admin@demo.local</code> + archivo + certificado + <code>admin</code></span>
            <span><code>operativo / demo1234</code></span>
          </div>
        </details>"""
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Iniciar sesi&oacute;n &middot; Casa Monarca</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Inter',system-ui,sans-serif;font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;background:url('/static/CM5.jpeg') center/cover no-repeat fixed;position:relative;}}
    .page-overlay{{position:fixed;inset:0;z-index:0;background:linear-gradient(to right,rgba(10,14,23,.95) 0%,rgba(10,14,23,.80) 45%,rgba(10,14,23,.50) 72%,rgba(10,14,23,.25) 100%);pointer-events:none;}}
    /* ── Branding panel (LEFT) ── */
    .ll{{flex:1;position:relative;display:flex;flex-direction:column;justify-content:space-between;padding:48px 52px;overflow:hidden;min-width:0;z-index:1;}}
    .ll-inner{{display:flex;flex-direction:column;justify-content:space-between;height:100%;gap:40px;}}
    .ll-logo{{height:100px;width:auto;display:block;}}
    .ll-sub{{font-size:11px;font-weight:600;color:#8b9ab0;text-transform:uppercase;letter-spacing:.12em;margin-top:10px;}}
    .ll-line{{width:36px;height:3px;background:#e06020;border-radius:2px;margin:24px 0;}}
    .ll-hero{{font-size:34px;font-weight:800;color:#fff;line-height:1.2;letter-spacing:-.5px;max-width:380px;}}
    .ll-hero em{{font-style:normal;color:#e06020;}}
    .ll-security{{display:flex;align-items:flex-start;gap:14px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:16px 18px;max-width:360px;margin-top:40px;}}
    .ll-shield{{width:40px;height:40px;border-radius:10px;background:rgba(255,255,255,.1);display:flex;align-items:center;justify-content:center;flex-shrink:0;}}
    .ll-sc-title{{font-size:14px;font-weight:700;color:#fff;}}
    .ll-sc-sub{{font-size:12px;color:#8b9ab0;margin-top:2px;line-height:1.5;}}
    .ll-footer{{font-size:12px;color:#4a5568;margin-top:auto;padding-top:24px;display:flex;align-items:center;gap:6px;}}
    @media(max-width:860px){{.ll{{display:none;}}}}
    /* ── Card panel (RIGHT ~3/4) ── */
    .lr{{width:460px;flex-shrink:0;display:flex;align-items:center;justify-content:center;padding:32px 36px;position:relative;z-index:1;}}
    @media(max-width:860px){{.lr{{width:100%;}}}}
    /* ── Card ── */
    .card{{background:#fff;border-radius:18px;box-shadow:0 8px 40px rgba(0,0,0,.22),0 2px 8px rgba(0,0,0,.12);padding:32px 32px 28px;width:100%;max-width:420px;}}
    .card-hdr{{display:flex;align-items:flex-start;gap:14px;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid #f0ebe4;}}
    .card-icon{{width:48px;height:48px;border-radius:12px;background:#fff3eb;display:flex;align-items:center;justify-content:center;flex-shrink:0;}}
    .card-title{{font-size:22px;font-weight:800;color:#1a2332;letter-spacing:-.4px;line-height:1.2;}}
    .card-sub{{font-size:13px;color:#6b7280;margin-top:3px;line-height:1.5;}}
    /* ── Form ── */
    .form-stack{{display:flex;flex-direction:column;gap:14px;}}
    .field-label{{font-size:13px;font-weight:600;color:#1a2332;display:flex;flex-direction:column;gap:4px;}}
    .field-hint{{font-size:11px;font-weight:400;color:#9ca3af;}}
    .input-wrap{{position:relative;display:flex;align-items:center;}}
    .input-wrap > svg{{position:absolute;left:13px;color:#9ca3af;pointer-events:none;flex-shrink:0;}}
    .input-wrap input{{font:inherit;font-size:14px;width:100%;padding:11px 44px 11px 38px;border-radius:10px;border:1.5px solid #e5ddd3;background:#fff;color:#1a2332;outline:none;transition:border-color .15s,box-shadow .15s;}}
    .input-wrap input:focus{{border-color:#e06020;box-shadow:0 0 0 3px rgba(224,96,32,.1);}}
    .eye-btn{{position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#9ca3af;padding:4px;display:flex;align-items:center;}}
    .eye-btn:hover{{color:#1a2332;}}
    /* ── File drop zone ── */
    .file-zone{{position:relative;display:flex;align-items:center;gap:14px;border:1.5px solid #f0d4c5;border-radius:10px;padding:13px 16px;cursor:pointer;background:#fff8f5;transition:border-color .15s,background .15s;overflow:hidden;}}
    .file-zone:hover{{border-color:#e06020;background:#fff3eb;}}
    .file-zone input[type="file"]{{position:absolute;inset:0;opacity:0;width:100%;height:100%;cursor:pointer;}}
    .file-zone-icon{{width:36px;height:36px;border-radius:8px;background:#fff3eb;border:1px solid #f0d4c5;display:flex;align-items:center;justify-content:center;flex-shrink:0;}}
    .file-zone-text{{font-size:13px;font-weight:600;color:#1a2332;}}
    .file-zone-sub{{font-size:11px;color:#e06020;font-weight:500;}}
    /* ── Buttons ── */
    .btn-enter{{font:inherit;font-size:15px;font-weight:700;padding:13px;border-radius:11px;border:none;cursor:pointer;width:100%;background:#e06020;color:#fff;margin-top:6px;display:flex;align-items:center;justify-content:center;gap:8px;transition:background .15s;letter-spacing:.2px;}}
    .btn-enter:hover{{background:#bf4f10;}}
    .btn-ghost{{font:inherit;font-size:13px;font-weight:600;padding:10px 20px;border-radius:10px;border:1.5px solid #e5ddd3;cursor:pointer;background:#fff;color:#1a2332;display:inline-flex;align-items:center;gap:7px;transition:border-color .15s,background .15s;}}
    .btn-ghost:hover{{background:#faf7f3;border-color:#cfc4b5;}}
    .divider{{border:none;border-top:1px solid #f0ebe4;margin:18px 0;}}
    .recovery-link{{display:block;text-align:center;font-size:12px;font-weight:600;color:#e06020;text-decoration:none;margin-top:14px;}}
    .recovery-link:hover{{text-decoration:underline;}}
    .alert-error{{background:#fee2e2;border:1px solid #fca5a5;color:#991b1b;border-radius:10px;padding:10px 14px;font-size:13px;margin-bottom:14px;}}
    .alert-ok{{background:#dcfce7;border:1px solid #86efac;color:#166534;border-radius:10px;padding:10px 14px;font-size:13px;margin-bottom:14px;}}
    code{{background:#faf7f3;border:1px solid #e5ddd3;border-radius:4px;padding:1px 5px;font-family:'Courier New',monospace;font-size:11px;}}
    .file-zone.has-file{{border-color:#22c55e;background:#f0fdf4;}}
    .file-zone.has-file .file-zone-icon{{background:#dcfce7;border-color:#86efac;}}
    .file-zone.has-file .file-zone-text{{color:#166534;}}
    .file-zone.has-file .file-zone-sub{{color:#16a34a;}}
    details summary::-webkit-details-marker{{display:none;}}
  </style>
</head>
<body>
  <div class="page-overlay"></div>
  <!-- Branding panel (LEFT) -->
  <div class="ll">
    <div class="ll-inner">
      <div>
        <img src="/static/Logoenblanco.png" alt="Casa Monarca" class="ll-logo">
        <p class="ll-sub">Ayuda Humanitaria al Migrante, A.B.P.</p>
        <div class="ll-line"></div>
        <h1 class="ll-hero">Sistema de gesti&oacute;n de <em>identidades y accesos</em> para el equipo de Casa Monarca.</h1>
        <div class="ll-security">
          <div class="ll-shield">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e06020" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <div>
            <div class="ll-sc-title">Acceso seguro</div>
            <div class="ll-sc-sub">Protegemos la informaci&oacute;n y la identidad de quienes ayudan a transformar vidas.</div>
          </div>
        </div>
      </div>
      <p class="ll-footer">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        &copy; 2026 Casa Monarca &mdash; Gestor de Identidades
      </p>
    </div>
  </div>
  <!-- Card panel (RIGHT) -->
  <div class="lr">
    <div class="card">      <div class="card-hdr">
        <div class="card-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#e06020" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        </div>
        <div>
          <div class="card-title">Iniciar sesi&oacute;n</div>
          <div class="card-sub">Acceso seguro para Administradores, Coordinadores y Voluntarios autorizados.</div>
        </div>
      </div>

      {demo_panel}{notice_html}{error_html}

      <form method="post" action="/login" enctype="multipart/form-data" class="form-stack">
        <label class="field-label">Correo o usuario
          <div class="input-wrap">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            <input name="identifier" placeholder="usuario@ejemplo.com" required autocomplete="username">
          </div>
        </label>

        <label class="field-label">Archivo de acceso
          <span class="field-hint">Solo para Administrador y Coordinador</span>
          <div class="file-zone">
            <div class="file-zone-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e06020" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
            </div>
            <div>
              <div class="file-zone-text" id="pkf-text">Arrastra tu archivo aqu&iacute;</div>
              <div class="file-zone-sub" id="pkf-sub">o selecciona un archivo</div>
            </div>
            <input type="file" name="private_key_file" accept=".pem,.key" id="pkf" onchange="setFile('pkf',this)">
          </div>
        </label>

        <label class="field-label">Certificado de identidad
          <span class="field-hint">Solo para Administrador y Coordinador</span>
          <div class="file-zone">
            <div class="file-zone-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e06020" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
            </div>
            <div>
              <div class="file-zone-text" id="cf-text">Arrastra tu certificado aqu&iacute;</div>
              <div class="file-zone-sub" id="cf-sub">o selecciona un archivo</div>
            </div>
            <input type="file" name="certificate_file" accept=".pem,.crt" id="cf" onchange="setFile('cf',this)">
          </div>
        </label>

        <label class="field-label">Contrase&ntilde;a
          <span class="field-hint">{password_hint}</span>
          <div class="input-wrap">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <input name="password" id="pwd" type="password" placeholder="Ingresa tu contrase&ntilde;a" required autocomplete="current-password">
            <button type="button" class="eye-btn" onclick="var i=document.getElementById('pwd');i.type=i.type==='password'?'text':'password'">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
          </div>
        </label>

        <button type="submit" class="btn-enter">
          Entrar
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
        </button>
      </form>

      <div class="divider"></div>
      <div style="text-align:center;">
        <p style="font-size:13px;color:#6b7280;margin-bottom:10px;">&iquest;Primera vez en el sistema?</p>
        <a href="/register" class="btn-ghost">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          Solicitar acceso
        </a>
      </div>

      <details style="margin-top:16px;">
        <summary style="cursor:pointer;list-style:none;text-align:center;">
          <a class="recovery-link" style="pointer-events:none;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;vertical-align:middle;margin-right:4px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            &iquest;Olvidaste tu contrase&ntilde;a o perdiste tus certificados?
          </a>
        </summary>
        <form method="post" action="/login/recovery-request" style="display:flex;flex-direction:column;gap:10px;margin-top:14px;padding:14px;background:#faf7f3;border-radius:10px;border:1px solid #e5ddd3;">
          <p style="font-size:12px;color:#6b7280;line-height:1.5;">Env&iacute;a tu nombre y correo. Un administrador verificar&aacute; tu identidad en persona y te entregar&aacute; nuevas credenciales.</p>
          <label style="font-size:13px;font-weight:500;display:flex;flex-direction:column;gap:4px;">Correo registrado
            <input name="identifier" type="email" placeholder="correo@ejemplo.com" required style="font:inherit;font-size:14px;padding:9px 12px;border-radius:9px;border:1.5px solid #e5ddd3;outline:none;width:100%;">
          </label>
          <label style="font-size:13px;font-weight:500;display:flex;flex-direction:column;gap:4px;">Nombre completo
            <input name="full_name" placeholder="Nombre Apellido" required style="font:inherit;font-size:14px;padding:9px 12px;border-radius:9px;border:1.5px solid #e5ddd3;outline:none;width:100%;">
          </label>
          <button type="submit" style="font:inherit;font-size:13px;font-weight:600;padding:10px;border-radius:9px;border:1.5px solid #e5ddd3;cursor:pointer;background:#fff;color:#1a2332;">Solicitar recuperaci&oacute;n</button>
        </form>
      </details>

      <div style="margin-top:16px;padding:14px 16px;background:rgba(224,96,32,0.06);border:1px solid rgba(224,96,32,0.15);border-radius:10px;text-align:center;">
        <p style="font-size:13px;color:#6b7280;margin-bottom:6px;">&iquest;Recibiste un documento de Casa Monarca?</p>
        <a href="/verificar" style="display:inline-flex;align-items:center;gap:6px;font-size:14px;font-weight:600;color:#e06020;text-decoration:none;">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
          Verificar autenticidad &rarr;
        </a>
      </div>
    </div>
  </div>
</body>
<script>
function setFile(id, input) {{
  var zone = input.closest('.file-zone');
  var textEl = document.getElementById(id + '-text');
  var subEl = document.getElementById(id + '-sub');
  if (input.files && input.files.length > 0) {{
    var name = input.files[0].name;
    textEl.textContent = name;
    subEl.textContent = (input.files[0].size / 1024).toFixed(1) + ' KB \u2714';
    zone.classList.add('has-file');
  }} else {{
    textEl.innerHTML = id === 'pkf' ? 'Arrastra tu archivo aqu\u00ed' : 'Arrastra tu certificado aqu\u00ed';
    subEl.textContent = 'o selecciona un archivo';
    zone.classList.remove('has-file');
  }}
}}
</script>
</html>"""




def render_self_register_page(error: str | None = None) -> str:
    BUTTERFLY_SVG_SMALL = """<svg width="36" height="32" viewBox="0 0 80 64" fill="none" xmlns="http://www.w3.org/2000/svg">
      <ellipse cx="20" cy="22" rx="19" ry="14" fill="#d1145a" transform="rotate(-20 20 22)"/>
      <ellipse cx="14" cy="36" rx="12" ry="8" fill="#d1145a" opacity=".7" transform="rotate(15 14 36)"/>
      <ellipse cx="60" cy="22" rx="19" ry="14" fill="#f06b35" transform="rotate(20 60 22)"/>
      <ellipse cx="66" cy="36" rx="12" ry="8" fill="#f06b35" opacity=".7" transform="rotate(-15 66 36)"/>
      <ellipse cx="40" cy="32" rx="3.5" ry="18" fill="#1a2332"/>
      <circle cx="40" cy="13" r="3" fill="#1a2332"/>
      <line x1="40" y1="10" x2="30" y2="4" stroke="#1a2332" stroke-width="1.5" stroke-linecap="round"/>
      <line x1="40" y1="10" x2="50" y2="4" stroke="#1a2332" stroke-width="1.5" stroke-linecap="round"/>
    </svg>"""
    error_html = f"<div class='error'>{escape(error)}</div>" if error else ""
    return f"""<!doctype html>
    <html lang="es">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Solicitar acceso &middot; Casa Monarca</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
      <style>
        *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
        body{{font-family:'Inter',system-ui,sans-serif;font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;min-height:100vh;background:#f6f2ec;display:flex;align-items:center;justify-content:center;padding:32px 16px}}
        .card{{background:#fff;border:1px solid #e5ddd3;border-radius:14px;box-shadow:0 1px 3px rgba(0,0,0,0.06),0 4px 16px rgba(0,0,0,0.05);padding:36px 32px;width:100%;max-width:460px}}
        .stack{{display:flex;flex-direction:column;gap:14px;margin-top:20px}}
        label{{display:flex;flex-direction:column;gap:5px;font-size:13px;font-weight:500;color:#1a2332}}
        input{{font:inherit;font-size:14px;padding:9px 12px;border-radius:10px;border:1px solid #cfc4b5;background:#fff;color:#1a2332;outline:none;width:100%;transition:border-color .15s,box-shadow .15s}}
        input:focus{{border-color:#e06020;box-shadow:0 0 0 3px rgba(224,96,32,0.12)}}
        .btn{{font:inherit;font-size:14px;font-weight:600;padding:11px;border-radius:10px;border:none;cursor:pointer;background:#e06020;color:#fff;width:100%;margin-top:6px}}
        .btn:hover{{background:#bf4f10}}
        .ok{{background:#dcfce7;border:1px solid #86efac;color:#166534;border-radius:10px;padding:10px 14px;font-size:13px;margin-top:14px}}
        .error{{background:#fee2e2;border:1px solid #fca5a5;color:#991b1b;border-radius:10px;padding:10px 14px;font-size:13px;margin-top:14px}}
        hr{{border:none;border-top:1px solid #e5ddd3;margin:20px 0}}
      </style>
    </head>
    <body>
      <div class="card">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid #e5ddd3;">
          <img src="/static/logoCasaMonarca.png" alt="Casa Monarca" style="height:44px;width:auto;border-radius:6px;">
          <div>
            <div style="font-size:18px;font-weight:700;color:#1a2332;letter-spacing:-.3px;">Solicitar acceso</div>
            <div style="font-size:12px;color:#6b7280;margin-top:1px;">Casa Monarca &mdash; Gestor de Identidades</div>
          </div>
        </div>

        <div style="padding:12px 14px;background:#eff6ff;border:1px solid #93c5fd;border-radius:8px;display:flex;gap:10px;align-items:flex-start;">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#1d4ed8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:1px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <p style="font-size:12px;color:#1e40af;line-height:1.5;">Tu cuenta quedar&aacute; en estado <strong>pendiente</strong> hasta que un administrador la apruebe.</p>
        </div>

        {error_html}

        <form method="post" action="/register" class="stack">
          <label>Nombre completo
            <input name="full_name" placeholder="Tu nombre completo" required autocomplete="name">
          </label>
          <label>Correo electr&oacute;nico
            <input name="email" type="email" placeholder="correo@ejemplo.com" required autocomplete="email">
          </label>
          <label>Contrase&ntilde;a
            <input name="password" type="password" placeholder="M&iacute;nimo 6 caracteres" required autocomplete="new-password">
          </label>
          <label>Confirmar contrase&ntilde;a
            <input name="password2" type="password" placeholder="Repite tu contrase&ntilde;a" required autocomplete="new-password">
          </label>
          <button type="submit" class="btn">Enviar solicitud</button>
        </form>
        <hr>
        <div style="text-align:center;">
          <a href="/login" style="font-size:13px;color:#6b7280;text-decoration:none;">&larr; Volver al inicio de sesi&oacute;n</a>
        </div>
      </div>
    </body>
    </html>"""


def render_admin_register_page(actor, roles, error: str | None = None) -> str:
    role_options = "".join(f"<option value='{role.id}'>{escape(role.name)}</option>" for role in roles)
    error_html = f"<div class='error'>{escape(error)}</div>" if error else ""
    body = f"""
    <div style="max-width:540px;margin:0 auto;">
      <div style="margin-bottom:18px;">
        <a href="/dashboard?as_user={actor.id}" style="display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--muted);font-weight:400;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
          Volver al panel
        </a>
      </div>
      <div class="card" style="padding:32px;">
        <div style="margin-bottom:24px;">
          <h1 style="margin-bottom:6px;">Otorgar registro</h1>
          <p class="muted">Crea la cuenta en estado <code>pending</code>. Administradores y Coordinadores reciben archivos de acceso de entrega &uacute;nica. Operativos y Voluntarios solo necesitan contrase&ntilde;a.</p>
        </div>
        {error_html}
        <form method="post" action="/admin/register" class="stack">

          <div class="grid">
            <label>Nombre completo<input name="full_name" placeholder="Nombre Apellido" required></label>
            <label>Correo electr&oacute;nico<input name="email" type="email" placeholder="correo@ejemplo.com" required></label>
          </div>
          <div class="grid">
            <label>Rol<select name="role_id">{role_options}</select></label>
            <label>Fecha de expiraci&oacute;n<input name="end_date" type="datetime-local"></label>
          </div>
          <label>
            Contrase&ntilde;a inicial
            <span class="muted" style="font-weight:400;font-size:12px;margin-top:-2px;">Para roles con archivos de acceso, esta clave los protege al descargarlos</span>
            <input name="credential_secret" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
          </label>
          <button type="submit" style="padding:10px;font-size:14px;margin-top:8px;">Crear usuario</button>
        </form>
      </div>
    </div>
    """
    return base_page("Otorgar registro · Casa Monarca", body)


_USER_ICON_SVG = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'
_SHIELD_ICON_SVG = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
_PEOPLE_ICON_SVG = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>'
_DOC_ICON_SVG = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>'


_VERIFY_ICON_SVG = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>'


def _build_portal_sections(actor, section: str = "cuenta") -> list:
    if not actor:
        return []
    aid = actor.id
    sections = [
        (f"/portal?section=cuenta&as_user={aid}", "Mi cuenta", _USER_ICON_SVG, None, section == "cuenta"),
    ]
    if role_requires_crypto(actor):
        sections.append((
            f"/portal?section=credenciales&as_user={aid}", "Mis credenciales", _SHIELD_ICON_SVG, None, section == "credenciales",
        ))
    if actor.status == "active":
        sections.append((
            f"/portal?section=beneficiarios&as_user={aid}", "Beneficiarios", _PEOPLE_ICON_SVG, None, section == "beneficiarios",
        ))
    if actor.status == "active" and actor.role.code in CRYPTO_ROLE_CODES:
        sections.append((
            f"/portal?section=documentos&as_user={aid}", "Documentos", _DOC_ICON_SVG, None, section == "documentos",
        ))
    if actor.status == "active":
        sections.append((
            "/verificar", "Verificar documento", _VERIFY_ICON_SVG, None, section == "verificar",
        ))
    if actor.status == "active" and actor.role.code == "COORDINADOR":
        sections.append((
            f"/portal?section=directorio&as_user={aid}", "Directorio", _SHIELD_ICON_SVG, None, section == "directorio",
        ))
    return sections


def render_portal_page(
    actor,
    permissions,
    logs,
    notice: str | None = None,
    verified: bool = False,
    beneficiarios=None,
    issuer_name: str | None = None,
    section: str = "cuenta",
    documents=None,
    pending_cosign=None,
) -> str:
    permission_text = ", ".join(f"{item['resource']}:{item['action']}" for item in permissions) or "sin permisos"
    verified_html = (
        "<p style='font-size:12px;color:var(--ok);font-weight:600;margin-bottom:10px;'>Identidad verificada con archivos de acceso.</p>"
        if verified
        else ""
    )

    # --- Certificate section (only for crypto roles) ---
    cert_section = ""
    if role_requires_crypto(actor):
        badge_class = "status-active" if actor.certificate_serial else "status-pending"
        badge_text = "emitido" if actor.certificate_serial else "pendiente"
        cert_section = f"""
        <div style="margin-top:18px;">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px;">
            <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);">Estado de credenciales</p>
            <span class="status {badge_class}">{badge_text}</span>
          </div>
          {_render_crypto_flow(actor, actor.id, issuer_name=issuer_name, verified=verified)}
        </div>
        """
    else:
        cert_section = "<p class='muted' style='margin-top:16px;'>Acceso con usuario y contrasena.</p>"

    # --- Demo content section (realistic sample data per role) ---
    bens = beneficiarios or []
    activos = [b for b in bens if b.status == "activo"]
    nuevos = [b for b in bens if b.status == "nuevo"]
    en_revision = [b for b in bens if b.status == "en_revision"]

    STATUS_LABELS = {"nuevo": "Nuevo", "en_revision": "En revisión", "canalizado": "Canalizado", "activo": "Activo"}
    STATUS_CSS = {"nuevo": "pending", "en_revision": "pending", "canalizado": "active", "activo": "active"}
    AREA_LABELS = {
        "ADMINISTRACION": "Administración", "LEGAL": "Legal",
        "PSICOSOCIAL": "Psicosocial", "HUMANITARIO": "Humanitario", "COMUNICACION": "Comunicación",
    }

    if actor.status != "active":
        demo_section = ""
    elif actor.role.code == "ADMIN":
        # CRUD: full list with status update + delete
        STATUS_OPTIONS_A = [("nuevo","Nuevo"),("en_revision","En revisión"),("canalizado","Canalizado"),("activo","Activo")]

        def _options_a(cur: str) -> str:
            return "".join(
                f'<option value="{v}"{" selected" if v == cur else ""}>{lbl}</option>'
                for v, lbl in STATUS_OPTIONS_A
            )

        admin_rows = "".join(
            f"""<div style="display:flex;align-items:center;gap:12px;padding:11px 14px;background:#fff;border-bottom:1px solid #e5ddd3;flex-wrap:wrap;">
              <div style="flex:1;min-width:160px;">
                <p style="font-weight:600;font-size:13px;color:#1a2332;">{escape(b.nombre_completo)}</p>
                <p style="font-size:12px;color:#6b7280;">{escape(b.pais_origen)} &middot; {b.fecha_ingreso.strftime('%d/%m/%Y')} &middot; {escape(AREA_LABELS.get(b.area, b.area))}</p>
                {f'<p style="font-size:11px;color:#6b7280;margin-top:3px;font-style:italic;">{escape(b.notas[:80])}</p>' if b.notas else ''}
              </div>
              <span class="status status-{STATUS_CSS[b.status]}">{STATUS_LABELS[b.status]}</span>
              <form method="post" action="/ui/beneficiarios/{b.id}/status" style="display:flex;gap:6px;align-items:center;">

                <select name="new_status" style="font-size:12px;padding:4px 8px;border-radius:7px;border:1px solid #cfc4b5;background:#fff;color:#1a2332;">{_options_a(b.status)}</select>
                <button type="submit" style="background:#a64b2a;color:#fff;padding:5px 10px;font-size:12px;border-radius:7px;cursor:pointer;border:none;">Guardar</button>
              </form>
              <form method="post" action="/ui/beneficiarios/{b.id}/delete" style="margin:0;">

                <button type="submit" onclick="return confirm('\u00bfEliminar este registro?')" style="background:none;border:1px solid #fca5a5;color:#dc2626;padding:5px 10px;border-radius:7px;font-size:12px;cursor:pointer;font-weight:500;">Eliminar</button>
              </form>
            </div>"""
            for b in bens
        )
        demo_section = f"""
        <div class="card" style="padding:24px;margin-top:18px;">
          <h2 style="margin-bottom:18px;">Resumen del sistema</h2>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px;">
            <div style="padding:16px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;">
              <p style="font-size:28px;font-weight:700;color:#1a2332;line-height:1;">{len(activos)}</p>
              <p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">Beneficiarios activos</p>
            </div>
            <div style="padding:16px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;">
              <p style="font-size:28px;font-weight:700;color:#1a2332;line-height:1;">{len(bens)}</p>
              <p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">Total registrados</p>
            </div>
            <div style="padding:16px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;">
              <p style="font-size:28px;font-weight:700;color:#1a2332;line-height:1;">{len(en_revision)}</p>
              <p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">En revisi&oacute;n</p>
            </div>
            <div style="padding:16px;background:#f0fdf4;border:1px solid #86efac;border-radius:10px;">
              <p style="font-size:28px;font-weight:700;color:#166534;line-height:1;">{len(nuevos)}</p>
              <p style="font-size:11px;font-weight:600;color:#166534;margin-top:4px;">Nuevos ingresos</p>
            </div>
          </div>
          <h2 style="margin-bottom:6px;">Registrar beneficiario</h2>
          <p style="font-size:13px;color:#6b7280;margin-bottom:16px;">Crea un nuevo registro directamente desde el portal de administrador.</p>
          <form method="post" action="/ui/beneficiarios" style="margin-bottom:24px;">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
              <label style="display:flex;flex-direction:column;gap:4px;">Nombre completo
                <input name="nombre_completo" placeholder="Apellido Apellido, Nombre" required style="margin-top:0;">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">Pa&iacute;s de origen
                <input name="pais_origen" placeholder="Honduras, Guatemala, Venezuela..." required style="margin-top:0;">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">&Aacute;rea de atenci&oacute;n
                <select name="area" required style="margin-top:0;">
                  <option value="">-- Selecciona --</option>
                  <option value="PSICOSOCIAL">Psicosocial</option>
                  <option value="LEGAL">Legal</option>
                  <option value="HUMANITARIO">Humanitario</option>
                  <option value="ADMINISTRACION">Administraci&oacute;n</option>
                  <option value="COMUNICACION">Comunicaci&oacute;n</option>
                </select>
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">Notas (opcional)
                <input name="notas" placeholder="Situaci&oacute;n general, motivo de solicitud..." style="margin-top:0;">
              </label>
            </div>
            <button type="submit" style="background:var(--accent);color:#fff;padding:9px 20px;border-radius:8px;font-size:13px;font-weight:600;border:none;cursor:pointer;">Registrar beneficiario</button>
          </form>
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
            <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#6b7280;">Todos los registros &mdash; CRUD</p>
            <span style="background:#fee2e2;color:#991b1b;border:1px solid #fca5a5;border-radius:999px;padding:2px 10px;font-size:11px;font-weight:600;">{len(bens)} total</span>
          </div>
          <div style="border:1px solid #e5ddd3;border-radius:8px;overflow:hidden;">
            {admin_rows or '<p style="padding:14px;font-size:13px;color:#6b7280;">Sin registros a&uacute;n.</p>'}
          </div>
        </div>
        """
    elif actor.role.code == "COORDINADOR":
        # CRU: all areas visible, allow status updates
        STATUS_OPTIONS = [("nuevo","Nuevo"),("en_revision","En revisión"),("canalizado","Canalizado"),("activo","Activo")]

        def _options(cur: str) -> str:
            return "".join(
                f'<option value="{v}"{" selected" if v == cur else ""}>{lbl}</option>'
                for v, lbl in STATUS_OPTIONS
            )

        coord_rows = "".join(
            f"""<div style="display:flex;align-items:center;gap:14px;padding:12px 16px;background:#fff;border-bottom:1px solid #e5ddd3;flex-wrap:wrap;">
              <div style="flex:1;min-width:160px;">
                <p style="font-weight:600;font-size:13px;color:#1a2332;">{escape(b.nombre_completo)}</p>
                <p style="font-size:12px;color:#6b7280;">{escape(b.pais_origen)} &middot; {b.fecha_ingreso.strftime('%d/%m/%Y')} &middot; {escape(AREA_LABELS.get(b.area, b.area))}</p>
                {f'<p style="font-size:11px;color:#6b7280;margin-top:3px;font-style:italic;">{escape(b.notas[:80])}</p>' if b.notas else ''}
              </div>
              <span class="status status-{STATUS_CSS[b.status]}">{STATUS_LABELS[b.status]}</span>
              <form method="post" action="/ui/beneficiarios/{b.id}/status" style="display:flex;gap:6px;align-items:center;">

                <select name="new_status" style="font-size:12px;padding:4px 8px;border-radius:7px;border:1px solid #cfc4b5;background:#fff;color:#1a2332;">{_options(b.status)}</select>
                <button type="submit" style="background:#a64b2a;color:#fff;padding:5px 12px;font-size:12px;border-radius:7px;cursor:pointer;border:none;">Guardar</button>
              </form>
            </div>"""
            for b in bens
        )
        demo_section = f"""
        <div style="display:flex;justify-content:flex-end;margin-bottom:12px;">
          <a href="/ui/beneficiarios/export.pdf" style="display:inline-flex;align-items:center;gap:6px;background:#4b5563;color:#fff;padding:8px 16px;border-radius:var(--radius);font-size:13px;font-weight:600;text-decoration:none;">&#8595; Exportar PDF</a>
        </div>
        <div class="card" style="padding:24px;margin-top:0;">
          <h2 style="margin-bottom:6px;">Registrar beneficiario</h2>
          <p style="font-size:13px;color:#6b7280;margin-bottom:18px;">Captura los datos. El registro queda visible para todos los coordinadores y el nivel operativo.</p>
          <form method="post" action="/ui/beneficiarios">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
              <label style="display:flex;flex-direction:column;gap:4px;">Nombre completo
                <input name="nombre_completo" placeholder="Apellido Apellido, Nombre" required style="margin-top:0;">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">Pa&iacute;s de origen
                <input name="pais_origen" placeholder="Honduras, Guatemala, Venezuela..." required style="margin-top:0;">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">&Aacute;rea de atenci&oacute;n
                <select name="area" required style="margin-top:0;">
                  <option value="">-- Selecciona --</option>
                  <option value="PSICOSOCIAL">Psicosocial</option>
                  <option value="LEGAL">Legal</option>
                  <option value="HUMANITARIO">Humanitario</option>
                  <option value="ADMINISTRACION">Administraci&oacute;n</option>
                  <option value="COMUNICACION">Comunicaci&oacute;n</option>
                </select>
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">Notas (opcional)
                <input name="notas" placeholder="Situaci&oacute;n general, motivo de solicitud..." style="margin-top:0;">
              </label>
            </div>
            <button type="submit" style="background:var(--accent);color:#fff;padding:9px 20px;border-radius:8px;font-size:13px;font-weight:600;border:none;cursor:pointer;">Registrar beneficiario</button>
          </form>
        </div>
        <div class="card" style="padding:24px;margin-top:14px;">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:18px;">
            <h2>Casos &mdash; todas las &aacute;reas</h2>
            <span style="background:#ede9fe;color:#5b21b6;border:1px solid #c4b5fd;border-radius:999px;padding:2px 12px;font-size:11px;font-weight:600;">{len(bens)} registro{'s' if len(bens) != 1 else ''}</span>
          </div>
          <div style="border:1px solid #e5ddd3;border-radius:10px;overflow:hidden;">
            {coord_rows or '<p style="padding:16px;font-size:13px;color:#6b7280;">Sin registros a&uacute;n.</p>'}
          </div>
          <p style="font-size:12px;color:#6b7280;margin-top:10px;">Para eliminar un registro, realiza la petici&oacute;n al administrador.</p>
        </div>
        """
    elif actor.role.code == "OPERATIVO":
        # CR: create + read, no status change
        read_rows = "".join(
            f"""<div style="padding:12px 16px;background:#faf7f3;border:1px solid #e5ddd3;border-radius:10px;">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;flex-wrap:wrap;">
                <div>
                  <p style="font-weight:600;font-size:13px;color:#1a2332;">{escape(b.nombre_completo)}</p>
                  <p style="font-size:12px;color:#6b7280;margin-top:2px;">{escape(b.pais_origen)} &middot; {b.fecha_ingreso.strftime('%d/%m/%Y')} &middot; {escape(AREA_LABELS.get(b.area, b.area))}</p>
                  {f'<p style="font-size:11px;color:#6b7280;margin-top:4px;font-style:italic;">{escape(b.notas[:100])}</p>' if b.notas else ''}
                </div>
                <span class="status status-{STATUS_CSS[b.status]}">{STATUS_LABELS[b.status]}</span>
              </div>
            </div>"""
            for b in bens
        )
        demo_section = f"""
        <div class="card" style="padding:24px;margin-top:18px;">
          <h2 style="margin-bottom:6px;">Registrar beneficiario</h2>
          <p style="font-size:13px;color:#6b7280;margin-bottom:18px;">Captura los datos del beneficiario. El registro queda visible para el coordinador del &aacute;rea.</p>
          <form method="post" action="/ui/beneficiarios">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
              <label style="display:flex;flex-direction:column;gap:4px;">Nombre completo
                <input name="nombre_completo" placeholder="Apellido Apellido, Nombre" required style="margin-top:0;">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">Pa&iacute;s de origen
                <input name="pais_origen" placeholder="Honduras, Guatemala, Venezuela..." required style="margin-top:0;">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">&Aacute;rea de atenci&oacute;n
                <select name="area" required style="margin-top:0;">
                  <option value="">-- Selecciona --</option>
                  <option value="PSICOSOCIAL">Psicosocial</option>
                  <option value="LEGAL">Legal</option>
                  <option value="HUMANITARIO">Humanitario</option>
                  <option value="ADMINISTRACION">Administraci&oacute;n</option>
                  <option value="COMUNICACION">Comunicaci&oacute;n</option>
                </select>
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">Notas (opcional)
                <input name="notas" placeholder="Situaci&oacute;n general, motivo de solicitud..." style="margin-top:0;">
              </label>
            </div>
            <button type="submit" style="background:var(--accent);color:#fff;padding:9px 20px;border-radius:8px;font-size:13px;font-weight:600;border:none;cursor:pointer;">Registrar beneficiario</button>
          </form>
        </div>
        <div class="card" style="padding:24px;margin-top:14px;">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:16px;">
            <h2>Registros en el sistema</h2>
            <span style="background:#e0f2fe;color:#075985;border:1px solid #7dd3fc;border-radius:999px;padding:2px 12px;font-size:11px;font-weight:600;">CR &mdash; Crear y Leer</span>
          </div>
          <p style="font-size:13px;color:#6b7280;margin-bottom:16px;">Para actualizar el estado de un caso, canaliza al coordinador del &aacute;rea correspondiente.</p>
          <div style="display:flex;flex-direction:column;gap:8px;">
            {read_rows or '<p style="font-size:13px;color:#6b7280;">Sin registros a&uacute;n.</p>'}
          </div>
        </div>
        """
    elif actor.role.code == "VOLUNTARIO":
        # C only: registration form, no table
        demo_section = f"""
        <div class="card" style="padding:24px;margin-top:18px;">
          <h2 style="margin-bottom:6px;">Registrar beneficiario</h2>
          <p style="font-size:13px;color:#6b7280;margin-bottom:18px;">Captura los datos b&aacute;sicos. El registro pasa autom&aacute;ticamente al nivel operativo para su revisi&oacute;n.</p>
          <form method="post" action="/ui/beneficiarios">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
              <label style="display:flex;flex-direction:column;gap:4px;">Nombre completo
                <input name="nombre_completo" placeholder="Apellido Apellido, Nombre" required style="margin-top:0;">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">Pa&iacute;s de origen
                <input name="pais_origen" placeholder="Honduras, Guatemala, Venezuela..." required style="margin-top:0;">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">&Aacute;rea de atenci&oacute;n
                <select name="area" required style="margin-top:0;">
                  <option value="">-- Selecciona --</option>
                  <option value="PSICOSOCIAL">Psicosocial</option>
                  <option value="LEGAL">Legal</option>
                  <option value="HUMANITARIO">Humanitario</option>
                  <option value="ADMINISTRACION">Administraci&oacute;n</option>
                  <option value="COMUNICACION">Comunicaci&oacute;n</option>
                </select>
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">Notas iniciales (opcional)
                <input name="notas" placeholder="Situaci&oacute;n general, motivo de solicitud..." style="margin-top:0;">
              </label>
            </div>
            <button type="submit" style="background:var(--accent);color:#fff;padding:9px 20px;border-radius:8px;font-size:13px;font-weight:600;border:none;cursor:pointer;">Registrar beneficiario</button>
          </form>
        </div>
        """
    else:
        demo_section = ""
    # --- Role-specific content block ---
    if actor.status != "active":
        role_content = f"<div class='error' style='margin-top:16px;'>Tu cuenta est&aacute; en estado <strong>{escape(actor.status)}</strong>. Contacta a un administrador para restablecer el acceso.</div>"
    elif actor.role.code == "ADMIN":
        role_content = f"""
        <div class="grid" style="margin-top:0;">
          <div class="panel">
            <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:6px;">Administrador</p>
            <p style="font-size:12px;color:var(--muted);margin-bottom:4px;">Acceso completo &mdash; <strong style="color:var(--text);">CRUD</strong> (Crear, Leer, Actualizar, Eliminar)</p>
            <p style="font-size:12px;color:var(--muted);margin-bottom:14px;">Gestiona usuarios, roles, certificados, auditor&iacute;a y recuperaci&oacute;n de emergencia.</p>
            <a href="/dashboard?as_user={actor.id}" style="display:inline-flex;align-items:center;gap:6px;background:var(--accent);color:#fff;padding:8px 16px;border-radius:8px;font-size:13px;font-weight:600;text-decoration:none;">
              Abrir panel de administraci&oacute;n &rarr;
            </a>
          </div>
          <div class="panel">
            <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:8px;">Auditor&iacute;a</p>
            <p style="font-size:32px;font-weight:700;line-height:1;letter-spacing:-1px;">{len(logs)}</p>
            <p class="muted" style="margin-top:4px;">eventos registrados</p>
          </div>
        </div>
        """
    elif actor.role.code == "COORDINADOR":
        role_content = f"""
        <div class="panel" style="margin-top:0;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:10px;">
            <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);">Coordinador</p>
            <span style="background:#ede9fe;color:#5b21b6;border:1px solid #c4b5fd;border-radius:999px;padding:2px 10px;font-size:11px;font-weight:600;">CRU &mdash; sin eliminaci&oacute;n</span>
          </div>
          <p style="font-size:13px;color:var(--muted);margin-bottom:14px;">Puedes crear, leer y actualizar registros. Para eliminar un registro debes realizar una petici&oacute;n al administrador.</p>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;">
            {''.join(f'<div style="padding:8px 12px;background:var(--surface-2);border:1px solid var(--border);border-radius:8px;font-size:12px;font-weight:500;">{area}</div>' for area in ['Administraci&oacute;n','Legal','Psicosocial','Humanitario','Comunicaci&oacute;n'])}
          </div>
        </div>
        """
    elif actor.role.code == "OPERATIVO":
        role_content = """
        <div class="panel" style="margin-top:0;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:10px;">
            <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);">Operativo</p>
            <span style="background:#e0f2fe;color:#075985;border:1px solid #7dd3fc;border-radius:999px;padding:2px 10px;font-size:11px;font-weight:600;">CR &mdash; Crear y Leer</span>
          </div>
          <p style="font-size:13px;color:var(--muted);">Puedes crear y consultar registros. Revisa los datos ingresados y canaliza al nivel coordinador para actualizaciones o acciones adicionales.</p>
        </div>
        """
    elif actor.role.code == "VOLUNTARIO":
        role_content = """
        <div class="panel" style="margin-top:0;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:10px;">
            <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);">Usuario (Becario / Voluntario / Servicio social / Recepci&oacute;n)</p>
            <span style="background:#f0fdf4;color:#14532d;border:1px solid #86efac;border-radius:999px;padding:2px 10px;font-size:11px;font-weight:600;">C &mdash; Solo registro</span>
          </div>
          <p style="font-size:13px;color:var(--muted);">Registras datos de beneficiarios y los canalizas al nivel operativo. No puedes modificar ni eliminar registros existentes.</p>
        </div>
        """
    else:
        role_content = "<div class='error' style='margin-top:16px;'>Rol no reconocido para esta demo.</div>"

    _STATUS_LABELS = {"active": "Activo", "pending": "Pendiente", "revoked": "Revocado", "expired": "Expirado"}
    _STATUS_CSS = {"active": "active", "pending": "pending", "revoked": "revoked", "expired": "expired"}

    # ── Certificate health indicator ──
    _cert_health_html = ""
    if role_requires_crypto(actor) and actor.certificate_not_after:
        from datetime import datetime, timezone
        _now = datetime.now(timezone.utc)
        _cert_exp = actor.certificate_not_after
        if _cert_exp.tzinfo is None:
            _cert_exp = _cert_exp.replace(tzinfo=timezone.utc)
        _days_left = (_cert_exp - _now).days
        if _days_left < 0:
            _health_color = "#dc2626"; _health_bg = "#fee2e2"; _health_border = "#fca5a5"
            _health_label = "Expirado"; _health_icon = "&#10007;"
            _health_msg = f"Tu certificado expiró hace {abs(_days_left)} día{'s' if abs(_days_left) != 1 else ''}."
        elif _days_left <= 7:
            _health_color = "#dc2626"; _health_bg = "#fee2e2"; _health_border = "#fca5a5"
            _health_label = "Crítico"; _health_icon = "&#9888;"
            _health_msg = f"Tu certificado expira en {_days_left} día{'s' if _days_left != 1 else ''}. Solicita renovación urgente."
        elif _days_left <= 30:
            _health_color = "#92400e"; _health_bg = "#fef3c7"; _health_border = "#fcd34d"
            _health_label = "Próximo a expirar"; _health_icon = "&#9888;"
            _health_msg = f"Tu certificado expira en {_days_left} días. Considera renovarlo pronto."
        else:
            _health_color = "#166534"; _health_bg = "#dcfce7"; _health_border = "#86efac"
            _health_label = "Saludable"; _health_icon = "&#10003;"
            _health_msg = f"Tu certificado es válido por {_days_left} días más."

        _cert_health_html = f"""
    <div style="background:{_health_bg};border:1px solid {_health_border};border-radius:12px;padding:16px 20px;margin-bottom:16px;display:flex;align-items:center;gap:14px;">
      <div style="width:42px;height:42px;border-radius:50%;background:{_health_border};display:flex;align-items:center;justify-content:center;font-size:20px;color:{_health_color};flex-shrink:0;">{_health_icon}</div>
      <div>
        <p style="font-weight:700;font-size:14px;color:{_health_color};">Salud del certificado: {_health_label}</p>
        <p style="font-size:13px;color:{_health_color};opacity:.85;">{_health_msg}</p>
        <p style="font-size:11px;color:{_health_color};opacity:.7;margin-top:2px;">Expira: {_cert_exp.strftime('%d/%m/%Y %H:%M')} UTC</p>
      </div>
    </div>"""

    # --- Section: Mi cuenta ---
    _cuenta_content = f"""
    <section style="margin-bottom:24px;">
      <h1 class="page-title">Mi cuenta</h1>
      <div class="page-title-accent"></div>
      <p class="muted" style="font-size:14px;margin-top:2px;">Bienvenido/a, <strong style="color:var(--text);">{escape(actor.full_name)}</strong></p>
      {verified_html}{render_notice(notice)}
      {_cert_health_html}
    </section>
    <div class="card" style="padding:28px;margin-bottom:16px;">
      <h2 style="margin-bottom:16px;">Informaci&oacute;n personal</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:20px;">
        <div style="padding:14px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;">
          <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:6px;">Nombre completo</p>
          <p style="font-weight:600;font-size:14px;">{escape(actor.full_name)}</p>
        </div>
        <div style="padding:14px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;">
          <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:6px;">Correo electr&oacute;nico</p>
          <p style="font-size:13px;word-break:break-all;">{escape(actor.email)}</p>
        </div>
        <div style="padding:14px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;">
          <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:6px;">Rol</p>
          <p style="font-weight:600;font-size:14px;">{escape(actor.role.name)}</p>
        </div>
        <div style="padding:14px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;">
          <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:8px;">Estado</p>
          <span class="status status-{_STATUS_CSS.get(actor.status, 'pending')}">{_STATUS_LABELS.get(actor.status, actor.status)}</span>
        </div>
      </div>
      {role_content}
    </div>
    <div class="card" style="padding:28px;">
      <h2 style="margin-bottom:8px;">&iquest;Necesitas recuperar el acceso?</h2>
      <p class="muted" style="font-size:13px;margin-bottom:16px;">Si olvidaste tu contrase&ntilde;a o perdiste tus archivos de acceso, puedes notificar al administrador. Deber&aacute;s verificar tu identidad en persona para recibir nuevas credenciales.</p>
      <form method="post" action="/portal/request-password-reset">
        <button type="submit" class="btn-ghost">Enviar solicitud al administrador</button>
      </form>
    </div>
    """

    if role_requires_crypto(actor):
        _credenciales_content = f"""
    <section style="margin-bottom:24px;">
      <h1 class="page-title">Mis credenciales</h1>
      <div class="page-title-accent"></div>
      <p class="muted" style="font-size:14px;margin-top:2px;">Archivos de acceso y certificado de identidad</p>
      {render_notice(notice)}
    </section>
    <div class="card" style="padding:28px;">{cert_section}</div>
    """
    else:
        _credenciales_content = f"""
    <section style="margin-bottom:24px;">
      <h1 class="page-title">Mis credenciales</h1>
      <div class="page-title-accent"></div>
      {render_notice(notice)}
    </section>
    <div class="card" style="padding:28px;"><p class="muted">Tu rol utiliza acceso con usuario y contrase&ntilde;a. No tienes archivos de acceso asignados.</p></div>
    """

    # --- Section: Beneficiarios ---
    if actor.status == "active":
        _beneficiarios_content = f"""
    <section style="margin-bottom:24px;">
      <h1 class="page-title">Beneficiarios</h1>
      <div class="page-title-accent"></div>
      <p class="muted" style="font-size:14px;margin-top:2px;">Gesti&oacute;n de registros de beneficiarios</p>
      {render_notice(notice)}
    </section>
    {demo_section}
    """
    else:
        _beneficiarios_content = f"""
    <section style="margin-bottom:24px;">
      <h1 class="page-title">Beneficiarios</h1>
      <div class="page-title-accent"></div>
    </section>
    <div class='error'>Tu cuenta est&aacute; en estado <strong>{escape(actor.status)}</strong>. Contacta a un administrador para restablecer el acceso.</div>
    """

    _directorio_content = ""
    if actor.role.code == "COORDINADOR" and actor.status == "active":
        _directorio_content = f"""
    <section style="margin-bottom:24px;">
      <h1 class="page-title">Directorio de usuarios</h1>
      <div class="page-title-accent"></div>
      <p class="muted" style="font-size:14px;margin-top:2px;">Exporta el listado completo de usuarios del sistema.</p>
    </section>
    <div class="card" style="padding:28px;">
      <p style="font-size:13px;color:#6b7280;margin-bottom:18px;">Genera un PDF con los datos de todos los usuarios registrados: nombre, correo, rol, estado y fecha de alta.</p>
      <a href="/ui/users/export.pdf" style="display:inline-flex;align-items:center;gap:6px;background:#4b5563;color:#fff;padding:10px 20px;border-radius:var(--radius);font-size:13px;font-weight:600;text-decoration:none;">&#8595; Descargar PDF</a>
    </div>
    """

    # --- Section: Documentos (firma y verificación) ---
    _documentos_content = ""
    if actor.status == "active" and actor.role.code in CRYPTO_ROLE_CODES:
        doc_list = documents or []
        doc_type_options = "".join(
            f'<option value="{k}">{escape(v)}</option>' for k, v in DOC_TYPE_LABELS.items()
        )
        doc_type_combo_items = "".join(
            f'<div class="combo-item" data-value="{k}" onclick="pickCombo(this)">{escape(v)}</div>'
            for k, v in DOC_TYPE_LABELS.items()
        )

        _DOC_STATUS_CSS = {
            "signed": "active",
            "verified": "active",
            "revoked": "revoked",
            "expired": "expired",
            "draft": "pending",
            "pending_signatures": "pending",
        }

        # Build pending-cosign section for users who can sign
        pending_cosign_list = pending_cosign or []
        pending_cosign_rows = ""
        for d in pending_cosign_list:
            sigs_done = len(d.co_signatures)
            sigs_needed = d.required_signers
            pending_cosign_rows += f"""<div style="display:flex;align-items:center;gap:12px;padding:12px 16px;background:#fff;border-bottom:1px solid #e5ddd3;flex-wrap:wrap;">
              <div style="flex:1;min-width:180px;">
                <p style="font-weight:600;font-size:13px;color:#1a2332;">{escape(d.title)}</p>
                <p style="font-size:12px;color:#6b7280;">
                  <code style="font-size:11px;">{escape(d.folio)}</code> &middot;
                  {escape(DOC_TYPE_LABELS.get(d.document_type, d.document_type))} &middot;
                  Iniciado por: {escape(d.signer.full_name)} &middot;
                  {d.issued_at.strftime('%d/%m/%Y %H:%M')}
                </p>
                <p style="font-size:11px;color:#92400e;margin-top:2px;">Firmas: {sigs_done}/{sigs_needed}</p>
              </div>
              <form method="post" action="/ui/documents/{escape(d.folio)}/cosign" style="margin:0;">
                <button type="submit" style="background:var(--accent);color:#fff;padding:5px 14px;border-radius:7px;font-size:12px;font-weight:600;border:none;cursor:pointer;">Cofirmar</button>
              </form>
            </div>"""

        _pending_cosign_section = ""
        if pending_cosign_rows:
            _pending_cosign_section = f"""
    <div class="card" style="padding:24px;margin-bottom:16px;border:2px solid #fde68a;background:#fffbeb;">
      <h2 style="margin-bottom:6px;color:#92400e;">&#9997; Documentos pendientes de tu firma</h2>
      <p style="font-size:13px;color:#78350f;margin-bottom:14px;">Los siguientes documentos requieren tu firma para quedar v&aacute;lidos.</p>
      <div style="border:1px solid #fde68a;border-radius:10px;overflow:hidden;">
        {pending_cosign_rows}
      </div>
    </div>"""

        doc_rows = ""
        for d in doc_list:
            st_css = _DOC_STATUS_CSS.get(d.status, "pending")
            st_label = DOC_STATUS_LABELS.get(d.status, d.status)
            # Build signers line
            if d.co_signatures:
                signer_names = ", ".join(
                    escape(s.signer.full_name) for s in sorted(d.co_signatures, key=lambda s: s.signed_at)
                )
                sigs_info = f"Firmado por: {signer_names} ({len(d.co_signatures)}/{d.required_signers})"
            else:
                sigs_info = f"Firmado por: {escape(d.signer.full_name)}"
            doc_rows += f"""<div class="doc-row" data-type="{escape(d.document_type)}" data-status="{escape(d.status)}" style="display:flex;align-items:center;gap:12px;padding:12px 16px;background:#fff;border-bottom:1px solid #e5ddd3;flex-wrap:wrap;">
              <div style="flex:1;min-width:180px;">
                <p style="font-weight:600;font-size:13px;color:#1a2332;">{escape(d.title)}</p>
                <p style="font-size:12px;color:#6b7280;">
                  <code style="font-size:11px;">{escape(d.folio)}</code> &middot;
                  {escape(DOC_TYPE_LABELS.get(d.document_type, d.document_type))} &middot;
                  {d.issued_at.strftime('%d/%m/%Y %H:%M')} &middot;
                  {sigs_info}
                </p>
              </div>
              <span class="status status-{st_css}">{st_label}</span>
              <a href="/verificar/{escape(d.folio)}" target="_blank" style="font-size:12px;font-weight:600;color:var(--accent);text-decoration:none;">Verificar</a>"""
            if d.status == "signed" and (actor.role.code == "ADMIN" or d.signer_user_id == actor.id):
                doc_rows += f"""
              <form method="post" action="/ui/documents/{d.folio}/revoke" style="margin:0;display:inline;">
                <input type="hidden" name="reason" value="">
                <button type="submit" onclick="var r=prompt('Motivo de revocaci&oacute;n:');if(!r)return false;this.form.reason.value=r;return true;" style="background:none;border:1px solid #fca5a5;color:#dc2626;padding:4px 10px;border-radius:7px;font-size:11px;cursor:pointer;font-weight:500;">Revocar</button>
              </form>"""
            doc_rows += "</div>"

        _documentos_content = f"""
    <section style="margin-bottom:24px;">
      <h1 class="page-title">Documentos</h1>
      <div class="page-title-accent"></div>
      <p class="muted" style="font-size:14px;margin-top:2px;">Firma digital de documentos y verificaci&oacute;n de autenticidad</p>
      {render_notice(notice)}
    </section>
    {_pending_cosign_section}

    <div class="card" style="padding:28px;margin-bottom:16px;">
      <h2 style="margin-bottom:6px;">Firmar documento</h2>
      <p style="font-size:13px;color:#6b7280;margin-bottom:18px;">Carga un documento para firmarlo digitalmente con tu certificado X.509. Se generar&aacute; un folio &uacute;nico de verificaci&oacute;n.</p>

      <div style="padding:12px 14px;background:#eff6ff;border:1px solid #93c5fd;border-radius:8px;display:flex;gap:10px;align-items:flex-start;margin-bottom:18px;">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#1d4ed8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:1px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <div style="font-size:12px;color:#1e40af;line-height:1.5;">
          <strong>Proceso criptogr&aacute;fico:</strong> Se calcula el hash SHA-256 del documento, se firma con tu llave privada RSA (RSA-PSS-SHA256) y se verifica inmediatamente con tu certificado p&uacute;blico. El documento original <strong>no se almacena</strong> en el servidor &mdash; solo el hash y la firma digital.
        </div>
      </div>

      <form method="post" action="/ui/documents/sign" enctype="multipart/form-data">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;">
          <label style="display:flex;flex-direction:column;gap:4px;">T&iacute;tulo del documento
            <input name="title" placeholder="Constancia de atenci&oacute;n, Carta institucional..." required>
          </label>
          <label style="display:flex;flex-direction:column;gap:4px;">Tipo de documento
            <div class="combo-wrap">
              <input type="text" id="combo-doctype" placeholder="Buscar tipo..." autocomplete="off"
                     onfocus="this.nextElementSibling.classList.add('open')"
                     oninput="filterCombo(this)"
                     onkeydown="comboKey(event,this)">
              <div class="combo-list" id="combo-doctype-list">
                {doc_type_combo_items}
              </div>
              <select name="document_type" id="combo-doctype-sel" required style="position:absolute;opacity:0;height:0;width:0;pointer-events:none;" tabindex="-1">
                <option value="">-- Selecciona --</option>
                {doc_type_options}
              </select>
            </div>
          </label>
          <label style="display:flex;flex-direction:column;gap:4px;">Vigencia (d&iacute;as, opcional)
            <input name="expires_days" type="number" min="1" max="3650" placeholder="Dejar vac&iacute;o para sin vencimiento">
          </label>
          <label style="display:flex;flex-direction:column;gap:4px;">Firmas requeridas
            <input name="required_signers" type="number" min="1" max="10" value="1" title="N&uacute;mero m&iacute;nimo de firmantes para que el documento sea v&aacute;lido">
            <span style="font-size:11px;color:#9ca3af;">1 = solo t&uacute;; m&aacute;s de 1 = requiere co-firmantes adicionales</span>
          </label>
        </div>
        <label style="display:flex;flex-direction:column;gap:4px;margin-bottom:14px;">Archivo a firmar
          <span style="font-size:11px;color:#9ca3af;">Formatos: PDF, DOC, DOCX, TXT, ODT &mdash; M&aacute;ximo 20 MB</span>
          <div class="file-zone" style="margin-top:4px;">
            <div class="file-zone-icon" style="width:36px;height:36px;border-radius:8px;background:#fff3eb;border:1px solid #f0d4c5;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e06020" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
            </div>
            <div>
              <div class="file-zone-text" id="docf-text">Arrastra tu documento aqu&iacute;</div>
              <div class="file-zone-sub" id="docf-sub">o selecciona un archivo</div>
            </div>
            <input type="file" name="document_file" accept=".pdf,.doc,.docx,.txt,.odt" id="docf" required onchange="setDocFile(this)" style="position:absolute;inset:0;opacity:0;width:100%;height:100%;cursor:pointer;">
          </div>
        </label>
        <button type="submit" style="background:var(--accent);color:#fff;padding:10px 22px;border-radius:8px;font-size:14px;font-weight:600;border:none;cursor:pointer;display:inline-flex;align-items:center;gap:8px;">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Firmar documento
        </button>
      </form>
    </div>

    <div class="card" style="padding:28px;margin-bottom:16px;">
      <h2 style="margin-bottom:6px;">Firma masiva (Batch Signing)</h2>
      <p style="font-size:13px;color:#6b7280;margin-bottom:18px;">Selecciona m&uacute;ltiples documentos para firmarlos todos con un solo clic. Ideal para constancias de atenci&oacute;n del d&iacute;a.</p>
      <form method="post" action="/ui/documents/batch-sign" enctype="multipart/form-data">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;">
          <label style="display:flex;flex-direction:column;gap:4px;">Tipo de documento (aplica a todos)
            <select name="document_type" required>
              <option value="">-- Selecciona --</option>
              {doc_type_options}
            </select>
          </label>
          <label style="display:flex;flex-direction:column;gap:4px;">Vigencia (d&iacute;as, opcional)
            <input name="expires_days" type="number" min="1" max="3650" placeholder="Sin vencimiento">
          </label>
        </div>
        <label style="display:flex;flex-direction:column;gap:4px;margin-bottom:14px;">Archivos a firmar
          <span style="font-size:11px;color:#9ca3af;">Selecciona hasta 20 archivos &mdash; PDF, DOC, DOCX, TXT, ODT</span>
          <div class="file-zone" style="margin-top:4px;" id="batch-zone">
            <div class="file-zone-icon" style="width:36px;height:36px;border-radius:8px;background:#fff3eb;border:1px solid #f0d4c5;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e06020" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="6" width="20" height="14" rx="2"/><path d="M2 10h20"/></svg>
            </div>
            <div>
              <div class="file-zone-text" id="batchf-text">Arrastra tus documentos aqu&iacute;</div>
              <div class="file-zone-sub" id="batchf-sub">o selecciona m&uacute;ltiples archivos</div>
            </div>
            <input type="file" name="document_files" accept=".pdf,.doc,.docx,.txt,.odt" id="batchf" required multiple onchange="setBatchFiles(this)">
          </div>
        </label>
        <button type="submit" style="background:var(--accent);color:#fff;padding:10px 22px;border-radius:8px;font-size:14px;font-weight:600;border:none;cursor:pointer;display:inline-flex;align-items:center;gap:8px;">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Firmar todos
        </button>
      </form>
    </div>

    <div class="card" style="padding:24px;">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:16px;">
        <h2>Documentos firmados</h2>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <span style="background:#e0f2fe;color:#075985;border:1px solid #7dd3fc;border-radius:999px;padding:2px 12px;font-size:11px;font-weight:600;">{len(doc_list)} documento{'s' if len(doc_list) != 1 else ''}</span>
          <a href="/ui/documents/export-csv" style="font-size:11px;font-weight:600;color:var(--accent);text-decoration:none;border:1px solid var(--accent);padding:3px 10px;border-radius:7px;">Exportar CSV</a>
        </div>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
        <input type="text" id="doc-search" placeholder="Buscar por folio, t&iacute;tulo o firmante..." oninput="filterDocs()" style="flex:1;min-width:180px;font-size:13px;padding:7px 12px;">
        <select id="doc-filter-type" onchange="filterDocs()" style="font-size:13px;padding:7px 10px;min-width:140px;">
          <option value="">Todos los tipos</option>
          {doc_type_options}
        </select>
        <select id="doc-filter-status" onchange="filterDocs()" style="font-size:13px;padding:7px 10px;min-width:140px;">
          <option value="">Todos los estados</option>
          <option value="signed">Firmado</option>
          <option value="pending_signatures">Pendiente de firma</option>
          <option value="revoked">Revocado</option>
          <option value="expired">Expirado</option>
        </select>
      </div>
      <div style="border:1px solid #e5ddd3;border-radius:10px;overflow:hidden;">
        {doc_rows or '<p style="padding:16px;font-size:13px;color:#6b7280;">No hay documentos firmados a&uacute;n.</p>'}
      </div>
      <p style="font-size:12px;color:#6b7280;margin-top:12px;">
        <a href="/verificar" target="_blank" style="font-weight:600;">Abrir portal p&uacute;blico de verificaci&oacute;n &rarr;</a>
      </p>
    </div>

    <script>
    function setDocFile(input) {{
      var zone = input.closest('.file-zone');
      var textEl = document.getElementById('docf-text');
      var subEl = document.getElementById('docf-sub');
      if (input.files && input.files.length > 0) {{
        textEl.textContent = input.files[0].name;
        subEl.textContent = (input.files[0].size / 1024).toFixed(1) + ' KB \\u2714';
        zone.classList.add('has-file');
      }} else {{
        textEl.innerHTML = 'Arrastra tu documento aqu\\u00ed';
        subEl.textContent = 'o selecciona un archivo';
        zone.classList.remove('has-file');
      }}
    }}
    /* ── Searchable combobox ── */
    function filterCombo(inp) {{
      var list = inp.nextElementSibling;
      var q = inp.value.toLowerCase();
      list.classList.add('open');
      list.querySelectorAll('.combo-item').forEach(function(it) {{
        it.classList.toggle('hidden', q && it.textContent.toLowerCase().indexOf(q) === -1);
      }});
    }}
    function pickCombo(item) {{
      var wrap = item.closest('.combo-wrap');
      var inp = wrap.querySelector('input[type="text"]');
      var sel = wrap.querySelector('select');
      inp.value = item.textContent;
      sel.value = item.getAttribute('data-value');
      item.parentElement.classList.remove('open');
    }}
    function comboKey(e, inp) {{
      if (e.key === 'Escape') inp.nextElementSibling.classList.remove('open');
    }}
    document.addEventListener('click', function(e) {{
      document.querySelectorAll('.combo-list.open').forEach(function(cl) {{
        if (!cl.parentElement.contains(e.target)) cl.classList.remove('open');
      }});
    }});
    /* ── Batch file handler ── */
    function setBatchFiles(input) {{
      var zone = input.closest('.file-zone');
      var textEl = document.getElementById('batchf-text');
      var subEl = document.getElementById('batchf-sub');
      if (input.files && input.files.length > 0) {{
        textEl.textContent = input.files.length + ' archivo' + (input.files.length > 1 ? 's' : '') + ' seleccionado' + (input.files.length > 1 ? 's' : '');
        var total = 0; for(var i=0;i<input.files.length;i++) total += input.files[i].size;
        subEl.textContent = (total/1024).toFixed(1) + ' KB total \\u2714';
        zone.classList.add('has-file');
      }} else {{
        textEl.innerHTML = 'Arrastra tus documentos aqu\\u00ed';
        subEl.textContent = 'o selecciona m\\u00faltiples archivos';
        zone.classList.remove('has-file');
      }}
    }}
    /* ── Smart search & filter ── */
    function filterDocs() {{
      var q = (document.getElementById('doc-search').value || '').toLowerCase();
      var ft = document.getElementById('doc-filter-type').value;
      var fs = document.getElementById('doc-filter-status').value;
      document.querySelectorAll('.doc-row').forEach(function(row) {{
        var matchQ = !q || row.textContent.toLowerCase().indexOf(q) !== -1;
        var matchT = !ft || row.getAttribute('data-type') === ft;
        var matchS = !fs || row.getAttribute('data-status') === fs;
        row.style.display = (matchQ && matchT && matchS) ? '' : 'none';
      }});
    }}
    </script>
    """

    _section_map = {
        "cuenta": _cuenta_content,
        "credenciales": _credenciales_content,
        "beneficiarios": _beneficiarios_content,
        "directorio": _directorio_content,
        "documentos": _documentos_content,
    }

    body = f"""
    {_section_map.get(section, _cuenta_content)}
    <script>
    function showTab(btn, tabId) {{
      document.querySelectorAll('.coord-tab').forEach(function(b) {{
        b.style.background = 'var(--surface-2)';
        b.style.color = 'var(--muted)';
        b.style.borderColor = 'var(--border)';
      }});
      btn.style.background = 'var(--accent)';
      btn.style.color = '#fff';
      btn.style.borderColor = 'var(--accent)';
    }}
    </script>
    """
    return base_page("Portal \u00b7 Casa Monarca", body, actor=actor, portal_sections=_build_portal_sections(actor, section))


def _render_beneficiarios_admin(actor, bens: list) -> str:
    STATUS_LABELS = {"nuevo": "Nuevo", "en_revision": "En revisión", "canalizado": "Canalizado", "activo": "Activo"}
    STATUS_CSS = {"nuevo": "pending", "en_revision": "pending", "canalizado": "active", "activo": "active"}
    AREA_LABELS = {
        "ADMINISTRACION": "Administración", "LEGAL": "Legal",
        "PSICOSOCIAL": "Psicosocial", "HUMANITARIO": "Humanitario", "COMUNICACION": "Comunicación",
    }
    STATUS_OPTIONS = [("nuevo","Nuevo"),("en_revision","En revisión"),("canalizado","Canalizado"),("activo","Activo")]

    def _opts(cur: str) -> str:
        return "".join(
            f'<option value="{v}"{" selected" if v == cur else ""}>{lbl}</option>'
            for v, lbl in STATUS_OPTIONS
        )

    activos = [b for b in bens if b.status == "activo"]
    nuevos  = [b for b in bens if b.status == "nuevo"]
    en_rev  = [b for b in bens if b.status == "en_revision"]

    rows = "".join(
        f"""<div style="display:flex;align-items:center;gap:12px;padding:11px 14px;background:#fff;border-bottom:1px solid #e5ddd3;flex-wrap:wrap;">
          <div style="flex:1;min-width:160px;">
            <p style="font-weight:600;font-size:13px;color:#1a2332;">{escape(b.nombre_completo)}</p>
            <p style="font-size:12px;color:#6b7280;">{escape(b.pais_origen)} &middot; {b.fecha_ingreso.strftime('%d/%m/%Y')} &middot; {escape(AREA_LABELS.get(b.area, b.area))}</p>
            {f'<p style="font-size:11px;color:#6b7280;margin-top:3px;font-style:italic;">{escape(b.notas[:80])}</p>' if b.notas else ''}
          </div>
          <span class="status status-{STATUS_CSS[b.status]}">{STATUS_LABELS[b.status]}</span>
          <form method="post" action="/ui/beneficiarios/{b.id}/status" style="display:flex;gap:6px;align-items:center;">

            <select name="new_status" style="font-size:12px;padding:4px 8px;border-radius:7px;border:1px solid #cfc4b5;background:#fff;color:#1a2332;">{_opts(b.status)}</select>
            <button type="submit" style="background:#a64b2a;color:#fff;padding:5px 10px;font-size:12px;border-radius:7px;cursor:pointer;border:none;">Guardar</button>
          </form>
          <form method="post" action="/ui/beneficiarios/{b.id}/delete" style="margin:0;">

            <button type="submit" onclick="return confirm('\u00bfEliminar este registro?')" style="background:none;border:1px solid #fca5a5;color:#dc2626;padding:5px 10px;border-radius:7px;font-size:12px;cursor:pointer;font-weight:500;">Eliminar</button>
          </form>
        </div>"""
        for b in bens
    )

    return f"""
    <details class="collapsible-panel" id="beneficiarios">
      <summary><h2>Beneficiarios</h2><span class="summary-button">Abrir</span></summary>
      <div class="panel-body" style="padding:16px 20px 24px;">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:20px;">
          <div style="padding:14px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;">
            <p style="font-size:24px;font-weight:700;color:#1a2332;line-height:1;">{len(activos)}</p>
            <p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">Activos</p>
          </div>
          <div style="padding:14px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;">
            <p style="font-size:24px;font-weight:700;color:#1a2332;line-height:1;">{len(bens)}</p>
            <p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">Total</p>
          </div>
          <div style="padding:14px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;">
            <p style="font-size:24px;font-weight:700;color:#1a2332;line-height:1;">{len(en_rev)}</p>
            <p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">En revisi&oacute;n</p>
          </div>
          <div style="padding:14px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;">
            <p style="font-size:24px;font-weight:700;color:#1a2332;line-height:1;">{len(nuevos)}</p>
            <p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">Nuevos</p>
          </div>
        </div>
        <div style="background:#fff;border:1px solid #e5ddd3;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.06);margin-bottom:20px;overflow:hidden;">
          <div style="padding:18px 24px;border-bottom:1px solid #e5ddd3;display:flex;justify-content:space-between;align-items:flex-start;">
            <div>
              <h2 style="font-size:16px;font-weight:700;color:#1a2332;margin:0;">Registrar beneficiario</h2>
              <p style="font-size:13px;color:#6b7280;margin-top:3px;">Captura los datos del beneficiario. El registro queda visible para el coordinador del &aacute;rea.</p>
            </div>
          </div>
          <div style="padding:20px 24px;">
            <form method="post" action="/ui/beneficiarios">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px;">
                <label style="display:flex;flex-direction:column;gap:5px;">Nombre completo
                  <input name="nombre_completo" placeholder="Apellido Apellido, Nombre" required>
                </label>
                <label style="display:flex;flex-direction:column;gap:5px;">Pa&iacute;s de origen
                  <input name="pais_origen" placeholder="Honduras, Guatemala, Venezuela...">
                </label>
                <label style="display:flex;flex-direction:column;gap:5px;">&Aacute;rea de atenci&oacute;n
                  <select name="area" required>
                    <option value="">-- Selecciona --</option>
                    <option value="PSICOSOCIAL">Psicosocial</option>
                    <option value="LEGAL">Legal</option>
                    <option value="HUMANITARIO">Humanitario</option>
                    <option value="ADMINISTRACION">Administraci&oacute;n</option>
                    <option value="COMUNICACION">Comunicaci&oacute;n</option>
                  </select>
                </label>
                <label style="display:flex;flex-direction:column;gap:5px;">Notas (opcional)
                  <input name="notas" placeholder="Situaci&oacute;n general, motivo de solicitud...">
                </label>
              </div>
              <button type="submit">Registrar beneficiario</button>
            </form>
          </div>
        </div>
        <div style="border:1px solid #e5ddd3;border-radius:8px;overflow:hidden;">
          {rows or '<p style="padding:14px;font-size:13px;color:#6b7280;">Sin registros a&uacute;n.</p>'}
        </div>
      </div>
    </details>
    """


def render_dashboard(actor, users, roles, permissions, logs, backup_admin, certificate_history, notice: str | None = None, error: str | None = None, beneficiarios=None, notifications=None, section: str = "usuarios") -> str:
    _name_parts = actor.full_name.split()
    _initials = (_name_parts[0][0] + (_name_parts[-1][0] if len(_name_parts) > 1 else "")).upper()
    permission_text = ", ".join(f"{item['resource']}:{item['action']}" for item in permissions) or "sin permisos"
    actor_options = "".join(
        f"<option value='{user.id}'>{escape(user.full_name)} ({escape(user.role.name)})</option>"
        for user in users
    )
    create_role_options = "".join(f"<option value='{role.id}'>{escape(role.name)}</option>" for role in roles)
    role_filter_options = "".join(
        f"<option value='{escape(role.code)}'>{escape(role.name)}</option>"
        for role in roles
    )

    can_create = any(item["resource"] == "users" and item["action"] == "create" for item in permissions)
    can_activate = any(item["resource"] == "users" and item["action"] == "activate" for item in permissions)
    can_revoke = any(item["resource"] == "users" and item["action"] == "revoke" for item in permissions)
    can_change_role = any(item["resource"] == "users" and item["action"] == "change_role" for item in permissions)
    can_change_expiration = any(
        item["resource"] == "users" and item["action"] == "change_expiration" for item in permissions
    )
    can_activate_mirror = any(
        item["resource"] == "admin_recovery" and item["action"] == "activate" for item in permissions
    )
    user_name_lookup = {user.id: user.full_name for user in users}
    if backup_admin:
        user_name_lookup[backup_admin.id] = backup_admin.full_name

    user_rows = []
    for user in users:
        user_uses_crypto = role_requires_crypto(user)
        activation_form = "<span class='muted'>Sin cambios pendientes</span>"
        if can_activate and user.status in {"pending", "revoked"}:
            needs_new_secret = (user_uses_crypto and (user.status == "revoked" or not user.certificate_serial)) or (not user_uses_crypto and not user.password_hash)
            if needs_new_secret:
                if user_uses_crypto:
                    secret_field = f"""
                    <div>
                      <label style="font-size:12px;font-weight:600;color:var(--muted);display:block;margin-bottom:4px;">
                        Contrase&ntilde;a para proteger los archivos de acceso
                      </label>
                      <input type="password" name="new_secret" id="activate-secret-{user.id}" placeholder="Contrase&ntilde;a de protecci&oacute;n"
                        style="width:100%;" required>
                      <p style="font-size:11px;color:var(--muted);margin-top:4px;">
                        Se generar&aacute;n archivos de acceso y certificado de identidad para este usuario.
                      </p>
                    </div>
                    """
                else:
                    secret_field = f"""
                    <div>
                      <label style="font-size:12px;font-weight:600;color:var(--muted);display:block;margin-bottom:4px;">
                        Nueva contrase&ntilde;a de acceso
                      </label>
                      <input type="password" name="new_secret" id="activate-secret-{user.id}" placeholder="Contrase&ntilde;a que usar&aacute; el usuario para entrar"
                        style="width:100%;" required>
                    </div>
                    """
            else:
                secret_field = ""
            activation_form = f"""
            <form method="post" action="/ui/users/{user.id}/status" class="inline-form">

              <input type="hidden" name="status" value="active">
              <input type="hidden" name="role_id" value="{user.role_id}" id="activate-role-{user.id}">
              {secret_field}
              <button type="submit">Activar</button>
            </form>
            """

        revoke_form = "<span class='muted'>Sin accion</span>"
        if can_revoke and user.status != "revoked":
            revoke_form = f"""
            <form method="post" action="/ui/users/{user.id}/status" class="inline-form" style="margin-top:12px;">

              <input type="hidden" name="status" value="revoked">
              <button type="submit" class="danger-button">Revocar de emergencia</button>
            </form>
            """

        expiration_text = (
            escape(user.end_date.isoformat(sep=" ", timespec="minutes"))
            if user.end_date
            else "sin vencimiento"
        )
        expiration_form = "<span class='muted'>Sin permiso</span>"
        if can_change_expiration:
            if user_uses_crypto:
                # Crypto users: expiration is sealed in the X.509 certificate.
                # Display it as read-only info; editing is not allowed.
                expiration_form = f"""
                <div style="font-size:12px;color:var(--muted);padding:8px 10px;background:var(--surface-2);border:1px solid var(--border);border-radius:8px;">
                  <p style="font-weight:600;margin-bottom:3px;">Fecha sellada en el certificado</p>
                  <p>La vigencia de este usuario est&aacute; fijada en su certificado de identidad y no puede modificarse directamente. Para extender el acceso, revocar la cuenta y generar nuevas credenciales desde la secci&oacute;n <strong>Credenciales</strong>.</p>
                </div>
                """
            else:
                expiration_value = user.end_date.strftime("%Y-%m-%dT%H:%M") if user.end_date else ""
                expiration_form = f"""
                <form method="post" action="/ui/users/{user.id}/expiration" class="inline-form">

                  <input type="datetime-local" name="end_date" value="{expiration_value}" required>
                  <button type="submit">Guardar vigencia</button>
                </form>
                """

        role_form = "<span class='muted'>Rol fijo</span>"
        if can_change_role:
            role_form = f"""
            <form method="post" action="/ui/users/{user.id}/role" class="inline-form">

              <select name="role_id" onchange="var h=document.getElementById('activate-role-{user.id}');if(h)h.value=this.value;var opt=this.options[this.selectedIndex];var cr=opt.getAttribute('data-crypto')==='1';var pw=document.getElementById('role-secret-{user.id}');if(pw){{pw.style.display=cr?'':'none';pw.required=cr;if(!cr)pw.value='';}}var a=document.getElementById('activate-secret-{user.id}');if(pw&&a)a.value=pw.value;">
                {''.join(f"<option value='{role.id}' data-crypto='{'1' if role.code in ('ADMIN','COORDINADOR') else '0'}' {'selected' if role.id == user.role_id else ''}>{escape(role.name)}</option>" for role in roles)}
              </select>
              <input type="password" name="new_secret" id="role-secret-{user.id}" placeholder="Contrase&ntilde;a nueva (d&aacute;sela al usuario)" style="display:{'none' if not user_uses_crypto else ''}" {'required' if user_uses_crypto else ''} oninput="var a=document.getElementById('activate-secret-{user.id}');if(a)a.value=this.value;">
              <button type="submit">Guardar rol</button>
            </form>
            """

        account_note = "Acceso vigente"
        if user.login_locked_until:
            account_note = "Acceso bloqueado por demasiados intentos fallidos de inicio de sesión."
        elif user.status == "revoked":
            account_note = (
                "El acceso fue bloqueado de inmediato. Al reactivar, se recomienda generar nuevas credenciales."
                if user_uses_crypto
                else "La revocación borra la contraseña almacenada y obliga a definir una nueva para reactivar."
            )
        elif user.status == "pending":
            account_note = "La cuenta existe pero todavia no puede entrar."
        elif user.status == "expired":
            account_note = "Actualiza la vigencia para que la cuenta vuelva a active."

        certificate_section = "<p class='muted'>Acceso solo con usuario y contrasena.</p>"
        if user_uses_crypto:
            missing_explicit_artifacts = not user.certificate_pem or not CertificateService.get_user_public_key_pem(user)
            certificate_section = _render_crypto_flow(
                user,
                actor.id,
                issuer_name=user_name_lookup.get(user.certificate_issuer_user_id),
            )
            if not user.certificate_serial or missing_explicit_artifacts:
                if not needs_new_secret:
                    action_label = "Generar credenciales" if not user.certificate_serial else "Renovar credenciales"
                    certificate_section += f"""
                    <form method="post" action="/ui/users/{user.id}/certificate" class="inline-form" style="margin-top:10px;">
                      <input type="password" name="credential_secret" placeholder="Contrase&ntilde;a de protecci&oacute;n" required>
                      <button type="submit">{action_label}</button>
                    </form>
                    """
                else:
                    certificate_section += """
                    <p class="muted" style="margin-top:8px;">Las credenciales se generar&aacute;n autom&aacute;ticamente al activar la cuenta.</p>
                    """
            else:
                certificate_section += """
                <p class="muted" style="margin-top:8px;">Credenciales listas para entregar al usuario.</p>
                """

        summary_expiration = expiration_text
        row_hint = "Acceso con archivos" if user_uses_crypto else "Acceso con contrase&ntilde;a"
        unlock_form = ""
        if user.login_locked_until:
            unlock_form = f"""
            <form method="post" action="/ui/users/{user.id}/unlock" class="inline-form" style="margin-top:8px;">
              <button type="submit" style="background:#d97706;">Desbloquear cuenta</button>
            </form>
            """

        user_rows.append(
            f"""
            <details class="user-row" data-id="{user.id}" data-name="{escape(user.full_name)}" data-email="{escape(user.email)}" data-role="{escape(user.role.code)}" data-status="{escape(user.status)}">
              <summary class="user-row-summary">
                <span class="summary-name">
                  <strong>{escape(user.full_name)}</strong>
                  <small>{escape(user.email)}</small>
                </span>
                <span>{escape(user.role.name)}</span>
                <span class="status status-{escape(user.status)}">{escape(user.status)}</span>
                <span>{summary_expiration}</span>
                <span class="muted">{row_hint}</span>
                <span class="summary-button">Gestionar</span>
              </summary>
              <div class="user-row-body">
                <section class="control-panel">
                  <h4>Cuenta</h4>
                  <p class="muted">{escape(account_note)}</p>
                  {activation_form}
                  {revoke_form}
                  {unlock_form}
                </section>
                <section class="control-panel">
                  <h4>Vigencia</h4>
                  {expiration_form}
                </section>
                <section class="control-panel">
                  <h4>Rol</h4>
                  {role_form}
                </section>
                <section class="control-panel">
                  <h4>{'Credenciales' if user_uses_crypto else 'Acceso'}</h4>
                  {certificate_section}
                </section>
              </div>
            </details>
            """
        )

    create_form = ""
    if can_create:
        create_form = f"""
          <details class="collapsible-panel" id="alta">
          <summary><h2>Alta de usuario</h2><span class="summary-button">Abrir</span></summary>
          <form method="post" action="/ui/users" class="panel-body" style="padding:16px 20px 20px;">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <label>Nombre completo<input name="full_name" placeholder="Nombre Apellido" required></label>
              <label>Correo electr&oacute;nico<input name="email" type="email" placeholder="correo@ejemplo.com" required></label>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <label>Rol<select name="role_id">{create_role_options}</select></label>
              <label>Fecha de expiraci&oacute;n<input name="end_date" type="datetime-local"></label>
            </div>
            <label>
              Contrase&ntilde;a inicial
              <span class="muted" style="font-weight:400;font-size:12px;margin-top:-2px;">Para roles con archivos de acceso, esta clave los protege al descargarlos</span>
              <input name="credential_secret" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
            </label>
            <div><button type="submit" style="margin-top:4px;">Crear usuario</button></div>
          </form>
        </details>
        """

    backup_section = "<p class='muted'>Sin respaldo espejo disponible.</p>"
    if backup_admin:
        activate_button = ""
        if can_activate_mirror and backup_admin.status != "active":
            activate_button = f"""
            <form method="post" action="/ui/admin/recovery/activate-mirror" class="inline-form">

              <button type="submit">Activar espejo</button>
            </form>
            """
        backup_section = f"""
        <div class="stack">
          <p><strong>{escape(backup_admin.full_name)}</strong><br>{escape(backup_admin.email)}</p>
          <p>Estado: <span class="status status-{escape(backup_admin.status)}">{escape(backup_admin.status)}</span></p>
          <p class="muted">Contrasena demo documentada por separado. No se sincroniza con la cuenta principal.</p>
          {activate_button}
        </div>
        """

    certificate_rows = "".join(
        f"""
        <li>
          <strong>{escape(user.full_name)}</strong> · {escape(user.role.name)} · {escape('Autofirmado' if user.role.code == 'ADMIN' else user_name_lookup.get(user.certificate_issuer_user_id, 'Administrador firmante'))} ·
          <a href="/ui/users/{user.id}/certificate/view?as_user={actor.id}">ver certificado</a> ·
          {_crypto_file_state(user, actor.id)}
        </li>
        """
        for user in certificate_history
    ) or "<li>No hay certificados legacy registrados.</li>"

    log_items = "\n".join(
        f"<li style='padding:6px 0;border-bottom:1px solid var(--border);'><strong style='color:var(--text);'>{escape(log.event_type)}</strong> &middot; <span class='muted'>{escape(log.result)}</span> &middot; objetivo {log.target_user_id or '-'}"
        + (f" &middot; <span style='font-size:11px;color:var(--muted);'>{escape(log.ip_address)}</span>" if log.ip_address else "")
        + (f" &middot; <span style='font-size:11px;color:var(--muted);' title='{escape(log.user_agent or '')}'>{escape((log.user_agent or '')[:40])}{'…' if log.user_agent and len(log.user_agent) > 40 else ''}</span>" if log.user_agent else "")
        + "</li>"
        for log in logs
    ) or "<li>Sin eventos todav&iacute;a.</li>"

    _notif_icons = {
        "recovery_request": "&#128273;",
        "cert_expiring_soon": "&#9888;",
        "login_blocked": "&#128274;",
    }
    _notif_labels = {
        "recovery_request": "Recuperaci&oacute;n",
        "cert_expiring_soon": "Expiraci&oacute;n",
        "login_blocked": "Cuenta bloqueada",
    }
    notif_list = notifications or []
    unread_count = sum(1 for n in notif_list if not n.is_read)
    badge = f" <span style='background:var(--bad);color:#fff;border-radius:999px;padding:1px 7px;font-size:11px;font-weight:700;margin-left:6px;'>{unread_count}</span>" if unread_count else ""
    notif_rows = ""
    for n in notif_list:
        icon = _notif_icons.get(n.type, "&#8226;")
        label = _notif_labels.get(n.type, escape(n.type))
        read_style = "" if not n.is_read else "opacity:.55;"
        notif_rows += f"""
        <div style="{read_style}display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:start;padding:12px 0;border-bottom:1px solid var(--border);">
          <span style="font-size:18px;line-height:1;">{icon}</span>
          <div>
            <p style="font-weight:600;font-size:13px;margin-bottom:2px;">{escape(n.title)}</p>
            <p style="font-size:12px;color:var(--muted);">{escape(n.message)}</p>
            <p style="font-size:11px;color:var(--muted);margin-top:4px;">
              <span style="background:var(--surface-2);border:1px solid var(--border);border-radius:4px;padding:1px 6px;">{label}</span>
              &nbsp;{escape(n.created_at.strftime('%Y-%m-%d %H:%M'))}
            </p>
          </div>
          {"<span style='font-size:11px;color:var(--muted);'>Atendida</span>" if n.is_read else f"<form method='post' action='/ui/notifications/{n.id}/read'><button type='submit' style='font-size:11px;padding:4px 10px;background:var(--surface-2);color:var(--text);border:1px solid var(--border);'>Marcar atendida</button></form>"}
        </div>"""
    if not notif_rows:
        notif_rows = "<p class='muted' style='padding:12px 0;'>Sin notificaciones pendientes.</p>"
    notifications_section = f"""
    <details class="collapsible-panel" id="notifications">
      <summary><h2>Notificaciones{badge}</h2><span class="summary-button">Abrir</span></summary>
      <div class="panel-body" style="padding:10px 20px 20px;">
        {f"<div style='text-align:right;margin-bottom:10px;'><form method='post' action='/ui/notifications/read-all'><button type='submit' style='background:#e06020;color:#fff;border:none;padding:8px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;'>Marcar todas atendidas</button></form></div>" if unread_count else ""}
        {notif_rows}
      </div>
    </details>
    """

    # ── Section content builder ─────────────────────────────────────────────
    _base_url = f"/dashboard?as_user={actor.id}&section="

    def _sec_hdr(title, subtitle="", extra_btn=""):
        sub_p = f'<p style="color:var(--muted);font-size:14px;margin-top:2px;">{subtitle}</p>' if subtitle else ""
        return f"""
        <section style="margin-bottom:24px;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:20px;flex-wrap:wrap;">
            <div>
              <h1 class="page-title">{title}</h1>
              <div class="page-title-accent"></div>
              {sub_p}
            </div>
            {extra_btn}
          </div>
          {render_notice(notice)}
          {f"<div class='error' style='background:#fee2e2;border:1px solid #fca5a5;color:#991b1b;border-radius:10px;padding:10px 14px;font-size:13px;margin-bottom:14px;'>{escape(error)}</div>" if error else ""}
        </section>"""

    _new_user_btn = f'<a href="/admin/register?as_user={actor.id}" style="display:inline-block;background:var(--accent);color:#fff;padding:8px 16px;border-radius:var(--radius);font-size:13px;font-weight:600;text-decoration:none;">+ Nuevo usuario</a>'
    _export_btn_style = "display:inline-flex;align-items:center;gap:6px;background:#4b5563;color:#fff;padding:8px 16px;border-radius:var(--radius);font-size:13px;font-weight:600;text-decoration:none;"
    _export_users_btn = f'<a href="/ui/users/export.pdf" style="{_export_btn_style}">&#8595; Exportar PDF</a>'
    _export_audit_btn = f'<a href="/ui/audit-logs/export.pdf" style="{_export_btn_style}">&#8595; Exportar PDF</a>'
    _usuarios_header_btns = f'<div style="display:flex;gap:8px;flex-wrap:wrap;">{_new_user_btn}{_export_users_btn}</div>'

    # ── USUARIOS section ────────────────────────────────────────────────────
    _usuarios_content = f"""
    {_sec_hdr("Gestión de usuarios", "Casa Monarca — Control de identidades y accesos del equipo operativo", _usuarios_header_btns)}
    <div class="grid">
      <div class="stat-card">
        <div class="stat-number">{len(users)}</div>
        <div class="stat-label">Usuarios totales</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{len(roles)}</div>
        <div class="stat-label">Roles definidos</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{len(logs)}</div>
        <div class="stat-label">Eventos de auditor&iacute;a</div>
      </div>
      <div class="panel">
        <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:8px;">Ver portal como</p>
        <form method="get" action="/portal" style="display:flex;gap:8px;">
          <select name="as_user" style="flex:1;">{actor_options}</select>
          <button type="submit" style="white-space:nowrap;padding:8px 14px;font-size:13px;">Abrir</button>
        </form>
      </div>
    </div>
    <div class="card" id="usuarios" style="overflow:hidden;">
      <div class="filter-bar">
        <div style="position:relative;">
          <svg style="position:absolute;left:10px;top:50%;transform:translateY(-50%);pointer-events:none;color:var(--muted);" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input id="filter-search" type="search" placeholder="Buscar por nombre o correo..." oninput="filterUsers()" style="padding-left:32px;">
        </div>
        <select id="filter-role" onchange="filterUsers()" style="width:auto;min-width:160px;">
          <option value="">Todos los roles</option>
          {role_filter_options}
        </select>
        <select id="filter-status" onchange="filterUsers()" style="width:auto;min-width:150px;">
          <option value="">Todos los estados</option>
          <option value="active">Activo</option>
          <option value="pending">Pendiente</option>
          <option value="revoked">Revocado</option>
          <option value="expired">Expirado</option>
        </select>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:14px 20px 8px;">
        <h2>Usuarios</h2>
        <span id="filter-count" class="muted" style="font-size:12px;"></span>
      </div>
      <div class="users-list" style="padding:0 12px 16px 12px;">
        <div id="no-results" style="display:none;text-align:center;padding:32px 20px;color:var(--muted);"><p>No se encontraron usuarios con esos filtros.</p></div>
        {''.join(user_rows)}
      </div>
    </div>
    """

    # ── ALTA section ────────────────────────────────────────────────────────
    _alta_form_body = ""
    if can_create:
        _alta_form_body = f"""
        <div class="card" style="padding:24px;">
          <form method="post" action="/ui/users" style="display:flex;flex-direction:column;gap:12px;">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <label>Nombre completo<input name="full_name" placeholder="Nombre Apellido" required></label>
              <label>Correo electr&oacute;nico<input name="email" type="email" placeholder="correo@ejemplo.com" required></label>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <label>Rol<select name="role_id">{create_role_options}</select></label>
              <label>Fecha de expiraci&oacute;n<input name="end_date" type="datetime-local"></label>
            </div>
            <label>
              Contrase&ntilde;a inicial
              <span class="muted" style="font-weight:400;font-size:12px;margin-top:-2px;">Para roles con archivos de acceso, esta clave los protege al descargarlos</span>
              <input name="credential_secret" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
            </label>
            <div><button type="submit" style="margin-top:4px;">Crear usuario</button></div>
          </form>
        </div>"""
    else:
        _alta_form_body = "<div class='error'>No tienes permiso para crear usuarios.</div>"

    _alta_content = f"""
    {_sec_hdr("Alta de usuario", "Crea un nuevo usuario en el sistema.")}
    {_alta_form_body}
    """

    # ── AUDITORÍA section ───────────────────────────────────────────────────
    _auditoria_content = f"""
    {_sec_hdr("Auditor&iacute;a", f"{len(logs)} eventos registrados", _export_audit_btn)}
    <div class="card" style="padding:20px 24px;">
      <ul style="font-size:13px;">{log_items}</ul>
    </div>
    """

    # ── NOTIFICACIONES section ──────────────────────────────────────────────
    _notif_badge_text = f"{unread_count} sin atender" if unread_count else "Sin notificaciones pendientes"
    _notif_content = f"""
    {_sec_hdr("Notificaciones", _notif_badge_text)}
    <div class="card" style="padding:10px 24px 24px;">
      {notif_rows}
    </div>
    """

    # ── BENEFICIARIOS section ───────────────────────────────────────────────
    _bens = beneficiarios or []
    _bens_activos = len([b for b in _bens if b.status == "activo"])
    _bens_revision = len([b for b in _bens if b.status == "en_revision"])
    _bens_nuevos = len([b for b in _bens if b.status == "nuevo"])
    STATUS_LABELS_B = {"nuevo": "Nuevo", "en_revision": "En revisión", "canalizado": "Canalizado", "activo": "Activo"}
    STATUS_CSS_B = {"nuevo": "pending", "en_revision": "pending", "canalizado": "active", "activo": "active"}
    AREA_LABELS_B = {"ADMINISTRACION": "Administración", "LEGAL": "Legal", "PSICOSOCIAL": "Psicosocial", "HUMANITARIO": "Humanitario", "COMUNICACION": "Comunicación"}
    STATUS_OPTIONS_B = [("nuevo","Nuevo"),("en_revision","En revisión"),("canalizado","Canalizado"),("activo","Activo")]
    def _opts_b(cur):
        return "".join(f'<option value="{v}"{" selected" if v == cur else ""}>{lbl}</option>' for v,lbl in STATUS_OPTIONS_B)
    _bens_rows = "".join(
        f"""<div style="display:flex;align-items:center;gap:12px;padding:11px 14px;background:#fff;border-bottom:1px solid #e5ddd3;flex-wrap:wrap;">
          <div style="flex:1;min-width:160px;">
            <p style="font-weight:600;font-size:13px;color:#1a2332;">{escape(b.nombre_completo)}</p>
            <p style="font-size:12px;color:#6b7280;">{escape(b.pais_origen)} &middot; {b.fecha_ingreso.strftime('%d/%m/%Y')} &middot; {escape(AREA_LABELS_B.get(b.area, b.area))}</p>
            {f'<p style="font-size:11px;color:#6b7280;margin-top:3px;font-style:italic;">{escape(b.notas[:80])}</p>' if b.notas else ''}
          </div>
          <span class="status status-{STATUS_CSS_B[b.status]}">{STATUS_LABELS_B[b.status]}</span>
          <form method="post" action="/ui/beneficiarios/{b.id}/status" style="display:flex;gap:6px;align-items:center;">
            <select name="new_status" style="font-size:12px;padding:4px 8px;border-radius:7px;border:1px solid #cfc4b5;background:#fff;color:#1a2332;">{_opts_b(b.status)}</select>
            <button type="submit" style="background:var(--accent);color:#fff;padding:5px 10px;font-size:12px;border-radius:7px;cursor:pointer;border:none;">Guardar</button>
          </form>
          <form method="post" action="/ui/beneficiarios/{b.id}/delete" style="margin:0;">
            <button type="submit" onclick="return confirm('\u00bfEliminar este registro?')" style="background:none;border:1px solid #fca5a5;color:#dc2626;padding:5px 10px;border-radius:7px;font-size:12px;cursor:pointer;font-weight:500;">Eliminar</button>
          </form>
        </div>"""
        for b in _bens
    )
    _export_bens_btn = f'<a href="/ui/beneficiarios/export.pdf" style="{_export_btn_style}">&#8595; Exportar PDF</a>'
    _beneficiarios_content = f"""
    {_sec_hdr("Beneficiarios", f"{len(_bens)} registros &mdash; {_bens_activos} activos", _export_bens_btn)}
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:18px;">
      <div style="padding:14px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;"><p style="font-size:24px;font-weight:700;color:#1a2332;line-height:1;">{_bens_activos}</p><p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">Activos</p></div>
      <div style="padding:14px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;"><p style="font-size:24px;font-weight:700;color:#1a2332;line-height:1;">{len(_bens)}</p><p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">Total</p></div>
      <div style="padding:14px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;"><p style="font-size:24px;font-weight:700;color:#1a2332;line-height:1;">{_bens_revision}</p><p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">En revisi&oacute;n</p></div>
      <div style="padding:14px;background:#fff;border:1px solid #e5ddd3;border-radius:10px;"><p style="font-size:24px;font-weight:700;color:#1a2332;line-height:1;">{_bens_nuevos}</p><p style="font-size:11px;font-weight:600;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.05em;">Nuevos</p></div>
    </div>
    <div class="card" style="padding:0;overflow:hidden;margin-bottom:18px;">
      <div style="padding:18px 24px;border-bottom:1px solid #e5ddd3;display:flex;justify-content:space-between;align-items:flex-start;">
        <div>
          <h2 style="font-size:16px;font-weight:700;color:#1a2332;margin:0;">Registrar beneficiario</h2>
          <p style="font-size:13px;color:#6b7280;margin-top:3px;">Captura los datos del beneficiario. El registro queda visible para el coordinador del &aacute;rea.</p>
        </div>
      </div>
      <div style="padding:20px 24px;">
        <form method="post" action="/ui/beneficiarios">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px;">
            <label style="display:flex;flex-direction:column;gap:5px;">Nombre completo
              <input name="nombre_completo" placeholder="Apellido Apellido, Nombre" required>
            </label>
            <label style="display:flex;flex-direction:column;gap:5px;">Pa&iacute;s de origen
              <input name="pais_origen" placeholder="Honduras, Guatemala, Venezuela...">
            </label>
            <label style="display:flex;flex-direction:column;gap:5px;">&Aacute;rea de atenci&oacute;n
              <select name="area" required>
                <option value="">-- Selecciona --</option>
                <option value="PSICOSOCIAL">Psicosocial</option>
                <option value="LEGAL">Legal</option>
                <option value="HUMANITARIO">Humanitario</option>
                <option value="ADMINISTRACION">Administraci&oacute;n</option>
                <option value="COMUNICACION">Comunicaci&oacute;n</option>
              </select>
            </label>
            <label style="display:flex;flex-direction:column;gap:5px;">Notas (opcional)
              <input name="notas" placeholder="Situaci&oacute;n general, motivo de solicitud...">
            </label>
          </div>
          <button type="submit">Registrar beneficiario</button>
        </form>
      </div>
    </div>
    <div class="card" style="overflow:hidden;">
      {_bens_rows or '<p style="padding:14px;font-size:13px;color:#6b7280;">Sin registros a&uacute;n.</p>'}
    </div>
    """

    # ── HISTORIAL section ───────────────────────────────────────────────────
    _backup_card = f"""
    <div class="card" style="padding:24px;margin-top:16px;">
      <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:12px;">Recuperaci&oacute;n de administrador</p>
      {backup_section}
    </div>"""
    _historial_content = f"""
    {_sec_hdr("Historial de credenciales")}
    <div class="card" style="padding:20px 24px;">
      <p class="muted" style="margin-bottom:12px;">Los administradores validan la identidad de coordinadores. Administradores y Coordinadores usan archivos de acceso para entrar.</p>
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px;">
        <a href="/ui/ca/certificate/view?as_user={actor.id}">Ver certificado del administrador</a>
        <a href="/ui/ca/certificate?as_user={actor.id}">Descargar certificado (.pem)</a>
      </div>
      <ul style="font-size:13px;">{certificate_rows}</ul>
    </div>
    {_backup_card}
    """

    # ── Section selector ────────────────────────────────────────────────────
    _section_map = {
        "usuarios": _usuarios_content,
        "alta": _alta_content,
        "auditoria": _auditoria_content,
        "notificaciones": _notif_content,
        "beneficiarios": _beneficiarios_content,
        "historial": _historial_content,
    }
    section_main = _section_map.get(section, _usuarios_content)

    # ── Active section helper ───────────────────────────────────────────────
    def _slink(sec, label, icon_svg):
        cls = "sidebar-link active" if section == sec else "sidebar-link"
        href = f"/dashboard?as_user={actor.id}&section={sec}"
        return f'<a href="{href}" class="{cls}">{icon_svg}{label}</a>'

    return f"""
    <!doctype html>
    <html lang="es">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{escape(settings.app_name)}</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
          :root {{
            --bg: #f6f2ec;
            --surface: #ffffff;
            --surface-2: #faf7f3;
            --border: #e5ddd3;
            --border-strong: #cfc4b5;
            --text: #1a2332;
            --muted: #6b7280;
            --accent: #e06020;
            --accent-dark: #bf4f10;
            --accent-light: #fff3eb;
            --ok: #166534;
            --ok-bg: #dcfce7;
            --ok-border: #86efac;
            --warn: #92400e;
            --warn-bg: #fef3c7;
            --warn-border: #fcd34d;
            --bad: #991b1b;
            --bad-bg: #fee2e2;
            --bad-border: #fca5a5;
            --radius: 10px;
            --radius-lg: 14px;
            --shadow: 0 1px 3px rgba(0,0,0,0.06), 0 4px 16px rgba(0,0,0,0.05);
          }}
          *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
          body {{ background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 15px; line-height: 1.6; -webkit-font-smoothing: antialiased; display: flex; min-height: 100vh; }}
          /* ── Sidebar ── */
          .sidebar {{ width:290px; flex-shrink:0; background:#1a2332; display:flex; flex-direction:column; position:fixed; top:0; left:0; bottom:0; z-index:100; overflow-y:auto; overflow-x:hidden; }}
          .sidebar-brand {{ padding:22px 20px 18px; border-bottom:1px solid rgba(255,255,255,0.07); }}
          .sidebar-brand-logo {{ display:flex; align-items:center; gap:10px; margin-bottom:6px; }}
          .sidebar-brand-text {{ line-height:1.2; }}
          .sidebar-brand-name {{ font-size:17px; font-weight:800; color:#fff; letter-spacing:-0.3px; }}
          .sidebar-brand-sub {{ font-size:10px; color:#8b9ab0; text-transform:uppercase; letter-spacing:.08em; font-weight:500; }}
          .sidebar-tagline {{ font-size:11px; color:#8b9ab0; line-height:1.4; margin-top:6px; }}
          .sidebar-nav {{ flex:1; padding:16px 12px; display:flex; flex-direction:column; gap:2px; }}
          .sidebar-section-label {{ font-size:11px; font-weight:700; color:#8b9ab0; text-transform:uppercase; letter-spacing:.1em; padding:10px 8px 4px; margin-top:6px; }}
          .sidebar-link {{ display:flex; align-items:center; gap:9px; padding:8px 10px; border-radius:8px; color:#e8e4de; font-size:15px; font-weight:500; text-decoration:none; transition:background .15s; border-left:2px solid transparent; }}
          .sidebar-link:hover {{ background:rgba(255,255,255,0.07); color:#fff; text-decoration:none; }}
          .sidebar-link.active {{ background:rgba(224,96,32,0.18); border-left-color:#e06020; color:#fff; }}
          .sidebar-link svg {{ flex-shrink:0; opacity:.7; }}
          .sidebar-link.active svg {{ opacity:1; }}
          .sidebar-footer {{ padding:16px 12px; border-top:1px solid rgba(255,255,255,0.07); position:relative; }}
          .sidebar-logout {{ display:flex; align-items:center; gap:8px; color:#8b9ab0; font-size:13px; font-weight:500; text-decoration:none; padding:6px 8px; border-radius:7px; transition:color .15s,background .15s; }}
          .sidebar-logout:hover {{ color:#fff; background:rgba(255,255,255,0.07); text-decoration:none; }}
          .sidebar-user {{ padding:14px 16px 0; display:flex; align-items:center; gap:10px; }}
          .sidebar-avatar {{ width:36px; height:36px; border-radius:50%; background:rgba(224,96,32,0.25); color:#e06020; font-size:13px; font-weight:700; display:flex; align-items:center; justify-content:center; flex-shrink:0; letter-spacing:-0.5px; }}
          .sidebar-user-info {{ min-width:0; }}
          .sidebar-user-name {{ font-size:15px; font-weight:600; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
          .sidebar-user-role {{ font-size:11px; color:#8b9ab0; margin-top:2px; }}
          /* ── Watermarks ── */
          .page-bg-watermark {{ position:fixed; top:-60px; right:-80px; width:900px; pointer-events:none; opacity:0.15; z-index:0; }}
          .page-bg-watermark-2 {{ position:fixed; bottom:-80px; right:-60px; width:700px; pointer-events:none; opacity:0.11; z-index:0; transform:rotate(-15deg); }}
          .sidebar-watermark {{ position:absolute; bottom:40px; right:-40px; width:310px; pointer-events:none; opacity:0.12; transform:scaleX(-1) rotate(20deg); }}
          /* ── Page title ── */
          .page-title {{ font-size:30px; font-weight:800; letter-spacing:-0.6px; }}
          .page-title-accent {{ width:42px; height:3px; background:var(--accent); margin-top:6px; }}
          /* ── Page wrapper ── */
          .page-wrapper {{ margin-left:290px; flex:1; min-width:0; position:relative; z-index:1; }}
          main {{ max-width:1400px; margin:0 auto; padding:36px 48px 80px; display:flex; flex-direction:column; gap:18px; z-index:1; }}
          .card, .panel {{ position:relative; z-index:2; }}
          .hero {{ position:relative; z-index:2; }}
          @media (max-width:700px) {{ .sidebar {{ display:none; }} .page-wrapper {{ margin-left:0; }} }}
          h1 {{ font-size: 22px; font-weight: 700; letter-spacing: -0.3px; line-height: 1.3; }}
          h2 {{ font-size: 16px; font-weight: 600; letter-spacing: -0.1px; line-height: 1.4; }}
          p {{ margin: 0; }}
          .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); }}
          .panel {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); padding: 20px; }}
          .hero {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); padding: 24px 28px; }}
          .grid {{ display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }}
          .stack {{ display: flex; flex-direction: column; gap: 10px; }}
          label {{ display: flex; flex-direction: column; gap: 5px; font-size: 14px; font-weight: 500; }}
          input, select {{ font: inherit; font-size: 15px; padding: 8px 11px; border-radius: var(--radius); border: 1px solid var(--border-strong); background: var(--surface); color: var(--text); transition: border-color .15s, box-shadow .15s; outline: none; width: 100%; }}
          input:focus, select:focus {{ border-color: var(--accent); box-shadow: 0 0 0 3px rgba(224,96,32,0.12); }}
          input[type="file"] {{ padding: 6px 10px; cursor: pointer; background: var(--surface-2); }}
          button {{ font: inherit; font-size: 14px; font-weight: 600; padding: 8px 16px; border-radius: var(--radius); border: none; cursor: pointer; transition: background .15s; background: var(--accent); color: #fff; }}
          button:hover {{ background: var(--accent-dark); }}
          .danger-button {{ background: #dc2626 !important; }}
          .danger-button:hover {{ background: #b91c1c !important; }}
          a {{ color: var(--accent); font-weight: 500; text-decoration: none; }}
          a:hover {{ text-decoration: underline; }}
          .status {{ display: inline-flex; align-items: center; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; border: 1px solid; }}
          .status-active {{ background: var(--ok-bg); color: var(--ok); border-color: var(--ok-border); }}
          .status-pending {{ background: var(--warn-bg); color: var(--warn); border-color: var(--warn-border); }}
          .status-revoked, .status-expired {{ background: var(--bad-bg); color: var(--bad); border-color: var(--bad-border); }}
          .ok {{ background: var(--ok-bg); border: 1px solid var(--ok-border); color: var(--ok); border-radius: var(--radius); padding: 10px 14px; font-size: 13px; margin-bottom: 8px; }}
          .inline-form {{ display: flex; flex-direction: column; gap: 8px; }}
          .users-list {{ display: flex; flex-direction: column; gap: 6px; }}
          .user-row {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; transition: border-color .15s; }}
          .user-row:hover {{ border-color: var(--border-strong); }}
          .collapsible-panel {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; box-shadow: var(--shadow); }}
          .user-row-summary {{ list-style: none; cursor: pointer; display: grid; gap: 12px; align-items: center; padding: 13px 18px; grid-template-columns: minmax(180px, 2.5fr) minmax(100px, 1fr) auto minmax(120px, 1fr) minmax(130px, 1fr) auto; }}
          .user-row-summary::-webkit-details-marker {{ display: none; }}
          .collapsible-panel > summary {{ list-style: none; cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; }}
          .collapsible-panel > summary::-webkit-details-marker {{ display: none; }}
          .summary-name {{ display: flex; flex-direction: column; gap: 2px; min-width: 0; }}
          .summary-name strong {{ font-size: 15px; font-weight: 600; }}
          .summary-name small {{ font-size: 13px; color: var(--muted); overflow-wrap: anywhere; }}
          .summary-button {{ background: var(--accent-light); color: var(--accent); border-radius: 999px; padding: 5px 12px; font-size: 12px; font-weight: 600; white-space: nowrap; border: 1px solid #f0d4c5; }}
          .user-row-body {{ display: grid; gap: 1px; background: var(--border); border-top: 1px solid var(--border); grid-template-columns: repeat(4, minmax(0, 1fr)); }}
          .control-panel {{ background: var(--surface-2); padding: 16px; min-width: 0; }}
          .control-panel h4 {{ font-size: 11px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); margin-bottom: 10px; }}
          .panel-body {{ padding: 0 20px 20px; display: flex; flex-direction: column; gap: 10px; }}
          .muted {{ color: var(--muted); font-size: 13px; }}
          .mini-links {{ display: flex; flex-wrap: wrap; gap: 10px; }}
          .crypto-flow {{ display: flex; flex-direction: column; border-top: 1px solid var(--border); }}
          .crypto-row {{ display: grid; grid-template-columns: 126px 1fr; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--border); }}
          .crypto-step-name {{ font-size: 11px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); }}
          .crypto-step-body {{ display: flex; flex-direction: column; gap: 4px; min-width: 0; }}
          .crypto-step-main {{ font-size: 13px; color: var(--text); display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
          .crypto-step-meta {{ font-size: 12px; color: var(--muted); display: flex; gap: 10px; flex-wrap: wrap; }}
          .crypto-pill {{ display: inline-flex; align-items: center; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; border: 1px solid; }}
          .crypto-pill-ok {{ background: var(--ok-bg); color: var(--ok); border-color: var(--ok-border); }}
          .crypto-missing {{ color: var(--muted); font-size: 12px; }}
          .crypto-once {{ color: var(--warn); font-size: 11px; font-weight: 600; }}
          .crypto-delivered {{ color: var(--muted); font-size: 12px; }}
          ul {{ margin: 0; padding-left: 18px; }}
          li {{ margin-bottom: 4px; }}
          code {{ background: var(--surface-2); border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; font-family: 'Courier New', monospace; font-size: 12px; word-break: break-all; }}
          .filter-bar {{ display: grid; grid-template-columns: 1fr auto auto; gap: 10px; align-items: center; padding: 14px 20px; border-bottom: 1px solid var(--border); background: var(--surface-2); }}
          .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 20px 22px; box-shadow: var(--shadow); }}
          .stat-number {{ font-size: 30px; font-weight: 700; line-height: 1; letter-spacing: -1px; color: var(--text); }}
          .stat-label {{ font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; margin-top: 5px; }}
          @media (max-width: 840px) {{
            .user-row-summary {{ grid-template-columns: 1fr auto; }}
            .user-row-body {{ grid-template-columns: 1fr 1fr; }}
            .filter-bar {{ grid-template-columns: 1fr; }}
          }}
          @media (max-width: 560px) {{
            .user-row-body {{ grid-template-columns: 1fr; }}
            .crypto-row {{ grid-template-columns: 1fr; gap: 6px; }}
          }}
        </style>
      </head>
      <body>
        <img class="page-bg-watermark" src="/static/nuevamariposa.png" alt="">

        <aside class="sidebar">
          <div class="sidebar-brand">
            <img src="/static/Logoenblanco.png" alt="Casa Monarca" style="width:100%;max-width:200px;height:auto;display:block;margin:0 auto 6px;">
            <p class="sidebar-tagline" style="text-align:center;">Gestor de Identidades</p>
          </div>
          <div class="sidebar-user">
            <div class="sidebar-avatar">{_initials}</div>
            <div class="sidebar-user-info">
              <div class="sidebar-user-name">{escape(actor.full_name)}</div>
              <div class="sidebar-user-role">{escape(actor.role.name)}</div>
            </div>
          </div>
          <nav class="sidebar-nav">
            <span class="sidebar-section-label">Navegaci&oacute;n</span>
            <a href="/portal?as_user={actor.id}" class="sidebar-link">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
              Portal de usuario
            </a>
            <a href="/dashboard?as_user={actor.id}" class="sidebar-link active">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
              Panel de administraci&oacute;n
            </a>
            <span class="sidebar-section-label">Secciones</span>
            {_slink("usuarios", "Usuarios", '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>')}
            {_slink("alta", "Alta de usuario", '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>')}
            {_slink("auditoria", "Auditor&iacute;a", '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>')}
            {_slink("notificaciones", "Notificaciones" + ("&nbsp;<span style='background:#dc2626;color:#fff;border-radius:999px;padding:0 6px;font-size:10px;font-weight:700;vertical-align:middle;'>"+str(unread_count)+"</span>" if unread_count else ""), '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>')}
            {_slink("beneficiarios", "Beneficiarios", '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>')}
            {_slink("historial", "Historial", '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>')}
          </nav>
          <div class="sidebar-footer">
            <img class="sidebar-watermark" src="/static/mariposa.png" alt="">
            <a href="/logout" class="sidebar-logout">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
              Salir / cambiar usuario
            </a>
          </div>
        </aside>
        <div class="page-wrapper">
        <main>
          {section_main}
        </main>
        <script>
        var OPEN_KEY = 'cm_open_rows';

        function saveOpenRows() {{
          var open = [];
          document.querySelectorAll('.user-row[open]').forEach(function(row) {{
            var id = row.getAttribute('data-id');
            if (id) open.push(id);
          }});
          sessionStorage.setItem(OPEN_KEY, JSON.stringify(open));
        }}

        function restoreOpenRows() {{
          var saved = JSON.parse(sessionStorage.getItem(OPEN_KEY) || '[]');
          saved.forEach(function(id) {{
            var row = document.querySelector('.user-row[data-id="' + id + '"]');
            if (row) row.setAttribute('open', '');
          }});
        }}

        function filterUsers() {{
          var search = document.getElementById('filter-search').value.toLowerCase();
          var role = document.getElementById('filter-role').value.toUpperCase();
          var status = document.getElementById('filter-status').value;
          var count = 0;
          document.querySelectorAll('.user-row').forEach(function(row) {{
            var name = (row.getAttribute('data-name') || '').toLowerCase();
            var email = (row.getAttribute('data-email') || '').toLowerCase();
            var rowRole = (row.getAttribute('data-role') || '').toUpperCase();
            var rowStatus = row.getAttribute('data-status') || '';
            var ok = (!search || name.includes(search) || email.includes(search))
                   && (!role || rowRole === role)
                   && (!status || rowStatus === status);
            row.style.display = ok ? '' : 'none';
            if (ok) count++;
          }});
          var countEl = document.getElementById('filter-count');
          if (countEl) countEl.textContent = count + (count === 1 ? ' usuario' : ' usuarios');
          var noResults = document.getElementById('no-results');
          if (noResults) noResults.style.display = (count === 0) ? '' : 'none';
        }}

        document.addEventListener('DOMContentLoaded', function() {{
          restoreOpenRows();
          filterUsers();
          document.querySelectorAll('.user-row').forEach(function(row) {{
            row.addEventListener('toggle', saveOpenRows);
          }});
          document.querySelectorAll('.user-row form').forEach(function(form) {{
            form.addEventListener('submit', saveOpenRows);
          }});
        }});
        </script>
        </div>
      </body>
    </html>
    """


@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def login_page(notice: str | None = Query(default=None)):
    return HTMLResponse(render_login_page(notice=notice))


@app.get("/register", response_class=HTMLResponse)
def self_register_page():
    return HTMLResponse(render_self_register_page())


@app.post("/register", response_class=HTMLResponse)
def self_register(
    full_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
    db: Session = Depends(get_db),
):
    if password != password2:
        return HTMLResponse(render_self_register_page("Las contraseñas no coinciden."), status_code=400)
    if len(password) < 6:
        return HTMLResponse(render_self_register_page("La contraseña debe tener al menos 6 caracteres."), status_code=400)

    voluntario_role = UserService.get_role_by_code(db, "VOLUNTARIO")
    if not voluntario_role:
        return HTMLResponse(render_self_register_page("Error interno: rol no encontrado."), status_code=500)

    try:
        UserService.create_user(
            db,
            full_name=full_name,
            email=email,
            role_id=voluntario_role.id,
            credential_secret=password,
        )
    except ValueError as exc:
        return HTMLResponse(render_self_register_page(str(exc)), status_code=400)

    return RedirectResponse(url=f"/login?{urlencode({'notice': 'registro-enviado'})}", status_code=303)


@app.post("/login")
async def login(
    request: Request,
    identifier: str = Form(...),
    password: str = Form(...),
    private_key_file: UploadFile | None = File(default=None),
    certificate_file: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else "desconocida"
    ua = request.headers.get("user-agent", "desconocido")[:255]
    has_private_key = private_key_file is not None and bool(private_key_file.filename)
    has_certificate = certificate_file is not None and bool(certificate_file.filename)

    if (
        settings.demo_admin_bypass_enabled
        and identifier.strip().lower() == "admin"
        and password == "admin"
        and not has_private_key
        and not has_certificate
    ):
        admin = get_actor_or_404(db, None)
        if not is_active_admin(admin):
            return HTMLResponse(render_login_page("El administrador demo no esta activo"), status_code=403)

        AuditService.log(
            db,
            event_type="login_admin_bypass",
            actor_user_id=admin.id,
            target_user_id=admin.id,
            action="login_with_demo_password",
            resource="auth",
            result="success",
            metadata={"warning": "demo bypass without certificate"},
            ip_address=ip,
            user_agent=ua,
        )
        resp = RedirectResponse(url="/dashboard", status_code=303)
        return _login_redirect(resp, admin.id)

    try:
        private_key_bytes = b""
        certificate_bytes = b""
        if has_private_key:
            private_key_bytes = await private_key_file.read()
        if has_certificate:
            certificate_bytes = await certificate_file.read()

        if has_private_key != has_certificate:
            raise ValueError("Debes adjuntar el archivo de acceso y el certificado de identidad juntos")

        if private_key_bytes and certificate_bytes:
            user, proof = SignatureLoginService.authenticate_with_private_key_and_certificate(
                db,
                identifier=identifier,
                private_key_bytes=private_key_bytes,
                certificate_bytes=certificate_bytes,
                password=password,
            )
            AuditService.log(
                db,
                event_type="login_signature_verified",
                actor_user_id=user.id,
                target_user_id=user.id,
                action="login_with_private_key",
                resource="auth",
                result="success",
                metadata=proof,
                ip_address=ip,
                user_agent=ua,
            )
            if is_active_admin(user):
                resp = RedirectResponse(url=f"/dashboard?notice=crypto-login", status_code=303)
            else:
                resp = RedirectResponse(url=f"/portal?verified=1", status_code=303)
            return _login_redirect(resp, user.id)

        user = PasswordLoginService.authenticate_user(db, identifier=identifier, password=password)
    except ValueError as exc:
        AuditService.log(
            db,
            event_type="login_rejected",
            action="login_with_private_key" if has_private_key or has_certificate else "login_with_password",
            resource="auth",
            result="failure",
            metadata={"identifier": identifier.strip().lower(), "reason": str(exc)},
            ip_address=ip,
            user_agent=ua,
        )
        return HTMLResponse(render_login_page(str(exc)), status_code=400)

    AuditService.log(
        db,
        event_type="login_password_verified",
        actor_user_id=user.id,
        target_user_id=user.id,
        action="login_with_password",
        resource="auth",
        result="success",
        ip_address=ip,
        user_agent=ua,
    )

    dest = "/dashboard" if is_active_admin(user) else "/portal"
    resp = RedirectResponse(url=dest, status_code=303)
    return _login_redirect(resp, user.id)


@app.get("/portal", response_class=HTMLResponse)
def user_portal(
    section: str = Query(default="cuenta"),
    notice: str | None = Query(default=None),
    verified: bool = Query(default=False),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    permissions = AuthorizationService.get_permissions(db, actor)
    logs = AuditService.list_recent(db)
    beneficiarios = BeneficiarioService.list_all(db)
    issuer_user = UserService.get_user(db, actor.certificate_issuer_user_id) if actor.certificate_issuer_user_id else None
    # Load documents for users with signing rights
    docs = []
    pending_cosign = []
    if actor.status == "active" and actor.role.code in CRYPTO_ROLE_CODES:
        if actor.role.code == "ADMIN":
            docs = DocumentService.list_documents(db)
        else:
            docs = DocumentService.list_by_signer(db, actor.id)
        pending_cosign = DocumentService.list_pending_cosign(db, actor.id)
    return HTMLResponse(
        render_portal_page(
            actor,
            permissions,
            logs,
            notice=notice,
            verified=verified,
            beneficiarios=beneficiarios,
            issuer_name=issuer_user.full_name if issuer_user else None,
            section=section,
            documents=docs,
            pending_cosign=pending_cosign,
        )
    )


@app.post("/portal/request-password-reset")
def portal_request_password_reset(
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    NotificationService.create(
        db,
        type="recovery_request",
        title=f"Solicitud de recuperaci\u00f3n: {actor.full_name}",
        message=(
            f"{actor.full_name} ({actor.email}) solicita recuperaci\u00f3n de acceso desde su portal. "
            "Verificar identidad en persona antes de entregar nuevas credenciales."
        ),
        user_id=actor.id,
        metadata={"email": actor.email, "user_id": actor.id},
    )
    resp = RedirectResponse(url=f"/portal?section=cuenta&notice=recovery-sent", status_code=303)
    return _login_redirect(resp, actor.id)


@app.post("/ui/beneficiarios", response_class=HTMLResponse)
def create_beneficiario(
    nombre_completo: str = Form(...),
    pais_origen: str = Form(...),
    area: str = Form(...),
    notas: str = Form(default=""),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if area not in ["ADMINISTRACION", "LEGAL", "PSICOSOCIAL", "HUMANITARIO", "COMUNICACION"]:
        raise HTTPException(status_code=400, detail="Área inválida")
    BeneficiarioService.create(
        db,
        nombre_completo=nombre_completo,
        pais_origen=pais_origen,
        area=area,
        notas=notas.strip() or None,
        created_by_user_id=actor.id,
    )
    db.commit()
    resp = RedirectResponse(url="/portal?section=beneficiarios&notice=beneficiario-creado", status_code=303)
    return _login_redirect(resp, actor.id)


@app.post("/ui/beneficiarios/{ben_id}/status", response_class=HTMLResponse)
def update_beneficiario_status(
    ben_id: int,
    new_status: str = Form(...),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if actor.role.code not in ("ADMIN", "COORDINADOR"):
        raise HTTPException(status_code=403, detail="Solo Coordinador o Admin pueden actualizar el estado")
    if new_status not in ["nuevo", "en_revision", "canalizado", "activo"]:
        raise HTTPException(status_code=400, detail="Estado inválido")
    BeneficiarioService.update_status(db, ben_id, new_status)
    db.commit()
    resp = RedirectResponse(url="/portal", status_code=303)
    return _login_redirect(resp, actor.id)


@app.post("/ui/beneficiarios/{ben_id}/delete", response_class=HTMLResponse)
def delete_beneficiario(
    ben_id: int,
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if actor.role.code != "ADMIN":
        raise HTTPException(status_code=403, detail="Solo Admin puede eliminar registros")
    BeneficiarioService.delete(db, ben_id)
    db.commit()
    resp = RedirectResponse(url="/portal", status_code=303)
    return _login_redirect(resp, actor.id)


@app.get("/admin/register", response_class=HTMLResponse)
def admin_register_page(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    require_actor_permission(db, actor, "users", "create")
    roles = UserService.list_roles(db)
    return HTMLResponse(render_admin_register_page(actor, roles))


@app.post("/admin/register", response_class=HTMLResponse)
def admin_register_user(
    full_name: str = Form(...),
    email: str = Form(...),
    role_id: int = Form(...),
    end_date: str = Form(default=""),
    credential_secret: str = Form(...),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    require_actor_permission(db, actor, "users", "create")
    roles = UserService.list_roles(db)

    try:
        user = UserService.create_user(
            db,
            full_name=full_name,
            email=email,
            role_id=role_id,
            end_date=parse_end_date(end_date),
            credential_secret=credential_secret,
        )
    except ValueError as exc:
        return HTMLResponse(render_admin_register_page(actor, roles, str(exc)), status_code=400)

    AuditService.log(
        db,
        event_type="user_created",
        actor_user_id=actor.id,
        target_user_id=user.id,
        action="create",
        resource="users",
        result="success",
        metadata={"source": "admin_register", "role": user.role.code},
    )
    return redirect_home(actor.id, "user-created")


# ── Document signing & verification endpoints ─────────────────────────────

NOTICE_MESSAGES["document-signed"] = "Documento firmado exitosamente. Se generó un folio único de verificación."
NOTICE_MESSAGES["document-pending-signatures"] = "Documento creado. Está pendiente de firmas adicionales para ser válido."
NOTICE_MESSAGES["document-cosigned"] = "Co-firma agregada exitosamente."
NOTICE_MESSAGES["document-cosigned-complete"] = "Co-firma agregada. El documento ya tiene todas las firmas requeridas y está listo."
NOTICE_MESSAGES["document-revoked"] = "El documento fue revocado correctamente."


@app.post("/ui/documents/sign")
async def ui_sign_document(
    request: Request,
    title: str = Form(...),
    document_type: str = Form(...),
    expires_days: str = Form(default=""),
    required_signers: str = Form(default="1"),
    document_file: UploadFile = File(...),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if not AuthorizationService.authorize(db, actor, "documents", "sign"):
        raise HTTPException(status_code=403, detail="No tienes permiso para firmar documentos")

    file_bytes = await document_file.read()
    exp_days = None
    if expires_days.strip():
        try:
            exp_days = int(expires_days.strip())
        except ValueError:
            pass

    try:
        req_signers = max(1, int(required_signers.strip()))
    except (ValueError, AttributeError):
        req_signers = 1

    ip = request.client.host if request.client else "desconocida"
    ua = request.headers.get("user-agent", "desconocido")[:255]

    try:
        doc = DocumentService.sign_document(
            db,
            file_bytes=file_bytes,
            title=title,
            document_type=document_type,
            signer=actor,
            original_filename=document_file.filename,
            expires_days=exp_days,
            required_signers=req_signers,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    is_pending = doc.status == "pending_signatures"

    AuditService.log(
        db,
        event_type="document_signed",
        actor_user_id=actor.id,
        action="sign_document",
        resource="documents",
        result="success",
        metadata={
            "folio": doc.folio,
            "title": doc.title,
            "document_type": doc.document_type,
            "hash_sha256": doc.document_hash,
            "certificate_serial": doc.certificate_serial,
            "required_signers": doc.required_signers,
            "status": doc.status,
        },
        ip_address=ip,
        user_agent=ua,
    )

    # Real-time notification to admins
    NotificationService.create(
        db, type="document_signed",
        title=f"Documento {'iniciado (multi-firma)' if is_pending else 'firmado'}: {doc.title}",
        message=f"{actor.full_name} firmó '{doc.title}' ({DOC_TYPE_LABELS.get(doc.document_type, doc.document_type)}). Folio: {doc.folio}",
        metadata={"folio": doc.folio, "signer": actor.full_name},
    )
    _fire_ws(_ws_manager.send_to_admins(db, {
        "type": "document_signed", "level": "success",
        "title": "Documento firmado",
        "message": f"{actor.full_name} firmó: {doc.title} (Folio: {doc.folio})",
    }))

    notice_key = "document-pending-signatures" if is_pending else "document-signed"
    resp = RedirectResponse(
        url=f"/portal?section=documentos&{urlencode({'notice': notice_key})}",
        status_code=303,
    )
    return _login_redirect(resp, actor.id)


@app.post("/ui/documents/batch-sign")
async def ui_batch_sign(
    request: Request,
    document_type: str = Form(...),
    expires_days: str = Form(default=""),
    document_files: list[UploadFile] = File(...),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if not AuthorizationService.authorize(db, actor, "documents", "sign"):
        raise HTTPException(status_code=403, detail="No tienes permiso para firmar documentos")

    exp_days = None
    if expires_days.strip():
        try:
            exp_days = int(expires_days.strip())
        except ValueError:
            pass

    ip = request.client.host if request.client else "desconocida"
    ua = request.headers.get("user-agent", "desconocido")[:255]
    signed_count = 0
    errors = []

    for uf in document_files[:20]:  # limit to 20
        file_bytes = await uf.read()
        title = uf.filename or f"Documento {signed_count + 1}"
        try:
            doc = DocumentService.sign_document(
                db,
                file_bytes=file_bytes,
                title=title,
                document_type=document_type,
                signer=actor,
                original_filename=uf.filename,
                expires_days=exp_days,
            )
            AuditService.log(
                db,
                event_type="document_signed",
                actor_user_id=actor.id,
                action="batch_sign_document",
                resource="documents",
                result="success",
                metadata={"folio": doc.folio, "title": doc.title, "batch": True},
                ip_address=ip,
                user_agent=ua,
            )
            signed_count += 1
        except (ValueError, Exception) as exc:
            errors.append(f"{uf.filename}: {exc}")

    if signed_count > 0:
        NotificationService.create(
            db, type="batch_signed",
            title=f"Firma masiva: {signed_count} documentos",
            message=f"{actor.full_name} firmó {signed_count} documentos en lote.",
            metadata={"count": signed_count, "signer": actor.full_name},
        )
        _fire_ws(_ws_manager.send_to_admins(db, {
            "type": "batch_signed", "level": "success",
            "title": "Firma masiva completada",
            "message": f"{actor.full_name} firmó {signed_count} documentos en lote.",
        }))

    notice_msg = f"batch-signed-{signed_count}"
    if errors:
        notice_msg += f"-errors-{len(errors)}"

    resp = RedirectResponse(
        url=f"/portal?section=documentos&{urlencode({'notice': notice_msg})}",
        status_code=303,
    )
    return _login_redirect(resp, actor.id)


@app.post("/ui/documents/{folio}/cosign")
def ui_cosign_document(
    folio: str,
    request: Request,
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if not AuthorizationService.authorize(db, actor, "documents", "sign"):
        raise HTTPException(status_code=403, detail="No tienes permiso para co-firmar documentos")

    doc = DocumentService.find_by_folio(db, folio)
    if not doc:
        raise HTTPException(status_code=404, detail="Documento no encontrado")

    ip = request.client.host if request.client else "desconocida"
    ua = request.headers.get("user-agent", "desconocido")[:255]

    try:
        doc = DocumentService.cosign_document(db, doc=doc, cosigner=actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    now_complete = doc.status == "signed"

    AuditService.log(
        db,
        event_type="document_cosigned",
        actor_user_id=actor.id,
        action="cosign_document",
        resource="documents",
        result="success",
        metadata={
            "folio": doc.folio,
            "title": doc.title,
            "signatures_collected": len(doc.co_signatures),
            "required_signers": doc.required_signers,
            "now_complete": now_complete,
        },
        ip_address=ip,
        user_agent=ua,
    )

    NotificationService.create(
        db, type="document_cosigned",
        title=f"Co-firma: {doc.title}",
        message=f"{actor.full_name} co-firmó '{doc.title}'. Folio: {doc.folio}. "
                f"Firmas: {len(doc.co_signatures)}/{doc.required_signers}.",
        metadata={"folio": doc.folio, "cosigner": actor.full_name, "complete": now_complete},
    )

    notice_key = "document-cosigned-complete" if now_complete else "document-cosigned"
    resp = RedirectResponse(
        url=f"/portal?section=documentos&{urlencode({'notice': notice_key})}",
        status_code=303,
    )
    return _login_redirect(resp, actor.id)


@app.get("/ui/documents/export-csv")
def ui_export_csv(
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if not AuthorizationService.authorize(db, actor, "documents", "sign"):
        raise HTTPException(status_code=403, detail="Sin permiso")

    from app.models import Document as DocModel
    docs = db.query(DocModel).order_by(DocModel.issued_at.desc()).all()

    import io, csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Folio", "Título", "Tipo", "Estado", "Firmante", "Fecha", "Vencimiento", "Archivo original", "Tamaño (bytes)"])
    for d in docs:
        writer.writerow([
            d.folio, d.title,
            DOC_TYPE_LABELS.get(d.document_type, d.document_type),
            DOC_STATUS_LABELS.get(d.status, d.status),
            d.signer.full_name if d.signer else "?",
            d.issued_at.strftime("%Y-%m-%d %H:%M") if d.issued_at else "",
            d.expires_at.strftime("%Y-%m-%d") if d.expires_at else "Sin vencimiento",
            d.original_filename or "",
            d.file_size or "",
        ])

    csv_bytes = output.getvalue().encode("utf-8-sig")
    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=documentos_casa_monarca.csv"},
    )


@app.post("/ui/documents/{folio}/revoke")
def ui_revoke_document(
    folio: str,
    request: Request,
    reason: str = Form(default=""),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if not AuthorizationService.authorize(db, actor, "documents", "revoke") and not (
        AuthorizationService.authorize(db, actor, "documents", "sign")
    ):
        raise HTTPException(status_code=403, detail="No tienes permiso para revocar documentos")

    doc = DocumentService.find_by_folio(db, folio)
    if not doc:
        raise HTTPException(status_code=404, detail="Documento no encontrado")

    if actor.role.code != "ADMIN" and doc.signer_user_id != actor.id:
        raise HTTPException(status_code=403, detail="Solo puedes revocar documentos que tú firmaste")

    ip = request.client.host if request.client else "desconocida"
    ua = request.headers.get("user-agent", "desconocido")[:255]

    DocumentService.revoke_document(db, doc, reason or "Revocado por el usuario")

    AuditService.log(
        db,
        event_type="document_revoked",
        actor_user_id=actor.id,
        action="revoke_document",
        resource="documents",
        result="success",
        metadata={"folio": doc.folio, "reason": reason},
        ip_address=ip,
        user_agent=ua,
    )

    resp = RedirectResponse(
        url=f"/portal?section=documentos&{urlencode({'notice': 'document-revoked'})}",
        status_code=303,
    )
    return _login_redirect(resp, actor.id)


# ── Public verification portal (no login required) ────────────────────────

def _render_verification_page(
    result: str | None = None,
    doc=None,
    folio: str = "",
    error: str | None = None,
    actor=None,
) -> str:
    RESULT_CONFIG = {
        "valid": ("&#10003; Documento v&aacute;lido", "El documento fue emitido por Casa Monarca y su contenido coincide con el registro original.", "#dcfce7", "#166534", "#86efac"),
        "tampered": ("&#9888; Documento alterado", "El folio existe, pero el archivo cargado no coincide con el documento originalmente firmado.", "#fee2e2", "#991b1b", "#fca5a5"),
        "revoked": ("&#10007; Documento revocado", "El documento fue emitido, pero actualmente se encuentra revocado por Casa Monarca.", "#fee2e2", "#991b1b", "#fca5a5"),
        "expired": ("&#9888; Documento expirado", "El documento fue v&aacute;lido, pero su vigencia termin&oacute;.", "#fef3c7", "#92400e", "#fcd34d"),
        "not_found": ("&#10007; Documento no encontrado", "No existe un documento registrado con ese folio.", "#fee2e2", "#991b1b", "#fca5a5"),
        "invalid_signature": ("&#10007; Firma inv&aacute;lida", "La firma criptogr&aacute;fica no corresponde con el certificado registrado.", "#fee2e2", "#991b1b", "#fca5a5"),
    }

    result_html = ""
    if result:
        cfg = RESULT_CONFIG.get(result, ("Resultado desconocido", "", "#f3f4f6", "#374151", "#d1d5db"))
        title, msg, bg, color, border = cfg
        result_html = f"""
        <div style="background:{bg};border:1px solid {border};color:{color};border-radius:12px;padding:20px 24px;margin-bottom:20px;">
          <p style="font-size:18px;font-weight:700;margin-bottom:6px;">{title}</p>
          <p style="font-size:14px;line-height:1.5;">{msg}</p>
        </div>"""

        if doc and result != "not_found":
            st_label = DOC_STATUS_LABELS.get(doc.status, doc.status)
            signer_name = escape(doc.signer.full_name) if doc.signer else "Desconocido"
            signer_role = escape(doc.signer.role.name) if doc.signer and doc.signer.role else ""
            result_html += f"""
        <div style="background:#fff;border:1px solid #e5ddd3;border-radius:12px;padding:20px 24px;margin-bottom:16px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#1a2332" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            <h2 style="font-size:16px;font-weight:700;margin:0;color:#1a2332;">Datos del documento</h2>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;">
            <div>
              <p style="font-size:11px;font-weight:600;color:#6b7280;">Folio</p>
              <p style="font-weight:600;font-size:14px;"><code>{escape(doc.folio)}</code></p>
            </div>
            <div>
              <p style="font-size:11px;font-weight:600;color:#6b7280;">T&iacute;tulo</p>
              <p style="font-weight:500;font-size:14px;">{escape(doc.title)}</p>
            </div>
            <div>
              <p style="font-size:11px;font-weight:600;color:#6b7280;">Tipo</p>
              <p style="font-size:14px;">{escape(DOC_TYPE_LABELS.get(doc.document_type, doc.document_type))}</p>
            </div>
            <div>
              <p style="font-size:11px;font-weight:600;color:#6b7280;">Estado</p>
              <p style="font-size:14px;font-weight:600;">{st_label}</p>
            </div>
          </div>
        </div>
        <div style="background:#fff;border:1px solid #e5ddd3;border-radius:12px;padding:20px 24px;margin-bottom:16px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <h2 style="font-size:16px;font-weight:700;margin:0;color:#1a2332;">Integridad del documento</h2>
          </div>
          <p style="font-size:12px;color:#6b7280;margin-bottom:12px;">El hash SHA-256 confirma que el contenido del documento no ha sido modificado desde su emisión.</p>
          <p style="font-size:11px;font-weight:600;color:#6b7280;margin-bottom:4px;">Hash SHA-256</p>
          <p style="font-size:11px;font-family:monospace;word-break:break-all;background:#f0fdf4;border:1px solid #bbf7d0;color:#166534;padding:10px 12px;border-radius:8px;">{escape(doc.document_hash)}</p>
        </div>
        <div style="background:#fff;border:1px solid #e5ddd3;border-radius:12px;padding:20px 24px;margin-bottom:20px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#1a2332" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            <h2 style="font-size:16px;font-weight:700;margin:0;color:#1a2332;">Firma digital</h2>
          </div>
          <p style="font-size:12px;color:#6b7280;margin-bottom:14px;">Identidad del firmante y algoritmo criptográfico utilizado para emitir este documento.</p>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;">
            <div>
              <p style="font-size:11px;font-weight:600;color:#6b7280;">Firmado por</p>
              <p style="font-size:14px;">{signer_name}</p>
              <p style="font-size:11px;color:#6b7280;">{signer_role}</p>
            </div>
            <div>
              <p style="font-size:11px;font-weight:600;color:#6b7280;">Algoritmo de firma</p>
              <p style="font-size:14px;">RSA-PSS-SHA256</p>
            </div>
            <div>
              <p style="font-size:11px;font-weight:600;color:#6b7280;">Fecha de firma</p>
              <p style="font-size:14px;">{doc.issued_at.strftime('%d/%m/%Y %H:%M')}</p>
            </div>
          </div>
        </div>"""

    error_html = f'<div style="background:#fee2e2;border:1px solid #fca5a5;color:#991b1b;border-radius:10px;padding:10px 14px;font-size:13px;margin-bottom:14px;">{escape(error)}</div>' if error else ""

    # ── Shared body (used in both portal and standalone modes) ──
    _verify_body = f"""
    <section style="margin-bottom:24px;">
      <h1 class="page-title" style="font-size:24px;">Verificaci&oacute;n de documentos</h1>
      <div class="page-title-accent" style="width:42px;height:3px;background:#e06020;border-radius:2px;margin:8px 0 6px;"></div>
      <p style="font-size:14px;color:#6b7280;margin-top:4px;">Comprueba si un documento fue emitido oficialmente por Casa Monarca</p>
    </section>

    {result_html}{error_html}

    <div class="card" style="padding:28px;margin-bottom:20px;">
      <h2 style="font-size:16px;font-weight:700;margin-bottom:6px;">Verificar por folio</h2>
      <p style="font-size:13px;color:#6b7280;margin-bottom:14px;">Ingresa el folio que aparece en el documento.</p>
      <form method="post" action="/verificar">
        <label style="display:flex;flex-direction:column;gap:5px;font-size:14px;font-weight:500;">Folio del documento
          <input type="text" name="folio" placeholder="CM-2026-DOC-XXXXXXXX" value="{escape(folio)}" required style="text-transform:uppercase;font:inherit;font-size:15px;padding:11px 14px;border-radius:10px;border:1.5px solid #e5ddd3;background:#fff;color:#1a2332;outline:none;width:100%;">
        </label>
        <button type="submit" style="font:inherit;font-size:14px;font-weight:600;padding:11px 22px;border-radius:10px;border:none;cursor:pointer;background:#e06020;color:#fff;width:100%;margin-top:10px;">Verificar folio</button>
      </form>
    </div>

    <div class="card" style="padding:28px;margin-bottom:20px;">
      <h2 style="font-size:16px;font-weight:700;margin-bottom:6px;">Verificar por archivo</h2>
      <p style="font-size:13px;color:#6b7280;margin-bottom:14px;">Carga el documento recibido para comparar su contenido con el hash original registrado.</p>
      <div style="padding:12px 14px;background:#eff6ff;border:1px solid #93c5fd;border-radius:8px;display:flex;gap:10px;align-items:flex-start;margin-bottom:18px;font-size:12px;color:#1e40af;line-height:1.5;">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#1d4ed8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:1px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span>El sistema calcula el hash SHA-256 del archivo y lo compara con el hash registrado al momento de la firma digital. Si coincide, el documento no fue alterado.</span>
      </div>
      <form method="post" action="/verificar/archivo" enctype="multipart/form-data">
        <label style="display:flex;flex-direction:column;gap:5px;font-size:14px;font-weight:500;">Archivo a verificar
          <div class="file-zone">
            <div style="width:36px;height:36px;border-radius:8px;background:#fff3eb;border:1px solid #f0d4c5;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e06020" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
            </div>
            <div>
              <div class="file-zone-text" id="vf-text">Arrastra tu documento aqu&iacute;</div>
              <div class="file-zone-sub" id="vf-sub">o selecciona un archivo</div>
            </div>
            <input type="file" name="verify_file" required id="vf" onchange="setVerFile(this)">
          </div>
        </label>
        <button type="submit" style="font:inherit;font-size:14px;font-weight:600;padding:11px 22px;border-radius:10px;border:none;cursor:pointer;background:#e06020;color:#fff;width:100%;margin-top:14px;">Verificar archivo</button>
      </form>
    </div>

    <script>
    function setVerFile(input) {{
      var textEl = document.getElementById('vf-text');
      var subEl = document.getElementById('vf-sub');
      var zone = input.closest('.file-zone');
      if (input.files && input.files.length > 0) {{
        textEl.textContent = input.files[0].name;
        subEl.textContent = (input.files[0].size / 1024).toFixed(1) + ' KB \\u2714';
        zone.classList.add('has-file');
      }} else {{
        textEl.innerHTML = 'Arrastra tu documento aqu\\u00ed';
        subEl.textContent = 'o selecciona un archivo';
        zone.classList.remove('has-file');
      }}
    }}
    </script>
    """

    # ── If logged in, render inside the portal with sidebar ──
    if actor:
        portal_sections = _build_portal_sections(actor, section="verificar")
        return base_page("Verificar documento", _verify_body, actor=actor, portal_sections=portal_sections)

    # ── Public standalone page (no login) ──
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Verificar documento &middot; Casa Monarca</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Inter',system-ui,sans-serif;font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased;min-height:100vh;background:#f5f0e8;}}
    main{{max-width:700px;margin:0 auto;padding:40px 20px 80px;}}
    .header{{text-align:center;margin-bottom:32px;}}
    .header img{{height:50px;margin-bottom:12px;}}
    h1{{font-size:24px;font-weight:800;color:#1a2332;letter-spacing:-0.4px;}}
    .subtitle{{font-size:14px;color:#6b7280;margin-top:4px;}}
    .card{{background:#fff;border:1px solid #e5ddd3;border-radius:14px;box-shadow:0 1px 3px rgba(0,0,0,0.06),0 4px 16px rgba(0,0,0,0.05);padding:28px;margin-bottom:20px;}}
    label{{display:flex;flex-direction:column;gap:5px;font-size:14px;font-weight:500;color:#1a2332;}}
    input[type="text"]{{font:inherit;font-size:15px;padding:11px 14px;border-radius:10px;border:1.5px solid #e5ddd3;background:#fff;color:#1a2332;outline:none;width:100%;transition:border-color .15s,box-shadow .15s;}}
    input[type="text"]:focus{{border-color:#e06020;box-shadow:0 0 0 3px rgba(224,96,32,0.12);}}
    .btn{{font:inherit;font-size:14px;font-weight:600;padding:11px 22px;border-radius:10px;border:none;cursor:pointer;background:#e06020;color:#fff;width:100%;margin-top:10px;}}
    .btn:hover{{background:#bf4f10;}}
    .btn-secondary{{background:#4b5563;}}
    .btn-secondary:hover{{background:#374151;}}
    .file-zone{{position:relative;display:flex;align-items:center;gap:14px;border:1.5px solid #f0d4c5;border-radius:10px;padding:13px 16px;cursor:pointer;background:#fff8f5;transition:border-color .15s,background .15s;overflow:hidden;margin-top:4px;}}
    .file-zone:hover{{border-color:#e06020;background:#fff3eb;}}
    .file-zone input[type="file"]{{position:absolute;inset:0;opacity:0;width:100%;height:100%;cursor:pointer;}}
    .file-zone.has-file{{border-color:#22c55e;background:#f0fdf4;}}
    .file-zone.has-file .fz-text{{color:#166534;}}
    .file-zone.has-file .fz-sub{{color:#16a34a;}}
    .divider{{border:none;border-top:1px solid #e5ddd3;margin:20px 0;}}
    code{{background:#faf7f3;border:1px solid #e5ddd3;border-radius:4px;padding:1px 5px;font-family:'Courier New',monospace;font-size:12px;}}
    .footer{{text-align:center;margin-top:32px;font-size:12px;color:#9ca3af;}}
    .footer a{{color:#e06020;text-decoration:none;font-weight:600;}}
    .info-box{{padding:12px 14px;background:#eff6ff;border:1px solid #93c5fd;border-radius:8px;display:flex;gap:10px;align-items:flex-start;margin-bottom:18px;font-size:12px;color:#1e40af;line-height:1.5;}}
  </style>
</head>
<body>
  <main>
    <div style="text-align:center;margin-bottom:24px;">
      <img src="/static/logoCasaMonarca.png" alt="Casa Monarca" style="height:50px;margin-bottom:12px;">
    </div>

    {_verify_body}

    <div style="text-align:center;margin-top:32px;font-size:12px;color:#9ca3af;">
      <p>&copy; 2026 Casa Monarca &mdash; Ayuda Humanitaria al Migrante, A.B.P.</p>
      <p style="margin-top:4px;">Este portal no almacena informaci&oacute;n personal. <a href="/login" style="color:#e06020;text-decoration:none;font-weight:600;">Acceso interno &rarr;</a></p>
    </div>
  </main>
</body>
</html>"""


@app.get("/verificar", response_class=HTMLResponse)
def public_verify_page(
    request: Request,
    db: Session = Depends(get_db),
):
    actor = _try_get_session_actor(request, db)
    return HTMLResponse(_render_verification_page(actor=actor))


@app.get("/verificar/{folio}", response_class=HTMLResponse)
def public_verify_by_folio_get(
    folio: str,
    request: Request,
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent", "")[:255] or None
    doc, result = DocumentService.verify_by_folio(db, folio, ip_address=ip, user_agent_str=ua)

    AuditService.log(
        db,
        event_type="document_verification",
        action="verify_by_folio",
        resource="documents",
        result="success" if result == "valid" else "failure",
        metadata={"folio": folio, "result": result},
        ip_address=ip,
        user_agent=ua,
    )

    actor = _try_get_session_actor(request, db)
    return HTMLResponse(_render_verification_page(result=result, doc=doc, folio=folio, actor=actor))


@app.post("/verificar", response_class=HTMLResponse)
def public_verify_by_folio_post(
    request: Request,
    folio: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent", "")[:255] or None
    doc, result = DocumentService.verify_by_folio(db, folio, ip_address=ip, user_agent_str=ua)

    AuditService.log(
        db,
        event_type="document_verification",
        action="verify_by_folio",
        resource="documents",
        result="success" if result == "valid" else "failure",
        metadata={"folio": folio, "result": result},
        ip_address=ip,
        user_agent=ua,
    )

    actor = _try_get_session_actor(request, db)

    # Alert admins on suspicious verification results
    if result in ("tampered", "invalid_signature"):
        NotificationService.create(
            db, type="verification_alert",
            title=f"Alerta: Verificación fallida ({result})",
            message=f"Intento de validación con documento alterado. Folio: {folio}. IP: {ip}",
            metadata={"folio": folio, "result": result, "ip": ip},
        )
        _fire_ws(_ws_manager.send_to_admins(db, {
            "type": "verification_alert", "level": "danger",
            "title": "\u26a0 Alerta de seguridad",
            "message": f"Intento de validación fallido ({result}) desde IP {ip}. Folio: {folio}",
        }))

    return HTMLResponse(_render_verification_page(result=result, doc=doc, folio=folio, actor=actor))


@app.post("/verificar/archivo", response_class=HTMLResponse)
async def public_verify_by_file(
    request: Request,
    folio: str = Form(""),
    verify_file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent", "")[:255] or None
    file_bytes = await verify_file.read()

    actor = _try_get_session_actor(request, db)

    if len(file_bytes) == 0:
        return HTMLResponse(_render_verification_page(error="El archivo está vacío.", folio=folio, actor=actor))

    doc, result = DocumentService.verify_by_file(
        db, folio, file_bytes, ip_address=ip, user_agent_str=ua,
    )

    AuditService.log(
        db,
        event_type="document_verification",
        action="verify_by_file",
        resource="documents",
        result="success" if result == "valid" else "failure",
        metadata={
            "folio": folio,
            "result": result,
            "uploaded_hash": DocumentService.compute_hash(file_bytes),
        },
        ip_address=ip,
        user_agent=ua,
    )

    # Alert admins on suspicious file verification results
    if result in ("tampered", "invalid_signature"):
        NotificationService.create(
            db, type="verification_alert",
            title=f"Alerta: Archivo alterado ({result})",
            message=f"Se cargó un archivo que no coincide con el documento original. Folio: {folio or 'sin folio'}. IP: {ip}",
            metadata={"folio": folio, "result": result, "ip": ip},
        )
        _fire_ws(_ws_manager.send_to_admins(db, {
            "type": "verification_alert", "level": "danger",
            "title": "\u26a0 Alerta: Documento alterado",
            "message": f"Archivo no coincide con el original. Folio: {folio or 'sin folio'}. IP: {ip}",
        }))

    return HTMLResponse(_render_verification_page(result=result, doc=doc, folio=folio, actor=actor))


@app.get("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(_SESSION_COOKIE, path="/", secure=settings.session_cookie_secure_resolved, samesite="lax")
    return resp


@app.get("/health")
def health():
    return {"status": "ok"}


@app.websocket("/ws/notifications")
async def ws_notifications(ws: WebSocket, db: Session = Depends(get_db)):
    token = ws.cookies.get(_SESSION_COOKIE)
    payload = _read_session_cookie(token)
    if not payload:
        await ws.close(code=1008)
        return
    user_id = payload["uid"]
    await _ws_manager.connect(user_id, ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _ws_manager.disconnect(user_id, ws)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    section: str = Query(default="usuarios"),
    notice: str | None = Query(default=None),
    error: str | None = Query(default=None),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if not is_active_admin(actor):
        resp = RedirectResponse(url="/portal", status_code=303)
        return _login_redirect(resp, actor.id)

    permissions = AuthorizationService.get_permissions(db, actor)
    logs = AuditService.list_recent(db)
    users = UserService.list_users(db)
    roles = UserService.list_roles(db)
    backup_admin = AdminRecoveryService.get_backup_admin(db)
    certificate_history = UserService.list_certificate_history(db)
    NotificationService.check_expiring_certificates(db)
    NotificationService.check_expiring_users(db)
    notifications = NotificationService.list_all(db)
    return HTMLResponse(render_dashboard(actor, users, roles, permissions, logs, backup_admin, certificate_history, notice, error=error, beneficiarios=BeneficiarioService.list_all(db), notifications=notifications, section=section))


@app.get("/api/me", response_model=MeOut)
def api_me(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    return {"user": actor, "role": actor.role, "permissions": AuthorizationService.get_permissions(db, actor)}


@app.get("/api/users", response_model=list[UserOut])
def api_users(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    require_actor_permission(db, actor, "users", "view")
    return UserService.list_users(db)


@app.get("/api/audit-logs", response_model=list[AuditLogOut])
def api_audit_logs(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    require_actor_permission(db, actor, "audit", "view")
    return AuditService.list_recent(db, limit=50)


@app.get("/ui/audit-logs/export.pdf")
def export_audit_logs_pdf(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    if not is_active_admin(actor):
        raise HTTPException(status_code=403)
    logs = AuditService.list_recent(db, limit=200)
    rows = [
        (
            log.created_at.strftime("%Y-%m-%d %H:%M") if log.created_at else "",
            log.event_type or "",
            log.action or "",
            log.result or "",
            log.ip_address or "-",
        )
        for log in logs
    ]
    pdf_bytes = _pdf_report(
        title="Registro de Auditoría",
        subtitle=f"{len(rows)} eventos - exportado para revision",
        col_headers=["Fecha", "Evento", "Acción", "Resultado", "IP"],
        col_widths=[38, 42, 50, 22, 28],
        rows=rows,
        generated_by=actor.full_name,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=auditoria.pdf"},
    )


@app.get("/ui/users/export.pdf")
def export_users_pdf(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    if not (actor.status == "active" and actor.role.code in ("ADMIN", "COORDINADOR")):
        raise HTTPException(status_code=403)
    users = UserService.list_users(db)
    rows = [
        (
            u.full_name,
            u.email,
            u.role.name if u.role else "",
            u.status,
            u.created_at.strftime("%Y-%m-%d") if u.created_at else "",
        )
        for u in users
    ]
    pdf_bytes = _pdf_report(
        title="Directorio de Usuarios",
        subtitle=f"{len(rows)} usuarios registrados",
        col_headers=["Nombre", "Correo", "Rol", "Estado", "Creado"],
        col_widths=[48, 58, 28, 20, 26],
        rows=rows,
        generated_by=actor.full_name,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=usuarios.pdf"},
    )


@app.get("/ui/beneficiarios/export.pdf")
def export_beneficiarios_pdf(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    if not (actor.status == "active" and actor.role.code in ("ADMIN", "COORDINADOR")):
        raise HTTPException(status_code=403)
    AREA_LABELS = {
        "ADMINISTRACION": "Administracion", "LEGAL": "Legal",
        "PSICOSOCIAL": "Psicosocial", "HUMANITARIO": "Humanitario", "COMUNICACION": "Comunicacion",
    }
    STATUS_LABELS = {"nuevo": "Nuevo", "en_revision": "En revision", "canalizado": "Canalizado", "activo": "Activo"}
    bens = BeneficiarioService.list_all(db)
    rows = [
        (
            b.nombre_completo,
            b.pais_origen,
            AREA_LABELS.get(b.area, b.area),
            STATUS_LABELS.get(b.status, b.status),
            b.fecha_ingreso.strftime("%Y-%m-%d") if b.fecha_ingreso else "",
        )
        for b in bens
    ]
    pdf_bytes = _pdf_report(
        title="Registro de Beneficiarios",
        subtitle=f"{len(rows)} beneficiarios registrados",
        col_headers=["Nombre", "Pais de origen", "Area", "Estado", "Ingreso"],
        col_widths=[56, 40, 32, 24, 28],
        rows=rows,
        generated_by=actor.full_name,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=beneficiarios.pdf"},
    )


@app.post("/ui/users")
def ui_create_user(
    full_name: str = Form(...),
    email: str = Form(...),
    role_id: int = Form(...),
    end_date: str = Form(default=""),
    credential_secret: str = Form(...),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    require_actor_permission(db, actor, "users", "create")
    try:
        user = UserService.create_user(
            db,
            full_name=full_name,
            email=email,
            role_id=role_id,
            end_date=parse_end_date(end_date),
            credential_secret=credential_secret,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    AuditService.log(
        db,
        event_type="user_created",
        actor_user_id=actor.id,
        target_user_id=user.id,
        action="create",
        resource="users",
        result="success",
        metadata={"role": user.role.code},
    )
    return redirect_home(actor.id, "user-created")


@app.post("/ui/users/{user_id}/status")
def ui_change_status(
    user_id: int,
    status: str = Form(...),
    new_secret: str = Form(default=""),
    role_id: int = Form(default=None),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    _require_own_or_admin(actor, user_id)
    target = UserService.get_user(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    config = {
        "active": ("users", "activate", "user_access_restored"),
        "revoked": ("users", "revoke", "emergency_revoke"),
    }
    if status not in config:
        raise HTTPException(status_code=400, detail="Unsupported status")

    resource, action, event_type = config[status]
    require_actor_permission(db, actor, resource, action)

    # Apply role change before activation when the admin changed the role dropdown
    role_changed = False
    if status == "active" and role_id is not None and role_id != target.role_id:
        require_actor_permission(db, actor, "users", "change_role")
        try:
            target = UserService.change_role(db, target, role_id, new_secret)
        except ValueError as exc:
            back_href = "/dashboard" if is_active_admin(actor) else "/portal"
            url = f"{back_href}?{urlencode({'error': str(exc)})}"
            return RedirectResponse(url=url, status_code=303)
        role_changed = True
        AuditService.log(
            db,
            event_type="role_changed",
            actor_user_id=actor.id,
            target_user_id=target.id,
            action="change_role",
            resource="users",
            result="success",
            metadata={"new_role_id": role_id},
        )
        db.refresh(target)

    try:
        updated = UserService.update_status(db, target, status, new_secret)
    except ValueError as exc:
        back_href = "/dashboard" if is_active_admin(actor) else "/portal"
        url = f"{back_href}?{urlencode({'error': str(exc)})}"
        return RedirectResponse(url=url, status_code=303)

    metadata = {"credential_reset": bool(new_secret.strip())}
    if status == "revoked":
        metadata["protocol"] = "emergency"

    AuditService.log(
        db,
        event_type=event_type,
        actor_user_id=actor.id,
        target_user_id=updated.id,
        action=action,
        resource=resource,
        result="success",
        metadata=metadata,
    )
    back_href = "/dashboard" if is_active_admin(actor) else "/portal"
    url = f"{back_href}?{urlencode({'notice': 'status-updated'})}"
    return RedirectResponse(url=url, status_code=303)


@app.post("/ui/users/{user_id}/expiration")
def ui_change_expiration(
    user_id: int,
    end_date: str = Form(...),
    new_secret: str = Form(default=""),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    _require_own_or_admin(actor, user_id)
    target = UserService.get_user(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    require_actor_permission(db, actor, "users", "change_expiration")
    try:
        parsed_end_date = parse_end_date(end_date)
        if parsed_end_date is None:
            raise ValueError("Debes indicar una nueva fecha de expiracion")
        updated = UserService.update_expiration(db, target, parsed_end_date, new_secret)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    AuditService.log(
        db,
        event_type="expiration_changed",
        actor_user_id=actor.id,
        target_user_id=updated.id,
        action="change_expiration",
        resource="users",
        result="success",
        metadata={
            "end_date": updated.end_date.isoformat() if updated.end_date else None,
            "reissued_certificate": bool(new_secret.strip()),
        },
    )
    back_href = "/dashboard" if is_active_admin(actor) else "/portal"
    url = f"{back_href}?{urlencode({'notice': 'expiration-updated'})}"
    return RedirectResponse(url=url, status_code=303)


@app.post("/ui/users/{user_id}/role")
def ui_change_role(
    user_id: int,
    role_id: int = Form(...),
    new_secret: str = Form(default=""),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    _require_own_or_admin(actor, user_id)
    target = UserService.get_user(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    require_actor_permission(db, actor, "users", "change_role")
    try:
        updated = UserService.change_role(db, target, role_id, new_secret)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    AuditService.log(
        db,
        event_type="role_changed",
        actor_user_id=actor.id,
        target_user_id=updated.id,
        action="change_role",
        resource="users",
        result="success",
        metadata={"role_id": role_id, "credential_updated": bool(new_secret.strip())},
    )
    back_href = "/dashboard" if is_active_admin(actor) else "/portal"
    url = f"{back_href}?{urlencode({'notice': 'role-updated'})}"
    return RedirectResponse(url=url, status_code=303)


@app.post("/ui/users/{user_id}/certificate")
def ui_issue_certificate(
    user_id: int,
    credential_secret: str = Form(...),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    _require_own_or_admin(actor, user_id)
    target = UserService.get_user(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    require_actor_permission(db, actor, "users", "create")
    try:
        updated = CertificateService.issue_for_user(db, target, credential_secret, reissue=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    AuditService.log(
        db,
        event_type="certificate_issued",
        actor_user_id=actor.id,
        target_user_id=updated.id,
        action="issue_certificate",
        resource="certificates",
        result="success",
        metadata={"certificate_serial": updated.certificate_serial},
    )
    back_href = "/dashboard" if is_active_admin(actor) else "/portal"
    url = f"{back_href}?{urlencode({'notice': 'certificate-issued'})}"
    return RedirectResponse(url=url, status_code=303)


@app.post("/ui/admin/recovery/activate-mirror")
def ui_activate_mirror(
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    require_actor_permission(db, actor, "admin_recovery", "activate")
    try:
        revoked_admin, backup_admin = AdminRecoveryService.activate_mirror(db, actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    AuditService.log(
        db,
        event_type="admin_recovery_activated",
        actor_user_id=revoked_admin.id,
        target_user_id=backup_admin.id,
        action="activate_mirror",
        resource="admin_recovery",
        result="success",
        metadata={"revoked_admin_id": revoked_admin.id, "backup_admin_id": backup_admin.id},
    )
    return redirect_home(backup_admin.id, "recovery-activated")



@app.get("/ui/users/{user_id}/certificate/view", response_class=HTMLResponse)
def view_user_certificate(user_id: int, db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    _require_own_or_admin(actor, user_id)
    require_actor_permission(db, actor, "certificates", "view")
    user = UserService.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    summary = CertificateService.describe_user_certificate(user)
    if not summary:
        raise HTTPException(status_code=404, detail="Certificate not found")

    back_href = "/dashboard" if is_active_admin(actor) else "/portal"
    return HTMLResponse(render_certificate_page(f"Certificado de {user.full_name}", summary, back_href))


@app.get("/ui/users/{user_id}/certificate.pem")
def download_certificate_pem(user_id: int, db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    _require_own_or_admin(actor, user_id)
    require_actor_permission(db, actor, "certificates", "view")
    user = UserService.get_user(db, user_id)
    if not user or not user.certificate_pem:
        raise HTTPException(status_code=404, detail="Certificate not found")

    return Response(
        content=user.certificate_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{user.email.replace("@", "_")}.crt.pem"'},
    )


@app.get("/ui/users/{user_id}/public-key.pem")
def download_public_key_pem(user_id: int, db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    _require_own_or_admin(actor, user_id)
    require_actor_permission(db, actor, "certificates", "view")
    user = UserService.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    public_key_pem = CertificateService.get_user_public_key_pem(user)
    if not public_key_pem:
        raise HTTPException(status_code=404, detail="Public key not found")

    return Response(
        content=public_key_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{user.email.replace("@", "_")}.public.pem"'},
    )


@app.get("/ui/users/{user_id}/private-key.pem")
def download_private_key_pem(user_id: int, db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    _require_own_or_admin(actor, user_id)
    require_actor_permission(db, actor, "certificates", "view")
    user = UserService.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        private_key_pem = CertificateService.deliver_user_private_key(db, user)
    except ValueError:
        back_href = "/dashboard" if is_active_admin(actor) else "/portal"
        url = f"{back_href}?{urlencode({'notice': 'private-key-already-delivered'})}"
        resp = RedirectResponse(url=url, status_code=303)
        return _login_redirect(resp, actor.id)

    AuditService.log(
        db,
        event_type="private_key_delivered",
        actor_user_id=actor.id,
        target_user_id=user.id,
        action="deliver_private_key",
        resource="certificates",
        result="success",
        metadata={"delivery_mode": "one_time_download"},
    )

    return Response(
        content=private_key_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{user.email.replace("@", "_")}.private.pem"'},
    )


@app.get("/ui/ca/certificate/view", response_class=HTMLResponse)
def view_ca_certificate(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    require_actor_permission(db, actor, "certificates", "view")
    summary = AdminSignerService.describe_active_signer_certificate(db)
    back_href = "/dashboard" if is_active_admin(actor) else "/portal"
    return HTMLResponse(render_certificate_page("Certificado autofirmado del administrador firmante", summary, back_href))


@app.get("/ui/ca/certificate")
def download_ca_certificate(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    require_actor_permission(db, actor, "certificates", "view")
    return Response(
        content=AdminSignerService.get_active_signer_certificate_pem(db),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="casa-monarca-admin-firmante.crt.pem"'},
    )


@app.post("/login/recovery-request")
def recovery_request(
    identifier: str = Form(...),
    full_name: str = Form(...),
    db: Session = Depends(get_db),
):
    user = PasswordLoginService.find_user_by_identifier(db, identifier)
    if user:
        NotificationService.create(
            db,
            type="recovery_request",
            title=f"Solicitud de recuperaci\u00f3n: {user.full_name}",
            message=f"{user.full_name} ({user.email}) solicita recuperaci\u00f3n de acceso. Verificar identidad en persona antes de entregar nuevas credenciales.",
            user_id=user.id,
            metadata={"email": user.email, "requester_name": full_name},
        )
    return RedirectResponse(url=f"/login?{urlencode({'notice': 'recovery-sent'})}", status_code=303)


@app.post("/ui/users/{user_id}/unlock")
def ui_unlock_user(
    user_id: int,
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if not is_active_admin(actor):
        raise HTTPException(status_code=403, detail="Solo administradores pueden desbloquear cuentas")
    user = UserService.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    UserService.unlock_user(db, user)
    AuditService.log(
        db,
        event_type="account_unlocked",
        actor_user_id=actor.id,
        target_user_id=user.id,
        action="unlock_account",
        resource="users",
        result="success",
    )
    back_href = f"/dashboard?{urlencode({'notice': 'user-unlocked'})}"
    resp = RedirectResponse(url=back_href, status_code=303)
    return _login_redirect(resp, actor.id)


@app.post("/ui/notifications/read-all")
def ui_mark_all_notifications_read(
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if not is_active_admin(actor):
        raise HTTPException(status_code=403, detail="Solo administradores pueden gestionar notificaciones")
    from app.models import Notification as NotifModel
    db.query(NotifModel).filter(NotifModel.is_read == False).update({"is_read": True})
    db.commit()
    back_href = f"/dashboard?section=notificaciones&as_user={actor.id}"
    return RedirectResponse(url=back_href, status_code=303)


@app.post("/ui/notifications/{notification_id}/read")
def ui_mark_notification_read(
    notification_id: int,
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if not is_active_admin(actor):
        raise HTTPException(status_code=403, detail="Solo administradores pueden gestionar notificaciones")
    NotificationService.mark_read(db, notification_id)
    back_href = f"/dashboard?section=notificaciones&as_user={actor.id}"
    return RedirectResponse(url=back_href, status_code=303)

