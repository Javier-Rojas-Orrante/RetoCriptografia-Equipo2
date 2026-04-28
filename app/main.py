from contextlib import asynccontextmanager
from datetime import datetime
from html import escape
from urllib.parse import urlencode

from fastapi import Cookie, Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.config import settings
from app.db import Base, engine
from app.deps import get_db
from app.schemas import AuditLogOut, MeOut, UserOut
from app.services import (
    AdminRecoveryService,
    AuditService,
    AuthorizationService,
    BeneficiarioService,
    BootstrapService,
    CertificateAuthorityService,
    CertificateService,
    PasswordLoginService,
    SignatureLoginService,
    UserService,
    role_requires_crypto,
)
from app.models import Role


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    with Session(bind=engine) as db:
        BootstrapService.seed(db)
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# ── Session cookie (signed with HMAC, 8-hour expiry) ──────────────────────
_SESSION_COOKIE = "cm_session"
_SESSION_MAX_AGE = 8 * 3600  # seconds
_signer = URLSafeTimedSerializer(settings.session_secret, salt="cm-session")


def _make_session_cookie(user_id: int, notice: str | None = None) -> str:
    payload = {"uid": user_id}
    if notice:
        payload["notice"] = notice
    return _signer.dumps(payload)


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
        samesite="lax",
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


NOTICE_MESSAGES = {
    "user-created": "Usuario creado en estado pending. Debes activarlo para que pueda entrar.",
    "status-updated": "El acceso del usuario fue actualizado.",
    "expiration-updated": "La fecha de expiracion fue actualizada.",
    "role-updated": "El rol del usuario fue actualizado.",
    "recovery-activated": "El administrador espejo ya esta activo. El admin principal fue revocado y debe regenerarse un nuevo respaldo.",
    "certificate-issued": "El certificado y el .p12 del usuario fueron emitidos o reemitidos.",
    "crypto-login": "Identidad verificada con el certificado criptografico del usuario.",
    "beneficiario-creado": "Beneficiario registrado correctamente. Ya está visible para el equipo operativo.",
    "registro-enviado": "Solicitud de acceso enviada. Un administrador revisará tu cuenta y te notificará cuando esté activa.",
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


def render_notice(notice: str | None) -> str:
    if not notice:
        return ""
    message = NOTICE_MESSAGES.get(notice, notice)
    return f"<div class='ok'>{escape(message)}</div>"


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
            --accent: #a64b2a;
            --accent-dark: #8a3d22;
            --radius: 10px;
            --radius-lg: 14px;
            --shadow: 0 1px 3px rgba(0,0,0,0.06), 0 4px 16px rgba(0,0,0,0.05);
          }}
          *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
          body {{ background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 14px; line-height: 1.6; -webkit-font-smoothing: antialiased; }}
          main {{ max-width: 780px; margin: 0 auto; padding: 32px 20px 64px; }}
          h1 {{ font-size: 20px; font-weight: 700; letter-spacing: -0.3px; }}
          h2 {{ font-size: 14px; font-weight: 600; margin: 20px 0 10px; }}
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


def base_page(title: str, body: str, actor=None) -> str:
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
    _user_block = (
        f'<div class="sidebar-user">'
        f'<div class="sidebar-user-name">{escape(actor.full_name)}</div>'
        f'<div class="sidebar-user-role">{escape(actor.role.name)}</div>'
        f'</div>'
    ) if actor else ""

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
            --bg: #f6f2ec;
            --surface: #ffffff;
            --surface-2: #faf7f3;
            --border: #e5ddd3;
            --border-strong: #cfc4b5;
            --text: #1a2332;
            --muted: #6b7280;
            --accent: #a64b2a;
            --accent-dark: #8a3d22;
            --accent-light: #fdf0eb;
            --brand-pink: #d1145a;
            --brand-orange: #f06b35;
            --sidebar-bg: #1a2332;
            --sidebar-text: #e8e4de;
            --sidebar-muted: #8b9ab0;
            --sidebar-active: rgba(209,20,90,0.18);
            --sidebar-active-border: #d1145a;
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
          body {{ background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 14px; line-height: 1.6; -webkit-font-smoothing: antialiased; display: flex; min-height: 100vh; }}

          /* ─── Sidebar ─────────────────────────────────── */
          .sidebar {{
            width: 230px; flex-shrink: 0;
            background: var(--sidebar-bg);
            display: flex; flex-direction: column;
            position: fixed; top: 0; left: 0; bottom: 0;
            z-index: 100; overflow-y: auto;
          }}
          .sidebar-brand {{
            padding: 22px 20px 18px;
            border-bottom: 1px solid rgba(255,255,255,0.07);
          }}
          .sidebar-brand-logo {{
            display: flex; align-items: center; gap: 10px; margin-bottom: 6px;
          }}
          .sidebar-brand-text {{ line-height: 1.2; }}
          .sidebar-brand-name {{
            font-size: 15px; font-weight: 800; color: #fff; letter-spacing: -0.3px;
          }}
          .sidebar-brand-sub {{
            font-size: 10px; color: var(--sidebar-muted); text-transform: uppercase; letter-spacing: .08em; font-weight: 500;
          }}
          .sidebar-tagline {{
            font-size: 11px; color: var(--sidebar-muted); line-height: 1.4; margin-top: 6px;
          }}
          .sidebar-nav {{
            flex: 1; padding: 16px 12px;
            display: flex; flex-direction: column; gap: 2px;
          }}
          .sidebar-section-label {{
            font-size: 10px; font-weight: 700; color: var(--sidebar-muted); text-transform: uppercase;
            letter-spacing: .1em; padding: 10px 8px 4px; margin-top: 6px;
          }}
          .sidebar-link {{
            display: flex; align-items: center; gap: 9px;
            padding: 8px 10px; border-radius: 8px;
            color: var(--sidebar-text); font-size: 13px; font-weight: 500;
            text-decoration: none; transition: background .15s, color .15s;
            border-left: 2px solid transparent;
          }}
          .sidebar-link:hover {{ background: rgba(255,255,255,0.07); color: #fff; text-decoration: none; }}
          .sidebar-link.active {{
            background: var(--sidebar-active);
            border-left-color: var(--sidebar-active-border);
            color: #fff;
          }}
          .sidebar-link svg {{ flex-shrink: 0; opacity: .7; }}
          .sidebar-link.active svg {{ opacity: 1; }}
          .sidebar-footer {{
            padding: 16px 12px;
            border-top: 1px solid rgba(255,255,255,0.07);
          }}
          .sidebar-logout {{
            display: flex; align-items: center; gap: 8px;
            color: var(--sidebar-muted); font-size: 12px; font-weight: 500;
            text-decoration: none; padding: 6px 8px; border-radius: 7px;
            transition: color .15s, background .15s;
          }}
          .sidebar-logout:hover {{ color: #fff; background: rgba(255,255,255,0.07); text-decoration: none; }}
          .sidebar-user {{ padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.07); }}
          .sidebar-user-name {{ font-size: 13px; font-weight: 600; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
          .sidebar-user-role {{ font-size: 11px; color: var(--sidebar-muted); margin-top: 2px; }}

          /* ─── Main content ────────────────────────────── */
          .page-wrapper {{
            margin-left: 230px;
            flex: 1;
            min-width: 0;
          }}
          main {{ max-width: 900px; margin: 0 auto; padding: 32px 28px 72px; }}
          h1 {{ font-size: 20px; font-weight: 700; letter-spacing: -0.3px; line-height: 1.3; }}
          h2 {{ font-size: 15px; font-weight: 600; letter-spacing: -0.1px; line-height: 1.4; }}
          p {{ margin: 0; }}
          .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); }}
          .panel {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); padding: 24px; }}
          .stack {{ display: flex; flex-direction: column; gap: 14px; }}
          .grid {{ display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }}
          label {{ display: flex; flex-direction: column; gap: 5px; font-size: 13px; font-weight: 500; color: var(--text); }}
          input, select {{ font: inherit; font-size: 14px; padding: 9px 12px; border-radius: var(--radius); border: 1px solid var(--border-strong); background: var(--surface); color: var(--text); transition: border-color .15s, box-shadow .15s; outline: none; width: 100%; }}
          input:focus, select:focus {{ border-color: var(--accent); box-shadow: 0 0 0 3px rgba(166,75,42,0.12); }}
          input[type="file"] {{ padding: 7px 10px; cursor: pointer; background: var(--surface-2); }}
          button {{ font: inherit; font-size: 13px; font-weight: 600; padding: 9px 18px; border-radius: var(--radius); border: none; cursor: pointer; transition: background .15s; }}
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

          /* ─── Responsive ──────────────────────────────── */
          @media (max-width: 700px) {{
            .sidebar {{ display: none; }}
            .page-wrapper {{ margin-left: 0; }}
            main {{ padding: 20px 14px 60px; }}
          }}
        </style>
      </head>
      <body>
        <aside class="sidebar">
          <div class="sidebar-brand">
            <div class="sidebar-brand-logo">
              {BUTTERFLY_SVG}
              <div class="sidebar-brand-text">
                <div class="sidebar-brand-name">Casa Monarca</div>
                <div class="sidebar-brand-sub">Gestor de Identidades</div>
              </div>
            </div>
            <p class="sidebar-tagline">Ayuda Humanitaria al Migrante, A.B.P.</p>
          </div>
          {_user_block}
          <nav class="sidebar-nav">
            <span class="sidebar-section-label">Navegaci&oacute;n</span>
            <a href="{_portal_href}" class="sidebar-link">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
              Portal de usuario
            </a>
            {_admin_nav}
            <span class="sidebar-section-label">En esta p&aacute;gina</span>
            <a href="#certificados" class="sidebar-link">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Certificado
            </a>
            <a href="#beneficiarios" class="sidebar-link">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
              Beneficiarios
            </a>
          </nav>
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
      </body>
    </html>
    """


def render_login_page(error: str | None = None, notice: str | None = None) -> str:
    BUTTERFLY_SVG = """<svg width="52" height="46" viewBox="0 0 80 64" fill="none" xmlns="http://www.w3.org/2000/svg">
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
      <title>Iniciar sesi&oacute;n &middot; Casa Monarca</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
      <style>
        *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
        body{{font-family:'Inter',system-ui,sans-serif;font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;display:flex;min-height:100vh}}
        .login-left{{flex:1;background:#1a2332;display:flex;flex-direction:column;justify-content:space-between;padding:48px 52px;min-width:0;position:relative;overflow:hidden;}}
        .login-left-bg{{position:absolute;inset:0;background:url('/static/CM5.jpeg') center/cover no-repeat;opacity:.35;}}
        .login-left-fade{{position:absolute;inset:0;background:linear-gradient(to right, #1a2332 28%, rgba(26,35,50,0) 100%);}}
        .login-left-content{{position:relative;z-index:1;display:flex;flex-direction:column;justify-content:space-between;height:100%;}}
        .login-right{{width:460px;flex-shrink:0;display:flex;align-items:center;justify-content:center;background:#f6f2ec;padding:40px 32px}}
        @media(max-width:800px){{.login-left{{display:none}}.login-right{{width:100%}}}}
        .brand-name{{font-size:32px;font-weight:800;color:#fff;letter-spacing:-1px;line-height:1.1;margin-top:24px}}
        .brand-sub{{font-size:13px;color:#8b9ab0;text-transform:uppercase;letter-spacing:.1em;font-weight:500;margin-top:6px}}
        .brand-tagline{{font-size:15px;color:#c8d0da;line-height:1.6;margin-top:32px;max-width:320px}}
        .left-footer{{font-size:12px;color:#4a5568}}
        .card{{background:#fff;border:1px solid #e5ddd3;border-radius:14px;box-shadow:0 1px 3px rgba(0,0,0,0.06),0 4px 16px rgba(0,0,0,0.05);padding:36px 32px;width:100%;max-width:400px}}
        .form-title{{font-size:20px;font-weight:700;color:#1a2332;letter-spacing:-.3px}}
        .form-sub{{font-size:13px;color:#6b7280;margin-top:4px}}
        .stack{{display:flex;flex-direction:column;gap:14px;margin-top:24px}}
        label{{display:flex;flex-direction:column;gap:5px;font-size:13px;font-weight:500;color:#1a2332}}
        .label-hint{{font-size:11px;color:#6b7280;font-weight:400;margin-top:-2px}}
        input,select{{font:inherit;font-size:14px;padding:9px 12px;border-radius:10px;border:1px solid #cfc4b5;background:#fff;color:#1a2332;outline:none;width:100%;transition:border-color .15s,box-shadow .15s}}
        input:focus,select:focus{{border-color:#a64b2a;box-shadow:0 0 0 3px rgba(166,75,42,0.12)}}
        input[type="file"]{{padding:7px 10px;cursor:pointer;background:#faf7f3}}
        .btn{{font:inherit;font-size:14px;font-weight:600;padding:11px;border-radius:10px;border:none;cursor:pointer;transition:background .15s;width:100%;background:#a64b2a;color:#fff;margin-top:6px}}
        .btn:hover{{background:#8a3d22}}
        .btn-ghost{{background:#faf7f3;color:#1a2332;border:1px solid #cfc4b5;margin-top:0}}
        .btn-ghost:hover{{background:#f0ebe4}}
        .divider{{border:none;border-top:1px solid #e5ddd3;margin:20px 0}}
        .ok{{background:#dcfce7;border:1px solid #86efac;color:#166534;border-radius:10px;padding:10px 14px;font-size:13px}}
        .error{{background:#fee2e2;border:1px solid #fca5a5;color:#991b1b;border-radius:10px;padding:10px 14px;font-size:13px}}
        code{{background:#faf7f3;border:1px solid #e5ddd3;border-radius:4px;padding:1px 5px;font-family:'Courier New',monospace;font-size:12px}}
        details summary{{cursor:pointer;list-style:none;font-size:12px;font-weight:600;color:#6b7280;display:flex;align-items:center;gap:6px;user-select:none}}
        details summary::-webkit-details-marker{{display:none}}
      </style>
    </head>
    <body>
      <div class="login-left">
        <div class="login-left-bg"></div>
        <div class="login-left-fade"></div>
        <div class="login-left-content">
          <div>
            {BUTTERFLY_SVG}
            <div class="brand-name">Casa Monarca</div>
            <div class="brand-sub">Ayuda Humanitaria al Migrante, A.B.P.</div>
            <p class="brand-tagline">Sistema de gestión de identidades digitales y certificados X.509 para el equipo de Casa Monarca.</p>
          </div>
          <p class="left-footer">&copy; 2026 Casa Monarca &mdash; Gestor de Identidades</p>
        </div>
      </div>
      <div class="login-right">
        <div class="card">
          <div class="form-title">Iniciar sesi&oacute;n</div>
          <div class="form-sub">Ingresa tus credenciales para acceder al sistema</div>

          <details style="margin-top:18px;">
            <summary>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
              Credenciales demo
            </summary>
            <div style="margin-top:10px;padding:12px 14px;background:#faf7f3;border:1px solid #e5ddd3;border-radius:8px;display:grid;gap:5px;font-size:12px;color:#6b7280;">
              <span><code>admin / admin</code> &mdash; bypass sin certificado</span>
              <span><code>admin@demo.local</code> + .p12 + <code>admin</code></span>
              <span><code>coord.legal@demo.local</code> + .p12 + <code>demo1234</code></span>
              <span><code>operativo / demo1234</code></span>
              <span><code>voluntario / demo1234</code></span>
            </div>
          </details>

          {render_notice(notice)}
          {error_html}

          <form method="post" action="/login" enctype="multipart/form-data" class="stack">
            <label>Correo o usuario
              <input name="identifier" placeholder="usuario@ejemplo.com" required autocomplete="username">
            </label>
            <label>Archivo .p12
              <span class="label-hint">Solo para Admin y Coordinador</span>
              <input name="p12_file" type="file" accept=".p12,.pfx">
            </label>
            <label>Contrase&ntilde;a
              <span class="label-hint">O clave del archivo .p12</span>
              <input name="password" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required autocomplete="current-password">
            </label>
            <button type="submit" class="btn">Entrar</button>
          </form>
          <hr class="divider">
          <div style="text-align:center;">
            <p style="font-size:13px;color:#6b7280;margin-bottom:10px;">&iquest;Primera vez en el sistema?</p>
            <a href="/register" style="display:inline-flex;align-items:center;gap:6px;background:#faf7f3;border:1px solid #cfc4b5;color:#1a2332;padding:9px 20px;border-radius:9px;font-size:13px;font-weight:600;text-decoration:none;">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
              Solicitar acceso
            </a>
          </div>
        </div>
      </div>
    </body>
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
        input:focus{{border-color:#a64b2a;box-shadow:0 0 0 3px rgba(166,75,42,0.12)}}
        .btn{{font:inherit;font-size:14px;font-weight:600;padding:11px;border-radius:10px;border:none;cursor:pointer;background:#a64b2a;color:#fff;width:100%;margin-top:6px}}
        .btn:hover{{background:#8a3d22}}
        .ok{{background:#dcfce7;border:1px solid #86efac;color:#166534;border-radius:10px;padding:10px 14px;font-size:13px;margin-top:14px}}
        .error{{background:#fee2e2;border:1px solid #fca5a5;color:#991b1b;border-radius:10px;padding:10px 14px;font-size:13px;margin-top:14px}}
        hr{{border:none;border-top:1px solid #e5ddd3;margin:20px 0}}
      </style>
    </head>
    <body>
      <div class="card">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid #e5ddd3;">
          {BUTTERFLY_SVG_SMALL}
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
          <p class="muted">Crea la cuenta en estado <code>pending</code>. ADMIN y COORDINADOR reciben certificado .p12; OPERATIVO y VOLUNTARIO usan solo contrase&ntilde;a.</p>
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
            <span class="muted" style="font-weight:400;font-size:12px;margin-top:-2px;">O clave del archivo .p12 para roles criptogr&aacute;ficos</span>
            <input name="credential_secret" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
          </label>
          <button type="submit" style="padding:10px;font-size:14px;margin-top:8px;">Crear usuario</button>
        </form>
      </div>
    </div>
    """
    return base_page("Otorgar registro · Casa Monarca", body)


def render_portal_page(actor, permissions, logs, notice: str | None = None, verified: bool = False, beneficiarios=None) -> str:
    permission_text = ", ".join(f"{item['resource']}:{item['action']}" for item in permissions) or "sin permisos"
    verified_html = "<div class='ok' style='margin-bottom:10px;'>&check; Identidad verificada con firma digital del .p12.</div>" if verified else ""

    # --- Certificate section (only for crypto roles) ---
    cert_section = ""
    if role_requires_crypto(actor):
        if actor.certificate_serial:
            expires_text = (
                escape(actor.certificate_not_after.isoformat(sep=" ", timespec="minutes"))
                if actor.certificate_not_after
                else "n/a"
            )
            cert_section = f"""
            <div style="margin-top:16px;padding:16px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
                <div>
                  <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:4px;">Certificado X.509</p>
                  <p style="font-size:12px;color:var(--muted);">Serial: <code>{escape(actor.certificate_serial)}</code></p>
                  <p style="font-size:12px;color:var(--muted);margin-top:3px;">Vence: {expires_text}</p>
                </div>
                <span class="status status-active" style="white-space:nowrap;">Activo</span>
              </div>
              <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <a href="/ui/users/{actor.id}/certificate/view?as_user={actor.id}"
                   style="display:inline-flex;align-items:center;gap:6px;background:var(--surface);border:1px solid var(--border-strong);color:var(--text);padding:7px 14px;border-radius:8px;font-size:13px;font-weight:500;text-decoration:none;">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                  Ver detalles
                </a>
                <a href="/ui/users/{actor.id}/certificate.pem?as_user={actor.id}"
                   style="display:inline-flex;align-items:center;gap:6px;background:var(--surface);border:1px solid var(--border-strong);color:var(--text);padding:7px 14px;border-radius:8px;font-size:13px;font-weight:500;text-decoration:none;">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  Descargar .pem
                </a>
                <a href="/ui/users/{actor.id}/certificate.p12?as_user={actor.id}"
                   style="display:inline-flex;align-items:center;gap:6px;background:var(--accent);color:#fff;padding:7px 14px;border-radius:8px;font-size:13px;font-weight:600;text-decoration:none;">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  Descargar .p12
                </a>
              </div>
            </div>
            """
        else:
            cert_section = """
            <div style="margin-top:16px;padding:14px 16px;background:var(--warn-bg);border:1px solid var(--warn-border);border-radius:10px;display:flex;align-items:center;gap:10px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#92400e" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <p style="font-size:13px;color:#92400e;">Tu perfil requiere un certificado .p12 que a&uacute;n no ha sido emitido. Contacta al administrador para solicitarlo.</p>
            </div>
            """

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
            <div style="padding:16px;background:#f0fdf4;border:1px solid #86efac;border-radius:10px;">
              <p style="font-size:28px;font-weight:700;color:#166534;line-height:1;">{len(activos)}</p>
              <p style="font-size:11px;font-weight:600;color:#166534;margin-top:4px;">Beneficiarios activos</p>
            </div>
            <div style="padding:16px;background:#eff6ff;border:1px solid #93c5fd;border-radius:10px;">
              <p style="font-size:28px;font-weight:700;color:#1d4ed8;line-height:1;">{len(bens)}</p>
              <p style="font-size:11px;font-weight:600;color:#1d4ed8;margin-top:4px;">Total registrados</p>
            </div>
            <div style="padding:16px;background:#fef3c7;border:1px solid #fcd34d;border-radius:10px;">
              <p style="font-size:28px;font-weight:700;color:#92400e;line-height:1;">{len(en_revision)}</p>
              <p style="font-size:11px;font-weight:600;color:#92400e;margin-top:4px;">En revisi&oacute;n</p>
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
        <div class="card" style="padding:24px;margin-top:18px;">
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

    body = f"""
    <div class="card" style="padding:28px;margin-bottom:20px;">
      <div style="margin-bottom:20px;padding-bottom:20px;border-bottom:1px solid var(--border);">
        <h1 style="margin-bottom:4px;">Portal de usuario</h1>
        <p class="muted" style="font-size:13px;">Bienvenido/a, <strong style="color:var(--text);">{escape(actor.full_name)}</strong> &mdash; {escape(actor.role.name)}</p>
      </div>
      {verified_html}
      {render_notice(notice)}
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-top:18px;">
        <div style="padding:14px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;">
          <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:6px;">Usuario</p>
          <p style="font-weight:600;font-size:14px;">{escape(actor.full_name)}</p>
          <p style="font-size:12px;color:var(--muted);">{escape(actor.email)}</p>
        </div>
        <div style="padding:14px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;">
          <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:6px;">Rol</p>
          <p style="font-weight:600;font-size:14px;">{escape(actor.role.name)}</p>
        </div>
        <div style="padding:14px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;">
          <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:8px;">Estado</p>
          <span class="status status-{escape(actor.status)}">{escape(actor.status)}</span>
        </div>
      </div>
      <div style="margin-top:14px;padding:12px 14px;background:var(--surface-2);border:1px solid var(--border);border-radius:8px;">
        <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:5px;">Permisos efectivos</p>
        <p style="font-size:12px;font-family:'Courier New',monospace;word-break:break-word;color:var(--text);">{escape(permission_text)}</p>
      </div>
      <div id="certificados">{cert_section}</div>
    </div>
    {role_content}
    <div id="beneficiarios">{demo_section}</div>
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
    return base_page("Portal \u00b7 Casa Monarca", body, actor=actor)


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
    <details class="collapsible-panel">
      <summary><h2>Beneficiarios</h2><span class="summary-button">Abrir</span></summary>
      <div class="panel-body" style="padding:16px 20px 24px;">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:20px;">
          <div style="padding:14px;background:#f0fdf4;border:1px solid #86efac;border-radius:10px;">
            <p style="font-size:24px;font-weight:700;color:#166534;line-height:1;">{len(activos)}</p>
            <p style="font-size:11px;font-weight:600;color:#166534;margin-top:4px;">Activos</p>
          </div>
          <div style="padding:14px;background:#eff6ff;border:1px solid #93c5fd;border-radius:10px;">
            <p style="font-size:24px;font-weight:700;color:#1d4ed8;line-height:1;">{len(bens)}</p>
            <p style="font-size:11px;font-weight:600;color:#1d4ed8;margin-top:4px;">Total</p>
          </div>
          <div style="padding:14px;background:#fef3c7;border:1px solid #fcd34d;border-radius:10px;">
            <p style="font-size:24px;font-weight:700;color:#92400e;line-height:1;">{len(en_rev)}</p>
            <p style="font-size:11px;font-weight:600;color:#92400e;margin-top:4px;">En revisi&oacute;n</p>
          </div>
          <div style="padding:14px;background:#f0fdf4;border:1px solid #86efac;border-radius:10px;">
            <p style="font-size:24px;font-weight:700;color:#166534;line-height:1;">{len(nuevos)}</p>
            <p style="font-size:11px;font-weight:600;color:#166534;margin-top:4px;">Nuevos</p>
          </div>
        </div>
        <details style="margin-bottom:20px;border:1px solid #e5ddd3;border-radius:8px;padding:14px 16px;">
          <summary style="cursor:pointer;font-size:13px;font-weight:600;color:#1a2332;list-style:none;">+ Registrar nuevo beneficiario</summary>
          <form method="post" action="/ui/beneficiarios" style="margin-top:14px;">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
              <label style="display:flex;flex-direction:column;gap:4px;">Nombre completo
                <input name="nombre_completo" placeholder="Apellido Apellido, Nombre" required style="margin-top:0;">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">Pa&iacute;s de origen
                <input name="pais_origen" placeholder="Honduras, Guatemala, Venezuela..." required style="margin-top:0;">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;">&Aacute;rea
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
                <input name="notas" placeholder="Situaci&oacute;n general..." style="margin-top:0;">
              </label>
            </div>
            <button type="submit" style="background:var(--accent);color:#fff;padding:9px 20px;border-radius:8px;font-size:13px;font-weight:600;border:none;cursor:pointer;">Registrar</button>
          </form>
        </details>
        <div style="border:1px solid #e5ddd3;border-radius:8px;overflow:hidden;">
          {rows or '<p style="padding:14px;font-size:13px;color:#6b7280;">Sin registros a&uacute;n.</p>'}
        </div>
      </div>
    </details>
    """


def render_dashboard(actor, users, roles, permissions, logs, backup_admin, certificate_history, notice: str | None = None, beneficiarios=None) -> str:
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

    user_rows = []
    for user in users:
        user_uses_crypto = role_requires_crypto(user)
        activation_form = "<span class='muted'>Sin cambios pendientes</span>"
        if can_activate and user.status in {"pending", "revoked"}:
            needs_new_secret = user_uses_crypto and user.status == "revoked" or (not user_uses_crypto and not user.password_hash)
            if user_uses_crypto:
                secret_field = f"""
                <div>
                  <label style="font-size:12px;font-weight:600;color:var(--muted);display:block;margin-bottom:4px;">
                    Clave para el nuevo .p12
                  </label>
                  <input type="password" name="new_secret" placeholder="Escribe una contrase&ntilde;a para proteger el archivo .p12"
                    style="width:100%;" {'required' if needs_new_secret else ''}>
                  <p style="font-size:11px;color:var(--muted);margin-top:4px;">
                    Se generar&aacute; un nuevo certificado X.509 y un paquete .p12 protegido con esta clave. Ent&eacute;gasela al usuario para que pueda iniciar sesi&oacute;n.
                  </p>
                </div>
                """
            else:
                secret_field = f"""
                <div>
                  <label style="font-size:12px;font-weight:600;color:var(--muted);display:block;margin-bottom:4px;">
                    Nueva contrase&ntilde;a de acceso
                  </label>
                  <input type="password" name="new_secret" placeholder="Contrase&ntilde;a que usar&aacute; el usuario para entrar"
                    style="width:100%;" {'required' if needs_new_secret else ''}>
                </div>
                """
            activation_form = f"""
            <form method="post" action="/ui/users/{user.id}/status" class="inline-form">

              <input type="hidden" name="status" value="active">
              {secret_field}
              <button type="submit">Activar</button>
            </form>
            """

        revoke_form = "<span class='muted'>Sin accion</span>"
        if can_revoke and user.status != "revoked":
            revoke_form = f"""
            <form method="post" action="/ui/users/{user.id}/status" class="inline-form">

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
                  <p style="font-weight:600;margin-bottom:3px;">Sellada criptogr&aacute;ficamente</p>
                  <p>La vigencia de este usuario est&aacute; fijada en su certificado X.509 y no puede modificarse. Para extender el acceso, revocar la cuenta y re-emitir un nuevo certificado desde la secci&oacute;n <strong>Credencial</strong>.</p>
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

              <select name="role_id">
                {''.join(f"<option value='{role.id}' {'selected' if role.id == user.role_id else ''}>{escape(role.name)}</option>" for role in roles)}
              </select>
              <input type="password" name="new_secret" placeholder="Clave .p12 si cambias a rol criptografico">
              <button type="submit">Guardar rol</button>
            </form>
            """

        account_note = "Acceso vigente"
        if user.status == "revoked":
            account_note = (
                "La revocacion bloquea de inmediato el acceso. En roles criptograficos se recomienda reemitir un nuevo .p12 al reactivar."
                if user_uses_crypto
                else "La revocacion borra la contrasena almacenada y obliga a definir una nueva para reactivar."
            )
        elif user.status == "pending":
            account_note = "La cuenta existe pero todavia no puede entrar."
        elif user.status == "expired":
            account_note = "Actualiza la vigencia para que la cuenta vuelva a active."

        certificate_section = "<p class='muted'>Acceso solo con usuario y contrasena.</p>"
        if user_uses_crypto:
            if user.certificate_serial and (user.p12_base64 or user.p12_path):
                expires_text = (
                    escape(user.certificate_not_after.isoformat(sep=' ', timespec='minutes'))
                    if user.certificate_not_after
                    else "n/a"
                )
                certificate_section = f"""
                <div class="stack">
                  <p class="muted">Login con `.p12` activo para este usuario.</p>
                  <p>Serial: <code>{escape(user.certificate_serial)}</code></p>
                  <p>Vence: {expires_text}</p>
                  <div class="mini-links">
                    <a href="/ui/users/{user.id}/certificate/view?as_user={actor.id}">Ver</a>
                    <a href="/ui/users/{user.id}/certificate.pem?as_user={actor.id}">PEM</a>
                    <a href="/ui/users/{user.id}/certificate.p12?as_user={actor.id}">.p12</a>
                  </div>
                </div>
                """
            else:
                certificate_section = f"""
                <form method="post" action="/ui/users/{user.id}/certificate" class="inline-form">

                  <input type="password" name="credential_secret" placeholder="Contrasena .p12" required>
                  <button type="submit">Emitir certificado</button>
                </form>
                """

        summary_expiration = expiration_text
        row_hint = "Admin/coordinador con .p12" if user_uses_crypto else "Password local"

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
                  <h4>Credencial</h4>
                  {certificate_section}
                </section>
              </div>
            </details>
            """
        )

    create_form = ""
    if can_create:
        create_form = f"""
        <details class="collapsible-panel">
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
              <span class="muted" style="font-weight:400;font-size:12px;margin-top:-2px;">O clave .p12 para roles criptogr&aacute;ficos</span>
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
          <strong>{escape(user.full_name)}</strong> · {escape(user.role.name)} ·
          <a href="/ui/users/{user.id}/certificate/view?as_user={actor.id}">Ver</a> ·
          <a href="/ui/users/{user.id}/certificate.pem?as_user={actor.id}">PEM</a> ·
          <a href="/ui/users/{user.id}/certificate.p12?as_user={actor.id}">.p12</a>
        </li>
        """
        for user in certificate_history
    ) or "<li>No hay certificados legacy registrados.</li>"

    log_items = "\n".join(
        f"<li style='padding:6px 0;border-bottom:1px solid var(--border);'><strong style='color:var(--text);'>{escape(log.event_type)}</strong> &middot; <span class='muted'>{escape(log.result)}</span> &middot; objetivo {log.target_user_id or '-'}</li>"
        for log in logs
    ) or "<li>Sin eventos todav&iacute;a.</li>"

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
            --accent: #a64b2a;
            --accent-dark: #8a3d22;
            --accent-light: #fdf0eb;
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
          body {{ background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 14px; line-height: 1.6; -webkit-font-smoothing: antialiased; display: flex; min-height: 100vh; }}
          /* ── Sidebar ── */
          .sidebar {{ width:230px; flex-shrink:0; background:#1a2332; display:flex; flex-direction:column; position:fixed; top:0; left:0; bottom:0; z-index:100; overflow-y:auto; }}
          .sidebar-brand {{ padding:22px 20px 18px; border-bottom:1px solid rgba(255,255,255,0.07); }}
          .sidebar-brand-logo {{ display:flex; align-items:center; gap:10px; margin-bottom:6px; }}
          .sidebar-brand-text {{ line-height:1.2; }}
          .sidebar-brand-name {{ font-size:15px; font-weight:800; color:#fff; letter-spacing:-0.3px; }}
          .sidebar-brand-sub {{ font-size:10px; color:#8b9ab0; text-transform:uppercase; letter-spacing:.08em; font-weight:500; }}
          .sidebar-tagline {{ font-size:11px; color:#8b9ab0; line-height:1.4; margin-top:6px; }}
          .sidebar-nav {{ flex:1; padding:16px 12px; display:flex; flex-direction:column; gap:2px; }}
          .sidebar-section-label {{ font-size:10px; font-weight:700; color:#8b9ab0; text-transform:uppercase; letter-spacing:.1em; padding:10px 8px 4px; margin-top:6px; }}
          .sidebar-link {{ display:flex; align-items:center; gap:9px; padding:8px 10px; border-radius:8px; color:#e8e4de; font-size:13px; font-weight:500; text-decoration:none; transition:background .15s; border-left:2px solid transparent; }}
          .sidebar-link:hover {{ background:rgba(255,255,255,0.07); color:#fff; text-decoration:none; }}
          .sidebar-link.active {{ background:rgba(209,20,90,0.18); border-left-color:#d1145a; color:#fff; }}
          .sidebar-link svg {{ flex-shrink:0; opacity:.7; }}
          .sidebar-link.active svg {{ opacity:1; }}
          .sidebar-footer {{ padding:16px 12px; border-top:1px solid rgba(255,255,255,0.07); }}
          .sidebar-logout {{ display:flex; align-items:center; gap:8px; color:#8b9ab0; font-size:12px; font-weight:500; text-decoration:none; padding:6px 8px; border-radius:7px; transition:color .15s,background .15s; }}
          .sidebar-logout:hover {{ color:#fff; background:rgba(255,255,255,0.07); text-decoration:none; }}
          .sidebar-user {{ padding:14px 16px 0; }}
          .sidebar-user-name {{ font-size:13px; font-weight:600; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
          .sidebar-user-role {{ font-size:11px; color:#8b9ab0; margin-top:2px; }}
          /* ── Page wrapper ── */
          .page-wrapper {{ margin-left:230px; flex:1; min-width:0; }}
          main {{ max-width:1200px; margin:0 auto; padding:28px 20px 64px; display:flex; flex-direction:column; gap:18px; }}
          @media (max-width:700px) {{ .sidebar {{ display:none; }} .page-wrapper {{ margin-left:0; }} }}
          h1 {{ font-size: 20px; font-weight: 700; letter-spacing: -0.3px; line-height: 1.3; }}
          h2 {{ font-size: 15px; font-weight: 600; letter-spacing: -0.1px; line-height: 1.4; }}
          p {{ margin: 0; }}
          .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); }}
          .panel {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); padding: 20px; }}
          .hero {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: var(--shadow); padding: 24px 28px; }}
          .grid {{ display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }}
          .stack {{ display: flex; flex-direction: column; gap: 10px; }}
          label {{ display: flex; flex-direction: column; gap: 5px; font-size: 13px; font-weight: 500; }}
          input, select {{ font: inherit; font-size: 14px; padding: 8px 11px; border-radius: var(--radius); border: 1px solid var(--border-strong); background: var(--surface); color: var(--text); transition: border-color .15s, box-shadow .15s; outline: none; width: 100%; }}
          input:focus, select:focus {{ border-color: var(--accent); box-shadow: 0 0 0 3px rgba(166,75,42,0.12); }}
          input[type="file"] {{ padding: 6px 10px; cursor: pointer; background: var(--surface-2); }}
          button {{ font: inherit; font-size: 13px; font-weight: 600; padding: 8px 16px; border-radius: var(--radius); border: none; cursor: pointer; transition: background .15s; background: var(--accent); color: #fff; }}
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
          .summary-name strong {{ font-size: 14px; font-weight: 600; }}
          .summary-name small {{ font-size: 12px; color: var(--muted); overflow-wrap: anywhere; }}
          .summary-button {{ background: var(--accent-light); color: var(--accent); border-radius: 999px; padding: 5px 12px; font-size: 12px; font-weight: 600; white-space: nowrap; border: 1px solid #f0d4c5; }}
          .user-row-body {{ display: grid; gap: 1px; background: var(--border); border-top: 1px solid var(--border); grid-template-columns: repeat(4, minmax(0, 1fr)); }}
          .control-panel {{ background: var(--surface-2); padding: 16px; min-width: 0; }}
          .control-panel h4 {{ font-size: 11px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); margin-bottom: 10px; }}
          .panel-body {{ padding: 0 20px 20px; display: flex; flex-direction: column; gap: 10px; }}
          .muted {{ color: var(--muted); font-size: 13px; }}
          .mini-links {{ display: flex; flex-wrap: wrap; gap: 10px; }}
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
          }}
        </style>
      </head>
      <body>
        <aside class="sidebar">
          <div class="sidebar-brand">
            <div class="sidebar-brand-logo">
              <svg width="32" height="28" viewBox="0 0 80 64" fill="none" xmlns="http://www.w3.org/2000/svg"><ellipse cx="20" cy="22" rx="19" ry="14" fill="#d1145a" transform="rotate(-20 20 22)"/><ellipse cx="14" cy="36" rx="12" ry="8" fill="#d1145a" opacity=".7" transform="rotate(15 14 36)"/><ellipse cx="60" cy="22" rx="19" ry="14" fill="#f06b35" transform="rotate(20 60 22)"/><ellipse cx="66" cy="36" rx="12" ry="8" fill="#f06b35" opacity=".7" transform="rotate(-15 66 36)"/><ellipse cx="40" cy="32" rx="3.5" ry="18" fill="#1a2332"/><circle cx="40" cy="13" r="3" fill="#1a2332"/><line x1="40" y1="10" x2="30" y2="4" stroke="#1a2332" stroke-width="1.5" stroke-linecap="round"/><line x1="40" y1="10" x2="50" y2="4" stroke="#1a2332" stroke-width="1.5" stroke-linecap="round"/></svg>
              <div class="sidebar-brand-text">
                <div class="sidebar-brand-name">Casa Monarca</div>
                <div class="sidebar-brand-sub">Gestor de Identidades</div>
              </div>
            </div>
            <p class="sidebar-tagline">Ayuda Humanitaria al Migrante, A.B.P.</p>
          </div>
          <div class="sidebar-user">
            <div class="sidebar-user-name">{escape(actor.full_name)}</div>
            <div class="sidebar-user-role">{escape(actor.role.name)}</div>
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
            <span class="sidebar-section-label">Accesos r&aacute;pidos</span>
            <a href="/admin/register?as_user={actor.id}" class="sidebar-link">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>
              Nuevo usuario
            </a>
            <a href="/ui/ca/certificate/view?as_user={actor.id}" class="sidebar-link">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Certificado CA
            </a>
          </nav>
          <div class="sidebar-footer">
            <a href="/logout" class="sidebar-logout">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
              Salir / cambiar usuario
            </a>
          </div>
        </aside>
        <div class="page-wrapper">
        <main>
          <section class="hero">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:20px;flex-wrap:wrap;">
              <div>
                <h1 style="margin-bottom:4px;">Gestor de Identidades</h1>
                <p style="color:var(--muted);font-size:13px;">Casa Monarca &mdash; Control de identidades, certificados X.509 y auditor&iacute;a operativa</p>
              </div>
              <a href="/admin/register?as_user={actor.id}" style="display:inline-block;background:var(--accent);color:#fff;padding:8px 16px;border-radius:var(--radius);font-size:13px;font-weight:600;">+ Nuevo usuario</a>
            </div>
            <hr style="border:none;border-top:1px solid var(--border);margin:18px 0;">
            {render_notice(notice)}
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;">
              <div>
                <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:6px;">Usuario actual</p>
                <p style="font-weight:600;font-size:15px;">{escape(actor.full_name)}</p>
                <p style="font-size:12px;color:var(--muted);margin-top:2px;">{escape(actor.email)}</p>
                <span style="display:inline-block;margin-top:6px;background:var(--accent-light);color:var(--accent);border:1px solid #f0d4c5;border-radius:999px;padding:2px 9px;font-size:11px;font-weight:600;">{escape(actor.role.name)}</span>
              </div>
              <div>
                <p style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:8px;">Ver portal como</p>
                <form method="get" action="/portal" style="display:flex;gap:8px;">
                  <select name="as_user" style="flex:1;">{actor_options}</select>
                  <button type="submit" style="white-space:nowrap;padding:8px 14px;font-size:13px;">Abrir</button>
                </form>
              </div>
            </div>
          </section>

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
            <details class="collapsible-panel">
              <summary><h2>Recuperaci&oacute;n admin</h2><span class="summary-button">Abrir</span></summary>
              <div class="panel-body">{backup_section}</div>
            </details>
          </div>

          <details class="collapsible-panel">
            <summary><h2>Certificados de CA e hist&oacute;rico</h2><span class="summary-button">Abrir</span></summary>
            <div class="panel-body" style="padding:14px 20px 20px;">
              <p class="muted">ADMIN y COORDINADOR autentican con .p12. Aqu&iacute; puedes consultar el certificado de la CA y el hist&oacute;rico emitido.</p>
              <div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:8px;">
                <a href="/ui/ca/certificate/view?as_user={actor.id}">Ver certificado CA</a>
                <a href="/ui/ca/certificate?as_user={actor.id}">Descargar certificado CA (.pem)</a>
              </div>
              <ul style="margin-top:12px;font-size:13px;">{certificate_rows}</ul>
            </div>
          </details>

          {create_form}

          <div class="card" style="overflow:hidden;">
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
              <div id="no-results" style="display:none;text-align:center;padding:32px 20px;color:var(--muted);">
                <p>No se encontraron usuarios con esos filtros.</p>
              </div>
              {''.join(user_rows)}
            </div>
          </div>

          <details class="collapsible-panel">
            <summary><h2>Auditor&iacute;a reciente</h2><span class="summary-button">Abrir</span></summary>
            <div class="panel-body" style="padding:10px 20px 20px;">
              <ul style="font-size:13px;">{log_items}</ul>
            </div>
          </details>

          {_render_beneficiarios_admin(actor, beneficiarios or [])}

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

    voluntario_role = db.scalar(select(Role).where(Role.code == "VOLUNTARIO"))
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
    identifier: str = Form(...),
    password: str = Form(...),
    p12_file: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
):
    if identifier.strip().lower() == "admin" and password == "admin" and (p12_file is None or not p12_file.filename):
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
        )
        resp = RedirectResponse(url="/dashboard", status_code=303)
        return _login_redirect(resp, admin.id)

    try:
        p12_bytes = b""
        if p12_file is not None and p12_file.filename:
            p12_bytes = await p12_file.read()

        if p12_bytes:
            user, proof = SignatureLoginService.authenticate_with_p12(
                db,
                identifier=identifier,
                p12_bytes=p12_bytes,
                password=password,
            )
            AuditService.log(
                db,
                event_type="login_signature_verified",
                actor_user_id=user.id,
                target_user_id=user.id,
                action="login_with_p12",
                resource="auth",
                result="success",
                metadata=proof,
            )
            if is_active_admin(user):
                resp = RedirectResponse(url=f"/dashboard?notice=crypto-login", status_code=303)
            else:
                resp = RedirectResponse(url=f"/portal?verified=1&notice=crypto-login", status_code=303)
            return _login_redirect(resp, user.id)

        user = PasswordLoginService.authenticate_user(db, identifier=identifier, password=password)
    except ValueError as exc:
        AuditService.log(
            db,
            event_type="login_rejected",
            action="login_with_p12" if p12_file is not None and p12_file.filename else "login_with_password",
            resource="auth",
            result="failure",
            metadata={"identifier": identifier.strip().lower(), "reason": str(exc)},
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
    )

    dest = "/dashboard" if is_active_admin(user) else "/portal"
    resp = RedirectResponse(url=dest, status_code=303)
    return _login_redirect(resp, user.id)


@app.get("/portal", response_class=HTMLResponse)
def user_portal(
    notice: str | None = Query(default=None),
    verified: bool = Query(default=False),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    permissions = AuthorizationService.get_permissions(db, actor)
    logs = AuditService.list_recent(db)
    beneficiarios = BeneficiarioService.list_all(db)
    return HTMLResponse(render_portal_page(actor, permissions, logs, notice=notice, verified=verified, beneficiarios=beneficiarios))


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
    resp = RedirectResponse(url="/portal?notice=beneficiario-creado", status_code=303)
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


@app.get("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(_SESSION_COOKIE)
    return resp


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    notice: str | None = Query(default=None),
    db: Session = Depends(get_db),
    actor=Depends(_get_session_actor),
):
    if not is_active_admin(actor):
        # Non-admins that somehow land on /dashboard get sent to portal
        resp = RedirectResponse(url="/portal", status_code=303)
        return _login_redirect(resp, actor.id)

    permissions = AuthorizationService.get_permissions(db, actor)
    logs = AuditService.list_recent(db)
    users = UserService.list_users(db)
    roles = UserService.list_roles(db)
    backup_admin = AdminRecoveryService.get_backup_admin(db)
    certificate_history = UserService.list_certificate_history(db)
    return HTMLResponse(render_dashboard(actor, users, roles, permissions, logs, backup_admin, certificate_history, notice, beneficiarios=BeneficiarioService.list_all(db)))


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

    try:
        updated = UserService.update_status(db, target, status, new_secret)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

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
    return redirect_home(actor.id, "status-updated")


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
    return redirect_home(actor.id, "expiration-updated")


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
    return redirect_home(actor.id, "role-updated")


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
    return redirect_home(actor.id, "certificate-issued")


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


@app.get("/ui/users/{user_id}/certificate.p12")
def download_p12(user_id: int, db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    _require_own_or_admin(actor, user_id)
    require_actor_permission(db, actor, "certificates", "view")
    user = UserService.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Certificate package not found")

    p12_bytes = CertificateService.get_user_p12_bytes(db, user)
    if not p12_bytes:
        raise HTTPException(status_code=404, detail="Certificate package file not found")

    return Response(
        content=p12_bytes,
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f'attachment; filename="{user.email.replace("@", "_")}.p12"'},
    )


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
    return HTMLResponse(render_certificate_page(f"Certificado legacy de {user.full_name}", summary, back_href))


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


@app.get("/ui/ca/certificate/view", response_class=HTMLResponse)
def view_ca_certificate(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    require_actor_permission(db, actor, "certificates", "view")
    summary = CertificateAuthorityService.describe_ca_certificate(db)
    back_href = "/dashboard" if is_active_admin(actor) else "/portal"
    return HTMLResponse(render_certificate_page("Certificado legacy de la CA interna", summary, back_href))


@app.get("/ui/ca/certificate")
def download_ca_certificate(db: Session = Depends(get_db), actor=Depends(_get_session_actor)):
    require_actor_permission(db, actor, "certificates", "view")
    return Response(
        content=CertificateAuthorityService.get_ca_certificate_pem(db),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="casa-monarca-demo-ca.crt.pem"'},
    )
