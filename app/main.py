from contextlib import asynccontextmanager
from datetime import datetime
from html import escape
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Base, engine
from app.deps import get_db
from app.schemas import AuditLogOut, MeOut, UserOut
from app.services import (
    AuditService,
    AuthorizationService,
    BootstrapService,
    CertificateAuthorityService,
    CertificateService,
    PasswordLoginService,
    SignatureLoginService,
    UserService,
    role_requires_crypto,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    with Session(bind=engine) as db:
        BootstrapService.seed(db)
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)


def parse_end_date(value: str) -> datetime | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    return datetime.fromisoformat(cleaned)


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


def redirect_home(actor_id: int) -> RedirectResponse:
    return RedirectResponse(url=f"/dashboard?{urlencode({'as_user': actor_id})}", status_code=303)


def is_active_admin(actor) -> bool:
    return actor.status == "active" and actor.role.code == "ADMIN"


def render_certificate_page(title: str, summary: dict, back_href: str) -> str:
    san_items = "".join(f"<li>{escape(item)}</li>" for item in summary["san_emails"]) or "<li>Sin SAN de correo.</li>"
    return f"""
    <!doctype html>
    <html lang="es">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{escape(title)}</title>
        <style>
          :root {{
            --bg: #f5efe2;
            --card: #fffdf8;
            --ink: #1f2b37;
            --line: #dfd4c0;
            --accent: #a64b2a;
          }}
          * {{ box-sizing: border-box; }}
          body {{ margin: 0; background: linear-gradient(180deg, #efe3d0, var(--bg)); color: var(--ink); font-family: Georgia, serif; }}
          main {{ max-width: 980px; margin: 0 auto; padding: 28px 18px 52px; }}
          .panel {{ background: var(--card); border: 1px solid var(--line); border-radius: 20px; box-shadow: 0 12px 32px rgba(31, 43, 55, 0.08); padding: 22px; }}
          .topbar {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }}
          .back-link {{ color: var(--accent); font-weight: 700; text-decoration: none; }}
          dl {{ display: grid; grid-template-columns: 180px 1fr; gap: 10px 14px; margin: 22px 0; }}
          dt {{ font-weight: 700; }}
          dd {{ margin: 0; word-break: break-word; }}
          code, pre {{ background: #f6efe2; border-radius: 12px; }}
          code {{ padding: 3px 6px; }}
          pre {{ padding: 14px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }}
          ul {{ margin: 0; padding-left: 18px; }}
          details {{ margin-top: 20px; }}
          @media (max-width: 700px) {{
            dl {{ grid-template-columns: 1fr; }}
          }}
        </style>
      </head>
      <body>
        <main>
          <section class="panel">
            <div class="topbar">
              <h1>{escape(title)}</h1>
              <a class="back-link" href="{escape(back_href)}">Volver</a>
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
            <h2>SAN</h2>
            <ul>{san_items}</ul>
            <details>
              <summary>Ver PEM completo</summary>
              <pre>{escape(summary["pem"])}</pre>
            </details>
          </section>
        </main>
      </body>
    </html>
    """


def base_page(title: str, body: str) -> str:
    return f"""
    <!doctype html>
    <html lang="es">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{escape(title)}</title>
        <style>
          :root {{
            --bg: #f5efe2;
            --card: #fffdf8;
            --ink: #1f2b37;
            --line: #dfd4c0;
            --accent: #a64b2a;
            --ok: #287346;
            --bad: #922f2f;
          }}
          * {{ box-sizing: border-box; }}
          body {{ margin: 0; background: linear-gradient(180deg, #efe3d0, var(--bg)); color: var(--ink); font-family: Georgia, serif; }}
          main {{ max-width: 980px; margin: 0 auto; padding: 28px 18px 52px; }}
          .panel {{ background: var(--card); border: 1px solid var(--line); border-radius: 20px; box-shadow: 0 12px 32px rgba(31, 43, 55, 0.08); padding: 22px; }}
          .stack {{ display: grid; gap: 12px; }}
          .grid {{ display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }}
          label {{ display: grid; gap: 6px; font-size: 14px; }}
          input, select, button {{ font: inherit; padding: 10px 12px; border-radius: 10px; border: 1px solid #c9bca9; }}
          button {{ background: var(--accent); color: #fff; border: none; cursor: pointer; }}
          a {{ color: var(--accent); font-weight: 700; text-decoration: none; }}
          a:hover {{ text-decoration: underline; }}
          .error {{ background: #f8dfdf; border: 1px solid #e4a5a5; color: var(--bad); border-radius: 12px; padding: 10px 12px; }}
          .ok {{ background: #ddf3e4; border: 1px solid #a7d8b7; color: var(--ok); border-radius: 12px; padding: 10px 12px; }}
          .muted {{ opacity: 0.76; }}
          code {{ word-break: break-all; background: #f6efe2; border-radius: 8px; padding: 2px 5px; }}
        </style>
      </head>
      <body>
        <main>{body}</main>
      </body>
    </html>
    """


def render_login_page(error: str | None = None) -> str:
    error_html = f"<div class='error'>{escape(error)}</div>" if error else ""
    body = f"""
    <section class="panel">
      <h1>Login</h1>
      <p class="muted">Administradores y coordinadores entran con `.p12`; voluntarios entran solo con correo y contrasena. Para pruebas, tambien puedes usar <code>admin</code> / <code>admin</code>.</p>
      {error_html}
      <form method="post" action="/login" enctype="multipart/form-data" class="stack">
        <label>Correo o usuario demo<input name="email" required></label>
        <label>Archivo .p12 para admin/coordinador<input name="p12_file" type="file" accept=".p12,.pfx"></label>
        <label>Contrasena<input name="p12_password" type="password" required></label>
        <button type="submit">Entrar</button>
      </form>
    </section>
    """
    return base_page("Login", body)


def render_admin_register_page(actor, roles, error: str | None = None) -> str:
    role_options = "".join(f"<option value='{role.id}'>{escape(role.name)}</option>" for role in roles)
    error_html = f"<div class='error'>{escape(error)}</div>" if error else ""
    body = f"""
    <section class="panel">
      <h1>Otorgar registro</h1>
      <p class="muted">Administrador actual: <strong>{escape(actor.full_name)}</strong>. Administradores y coordinadores reciben `.p12`; voluntarios reciben solo contrasena local.</p>
      {error_html}
      <form method="post" action="/admin/register" class="stack">
        <input type="hidden" name="actor_id" value="{actor.id}">
        <label>Nombre completo<input name="full_name" required></label>
        <label>Correo<input name="email" type="email" required></label>
        <label>Rol<select name="role_id">{role_options}</select></label>
        <label>Fecha de expiracion<input name="end_date" type="datetime-local"></label>
        <label>Contrasena de usuario o .p12<input name="p12_password" type="password" required></label>
        <button type="submit">Crear usuario</button>
      </form>
      <p><a href="/dashboard?as_user={actor.id}">Volver</a></p>
    </section>
    """
    return base_page("Otorgar registro", body)


def render_portal_page(actor, permissions, logs, verified: bool = False) -> str:
    permission_text = ", ".join(f"{item['resource']}:{item['action']}" for item in permissions) or "sin permisos"
    verified_html = "<div class='ok'>Identidad verificada con firma digital del .p12.</div>" if verified else ""

    if actor.status != "active":
        role_content = f"<div class='error'>Tu cuenta esta en estado {escape(actor.status)}. No puedes operar todavia.</div>"
    elif actor.role.code == "ADMIN":
        role_content = f"""
        <div class="grid">
          <article class="panel">
            <h2>Administracion</h2>
            <p>Puedes otorgar registros, emitir certificados, cambiar roles y revisar auditoria.</p>
            <p><a href="/admin/register?as_user={actor.id}">Otorgar registro</a></p>
            <p><a href="/dashboard?as_user={actor.id}">Abrir panel administrador</a></p>
          </article>
          <article class="panel">
            <h2>Auditoria reciente</h2>
            <p>Eventos visibles: <strong>{len(logs)}</strong></p>
          </article>
        </div>
        """
    elif actor.role.code == "COORDINADOR":
        role_content = """
        <div class="panel">
          <h2>Vista Coordinador</h2>
          <p>Puedes consultar y editar documentos operativos de la demo.</p>
        </div>
        """
    elif actor.role.code == "VOLUNTARIO":
        role_content = """
        <div class="panel">
          <h2>Vista Voluntario</h2>
          <p>Acceso basico a la informacion visible para voluntarios. No requiere certificado criptografico.</p>
        </div>
        """
    else:
        role_content = "<div class='error'>Rol no reconocido para esta demo.</div>"

    cert_link = ""
    if role_requires_crypto(actor) and actor.certificate_serial:
        cert_link = f"<p><a href='/ui/users/{actor.id}/certificate/view?as_user={actor.id}'>Ver mi certificado</a></p>"

    body = f"""
    <section class="panel">
      <h1>Portal de usuario</h1>
      {verified_html}
      <p><strong>{escape(actor.full_name)}</strong> · {escape(actor.email)}</p>
      <p>Rol: <strong>{escape(actor.role.name)}</strong></p>
      <p>Estado: <strong>{escape(actor.status)}</strong></p>
      <p>Permisos efectivos: {escape(permission_text)}</p>
      {cert_link}
      <p><a href="/login">Salir / cambiar usuario</a></p>
    </section>
    {role_content}
    """
    return base_page("Portal de usuario", body)


def render_dashboard(actor, users, roles, permissions, logs) -> str:
    permission_text = ", ".join(f"{item['resource']}:{item['action']}" for item in permissions) or "sin permisos"
    ca_download_url = "/ui/ca/certificate"

    actor_options = "".join(
        f"<option value='{user.id}' {'selected' if user.id == actor.id else ''}>{escape(user.full_name)} ({escape(user.status)})</option>"
        for user in users
    )
    create_role_options = "".join(
        f"<option value='{role.id}'>{escape(role.name)}</option>"
        for role in roles
    )

    can_create = any(item["resource"] == "users" and item["action"] == "create" for item in permissions)
    can_activate = any(item["resource"] == "users" and item["action"] == "activate" for item in permissions)
    can_revoke = any(item["resource"] == "users" and item["action"] == "revoke" for item in permissions)
    can_change_role = any(item["resource"] == "users" and item["action"] == "change_role" for item in permissions)

    user_cards = []
    for user in users:
        user_uses_crypto = role_requires_crypto(user)
        status_forms = []
        if can_activate and user.status in {"pending", "revoked"}:
            status_forms.append(
                f"""
                <form method="post" action="/ui/users/{user.id}/status">
              <input type="hidden" name="actor_id" value="{actor.id}">
              <input type="hidden" name="status" value="active">
              <button type="submit" class="compact-button">Activar</button>
            </form>
            """
        )
        if can_revoke and user.status != "revoked":
            status_forms.append(
                f"""
                <form method="post" action="/ui/users/{user.id}/status">
              <input type="hidden" name="actor_id" value="{actor.id}">
              <input type="hidden" name="status" value="revoked">
              <button type="submit" class="compact-button">Revocar</button>
            </form>
            """
        )

        expiration_text = (
            escape(user.end_date.isoformat(sep=" ", timespec="minutes"))
            if user.end_date
            else "sin vencimiento"
        )
        expiration_form = ""
        if can_activate:
            expiration_value = user.end_date.strftime("%Y-%m-%dT%H:%M") if user.end_date else ""
            crypto_password_input = (
                '<input type="password" name="p12_password" placeholder="Nueva contrasena .p12" required>'
                if user_uses_crypto
                else ""
            )
            expiration_form = f"""
            <form method="post" action="/ui/users/{user.id}/expiration" class="inline-form expiration-form">
              <input type="hidden" name="actor_id" value="{actor.id}">
              <input type="datetime-local" name="end_date" value="{expiration_value}" required>
              {crypto_password_input}
              <button type="submit">Guardar vigencia</button>
            </form>
            """

        role_form = "rol fijo"
        if can_change_role:
            role_form = f"""
            <form method="post" action="/ui/users/{user.id}/role" class="inline-form">
              <input type="hidden" name="actor_id" value="{actor.id}">
              <select name="role_id">
                {''.join(f"<option value='{role.id}' {'selected' if role.id == user.role_id else ''}>{escape(role.name)}</option>" for role in roles)}
              </select>
              <button type="submit">Guardar rol</button>
            </form>
            """

        certificate_block = "Voluntario: no requiere certificado"
        if user_uses_crypto and user.certificate_serial and user.p12_path:
            certificate_block = f"""
            <div class="certificate-box">
              <div>Serial: <code>{escape(user.certificate_serial)}</code></div>
              <div>Vence: {escape(user.certificate_not_after.isoformat(sep=' ', timespec='minutes')) if user.certificate_not_after else 'n/a'}</div>
              <div class="download-links">
                <a href="/ui/users/{user.id}/certificate/view?as_user={actor.id}">Ver</a>
                <a href="/ui/users/{user.id}/certificate.pem?as_user={actor.id}">PEM</a>
                <a href="/ui/users/{user.id}/certificate.p12?as_user={actor.id}">.p12</a>
              </div>
            </div>
            """
        elif user_uses_crypto and can_create:
            certificate_block = f"""
            <form method="post" action="/ui/users/{user.id}/certificate" class="inline-form">
              <input type="hidden" name="actor_id" value="{actor.id}">
              <input type="password" name="p12_password" placeholder="Contrasena .p12" required>
              <button type="submit">Emitir certificado</button>
            </form>
            """

        account_actions = "".join(status_forms) or "<span class='muted'>Sin acciones</span>"
        user_cards.append(
            f"""
            <article class="user-card">
              <header class="user-card-header">
                <div>
                  <h3>{escape(user.full_name)}</h3>
                  <p>{escape(user.email)}</p>
                </div>
                <span class="status status-{escape(user.status)}">{escape(user.status)}</span>
              </header>

              <div class="user-summary">
                <div class="fact">
                  <span class="label">Rol</span>
                  <strong>{escape(user.role.name)}</strong>
                </div>
                <div class="fact">
                  <span class="label">Expira</span>
                  <strong>{expiration_text}</strong>
                </div>
              </div>

              <div class="user-controls">
                <section class="control-panel">
                  <h4>Cuenta</h4>
                  <div class="button-row">{account_actions}</div>
                </section>
                <section class="control-panel">
                  <h4>Vigencia</h4>
                  {expiration_form or "<span class='muted'>Sin permiso</span>"}
                </section>
                <section class="control-panel">
                  <h4>Rol</h4>
                  {role_form}
                </section>
                <section class="control-panel certificate-section">
                  <h4>Certificado</h4>
                  {certificate_block}
                </section>
              </div>
            </article>
            """
        )

    create_form = ""
    if can_create:
        create_form = f"""
        <section class="panel">
          <h2>Crear preregistro con certificado</h2>
          <form method="post" action="/ui/users" class="stack">
            <input type="hidden" name="actor_id" value="{actor.id}">
            <label>Nombre completo<input name="full_name" required></label>
            <label>Correo<input name="email" type="email" required></label>
            <label>Rol<select name="role_id">{create_role_options}</select></label>
            <label>Fecha de expiracion<input name="end_date" type="datetime-local"></label>
            <label>Contrasena de usuario o .p12<input name="p12_password" type="password" required></label>
            <button type="submit">Crear usuario</button>
          </form>
        </section>
        """

    log_items = "".join(
        f"<li><strong>{escape(log.event_type)}</strong> · {escape(log.result)} · objetivo {log.target_user_id or '-'} </li>"
        for log in logs
    ) or "<li>Sin eventos todavia.</li>"

    return f"""
    <!doctype html>
    <html lang="es">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{escape(settings.app_name)}</title>
        <style>
          :root {{
            --bg: #f5efe2;
            --card: #fffdf8;
            --ink: #1f2b37;
            --line: #dfd4c0;
            --accent: #a64b2a;
            --ok: #287346;
            --warn: #aa6a1f;
            --bad: #922f2f;
          }}
          * {{ box-sizing: border-box; }}
          body {{ margin: 0; background: linear-gradient(180deg, #efe3d0, var(--bg)); color: var(--ink); font-family: Georgia, serif; }}
          main {{ max-width: 1280px; margin: 0 auto; padding: 28px 18px 52px; }}
          .hero, .panel {{ background: var(--card); border: 1px solid var(--line); border-radius: 20px; box-shadow: 0 12px 32px rgba(31, 43, 55, 0.08); }}
          .hero {{ padding: 26px; }}
          .panel {{ padding: 18px; }}
          .grid {{ display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); margin-top: 18px; }}
          .stack {{ display: grid; gap: 10px; }}
          label {{ display: grid; gap: 6px; font-size: 14px; }}
          input, select, button {{ font: inherit; padding: 10px 12px; border-radius: 10px; border: 1px solid #c9bca9; }}
          button {{ background: var(--accent); color: #fff; border: none; cursor: pointer; }}
          .status {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-weight: 700; font-size: 12px; }}
          .status-active {{ background: #ddf3e4; color: var(--ok); }}
          .status-pending {{ background: #fff0dc; color: var(--warn); }}
          .status-revoked, .status-expired {{ background: #f8dfdf; color: var(--bad); }}
          .inline-form {{ display: grid; gap: 8px; }}
          .inline-form input, .inline-form select, .inline-form button {{ min-width: 0; width: 100%; }}
          .users-grid {{ display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); }}
          .user-card {{ display: grid; gap: 14px; min-width: 0; background: #fffaf1; border: 1px solid #eadcc8; border-radius: 18px; padding: 16px; }}
          .user-card-header {{ display: flex; justify-content: space-between; gap: 14px; align-items: flex-start; }}
          .user-card-header h3 {{ margin: 0; font-size: 22px; line-height: 1.05; }}
          .user-card-header p {{ margin: 6px 0 0; overflow-wrap: anywhere; }}
          .user-summary {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }}
          .fact {{ min-width: 0; background: #f6efe2; border-radius: 14px; padding: 10px 12px; overflow-wrap: anywhere; }}
          .label {{ display: block; margin-bottom: 3px; font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; opacity: 0.65; }}
          .user-controls {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
          .control-panel {{ min-width: 0; border-top: 1px solid #efe4d3; padding-top: 10px; }}
          .control-panel h4 {{ margin: 0 0 8px; font-size: 14px; letter-spacing: 0.04em; text-transform: uppercase; opacity: 0.72; }}
          .button-row {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
          .button-row form {{ margin: 0; }}
          .compact-button {{ padding: 8px 12px; }}
          .expiration-form input {{ font-size: 15px; }}
          .certificate-box {{ display: grid; gap: 8px; }}
          .certificate-section {{ grid-column: 1 / -1; }}
          .certificate-box code {{ display: block; overflow-wrap: anywhere; }}
          .download-links {{ display: flex; flex-wrap: wrap; gap: 10px; }}
          .download-links a {{ color: var(--accent); text-decoration: none; font-weight: 700; }}
          .download-links a:hover {{ text-decoration: underline; }}
          code {{ word-break: break-all; }}
          ul {{ margin: 0; padding-left: 18px; }}
          @media (max-width: 760px) {{
            .users-grid {{ grid-template-columns: 1fr; }}
            .user-summary, .user-controls {{ grid-template-columns: 1fr; }}
            .user-card-header {{ align-items: flex-start; }}
          }}
        </style>
      </head>
      <body>
        <main>
          <section class="hero">
            <h1>Gestor de identidades demo</h1>
            <p>Version minima para demostrar altas, roles, revocacion, expiracion, bitacora y emision de certificados X.509 firmados por una CA interna.</p>
            <form method="get" action="/dashboard" class="stack" style="max-width: 360px;">
              <label>Actuar como
                <select name="as_user">{actor_options}</select>
              </label>
              <button type="submit">Cambiar usuario actual</button>
            </form>
            <div class="download-links" style="margin-top: 14px;">
              <a href="/">Login</a>
              <a href="/portal?as_user={actor.id}">Vista de rol</a>
              <a href="/admin/register?as_user={actor.id}">Otorgar registro</a>
            </div>
          </section>

          <section class="grid">
            <article class="panel">
              <h2>Usuario actual</h2>
              <p><strong>{escape(actor.full_name)}</strong><br>{escape(actor.email)}</p>
              <p>Rol: <strong>{escape(actor.role.name)}</strong></p>
              <p>Estado: <span class="status status-{escape(actor.status)}">{escape(actor.status)}</span></p>
              <p>Permisos: {escape(permission_text)}</p>
            </article>
            <article class="panel">
              <h2>CA interna</h2>
              <p>La demo mantiene una autoridad certificadora local y firma certificados X.509 para cada usuario emitido.</p>
              <div class="download-links">
                <a href="/ui/ca/certificate/view">Ver certificado CA</a>
                <a href="{ca_download_url}">Descargar certificado de la CA</a>
              </div>
            </article>
            <article class="panel">
              <h2>Resumen</h2>
              <p>Usuarios: <strong>{len(users)}</strong></p>
              <p>Roles: <strong>{len(roles)}</strong></p>
              <p>Eventos visibles: <strong>{len(logs)}</strong></p>
            </article>
          </section>

          {create_form}

          <section class="panel">
            <h2>Usuarios</h2>
            <div class="users-grid">{''.join(user_cards)}</div>
          </section>

          <section class="panel">
            <h2>Auditoria reciente</h2>
            <ul>{log_items}</ul>
          </section>
        </main>
      </body>
    </html>
    """


@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse(render_login_page())


@app.post("/login")
async def login_with_certificate(
    email: str = Form(...),
    p12_password: str = Form(...),
    p12_file: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
):
    if email.strip().lower() == "admin" and p12_password == "admin":
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
        return RedirectResponse(url=f"/dashboard?{urlencode({'as_user': admin.id})}", status_code=303)

    try:
        p12_bytes = b""
        if p12_file is not None and p12_file.filename:
            p12_bytes = await p12_file.read()

        if p12_bytes:
            user, proof = SignatureLoginService.authenticate_with_p12(
                db,
                email=email,
                p12_bytes=p12_bytes,
                password=p12_password,
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
            return RedirectResponse(url=f"/portal?{urlencode({'as_user': user.id, 'verified': '1'})}", status_code=303)

        user = PasswordLoginService.authenticate_volunteer(db, email=email, password=p12_password)
    except ValueError as exc:
        AuditService.log(
            db,
            event_type="login_rejected",
            action="login_with_p12",
            resource="auth",
            result="failure",
            metadata={"email": email.lower(), "reason": str(exc)},
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
    return RedirectResponse(url=f"/portal?{urlencode({'as_user': user.id})}", status_code=303)


@app.get("/portal", response_class=HTMLResponse)
def user_portal(
    as_user: int | None = Query(default=None),
    verified: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, as_user)
    permissions = AuthorizationService.get_permissions(db, actor)
    logs = AuditService.list_recent(db)
    return HTMLResponse(render_portal_page(actor, permissions, logs, verified))


@app.get("/admin/register", response_class=HTMLResponse)
def admin_register_page(as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
    require_actor_permission(db, actor, "users", "create")
    roles = UserService.list_roles(db)
    return HTMLResponse(render_admin_register_page(actor, roles))


@app.post("/admin/register", response_class=HTMLResponse)
def admin_register_user(
    actor_id: int = Form(...),
    full_name: str = Form(...),
    email: str = Form(...),
    role_id: int = Form(...),
    end_date: str = Form(default=""),
    p12_password: str = Form(...),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
    require_actor_permission(db, actor, "users", "create")
    roles = UserService.list_roles(db)

    try:
        user = UserService.create_user(
            db,
            full_name=full_name,
            email=email,
            role_id=role_id,
            end_date=parse_end_date(end_date),
            p12_password=p12_password,
        )
        user = UserService.update_status(db, user, "active")
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
    AuditService.log(
        db,
        event_type="user_activated",
        actor_user_id=actor.id,
        target_user_id=user.id,
        action="activate",
        resource="users",
        result="success",
        metadata={"source": "admin_register"},
    )
    if user.certificate_serial:
        AuditService.log(
            db,
            event_type="certificate_issued",
            actor_user_id=actor.id,
            target_user_id=user.id,
            action="issue_certificate",
            resource="certificates",
            result="success",
            metadata={"certificate_serial": user.certificate_serial},
        )
    return redirect_home(actor.id)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    if as_user is None:
        return RedirectResponse(url="/", status_code=303)

    actor = get_actor_or_404(db, as_user)
    if not is_active_admin(actor):
        permissions = AuthorizationService.get_permissions(db, actor)
        logs = AuditService.list_recent(db)
        return HTMLResponse(render_portal_page(actor, permissions, logs))

    users = UserService.list_users(db)
    roles = UserService.list_roles(db)
    permissions = AuthorizationService.get_permissions(db, actor)
    logs = AuditService.list_recent(db)
    return HTMLResponse(render_dashboard(actor, users, roles, permissions, logs))


@app.get("/api/me", response_model=MeOut)
def api_me(as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
    return {"user": actor, "role": actor.role, "permissions": AuthorizationService.get_permissions(db, actor)}


@app.get("/api/users", response_model=list[UserOut])
def api_users(as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
    require_actor_permission(db, actor, "users", "view")
    return UserService.list_users(db)


@app.get("/api/audit-logs", response_model=list[AuditLogOut])
def api_audit_logs(as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
    require_actor_permission(db, actor, "audit", "view")
    return AuditService.list_recent(db, limit=50)


@app.post("/ui/users")
def ui_create_user(
    actor_id: int = Form(...),
    full_name: str = Form(...),
    email: str = Form(...),
    role_id: int = Form(...),
    end_date: str = Form(default=""),
    p12_password: str = Form(...),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
    require_actor_permission(db, actor, "users", "create")
    try:
        user = UserService.create_user(
            db,
            full_name=full_name,
            email=email,
            role_id=role_id,
            end_date=parse_end_date(end_date),
            p12_password=p12_password,
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
        metadata={"certificate_serial": user.certificate_serial, "role": user.role.code},
    )
    if user.certificate_serial:
        AuditService.log(
            db,
            event_type="certificate_issued",
            actor_user_id=actor.id,
            target_user_id=user.id,
            action="issue_certificate",
            resource="certificates",
            result="success",
            metadata={"certificate_serial": user.certificate_serial},
        )
    return redirect_home(actor.id)


@app.post("/ui/users/{user_id}/status")
def ui_change_status(
    user_id: int,
    actor_id: int = Form(...),
    status: str = Form(...),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
    target = UserService.get_user(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    config = {
        "active": ("users", "activate", "user_activated"),
        "revoked": ("users", "revoke", "user_revoked"),
    }
    if status not in config:
        raise HTTPException(status_code=400, detail="Unsupported status")

    resource, action, event_type = config[status]

    require_actor_permission(db, actor, resource, action)
    updated = UserService.update_status(db, target, status)
    AuditService.log(
        db,
        event_type=event_type,
        actor_user_id=actor.id,
        target_user_id=updated.id,
        action=action,
        resource=resource,
        result="success",
    )
    return redirect_home(actor.id)


@app.post("/ui/users/{user_id}/expiration")
def ui_change_expiration(
    user_id: int,
    actor_id: int = Form(...),
    end_date: str = Form(...),
    p12_password: str = Form(default=""),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
    target = UserService.get_user(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    require_actor_permission(db, actor, "users", "activate")
    try:
        parsed_end_date = parse_end_date(end_date)
        if parsed_end_date is None:
            raise ValueError("Debes indicar una nueva fecha de expiracion")
        updated = UserService.update_expiration(db, target, parsed_end_date, p12_password)
    except ValueError as exc:
        db.rollback()
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
            "certificate_serial": updated.certificate_serial,
        },
    )
    return redirect_home(actor.id)


@app.post("/ui/users/{user_id}/role")
def ui_change_role(
    user_id: int,
    actor_id: int = Form(...),
    role_id: int = Form(...),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
    target = UserService.get_user(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    require_actor_permission(db, actor, "users", "change_role")
    try:
        updated = UserService.change_role(db, target, role_id)
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
        metadata={"role_id": role_id},
    )
    return redirect_home(actor.id)


@app.post("/ui/users/{user_id}/certificate")
def ui_issue_certificate(
    user_id: int,
    actor_id: int = Form(...),
    p12_password: str = Form(...),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
    target = UserService.get_user(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    require_actor_permission(db, actor, "users", "create")
    try:
        updated = CertificateService.issue_for_user(db, target, p12_password, reissue=True)
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
    return redirect_home(actor.id)


@app.get("/ui/users/{user_id}/certificate.p12")
def download_p12(user_id: int, as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
    user = UserService.get_user(db, user_id)
    if not user or not user.p12_path:
        raise HTTPException(status_code=404, detail="Certificate package not found")
    if actor.id != user.id and not AuthorizationService.authorize(db, actor, "users", "create"):
        raise HTTPException(status_code=403, detail="Not allowed to download this package")

    p12_path = Path(user.p12_path)
    if not p12_path.exists():
        raise HTTPException(status_code=404, detail="Certificate package file not found")

    return FileResponse(
        path=p12_path,
        media_type="application/x-pkcs12",
        filename=f"{user.email.replace('@', '_')}.p12",
    )


@app.get("/ui/users/{user_id}/certificate/view", response_class=HTMLResponse)
def view_user_certificate(user_id: int, as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
    user = UserService.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if actor.id != user.id and not AuthorizationService.authorize(db, actor, "users", "view"):
        raise HTTPException(status_code=403, detail="Not allowed to view this certificate")

    summary = CertificateService.describe_user_certificate(user)
    if not summary:
        raise HTTPException(status_code=404, detail="Certificate not found")

    back_href = f"/dashboard?{urlencode({'as_user': actor.id})}"
    return HTMLResponse(render_certificate_page(f"Certificado de {user.full_name}", summary, back_href))


@app.get("/ui/users/{user_id}/certificate.pem")
def download_certificate_pem(user_id: int, as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
    user = UserService.get_user(db, user_id)
    if not user or not user.certificate_pem:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if actor.id != user.id and not AuthorizationService.authorize(db, actor, "users", "view"):
        raise HTTPException(status_code=403, detail="Not allowed to download this certificate")

    return Response(
        content=user.certificate_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{user.email.replace("@", "_")}.crt.pem"'},
    )


@app.get("/ui/ca/certificate/view", response_class=HTMLResponse)
def view_ca_certificate():
    summary = CertificateAuthorityService.describe_ca_certificate()
    return HTMLResponse(render_certificate_page("Certificado de la CA interna", summary, "/"))


@app.get("/ui/ca/certificate")
def download_ca_certificate():
    ca_cert_path = CertificateAuthorityService.get_ca_certificate_path()
    return FileResponse(
        path=ca_cert_path,
        media_type="application/x-pem-file",
        filename="casa-monarca-demo-ca.crt.pem",
    )
