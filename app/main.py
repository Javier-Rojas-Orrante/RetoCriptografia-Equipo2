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
    AdminRecoveryService,
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


NOTICE_MESSAGES = {
    "user-created": "Usuario creado en estado pending. Debes activarlo para que pueda entrar.",
    "status-updated": "El acceso del usuario fue actualizado.",
    "expiration-updated": "La fecha de expiracion fue actualizada.",
    "role-updated": "El rol del usuario fue actualizado.",
    "recovery-activated": "El administrador espejo ya esta activo. El admin principal fue revocado y debe regenerarse un nuevo respaldo.",
    "certificate-issued": "El certificado y el .p12 del usuario fueron emitidos o reemitidos.",
    "crypto-login": "Identidad verificada con el certificado criptografico del usuario.",
}


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


def redirect_home(actor_id: int, notice: str | None = None) -> RedirectResponse:
    params = {"as_user": actor_id}
    if notice:
        params["notice"] = notice
    return RedirectResponse(url=f"/dashboard?{urlencode(params)}", status_code=303)


def is_active_admin(actor) -> bool:
    return actor.status == "active" and actor.role.code == "ADMIN"


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


def render_login_page(error: str | None = None, notice: str | None = None) -> str:
    error_html = f"<div class='error'>{escape(error)}</div>" if error else ""
    body = f"""
    <section class="panel stack">
      <h1>Login</h1>
      {render_notice(notice)}
      <p class="muted">`ADMIN` y `COORDINADOR` entran con archivo `.p12` y contrasena del paquete. `OPERATIVO` y `VOLUNTARIO` usan solo usuario o correo y contrasena.</p>
      <div class="muted">
        <strong>Credenciales demo:</strong><br>
        <code>admin / admin</code> bypass demo sin certificado<br>
        <code>admin@demo.local + .p12 + admin</code><br>
        <code>coordinador@demo.local + .p12 + demo1234</code><br>
        <code>operativo / demo1234</code><br>
        <code>voluntario / demo1234</code>
      </div>
      {error_html}
      <form method="post" action="/login" enctype="multipart/form-data" class="stack">
        <label>Correo o usuario<input name="identifier" required></label>
        <label>Archivo .p12 para admin/coordinador<input name="p12_file" type="file" accept=".p12,.pfx"></label>
        <label>Contrasena o clave del .p12<input name="password" type="password" required></label>
        <button type="submit">Entrar</button>
      </form>
    </section>
    """
    return base_page("Login", body)


def render_admin_register_page(actor, roles, error: str | None = None) -> str:
    role_options = "".join(f"<option value='{role.id}'>{escape(role.name)}</option>" for role in roles)
    error_html = f"<div class='error'>{escape(error)}</div>" if error else ""
    body = f"""
    <section class="panel stack">
      <h1>Otorgar registro</h1>
      <p class="muted">Crea la cuenta en estado <code>pending</code>. `ADMIN` y `COORDINADOR` reciben certificado `.p12`; `OPERATIVO` y `VOLUNTARIO` usan solo contrasena.</p>
      {error_html}
      <form method="post" action="/admin/register" class="stack">
        <input type="hidden" name="actor_id" value="{actor.id}">
        <label>Nombre completo<input name="full_name" required></label>
        <label>Correo<input name="email" type="email" required></label>
        <label>Rol<select name="role_id">{role_options}</select></label>
        <label>Fecha de expiracion<input name="end_date" type="datetime-local"></label>
        <label>Contrasena inicial o clave .p12<input name="credential_secret" type="password" required></label>
        <button type="submit">Crear usuario</button>
      </form>
      <p><a href="/dashboard?as_user={actor.id}">Volver</a></p>
    </section>
    """
    return base_page("Otorgar registro", body)


def render_portal_page(actor, permissions, logs, notice: str | None = None, verified: bool = False) -> str:
    permission_text = ", ".join(f"{item['resource']}:{item['action']}" for item in permissions) or "sin permisos"
    verified_html = "<div class='ok'>Identidad verificada con firma digital del .p12.</div>" if verified else ""

    if actor.status != "active":
        role_content = f"<div class='error'>Tu cuenta esta en estado {escape(actor.status)}. Contacta a un administrador para restablecer el acceso.</div>"
    elif actor.role.code == "ADMIN":
        role_content = f"""
        <div class="grid">
          <article class="panel">
            <h2>Administrador</h2>
            <p>Tienes acceso completo al panel, auditoria, gestion de usuarios y recuperacion del administrador espejo.</p>
            <p><a href="/dashboard?as_user={actor.id}">Abrir panel administrador</a></p>
          </article>
          <article class="panel">
            <h2>Auditoria</h2>
            <p>Eventos visibles en esta demo: <strong>{len(logs)}</strong></p>
          </article>
        </div>
        """
    elif actor.role.code == "COORDINADOR":
        role_content = """
        <div class="panel">
          <h2>Vista Coordinador</h2>
          <p>Puedes consultar operaciones y editar informacion operativa de la demo, pero no administrar usuarios ni credenciales.</p>
        </div>
        """
    elif actor.role.code == "OPERATIVO":
        role_content = """
        <div class="panel">
          <h2>Vista Operativo</h2>
          <p>Tienes acceso acotado para revisar documentos y actualizar elementos operativos puntuales.</p>
        </div>
        """
    elif actor.role.code == "VOLUNTARIO":
        role_content = """
        <div class="panel">
          <h2>Vista Voluntario</h2>
          <p>Acceso restringido y simplificado, orientado principalmente a consulta.</p>
        </div>
        """
    else:
        role_content = "<div class='error'>Rol no reconocido para esta demo.</div>"

    body = f"""
    <section class="panel stack">
      <h1>Portal de usuario</h1>
      {verified_html}
      {render_notice(notice)}
      <p><strong>{escape(actor.full_name)}</strong> · {escape(actor.email)}</p>
      <p>Rol: <strong>{escape(actor.role.name)}</strong></p>
      <p>Estado: <strong>{escape(actor.status)}</strong></p>
      <p>Permisos efectivos: {escape(permission_text)}</p>
      {"<p><a href='/ui/users/%s/certificate/view?as_user=%s'>Ver mi certificado</a></p>" % (actor.id, actor.id) if role_requires_crypto(actor) and actor.certificate_serial else ""}
      <p><a href="/login">Salir / cambiar usuario</a></p>
    </section>
    {role_content}
    """
    return base_page("Portal de usuario", body)


def render_dashboard(actor, users, roles, permissions, logs, backup_admin, certificate_history, notice: str | None = None) -> str:
    permission_text = ", ".join(f"{item['resource']}:{item['action']}" for item in permissions) or "sin permisos"
    actor_options = "".join(
        f"<option value='{user.id}'>{escape(user.full_name)} ({escape(user.role.name)})</option>"
        for user in users
    )
    create_role_options = "".join(f"<option value='{role.id}'>{escape(role.name)}</option>" for role in roles)

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
            helper = "Nueva contrasena .p12" if user_uses_crypto else "Nueva contrasena"
            activation_form = f"""
            <form method="post" action="/ui/users/{user.id}/status" class="inline-form">
              <input type="hidden" name="actor_id" value="{actor.id}">
              <input type="hidden" name="status" value="active">
              <input type="password" name="new_secret" placeholder="{helper}" {'required' if needs_new_secret else ''}>
              <button type="submit">Activar</button>
            </form>
            """

        revoke_form = "<span class='muted'>Sin accion</span>"
        if can_revoke and user.status != "revoked":
            revoke_form = f"""
            <form method="post" action="/ui/users/{user.id}/status" class="inline-form">
              <input type="hidden" name="actor_id" value="{actor.id}">
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
            expiration_value = user.end_date.strftime("%Y-%m-%dT%H:%M") if user.end_date else ""
            expiration_secret = (
                '<input type="password" name="new_secret" placeholder="Nueva contrasena .p12" required>'
                if user_uses_crypto
                else ""
            )
            expiration_form = f"""
            <form method="post" action="/ui/users/{user.id}/expiration" class="inline-form">
              <input type="hidden" name="actor_id" value="{actor.id}">
              <input type="datetime-local" name="end_date" value="{expiration_value}" required>
              {expiration_secret}
              <button type="submit">Guardar vigencia</button>
            </form>
            """

        role_form = "<span class='muted'>Rol fijo</span>"
        if can_change_role:
            role_form = f"""
            <form method="post" action="/ui/users/{user.id}/role" class="inline-form">
              <input type="hidden" name="actor_id" value="{actor.id}">
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
            if user.certificate_serial and user.p12_path:
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
                  <input type="hidden" name="actor_id" value="{actor.id}">
                  <input type="password" name="credential_secret" placeholder="Contrasena .p12" required>
                  <button type="submit">Emitir certificado</button>
                </form>
                """

        summary_expiration = expiration_text
        row_hint = "Admin/coordinador con .p12" if user_uses_crypto else "Password local"

        user_rows.append(
            f"""
            <details class="user-row">
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
        <details class="panel collapsible-panel">
          <summary><h2>Alta de usuario</h2><span class="summary-button">Abrir</span></summary>
          <form method="post" action="/ui/users" class="stack panel-body">
            <input type="hidden" name="actor_id" value="{actor.id}">
            <label>Nombre completo<input name="full_name" required></label>
            <label>Correo<input name="email" type="email" required></label>
            <label>Rol<select name="role_id">{create_role_options}</select></label>
            <label>Fecha de expiracion<input name="end_date" type="datetime-local"></label>
            <label>Contrasena inicial o clave .p12<input name="credential_secret" type="password" required></label>
            <button type="submit">Crear usuario</button>
          </form>
        </details>
        """

    backup_section = "<p class='muted'>Sin respaldo espejo disponible.</p>"
    if backup_admin:
        activate_button = ""
        if can_activate_mirror and backup_admin.status != "active":
            activate_button = f"""
            <form method="post" action="/ui/admin/recovery/activate-mirror" class="inline-form">
              <input type="hidden" name="actor_id" value="{actor.id}">
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
          .danger-button {{ background: #8f2f2f; }}
          a {{ color: var(--accent); font-weight: 700; text-decoration: none; }}
          a:hover {{ text-decoration: underline; }}
          .status {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-weight: 700; font-size: 12px; }}
          .status-active {{ background: #ddf3e4; color: var(--ok); }}
          .status-pending {{ background: #fff0dc; color: var(--warn); }}
          .status-revoked, .status-expired {{ background: #f8dfdf; color: var(--bad); }}
          .ok {{ background: #ddf3e4; border: 1px solid #a7d8b7; color: var(--ok); border-radius: 12px; padding: 10px 12px; margin-bottom: 14px; }}
          .inline-form {{ display: grid; gap: 8px; }}
          .users-list {{ display: grid; gap: 10px; }}
          .user-row, .collapsible-panel {{ background: #fffaf1; border: 1px solid #eadcc8; border-radius: 18px; overflow: hidden; }}
          .user-row-summary, .collapsible-panel > summary {{ list-style: none; cursor: pointer; display: grid; gap: 10px; align-items: center; padding: 14px 16px; }}
          .user-row-summary::-webkit-details-marker, .collapsible-panel > summary::-webkit-details-marker {{ display: none; }}
          .user-row-summary {{ grid-template-columns: minmax(180px, 2fr) minmax(100px, 1fr) auto minmax(140px, 1fr) minmax(140px, 1fr) auto; }}
          .summary-name {{ display: grid; gap: 4px; min-width: 0; }}
          .summary-name small {{ overflow-wrap: anywhere; opacity: 0.78; }}
          .summary-button {{ justify-self: end; background: #f1dfca; color: var(--accent); border-radius: 999px; padding: 6px 12px; font-weight: 700; }}
          .user-row-body, .panel-body {{ display: grid; gap: 12px; padding: 0 16px 16px; }}
          .user-row-body {{ grid-template-columns: repeat(4, minmax(0, 1fr)); }}
          .control-panel {{ min-width: 0; border-top: 1px solid #efe4d3; padding-top: 10px; }}
          .control-panel h4 {{ margin: 0 0 8px; font-size: 14px; letter-spacing: 0.04em; text-transform: uppercase; opacity: 0.72; }}
          .muted {{ opacity: 0.76; }}
          .mini-links {{ display: flex; flex-wrap: wrap; gap: 10px; }}
          ul {{ margin: 0; padding-left: 18px; }}
          code {{ word-break: break-all; }}
          @media (max-width: 760px) {{
            .user-row-summary {{ grid-template-columns: 1fr; }}
            .user-row-body {{ grid-template-columns: 1fr; }}
          }}
        </style>
      </head>
      <body>
        <main>
          <section class="hero">
            <h1>Gestor de Identidades Casa Monarca</h1>
            {render_notice(notice)}
            <p>Plataforma de control de identidades con autenticacion por rol, certificados X.509 para perfiles criptograficos, gestion de vigencia, revocacion y auditoria operativa.</p>
            <div class="grid">
              <article>
                <h2>Usuario actual</h2>
                <p><strong>{escape(actor.full_name)}</strong><br>{escape(actor.email)}</p>
                <p>Rol: <strong>{escape(actor.role.name)}</strong></p>
                <p>Permisos: {escape(permission_text)}</p>
              </article>
              <article>
                <h2>Vista rapida por rol</h2>
                <form method="get" action="/portal" class="stack">
                  <label>Ver como usuario
                    <select name="as_user">{actor_options}</select>
                  </label>
                  <button type="submit">Abrir portal</button>
                </form>
              </article>
            <article>
                <h2>Atajos</h2>
                <p><a href="/login">Volver al login</a></p>
                <p><a href="/admin/register?as_user={actor.id}">Otorgar registro</a></p>
              </article>
            </div>
          </section>

          <section class="grid">
            <article class="panel">
              <h2>Resumen</h2>
              <p>Usuarios visibles: <strong>{len(users)}</strong></p>
              <p>Roles: <strong>{len(roles)}</strong></p>
              <p>Eventos visibles: <strong>{len(logs)}</strong></p>
            </article>
            <details class="panel collapsible-panel">
              <summary><h2>Recuperacion admin</h2><span class="summary-button">Abrir</span></summary>
              <div class="panel-body">{backup_section}</div>
            </details>
            <details class="panel collapsible-panel">
              <summary><h2>Certificados</h2><span class="summary-button">Abrir</span></summary>
              <div class="panel-body">
                <p class="muted">`ADMIN` y `COORDINADOR` autentican con `.p12`. Aqui tambien puedes consultar el certificado de la CA y el historico emitido.</p>
                <p><a href="/ui/ca/certificate/view?as_user={actor.id}">Ver certificado CA</a></p>
                <p><a href="/ui/ca/certificate?as_user={actor.id}">Descargar certificado CA</a></p>
              </div>
            </details>
          </section>

          {create_form}

          <section class="panel">
            <h2>Usuarios</h2>
            <div class="users-list">{''.join(user_rows)}</div>
          </section>

          <section class="grid">
            <details class="panel collapsible-panel">
              <summary><h2>Historico de certificados</h2><span class="summary-button">Abrir</span></summary>
              <div class="panel-body"><ul>{certificate_rows}</ul></div>
            </details>
            <article class="panel">
              <h2>Auditoria reciente</h2>
              <ul>{log_items}</ul>
            </article>
          </section>
        </main>
      </body>
    </html>
    """


@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def login_page(notice: str | None = Query(default=None)):
    return HTMLResponse(render_login_page(notice=notice))


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
        return redirect_home(admin.id)

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
                return redirect_home(user.id, "crypto-login")
            return RedirectResponse(
                url=f"/portal?{urlencode({'as_user': user.id, 'verified': '1', 'notice': 'crypto-login'})}",
                status_code=303,
            )

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

    if is_active_admin(user):
        return redirect_home(user.id)
    return RedirectResponse(url=f"/portal?{urlencode({'as_user': user.id})}", status_code=303)


@app.get("/portal", response_class=HTMLResponse)
def user_portal(
    as_user: int | None = Query(default=None),
    notice: str | None = Query(default=None),
    verified: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, as_user)
    permissions = AuthorizationService.get_permissions(db, actor)
    logs = AuditService.list_recent(db)
    return HTMLResponse(render_portal_page(actor, permissions, logs, notice=notice, verified=verified))


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
    credential_secret: str = Form(...),
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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    as_user: int | None = Query(default=None),
    notice: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    if as_user is None:
        return RedirectResponse(url="/", status_code=303)

    actor = get_actor_or_404(db, as_user)
    permissions = AuthorizationService.get_permissions(db, actor)
    logs = AuditService.list_recent(db)
    if not is_active_admin(actor):
        return HTMLResponse(render_portal_page(actor, permissions, logs, notice=notice))

    users = UserService.list_users(db)
    roles = UserService.list_roles(db)
    backup_admin = AdminRecoveryService.get_backup_admin(db)
    certificate_history = UserService.list_certificate_history(db)
    return HTMLResponse(render_dashboard(actor, users, roles, permissions, logs, backup_admin, certificate_history, notice))


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
    credential_secret: str = Form(...),
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
    actor_id: int = Form(...),
    status: str = Form(...),
    new_secret: str = Form(default=""),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
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
    actor_id: int = Form(...),
    end_date: str = Form(...),
    new_secret: str = Form(default=""),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
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
    actor_id: int = Form(...),
    role_id: int = Form(...),
    new_secret: str = Form(default=""),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
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
    actor_id: int = Form(...),
    credential_secret: str = Form(...),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
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
    actor_id: int = Form(...),
    db: Session = Depends(get_db),
):
    actor = get_actor_or_404(db, actor_id)
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
def download_p12(user_id: int, as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
    require_actor_permission(db, actor, "certificates", "view")
    user = UserService.get_user(db, user_id)
    if not user or not user.p12_path:
        raise HTTPException(status_code=404, detail="Certificate package not found")

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
    require_actor_permission(db, actor, "certificates", "view")
    user = UserService.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    summary = CertificateService.describe_user_certificate(user)
    if not summary:
        raise HTTPException(status_code=404, detail="Certificate not found")

    back_href = f"/dashboard?{urlencode({'as_user': actor.id})}"
    return HTMLResponse(render_certificate_page(f"Certificado legacy de {user.full_name}", summary, back_href))


@app.get("/ui/users/{user_id}/certificate.pem")
def download_certificate_pem(user_id: int, as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
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
def view_ca_certificate(as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
    require_actor_permission(db, actor, "certificates", "view")
    summary = CertificateAuthorityService.describe_ca_certificate()
    return HTMLResponse(render_certificate_page("Certificado legacy de la CA interna", summary, f"/dashboard?as_user={actor.id}"))


@app.get("/ui/ca/certificate")
def download_ca_certificate(as_user: int | None = Query(default=None), db: Session = Depends(get_db)):
    actor = get_actor_or_404(db, as_user)
    require_actor_permission(db, actor, "certificates", "view")
    ca_cert_path = CertificateAuthorityService.get_ca_certificate_path()
    return FileResponse(
        path=ca_cert_path,
        media_type="application/x-pem-file",
        filename="casa-monarca-demo-ca.crt.pem",
    )
