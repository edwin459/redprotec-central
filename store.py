"""Almacén intercambiable del relay central.

El relay siempre fue "estado EN MEMORIA … migración a pago = cambiar el almacén"
(ver main.py). Este módulo materializa esa migración SIN tocar los endpoints:

  • MemoryStore   — el comportamiento de siempre (dicts en RAM + un Lock). Es el
                    que se usa cuando NO hay base de datos configurada. Mantiene
                    el fallback gratis (Render/Fly) y los tests existentes verdes:
                    envuelve LOS MISMOS dicts de módulo que los tests manipulan.

  • PostgresStore — persistencia real (Supabase Postgres u otro Postgres). Se usa
                    cuando la variable de entorno DATABASE_URL está presente. El
                    estado sobrevive reinicios y deja de vivir en RAM → escala a
                    miles de sedes/usuarios. Crea sus tablas de forma idempotente.

`create_store()` elige uno u otro por entorno. Los endpoints hablan SOLO con esta
interfaz (`Store`), así que cambiar de backend no cambia ninguna respuesta.
"""

from __future__ import annotations

import logging
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Protocol

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────── interfaz ───────────────────────────
class Store(Protocol):
    """Operaciones de estado que necesitan los endpoints del relay.

    Las formas de datos son idénticas a las del almacén en memoria original:
    un "record" de sede es ``{site_name, summary, devices, remote_admin,
    updated_at}`` con ``updated_at`` como ``datetime`` (aware, UTC).
    """

    # salud
    def stats(self) -> tuple[int, int]: ...

    # sedes
    def get_site(self, org: str, site_id: str) -> dict | None: ...
    def upsert_site(self, org: str, site_id: str, site_name: str,
                    summary: dict, devices: list | None,
                    remote_admin: bool, updated_at: datetime) -> None: ...
    def list_sites(self, org: str) -> list[tuple[str, dict]]: ...
    # TODAS las sedes de TODAS las orgs (solo para el panel de FLOTA del dueño).
    def iter_sites_all(self) -> list[tuple[str, str, dict]]: ...
    # Da de baja una sede (el dueño la quita del panel). Devuelve True si existía.
    def remove_site(self, org: str, site_id: str) -> bool: ...

    # comandos (cola por sede)
    def enqueue_command(self, org: str, site_id: str, command: dict) -> None: ...
    def pending_commands(self, org: str, site_id: str,
                         ttl_seconds: int, now: datetime) -> list[dict]: ...
    def ack_command(self, org: str, site_id: str, command_id: str) -> None: ...

    # config de la organización
    def get_org_config(self, org: str) -> dict: ...
    def set_alert_topic(self, org: str, topic: str | None) -> None: ...

    # accesos (RBAC en la nube)
    def resolve_user(self, user_token: str) -> tuple[str, dict] | None: ...
    def list_access(self, org: str) -> dict[str, dict]: ...
    def set_access(self, org: str, users: list[dict]) -> None: ...

    # tokens de agente (Auth-2: vincular una sede a una cuenta)
    def create_agent_token(self, org: str, token: str, label: str,
                           created_at: datetime) -> None: ...
    def resolve_agent_token(self, token: str) -> str | None: ...
    def list_agent_tokens(self, org: str) -> list[dict]: ...
    def revoke_agent_token(self, org: str, token: str) -> None: ...

    # entitlement / plan (Auth-3: freemium)
    def get_entitlement(self, org: str) -> dict | None: ...
    def set_entitlement(self, org: str, plan: str,
                        trial_ends_at: datetime | None) -> None: ...

    # clave/valor singleton (Auth-3C: llave de firma del entitlement, etc.)
    def kv_get(self, key: str) -> str | None: ...
    def kv_set(self, key: str, value: str) -> None: ...


# ─────────────────────────── memoria ───────────────────────────
class MemoryStore:
    """Backend en RAM. Envuelve dicts que pueden ser propiedad del módulo `main`
    (para que los tests que tocan `main._STORE`/`_COMMANDS`/… sigan funcionando
    exactamente igual). La semántica y el candado son los del relay original."""

    def __init__(self, sites: dict, commands: dict, org_config: dict,
                 access: dict, lock: threading.Lock | None = None):
        self._sites = sites          # org -> site_id -> record
        self._commands = commands    # org -> site_id -> list[command]
        self._org_config = org_config  # org -> {alert_topic}
        self._access = access        # org -> user_token -> {name, role, sites}
        self._agent_tokens: dict[str, dict] = {}  # token -> {org, label, created_at}
        self._entitlements: dict[str, dict] = {}  # org -> {plan, trial_ends_at}
        self._kv: dict[str, str] = {}             # clave/valor singleton (RAM)
        self._lock = lock or threading.Lock()

    def stats(self) -> tuple[int, int]:
        with self._lock:
            return len(self._sites), sum(len(v) for v in self._sites.values())

    def get_site(self, org: str, site_id: str) -> dict | None:
        with self._lock:
            return self._sites.get(org, {}).get(site_id)

    def upsert_site(self, org, site_id, site_name, summary, devices,
                    remote_admin, updated_at) -> None:
        with self._lock:
            self._sites.setdefault(org, {})[site_id] = {
                "site_name": site_name,
                "summary": summary,
                "devices": devices,
                "remote_admin": remote_admin,
                "updated_at": updated_at,
            }

    def list_sites(self, org: str) -> list[tuple[str, dict]]:
        with self._lock:
            return list(self._sites.get(org, {}).items())

    def iter_sites_all(self) -> list[tuple[str, str, dict]]:
        with self._lock:
            return [(org, sid, rec)
                    for org, sites in self._sites.items()
                    for sid, rec in sites.items()]

    def remove_site(self, org: str, site_id: str) -> bool:
        with self._lock:
            existed = self._sites.get(org, {}).pop(site_id, None) is not None
            # Descarta también su cola de comandos (no debe sobrevivir a la sede).
            self._commands.get(org, {}).pop(site_id, None)
            return existed

    def enqueue_command(self, org, site_id, command) -> None:
        with self._lock:
            self._commands.setdefault(org, {}).setdefault(site_id, []).append(command)

    def pending_commands(self, org, site_id, ttl_seconds, now) -> list[dict]:
        with self._lock:
            q = self._commands.get(org, {}).get(site_id, [])
            fresh = [c for c in q
                     if (now - c["created_at"]).total_seconds() <= ttl_seconds]
            self._commands.setdefault(org, {})[site_id] = fresh
            return [
                {"id": c["id"], "action": c["action"], "mac": c["mac"],
                 "value": c.get("value")}
                for c in fresh
            ]

    def ack_command(self, org, site_id, command_id) -> None:
        with self._lock:
            q = self._commands.get(org, {}).get(site_id, [])
            self._commands.setdefault(org, {})[site_id] = [
                c for c in q if c["id"] != command_id
            ]

    def get_org_config(self, org: str) -> dict:
        with self._lock:
            return dict(self._org_config.get(org, {}))

    def set_alert_topic(self, org: str, topic: str | None) -> None:
        with self._lock:
            self._org_config.setdefault(org, {})["alert_topic"] = topic

    def resolve_user(self, user_token: str) -> tuple[str, dict] | None:
        with self._lock:
            for org_tok, users in self._access.items():
                u = users.get(user_token)
                if u:
                    return org_tok, dict(u)
        return None

    def list_access(self, org: str) -> dict[str, dict]:
        with self._lock:
            return {t: dict(u) for t, u in self._access.get(org, {}).items()}

    def set_access(self, org: str, users: list[dict]) -> None:
        with self._lock:
            self._access[org] = {
                u["token"]: {
                    "name": u.get("name", ""),
                    "role": u.get("role", "guest"),
                    "sites": list(u.get("sites") or ["*"]),
                }
                for u in users
            }

    def create_agent_token(self, org, token, label, created_at) -> None:
        with self._lock:
            self._agent_tokens[token] = {
                "org": org, "label": label, "created_at": created_at}

    def resolve_agent_token(self, token: str) -> str | None:
        with self._lock:
            rec = self._agent_tokens.get(token)
            return rec["org"] if rec else None

    def list_agent_tokens(self, org: str) -> list[dict]:
        with self._lock:
            return [
                {"token": t, "label": r.get("label", ""),
                 "created_at": r.get("created_at")}
                for t, r in self._agent_tokens.items() if r.get("org") == org
            ]

    def revoke_agent_token(self, org: str, token: str) -> None:
        with self._lock:
            rec = self._agent_tokens.get(token)
            if rec and rec.get("org") == org:
                del self._agent_tokens[token]

    def get_entitlement(self, org: str) -> dict | None:
        with self._lock:
            rec = self._entitlements.get(org)
            return dict(rec) if rec else None

    def set_entitlement(self, org, plan, trial_ends_at) -> None:
        with self._lock:
            self._entitlements[org] = {
                "plan": plan, "trial_ends_at": trial_ends_at}

    def kv_get(self, key: str) -> str | None:
        with self._lock:
            return self._kv.get(key)

    def kv_set(self, key: str, value: str) -> None:
        with self._lock:
            self._kv[key] = value


# ─────────────────────────── postgres ───────────────────────────
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sites (
    org_token    text        NOT NULL,
    site_id      text        NOT NULL,
    site_name    text        NOT NULL,
    summary      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    devices      jsonb,
    remote_admin boolean     NOT NULL DEFAULT false,
    updated_at   timestamptz NOT NULL,
    PRIMARY KEY (org_token, site_id)
);

CREATE TABLE IF NOT EXISTS commands (
    id         text        PRIMARY KEY,
    org_token  text        NOT NULL,
    site_id    text        NOT NULL,
    action     text        NOT NULL,
    mac        text        NOT NULL,
    value      text,
    created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS commands_site_idx
    ON commands (org_token, site_id, created_at);

CREATE TABLE IF NOT EXISTS org_config (
    org_token   text PRIMARY KEY,
    alert_topic text
);

CREATE TABLE IF NOT EXISTS access (
    org_token  text  NOT NULL,
    user_token text  NOT NULL,
    name       text  NOT NULL DEFAULT '',
    role       text  NOT NULL DEFAULT 'guest',
    sites      jsonb NOT NULL DEFAULT '["*"]'::jsonb,
    PRIMARY KEY (org_token, user_token)
);
CREATE INDEX IF NOT EXISTS access_user_idx ON access (user_token);

CREATE TABLE IF NOT EXISTS agent_tokens (
    token      text        PRIMARY KEY,
    org_token  text        NOT NULL,
    label      text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_tokens_org_idx ON agent_tokens (org_token);

CREATE TABLE IF NOT EXISTS entitlements (
    org_token     text PRIMARY KEY,
    plan          text NOT NULL DEFAULT 'trial',   -- free | trial | pro
    trial_ends_at timestamptz
);

CREATE TABLE IF NOT EXISTS relay_kv (
    k text PRIMARY KEY,
    v text NOT NULL
);
"""


class PostgresStore:
    """Backend Postgres (Supabase u otro). Mismas formas de datos que MemoryStore.

    Usa un pool de conexiones y DESACTIVA los prepared statements
    (``prepare_threshold=None``) para ser compatible con el pooler de transacción
    de Supabase (puerto 6543). Crea las tablas de forma idempotente al arrancar,
    de modo que un deploy limpio funciona sin pasos manuales — aunque también se
    entrega `schema.sql` para revisarlo/aplicarlo a mano.
    """

    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 10,
                 create_schema: bool = True):
        from psycopg.types.json import Json  # noqa: F401  (validación temprana)
        from psycopg_pool import ConnectionPool

        self._Json = Json
        self._schema_ready = False
        self._schema_lock = threading.Lock()
        self._pool = ConnectionPool(
            conninfo=dsn,
            min_size=min_size,
            max_size=max_size,
            kwargs={"prepare_threshold": None},
            open=True,
        )
        if create_schema:
            # Intento TEMPRANO best-effort: si la base ya responde, deja las
            # tablas listas. En un arranque en frío en que aún no conecta, NO
            # bloquea ni se cae — el esquema se crea de forma perezosa en la
            # primera operación real (_ensure_schema). Así el proceso arranca y
            # responde /health sin depender de que Postgres esté listo, y el
            # healthcheck del host no marca el deploy como fallido.
            try:
                self._ensure_schema()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Esquema no creado al arrancar (se hará al primer uso): %s", exc)

    def _ensure_schema(self) -> None:
        """Crea las tablas una sola vez (idempotente, perezoso, thread-safe)."""
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)
            self._schema_ready = True

    def init_schema(self) -> None:
        """Crea/asegura las tablas ahora (idempotente). Útil para tests."""
        self._schema_ready = False
        self._ensure_schema()

    @contextmanager
    def _connection(self):
        """Conexión del pool asegurando el esquema (perezoso) antes de usarla."""
        self._ensure_schema()
        with self._pool.connection() as conn:
            yield conn

    def close(self) -> None:
        self._pool.close()

    # ── helpers de forma ──
    def _row_to_site(self, row) -> dict:
        site_name, summary, devices, remote_admin, updated_at = row
        return {
            "site_name": site_name,
            "summary": summary or {},
            "devices": devices,
            "remote_admin": remote_admin,
            "updated_at": updated_at,
        }

    # ── salud ──
    def stats(self) -> tuple[int, int]:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(DISTINCT org_token), count(*) FROM sites")
            orgs, sites = cur.fetchone()
        return int(orgs or 0), int(sites or 0)

    # ── sedes ──
    def get_site(self, org: str, site_id: str) -> dict | None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT site_name, summary, devices, remote_admin, updated_at "
                "FROM sites WHERE org_token = %s AND site_id = %s",
                (org, site_id),
            )
            row = cur.fetchone()
        return self._row_to_site(row) if row else None

    def upsert_site(self, org, site_id, site_name, summary, devices,
                    remote_admin, updated_at) -> None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sites
                    (org_token, site_id, site_name, summary, devices,
                     remote_admin, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (org_token, site_id) DO UPDATE SET
                    site_name    = EXCLUDED.site_name,
                    summary      = EXCLUDED.summary,
                    devices      = EXCLUDED.devices,
                    remote_admin = EXCLUDED.remote_admin,
                    updated_at   = EXCLUDED.updated_at
                """,
                (org, site_id, site_name, self._Json(summary),
                 self._Json(devices) if devices is not None else None,
                 remote_admin, updated_at),
            )

    def list_sites(self, org: str) -> list[tuple[str, dict]]:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT site_id, site_name, summary, devices, remote_admin, "
                "updated_at FROM sites WHERE org_token = %s",
                (org,),
            )
            rows = cur.fetchall()
        return [(r[0], self._row_to_site(r[1:])) for r in rows]

    def iter_sites_all(self) -> list[tuple[str, str, dict]]:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT org_token, site_id, site_name, summary, devices, "
                "remote_admin, updated_at FROM sites")
            rows = cur.fetchall()
        return [(r[0], r[1], self._row_to_site(r[2:])) for r in rows]

    def remove_site(self, org: str, site_id: str) -> bool:
        with self._connection() as conn, conn.cursor() as cur:
            # Descarta también la cola de comandos de la sede.
            cur.execute(
                "DELETE FROM commands WHERE org_token = %s AND site_id = %s",
                (org, site_id),
            )
            cur.execute(
                "DELETE FROM sites WHERE org_token = %s AND site_id = %s",
                (org, site_id),
            )
            return cur.rowcount > 0

    # ── comandos ──
    def enqueue_command(self, org, site_id, command) -> None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO commands (id, org_token, site_id, action, mac, "
                "value, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (command["id"], org, site_id, command["action"], command["mac"],
                 command.get("value"), command["created_at"]),
            )

    def pending_commands(self, org, site_id, ttl_seconds, now) -> list[dict]:
        cutoff = now - timedelta(seconds=ttl_seconds)
        with self._connection() as conn, conn.cursor() as cur:
            # Poda las órdenes vencidas (misma semántica que el TTL en memoria).
            cur.execute(
                "DELETE FROM commands WHERE org_token = %s AND site_id = %s "
                "AND created_at < %s",
                (org, site_id, cutoff),
            )
            cur.execute(
                "SELECT id, action, mac, value FROM commands "
                "WHERE org_token = %s AND site_id = %s ORDER BY created_at",
                (org, site_id),
            )
            rows = cur.fetchall()
        return [{"id": r[0], "action": r[1], "mac": r[2], "value": r[3]}
                for r in rows]

    def ack_command(self, org, site_id, command_id) -> None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM commands WHERE org_token = %s AND site_id = %s "
                "AND id = %s",
                (org, site_id, command_id),
            )

    # ── config ──
    def get_org_config(self, org: str) -> dict:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT alert_topic FROM org_config WHERE org_token = %s",
                (org,),
            )
            row = cur.fetchone()
        return {"alert_topic": row[0]} if row else {}

    def set_alert_topic(self, org: str, topic: str | None) -> None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO org_config (org_token, alert_topic) VALUES (%s, %s) "
                "ON CONFLICT (org_token) DO UPDATE SET alert_topic = EXCLUDED.alert_topic",
                (org, topic),
            )

    # ── accesos ──
    def resolve_user(self, user_token: str) -> tuple[str, dict] | None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT org_token, name, role, sites FROM access "
                "WHERE user_token = %s LIMIT 1",
                (user_token,),
            )
            row = cur.fetchone()
        if not row:
            return None
        org_tok, name, role, sites = row
        return org_tok, {"name": name, "role": role,
                         "sites": list(sites or ["*"])}

    def list_access(self, org: str) -> dict[str, dict]:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT user_token, name, role, sites FROM access "
                "WHERE org_token = %s",
                (org,),
            )
            rows = cur.fetchall()
        return {r[0]: {"name": r[1], "role": r[2], "sites": list(r[3] or ["*"])}
                for r in rows}

    def set_access(self, org: str, users: list[dict]) -> None:
        # Reemplazo atómico de la lista completa (misma semántica que PUT en memoria).
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM access WHERE org_token = %s", (org,))
            for u in users:
                cur.execute(
                    "INSERT INTO access (org_token, user_token, name, role, sites) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (org, u["token"], u.get("name", ""), u.get("role", "guest"),
                     self._Json(list(u.get("sites") or ["*"]))),
                )

    # ── tokens de agente ──
    def create_agent_token(self, org, token, label, created_at) -> None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO agent_tokens (token, org_token, label, created_at) "
                "VALUES (%s, %s, %s, %s)",
                (token, org, label, created_at),
            )

    def resolve_agent_token(self, token: str) -> str | None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT org_token FROM agent_tokens WHERE token = %s", (token,))
            row = cur.fetchone()
        return row[0] if row else None

    def list_agent_tokens(self, org: str) -> list[dict]:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT token, label, created_at FROM agent_tokens "
                "WHERE org_token = %s ORDER BY created_at", (org,))
            rows = cur.fetchall()
        return [{"token": r[0], "label": r[1], "created_at": r[2]} for r in rows]

    def revoke_agent_token(self, org: str, token: str) -> None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM agent_tokens WHERE org_token = %s AND token = %s",
                (org, token))

    # ── entitlement ──
    def get_entitlement(self, org: str) -> dict | None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT plan, trial_ends_at FROM entitlements WHERE org_token = %s",
                (org,))
            row = cur.fetchone()
        return {"plan": row[0], "trial_ends_at": row[1]} if row else None

    def set_entitlement(self, org, plan, trial_ends_at) -> None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO entitlements (org_token, plan, trial_ends_at) "
                "VALUES (%s, %s, %s) ON CONFLICT (org_token) DO UPDATE SET "
                "plan = EXCLUDED.plan, trial_ends_at = EXCLUDED.trial_ends_at",
                (org, plan, trial_ends_at))

    # ── clave/valor singleton ──
    def kv_get(self, key: str) -> str | None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT v FROM relay_kv WHERE k = %s", (key,))
            row = cur.fetchone()
        return row[0] if row else None

    def kv_set(self, key: str, value: str) -> None:
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO relay_kv (k, v) VALUES (%s, %s) "
                "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v",
                (key, value))


# ─────────────────────────── selección ───────────────────────────
def create_store(sites: dict, commands: dict, org_config: dict, access: dict,
                 lock: threading.Lock) -> Store:
    """Elige el backend por entorno.

    Si ``DATABASE_URL`` está definida → PostgresStore (persistencia real).
    Si no → MemoryStore sobre los dicts del módulo `main` (fallback gratis +
    compatibilidad con los tests existentes).
    """
    dsn = os.environ.get("DATABASE_URL", "").strip()
    if dsn:
        # create_schema=False: NO se toca la base al importar el módulo (así el
        # proceso arranca al instante y /health pasa el healthcheck sin esperar a
        # Postgres). Las tablas se crean de forma perezosa en la primera
        # operación real (_ensure_schema), que es idempotente.
        return PostgresStore(dsn, create_schema=False)
    return MemoryStore(sites, commands, org_config, access, lock)
