-- RedProtec — Relay central · esquema Postgres (Supabase)
--
-- El relay CREA estas tablas solo al arrancar (store.py::PostgresStore.init_schema),
-- así que un deploy limpio funciona sin correr nada a mano. Este archivo es el
-- mismo DDL, para revisarlo o aplicarlo manualmente desde el SQL Editor de
-- Supabase si prefieres controlar la migración tú.
--
-- Multi-tenant por `org_token` (el Bearer del agente/dueño). No hay tabla de
-- organizaciones: el token ES la partición. Todo es idempotente (IF NOT EXISTS).

-- Sedes: un registro por (organización, sede). `summary` y `devices` son JSON
-- exactamente como los envía el agente en el latido.
CREATE TABLE IF NOT EXISTS sites (
    org_token    text        NOT NULL,
    site_id      text        NOT NULL,
    site_name    text        NOT NULL,
    summary      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    devices      jsonb,                       -- NULL = sin inventario completo
    remote_admin boolean     NOT NULL DEFAULT false,
    updated_at   timestamptz NOT NULL,
    PRIMARY KEY (org_token, site_id)
);

-- Cola de comandos por sede. El agente los recoge en su latido y los confirma
-- (ack) → se borran. Los vencidos (TTL) se podan al leer.
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

-- Config por organización (por ahora, el tema ntfy para alertas).
CREATE TABLE IF NOT EXISTS org_config (
    org_token   text PRIMARY KEY,
    alert_topic text
);

-- RBAC en la nube: accesos por-persona (token de usuario → rol + alcance de
-- sedes). El índice por user_token acelera la resolución del principal en cada
-- request.
CREATE TABLE IF NOT EXISTS access (
    org_token  text  NOT NULL,
    user_token text  NOT NULL,
    name       text  NOT NULL DEFAULT '',
    role       text  NOT NULL DEFAULT 'guest',
    sites      jsonb NOT NULL DEFAULT '["*"]'::jsonb,
    PRIMARY KEY (org_token, user_token)
);
CREATE INDEX IF NOT EXISTS access_user_idx ON access (user_token);
