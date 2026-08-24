-- RedProtec — Perfil de usuario (CRM) sobre Supabase Auth
-- ---------------------------------------------------------------------------
-- Se aplica en el MISMO proyecto Supabase que hospeda Auth (el que usa la app
-- y también el relay vía DATABASE_URL). Pégalo en el SQL Editor de Supabase.
-- Es 100% IDEMPOTENTE: seguro de correr varias veces.
--
-- Modelo: UNA fila por usuario (auth.users.id). RLS = cada quien lee/edita SOLO
-- su propia fila (nadie ve lo de nadie). El panel de suscriptores (relay, con
-- service_role) la une con `entitlements` por:
--     profiles.id::text = entitlements.org_token
-- porque el org_token de una cuenta ES el claim `sub` (UUID) del JWT (ver auth.py).
--
-- Datos que van AQUÍ (identidad/CRM): nombre, tipo de cuenta, empresa, teléfono,
-- cargo, tamaño, país/ciudad, idioma, cómo nos conoció, consentimiento.
-- Lo que NO va aquí (ya vive en su sitio): plan/cobro → `entitlements` + Google
-- Play; redes/equipos/sedes → el agente.

-- ── Tabla ───────────────────────────────────────────────────────────────────
create table if not exists public.profiles (
    id                 uuid primary key references auth.users (id) on delete cascade,
    full_name          text,
    account_type       text,                 -- 'hogar' | 'empresa'
    company_name       text,
    phone              text,
    job_title          text,
    company_size       text,                 -- '1-10' | '11-50' | '51-200' | '200+'
    country            text,
    city               text,
    timezone           text,
    preferred_language text,
    referral_source    text,                 -- ¿cómo nos conociste?
    marketing_opt_in   boolean not null default false,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now()
);

-- Solo valores conocidos para account_type (permite NULL mientras no se elige).
do $$
begin
    if not exists (
        select 1 from pg_constraint where conname = 'profiles_account_type_chk'
    ) then
        alter table public.profiles
            add constraint profiles_account_type_chk
            check (account_type is null or account_type in ('hogar', 'empresa'));
    end if;
end $$;

-- ── RLS: cada usuario SOLO su fila ──────────────────────────────────────────
alter table public.profiles enable row level security;

drop policy if exists profiles_select_own on public.profiles;
create policy profiles_select_own on public.profiles
    for select using (auth.uid() = id);

drop policy if exists profiles_insert_own on public.profiles;
create policy profiles_insert_own on public.profiles
    for insert with check (auth.uid() = id);

drop policy if exists profiles_update_own on public.profiles;
create policy profiles_update_own on public.profiles
    for update using (auth.uid() = id) with check (auth.uid() = id);

-- ── updated_at automático ───────────────────────────────────────────────────
create or replace function public.touch_profiles_updated_at()
returns trigger language plpgsql as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

drop trigger if exists trg_profiles_updated_at on public.profiles;
create trigger trg_profiles_updated_at
    before update on public.profiles
    for each row execute function public.touch_profiles_updated_at();

-- ── Al registrarse un usuario, crea su fila desde los metadatos del signUp ───
-- La app envía full_name/account_type/company_name/phone en raw_user_meta_data.
-- Funciona AUNQUE el usuario deba confirmar el correo (no requiere su sesión).
-- SECURITY DEFINER: corre con permisos del dueño para poder insertar bajo RLS.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
    insert into public.profiles (id, full_name, account_type, company_name, phone)
    values (
        new.id,
        nullif(new.raw_user_meta_data ->> 'full_name', ''),
        nullif(new.raw_user_meta_data ->> 'account_type', ''),
        nullif(new.raw_user_meta_data ->> 'company_name', ''),
        nullif(new.raw_user_meta_data ->> 'phone', '')
    )
    on conflict (id) do nothing;
    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

-- ── Backfill: perfil para los usuarios YA existentes que no lo tengan ────────
-- Rescata lo que haya en sus metadatos; el resto queda NULL (lo completarán
-- desde «Mi perfil» en la app).
insert into public.profiles (id, full_name, account_type, company_name, phone)
select u.id,
       nullif(u.raw_user_meta_data ->> 'full_name', ''),
       nullif(u.raw_user_meta_data ->> 'account_type', ''),
       nullif(u.raw_user_meta_data ->> 'company_name', ''),
       nullif(u.raw_user_meta_data ->> 'phone', '')
from auth.users u
left join public.profiles p on p.id = u.id
where p.id is null;
