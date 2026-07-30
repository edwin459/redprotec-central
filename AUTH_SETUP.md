# Auth-1 (SaaS) — Cuentas de cliente con Supabase Auth

Con Auth-1, cada cliente se registra en la app con **correo + contraseña** y
obtiene **su propia organización aislada**, sin repartir tokens a mano. Aquí van
los datos que hay que configurar. **Ninguno se pega en el chat**: el secreto va
en Railway; las claves de cliente se inyectan al compilar la app.

Nada de esto rompe lo existente: si no se configura, la app y el relay se
comportan igual que hoy (modelo de token manual).

---

## 1. Relay (Railway) — verificar el login

El relay valida el JWT que emite Supabase. Necesita **una** de estas dos vías:

- **`SUPABASE_JWT_SECRET`** (recomendado, HS256): Supabase → **Project Settings →
  API → JWT Settings → JWT Secret**. Cópialo y agrégalo como **Variable** del
  servicio en Railway (igual que hiciste con `DATABASE_URL`). Es **secreto**.
- *(Alternativa, firmas asimétricas)* **`SUPABASE_URL`** (ej.
  `https://xxxx.supabase.co`): el relay verifica contra el JWKS público del
  proyecto. Útil si el proyecto usa llaves ES256/RS256.

Opcional: `SUPABASE_JWT_AUD` (por defecto `authenticated`, que es lo normal).

> Tras agregar la variable, Railway re-despliega solo. Como es aditivo, el relay
> sigue aceptando también los tokens manuales de antes.

## 2. App (al compilar el APK) — claves de CLIENTE

La app necesita la **URL del proyecto** y la **anon/publishable key** (claves
públicas por diseño, seguras de embeber). Se pasan al compilar:

```
flutter build apk --release \
  --dart-define=SUPABASE_URL=https://xxxx.supabase.co \
  --dart-define=SUPABASE_ANON_KEY=eyJhbGciOi... \
  --dart-define=CENTRAL_URL=https://redprotec-central-production.up.railway.app
```

Dónde salen en Supabase: **Project Settings → API**
- `SUPABASE_URL` = "Project URL".
- `SUPABASE_ANON_KEY` = "Project API keys → anon / publishable".

Si NO se pasan, la app no muestra la sección de cuentas (queda como hoy).

## 3. Verificar

1. Compila el APK con los tres `--dart-define` de arriba.
2. Abre la app → **Seguridad → Sedes** → ícono de **Iniciar sesión** (arriba) →
   **Crear cuenta** con un correo + contraseña.
3. Confirma el correo (si el proyecto lo exige) e inicia sesión.
4. La app ya habla con el relay usando tu cuenta: al vincular el agente a esta
   cuenta (Fase Auth-2), tus sedes aparecerán aquí desde cualquier lugar.

> Nota: dos usuarios distintos NUNCA se ven entre sí — el relay aísla por el
> identificador de cada cuenta (`sub` del JWT). Verificado con tests
> (`test_auth.py`).
