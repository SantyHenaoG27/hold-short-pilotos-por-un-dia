-- ============================================================================
-- Hold Short Pilotos por un Día — esquema Supabase
-- Proyecto: lpjdccinwmzfuevqmrft
-- Ejecutar completo en: Supabase Dashboard > SQL Editor
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Tipos enumerados (rol, estado, pago, servicio) — no texto libre
-- ----------------------------------------------------------------------------
create type public.user_role as enum ('admin', 'instructor', 'client');

create type public.reserva_servicio as enum ('pxd', 'hs');

create type public.reserva_estado as enum (
  'solicitud', 'pendiente', 'confirmada', 'proxima', 'checkin',
  'curso', 'completada', 'cancelada', 'reprogramada', 'noasistio'
);

create type public.reserva_pago as enum ('pendiente', 'abono', 'pagado', 'vencido', 'reembolso');

-- ----------------------------------------------------------------------------
-- 2. profiles — extiende auth.users con nombre/teléfono/rol
-- ----------------------------------------------------------------------------
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  name text not null,
  phone text,
  role public.user_role not null default 'client',
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- Helper: corre con privilegios del owner (bypassa RLS) para evitar
-- recursión infinita al consultar el rol del usuario actual.
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.profiles where id = auth.uid() and role = 'admin'
  );
$$;

-- Cada usuario ve y edita su propio perfil
create policy "profiles_select_own" on public.profiles
  for select using (auth.uid() = id);

create policy "profiles_update_own" on public.profiles
  for update using (auth.uid() = id);

-- Admins ven y administran todos los perfiles (incluye cambiar roles)
create policy "profiles_admin_all" on public.profiles
  for all using (public.is_admin());

-- Evita que un usuario se autoasigne un rol distinto al actual.
-- Solo un admin (vía profiles_admin_all) puede cambiar el rol de alguien.
create or replace function public.prevent_role_self_escalation()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- auth.uid() es NULL cuando el cambio viene del SQL Editor / rol postgres
  -- (no de la API vía PostgREST). En ese caso confiamos en el operador.
  if new.role <> old.role and auth.uid() is not null and not public.is_admin() then
    new.role := old.role;
  end if;

  return new;
end;
$$;

create trigger trg_prevent_role_escalation
  before update on public.profiles
  for each row execute function public.prevent_role_self_escalation();

-- Al registrarse en auth.users, crea automáticamente su perfil.
-- El rol SIEMPRE inicia en 'client' (ignora cualquier "role" enviado en el
-- signup) — los roles admin/instructor los asigna un admin desde profiles.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, name, phone, role)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'name', ''),
    new.raw_user_meta_data->>'phone',
    'client'
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ----------------------------------------------------------------------------
-- 3. reservations
-- ----------------------------------------------------------------------------
create sequence public.reservation_code_seq start with 1001;

create table public.reservations (
  id bigint generated always as identity primary key,
  code text not null default ('HS-' || nextval('public.reservation_code_seq')::text),
  client_id uuid not null references public.profiles(id),
  instructor_id uuid references public.profiles(id),
  servicio public.reserva_servicio not null default 'pxd',
  paquete text not null,
  simulador text,
  fecha date not null,
  hora_inicio time,
  hora_fin time,
  estado public.reserva_estado not null default 'solicitud',
  pago public.reserva_pago not null default 'pendiente',
  total integer not null default 0,
  abono integer not null default 0,
  notas text,
  -- Snapshot de nombres para mostrar en los paneles sin necesitar que
  -- cliente/instructor puedan leer el perfil del otro (RLS más simple y segura)
  cliente_nombre text,
  instructor_nombre text,
  created_at timestamptz not null default now()
);

create index idx_reservations_client on public.reservations(client_id);
create index idx_reservations_instructor on public.reservations(instructor_id);
create index idx_reservations_fecha on public.reservations(fecha);

alter table public.reservations enable row level security;

-- Mantiene cliente_nombre / instructor_nombre sincronizados desde profiles,
-- corre con privilegios del owner (lee profiles aunque el caller no pueda)
create or replace function public.set_reservation_names()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  select name into new.cliente_nombre from public.profiles where id = new.client_id;
  if new.instructor_id is not null then
    select name into new.instructor_nombre from public.profiles where id = new.instructor_id;
  else
    new.instructor_nombre := null;
  end if;
  return new;
end;
$$;

create trigger trg_set_reservation_names
  before insert or update on public.reservations
  for each row execute function public.set_reservation_names();

-- Cliente: ve y crea sus propias reservas (siempre como 'solicitud')
create policy "reservations_client_select" on public.reservations
  for select using (auth.uid() = client_id);

create policy "reservations_client_insert" on public.reservations
  for insert with check (
    auth.uid() = client_id
    and estado = 'solicitud'
    and pago = 'pendiente'
    and total = 0
    and abono = 0
    and instructor_id is null
  );

-- Instructor: ve y actualiza (estado/pago/notas) las reservas asignadas a él
create policy "reservations_instructor_select" on public.reservations
  for select using (auth.uid() = instructor_id);

create policy "reservations_instructor_update" on public.reservations
  for update using (auth.uid() = instructor_id)
  with check (auth.uid() = instructor_id);

-- Admin: control total
create policy "reservations_admin_all" on public.reservations
  for all using (public.is_admin());

-- ----------------------------------------------------------------------------
-- 4. settings — configuración global (mantenimiento de simulador, etc.)
-- ----------------------------------------------------------------------------
create table public.settings (
  key text primary key,
  value jsonb not null default '{}',
  updated_at timestamptz not null default now()
);

alter table public.settings enable row level security;

-- Cualquiera (incluyendo anónimo) puede leer settings
create policy "settings_read_public" on public.settings
  for select using (true);

-- Solo admins pueden crear o modificar settings
create policy "settings_admin_write" on public.settings
  for all using (public.is_admin());

-- Registro inicial: mantenimiento inactivo
insert into public.settings (key, value) values
  ('simulator_maintenance', '{"activo": false, "desde": null, "hasta": null}')
on conflict do nothing;

-- ----------------------------------------------------------------------------
-- 5. instructors — perfiles de instructores (no necesitan cuenta en la app)
-- ----------------------------------------------------------------------------
create table public.instructors (
  id bigint generated always as identity primary key,
  nombre text not null,
  email text,
  areas text[] not null default '{}',
  bio text,
  foto_url text,
  activo boolean not null default true,
  created_at timestamptz not null default now()
);

alter table public.instructors enable row level security;

-- Todos los usuarios autenticados pueden leer instructores (para el picker)
create policy "instructors_read_auth" on public.instructors
  for select using (auth.role() = 'authenticated');

-- Solo admins pueden crear / modificar / eliminar
create policy "instructors_admin_all" on public.instructors
  for all using (public.is_admin());

-- ----------------------------------------------------------------------------
-- 6. reservation_instructors — asignación de instructores a reservas (N:M)
-- ----------------------------------------------------------------------------
create table public.reservation_instructors (
  id bigint generated always as identity primary key,
  reservation_id bigint not null references public.reservations(id) on delete cascade,
  instructor_id bigint not null references public.instructors(id) on delete cascade,
  rol text not null default 'apoyo' check (rol in ('lider', 'apoyo', 'observador')),
  created_at timestamptz not null default now(),
  unique(reservation_id, instructor_id)
);

alter table public.reservation_instructors enable row level security;

-- Admin: control total
create policy "res_inst_admin_all" on public.reservation_instructors
  for all using (public.is_admin());

-- Cliente: solo puede leer los instructores de sus propias reservas
create policy "res_inst_client_select" on public.reservation_instructors
  for select using (
    exists (
      select 1 from public.reservations r
      where r.id = reservation_id and r.client_id = auth.uid()
    )
  );

-- ----------------------------------------------------------------------------
-- 7. Seed de roles (ejecutar DESPUÉS de crear los usuarios desde la app /
--    Supabase Auth con sus emails reales). Ejemplo:
-- ----------------------------------------------------------------------------
-- update public.profiles set role = 'admin'      where email = 'admin@holdshort.com';
-- update public.profiles set role = 'instructor' where email = 'instructor@holdshort.com';
-- (los nuevos registros quedan como 'client' por defecto)
