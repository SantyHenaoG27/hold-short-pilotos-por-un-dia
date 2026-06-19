const SUPABASE_URL = 'https://lpjdccinwmzfuevqmrft.supabase.co';

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'content-type': 'application/json' },
  });
}

// Supabase error responses aren't always JSON (e.g. a Cloudflare/edge error
// page upstream) — .json() throwing on those turned every such failure into
// an opaque 500 with no logged reason. Read as text first, parse if we can.
async function safeJson(res) {
  const text = await res.text();
  try { return { body: JSON.parse(text), raw: text }; }
  catch { return { body: null, raw: text }; }
}

// Verifies the caller's Supabase access token and confirms their profile
// role is 'admin'. Uses the service role key so this check can't be spoofed
// by a client editing their own profile row (RLS still applies to anon/auth
// keys, but the service key reads the ground truth).
async function requireAdmin(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) { console.log('requireAdmin: no token'); return null; }

  const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${token}` },
  });
  const { body: user, raw: userRaw } = await safeJson(userRes);
  if (!userRes.ok || !user) { console.log('requireAdmin: /auth/v1/user failed', userRes.status, userRaw); return null; }

  const profRes = await fetch(
    `${SUPABASE_URL}/rest/v1/profiles?select=id,role&id=eq.${user.id}`,
    { headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}` } }
  );
  const { body: rows, raw: profRaw } = await safeJson(profRes);
  if (!profRes.ok || !rows) { console.log('requireAdmin: profiles lookup failed', profRes.status, profRaw); return null; }
  if (!rows[0] || rows[0].role !== 'admin') { console.log('requireAdmin: not an admin', rows[0]); return null; }
  return user;
}

async function handleCreateInstructor(request, env) {
  if (!env.SUPABASE_SERVICE_ROLE_KEY) return json({ error: 'Server misconfigured' }, 500);

  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'No autorizado' }, 403);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  const name = (body.name || '').trim();
  if (!email || !password || password.length < 8 || !name) {
    return json({ error: 'Nombre, correo y contraseña (mín. 8 caracteres) son obligatorios' }, 400);
  }

  const svcHeaders = {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    'content-type': 'application/json',
  };

  // 1. Create the auth user (admin API — never reachable with the public key).
  const createRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
    method: 'POST',
    headers: svcHeaders,
    body: JSON.stringify({
      email, password, email_confirm: true,
      user_metadata: { name, role: 'instructor' },
    }),
  });
  const { body: created, raw: createRaw } = await safeJson(createRes);
  if (!createRes.ok || !created) {
    console.log('create-instructor: admin/users failed', createRes.status, createRaw);
    const msg = (created && (created.msg || created.message)) || 'No se pudo crear la cuenta';
    return json({ error: msg }, createRes.status === 422 ? 409 : 500);
  }

  // 2. Upsert the profile row so hsGetSession() resolves role='instructor'.
  const profRes = await fetch(`${SUPABASE_URL}/rest/v1/profiles`, {
    method: 'POST',
    headers: { ...svcHeaders, Prefer: 'resolution=merge-duplicates' },
    body: JSON.stringify({ id: created.id, email, name, role: 'instructor' }),
  });
  if (!profRes.ok) {
    const errText = await profRes.text();
    console.log('create-instructor: profiles upsert failed', profRes.status, errText);
    return json({ error: 'Cuenta creada pero el perfil falló: ' + errText }, 500);
  }

  return json({ ok: true, userId: created.id });
}

async function handleResetInstructorPassword(request, env) {
  if (!env.SUPABASE_SERVICE_ROLE_KEY) return json({ error: 'Server misconfigured' }, 500);

  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'No autorizado' }, 403);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  if (!email || !password || password.length < 8) {
    return json({ error: 'Correo y contraseña (mín. 8 caracteres) son obligatorios' }, 400);
  }

  const svcHeaders = {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    'content-type': 'application/json',
  };

  // GoTrue's admin "list users" endpoint supports filtering by email.
  const lookupRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users?email=${encodeURIComponent(email)}`, {
    headers: svcHeaders,
  });
  const { body: lookup, raw: lookupRaw } = await safeJson(lookupRes);
  const found = lookupRes.ok && lookup && Array.isArray(lookup.users) ? lookup.users[0] : null;
  if (!found) {
    console.log('reset-password: user lookup failed', lookupRes.status, lookupRaw);
    return json({ error: 'No existe una cuenta con ese correo' }, 404);
  }

  const updRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${found.id}`, {
    method: 'PUT',
    headers: svcHeaders,
    body: JSON.stringify({ password }),
  });
  if (!updRes.ok) {
    const { body: out, raw: updRaw } = await safeJson(updRes);
    console.log('reset-password: update failed', updRes.status, updRaw);
    return json({ error: (out && (out.msg || out.message)) || 'No se pudo actualizar la contraseña' }, 500);
  }
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.pathname === '/api/create-instructor' && request.method === 'POST') {
        return await handleCreateInstructor(request, env);
      }
      if (url.pathname === '/api/reset-instructor-password' && request.method === 'POST') {
        return await handleResetInstructorPassword(request, env);
      }
      return env.ASSETS.fetch(request);
    } catch (e) {
      console.error('worker fetch crashed', e && e.stack || e);
      return json({ error: 'Error interno: ' + (e && e.message || String(e)) }, 500);
    }
  },
};
