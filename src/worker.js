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

  // GoTrue's list endpoint doesn't reliably filter by email — look up the
  // user's UUID from the profiles table (which has email indexed) instead.
  const profLookupRes = await fetch(
    `${SUPABASE_URL}/rest/v1/profiles?select=id&email=eq.${encodeURIComponent(email)}&limit=1`,
    { headers: svcHeaders },
  );
  const { body: profRows, raw: profRaw } = await safeJson(profLookupRes);
  const userId = profLookupRes.ok && Array.isArray(profRows) && profRows[0] ? profRows[0].id : null;
  if (!userId) {
    console.log('reset-password: profile lookup failed', profLookupRes.status, profRaw);
    return json({ error: 'No existe una cuenta con ese correo' }, 404);
  }

  const updRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${userId}`, {
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

async function sendReservationEmail(r, env) {
  if (!env.RESEND_API_KEY) return;
  const MESES = ['enero','febrero','marzo','abril','mayo','junio','julio','agosto','septiembre','octubre','noviembre','diciembre'];
  const [y, m, d] = (r.fecha || '').split('-');
  const fechaFmt = y && m && d ? `${parseInt(d)} de ${MESES[parseInt(m)-1]} de ${y}` : r.fecha || '—';
  const horario = r.hora_inicio && r.hora_fin ? `${r.hora_inicio} – ${r.hora_fin}` : r.hora_inicio || '—';
  const phoneRaw = (r.cliente_phone || '').replace(/\D/g, '').replace(/^0+/, '').replace(/^57/, '');
  const waPhone = `57${phoneRaw}`;
  const waMsg = encodeURIComponent(`Hola ${r.cliente_nombre||''}, soy del equipo de Hold Short Aviation ✈. Vi tu reserva para el ${fechaFmt} (${r.paquete||(r.paquete||'')}). ¿Podemos coordinar los detalles del pago y confirmar tu vuelo?`);
  const waLink = `https://wa.me/${waPhone}?text=${waMsg}`;
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:24px;background:#F4F4F1;font-family:Arial,sans-serif">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #E6E4DD">
  <div style="background:#0C0D10;padding:18px 24px;display:flex;align-items:center;gap:10px">
    <span style="color:#F5841F;font-size:22px">✈</span>
    <span style="color:#fff;font-weight:700;font-size:15px;letter-spacing:.06em">HOLD SHORT AVIATION</span>
  </div>
  <div style="padding:24px">
    <div style="background:#FBF0D5;border-left:3px solid #D9920A;border-radius:6px;padding:12px 16px;margin-bottom:22px">
      <p style="margin:0;color:#7a5c10;font-weight:700;font-size:13px;letter-spacing:.04em">🛩 NUEVA RESERVA RECIBIDA</p>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <tr><td style="padding:9px 0;color:#73777e;font-size:11px;letter-spacing:.06em;width:110px;vertical-align:top">CLIENTE</td><td style="padding:9px 0;font-weight:600;color:#16181c">${r.cliente_nombre||'—'}</td></tr>
      <tr><td style="padding:9px 0;color:#73777e;font-size:11px;letter-spacing:.06em;vertical-align:top">WHATSAPP</td><td style="padding:9px 0"><a href="${waLink}" style="color:#2E9E5B;font-weight:600;text-decoration:none">${r.cliente_phone||'—'} →</a></td></tr>
      <tr><td style="padding:9px 0;color:#73777e;font-size:11px;letter-spacing:.06em;vertical-align:top">EMAIL</td><td style="padding:9px 0;color:#16181c">${r.cliente_email||'—'}</td></tr>
      <tr><td colspan="2" style="padding:4px 0"><div style="border-top:1px solid #F0F0EA"></div></td></tr>
      <tr><td style="padding:9px 0;color:#73777e;font-size:11px;letter-spacing:.06em;vertical-align:top">PAQUETE</td><td style="padding:9px 0;font-weight:600;color:#16181c">${r.paquete||'—'}</td></tr>
      <tr><td style="padding:9px 0;color:#73777e;font-size:11px;letter-spacing:.06em;vertical-align:top">FECHA</td><td style="padding:9px 0;color:#16181c">${fechaFmt}</td></tr>
      <tr><td style="padding:9px 0;color:#73777e;font-size:11px;letter-spacing:.06em;vertical-align:top">HORARIO</td><td style="padding:9px 0;color:#16181c">${horario}</td></tr>
      <tr><td style="padding:9px 0;color:#73777e;font-size:11px;letter-spacing:.06em;vertical-align:top">CÓDIGO</td><td style="padding:9px 0;font-family:monospace;color:#b5630a;font-weight:700;font-size:15px">${r.code||'—'}</td></tr>
    </table>
    <div style="margin-top:22px;display:flex;gap:10px;flex-wrap:wrap">
      <a href="https://hangar-1903.holdshortweb.workers.dev/admin/" style="display:inline-block;background:#16181c;color:#fff;text-decoration:none;padding:11px 18px;border-radius:8px;font-size:13px;font-weight:600">Ver en panel →</a>
      <a href="${waLink}" style="display:inline-block;background:#25D366;color:#fff;text-decoration:none;padding:11px 18px;border-radius:8px;font-size:13px;font-weight:600">Contactar por WhatsApp →</a>
    </div>
  </div>
  <div style="background:#F8F7F4;padding:12px 24px;border-top:1px solid #E6E4DD">
    <p style="margin:0;font-size:11px;color:#9a9ea5">Hold Short Aviation · Pereira · @holdshortpei</p>
  </div>
</div>
</body></html>`;
  const emailRes = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'Hold Short Aviation <reservas@hangar1903.com>',
      to: ['holdshortweb@gmail.com'],
      subject: `Nueva reserva — ${r.cliente_nombre||'Cliente'} · ${r.paquete||''} · ${fechaFmt}`,
      html,
    }),
  });
  if (!emailRes.ok) console.log('resend failed', emailRes.status, await emailRes.text());
}

async function handleNewReservationWebhook(request, env) {
  const secret = request.headers.get('X-Webhook-Secret');
  if (!secret || secret !== env.WEBHOOK_SECRET) return json({ error: 'No autorizado' }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }
  if (body.type !== 'INSERT' || body.table !== 'reservations') return json({ ok: true, skipped: true });
  const r = body.record;
  if (!r) return json({ error: 'Sin datos' }, 400);
  await sendReservationEmail(r, env);
  return json({ ok: true });
}

async function handleReservaStatus(request, env) {
  if (!env.SUPABASE_SERVICE_ROLE_KEY) return json({ error: 'Server misconfigured' }, 500);
  const url = new URL(request.url);
  const code  = (url.searchParams.get('code')  || '').trim().toUpperCase();
  const email = (url.searchParams.get('email') || '').trim().toLowerCase();
  if (!code && !email) return json({ error: 'Se requiere código o correo' }, 400);

  const svcHeaders = {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
  };

  let filter = '';
  if (code)  filter = `code=eq.${encodeURIComponent(code)}`;
  else       filter = `cliente_email=eq.${encodeURIComponent(email)}`;

  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/reservations?${filter}&select=code,cliente_nombre,paquete,fecha,hora_inicio,hora_fin,estado&limit=1&order=created_at.desc`,
    { headers: svcHeaders },
  );
  const { body: rows } = await safeJson(res);
  if (!res.ok || !Array.isArray(rows) || !rows[0]) {
    return json({ error: 'No encontramos ninguna reserva con esos datos.' }, 404);
  }
  const r = rows[0];
  return json({
    code:          r.code,
    cliente_nombre: r.cliente_nombre,
    paquete:       r.paquete,
    fecha:         r.fecha,
    hora_inicio:   r.hora_inicio,
    hora_fin:      r.hora_fin,
    estado:        r.estado,
  });
}

async function sendClientAcknowledgement(r, env) {
  if (!env.RESEND_API_KEY || !r.cliente_email) return;
  const MESES = ['enero','febrero','marzo','abril','mayo','junio','julio','agosto','septiembre','octubre','noviembre','diciembre'];
  const [y, m, d] = (r.fecha || '').split('-');
  const fechaFmt = y && m && d ? `${parseInt(d)} de ${MESES[parseInt(m)-1]} de ${y}` : r.fecha || '—';
  const horario = r.hora_inicio && r.hora_fin ? `${r.hora_inicio} – ${r.hora_fin}` : r.hora_inicio || '—';
  const esRegalo = r.book_for === 'regalo';
  const nombreDestinatario = esRegalo ? (r.regalo_nombre || r.cliente_nombre || '') : (r.cliente_nombre || '');
  const primerNombre = nombreDestinatario.split(' ')[0];

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#F4F4F1;font-family:Arial,Helvetica,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F4F4F1;padding:32px 16px">
<tr><td align="center">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #E6E4DD">

  <!-- Header -->
  <tr><td style="background:#0C0D10;padding:20px 28px">
    <table cellpadding="0" cellspacing="0"><tr>
      <td style="color:#F5841F;font-size:24px;padding-right:10px">✈</td>
      <td style="color:#ffffff;font-weight:700;font-size:15px;letter-spacing:.08em">HOLD SHORT AVIATION</td>
    </tr></table>
  </td></tr>

  <!-- Hero -->
  <tr><td style="background:#16181c;padding:28px 28px 24px">
    <p style="margin:0 0 6px;color:#F5841F;font-size:11px;font-weight:700;letter-spacing:.12em">${esRegalo ? 'REGALO DE EXPERIENCIA' : 'SOLICITUD DE VUELO'}</p>
    <h1 style="margin:0 0 10px;color:#ffffff;font-size:22px;font-weight:800;line-height:1.2">¡${primerNombre}, recibimos tu solicitud!</h1>
    <p style="margin:0;color:#9fa3a8;font-size:14px;line-height:1.6">
      ${esRegalo
        ? `Estás regalando una experiencia de vuelo única. Muy pronto nos ponemos en contacto contigo para coordinar todos los detalles y enviarte la invitación oficial.`
        : `Estás a un paso de volar. Nuestro equipo revisará tu solicitud y se pondrá en contacto contigo para coordinar el pago y enviarte tu pase de abordar.`}
    </p>
  </td></tr>

  <!-- Detalles reserva -->
  <tr><td style="padding:24px 28px">
    <p style="margin:0 0 14px;font-size:11px;font-weight:700;letter-spacing:.1em;color:#73777e">RESUMEN DE TU SOLICITUD</p>
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #EDECEA;border-radius:10px;overflow:hidden">
      <tr style="background:#F8F7F4">
        <td style="padding:11px 16px;font-size:12px;color:#73777e;width:90px">PAQUETE</td>
        <td style="padding:11px 16px;font-size:14px;font-weight:700;color:#16181c">${r.paquete || '—'}</td>
      </tr>
      <tr>
        <td style="padding:11px 16px;font-size:12px;color:#73777e;border-top:1px solid #EDECEA">FECHA</td>
        <td style="padding:11px 16px;font-size:14px;color:#16181c;border-top:1px solid #EDECEA">${fechaFmt}</td>
      </tr>
      <tr style="background:#F8F7F4">
        <td style="padding:11px 16px;font-size:12px;color:#73777e;border-top:1px solid #EDECEA">HORARIO</td>
        <td style="padding:11px 16px;font-size:14px;color:#16181c;border-top:1px solid #EDECEA">${horario}</td>
      </tr>
      <tr>
        <td style="padding:11px 16px;font-size:12px;color:#73777e;border-top:1px solid #EDECEA">CÓDIGO</td>
        <td style="padding:11px 16px;font-size:15px;font-weight:700;color:#b5630a;font-family:monospace;border-top:1px solid #EDECEA">${r.code || '—'}</td>
      </tr>
    </table>
  </td></tr>

  <!-- Qué sigue -->
  <tr><td style="padding:0 28px 20px">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#EBF5FF;border-radius:10px;padding:16px">
      <tr><td>
        <p style="margin:0 0 10px;font-size:12px;font-weight:700;color:#1a4a7a;letter-spacing:.06em">¿QUÉ SIGUE?</p>
        <table cellpadding="0" cellspacing="0">
          <tr>
            <td style="vertical-align:top;padding-right:10px;padding-bottom:8px;color:#2563a8;font-size:16px">①</td>
            <td style="padding-bottom:8px;font-size:13px;color:#1e3a5f;line-height:1.5">Nuestro equipo revisará tu solicitud en las próximas horas.</td>
          </tr>
          <tr>
            <td style="vertical-align:top;padding-right:10px;padding-bottom:8px;color:#2563a8;font-size:16px">②</td>
            <td style="padding-bottom:8px;font-size:13px;color:#1e3a5f;line-height:1.5">Te contactaremos por WhatsApp para coordinar el pago.</td>
          </tr>
          <tr>
            <td style="vertical-align:top;padding-right:10px;color:#2563a8;font-size:16px">③</td>
            <td style="font-size:13px;color:#1e3a5f;line-height:1.5">Recibirás tu ${esRegalo ? 'invitación de regalo' : 'pase de abordar'} oficial con todos los detalles de tu vuelo.</td>
          </tr>
        </table>
      </td></tr>
    </table>
  </td></tr>

  <!-- Botones de acción -->
  <tr><td style="padding:0 28px 20px">
    <table cellpadding="0" cellspacing="0"><tr>
      <td style="padding-right:10px">
        <a href="https://hangar1903.com/?reserva=${r.code||''}" style="display:inline-block;background:#16181c;color:#ffffff;text-decoration:none;padding:12px 18px;border-radius:9px;font-size:13px;font-weight:600;font-family:Arial,sans-serif">Maneja tu reserva →</a>
      </td>
    </tr></table>
  </td></tr>

  <!-- Video de seguridad -->
  <tr><td style="padding:0 28px 24px">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#1a1c20;border-radius:10px;overflow:hidden">
      <tr>
        <td style="padding:16px 18px">
          <p style="margin:0 0 4px;font-size:11px;font-weight:700;color:#F5841F;letter-spacing:.1em">ANTES DE TU VUELO</p>
          <p style="margin:0 0 10px;font-size:14px;font-weight:700;color:#ffffff">Mira el video de seguridad</p>
          <p style="margin:0 0 14px;font-size:12px;color:#73777e;line-height:1.5">Es obligatorio ver este video antes de tu sesión en el simulador. Escanea el código QR o haz clic en el botón.</p>
          <a href="https://hangar-1903.holdshortweb.workers.dev/preflight" style="display:inline-block;background:#F5841F;color:#15171b;text-decoration:none;padding:10px 16px;border-radius:8px;font-size:13px;font-weight:700;font-family:Arial,sans-serif">▶ Ver video de seguridad</a>
        </td>
        <td style="padding:16px 18px 16px 0;vertical-align:middle;width:100px">
          <img src="https://api.qrserver.com/v1/create-qr-code/?size=90x90&data=https://hangar-1903.holdshortweb.workers.dev/preflight&bgcolor=1a1c20&color=F5841F&margin=2" width="90" height="90" alt="QR video seguridad" style="display:block;border-radius:6px">
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Footer -->
  <tr><td style="background:#F8F7F4;border-top:1px solid #E6E4DD;padding:16px 28px">
    <p style="margin:0 0 4px;font-size:12px;color:#16181c;font-weight:600">Hold Short Aviation</p>
    <p style="margin:0;font-size:11px;color:#9a9ea5">Aeropuerto Matecaña · Pereira · @holdshortpei</p>
  </td></tr>

</table>
</td></tr>
</table>
</body></html>`;

  const asunto = esRegalo
    ? `Recibimos tu regalo de experiencia, ${primerNombre}`
    : `Recibimos tu solicitud de vuelo, ${primerNombre}`;

  const emailRes = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'Hold Short Aviation <reservas@hangar1903.com>',
      to: [r.cliente_email],
      subject: asunto,
      html,
    }),
  });
  if (!emailRes.ok) console.log('client-ack failed', emailRes.status, await emailRes.text());
}

async function handleCreateReservation(request, env) {
  if (!env.SUPABASE_SERVICE_ROLE_KEY) return json({ error: 'Server misconfigured' }, 500);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }

  const svcHeaders = {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    'content-type': 'application/json',
    Prefer: 'return=representation',
  };

  const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/reservations`, {
    method: 'POST',
    headers: svcHeaders,
    body: JSON.stringify(body),
  });
  const { body: rows, raw } = await safeJson(insertRes);
  if (!insertRes.ok || !rows?.[0]) {
    console.log('create-reservation: insert failed', insertRes.status, raw);
    return json({ error: (rows && (rows.message || rows.msg)) || 'Error al guardar la reserva' }, 500);
  }

  const r = rows[0];
  await Promise.all([
    sendReservationEmail(r, env),
    sendClientAcknowledgement(r, env),
  ]);
  return json({ code: r.code, qr_token: r.qr_token });
}


async function handleUpdateInstructorEstado(request, env) {
  if (!env.SUPABASE_SERVICE_ROLE_KEY) return json({ error: 'Server misconfigured' }, 500);

  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return json({ error: 'No autorizado' }, 403);

  const svcHeaders = {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    'content-type': 'application/json',
  };

  const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${token}` },
  });
  const { body: user } = await safeJson(userRes);
  if (!userRes.ok || !user?.id) return json({ error: 'No autorizado' }, 403);

  const profRes = await fetch(
    `${SUPABASE_URL}/rest/v1/profiles?select=role,email&id=eq.${user.id}&limit=1`,
    { headers: svcHeaders },
  );
  const { body: profRows } = await safeJson(profRes);
  if (!profRes.ok || !profRows?.[0] || profRows[0].role !== 'instructor') {
    return json({ error: 'No autorizado' }, 403);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido' }, 400); }

  const { reservationId, estado } = body || {};
  const ALLOWED_ESTADOS = ['checkin', 'curso', 'completada'];
  if (!reservationId || !ALLOWED_ESTADOS.includes(estado)) {
    return json({ error: 'Estado no permitido' }, 400);
  }

  const email = (profRows[0].email || '').toLowerCase();

  const instRes = await fetch(
    `${SUPABASE_URL}/rest/v1/instructors?select=id&email=ilike.${encodeURIComponent(email)}&limit=1`,
    { headers: svcHeaders },
  );
  const { body: instRows } = await safeJson(instRes);
  if (!instRes.ok || !instRows?.[0]) return json({ error: 'Perfil de instructor no encontrado' }, 404);
  const instructorId = instRows[0].id;

  // Confirm this reservation belongs to this instructor before touching it
  const riRes = await fetch(
    `${SUPABASE_URL}/rest/v1/reservation_instructors?instructor_id=eq.${instructorId}&reservation_id=eq.${reservationId}&limit=1`,
    { headers: svcHeaders },
  );
  const { body: riRows } = await safeJson(riRes);
  if (!riRes.ok || !riRows?.length) {
    return json({ error: 'No tienes permiso para modificar esta reserva' }, 403);
  }

  const updRes = await fetch(
    `${SUPABASE_URL}/rest/v1/reservations?id=eq.${reservationId}`,
    {
      method: 'PATCH',
      headers: { ...svcHeaders, Prefer: 'return=minimal' },
      body: JSON.stringify({ estado }),
    },
  );
  if (!updRes.ok) {
    const { raw } = await safeJson(updRes);
    console.log('update-instructor-estado: failed', updRes.status, raw);
    return json({ error: 'No se pudo actualizar el estado' }, 500);
  }
  return json({ ok: true });
}

async function handleInstructorSessions(request, env) {
  if (!env.SUPABASE_SERVICE_ROLE_KEY) return json({ error: 'Server misconfigured' }, 500);

  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return json({ error: 'No autorizado' }, 403);

  const svcHeaders = {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    'content-type': 'application/json',
  };

  // Verify the caller is an authenticated instructor
  const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${token}` },
  });
  const { body: user } = await safeJson(userRes);
  if (!userRes.ok || !user?.id) return json({ error: 'No autorizado' }, 403);

  const profRes = await fetch(
    `${SUPABASE_URL}/rest/v1/profiles?select=role,email&id=eq.${user.id}&limit=1`,
    { headers: svcHeaders },
  );
  const { body: profRows } = await safeJson(profRes);
  if (!profRes.ok || !profRows?.[0] || profRows[0].role !== 'instructor') {
    return json({ error: 'No autorizado' }, 403);
  }

  const email = (profRows[0].email || '').toLowerCase();

  // Resolve the instructors table row by email
  const instRes = await fetch(
    `${SUPABASE_URL}/rest/v1/instructors?select=id&email=ilike.${encodeURIComponent(email)}&limit=1`,
    { headers: svcHeaders },
  );
  const { body: instRows, raw: instRaw } = await safeJson(instRes);
  if (!instRes.ok || !instRows?.[0]) {
    console.log('instructor-sessions: instructor lookup failed', instRes.status, instRaw);
    return json({ error: 'No se encontró perfil de instructor' }, 404);
  }

  const instructorId = instRows[0].id;

  // Get all reservation IDs assigned to this instructor
  const riRes = await fetch(
    `${SUPABASE_URL}/rest/v1/reservation_instructors?select=reservation_id&instructor_id=eq.${instructorId}`,
    { headers: svcHeaders },
  );
  const { body: riRows } = await safeJson(riRes);
  if (!riRes.ok) return json({ error: 'Error al cargar asignaciones' }, 500);
  if (!riRows?.length) return json({ sessions: [] });

  const ids = riRows.map(r => r.reservation_id).join(',');

  // Fetch the full reservation rows
  const resRes = await fetch(
    `${SUPABASE_URL}/rest/v1/reservations?id=in.(${ids})&order=fecha.asc,hora_inicio.asc`,
    { headers: svcHeaders },
  );
  const { body: sessions, raw: resRaw } = await safeJson(resRes);
  if (!resRes.ok) {
    console.log('instructor-sessions: reservations fetch failed', resRes.status, resRaw);
    return json({ error: 'Error al cargar sesiones' }, 500);
  }

  return json({ sessions: sessions || [] });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.pathname === '/api/webhooks/nueva-reserva' && request.method === 'POST') {
        return await handleNewReservationWebhook(request, env);
      }
      if (url.pathname === '/api/reservations' && request.method === 'POST') {
        return await handleCreateReservation(request, env);
      }
      if (url.pathname === '/api/reserva-status' && request.method === 'GET') {
        return await handleReservaStatus(request, env);
      }
      if (url.pathname === '/api/instructor/sessions' && request.method === 'GET') {
        return await handleInstructorSessions(request, env);
      }
      if (url.pathname === '/api/instructor/reservation-estado' && request.method === 'PATCH') {
        return await handleUpdateInstructorEstado(request, env);
      }
      if (url.pathname === '/api/create-instructor' && request.method === 'POST') {
        return await handleCreateInstructor(request, env);
      }
      if (url.pathname === '/api/reset-instructor-password' && request.method === 'POST') {
        return await handleResetInstructorPassword(request, env);
      }
      // DC runtime image-slot state file — devuelve JSON vacío para evitar 404 en consola
      if (url.pathname === '/.image-slots.state.json') {
        return new Response('{}', { headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=86400' } });
      }
      // Src de imagen con template literal sin procesar ({{ expr }}) — gif transparente 1px para suprimir 404
      if (url.pathname.includes('%7B%7B')) {
        const gif = 'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
        const buf = Uint8Array.from(atob(gif), c => c.charCodeAt(0));
        return new Response(buf, { headers: { 'content-type': 'image/gif', 'cache-control': 'public, max-age=86400' } });
      }
      return env.ASSETS.fetch(request);
    } catch (e) {
      console.error('worker fetch crashed', e && e.stack || e);
      return json({ error: 'Error interno: ' + (e && e.message || String(e)) }, 500);
    }
  },
};
