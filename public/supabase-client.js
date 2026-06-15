// Cliente Supabase compartido (auth + datos). La anon key es pública por
// diseño: el acceso real está controlado por las políticas RLS en Supabase.
const SUPABASE_URL = 'https://lpjdccinwmzfuevqmrft.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_Iob3orta6diSKAxdGIzxdA_yIknQzHu';

const supabaseClient = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Devuelve { authenticated, user:{id,email,name,phone,role} } o { authenticated:false }
async function hsGetSession() {
  const { data: { session } } = await supabaseClient.auth.getSession();
  if (!session) return { authenticated: false };
  const { data: profile, error } = await supabaseClient
    .from('profiles')
    .select('id, email, name, phone, role')
    .eq('id', session.user.id)
    .single();
  if (error || !profile) return { authenticated: false };
  return { authenticated: true, user: profile };
}

function hsRoleHome(role) {
  return role === 'admin' ? '/admin/' : role === 'instructor' ? '/instructor/' : '/client/';
}

async function hsLogout() {
  await supabaseClient.auth.signOut();
  window.location.href = '/';
}

// Convierte una fila de la tabla `reservations` (snake_case) al shape
// camelCase que usan los paneles.
function hsMapReservation(r) {
  return {
    id: r.id,
    code: r.code,
    clientId: r.client_id,
    instructorId: r.instructor_id,
    servicio: r.servicio,
    paquete: r.paquete,
    simulador: r.simulador,
    fecha: r.fecha,
    horaInicio: r.hora_inicio,
    horaFin: r.hora_fin,
    estado: r.estado,
    pago: r.pago,
    total: r.total,
    abono: r.abono,
    notas: r.notas,
    clienteNombre: r.cliente_nombre,
    instructorNombre: r.instructor_nombre,
    createdAt: r.created_at,
  };
}
