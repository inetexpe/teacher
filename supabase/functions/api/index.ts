// Серверна функція «api» для кабінету викладача.
// Кожен запит несе initData з Telegram Mini App; функція перевіряє його підпис токеном бота
// і лише тоді читає чи пише базу. Секрети (Edge Functions → Secrets):
//   BOT_TOKEN    — токен бота від @BotFather (обов'язково)
//   TEACHER_IDS  — Telegram ID викладачів через кому (рекомендовано; якщо порожньо,
//                  викладачем може стати будь-хто, хто відкрив бота без запрошення)
// SUPABASE_URL і SUPABASE_SERVICE_ROLE_KEY Supabase додає сам.
import { createClient } from 'npm:@supabase/supabase-js@2';

const BOT_TOKEN = Deno.env.get('BOT_TOKEN') ?? '';
const TEACHER_IDS = (Deno.env.get('TEACHER_IDS') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const db = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, {
  auth: { persistSession: false },
});

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

/* Перевірка initData за документацією Telegram:
   secret = HMAC_SHA256(key="WebAppData", msg=bot_token); hash = hex(HMAC_SHA256(key=secret, msg=data_check_string)) */
const enc = new TextEncoder();
async function hmac(key: Uint8Array, msg: string) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
export async function verifyInitData(initData: string, botToken: string, maxAgeSec = 86400) {
  const p = new URLSearchParams(initData);
  const hash = p.get('hash');
  if (!hash || !botToken) return null;
  p.delete('hash');
  const check = [...p.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => `${k}=${v}`).join('\n');
  const secret = await hmac(enc.encode('WebAppData'), botToken);
  if (hex(await hmac(secret, check)) !== hash) return null;
  if (Date.now() / 1000 - Number(p.get('auth_date') ?? 0) > maxAgeSec) return null;
  const user = JSON.parse(p.get('user') ?? 'null');
  if (!user?.id) return null;
  return { user, startParam: p.get('start_param') ?? '' };
}

type Action = { id: number; student_id: string; kind: string; payload: Record<string, unknown>; created_at: string };

async function workspace(teacherId: number) {
  const { data, error } = await db.from('workspaces').select('data, version').eq('teacher_id', teacherId).maybeSingle();
  if (error) throw error;
  return data as { data: any; version: number } | null;
}
async function pendingActions(teacherId: number, studentId?: string) {
  let q = db.from('student_actions').select('id, student_id, kind, payload, created_at').eq('teacher_id', teacherId).eq('applied', false);
  if (studentId) q = q.eq('student_id', studentId);
  const { data, error } = await q.order('id');
  if (error) throw error;
  return (data ?? []) as Action[];
}
async function linkOf(tgId: number) {
  const { data, error } = await db.from('links').select('teacher_id, student_id').eq('tg_id', tgId).maybeSingle();
  if (error) throw error;
  return data as { teacher_id: number; student_id: string } | null;
}

// Те, що бачить учень: свій профіль без нотаток викладача, свої уроки без нотаток, свої матеріали.
// Ще не застосовані викладачем дії учня накладаються зверху, щоб він одразу бачив свої відмітки.
async function studentView(teacherId: number, studentId: string) {
  const w = await workspace(teacherId);
  const s = w?.data?.students?.find((x: any) => x.id === studentId);
  if (!s) return null;
  const homework = (s.homework ?? []).map((h: any) => ({ ...h }));
  const lessons = (w!.data.lessons ?? []).filter((l: any) => l.studentId === studentId).map(({ note: _n, ...l }: any) => l);
  for (const a of await pendingActions(teacherId, studentId)) {
    if (a.kind === 'hw') { const h = homework.find((x: any) => x.id === a.payload.id); if (h) h.done = !!a.payload.done; }
    if (a.kind === 'resched') { const l = lessons.find((x: any) => x.id === a.payload.lessonId); if (l) l.request = a.payload; }
  }
  const materialIds: string[] = s.materialIds ?? [];
  return {
    student: { id: s.id, name: s.name, lang: s.lang, level: s.level, format: s.format, progress: s.progress ?? 0, goals: s.goals ?? '', homework, materialIds },
    lessons,
    materials: (w!.data.materials ?? []).filter((m: any) => materialIds.includes(m.id)),
    teacherName: w!.data.settings?.name ?? '',
  };
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ error: 'method' }, 405);
  try {
    if (!BOT_TOKEN) return json({ error: 'BOT_TOKEN не задано в секретах функції' }, 500);
    const body = await req.json();
    const auth = await verifyInitData(body.initData ?? '', BOT_TOKEN);
    if (!auth) return json({ error: 'auth' }, 401);
    const uid = Number(auth.user.id);
    const me = { id: uid, name: [auth.user.first_name, auth.user.last_name].filter(Boolean).join(' '), username: auth.user.username ?? '' };
    const listedTeacher = TEACHER_IDS.includes(String(uid));
    const own = await workspace(uid);

    const teacherResp = async () => {
      const w = await workspace(uid);
      return { role: 'teacher', me, data: w?.data ?? null, version: w?.version ?? 0, actions: await pendingActions(uid) };
    };
    const studentResp = async (l: { teacher_id: number; student_id: string }) =>
      ({ role: 'student', me, view: await studentView(l.teacher_id, l.student_id) });
    const canTeach = async () => !!own || listedTeacher || (!TEACHER_IDS.length && !(await linkOf(uid)));

    switch (body.op) {
      case 'init': {
        if (own || listedTeacher) return json({ ...(await teacherResp()), ownInvite: auth.startParam.startsWith('s_') });
        if (auth.startParam.startsWith('s_')) {
          const { data: inv, error } = await db.from('invites').select('teacher_id, student_id').eq('code', auth.startParam.slice(2)).maybeSingle();
          if (error) throw error;
          if (!inv) return json({ role: 'invalid-invite', me });
          const prev = await linkOf(uid);
          await db.from('links').upsert({ tg_id: uid, teacher_id: inv.teacher_id, student_id: inv.student_id });
          if (!prev || prev.student_id !== inv.student_id || prev.teacher_id !== inv.teacher_id) {
            await db.from('student_actions').insert({ teacher_id: inv.teacher_id, student_id: inv.student_id, kind: 'joined', payload: { name: me.name, username: me.username } });
          }
          return json(await studentResp(inv));
        }
        const l = await linkOf(uid);
        if (l) return json(await studentResp(l));
        if (await canTeach()) return json(await teacherResp());
        return json({ role: 'none', me });
      }

      case 'pull': {
        if (!(await canTeach())) return json({ error: 'forbidden' }, 403);
        return json(await teacherResp());
      }

      case 'save': {
        if (!(await canTeach())) return json({ error: 'forbidden' }, 403);
        const data = body.data;
        if (!data || !Array.isArray(data.students)) return json({ error: 'bad data' }, 400);
        let version: number;
        if (!own) {
          const { error } = await db.from('workspaces').insert({ teacher_id: uid, data, version: 1 });
          if (error) return json({ conflict: true, ...(await teacherResp()) }, 409);
          version = 1;
        } else {
          const { data: rows, error } = await db.from('workspaces')
            .update({ data, version: own.version + 1, updated_at: new Date().toISOString() })
            .eq('teacher_id', uid).eq('version', Number(body.version)).select('version');
          if (error) throw error;
          if (!rows?.length) return json({ conflict: true, ...(await teacherResp()) }, 409);
          version = rows[0].version;
        }
        const applied = (body.applied ?? []).map(Number).filter(Number.isFinite);
        if (applied.length) await db.from('student_actions').update({ applied: true }).eq('teacher_id', uid).in('id', applied);
        // Коди запрошень беруться з профілів учнів: видалений учень — недійсне запрошення.
        await db.from('invites').delete().eq('teacher_id', uid);
        const codes = data.students.filter((s: any) => typeof s.invite === 'string' && s.invite)
          .map((s: any) => ({ code: s.invite, teacher_id: uid, student_id: s.id }));
        if (codes.length) await db.from('invites').upsert(codes);
        return json({ version });
      }

      case 'view':
      case 'hw':
      case 'resched': {
        const l = await linkOf(uid);
        if (!l) return json({ error: 'forbidden' }, 403);
        if (body.op === 'hw') {
          await db.from('student_actions').insert({ teacher_id: l.teacher_id, student_id: l.student_id, kind: 'hw', payload: { id: String(body.id), done: !!body.done } });
        }
        if (body.op === 'resched') {
          const payload = { lessonId: String(body.lessonId), date: String(body.date ?? ''), time: String(body.time ?? ''), text: String(body.text ?? '').slice(0, 500), at: Date.now() };
          await db.from('student_actions').insert({ teacher_id: l.teacher_id, student_id: l.student_id, kind: 'resched', payload });
        }
        return json(await studentResp(l));
      }

      default:
        return json({ error: 'unknown op' }, 400);
    }
  } catch (e) {
    console.error(e);
    return json({ error: String((e as Error)?.message ?? e) }, 500);
  }
});
