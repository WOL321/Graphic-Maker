/**
 * DMC Graphic Maker — License Key Backend
 * ----------------------------------------
 * Runs on Cloudflare Workers (free tier). Uses a KV namespace called
 * PRO_KEYS as the database of issued keys.
 *
 * Endpoints:
 *   POST /redeem
 *     body: { "key": "DMC-GM-AB12-3456" }
 *     -> { ok: true }                       if key exists (used or unused)
 *     -> { ok: false, reason: "..." }       if key is unknown or revoked
 *
 *   POST /admin/generate      (requires header  x-admin-key: <ADMIN_SECRET>)
 *     body: { "count": 10, "note": "batch for discord giveaway" }
 *     -> { keys: ["DMC-GM-....-....", ...] }
 *
 *   GET  /admin/keys           (requires header  x-admin-key: <ADMIN_SECRET>)
 *     -> { keys: [ { key, status, note, createdAt, redeemedAt }, ... ] }
 *
 *   POST /admin/revoke        (requires header  x-admin-key: <ADMIN_SECRET>)
 *     body: { "key": "DMC-GM-AB12-3456" }
 *     -> { ok: true }
 *
 * Set ADMIN_SECRET as a Worker secret (wrangler secret put ADMIN_SECRET).
 * Never put the admin secret in the public index.html — it's only used
 * by you, from curl / Postman / the admin.html helper page.
 */

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I to avoid confusion

function randomBlock(len) {
  let out = '';
  for (let i = 0; i < len; i++) {
    out += ALPHABET[Math.floor(Math.random() * ALPHABET.length)];
  }
  return out;
}

function makeKey() {
  return `DMC-GM-${randomBlock(4)}-${randomBlock(4)}`;
}

function cors(resp) {
  resp.headers.set('Access-Control-Allow-Origin', '*');
  resp.headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  resp.headers.set('Access-Control-Allow-Headers', 'Content-Type,x-admin-key');
  return resp;
}

function json(data, status = 200) {
  return cors(new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }));
}

function requireAdmin(request, env) {
  const provided = request.headers.get('x-admin-key') || '';
  return env.ADMIN_SECRET && provided === env.ADMIN_SECRET;
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return cors(new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);

    // ---------- PUBLIC: redeem a key ----------
    if (url.pathname === '/redeem' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ ok: false, reason: 'bad request' }, 400); }
      const key = String(body.key || '').trim().toUpperCase();
      if (!/^DMC-GM-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)) {
        return json({ ok: false, reason: 'invalid format' }, 400);
      }

      const raw = await env.PRO_KEYS.get(key);
      if (!raw) return json({ ok: false, reason: 'key not found' }, 404);

      const record = JSON.parse(raw);
      if (record.status === 'revoked') {
        return json({ ok: false, reason: 'key revoked' }, 403);
      }
      if (record.status === 'unused') {
        record.status = 'redeemed';
        record.redeemedAt = new Date().toISOString();
        await env.PRO_KEYS.put(key, JSON.stringify(record));
      }
      return json({ ok: true });
    }

    // ---------- ADMIN: generate a batch ----------
    if (url.pathname === '/admin/generate' && request.method === 'POST') {
      if (!requireAdmin(request, env)) return json({ ok: false, reason: 'unauthorized' }, 401);
      let body = {};
      try { body = await request.json(); } catch {}
      const count = Math.min(Math.max(parseInt(body.count) || 1, 1), 200);
      const note = String(body.note || '').slice(0, 200);

      const keys = [];
      for (let i = 0; i < count; i++) {
        let key;
        // avoid extremely unlikely collisions
        do { key = makeKey(); } while (await env.PRO_KEYS.get(key));
        const record = {
          status: 'unused',
          note,
          createdAt: new Date().toISOString(),
          redeemedAt: null,
        };
        await env.PRO_KEYS.put(key, JSON.stringify(record));
        keys.push(key);
      }
      return json({ keys });
    }

    // ---------- ADMIN: list all keys ----------
    if (url.pathname === '/admin/keys' && request.method === 'GET') {
      if (!requireAdmin(request, env)) return json({ ok: false, reason: 'unauthorized' }, 401);
      const list = await env.PRO_KEYS.list();
      const results = [];
      for (const entry of list.keys) {
        const raw = await env.PRO_KEYS.get(entry.name);
        if (raw) results.push({ key: entry.name, ...JSON.parse(raw) });
      }
      results.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
      return json({ keys: results });
    }

    // ---------- ADMIN: revoke a key ----------
    if (url.pathname === '/admin/revoke' && request.method === 'POST') {
      if (!requireAdmin(request, env)) return json({ ok: false, reason: 'unauthorized' }, 401);
      let body;
      try { body = await request.json(); } catch { return json({ ok: false }, 400); }
      const key = String(body.key || '').trim().toUpperCase();
      const raw = await env.PRO_KEYS.get(key);
      if (!raw) return json({ ok: false, reason: 'not found' }, 404);
      const record = JSON.parse(raw);
      record.status = 'revoked';
      await env.PRO_KEYS.put(key, JSON.stringify(record));
      return json({ ok: true });
    }

    return json({ ok: false, reason: 'not found' }, 404);
  },
};
