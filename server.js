// ============================================================================
//  Unic Client - Servidor de Licencas (Node.js + Postgres/Supabase)
//  Recursos:
//   - Geracao de chaves unicas
//   - Vinculacao 1 device por key (HWID)
//   - Validacao automatica (key + HWID)
//   - Revogar / renovar / expirar / desvincular
//   - Painel administrativo web (/admin) protegido por token
//   - Armazenamento no Postgres (Supabase) -> nao perde as keys
//  Uso:
//   DATABASE_URL=postgresql://... ADMIN_TOKEN=... SIGN_SECRET=... node server.js
// ============================================================================
'use strict';
const http = require('http');
const crypto = require('crypto');
const { Pool } = require('pg');

// ----------------------------------------------------------------------------
// Config
// ----------------------------------------------------------------------------
const PORT        = parseInt(process.env.PORT || '8090', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'troque-este-token-admin';
const SIGN_SECRET = process.env.SIGN_SECRET || 'troque-este-segredo-de-assinatura';
const DATABASE_URL = process.env.DATABASE_URL || '';

if (!DATABASE_URL) {
  console.error('ERRO: defina DATABASE_URL (connection string do Supabase/Postgres).');
  process.exit(1);
}

// Supabase exige SSL. rejectUnauthorized:false aceita o certificado deles.
// Supabase exige SSL. Em Postgres local de teste, defina PGSSL=disable.
const useSsl = process.env.PGSSL !== 'disable';
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: useSsl ? { rejectUnauthorized: false } : false
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      key           TEXT PRIMARY KEY,
      created       BIGINT NOT NULL,
      expires_at    BIGINT NOT NULL,
      hwid          TEXT,
      activated_at  BIGINT,
      revoked       BOOLEAN NOT NULL DEFAULT false,
      note          TEXT DEFAULT ''
    );
  `);
}

// ----------------------------------------------------------------------------
// Util
// ----------------------------------------------------------------------------
const now = () => Date.now();
const days = (n) => n * 24 * 60 * 60 * 1000;
function sign(obj) {
  const body = JSON.stringify(obj);
  const mac = crypto.createHmac('sha256', SIGN_SECRET).update(body).digest('hex').slice(0, 24);
  return { ...obj, sig: mac };
}
function genKey() {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const buf = crypto.randomBytes(15);
  let bits = 0, val = 0, out = '';
  for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  let grouped = '';
  for (let i = 0; i < out.length; i++) { if (i && i % 5 === 0) grouped += '-'; grouped += out[i]; }
  return 'UNIC-' + grouped;
}
const daysLeft = (r) => Math.max(0, Math.ceil((Number(r.expires_at) - now()) / days(1)));
function publicView(r) {
  let status = 'ativa';
  if (r.revoked) status = 'revogada';
  else if (now() > Number(r.expires_at)) status = 'expirada';
  else if (!r.hwid) status = 'nao ativada';
  return {
    key: r.key, status,
    created: new Date(Number(r.created)).toISOString(),
    expiresAt: new Date(Number(r.expires_at)).toISOString(),
    daysLeft: daysLeft(r),
    hwid: r.hwid || null,
    activatedAt: r.activated_at ? new Date(Number(r.activated_at)).toISOString() : null,
    note: r.note || ''
  };
}

// ----------------------------------------------------------------------------
// Acesso ao banco
// ----------------------------------------------------------------------------
async function getKey(key) {
  const r = await pool.query('SELECT * FROM licenses WHERE key=$1', [key]);
  return r.rows[0] || null;
}

// ----------------------------------------------------------------------------
// HTTP helpers
// ----------------------------------------------------------------------------
function sendJson(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { resolve({}); } });
  });
}
function isAdmin(req) {
  const h = req.headers['authorization'] || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : h;
  const a = Buffer.from(t); const b = Buffer.from(ADMIN_TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ----------------------------------------------------------------------------
// Logica de licenca
// ----------------------------------------------------------------------------
async function doActivate(key, hwid) {
  const r = await getKey(key);
  if (!r) return { ok: false, reason: 'chave inexistente' };
  if (r.revoked) return { ok: false, reason: 'chave revogada' };
  if (now() > Number(r.expires_at)) return { ok: false, reason: 'chave expirada' };
  if (!hwid) return { ok: false, reason: 'hwid ausente' };
  if (r.hwid && r.hwid !== hwid) return { ok: false, reason: 'chave ja vinculada a outro dispositivo' };
  if (!r.hwid) {
    await pool.query('UPDATE licenses SET hwid=$1, activated_at=$2 WHERE key=$3', [hwid, now(), key]);
  }
  return sign({ ok: true, expiresAt: Number(r.expires_at), daysLeft: daysLeft(r), ts: now() });
}
async function doValidate(key, hwid) {
  const r = await getKey(key);
  if (!r) return { ok: false, reason: 'chave inexistente' };
  if (r.revoked) return { ok: false, reason: 'chave revogada' };
  if (now() > Number(r.expires_at)) return { ok: false, reason: 'chave expirada' };
  if (!r.hwid) return { ok: false, reason: 'chave nao ativada' };
  if (r.hwid !== hwid) return { ok: false, reason: 'dispositivo nao autorizado' };
  return sign({ ok: true, expiresAt: Number(r.expires_at), daysLeft: daysLeft(r), ts: now() });
}

// ----------------------------------------------------------------------------
// Roteamento
// ----------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname, method = req.method;

    if (method === 'OPTIONS') {
      res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' });
      return res.end();
    }

    // ---- API publica (app) ----
    if (p === '/api/activate' && method === 'POST') {
      const b = await readBody(req);
      return sendJson(res, 200, await doActivate(String(b.key || '').trim(), String(b.hwid || '').trim()));
    }
    if (p === '/api/validate' && method === 'POST') {
      const b = await readBody(req);
      return sendJson(res, 200, await doValidate(String(b.key || '').trim(), String(b.hwid || '').trim()));
    }
    if (p === '/api/health') {
      const c = await pool.query('SELECT COUNT(*)::int AS n FROM licenses');
      return sendJson(res, 200, { ok: true, keys: c.rows[0].n });
    }

    // ---- Painel admin ----
    if (p === '/admin' && method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(adminHtml());
    }

    // ---- API admin ----
    if (p.startsWith('/admin/')) {
      if (!isAdmin(req)) return sendJson(res, 401, { ok: false, reason: 'nao autorizado' });

      if (p === '/admin/genkey' && method === 'POST') {
        const b = await readBody(req);
        const d = Math.max(1, parseInt(b.days || 30, 10));
        const count = Math.min(100, Math.max(1, parseInt(b.count || 1, 10)));
        const note = String(b.note || '');
        const created = [];
        for (let i = 0; i < count; i++) {
          let k;
          for (;;) { k = genKey(); if (!(await getKey(k))) break; }
          await pool.query(
            'INSERT INTO licenses(key, created, expires_at, hwid, activated_at, revoked, note) VALUES($1,$2,$3,NULL,NULL,false,$4)',
            [k, now(), now() + days(d), note]);
          created.push(k);
        }
        return sendJson(res, 200, { ok: true, keys: created });
      }
      if (p === '/admin/list' && method === 'GET') {
        const r = await pool.query('SELECT * FROM licenses ORDER BY created DESC');
        return sendJson(res, 200, { ok: true, keys: r.rows.map(publicView) });
      }
      if (p === '/admin/revoke' && method === 'POST') {
        const b = await readBody(req);
        const u = await pool.query('UPDATE licenses SET revoked=true WHERE key=$1', [String(b.key || '').trim()]);
        return sendJson(res, 200, u.rowCount ? { ok: true } : { ok: false, reason: 'chave inexistente' });
      }
      if (p === '/admin/unrevoke' && method === 'POST') {
        const b = await readBody(req);
        const u = await pool.query('UPDATE licenses SET revoked=false WHERE key=$1', [String(b.key || '').trim()]);
        return sendJson(res, 200, u.rowCount ? { ok: true } : { ok: false, reason: 'chave inexistente' });
      }
      if (p === '/admin/renew' && method === 'POST') {
        const b = await readBody(req); const key = String(b.key || '').trim();
        const r = await getKey(key);
        if (!r) return sendJson(res, 200, { ok: false, reason: 'chave inexistente' });
        const d = Math.max(1, parseInt(b.days || 30, 10));
        const base = Math.max(now(), Number(r.expires_at));
        const exp = base + days(d);
        await pool.query('UPDATE licenses SET expires_at=$1 WHERE key=$2', [exp, key]);
        return sendJson(res, 200, { ok: true, expiresAt: new Date(exp).toISOString() });
      }
      if (p === '/admin/unbind' && method === 'POST') {
        const b = await readBody(req);
        const u = await pool.query('UPDATE licenses SET hwid=NULL, activated_at=NULL WHERE key=$1', [String(b.key || '').trim()]);
        return sendJson(res, 200, u.rowCount ? { ok: true } : { ok: false, reason: 'chave inexistente' });
      }
      if (p === '/admin/delete' && method === 'POST') {
        const b = await readBody(req);
        const u = await pool.query('DELETE FROM licenses WHERE key=$1', [String(b.key || '').trim()]);
        return sendJson(res, 200, u.rowCount ? { ok: true } : { ok: false, reason: 'chave inexistente' });
      }
      return sendJson(res, 404, { ok: false, reason: 'rota admin inexistente' });
    }

    if (p === '/') { res.writeHead(302, { Location: '/admin' }); return res.end(); }
    sendJson(res, 404, { ok: false, reason: 'rota inexistente' });
  } catch (e) {
    console.error(e);
    sendJson(res, 500, { ok: false, reason: 'erro interno' });
  }
});

initDb().then(() => {
  server.listen(PORT, () => {
    console.log('=== Unic Client - Servidor de Licencas (Postgres) ===');
    console.log('Porta:        ' + PORT);
    console.log('Painel admin: http://localhost:' + PORT + '/admin');
    if (ADMIN_TOKEN === 'troque-este-token-admin') console.log('AVISO: defina ADMIN_TOKEN!');
    if (SIGN_SECRET === 'troque-este-segredo-de-assinatura') console.log('AVISO: defina SIGN_SECRET!');
  });
}).catch((e) => { console.error('Falha ao iniciar o banco:', e); process.exit(1); });

// ----------------------------------------------------------------------------
// Painel admin (HTML)
// ----------------------------------------------------------------------------
function adminHtml() {
  return `<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Licencas - Admin</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:'Segoe UI',system-ui,sans-serif;background:#0f1115;color:#e6e8ec;padding:22px}
h1{font-size:20px;letter-spacing:2px;margin:0 0 14px}
.card{background:#171a21;border:1px solid #262b34;border-radius:14px;padding:18px;margin-bottom:16px;max-width:980px}
label{font-size:12px;color:#8b929c;display:block;margin:8px 0 4px}
input{padding:10px 12px;border:1px solid #2b313b;border-radius:9px;background:#0f1115;color:#e6e8ec;font-size:14px;outline:none}
button{padding:10px 16px;border:none;border-radius:9px;cursor:pointer;font-weight:600;color:#fff;background:#3a82f6;margin-right:6px}
button.g{background:#2b313b}button.r{background:#c0392b}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #20242c}
th{color:#8b929c;font-weight:600}.mono{font-family:Consolas,monospace}
.s-ativa{color:#46d27e}.s-expirada{color:#e0a23b}.s-revogada{color:#e25555}.s-nao{color:#8b929c}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
pre{background:#0f1115;border:1px solid #262b34;border-radius:9px;padding:10px;white-space:pre-wrap;word-break:break-all}
small{color:#8b929c}
</style></head><body>
<h1>UNIC CLIENT &mdash; LICENCAS</h1>
<div class="card">
  <label>Token de admin</label>
  <div class="row"><input id="tok" type="password" placeholder="ADMIN_TOKEN" style="min-width:280px">
  <button onclick="save()">Salvar token</button><small id="who"></small></div>
</div>
<div class="card">
  <div class="row">
    <div><label>Dias de validade</label><input id="days" type="number" value="30" min="1" style="width:120px"></div>
    <div><label>Quantidade</label><input id="count" type="number" value="1" min="1" max="100" style="width:120px"></div>
    <div><label>Nota (opcional)</label><input id="note" type="text" placeholder="cliente / obs" style="width:220px"></div>
    <button onclick="gen()">Gerar chave(s)</button>
  </div>
  <pre id="genout" style="display:none"></pre>
</div>
<div class="card">
  <div class="row"><button class="g" onclick="load()">Atualizar lista</button><small id="msg"></small></div>
  <table id="tbl"><thead><tr><th>Chave</th><th>Status</th><th>Validade</th><th>Dias</th><th>HWID</th><th>Nota</th><th>Acoes</th></tr></thead><tbody></tbody></table>
</div>
<script>
const $=i=>document.getElementById(i);
function tok(){return localStorage.getItem('lic_tok')||'';}
function save(){localStorage.setItem('lic_tok',$('tok').value.trim());$('who').textContent='token salvo';load();}
async function api(path,method,body){
  const r=await fetch(path,{method:method||'GET',headers:{'Content-Type':'application/json','Authorization':'Bearer '+tok()},body:body?JSON.stringify(body):undefined});
  return r.json();
}
async function gen(){
  const j=await api('/admin/genkey','POST',{days:+$('days').value||30,count:+$('count').value||1,note:$('note').value});
  if(!j.ok){alert('Erro: '+(j.reason||'falhou'));return;}
  $('genout').style.display='block';$('genout').textContent=j.keys.join('\\n');load();
}
async function load(){
  const j=await api('/admin/list','GET');
  if(!j.ok){$('msg').textContent='Token invalido?';return;}
  $('msg').textContent=j.keys.length+' chave(s)';
  const tb=$('tbl').querySelector('tbody');tb.innerHTML='';
  j.keys.forEach(k=>{
    const tr=document.createElement('tr');
    const sc={ativa:'s-ativa',expirada:'s-expirada',revogada:'s-revogada','nao ativada':'s-nao'}[k.status]||'';
    tr.innerHTML='<td class=mono>'+k.key+'</td>'+
      '<td class="'+sc+'">'+k.status+'</td>'+
      '<td>'+k.expiresAt.slice(0,10)+'</td>'+
      '<td>'+k.daysLeft+'</td>'+
      '<td class=mono>'+(k.hwid||'-')+'</td>'+
      '<td>'+(k.note||'')+'</td>'+
      '<td></td>';
    const td=tr.lastChild;
    const mk=(label,cls,fn)=>{const b=document.createElement('button');b.textContent=label;if(cls)b.className=cls;b.style.padding='5px 9px';b.style.fontSize='12px';b.onclick=fn;td.appendChild(b);};
    if(k.status==='revogada') mk('Reativar','g',()=>act('/admin/unrevoke',k.key));
    else mk('Revogar','r',()=>act('/admin/revoke',k.key));
    mk('+30d','g',()=>act('/admin/renew',k.key,{days:30}));
    if(k.hwid) mk('Desvincular','g',()=>act('/admin/unbind',k.key));
    mk('Excluir','r',()=>{if(confirm('Excluir '+k.key+'?'))act('/admin/delete',k.key);});
    tb.appendChild(tr);
  });
}
async function act(path,key,extra){const j=await api(path,'POST',Object.assign({key},extra||{}));if(!j.ok)alert('Erro: '+(j.reason||'falhou'));load();}
$('tok').value=tok();if(tok())load();
</script></body></html>`;
}
