// ============================================================
// COMBATLOADER / BLACKBERRY AUTH WORKER
// Cloudflare Workers + D1 Database (Mobile Optimized)
// ============================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';

    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: cors });
    }

    try {
      if (path === '/' || path === '/panel') {
        return new Response(getPanelHTML(), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }

      if (path === '/api.php' || path === '/login') {
        return await handleLogin(request, env, ip);
      }

      if (path.startsWith('/admin/')) {
        return await handleAdmin(request, env, path, cors);
      }

      return new Response('Not Found', { status: 404 });
    } catch (e) {
      return new Response('Internal Error: ' + e.message, { status: 500 });
    }
  }
};

// ============================================================
// LOGIN API (Lua)
// ============================================================
async function handleLogin(request, env, ip) {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

  let body;
  try { body = await request.text(); } catch { return textResponse('invalid body'); }

  const params = new URLSearchParams(body);
  const userKey   = (params.get('user_key') || params.get('key') || '').trim();
  const hwid      = (params.get('hwid') || '').trim();

  if (!userKey || userKey.length < 3 || userKey.length > 128) {
    return textResponse('invalid - bad key format');
  }
  if (!hwid || hwid.length < 5 || hwid.length > 256) {
    return textResponse('invalid - bad hwid');
  }

  try {
    const keyRecord = await env.DB.prepare('SELECT * FROM keys WHERE key = ? LIMIT 1').bind(userKey).first();

    if (!keyRecord) return textResponse('invalid - key not found');
    if (!keyRecord.active) return textResponse('invalid - key disabled');

    const nowSec = Math.floor(Date.now() / 1000);
    if (keyRecord.expires_at > 0 && nowSec > keyRecord.expires_at) {
      return textResponse('expired - key has expired');
    }

    if (!keyRecord.hwid || keyRecord.hwid === '') {
      await env.DB.prepare('UPDATE keys SET hwid = ?, last_login = ? WHERE id = ?')
        .bind(hwid, nowSec, keyRecord.id).run();
    } else if (keyRecord.hwid !== hwid) {
      return textResponse('HWID mismatch - bound to another device');
    } else {
      await env.DB.prepare('UPDATE keys SET last_login = ? WHERE id = ?')
        .bind(nowSec, keyRecord.id).run();
    }

    let daysLeft = 'unlimited';
    if (keyRecord.expires_at > 0) {
      daysLeft = Math.ceil((keyRecord.expires_at - nowSec) / 86400) + ' days';
    }

    return textResponse('SUCCESS\nKey verified OK\nDays remaining: ' + daysLeft + '\nWelcome to CombatLoader');
  } catch (err) {
    return textResponse('error - database error: ' + err.message);
  }
}

function textResponse(text) {
  return new Response(text, { status: 200, headers: { 'Content-Type': 'text/plain' } });
}

// ============================================================
// ADMIN API
// ============================================================
async function handleAdmin(request, env, path, cors) {
  if (!env.ADMIN_TOKEN) {
    return jsonResponse({ error: 'ADMIN_TOKEN belum di-set di Cloudflare!' }, 500, cors);
  }

  const token = request.headers.get('X-Admin-Token');
  if (token !== env.ADMIN_TOKEN) return jsonResponse({ error: 'Password salah!' }, 401, cors);

  try {
    if (path === '/admin/ping' && request.method === 'GET') {
      return jsonResponse({ ok: true }, 200, cors);
    }

    if (path === '/admin/keys' && request.method === 'GET') {
      const results = await env.DB.prepare('SELECT * FROM keys ORDER BY created_at DESC LIMIT 500').all();
      return jsonResponse({ keys: results.results || [] }, 200, cors);
    }

    if (path === '/admin/keys' && request.method === 'POST') {
      const body = await request.json();
      let key = (body.key || '').trim();
      if (!key) {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        key = 'CB-' + Array.from({length: 4}, () => Array.from({length: 6}, () => chars[Math.floor(Math.random() * chars.length)]).join('')).join('-');
      }
      const days = parseInt(body.days || '0', 10);
      const now = Math.floor(Date.now() / 1000);
      const expiresAt = days > 0 ? now + (days * 86400) : 0;

      await env.DB.prepare('INSERT INTO keys (key, expires_at, notes, active, created_at) VALUES (?, ?, ?, 1, ?)')
        .bind(key, expiresAt, body.notes || '', now).run();
      return jsonResponse({ ok: true, key, expires_at: expiresAt }, 200, cors);
    }

    if (path === '/admin/keys/delete' && request.method === 'POST') {
      const body = await request.json();
      await env.DB.prepare('DELETE FROM keys WHERE key = ?').bind(body.key).run();
      return jsonResponse({ ok: true }, 200, cors);
    }

    return jsonResponse({ error: 'Endpoint tidak ditemukan' }, 404, cors);
  } catch (e) {
    return jsonResponse({ error: 'DB Error: Pastikan tabel sudah dibuat. ' + e.message }, 500, cors);
  }
}

function jsonResponse(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status, headers: { ...cors, 'Content-Type': 'application/json' } });
}

// ============================================================
// UI PANEL (Bebas Bug Browser HP)
// ============================================================
function getPanelHTML() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auth Panel</title>
<style>
  body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
  .card { background: #1e293b; padding: 20px; border-radius: 8px; max-width: 600px; margin: auto; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
  input, button { padding: 12px; margin: 8px 0; width: 100%; border-radius: 5px; border: none; box-sizing: border-box; font-size: 16px; }
  button { background: #10b981; color: #fff; cursor: pointer; font-weight: bold; transition: 0.2s; }
  button:hover { background: #059669; }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
  th, td { padding: 10px; border-bottom: 1px solid #334155; text-align: left; }
  .badge { padding: 3px 8px; border-radius: 4px; font-size: 12px; }
  .active { background: #065f46; color: #34d399; }
  .inactive { background: #7f1d1d; color: #fca5a5; }
  #errorMsg { color: #ef4444; font-size: 14px; margin-top: 10px; font-weight: bold; text-align: center; min-height: 20px; }
</style>
</head>
<body>
<div class="card" id="loginBox">
  <h2 style="text-align:center; margin-bottom: 20px;">Admin Login</h2>
  <input type="password" id="pass" placeholder="Masukkan Password Panel">
  <button id="loginBtn" onclick="this.innerText='Memeriksa...'; this.disabled=true; doLogin();">Login</button>
  <div id="errorMsg"></div>
</div>

<div class="card" id="panelBox" style="display:none">
  <h2>Manage Keys</h2>
  <input type="text" id="newKey" placeholder="Key (kosongkan untuk auto)">
  <input type="number" id="newDays" value="30" placeholder="Hari (0=lifetime)">
  <button onclick="createKey()">Buat Key</button>
  <button onclick="logout()" style="background:#ef4444; margin-top:20px">Logout</button>
  <table id="keysTable">
    <tr><th>Key</th><th>Status</th><th>Expired</th><th>Aksi</th></tr>
  </table>
</div>

<script>
var token = '';
try { token = localStorage.getItem('token') || ''; } catch(e) { console.log('LocalStorage blocked'); }

if(token) {
  document.getElementById('loginBox').style.display = 'none';
  document.getElementById('panelBox').style.display = 'block';
  loadKeys();
}

function doLogin() {
  var passVal = document.getElementById('pass').value;
  var btn = document.getElementById('loginBtn');
  var errDiv = document.getElementById('errorMsg');
  
  errDiv.innerText = '';
  
  fetch('/admin/ping', {
    method: 'GET',
    headers: { 'X-Admin-Token': passVal }
  })
  .then(function(res) { return res.text(); })
  .then(function(text) {
    var d;
    try { d = JSON.parse(text); } catch(e) { d = { error: 'Respons tidak valid: ' + text }; }
    
    if(d && d.ok) { 
      try { localStorage.setItem('token', passVal); } catch(e) {}
      window.location.reload(); 
    } else {
      btn.innerText = 'Login';
      btn.disabled = false;
      errDiv.innerText = d.error || 'Password Salah!';
    }
  })
  .catch(function(err) {
    btn.innerText = 'Login';
    btn.disabled = false;
    errDiv.innerText = 'Koneksi error: ' + err.message;
  });
}

function logout() { 
  try { localStorage.removeItem('token'); } catch(e) {}
  window.location.reload(); 
}

function loadKeys() {
  fetch('/admin/keys', { headers: { 'X-Admin-Token': token } })
  .then(function(res) { return res.json(); })
  .then(function(d) {
    if(d.error) { alert('Gagal load: ' + d.error); return; }
    if(!d.keys) return;
    
    var t = document.getElementById('keysTable');
    t.innerHTML = '<tr><th>Key</th><th>Status</th><th>Expired</th><th>Aksi</th></tr>';
    
    for(var i=0; i < d.keys.length; i++) {
      var k = d.keys[i];
      var exp = k.expires_at > 0 ? new Date(k.expires_at*1000).toISOString().split('T')[0] : 'Lifetime';
      var badgeClass = k.active ? 'active' : 'inactive';
      var badgeText = k.active ? 'Active' : 'Off';
      
      t.innerHTML += '<tr>' +
        '<td><b>' + k.key + '</b></td>' +
        '<td><span class="badge ' + badgeClass + '">' + badgeText + '</span></td>' +
        '<td>' + exp + '</td>' +
        '<td><button onclick="del(\'' + k.key + '\')" style="width:auto; background:#ef4444; padding:5px 10px">Hapus</button></td>' +
      '</tr>';
    }
  });
}

function createKey() {
  var key = document.getElementById('newKey').value;
  var days = document.getElementById('newDays').value;
  
  fetch('/admin/keys', { 
    method: 'POST', 
    headers: { 'Content-Type': 'application/json', 'X-Admin-Token': token },
    body: JSON.stringify({ key: key, days: days }) 
  })
  .then(function(res) { return res.json(); })
  .then(function(r) {
    if(r.ok) { alert('Key dibuat: ' + r.key); loadKeys(); }
    else { alert('Gagal membuat key: ' + (r.error || 'Terjadi kesalahan')); }
  });
}

function del(key) {
  if(confirm('Hapus key ' + key + '?')) { 
    fetch('/admin/keys/delete', { 
      method: 'POST', 
      headers: { 'Content-Type': 'application/json', 'X-Admin-Token': token },
      body: JSON.stringify({ key: key }) 
    }).then(function() { loadKeys(); });
  }
}
</script>
</body>
</html>`;
}
