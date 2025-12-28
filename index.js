/**
 * index.js
 *
 * 单文件 Node.js 应用 — 通过 Let's Encrypt (ACME) 申请受信任证书（默认 production）
 * 特性：
 * - 登录（默认 admin / 12345678）
 * - 支持上传 CSR 或 服务器生成私钥+CSR
 * - 支持验证：HTTP-01、DNS-01（手动）、DNS-01（Cloudflare 自动）
 * - 导出格式：PEM (.crt/.key)、DER (.der)、PFX (.pfx)
 *
 * 注意（必读）：
 * - HTTP-01 验证需要 Let’s Encrypt 能访问域名的 80 端口（可用反向代理把 /.well-known/acme-challenge 转发到本程序）。
 * - 强烈建议先使用 staging 环境做测试（页面可切换），避免触发 production 的限流。
 * - 此示例把密钥/证书保存在内存（重启丢失）。生产请持久化并保护好凭据。
 * - 默认端口：3000（可用环境变量 PORT 覆盖）
 *
 * 使用：
 * 1. npm install
 * 2. PORT=3000 node index.js
 * 3. 浏览器访问 http://<host>:3000
 */

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const acme = require('acme-client');
const forge = require('node-forge');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

const PORT = process.env.PORT || 3000;

// In-memory stores (demo)
const STORE = {}; // id -> { name, files, meta }
const HTTP_TOKENS = {}; // token -> keyAuthorization
const PENDING_DNS = {}; // id -> pending context for manual DNS
let CF_API_TOKEN = ''; // Cloudflare API token (optional)

// Admin (demo only)
const ADMIN_USER = 'admin';
const ADMIN_PASS = '12345678';

// Middleware
app.use(session({
  secret: 'acme-demo-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 2 * 3600 * 1000 }
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Serve ACME HTTP-01 tokens
app.get('/.well-known/acme-challenge/:token', (req, res) => {
  const tok = req.params.token;
  const val = HTTP_TOKENS[tok];
  if (!val) return res.status(404).send('Not Found');
  res.type('text/plain').send(val);
});

// Helpers
function requireAuth(req, res, next) {
  if (req.session && req.session.authed) return next();
  res.redirect('/login');
}
function escapeHtml(s = '') {
  return String(s).replace(/[&<>"']/g, ch => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[ch]);
}
function renderPage(title, bodyHtml) {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>${escapeHtml(title)}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{padding:20px;background:#f6f8fa}.card{border-radius:10px}.monos{font-family:ui-monospace,Menlo,monospace}</style>
</head><body>
<div class="container">
<nav class="navbar navbar-light bg-white shadow-sm mb-4 rounded"><div class="container-fluid"><a class="navbar-brand" href="/">ACME SSL 管理</a><div><a class="btn btn-outline-secondary btn-sm" href="/logout">退出</a></div></div></nav>
${bodyHtml}
<footer class="mt-4 text-center text-muted"><small>演示用途 — 请妥善保护管理员账号与证书数据。默认登录：admin / 12345678</small></footer>
</div></body></html>`;
}

// Converters
function certPemToDerBuffer(pem) {
  const cert = forge.pki.certificateFromPem(pem);
  const asn1 = forge.pki.certificateToAsn1(cert);
  const der = forge.asn1.toDer(asn1).getBytes();
  return Buffer.from(der, 'binary');
}
function makePfxBuffer(privateKeyPem, certificatePem, passphrase) {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const cert = forge.pki.certificateFromPem(certificatePem);
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, [cert], passphrase || '', { algorithm: '3des' });
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  return Buffer.from(p12Der, 'binary');
}
function base64url(buf) {
  return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function dns01TxtValue(keyAuthorization) {
  const sha256 = crypto.createHash('sha256').update(keyAuthorization).digest();
  return base64url(sha256);
}

// Routes: auth
app.get('/login', (req, res) => {
  const err = req.query.e ? '<div class="alert alert-danger">登录失败</div>' : '';
  res.send(renderPage('登录', `
  <div class="row justify-content-center"><div class="col-md-6">
    <div class="card p-4 shadow-sm">
      <h5>管理员登录</h5>
      ${err}
      <form method="post" action="/login">
        <div class="mb-3"><label class="form-label">用户名</label><input name="username" class="form-control" value="admin" required></div>
        <div class="mb-3"><label class="form-label">密码</label><input name="password" type="password" class="form-control" value="12345678" required></div>
        <div class="d-flex justify-content-between"><button class="btn btn-primary">登录</button><a class="btn btn-link" href="/">返回</a></div>
      </form>
    </div>
  </div></div>
  `));
});
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.authed = true;
    req.session.user = username;
    res.redirect('/');
  } else res.redirect('/login?e=1');
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// Dashboard
app.get('/', requireAuth, (req, res) => {
  const certListHtml = Object.keys(STORE).length === 0 ? `<li class="list-group-item">暂无记录</li>` :
    Object.keys(STORE).reverse().map(id => {
      const it = STORE[id];
      return `<li class="list-group-item d-flex justify-content-between align-items-start"><div><strong>${escapeHtml(it.name)}</strong><br/><small class="text-muted">${escapeHtml(it.meta.type)} • ${escapeHtml(it.meta.created)}</small></div><div>${Object.keys(it.files).map(fn=>`<a class="btn btn-sm btn-outline-secondary ms-1" href="/download/${id}/${encodeURIComponent(fn)}" download="${fn}">${escapeHtml(fn)}</a>`).join('')}</div></li>`;
    }).join('');
  res.send(renderPage('在线申请 SSL（默认 production）', `
  <div class="row">
    <div class="col-md-8">
      <div class="card p-3 mb-3 shadow-sm">
        <h5>申请新证书（向 Let's Encrypt 下单）</h5>
        <form method="post" action="/request" enctype="multipart/form-data">
          <div class="mb-3"><label class="form-label">域名（逗号分隔）</label><input name="domains" class="form-control" placeholder="example.com, www.example.com" required></div>
          <div class="row mb-3">
            <div class="col-md-6"><label class="form-label">验证方式</label><select name="challenge" class="form-select"><option value="http-01">HTTP-01</option><option value="dns-01-manual">DNS-01（手动）</option><option value="dns-01-cloudflare">DNS-01（Cloudflare 自动）</option></select><div class="form-text">HTTP-01 需 80 可达</div></div>
            <div class="col-md-3"><label class="form-label">环境</label><select name="env" class="form-select"><option value="production" selected>production</option><option value="staging">staging</option></select><div class="form-text">建议先用 staging 测试</div></div>
            <div class="col-md-3"><label class="form-label">导出格式</label><div class="form-check"><input class="form-check-input" type="checkbox" name="formats" value="pem" checked><label class="form-check-label">PEM</label></div><div class="form-check"><input class="form-check-input" type="checkbox" name="formats" value="der"><label class="form-check-label">DER</label></div><div class="form-check"><input class="form-check-input" type="checkbox" name="formats" value="pfx"><label class="form-check-label">PFX</label></div></div>
          </div>
          <div class="mb-3"><label class="form-label">上传 CSR（可选）</label><input type="file" name="csrfile" accept=".csr,.pem" class="form-control"></div>
          <div class="mb-3"><label class="form-label">PFX 密码（若导出 PFX）</label><input name="pfxpass" class="form-control" placeholder="可选"></div>
          <div class="d-flex gap-2"><button class="btn btn-success">提交申请</button><a class="btn btn-outline-secondary" href="/settings">设置</a></div>
        </form>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card p-3 shadow-sm mb-3"><h6>我的申请</h6><ul class="list-group list-group-flush">${certListHtml}</ul></div>
      <div class="card p-3 shadow-sm"><h6>提示</h6><p class="small text-muted">正式环境有限流，请谨慎使用。若无法开放 80，使用 DNS-01。</p></div>
    </div>
  </div>
  `));
});

// Settings (Cloudflare token)
app.get('/settings', requireAuth, (req, res) => {
  res.send(renderPage('设置', `
  <div class="row justify-content-center"><div class="col-md-8">
    <div class="card p-3 shadow-sm">
      <h5>设置</h5>
      <form method="post" action="/settings">
        <div class="mb-3"><label class="form-label">Cloudflare API Token（可选）</label><input name="cf_token" class="form-control" value="${escapeHtml(CF_API_TOKEN)}" placeholder="用于自动添加 DNS TXT"></div>
        <div><button class="btn btn-primary">保存</button><a class="btn btn-outline-secondary ms-2" href="/">返回</a></div>
      </form>
    </div>
  </div></div>
  `));
});
app.post('/settings', requireAuth, (req, res) => {
  CF_API_TOKEN = (req.body.cf_token || '').trim();
  res.redirect('/settings');
});

// Main request flow
app.post('/request', requireAuth, upload.single('csrfile'), async (req, res) => {
  const raw = (req.body.domains || '').trim();
  if (!raw) return res.send(renderPage('错误', `<div class="alert alert-danger">请填写域名</div><a class="btn btn-outline-secondary" href="/">返回</a>`));
  const domains = raw.split(',').map(s=>s.trim()).filter(Boolean);
  const challenge = req.body.challenge || 'http-01';
  const env = req.body.env === 'staging' ? 'staging' : 'production';
  const formats = Array.isArray(req.body.formats) ? req.body.formats : (req.body.formats ? [req.body.formats] : []);
  const pfxpass = req.body.pfxpass || '';

  const directoryUrl = env === 'production' ? acme.directory.letsencrypt.production : acme.directory.letsencrypt.staging;

  try {
    const accountKey = await acme.forge.createPrivateKey();
    const client = new acme.Client({ directoryUrl, accountKey });
    await client.createAccount({ termsOfServiceAgreed: true, contact: [] });

    let privateKeyPem = null;
    let csrPem = null;
    if (req.file && req.file.buffer && req.file.buffer.length > 0) {
      csrPem = req.file.buffer.toString('utf8');
    } else {
      const [key, csr] = await acme.forge.createCsr({ commonName: domains[0], altNames: domains });
      privateKeyPem = key;
      csrPem = csr;
    }

    const order = await client.createOrder({ identifiers: domains.map(d=>({ type:'dns', value:d })) });
    const authorizations = await client.getAuthorizations(order);

    const challengeTasks = [];
    const pendingManual = [];

    for (const auth of authorizations) {
      const domain = auth.identifier.value;
      if (challenge === 'http-01') {
        const ch = auth.challenges.find(c=>c.type==='http-01');
        if (!ch) throw new Error(`域 ${domain} 不支持 http-01`);
        const keyAuth = await client.getChallengeKeyAuthorization(ch);
        HTTP_TOKENS[ch.token] = keyAuth;
        await client.verifyChallenge(auth, ch);
        await client.completeChallenge(ch);
        challengeTasks.push(client.waitForValidStatus(ch));
      } else {
        const ch = auth.challenges.find(c=>c.type==='dns-01');
        if (!ch) throw new Error(`域 ${domain} 不支持 dns-01`);
        const keyAuth = await client.getChallengeKeyAuthorization(ch);
        const txtValue = dns01TxtValue(keyAuth);
        const fqdn = `_acme-challenge.${domain}`;
        if (challenge === 'dns-01-cloudflare' && CF_API_TOKEN) {
          const created = await createCloudflareTxt(domain, fqdn, txtValue, CF_API_TOKEN);
          if (!created) throw new Error(`自动创建 Cloudflare TXT 记录失败: ${domain}`);
          await client.verifyChallenge(auth, ch);
          await client.completeChallenge(ch);
          challengeTasks.push(client.waitForValidStatus(ch));
        } else {
          pendingManual.push({ domain, txtName: fqdn, txtValue, challenge: ch });
        }
      }
    }

    if (pendingManual.length > 0) {
      const id = uuidv4();
      PENDING_DNS[id] = { clientDir: directoryUrl, accountKey, order, csrPem, privateKeyPem, pendingManual, formats, pfxpass };
      return res.send(renderPage('请添加 DNS TXT 记录', `
        <div class="card p-3 shadow-sm">
          <h5>DNS-01 手动验证</h5>
          ${pendingManual.map(p => `<div class="mb-3"><strong>${escapeHtml(p.domain)}</strong><div class="monos mt-1">${escapeHtml(p.txtName)}</div><div class="mt-1"><code class="monos">${escapeHtml(p.txtValue)}</code></div><small class="text-muted">添加后等待生效，再点击下方按钮验证并完成申请。</small></div>`).join('')}
          <form method="post" action="/verify-dns"><input type="hidden" name="id" value="${id}"><button class="btn btn-primary">我已添加并验证</button> <a class="btn btn-outline-secondary" href="/">返回</a></form>
        </div>
      `));
    }

    await Promise.all(challengeTasks);
    const finalized = await client.finalizeOrder(order, csrPem);
    const certPem = await client.getCertificate(finalized);

    const id = uuidv4();
    const files = {};
    if (formats.includes('pem')) {
      files[`${domains[0]}.crt.pem`] = Buffer.from(certPem, 'utf8');
      if (privateKeyPem) files[`${domains[0]}.key.pem`] = Buffer.from(privateKeyPem, 'utf8');
    }
    if (formats.includes('der')) {
      files[`${domains[0]}.crt.der`] = certPem ? certPemToDerBuffer(certPem) : Buffer.from('');
    }
    if (formats.includes('pfx')) {
      if (!privateKeyPem) {
        files[`${domains[0]}.pfx-not-available.txt`] = Buffer.from('无法生成 PFX：上传了 CSR，服务器没有私钥。', 'utf8');
      } else {
        files[`${domains[0]}.pfx`] = makePfxBuffer(privateKeyPem, certPem, pfxpass);
      }
    }

    STORE[id] = { name: domains.join(', '), files, meta: { type:'letsencrypt', env, cn: domains[0], created: new Date().toISOString() } };

    // cleanup http tokens
    for (const k in HTTP_TOKENS) delete HTTP_TOKENS[k];

    const links = Object.keys(files).map(fn=>`<a class="btn btn-sm btn-outline-primary me-1" href="/download/${id}/${encodeURIComponent(fn)}" download="${fn}">${escapeHtml(fn)}</a>`).join(' ');
    res.send(renderPage('申请成功', `<div class="card p-3 shadow-sm"><h5>证书签发成功</h5><p>域名：<strong>${escapeHtml(domains.join(', '))}</strong></p><div>${links}</div><a class="btn btn-outline-secondary mt-2" href="/">返回首页</a></div>`));
  } catch (err) {
    console.error(err);
    res.send(renderPage('错误', `<div class="alert alert-danger">申请失败：${escapeHtml(err && err.message ? err.message : String(err))}</div><a class="btn btn-outline-secondary" href="/">返回</a>`));
  }
});

// Verify DNS manual flow
app.post('/verify-dns', requireAuth, async (req, res) => {
  const id = req.body.id;
  if (!id || !PENDING_DNS[id]) return res.send(renderPage('错误', `<div class="alert alert-danger">找不到待验证记录或已过期</div><a class="btn btn-outline-secondary" href="/">返回</a>`));
  const ctx = PENDING_DNS[id];
  try {
    const client = new acme.Client({ directoryUrl: ctx.clientDir, accountKey: ctx.accountKey });
    const order = ctx.order;
    const authorizations = await client.getAuthorizations(order);

    for (const p of ctx.pendingManual) {
      const auth = authorizations.find(a=>a.identifier.value===p.domain);
      if (!auth) throw new Error('找不到 authorization: ' + p.domain);
      const ch = auth.challenges.find(c=>c.type==='dns-01');
      if (!ch) throw new Error('找不到 dns-01 challenge: ' + p.domain);
      await client.verifyChallenge(auth, ch);
      await client.completeChallenge(ch);
      await client.waitForValidStatus(ch);
    }

    const finalized = await client.finalizeOrder(order, ctx.csrPem);
    const certPem = await client.getCertificate(finalized);

    const id2 = uuidv4();
    const files = {};
    if (ctx.formats.includes('pem')) {
      files[`${ctx.pendingManual[0].domain}.crt.pem`] = Buffer.from(certPem, 'utf8');
      if (ctx.privateKeyPem) files[`${ctx.pendingManual[0].domain}.key.pem`] = Buffer.from(ctx.privateKeyPem, 'utf8');
    }
    if (ctx.formats.includes('der')) files[`${ctx.pendingManual[0].domain}.crt.der`] = certPem ? certPemToDerBuffer(certPem) : Buffer.from('');
    if (ctx.formats.includes('pfx')) {
      if (!ctx.privateKeyPem) files[`${ctx.pendingManual[0].domain}.pfx-not-available.txt`] = Buffer.from('无法生成 PFX：上传了 CSR，服务器没有私钥。', 'utf8');
      else files[`${ctx.pendingManual[0].domain}.pfx`] = makePfxBuffer(ctx.privateKeyPem, certPem, ctx.pfxpass);
    }

    STORE[id2] = { name: ctx.pendingManual.map(p=>p.domain).join(', '), files, meta: { type:'letsencrypt', env: ctx.clientDir===acme.directory.letsencrypt.production ? 'production' : 'staging', cn: ctx.pendingManual[0].domain, created: new Date().toISOString() } };

    delete PENDING_DNS[id];

    const links = Object.keys(files).map(fn=>`<a class="btn btn-sm btn-outline-primary me-1" href="/download/${id2}/${encodeURIComponent(fn)}" download="${fn}">${escapeHtml(fn)}</a>`).join(' ');
    res.send(renderPage('验证并颁发成功', `<div class="card p-3 shadow-sm"><h5>证书签发成功</h5><div>${links}</div><a class="btn btn-outline-secondary mt-2" href="/">返回首页</a></div>`));
  } catch (err) {
    console.error(err);
    res.send(renderPage('错误', `<div class="alert alert-danger">验证或颁发失败：${escapeHtml(err && err.message ? err.message : String(err))}</div><a class="btn btn-outline-secondary" href="/">返回</a>`));
  }
});

// Download
app.get('/download/:id/:filename', requireAuth, (req, res) => {
  const id = req.params.id;
  const filename = decodeURIComponent(req.params.filename || '');
  const entry = STORE[id];
  if (!entry) return res.status(404).send('Not found');
  const file = entry.files[filename];
  if (!file) return res.status(404).send('Not found');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  if (filename.endsWith('.pem') || filename.endsWith('.crt') || filename.endsWith('.key') || filename.endsWith('.txt')) res.setHeader('Content-Type', 'application/x-pem-file; charset=utf-8');
  else if (filename.endsWith('.der')) res.setHeader('Content-Type', 'application/octet-stream');
  else if (filename.endsWith('.pfx')) res.setHeader('Content-Type', 'application/x-pkcs12');
  else res.setHeader('Content-Type', 'application/octet-stream');
  res.send(file);
});

// Cloudflare helper (simple)
async function createCloudflareTxt(domain, name, value, token) {
  try {
    const zonesResp = await fetch('https://api.cloudflare.com/client/v4/zones', {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    });
    const zonesBody = await zonesResp.json();
    if (!zonesBody.success) return false;
    const zones = zonesBody.result || [];
    let zone = null;
    for (const z of zones) {
      if (domain === z.name || domain.endsWith('.' + z.name)) { zone = z; break; }
    }
    if (!zone) return false;
    const zoneId = zone.id;
    const resp = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'TXT', name: name, content: value, ttl: 120 })
    });
    const body = await resp.json();
    return body && body.success;
  } catch (e) {
    console.error('Cloudflare API error', e);
    return false;
  }
}

// Start
app.listen(PORT, () => {
  console.log(`ACME demo server listening on http://0.0.0.0:${PORT}`);
  console.log('默认登录：admin / 12345678');
  console.log('注意：若使用 HTTP-01 请确保域名解析到本服务器并开放 80 端口（或将 /.well-known/* 转发）。');
});
