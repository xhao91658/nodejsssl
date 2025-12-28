```javascript
/**
 * index.js
 *
 * 单文件 Node.js 应用 — 通过 Let's Encrypt (ACME) 真正申请受信任证书（支持 HTTP-01 与 DNS-01 手动/Cloudflare）
 * - 单文件部署（配合 package.json）
 * - 登录（默认 admin / 12345678）
 * - 支持上传 CSR 或 服务器生成私钥+CSR
 * - 支持导出：PEM (.crt/.key), DER (.der), PFX (.pfx)
 * - 默认使用 Let's Encrypt staging（可在界面切换到 production）
 *
 * 注意与部署要求（重要）
 * - HTTP-01 验证需要把目标域名解析到此服务器并能让本程序对外提供 HTTP（端口 80）。
 *   如果你无法监听 80，请使用 DNS-01（手动或 Cloudflare 自动化）。
 * - 本程序仅用于测试/演示。请在生产环境中妥善保护管理员账号、持久化存储证书并启用 HTTPS 访问管理界面（本示例管理界面是通过 HTTP 提供的）。
 *
 * 使用：
 * 1) npm install
 * 2) node index.js
 * 3) 浏览器访问 http://<your-server>:3000 登录（admin / 12345678）
 *
 * 依赖（package.json 已列出）：
 * express, express-session, body-parser, multer, acme-client, node-forge, uuid, node-fetch
 *
 * 说明：
 * - 本程序在内存中保存已签发证书（重启失效）。可以根据需要改成文件/数据库持久化。
 * - Cloudflare 自动化 DNS 需要在 管理界面 -> 设置 中填写 Cloudflare API Token（最小权限： Zone.Zone, Zone.DNS）
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

// ---------- Simple in-memory storage (demo) ----------
const STORE = {}; // id -> { name, files: { filename: Buffer }, meta }
const HTTP_TOKENS = {}; // token -> keyAuthorization (for http-01 challenge responses)
const PENDING_DNS = {}; // pending dns challenges (for manual verify flow)
let CF_API_TOKEN = ''; // Cloudflare API token (optional, can be set in settings UI)

// ---------- Admin credentials (demo only) ----------
const ADMIN_USER = 'admin';
const ADMIN_PASS = '12345678';

// ---------- Middleware ----------
app.use(session({
  secret: 'acme-demo-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 2 * 3600 * 1000 }
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// serve ACME http-01 challenge responses
app.get('/.well-known/acme-challenge/:token', (req, res) => {
  const tok = req.params.token;
  const val = HTTP_TOKENS[tok];
  if (!val) return res.status(404).send('Not Found');
  res.set('Content-Type', 'text/plain');
  res.send(val);
});

// ---------- Helpers ----------
function requireAuth(req, res, next) {
  if (req.session && req.session.authed) return next();
  res.redirect('/login');
}

function escapeHtml(s = '') {
  return String(s).replace(/[&<>"']/g, ch => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  })[ch]);
}

function renderPage(title, bodyHtml) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${escapeHtml(title)}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding: 24px; background: #f6f8fa; }
    .card { border-radius: 12px; }
    .monos { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, "Roboto Mono", "Courier New", monospace; }
    footer { margin-top: 24px; color: #666; font-size: 13px; }
  </style>
</head>
<body>
<div class="container">
  <nav class="navbar navbar-expand-lg navbar-light bg-white shadow-sm mb-4 rounded">
    <div class="container-fluid">
      <a class="navbar-brand" href="/">ACME SSL 申请台</a>
      <div class="d-flex">
        <a class="btn btn-outline-secondary btn-sm me-2" href="/logout">退出</a>
      </div>
    </div>
  </nav>

  ${bodyHtml}

  <footer class="text-center">
    <small>演示程序 — 使用 Let's Encrypt（ACME）。请确保你对域名拥有控制权并按提示完成验证。默认登录：admin / 12345678</small>
  </footer>
</div>
</body>
</html>`;
}

// Convert PEM certificate to DER Buffer
function certPemToDerBuffer(pem) {
  const cert = forge.pki.certificateFromPem(pem);
  const asn1 = forge.pki.certificateToAsn1(cert);
  const der = forge.asn1.toDer(asn1).getBytes();
  return Buffer.from(der, 'binary');
}

// Create PFX buffer from privateKeyPem and certificatePem. passphrase may be empty string.
function makePfxBuffer(privateKeyPem, certificatePem, passphrase) {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const cert = forge.pki.certificateFromPem(certificatePem);
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, [cert], passphrase || '', { algorithm: '3des' });
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  return Buffer.from(p12Der, 'binary');
}

// base64url (no padding)
function base64url(buf) {
  return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

// Compute DNS-01 TXT value from keyAuthorization
function dns01TxtValue(keyAuthorization) {
  const sha256 = crypto.createHash('sha256').update(keyAuthorization).digest();
  return base64url(sha256);
}

// ---------- Routes: auth ----------
app.get('/login', (req, res) => {
  const err = req.query.e ? '<div class="alert alert-danger">用户名或密码错误</div>' : '';
  res.send(renderPage('登录', `
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card p-4 shadow-sm">
          <h4>管理员登录</h4>
          ${err}
          <form method="post" action="/login">
            <div class="mb-3">
              <label class="form-label">用户名</label>
              <input name="username" class="form-control" value="admin" required/>
            </div>
            <div class="mb-3">
              <label class="form-label">密码</label>
              <input name="password" type="password" class="form-control" value="12345678" required/>
            </div>
            <div class="d-flex justify-content-between">
              <button class="btn btn-primary">登录</button>
              <a class="btn btn-link" href="/">返回首页</a>
            </div>
          </form>
        </div>
      </div>
    </div>
  `));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.authed = true;
    req.session.user = username;
    res.redirect('/');
  } else {
    res.redirect('/login?e=1');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ---------- Dashboard ----------
app.get('/', requireAuth, (req, res) => {
  const certListHtml = Object.keys(STORE).length === 0
    ? `<li class="list-group-item">暂无记录</li>`
    : Object.keys(STORE).reverse().map(id => {
      const item = STORE[id];
      return `<li class="list-group-item">
        <div class="d-flex justify-content-between align-items-start">
          <div>
            <strong>${escapeHtml(item.name)}</strong><br/>
            <small class="text-muted">${escapeHtml(item.meta.type)} • ${escapeHtml(item.meta.created)}</small>
          </div>
          <div>
            ${Object.keys(item.files).map(fn => {
              return `<a class="btn btn-sm btn-outline-secondary ms-1" href="/download/${id}/${encodeURIComponent(fn)}" download="${fn}">${escapeHtml(fn)}</a>`;
            }).join('')}
          </div>
        </div>
      </li>`;
    }).join('');

  res.send(renderPage('在线申请 SSL 证书', `
    <div class="row">
      <div class="col-md-8">
        <div class="card mb-3 p-3 shadow-sm">
          <h5>申请新证书（真实向 Let's Encrypt 下单）</h5>
          <form id="orderForm" method="post" action="/request" enctype="multipart/form-data">
            <div class="mb-3">
              <label class="form-label">域名（主域名，多个用逗号分隔，例如 example.com, www.example.com）</label>
              <input name="domains" class="form-control" placeholder="example.com, www.example.com" required>
            </div>

            <div class="row mb-3">
              <div class="col-md-6">
                <label class="form-label">验证方式</label>
                <select name="challenge" class="form-select">
                  <option value="http-01">HTTP-01（自动，在 /.well-known/acme-challenge/ 提供）</option>
                  <option value="dns-01-manual">DNS-01（手动：会展示 TXT 值，需你在 DNS 管理面板添加）</option>
                  <option value="dns-01-cloudflare">DNS-01（Cloudflare API 自动添加 TXT）</option>
                </select>
                <div class="form-text">HTTP-01 需将域名指向本服务器并开放 80 端口。</div>
              </div>

              <div class="col-md-3">
                <label class="form-label">Let's Encrypt 环境</label>
                <select name="env" class="form-select">
                  <option value="staging" selected>staging (测试)</option>
                  <option value="production">production (正式)</option>
                </select>
                <div class="form-text">建议先用 staging 测试，避免限流。</div>
              </div>

              <div class="col-md-3">
                <label class="form-label">导出格式</label>
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="formats" value="pem" checked>
                  <label class="form-check-label">PEM (.crt/.key)</label>
                </div>
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="formats" value="der">
                  <label class="form-check-label">DER (.der)</label>
                </div>
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="formats" value="pfx">
                  <label class="form-check-label">PFX (.pfx)</label>
                </div>
              </div>
            </div>

            <div class="mb-3">
              <label class="form-label">上传 CSR（可选，若为空由服务器生成私钥+CSR）</label>
              <input type="file" name="csrfile" accept=".csr,.pem" class="form-control">
              <div class="form-text">如果上传 CSR，请确保包含公钥和域名信息。</div>
            </div>

            <div class="mb-3">
              <label class="form-label">PFX 密码（若选择导出 PFX）</label>
              <input name="pfxpass" class="form-control" placeholder="留空则无密码">
            </div>

            <div class="d-flex gap-2">
              <button class="btn btn-success">提交申请</button>
              <a class="btn btn-outline-secondary" href="/settings">设置 (Cloudflare API 等)</a>
            </div>
          </form>
        </div>

        <div id="logs" class="card p-3 shadow-sm">
          <h6>操作日志</h6>
          <div class="small text-muted">最新操作与错误会在页面响应中显示。请耐心等待挑战验证完成。</div>
        </div>
      </div>

      <div class="col-md-4">
        <div class="card shadow-sm p-3 mb-3">
          <h6>我的申请</h6>
          <ul class="list-group list-group-flush">
            ${certListHtml}
          </ul>
        </div>

        <div class="card shadow-sm p-3">
          <h6>内置 CA 信息</h6>
          <p class="small text-muted">本示例通过 Let's Encrypt 真实申请证书。请遵循验证流程完成申请。</p>
        </div>
      </div>
    </div>
  `));
});

// ---------- Settings (Cloudflare token) ----------
app.get('/settings', requireAuth, (req, res) => {
  res.send(renderPage('设置', `
    <div class="row justify-content-center">
      <div class="col-md-8">
        <div class="card p-3 shadow-sm">
          <h5>设置</h5>
          <form method="post" action="/settings">
            <div class="mb-3">
              <label class="form-label">Cloudflare API Token（可选，用于自动添加 DNS-01 TXT）</label>
              <input name="cf_token" class="form-control" value="${escapeHtml(CF_API_TOKEN)}" placeholder="填写时会用于自动 DNS 验证">
              <div class="form-text">Token 需包含对 Zone:Zone 与 Zone:DNS 的权限（最小权限）</div>
            </div>
            <button class="btn btn-primary">保存</button>
            <a class="btn btn-outline-secondary" href="/">返回</a>
          </form>
        </div>
      </div>
    </div>
  `));
});

app.post('/settings', requireAuth, (req, res) => {
  CF_API_TOKEN = (req.body.cf_token || '').trim();
  res.redirect('/settings');
});

// ---------- Request certificate (main flow) ----------
app.post('/request', requireAuth, upload.single('csrfile'), async (req, res) => {
  // extract params
  const rawDomains = (req.body.domains || '').trim();
  if (!rawDomains) return res.send(renderPage('错误', `<div class="alert alert-danger">请填写域名</div><a href="/">返回</a>`));
  const domains = rawDomains.split(',').map(s => s.trim()).filter(Boolean);
  const challenge = req.body.challenge || 'http-01';
  const env = req.body.env === 'production' ? 'production' : 'staging';
  const formats = Array.isArray(req.body.formats) ? req.body.formats : (req.body.formats ? [req.body.formats] : []);
  const pfxpass = req.body.pfxpass || '';

  // pick directory URL
  const directoryUrl = env === 'production' ? acme.directory.letsencrypt.production : acme.directory.letsencrypt.staging;

  // Prepare account key
  try {
    // create account keypair (PEM)
    const accountKey = await acme.forge.createPrivateKey();
    const client = new acme.Client({ directoryUrl, accountKey });

    // create account
    await client.createAccount({
      termsOfServiceAgreed: true,
      contact: []
    });

    // If user uploaded CSR, use it; else create key+csr with first domain as CN and others as altNames
    let privateKeyPem = null;
    let csrPem = null;
    if (req.file && req.file.buffer && req.file.buffer.length > 0) {
      // assume uploaded csr.pem or csr file
      csrPem = req.file.buffer.toString('utf8');
      // We won't have private key when user uploaded CSR, so PFX not available in that case
    } else {
      // create private key & CSR
      const [key, csr] = await acme.forge.createCsr({
        commonName: domains[0],
        altNames: domains
      });
      privateKeyPem = key;
      csrPem = csr;
    }

    // create order
    const order = await client.createOrder({
      identifiers: domains.map(d => ({ type: 'dns', value: d }))
    });

    // get authorizations
    const authorizations = await client.getAuthorizations(order);

    // collect challenges
    const challengeTasks = [];
    const pendingManual = []; // store dns manual info for show
    for (const auth of authorizations) {
      const domain = auth.identifier.value;
      if (challenge === 'http-01') {
        const ch = auth.challenges.find(c => c.type === 'http-01');
        if (!ch) throw new Error(`域 ${domain} 不支持 http-01 挑战`);
        const keyAuth = await client.getChallengeKeyAuthorization(ch);
        // store token response for ACME server to fetch
        HTTP_TOKENS[ch.token] = keyAuth;
        // verify (some ACME servers require calling verify/complete)
        await client.verifyChallenge(auth, ch);
        await client.completeChallenge(ch);
        // wait for status
        challengeTasks.push(client.waitForValidStatus(ch));
      } else if (challenge === 'dns-01-manual' || (challenge === 'dns-01-cloudflare')) {
        const ch = auth.challenges.find(c => c.type === 'dns-01');
        if (!ch) throw new Error(`域 ${domain} 不支持 dns-01 挑战`);
        const keyAuth = await client.getChallengeKeyAuthorization(ch);
        const txtValue = dns01TxtValue(keyAuth);
        const fqdn = `_acme-challenge.${domain}`;
        if (challenge === 'dns-01-cloudflare' && CF_API_TOKEN) {
          // automated via Cloudflare
          const created = await createCloudflareTxt(domain, fqdn, txtValue, CF_API_TOKEN);
          if (!created) throw new Error(`为域 ${domain} 自动创建 DNS TXT 记录失败`);
          // proceed to verify+complete
          await client.verifyChallenge(auth, ch);
          await client.completeChallenge(ch);
          challengeTasks.push(client.waitForValidStatus(ch));
        } else {
          // manual: save needed info for user and postpone verification
          pendingManual.push({
            domain,
            token: ch.token,
            txtName: fqdn,
            txtValue,
            challenge: ch
          });
        }
      } else {
        throw new Error('不支持的挑战类型: ' + challenge);
      }
    }

    // If we have manual pending (dns manual), store it and show page to user to add TXT records
    if (pendingManual.length > 0) {
      const id = uuidv4();
      PENDING_DNS[id] = {
        clientDir: directoryUrl,
        accountKey,
        order,
        csrPem,
        privateKeyPem,
        pendingManual,
        formats,
        pfxpass
      };
      // render page showing TXT records to add
      return res.send(renderPage('请在 DNS 中添加 TXT 记录', `
        <div class="card p-3 shadow-sm">
          <h5>DNS-01 手动验证 — 请为以下域名添加 TXT 记录</h5>
          ${pendingManual.map(p => `<div class="mb-3">
            <strong>${escapeHtml(p.domain)}</strong><br/>
            <div class="mt-1"><span class="monos">${escapeHtml(p.txtName)}</span></div>
            <div class="mt-1"><code class="monos">${escapeHtml(p.txtValue)}</code></div>
            <small class="text-muted">添加后等待 DNS 生效（通常几分钟），然后点击下方“我已添加并验证”开始完成申请。</small>
          </div>`).join('')}
          <form method="post" action="/verify-dns">
            <input type="hidden" name="id" value="${id}">
            <button class="btn btn-primary">我已添加并验证</button>
            <a class="btn btn-outline-secondary" href="/">返回首页</a>
          </form>
        </div>
      `));
    }

    // Wait for any outstanding challenge completions (http-01 or auto-cloudflare dns)
    await Promise.all(challengeTasks);

    // finalize order with CSR
    const finalized = await client.finalizeOrder(order, csrPem);
    const certPem = await client.getCertificate(finalized);

    // save artifacts in STORE
    const id = uuidv4();
    const files = {};
    // PEM: certificate and key (if we generated key)
    if (formats.includes('pem')) {
      files[`${domains[0]}.crt.pem`] = Buffer.from(certPem, 'utf8');
      if (privateKeyPem) files[`${domains[0]}.key.pem`] = Buffer.from(privateKeyPem, 'utf8');
    }
    // DER
    if (formats.includes('der')) {
      files[`${domains[0]}.crt.der`] = certPem ? certPemToDerBuffer(certPem) : Buffer.from('');
      if (privateKeyPem) {
        // DER for key is non-trivial; we omit key DER (usually not needed). We keep key PEM.
      }
    }
    // PFX
    if (formats.includes('pfx')) {
      if (!privateKeyPem) {
        // if no private key (user uploaded CSR), we cannot produce PFX
        // produce a small text file to explain
        files[`${domains[0]}.pfx-not-available.txt`] = Buffer.from('无法生成 PFX：上传了 CSR，服务器没有私钥，无法生成包含私钥的 PFX。', 'utf8');
      } else {
        const pfxBuf = makePfxBuffer(privateKeyPem, certPem, pfxpass);
        files[`${domains[0]}.pfx`] = pfxBuf;
      }
    }

    STORE[id] = {
      name: domains.join(', '),
      files,
      meta: {
        type: 'letsencrypt',
        env,
        cn: domains[0],
        created: new Date().toISOString()
      }
    };

    // cleanup any tokens used (for http-01)
    for (const k in HTTP_TOKENS) delete HTTP_TOKENS[k];

    // render success page with links
    const links = Object.keys(files).map(fn => `<a class="btn btn-sm btn-outline-primary me-1" href="/download/${id}/${encodeURIComponent(fn)}" download="${fn}">${escapeHtml(fn)}</a>`).join(' ');
    res.send(renderPage('申请成功', `
      <div class="card p-3 shadow-sm">
        <h5>证书签发成功</h5>
        <p>域名：<strong>${escapeHtml(domains.join(', '))}</strong></p>
        <div>${links}</div>
        <hr/>
        <a class="btn btn-outline-secondary mt-2" href="/">返回首页</a>
      </div>
    `));
  } catch (err) {
    console.error(err);
    res.send(renderPage('错误', `<div class="alert alert-danger">申请失败：${escapeHtml(err && err.message ? err.message : String(err))}</div><a class="btn btn-outline-secondary" href="/">返回</a>`));
  }
});

// ---------- Verify DNS (manual flow) ----------
app.post('/verify-dns', requireAuth, async (req, res) => {
  const id = req.body.id;
  if (!id || !PENDING_DNS[id]) return res.send(renderPage('错误', `<div class="alert alert-danger">找不到待验证的记录或已过期</div><a href="/">返回</a>`));
  const ctx = PENDING_DNS[id];

  try {
    // restore client
    const client = new acme.Client({ directoryUrl: ctx.clientDir, accountKey: ctx.accountKey });
    // reload order and authorizations
    const order = ctx.order;
    const authorizations = await client.getAuthorizations(order);

    // For each pending manual item, find corresponding authorization and challenge and verify/complete
    for (const p of ctx.pendingManual) {
      const domain = p.domain;
      const auth = authorizations.find(a => a.identifier.value === domain);
      if (!auth) throw new Error('找不到域对应的 authorization: ' + domain);
      const ch = auth.challenges.find(c => c.type === 'dns-01');
      if (!ch) throw new Error('找不到 dns-01 challenge: ' + domain);
      // try verify and complete
      await client.verifyChallenge(auth, ch);
      await client.completeChallenge(ch);
      await client.waitForValidStatus(ch);
    }

    // finalize order
    const finalized = await client.finalizeOrder(order, ctx.csrPem);
    const certPem = await client.getCertificate(finalized);

    // store artifacts
    const id2 = uuidv4();
    const files = {};
    if (ctx.formats.includes('pem')) {
      files[`${ctx.pendingManual[0].domain}.crt.pem`] = Buffer.from(certPem, 'utf8');
      if (ctx.privateKeyPem) files[`${ctx.pendingManual[0].domain}.key.pem`] = Buffer.from(ctx.privateKeyPem, 'utf8');
    }
    if (ctx.formats.includes('der')) {
      files[`${ctx.pendingManual[0].domain}.crt.der`] = certPem ? certPemToDerBuffer(certPem) : Buffer.from('');
    }
    if (ctx.formats.includes('pfx')) {
      if (!ctx.privateKeyPem) {
        files[`${ctx.pendingManual[0].domain}.pfx-not-available.txt`] = Buffer.from('无法生成 PFX：上传了 CSR，服务器没有私钥，无法生成包含私钥的 PFX。', 'utf8');
      } else {
        const pfxBuf = makePfxBuffer(ctx.privateKeyPem, certPem, ctx.pfxpass);
        files[`${ctx.pendingManual[0].domain}.pfx`] = pfxBuf;
      }
    }

    STORE[id2] = {
      name: ctx.pendingManual.map(p => p.domain).join(', '),
      files,
      meta: {
        type: 'letsencrypt',
        env: ctx.clientDir === acme.directory.letsencrypt.production ? 'production' : 'staging',
        cn: ctx.pendingManual[0].domain,
        created: new Date().toISOString()
      }
    };

    // cleanup
    delete PENDING_DNS[id];

    const links = Object.keys(files).map(fn => `<a class="btn btn-sm btn-outline-primary me-1" href="/download/${id2}/${encodeURIComponent(fn)}" download="${fn}">${escapeHtml(fn)}</a>`).join(' ');
    res.send(renderPage('DNS 验证并颁发成功', `
      <div class="card p-3 shadow-sm">
        <h5>证书签发成功</h5>
        <div>${links}</div>
        <a class="btn btn-outline-secondary mt-2" href="/">返回首页</a>
      </div>
    `));
  } catch (err) {
    console.error(err);
    res.send(renderPage('错误', `<div class="alert alert-danger">验证或签发失败：${escapeHtml(err && err.message ? err.message : String(err))}</div><a class="btn btn-outline-secondary" href="/">返回</a>`));
  }
});

// ---------- Download ----------
app.get('/download/:id/:filename', requireAuth, (req, res) => {
  const id = req.params.id;
  const filename = decodeURIComponent(req.params.filename || '');
  const entry = STORE[id];
  if (!entry) return res.status(404).send('Not found');
  const file = entry.files[filename];
  if (!file) return res.status(404).send('Not found');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  // try to set content-type
  if (filename.endsWith('.pem') || filename.endsWith('.crt') || filename.endsWith('.key') || filename.endsWith('.txt')) {
    res.setHeader('Content-Type', 'application/x-pem-file; charset=utf-8');
  } else if (filename.endsWith('.der')) {
    res.setHeader('Content-Type', 'application/octet-stream');
  } else if (filename.endsWith('.pfx')) {
    res.setHeader('Content-Type', 'application/x-pkcs12');
  } else {
    res.setHeader('Content-Type', 'application/octet-stream');
  }
  res.send(file);
});

// ---------- Cloudflare helper (very small) ----------
async function createCloudflareTxt(domain, name, value, token) {
  // get zone id by domain: Cloudflare zones are by root domain (e.g., example.com)
  // naive approach: list zones and find the zone whose name is suffix of domain (best-effort)
  try {
    const zonesResp = await fetch('https://api.cloudflare.com/client/v4/zones', {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    });
    const zonesBody = await zonesResp.json();
    if (!zonesBody.success) return false;
    const zones = zonesBody.result || [];
    // find best match
    let zone = null;
    for (const z of zones) {
      if (domain === z.name || domain.endsWith('.' + z.name)) {
        zone = z;
        break;
      }
    }
    if (!zone) return false;
    // create TXT record
    const zoneId = zone.id;
    const resp = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'TXT',
        name: name,
        content: value,
        ttl: 120
      })
    });
    const body = await resp.json();
    return body && body.success;
  } catch (e) {
    console.error('Cloudflare API error', e);
    return false;
  }
}

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`ACME demo server listening on http://0.0.0.0:${PORT}`);
  console.log('默认登录：admin / 12345678');
  console.log('请注意：HTTP-01 需开放 80 端口，或使用 DNS-01 手动/Cloudflare。');
});
```