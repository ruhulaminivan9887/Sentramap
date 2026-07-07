require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const dns = require('dns').promises;
const tls = require('tls');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());

const PORT = process.env.PORT || 3001;

// -------------------- Supabase --------------------
const supabaseAdmin = (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)
  : null;

app.get('/api/config', (req, res) => {
  res.json({
    supabaseUrl: process.env.SUPABASE_URL || null,
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY || null,
    demoDomains: DEMO_DOMAINS
  });
});

async function requireAuth(req, res, next) {
  if (!supabaseAdmin) return res.status(501).json({ error: 'auth_not_configured' });
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'not_authenticated' });
  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data.user) return res.status(401).json({ error: 'invalid_session' });
  req.user = data.user;
  next();
}

async function optionalAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (token && supabaseAdmin) {
    const { data } = await supabaseAdmin.auth.getUser(token);
    if (data?.user) req.user = data.user;
  }
  next();
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// -------------------- Domains --------------------
// Demo domains anyone can try, no login required. Public data, minimal HTTP footprint —
// same legal basis as Shodan/SecurityTrails. See README for the ethics boundary.
const DEMO_DOMAINS = (process.env.DEMO_DOMAINS || 'stripe.com,pentscribe.onrender.com,fireaudit-server.onrender.com')
  .split(',').map(d => d.trim()).filter(Boolean);

async function isDomainAuthorized(domain, user) {
  if (DEMO_DOMAINS.includes(domain)) return true;
  if (!user || !supabaseAdmin) return false;
  const { data } = await supabaseAdmin
    .from('user_domains')
    .select('domain')
    .eq('user_id', user.id)
    .eq('domain', domain)
    .maybeSingle();
  return !!data;
}

app.get('/api/domains', requireAuth, async (req, res) => {
  if (!supabaseAdmin) return res.status(501).json({ error: 'db_not_configured' });
  const { data, error } = await supabaseAdmin.from('user_domains').select('domain, added_at').eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/domains', requireAuth, async (req, res) => {
  if (!supabaseAdmin) return res.status(501).json({ error: 'db_not_configured' });
  const { domain, consent } = req.body;
  if (!domain || !consent) {
    return res.status(400).json({ error: 'consent_required', message: 'You must confirm you own this domain or have written permission to scan it.' });
  }
  const clean = domain.toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const { error } = await supabaseAdmin.from('user_domains').insert({ user_id: req.user.id, domain: clean, added_at: new Date().toISOString() });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true, domain: clean });
});

// -------------------- Freemium usage limiter --------------------
const usage = new Map();
const FREE_DAILY_LIMIT = 3;

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
}

async function isPro(userId) {
  if (!supabaseAdmin || !userId) return false;
  const { data } = await supabaseAdmin.from('subscriptions').select('status').eq('user_id', userId).eq('status', 'active').maybeSingle();
  return !!data;
}

async function checkLimit(req, res, next) {
  if (req.user && await isPro(req.user.id)) return next();
  const key = req.user ? `user:${req.user.id}` : `ip:${getClientIp(req)}`;
  const today = new Date().toISOString().slice(0, 10);
  const entry = usage.get(key);
  if (!entry || entry.date !== today) { usage.set(key, { date: today, count: 1 }); return next(); }
  if (entry.count >= FREE_DAILY_LIMIT) {
    return res.status(402).json({ error: 'limit_reached', message: 'Free daily scan limit reached. Upgrade to Pro for unlimited scans and custom domains.' });
  }
  entry.count += 1;
  next();
}

app.get('/api/usage', optionalAuth, async (req, res) => {
  if (req.user && await isPro(req.user.id)) return res.json({ pro: true });
  const key = req.user ? `user:${req.user.id}` : `ip:${getClientIp(req)}`;
  const today = new Date().toISOString().slice(0, 10);
  const entry = usage.get(key);
  const used = entry && entry.date === today ? entry.count : 0;
  res.json({ used, limit: FREE_DAILY_LIMIT, pro: false });
});

app.get('/api/me', requireAuth, async (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, pro: await isPro(req.user.id) });
});

// -------------------- Recon functions --------------------
async function findSubdomains(domain) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  try {
    const res = await fetch(url, { headers: { 'User-Agent': 'SentraMap/1.0' } });
    if (!res.ok) return [];
    const data = await res.json();
    const names = new Set();
    data.forEach(entry => {
      (entry.name_value || '').split('\n').forEach(n => {
        const clean = n.trim().toLowerCase().replace(/^\*\./, '');
        if (clean.endsWith(domain) && !clean.includes(' ')) names.add(clean);
      });
    });
    return Array.from(names).slice(0, 25);
  } catch (err) { return []; }
}

async function resolveHost(host) {
  try { return await dns.resolve4(host); } catch (err) { return []; }
}

async function inspectHttp(host) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(`https://${host}`, { method: 'GET', redirect: 'manual', signal: controller.signal });
    clearTimeout(timeout);
    return { status: res.status, server: res.headers.get('server') || 'unknown', poweredBy: res.headers.get('x-powered-by') || null, hsts: !!res.headers.get('strict-transport-security') };
  } catch (err) { return null; }
}

function inspectTls(host) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect({ host, port: 443, servername: host, timeout: 4000, rejectUnauthorized: false }, () => {
      if (settled) return;
      settled = true;
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.valid_to) return resolve(null);
      const validTo = new Date(cert.valid_to);
      const daysLeft = Math.round((validTo - Date.now()) / (1000 * 60 * 60 * 24));
      resolve({ issuer: cert.issuer?.O || 'unknown', validTo: cert.valid_to, daysLeft });
    });
    socket.on('error', () => { if (!settled) { settled = true; resolve(null); } });
    socket.on('timeout', () => { if (!settled) { settled = true; socket.destroy(); resolve(null); } });
  });
}

function computeRisk(http, tlsInfo) {
  const flags = [];
  if (tlsInfo && tlsInfo.daysLeft !== undefined && tlsInfo.daysLeft < 14) flags.push('cert_expiring_soon');
  if (!tlsInfo) flags.push('no_https');
  if (http?.poweredBy) flags.push('server_tech_exposed');
  if (http && !http.hsts) flags.push('missing_hsts');
  if (!flags.length) return 'low';
  if (flags.includes('cert_expiring_soon') || flags.includes('no_https')) return 'high';
  return 'medium';
}

// -------------------- Scan endpoint --------------------
app.get('/api/scan', optionalAuth, checkLimit, async (req, res) => {
  try {
    const domain = (req.query.domain || '').toLowerCase().trim();
    if (!await isDomainAuthorized(domain, req.user)) {
      return res.status(403).json({ error: 'domain_not_authorized', message: 'This domain is not authorized. Log in and add a domain you own or have permission to scan.' });
    }

    const subdomains = await findSubdomains(domain);
    const hostsToInspect = [domain, ...subdomains.filter(s => s !== domain)].slice(0, 15);
    const nodes = [];
    const edges = [];
    nodes.push({ id: domain, type: 'root', label: domain });

    for (const host of hostsToInspect) {
      const [addresses, http, tlsInfo] = await Promise.all([
        resolveHost(host).catch(() => []),
        inspectHttp(host).catch(() => null),
        inspectTls(host).catch(() => null)
      ]);
      if (host !== domain) {
        nodes.push({ id: host, type: 'subdomain', label: host, addresses, http, tls: tlsInfo, risk: computeRisk(http, tlsInfo) });
        edges.push({ from: domain, to: host });
      } else {
        nodes[0].addresses = addresses;
        nodes[0].http = http;
        nodes[0].tls = tlsInfo;
        nodes[0].risk = computeRisk(http, tlsInfo);
      }
    }
    res.json({ domain, scannedAt: new Date().toISOString(), nodes, edges });
  } catch (err) {
    console.error('Scan error:', err);
    res.status(500).json({ error: 'scan_failed', message: err.message });
  }
});

// -------------------- AI risk narration --------------------
app.post('/api/explain', optionalAuth, checkLimit, async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY) return res.status(501).json({ error: 'ai_not_configured' });
  const { node } = req.body;
  const prompt = `You are a cybersecurity analyst explaining an attack-surface finding to a non-technical business owner.
Host: ${node.label}
HTTP info: ${JSON.stringify(node.http)}
TLS certificate info: ${JSON.stringify(node.tls)}
Risk level already computed: ${node.risk}

In 3-4 plain-English sentences: explain what this finding means, why it matters, and one concrete recommended fix. No jargon without explaining it. Do not invent details not present above.`;
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 300, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    const text = (data.content || []).map(b => b.text || '').join('\n').trim();
    res.json({ text });
  } catch (err) {
    res.status(500).json({ error: 'server_error', message: err.message });
  }
});

// -------------------- AI Security Briefing (whole-scan executive summary) --------------------
app.post('/api/briefing', optionalAuth, checkLimit, async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY) return res.status(501).json({ error: 'ai_not_configured' });
  const { domain, nodes } = req.body;
  const counts = { high: 0, medium: 0, low: 0 };
  (nodes || []).forEach(n => { if (counts[n.risk] !== undefined) counts[n.risk]++; });
  const highRiskHosts = (nodes || []).filter(n => n.risk === 'high').map(n => n.label);

  const prompt = `You are a cybersecurity analyst briefing a business owner (non-technical) on the results of an external attack surface scan.
Domain scanned: ${domain}
Total hosts found: ${(nodes || []).length}
Risk breakdown: ${counts.high} high risk, ${counts.medium} medium risk, ${counts.low} low risk
Specific high-risk hosts: ${highRiskHosts.join(', ') || 'none'}

Write a 3-4 sentence executive briefing: overall posture in plain language, the single most urgent issue to fix first (name it specifically if there is a high-risk host), and one clear next action. Professional, direct, no jargon without explaining it, no invented details beyond what's given above.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 350, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    const text = (data.content || []).map(b => b.text || '').join('\n').trim();
    res.json({ text, score: computeOverallScore(counts), counts });
  } catch (err) {
    res.status(500).json({ error: 'server_error', message: err.message });
  }
});

function computeOverallScore(counts) {
  // 100 = pristine, drops with each risk found, weighted by severity.
  const penalty = (counts.high * 18) + (counts.medium * 8) + (counts.low * 2);
  return Math.max(5, 100 - penalty);
}

// -------------------- Stripe --------------------
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  if (!stripe) return res.status(501).json({ error: 'stripe_not_configured' });
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      client_reference_id: req.user.id,
      customer_email: req.user.email,
      success_url: `${req.headers.origin}/?upgraded=true`,
      cancel_url: `${req.headers.origin}/?upgraded=false`,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.status(501).end();
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (!supabaseAdmin) return res.json({ received: true });

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    if (session.client_reference_id) {
      await supabaseAdmin.from('subscriptions').upsert({
        user_id: session.client_reference_id, status: 'active', stripe_customer_id: session.customer, updated_at: new Date().toISOString()
      }, { onConflict: 'user_id' });
    }
  }
  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    await supabaseAdmin.from('subscriptions').update({ status: 'inactive', updated_at: new Date().toISOString() }).eq('stripe_customer_id', sub.customer);
  }
  if (event.type === 'customer.subscription.updated') {
    const sub = event.data.object;
    const isActive = sub.status === 'active' || sub.status === 'trialing';
    await supabaseAdmin.from('subscriptions').update({ status: isActive ? 'active' : 'inactive', updated_at: new Date().toISOString() }).eq('stripe_customer_id', sub.customer);
  }
  res.json({ received: true });
});

app.listen(PORT, () => console.log(`SentraMap server running on port ${PORT}`));

process.on('unhandledRejection', (err) => console.error('Unhandled rejection (kept server alive):', err));
process.on('uncaughtException', (err) => console.error('Uncaught exception (kept server alive):', err));
