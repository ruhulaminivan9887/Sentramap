const $ = (s) => document.querySelector(s);
const RISK_COLOR = { high: '#ff3b5c', medium: '#ffb84d', low: '#39ff9d' };
let authMode = 'login';
let demoDomains = [];

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2600);
}

function apiHeaders() {
  const h = { 'Content-Type': 'application/json' };
  const token = getAccessToken();
  if (token) h['Authorization'] = `Bearer ${token}`;
  return h;
}

// ============== Auth UI ==============
function openAuthModal(mode) {
  authMode = mode;
  $('#authTitle').textContent = mode === 'login' ? 'Log in' : 'Create your account';
  $('#authSubmit').textContent = mode === 'login' ? 'Log in' : 'Sign up';
  $('#authToggleText').textContent = mode === 'login' ? 'No account?' : 'Already have an account?';
  $('#authToggleLink').textContent = mode === 'login' ? 'Sign up' : 'Log in';
  $('#authModal').classList.add('show');
}

function renderAuthArea() {
  const user = getCurrentUser();
  const area = $('#authArea');
  if (user) {
    area.innerHTML = `<span class="usage-pill">${escapeHtml(user.email.split('@')[0])}</span> <button class="btn btn-ghost btn-sm" id="logoutBtn">Log out</button>`;
    $('#logoutBtn').addEventListener('click', async () => { await signOut(); toast('Logged out.'); });
  } else {
    area.innerHTML = `<button class="btn btn-ghost btn-sm" id="loginBtn">Log in</button>`;
    $('#loginBtn').addEventListener('click', () => openAuthModal('login'));
  }
}

async function onAuthChange(user) {
  renderAuthArea();
  refreshUsage();
  populateDomainSelect();
  if (user) $('#authModal').classList.remove('show');
}

function escapeHtml(s) { return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function bindAuthEvents() {
  $('#closeAuthModal').addEventListener('click', () => $('#authModal').classList.remove('show'));
  $('#authToggleLink').addEventListener('click', (e) => { e.preventDefault(); openAuthModal(authMode === 'login' ? 'signup' : 'login'); });
  $('#googleBtn').addEventListener('click', async () => { await signInGoogle(); });
  $('#authSubmit').addEventListener('click', async () => {
    const email = $('#authEmail').value.trim();
    const password = $('#authPassword').value;
    if (!email || !password) { toast('Enter email and password.'); return; }
    const { error } = authMode === 'login' ? await signInEmail(email, password) : await signUpEmail(email, password);
    if (error) { toast(error.message); return; }
    toast(authMode === 'login' ? 'Logged in ✅' : 'Account created — check your email to verify.');
  });

  $('#myDomainsBtn').addEventListener('click', openDomainsModal);
  $('#closeDomainsModal').addEventListener('click', () => $('#domainsModal').classList.remove('show'));
  $('#addDomainBtn').addEventListener('click', addDomain);

  $('#upgradeBtn').addEventListener('click', () => $('#paywallModal').classList.add('show'));
  $('#closePaywall').addEventListener('click', () => $('#paywallModal').classList.remove('show'));
  $('#checkoutBtn').addEventListener('click', startCheckout);

  $('#scanBtn').addEventListener('click', runScan);
}

// ============== Domains ==============
async function populateDomainSelect() {
  const user = getCurrentUser();
  let myDomains = [];
  if (user) {
    try {
      const res = await fetch('/api/domains', { headers: apiHeaders() });
      if (res.ok) myDomains = (await res.json()).map(d => d.domain);
    } catch (err) { /* ignore */ }
  }
  const options = [
    ...demoDomains.map(d => `<option value="${d}">${d} (demo)</option>`),
    ...myDomains.map(d => `<option value="${d}">${d} (yours)</option>`)
  ];
  $('#domainSelect').innerHTML = options.join('');
}

async function openDomainsModal() {
  if (!getCurrentUser()) { openAuthModal('login'); toast('Log in to add your own domains.'); return; }
  $('#domainsModal').classList.add('show');
  await refreshMyDomainsList();
}

async function refreshMyDomainsList() {
  try {
    const res = await fetch('/api/domains', { headers: apiHeaders() });
    const domains = await res.json();
    $('#myDomainsList').innerHTML = domains.length
      ? domains.map(d => `<div style="padding:8px 0; border-bottom:1px solid var(--border); font-family:var(--font-mono); font-size:12.5px;">${escapeHtml(d.domain)}</div>`).join('')
      : '<div style="color:var(--text-faint); text-align:center; padding:16px 0;">No domains added yet.</div>';
  } catch (err) { /* ignore */ }
}

async function addDomain() {
  const domain = $('#newDomainInput').value.trim();
  const consent = $('#consentCheck').checked;
  if (!domain) { toast('Enter a domain.'); return; }
  if (!consent) { toast('Please confirm you own this domain or have permission.'); return; }
  try {
    const res = await fetch('/api/domains', { method: 'POST', headers: apiHeaders(), body: JSON.stringify({ domain, consent }) });
    const data = await res.json();
    if (!res.ok) { toast(data.message || 'Could not add domain.'); return; }
    toast('Domain added ✅');
    $('#newDomainInput').value = '';
    $('#consentCheck').checked = false;
    await refreshMyDomainsList();
    await populateDomainSelect();
  } catch (err) { toast('Failed to add domain.'); }
}

// ============== Usage / Pro ==============
async function refreshUsage() {
  try {
    const res = await fetch('/api/usage', { headers: apiHeaders() });
    const data = await res.json();
    if (data.pro) { $('#usagePill').textContent = '✨ Pro — unlimited'; $('#upgradeBtn').style.display = 'none'; return; }
    $('#upgradeBtn').style.display = 'inline-flex';
    const left = Math.max(0, data.limit - data.used);
    $('#usagePill').textContent = `${left}/${data.limit} free scans left today`;
  } catch (err) { /* ignore */ }
}

async function startCheckout() {
  if (!getCurrentUser()) { openAuthModal('login'); toast('Log in first to upgrade.'); return; }
  try {
    const res = await fetch('/api/create-checkout-session', { method: 'POST', headers: apiHeaders() });
    const data = await res.json();
    if (data.url) window.location.href = data.url;
    else toast('Stripe not configured yet.');
  } catch (err) { toast('Checkout failed to start.'); }
}

// ============== Scan + Graph ==============
async function runScan() {
  const domain = $('#domainSelect').value;
  if (!domain) { toast('No domain selected — add one or pick a demo domain.'); return; }
  const btn = $('#scanBtn');
  btn.disabled = true;
  btn.textContent = '⟳ Scanning...';
  const status = $('#scanStatus');
  status.textContent = `Querying certificate logs, DNS, and TLS for ${domain}...`;
  status.classList.add('show');

  try {
    const res = await fetch(`/api/scan?domain=${encodeURIComponent(domain)}`, { headers: apiHeaders() });
    const data = await res.json();
    if (res.status === 402) { $('#paywallModal').classList.add('show'); status.classList.remove('show'); return; }
    if (data.error) { status.textContent = `Error: ${data.message}`; return; }
    status.textContent = `${data.nodes.length} hosts found · scanned ${new Date(data.scannedAt).toLocaleTimeString()}`;
    renderGraph(data);
    refreshUsage();
  } catch (err) {
    status.textContent = 'Scan failed — server unreachable.';
  } finally {
    btn.disabled = false;
    btn.textContent = '▶ Scan';
  }
}

function renderGraph(data) {
  const svg = d3.select('#graph');
  svg.selectAll('*').remove();
  const width = svg.node().clientWidth;
  const height = svg.node().clientHeight;

  const nodes = data.nodes.map(n => ({ ...n }));
  const links = data.edges.map(e => ({ source: e.from, target: e.to }));

  const simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(130))
    .force('charge', d3.forceManyBody().strength(-280))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(42));

  const link = svg.append('g').selectAll('line').data(links).enter().append('line').attr('class', 'link');

  const node = svg.append('g').selectAll('g').data(nodes).enter().append('g')
    .style('opacity', 0)
    .call(d3.drag()
      .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));

  node.transition().duration(500).delay((d, i) => i * 60).style('opacity', 1);

  const colorFor = d => d.type === 'root' ? '#39d6ff' : (RISK_COLOR[d.risk] || '#7f96b8');

  node.append('circle').attr('class', 'node-ring').attr('r', d => d.type === 'root' ? 24 : 14).attr('stroke', colorFor);
  node.append('circle')
    .attr('class', 'node-circle')
    .attr('r', d => d.type === 'root' ? 24 : 14)
    .attr('fill', colorFor)
    .attr('opacity', 0.9)
    .style('filter', d => `drop-shadow(0 0 8px ${colorFor(d)})`)
    .on('click', (event, d) => showDetail(d));

  node.append('text').attr('class', 'node-label').attr('dy', d => (d.type === 'root' ? 24 : 14) + 14).attr('text-anchor', 'middle')
    .text(d => d.label.length > 22 ? d.label.slice(0, 20) + '…' : d.label);

  simulation.on('tick', () => {
    link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    node.attr('transform', d => `translate(${d.x},${d.y})`);
  });
}

async function showDetail(nodeData) {
  const panel = $('#detailPanel');
  panel.innerHTML = `
    <div class="detail-section"><div class="detail-host">${nodeData.label}</div><div class="detail-risk risk-${nodeData.risk || 'low'}">${(nodeData.risk || 'low')} risk</div></div>
    <div class="detail-section"><div class="detail-label">IP Addresses</div><div class="detail-value">${(nodeData.addresses || []).join(', ') || 'Not resolved'}</div></div>
    <div class="detail-section"><div class="detail-label">HTTP</div><div class="detail-value">${nodeData.http ? `Status ${nodeData.http.status} · Server: ${nodeData.http.server}${nodeData.http.poweredBy ? ' · Powered-by: ' + nodeData.http.poweredBy : ''}` : 'No response'}</div></div>
    <div class="detail-section"><div class="detail-label">TLS Certificate</div><div class="detail-value">${nodeData.tls ? `Issued by ${nodeData.tls.issuer} · Expires in ${nodeData.tls.daysLeft} days` : 'No certificate found'}</div></div>
    <div class="detail-section"><div class="detail-label">AI Risk Analysis</div><div id="aiPanel" class="ai-loading">Analyzing...</div></div>
  `;
  try {
    const res = await fetch('/api/explain', { method: 'POST', headers: apiHeaders(), body: JSON.stringify({ node: nodeData }) });
    if (res.status === 402) { $('#paywallModal').classList.add('show'); $('#aiPanel').textContent = 'Upgrade to Pro for AI analysis.'; return; }
    const data = await res.json();
    document.getElementById('aiPanel').outerHTML = data.text
      ? `<div id="aiPanel" class="ai-narration">${data.text}</div>`
      : `<div id="aiPanel" class="ai-loading">AI analysis unavailable.</div>`;
  } catch (err) { const el = document.getElementById('aiPanel'); if (el) el.textContent = 'AI analysis failed.'; }
}

// ============== Init ==============
async function init() {
  bindAuthEvents();
  try {
    const res = await fetch('/api/config');
    const cfg = await res.json();
    demoDomains = cfg.demoDomains || [];
    if (cfg.supabaseUrl && cfg.supabaseAnonKey) {
      await initAuth(cfg.supabaseUrl, cfg.supabaseAnonKey);
    } else {
      renderAuthArea();
    }
  } catch (err) { renderAuthArea(); }
  populateDomainSelect();
  refreshUsage();
}

init();
