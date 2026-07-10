const $ = (s) => document.querySelector(s);
const RISK_COLOR = { high: '#ff3b5c', medium: '#ffb84d', low: '#39ff9d' };
let authMode = 'login';
let demoDomains = [];
let currentBriefingHTML = '';
let lastScanData = null;

function ringGauge(value, max, color, size = 52, strokeW = 3.5) {
  const r = (size - strokeW * 2) / 2;
  const c = 2 * Math.PI * r;
  const pct = max === 0 ? 0 : Math.min(1, value / max);
  const offset = c - pct * c;
  const center = size / 2;
  return `
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <circle cx="${center}" cy="${center}" r="${r}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="${strokeW}"/>
      <circle cx="${center}" cy="${center}" r="${r}" fill="none" stroke="${color}" stroke-width="${strokeW}" stroke-linecap="round"
        stroke-dasharray="${c}" stroke-dashoffset="${offset}" transform="rotate(-90 ${center} ${center})"
        style="transition: stroke-dashoffset 1s cubic-bezier(0.16,1,0.3,1); filter:drop-shadow(0 0 5px ${color})"/>
      <text x="${center}" y="${center + 4}" text-anchor="middle" font-family="Orbitron" font-weight="700" font-size="${size * 0.28}" fill="${color}">${value}</text>
    </svg>`;
}

function renderStatsRow(counts, total, score) {
  const scoreColor = score === null ? '#7f96b8' : score >= 80 ? '#39ff9d' : score >= 50 ? '#ffb84d' : '#ff3b5c';
  const maxCount = Math.max(total, 1);
  $('#statsRow').innerHTML = `
    <div class="stat-card score-card">
      ${ringGauge(score === null ? 0 : score, 100, scoreColor, 64, 4)}
      <div class="stat-label">🛡 SECURITY SCORE</div>
    </div>
    <div class="stat-card"><div class="stat-num">${total}</div><div class="stat-label">🌐 HOSTS FOUND</div></div>
    <div class="stat-card">${ringGauge(counts.high, maxCount, '#ff3b5c')}<div class="stat-label">⚠ HIGH RISK</div></div>
    <div class="stat-card">${ringGauge(counts.medium, maxCount, '#ffb84d')}<div class="stat-label">◐ MEDIUM RISK</div></div>
    <div class="stat-card">${ringGauge(counts.low, maxCount, '#39ff9d')}<div class="stat-label">✓ LOW RISK</div></div>
  `;
}

const RISK_ICON = { high: '!', medium: '~', low: '✓' };

function renderFindingsTable(nodes) {
  $('#findingsTable').innerHTML = nodes.map(n => `
    <div class="finding-row" data-host="${n.id}">
      <span class="finding-icon-dot" style="background:${n.type === 'root' ? '#39d6ff' : (RISK_COLOR[n.risk] || '#7f96b8')}">${n.type === 'root' ? '◈' : (RISK_ICON[n.risk] || '')}</span>
      <span class="finding-host">${n.label}</span>
      <span class="finding-badge risk-${n.risk || 'low'}">${(n.risk || 'low').toUpperCase()}</span>
      <span class="finding-meta">${n.tls ? n.tls.daysLeft + 'd cert' : 'no TLS'}</span>
    </div>
  `).join('');
  $('#findingsTable').querySelectorAll('.finding-row').forEach(row => {
    row.addEventListener('click', () => {
      const node = lastScanData.nodes.find(n => n.id === row.dataset.host);
      if (node) showDetail(node);
    });
  });
}

function exportReport() {
  if (!lastScanData) return;
  const blob = new Blob([JSON.stringify(lastScanData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `sentramap-${lastScanData.domain}-report.json`;
  a.click();
  URL.revokeObjectURL(url);
}

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
  $('#googleBtn').addEventListener('click', async () => {
    try { await signInGoogle(); } catch (err) { toast('Google sign-in failed: ' + err.message); }
  });
  $('#authSubmit').addEventListener('click', async () => {
    try {
      const email = $('#authEmail').value.trim();
      const password = $('#authPassword').value;
      if (!email || !password) { toast('Enter email and password.'); return; }
      const { error } = authMode === 'login' ? await signInEmail(email, password) : await signUpEmail(email, password);
      if (error) { toast(error.message); return; }
      toast(authMode === 'login' ? 'Logged in ✅' : 'Account created — check your email to verify.');
    } catch (err) {
      toast('Unexpected error: ' + err.message);
    }
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
    if (data.pro) {
      $('#usagePill').textContent = '✨ Pro — unlimited';
      $('#upgradeBtn').style.display = 'none';
      $('#exportBtn').style.display = 'inline-flex';
      return;
    }
    $('#upgradeBtn').style.display = 'inline-flex';
    $('#exportBtn').style.display = 'none';
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
let termInterval = null;

function termLog(msg) {
  const feed = $('#terminalFeed');
  const line = document.createElement('div');
  line.className = 'tline';
  line.innerHTML = `<span class="tprefix">&gt;</span> ${msg}`;
  feed.appendChild(line);
  while (feed.children.length > 8) feed.removeChild(feed.firstChild);
  feed.scrollTop = feed.scrollHeight;
}

async function runScan() {
  const domain = $('#domainSelect').value;
  if (!domain) { toast('No domain selected — add one or pick a demo domain.'); return; }
  const btn = $('#scanBtn');
  btn.disabled = true;
  btn.textContent = '⟳ Scanning...';
  const status = $('#scanStatus');
  status.textContent = `Querying certificate logs, DNS, and TLS for ${domain}...`;
  status.classList.add('show');
  currentBriefingHTML = '';
  renderStatsRow({ high: 0, medium: 0, low: 0 }, '--', null);
  $('#findingsTable').innerHTML = '<div class="finding-row-empty">Scanning...</div>';

  $('#terminalFeed').innerHTML = '';
  const bootLines = [
    `Target locked: ${domain}`,
    `Querying certificate transparency logs...`,
    `Resolving DNS records...`,
    `Establishing TLS handshake...`,
    `Inspecting HTTP response headers...`,
    `Cross-referencing risk signatures...`
  ];
  let li = 0;
  termLog(bootLines[0]);
  if (termInterval) clearInterval(termInterval);
  termInterval = setInterval(() => {
    li++;
    if (li >= bootLines.length) { clearInterval(termInterval); return; }
    termLog(bootLines[li]);
  }, 550);

  try {
    const res = await fetch(`/api/scan?domain=${encodeURIComponent(domain)}`, { headers: apiHeaders() });
    const data = await res.json();
    if (res.status === 402) { $('#paywallModal').classList.add('show'); status.classList.remove('show'); clearInterval(termInterval); return; }
    if (data.error) { status.textContent = `Error: ${data.message}`; clearInterval(termInterval); termLog(`ERROR: ${data.message}`); return; }
    status.textContent = `${data.nodes.length} hosts found · scanned ${new Date(data.scannedAt).toLocaleTimeString()}`;
    $('#breadcrumbDomain').textContent = data.domain;
    clearInterval(termInterval);
    termLog(`${data.nodes.length} host(s) mapped.`);
    lastScanData = data;
    const counts = { high: 0, medium: 0, low: 0 };
    data.nodes.forEach(n => { if (counts[n.risk] !== undefined) counts[n.risk]++; });
    renderStatsRow(counts, data.nodes.length, null);
    renderFindingsTable(data.nodes);
    renderGraph(data);
    refreshUsage();
    fetchBriefing(data);
  } catch (err) {
    status.textContent = 'Scan failed — server unreachable.';
    clearInterval(termInterval);
    termLog('ERROR: server unreachable.');
  } finally {
    btn.disabled = false;
    btn.textContent = '▶ Scan';
  }
}

async function fetchBriefing(data) {
  const panel = $('#detailPanel');
  panel.innerHTML = `<div class="briefing-panel"><div class="briefing-title">AI SECURITY BRIEFING</div><div class="ai-loading">Analyzing full scan...</div></div>`;
  try {
    const res = await fetch('/api/briefing', { method: 'POST', headers: apiHeaders(), body: JSON.stringify({ domain: data.domain, nodes: data.nodes }) });
    if (res.status === 402) return;
    const briefing = await res.json();
    if (briefing.counts && briefing.score !== undefined) renderStatsRow(briefing.counts, data.nodes.length, briefing.score);
    currentBriefingHTML = briefing.text
      ? `<div class="briefing-panel"><div class="briefing-title">AI SECURITY BRIEFING</div><div class="briefing-text">${briefing.text}</div></div>`
      : '';
    panel.innerHTML = currentBriefingHTML + '<div class="detail-empty">Click any node on the graph to inspect it.</div>';
  } catch (err) {
    panel.innerHTML = '<div class="detail-empty">Click any node on the graph to inspect it.</div>';
  }
}

let pulseAnimationId = null;

function renderGraph(data) {
  if (pulseAnimationId) cancelAnimationFrame(pulseAnimationId);
  const svg = d3.select('#graph');
  svg.selectAll('*').remove();
  const width = svg.node().clientWidth;
  const height = svg.node().clientHeight;

  const nodes = data.nodes.map(n => ({ ...n }));
  const links = data.edges.map((e, i) => ({ source: e.from, target: e.to, phase: (i * 0.37) % 1 }));

  const simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(130))
    .force('charge', d3.forceManyBody().strength(-280))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(42));

  const link = svg.append('g').selectAll('line').data(links).enter().append('line').attr('class', 'link');
  const pulses = svg.append('g').selectAll('circle').data(links).enter().append('circle')
    .attr('class', 'data-pulse').attr('r', 2.4);

  const node = svg.append('g').selectAll('g').data(nodes).enter().append('g')
    .style('opacity', 0)
    .call(d3.drag()
      .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));

  node.transition().duration(500).delay((d, i) => i * 60).style('opacity', 1);

  const colorFor = d => d.type === 'root' ? '#39d6ff' : (RISK_COLOR[d.risk] || '#7f96b8');

  // Soft ambient glow behind the root node — a premium hero halo, not a spinning ring.
  node.filter(d => d.type === 'root').append('circle')
    .attr('r', 60).attr('fill', '#39d6ff').attr('opacity', 0.14)
    .style('filter', 'blur(20px)');

  node.append('circle').attr('class', 'node-ring').attr('r', d => d.type === 'root' ? 40 : 15).attr('stroke', colorFor);
  node.each(function (d) {
    const r = d.type === 'root' ? 40 : 15;
    const g = d3.select(this);
    [0, 90, 180, 270].forEach(deg => {
      const rad = (deg * Math.PI) / 180;
      const x1 = Math.cos(rad) * (r + 3), y1 = Math.sin(rad) * (r + 3);
      const x2 = Math.cos(rad) * (r + 8), y2 = Math.sin(rad) * (r + 8);
      g.append('line').attr('class', 'reticle-tick').attr('x1', x1).attr('y1', y1).attr('x2', x2).attr('y2', y2).attr('stroke', colorFor(d));
    });
  });
  node.append('circle')
    .attr('class', 'node-circle')
    .attr('r', d => d.type === 'root' ? 22 : 8)
    .attr('fill', colorFor)
    .attr('opacity', 0.95)
    .style('filter', d => `drop-shadow(0 0 10px ${colorFor(d)})`)
    .on('click', (event, d) => showDetail(d));

  // Icon glyphs inside each node — shield for the scanned domain, warning/check for risk levels.
  node.each(function (d) {
    const g = d3.select(this);
    const radius = d.type === 'root' ? 22 : 8;
    const scale = (radius * 2 * 0.5) / 24;
    const iconG = g.append('g').attr('transform', `translate(${-12 * scale},${-12 * scale}) scale(${scale})`)
      .attr('pointer-events', 'none').attr('fill', 'none').attr('stroke', '#ffffff')
      .attr('stroke-width', 2.4).attr('stroke-linecap', 'round').attr('stroke-linejoin', 'round');

    if (d.type === 'root') {
      iconG.append('path').attr('d', 'M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z');
    } else if (d.risk === 'high') {
      iconG.append('line').attr('x1', 12).attr('y1', 7).attr('x2', 12).attr('y2', 14);
      iconG.append('circle').attr('cx', 12).attr('cy', 18).attr('r', 0.6).attr('fill', '#fff').attr('stroke', 'none');
    } else if (d.risk === 'medium') {
      iconG.append('circle').attr('cx', 12).attr('cy', 12).attr('r', 5).attr('stroke-dasharray', '3 3');
    } else {
      iconG.append('path').attr('d', 'M4 12l5 5L20 6');
    }
  });

  node.append('text').attr('class', 'node-label').attr('dy', d => (d.type === 'root' ? 40 : 15) + 16).attr('text-anchor', 'middle')
    .text(d => d.label.length > 22 ? d.label.slice(0, 20) + '…' : d.label);

  // Root node gets expanding sonar-style ping rings and orbiting satellite dots —
  // fills the empty space around a single result instead of leaving it bare.
  node.filter(d => d.type === 'root').each(function () {
    const g = d3.select(this);
    [0, 1, 2].forEach(i => {
      g.insert('circle', ':first-child')
        .attr('class', 'ping-ring')
        .attr('r', 20)
        .attr('fill', 'none')
        .attr('stroke', '#39d6ff')
        .attr('stroke-width', 1.5)
        .html(`
          <animate attributeName="r" values="20;260" dur="3.6s" begin="${i * 1.2}s" repeatCount="indefinite"/>
          <animate attributeName="opacity" values="0.55;0" dur="3.6s" begin="${i * 1.2}s" repeatCount="indefinite"/>
        `);
    });
    [{ r: 70, dur: 9 }, { r: 105, dur: 14 }, { r: 140, dur: 20 }].forEach((orbit, i) => {
      g.insert('circle', ':first-child')
        .attr('class', 'orbit-dot')
        .attr('cx', orbit.r).attr('cy', 0).attr('r', i === 1 ? 3 : 2)
        .attr('fill', '#39d6ff').attr('opacity', 0.7)
        .style('filter', 'drop-shadow(0 0 5px #39d6ff)')
        .append('animateTransform')
        .attr('attributeName', 'transform').attr('type', 'rotate')
        .attr('from', `0 0 0`).attr('to', i % 2 === 0 ? '360 0 0' : '-360 0 0')
        .attr('dur', `${orbit.dur}s`).attr('repeatCount', 'indefinite');
    });
  });

  simulation.on('tick', () => {
    link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    node.attr('transform', d => `translate(${d.x},${d.y})`);
  });

  // Continuous data-flow pulse animation — keeps moving even after the simulation settles,
  // reinforcing "live system" rather than a static diagram.
  function animatePulses() {
    const t = (Date.now() / 1300) % 1;
    pulses.attr('cx', d => d.source.x + (d.target.x - d.source.x) * ((t + d.phase) % 1))
          .attr('cy', d => d.source.y + (d.target.y - d.source.y) * ((t + d.phase) % 1))
          .attr('fill', d => RISK_COLOR[d.target.risk] || '#39d6ff')
          .style('opacity', d => 0.3 + 0.7 * Math.sin(((t + d.phase) % 1) * Math.PI));
    pulseAnimationId = requestAnimationFrame(animatePulses);
  }
  animatePulses();
}

async function showDetail(nodeData) {
  const panel = $('#detailPanel');
  panel.innerHTML = currentBriefingHTML + `
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
  renderStatsRow({ high: 0, medium: 0, low: 0 }, 0, null);
  $('#exportBtn').addEventListener('click', exportReport);
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
