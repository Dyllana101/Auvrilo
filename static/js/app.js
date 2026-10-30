let dashboardData = [
  { id: 'growth', title: 'Growth overview', category: 'Marketing', color: 'violet', initials: 'GO', updated: '2 min ago', grants: 3, people: [{ name: 'Maya Chen', email: 'maya.chen@acme.io', role: 'Editor' }, { name: 'Leo Park', email: 'leo.park@acme.io', role: 'Viewer' }, { name: 'Nina Patel', email: 'nina.patel@acme.io', role: 'Viewer' }] },
  { id: 'revenue', title: 'Revenue & forecast', category: 'Finance', color: 'mint', initials: 'RF', updated: '18 min ago', grants: 3, people: [{ name: 'Maya Chen', email: 'maya.chen@acme.io', role: 'Editor' }, { name: 'Owen Brooks', email: 'owen.brooks@acme.io', role: 'Editor' }, { name: 'Sam Rivera', email: 'sam.rivera@acme.io', role: 'Viewer' }] },
  { id: 'campaigns', title: 'Campaign performance', category: 'Marketing', color: 'peach', initials: 'CP', updated: '1 hour ago', grants: 2, people: [{ name: 'Leo Park', email: 'leo.park@acme.io', role: 'Viewer' }, { name: 'Priya Shah', email: 'priya.shah@acme.io', role: 'Viewer' }] },
  { id: 'product', title: 'Product engagement', category: 'Product', color: 'blue', initials: 'PE', updated: '3 hours ago', grants: 2, people: [{ name: 'Nina Patel', email: 'nina.patel@acme.io', role: 'Editor' }, { name: 'Maya Chen', email: 'maya.chen@acme.io', role: 'Viewer' }] },
  { id: 'weekly', title: 'Weekly business review', category: 'Executive', color: 'rose', initials: 'WB', updated: 'Yesterday', grants: 2, people: [{ name: 'Owen Brooks', email: 'owen.brooks@acme.io', role: 'Editor' }, { name: 'Sam Rivera', email: 'sam.rivera@acme.io', role: 'Viewer' }] },
  { id: 'retention', title: 'Customer retention', category: 'Customer success', color: 'yellow', initials: 'CR', updated: 'Yesterday', grants: 2, people: [{ name: 'Priya Shah', email: 'priya.shah@acme.io', role: 'Editor' }, { name: 'Leo Park', email: 'leo.park@acme.io', role: 'Viewer' }] },
  { id: 'pipeline', title: 'Sales pipeline', category: 'Sales', color: 'green', initials: 'SP', updated: '2 days ago', grants: 1, people: [{ name: 'Sam Rivera', email: 'sam.rivera@acme.io', role: 'Editor' }] },
  { id: 'support', title: 'Support health', category: 'Customer success', color: 'slate', initials: 'SH', updated: '3 days ago', grants: 1, people: [{ name: 'Nina Patel', email: 'nina.patel@acme.io', role: 'Viewer' }] }
];
const demoDashboardData = JSON.parse(JSON.stringify(dashboardData));
const personColors = ['avatar-indigo', 'avatar-coral', 'avatar-blue', 'avatar-green', 'avatar-gold', 'avatar-plum'];
let currentPage = 'dashboards';
let sortMode = 'recent';
let roleFilterMode = 'all';
let selectedPeople = new Set();
let selectedDashboardIds = new Set();
let liveWorkspaceMode = false;

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const initialsFor = name => name.split(/\s+/).map(part => part[0]).join('').slice(0, 2).toUpperCase();

function mapLiveReports(reports) {
  const colors = ['violet', 'mint', 'peach', 'blue', 'rose', 'yellow', 'green', 'slate'];
  return reports.map((report, index) => {
    const members = report.members || [];
    const people = members.filter(member => member.kind === 'user' && member.role !== 'OWNER').map(member => ({
      name: member.email,
      email: member.email,
      role: member.role === 'EDITOR' || member.role === 'LINK_EDITOR' ? 'Editor' : 'Viewer',
    }));
    return {
      id: report.id,
      title: report.title,
      category: 'Looker Studio',
      color: colors[index % colors.length],
      initials: initialsFor(report.title),
      updated: report.updated ? new Date(report.updated).toLocaleDateString() : 'Available now',
      grants: members.filter(member => member.role !== 'OWNER').length,
      people,
      members,
      owner: report.owner,
      description: report.description,
      isOwner: report.is_owner,
    };
  });
}

function openWorkspaceCache() {
  if (!('indexedDB' in window)) return Promise.resolve(null);
  return new Promise(resolve => {
    try {
      const request = indexedDB.open('auvrilo-cache', 1);
      request.onupgradeneeded = () => request.result.createObjectStore('workspaces', { keyPath: 'email' });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

async function readWorkspaceCache(email) {
  const db = await openWorkspaceCache();
  if (!db) return null;
  return new Promise(resolve => {
    const request = db.transaction('workspaces', 'readonly').objectStore('workspaces').get(email.toLowerCase());
    request.onsuccess = () => { const value = request.result || null; db.close(); resolve(value); };
    request.onerror = () => { db.close(); resolve(null); };
  });
}

async function saveWorkspaceCache(payload) {
  const email = payload.user?.email?.toLowerCase();
  if (!email) return;
  const db = await openWorkspaceCache();
  if (!db) return;
  return new Promise(resolve => {
    const transaction = db.transaction('workspaces', 'readwrite');
    transaction.objectStore('workspaces').put({ email, payload, savedAt: new Date().toISOString() });
    transaction.oncomplete = () => { db.close(); resolve(); };
    transaction.onerror = () => { db.close(); resolve(); };
  });
}

async function clearOtherWorkspaceCaches(email) {
  const db = await openWorkspaceCache();
  if (!db) return;
  return new Promise(resolve => {
    const transaction = db.transaction('workspaces', 'readwrite');
    const store = transaction.objectStore('workspaces');
    const request = store.getAllKeys();
    request.onsuccess = () => request.result.forEach(key => { if (key !== email.toLowerCase()) store.delete(key); });
    transaction.oncomplete = () => { db.close(); resolve(); };
    transaction.onerror = () => { db.close(); resolve(); };
  });
}

async function clearWorkspaceCache() {
  const db = await openWorkspaceCache();
  if (!db) return;
  return new Promise(resolve => {
    const transaction = db.transaction('workspaces', 'readwrite');
    transaction.objectStore('workspaces').clear();
    transaction.oncomplete = () => { db.close(); resolve(); };
    transaction.onerror = () => { db.close(); resolve(); };
  });
}

async function loadWorkspace(quiet = false) {
  const currentEmail = document.body.dataset.currentUser.toLowerCase();
  if (currentEmail) await clearOtherWorkspaceCaches(currentEmail);
  if (!liveWorkspaceMode && currentEmail) {
    const cached = await readWorkspaceCache(currentEmail);
    if (cached?.payload) {
      dashboardData = mapLiveReports(cached.payload.reports || []);
      liveWorkspaceMode = true;
      $('#syncText').textContent = `Cached ${new Date(cached.savedAt).toLocaleTimeString()}`;
      $('#workspaceModeLabel').textContent = 'Cached Workspace';
      $('#workspaceNotice').textContent = 'Showing the last synced Google permissions while Auvrilo refreshes.';
      renderAll();
    }
  }
  let response;
  try {
    response = await fetch('/api/workspace', { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
  } catch {
    if (!quiet) toast('Could not reach Auvrilo. Check your connection and try syncing again.');
    $('#syncText').textContent = liveWorkspaceMode ? 'Showing last sync' : 'Sample data';
    return null;
  }
  let payload = {};
  try { payload = await response.json(); } catch { payload = {}; }
  if (response.ok) {
    dashboardData = mapLiveReports(payload.reports || []);
    liveWorkspaceMode = true;
    saveWorkspaceCache(payload);
    $('#syncText').textContent = 'Live Google data';
    $('#workspaceModeLabel').textContent = 'Live Workspace';
    $('#workspaceNotice').textContent = 'Live Google access - changes apply to your reports.';
    $('.summary-note span:last-child').textContent = 'Report owners are protected. Changes are sent to Google after confirmation.';
    renderAll();
    if (payload.errors?.length && !quiet) toast(`${payload.errors.length} report permission list${payload.errors.length === 1 ? '' : 's'} could not be loaded.`);
    return payload;
  }
  if (!quiet && payload.error) toast(payload.error);
  if (response.status === 409) {
    await clearWorkspaceCache();
    if (liveWorkspaceMode) {
      dashboardData = JSON.parse(JSON.stringify(demoDashboardData));
      liveWorkspaceMode = false;
      renderAll();
    }
  }
  if (payload.setup_url) $('#connectionButton').href = payload.setup_url;
  if (payload.reconnect_url) $('#connectionButton').href = payload.reconnect_url;
  if (!liveWorkspaceMode && document.body.dataset.authenticated === 'true') {
    const state = response.status === 403 ? 'Google authorization needed' : response.status === 401 ? 'Reconnect Google' : response.status === 409 ? 'OAuth setup needed' : 'Workspace unavailable';
    $('#syncText').textContent = state;
    $('#workspaceModeLabel').textContent = state;
    $('#workspaceNotice').textContent = payload.error || 'Live report data is not available yet.';
  } else {
    $('#syncText').textContent = liveWorkspaceMode ? 'Showing last sync' : 'Sample data';
  }
  return null;
}

async function applyLiveActions(actions, reopenReportId = null) {
  let succeeded = 0;
  let unchanged = 0;
  let failed = 0;
  const perReport = new Map();
  for (const action of actions) {
    let response;
    try {
      response = await fetch('/api/access', {
        method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': $('meta[name="csrf-token"]').content,
      },
        body: JSON.stringify({
          ...action,
          report_titles: Object.fromEntries((action.report_ids || []).map(id => [id, dashboardData.find(item => item.id === id)?.title || id])),
        }),
      });
    } catch {
      toast('Could not reach Auvrilo. No result was received for this change.');
      return false;
    }
    let payload = {};
    try { payload = await response.json(); } catch { payload = {}; }
    if (!response.ok) {
      if (payload.reconnect_url || payload.setup_url) window.location.assign(payload.reconnect_url || payload.setup_url);
      toast(payload.error || 'The access change could not be completed.');
      return false;
    }
    (payload.results || []).forEach(result => {
      succeeded += result.succeeded || 0;
      unchanged += result.unchanged || 0;
      failed += result.failed || 0;
      const entry = perReport.get(result.report_id) || { title: result.title, succeeded: 0, unchanged: 0, failed: 0, issues: [] };
      entry.succeeded += result.succeeded || 0;
      entry.unchanged += result.unchanged || 0;
      entry.failed += result.failed || 0;
      if (result.message) entry.issues.push(result.message);
      (result.owner_protected || []).forEach(email => entry.issues.push(`${email} is an owner and was not changed.`));
      (result.failures || []).forEach(issue => entry.issues.push(`${issue.email}: ${issue.message}`));
      perReport.set(result.report_id, entry);
    });
  }
  await loadWorkspace(true);
  const outcome = succeeded
    ? `${succeeded} change${succeeded === 1 ? '' : 's'} applied${unchanged ? `, ${unchanged} already matched` : ''}.`
    : `${unchanged} selected permission${unchanged === 1 ? ' was' : 's were'} already as requested.`;
  if (perReport.size > 1 || failed > 0) {
    const reportRows = [...perReport.values()].map(result => `<div class="review-result-row"><span class="review-result-status ${result.failed ? 'result-warning' : 'result-success'}">${result.failed ? '!' : '✓'}</span><span><strong>${esc(result.title)}</strong><small>${result.succeeded} changed, ${result.unchanged} unchanged, ${result.failed} failed or protected${result.issues.length ? `<br>${result.issues.map(esc).join('<br>')}` : ''}</small></span></div>`).join('');
    openModal(`<div class="modal-header"><div class="review-icon">${failed ? '!' : '✓'}</div><div class="modal-heading-copy"><span class="category-label">GOOGLE API RESULTS</span><h2 id="modalTitle">Changes processed</h2><p>${succeeded} changed, ${unchanged} unchanged, and ${failed} failed or protected.</p></div><button class="modal-close" data-close aria-label="Close">×</button></div><div class="modal-body"><div class="review-results">${reportRows}</div></div><div class="modal-footer"><span class="modal-saved">Results are reported per dashboard</span><button class="button button-primary" data-close>Done</button></div>`);
    $$('[data-close]').forEach(button => button.addEventListener('click', closeModal));
  } else if (reopenReportId && liveWorkspaceMode) {
    openManageDashboard(reopenReportId);
    toast(outcome);
  } else {
    toast(outcome);
  }
  return failed === 0;
}

function getPeople() {
  const people = new Map();
  dashboardData.forEach(dashboard => dashboard.people.forEach(person => {
    const entry = people.get(person.email) || { ...person, dashboards: [], roles: [] };
    entry.dashboards.push(dashboard.title);
    entry.roles.push(person.role);
    people.set(person.email, entry);
  }));
  return [...people.values()].map(person => ({ ...person, role: person.roles.includes('Editor') ? 'Editor' : 'Viewer' }));
}

function renderStats() {
  const people = getPeople();
  $('#statDashboards').textContent = dashboardData.length;
  $('#statUsers').textContent = people.length;
  $('#statGrants').textContent = dashboardData.reduce((sum, dashboard) => sum + dashboard.grants, 0);
  $('#userTrendText').textContent = liveWorkspaceMode ? 'Live Google totals' : '↔ 2 added this month';
  $('#grantReportsFoot').textContent = `Across ${dashboardData.length} report${dashboardData.length === 1 ? '' : 's'}`;
  $('#navDashboardCount').textContent = dashboardData.length;
  $('#headingDashboardCount').textContent = String(dashboardData.length).padStart(2, '0');
  $('#navUserCount').textContent = people.length;
  $('#headingPeopleCount').textContent = people.length;
}

function renderDashboards() {
  const term = ($('#dashboardSearch')?.value || '').trim().toLowerCase();
  let rows = dashboardData.filter(item => `${item.title} ${item.category}`.toLowerCase().includes(term));
  if (sortMode === 'az') rows = [...rows].sort((a, b) => a.title.localeCompare(b.title));
  if (sortMode === 'access') rows = [...rows].sort((a, b) => b.grants - a.grants);
  $('#dashboardGrid').innerHTML = rows.map(item => `<article class="dashboard-card">
    <div class="card-top"><div class="report-mark mark-${item.color}"><span class="report-mark-inner">${item.initials}</span></div><button class="more-button" data-more="${esc(item.id)}" aria-label="More options">···</button></div>
    <div class="card-copy"><span class="category-label">${esc(item.category)}</span><h3>${esc(item.title)}</h3><div class="updated-label"><span class="tiny-clock">◷</span> Updated ${esc(item.updated)}</div></div>
    <div class="card-bottom"><div class="avatar-stack">${item.people.slice(0, 3).map(person => `<span class="avatar avatar-small ${personColor(person.email)}" title="${esc(person.name)}">${initialsFor(person.name)}</span>`).join('')}${item.grants > item.people.length ? `<span class="avatar avatar-more">+${item.grants - item.people.length}</span>` : ''}</div><span class="grant-count">${item.grants} ${liveWorkspaceMode ? 'grants' : item.grants === 1 ? 'person' : 'people'}</span><button class="manage-link" data-manage="${esc(item.id)}">${liveWorkspaceMode ? 'Manage access' : 'Manage'} <span>→</span></button></div>
  </article>`).join('');
  $('#resultCount').textContent = `${rows.length} dashboard${rows.length === 1 ? '' : 's'}`;
  $('#emptyDashboards').classList.toggle('hidden', rows.length !== 0);
  $('#dashboardGrid').classList.toggle('hidden', rows.length === 0);
  $$('[data-manage]').forEach(button => button.addEventListener('click', () => openManageDashboard(button.dataset.manage)));
  $$('[data-more]').forEach(button => button.addEventListener('click', () => openManageDashboard(button.dataset.more)));
}

function personColor(email) {
  const index = getPeople().findIndex(person => person.email === email);
  return personColors[(index + personColors.length) % personColors.length];
}

function renderUsers() {
  const term = ($('#userSearch')?.value || '').trim().toLowerCase();
  const rows = getPeople().filter(person => `${person.name} ${person.email} ${person.dashboards.join(' ')}`.toLowerCase().includes(term) && (roleFilterMode === 'all' || person.role.toLowerCase() === roleFilterMode));
  $('#peopleTableBody').innerHTML = rows.map(person => `<tr>
    <td><input type="checkbox" class="person-select" data-email="${esc(person.email)}" aria-label="Select ${esc(person.name)}" ${selectedPeople.has(person.email) ? 'checked' : ''}></td>
    <td><div class="person-cell"><span class="avatar ${personColor(person.email)}">${initialsFor(person.name)}</span><span><strong>${esc(person.name)}</strong><small>${esc(person.email)}</small></span></div></td>
    <td><span class="role-badge role-${person.role.toLowerCase()}"><span></span>${person.role}</span></td>
    <td><div class="dashboard-chips">${person.dashboards.slice(0, 2).map(name => `<span class="dashboard-chip" title="${esc(name)}">${esc(name)}</span>`).join('')}${person.dashboards.length > 2 ? `<span class="dashboard-chip chip-extra">+${person.dashboards.length - 2}</span>` : ''}</div></td>
    <td class="last-updated">${liveWorkspaceMode ? 'Current' : ['Today', 'Yesterday', '2 days ago'][person.name.length % 3]}</td>
    <td><button class="row-menu" data-user="${esc(person.email)}" aria-label="Manage ${esc(person.name)}">···</button></td>
  </tr>`).join('');
  $('#emptyPeople').classList.toggle('hidden', rows.length !== 0);
  $('.people-table-wrap').classList.toggle('hidden', rows.length === 0);
  $$('.person-select').forEach(box => box.addEventListener('change', () => togglePerson(box.dataset.email, box.checked)));
  $$('[data-user]').forEach(button => button.addEventListener('click', () => openManagePerson(button.dataset.user)));
  updateSelectionBar();
}

function togglePerson(email, selected) {
  selected ? selectedPeople.add(email) : selectedPeople.delete(email);
  updateSelectionBar();
}
function updateSelectionBar() {
  $('#selectedCount').textContent = selectedPeople.size;
  $('#peopleSelectionBar').classList.toggle('hidden', selectedPeople.size === 0);
  const checks = $$('.person-select');
  $('#selectAllPeople').checked = checks.length > 0 && checks.every(item => item.checked);
}

function setPage(page) {
  currentPage = page;
  $$('.nav-link').forEach(button => button.classList.toggle('active', button.dataset.page === page));
  $('#dashboardSection').classList.toggle('hidden', page !== 'dashboards');
  $('#usersSection').classList.toggle('hidden', page !== 'users');
  $('#bulkSection').classList.toggle('hidden', page !== 'bulk');
  const titles = { dashboards: ['Dashboards', 'A clearer view of your dashboards.', 'Everything you can manage, all in one place.'], users: ['People', 'The right people, in the right places.', 'See every person and the access they have.'], bulk: ['Bulk changes', 'Make access changes, simply.', 'One clear action across all the dashboards you choose.'] };
  $('#breadcrumbCurrent').textContent = titles[page][0];
  $('#pageTitle').textContent = titles[page][1];
  $('#pageSubtitle').textContent = titles[page][2];
  $('#openBulkButton').classList.toggle('hidden', page === 'bulk');
  if (page === 'users') renderUsers();
  if (page === 'bulk') renderBulkDashboards();
  $('#sidebar').classList.remove('sidebar-open');
}

function openModal(content) {
  $('#modalContent').innerHTML = content;
  $('#modalBackdrop').classList.remove('hidden');
  document.body.classList.add('modal-open');
  $('#modalContent').querySelector('[autofocus]')?.focus();
}
function closeModal() {
  $('#modalBackdrop').classList.add('hidden');
  document.body.classList.remove('modal-open');
}
function openLiveManageDashboard(dashboard) {
  const rows = dashboard.members.map(member => {
    const directUser = member.kind === 'user' && ['EDITOR', 'VIEWER'].includes(member.role);
    const label = member.email || member.member;
    const roleLabel = member.role.replaceAll('_', ' ').toLowerCase().replace(/\b\w/g, letter => letter.toUpperCase());
    return `<div class="modal-person"><span class="avatar ${member.kind === 'user' ? personColor(member.email) : 'avatar-plum'}">${initialsFor(label)}</span><span class="modal-person-copy"><strong>${esc(label)}</strong><small>${member.kind === 'user' ? 'Google account' : esc(member.kind)}</small></span>${directUser ? `<select class="role-select live-role-select" data-email="${esc(member.email)}" data-original-role="${member.role}"><option value="EDITOR" ${member.role === 'EDITOR' ? 'selected' : ''}>Editor</option><option value="VIEWER" ${member.role === 'VIEWER' ? 'selected' : ''}>Viewer</option></select><button class="remove-person" data-live-remove="${esc(member.email)}" aria-label="Remove ${esc(member.email)}">×</button>` : `<span class="owner-label">${esc(roleLabel)}</span><span class="owner-lock">${member.role === 'OWNER' ? '⌑' : ''}</span>`}</div>`;
  }).join('');
  openModal(`<div class="modal-header"><div class="report-mark mark-${dashboard.color}"><span class="report-mark-inner">${dashboard.initials}</span></div><div class="modal-heading-copy"><span class="category-label">${esc(dashboard.category)}</span><h2 id="modalTitle">${esc(dashboard.title)}</h2><p>${dashboard.grants} existing access grants</p></div><button class="modal-close" data-close aria-label="Close">×</button></div><div class="modal-body"><div class="modal-section-title"><strong>Current access</strong><span>OWNERS ARE PROTECTED</span></div><div class="modal-people">${rows || '<p class="all-dashboards-note">No explicit members found.</p>'}</div><div class="add-people-block"><strong>Add people</strong><p>Enter Workspace user email addresses separated by commas or new lines.</p><textarea id="inviteEmails" placeholder="colleague@company.com, team@company.com"></textarea><div class="add-role-row"><label for="newRole">Access level</label><select id="newRole" class="role-select"><option value="VIEWER">Viewer</option><option value="EDITOR">Editor</option></select></div></div></div><div class="modal-footer"><span class="modal-saved">Changes apply to Google immediately</span><button class="button button-secondary" data-close>Cancel</button><button class="button button-primary" id="saveLiveDashboard">Apply changes</button></div>`);
  $$('[data-close]').forEach(button => button.addEventListener('click', closeModal));
  $$('[data-live-remove]').forEach(button => button.addEventListener('click', async () => {
    if (!window.confirm(`Remove ${button.dataset.liveRemove} from this report?`)) return;
    closeModal();
    await applyLiveActions([{ action: 'remove', emails: [button.dataset.liveRemove], report_ids: [dashboard.id] }], dashboard.id);
  }));
  $('#saveLiveDashboard').addEventListener('click', async () => {
    const actions = [];
    const changesByRole = { EDITOR: [], VIEWER: [] };
    $$('.live-role-select').forEach(select => {
      if (select.value !== select.dataset.originalRole) changesByRole[select.value].push(select.dataset.email);
    });
    Object.entries(changesByRole).forEach(([role, emails]) => {
      if (emails.length) actions.push({ action: 'set_role', role, emails, report_ids: [dashboard.id] });
    });
    const existing = new Set(dashboard.members.filter(member => member.kind === 'user').map(member => member.email.toLowerCase()));
    const emails = $('#inviteEmails').value.split(/[\n,;]+/).map(value => value.trim().toLowerCase()).filter(value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && !existing.has(value));
    if (emails.length) actions.push({ action: 'grant', role: $('#newRole').value, emails, report_ids: [dashboard.id] });
    if (!actions.length) { closeModal(); return; }
    closeModal();
    await applyLiveActions(actions, dashboard.id);
  });
}

function openManageDashboard(id) {
  const dashboard = dashboardData.find(item => item.id === id);
  if (!dashboard) return;
  if (liveWorkspaceMode) { openLiveManageDashboard(dashboard); return; }
  openModal(`<div class="modal-header"><div class="report-mark mark-${dashboard.color}"><span class="report-mark-inner">${dashboard.initials}</span></div><div class="modal-heading-copy"><span class="category-label">${esc(dashboard.category)}</span><h2 id="modalTitle">${esc(dashboard.title)}</h2><p>${dashboard.grants} people have access</p></div><button class="modal-close" data-close aria-label="Close">×</button></div>
    <div class="modal-body"><div class="modal-section-title"><strong>People with access</strong><span>OWNER IS PROTECTED</span></div><div class="modal-people">${dashboard.people.map(person => `<div class="modal-person"><span class="avatar ${personColor(person.email)}">${initialsFor(person.name)}</span><span class="modal-person-copy"><strong>${esc(person.name)}</strong><small>${esc(person.email)}</small></span><select class="role-select" data-email="${esc(person.email)}"><option ${person.role === 'Editor' ? 'selected' : ''}>Editor</option><option ${person.role === 'Viewer' ? 'selected' : ''}>Viewer</option></select><button class="remove-person" data-remove="${esc(person.email)}" aria-label="Remove ${esc(person.name)}">×</button></div>`).join('')}
      <div class="modal-person owner-person"><span class="avatar avatar-indigo">DU</span><span class="modal-person-copy"><strong>Demo User <span class="you-label">YOU</span></strong><small>owner@example.com</small></span><span class="owner-label">Owner</span><span class="owner-lock">⌑</span></div></div>
      <div class="add-people-block"><strong>Add people</strong><p>Enter email addresses separated by commas or new lines.</p><textarea id="inviteEmails" placeholder="colleague@company.com, team@company.com" autofocus></textarea><div class="add-role-row"><label for="newRole">Access level</label><select id="newRole" class="role-select"><option>Viewer</option><option>Editor</option></select></div></div></div>
    <div class="modal-footer"><span class="modal-saved"><span class="status-dot"></span>Changes save in demo mode</span><button class="button button-secondary" data-close>Done</button><button class="button button-primary" id="saveDashboardChanges" data-dashboard="${dashboard.id}">Save changes</button></div>`);
  $$('[data-close]').forEach(button => button.addEventListener('click', closeModal));
  $$('[data-remove]').forEach(button => button.addEventListener('click', () => {
    dashboard.people = dashboard.people.filter(person => person.email !== button.dataset.remove);
    dashboard.grants = Math.max(dashboard.people.length, dashboard.grants - 1);
    openManageDashboard(id);
    toast('Access removed from this dashboard.');
  }));
  $('#saveDashboardChanges').addEventListener('click', () => {
    const emails = $('#inviteEmails').value.split(/[\n,;]+/).map(value => value.trim().toLowerCase()).filter(value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value));
    const role = $('#newRole').value;
    const existing = new Set(dashboard.people.map(person => person.email));
    emails.forEach(email => { if (!existing.has(email)) dashboard.people.push({ name: email.split('@')[0].replace(/[._-]/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase()), email, role }); });
    dashboard.grants += emails.filter(email => !existing.has(email)).length;
    dashboard.people.forEach(person => {
      const control = $(`.role-select[data-email="${CSS.escape(person.email)}"]`);
      if (control) person.role = control.value;
    });
    closeModal(); renderAll(); toast('Dashboard access updated.');
  });
}
function openLiveManagePerson(email) {
  const person = getPeople().find(item => item.email === email);
  if (!person) return;
  const reportsWithAccess = dashboardData.filter(dashboard => dashboard.members.some(member => member.kind === 'user' && member.email.toLowerCase() === email.toLowerCase() && member.role !== 'OWNER'));
  const accessRows = reportsWithAccess.map(dashboard => {
    const member = dashboard.members.find(item => item.kind === 'user' && item.email.toLowerCase() === email.toLowerCase());
    const editable = ['EDITOR', 'VIEWER'].includes(member.role);
    return `<div class="modal-person"><span class="report-mark report-mark-mini mark-${dashboard.color}"><span class="report-mark-inner">${dashboard.initials}</span></span><span class="modal-person-copy"><strong>${esc(dashboard.title)}</strong><small>${esc(dashboard.category)}</small></span>${editable ? `<select class="role-select live-person-role" data-dashboard="${esc(dashboard.id)}" data-original-role="${member.role}"><option value="EDITOR" ${member.role === 'EDITOR' ? 'selected' : ''}>Editor</option><option value="VIEWER" ${member.role === 'VIEWER' ? 'selected' : ''}>Viewer</option></select><button class="remove-person" data-live-user-remove="${esc(dashboard.id)}" aria-label="Remove access from ${esc(dashboard.title)}">×</button>` : `<span class="owner-label">${esc(member.role)}</span>`}</div>`;
  }).join('');
  const availableReports = dashboardData.filter(dashboard => !dashboard.members.some(member => member.kind === 'user' && member.email.toLowerCase() === email.toLowerCase()));
  openModal(`<div class="modal-header"><span class="avatar avatar-large ${personColor(email)}">${initialsFor(person.name)}</span><div class="modal-heading-copy"><span class="category-label">ACCESS PROFILE</span><h2 id="modalTitle">${esc(person.name)}</h2><p>${esc(person.email)}</p></div><button class="modal-close" data-close aria-label="Close">×</button></div><div class="modal-body"><div class="modal-section-title"><strong>Dashboard access</strong><span>${reportsWithAccess.length} REPORTS</span></div><div class="modal-people">${accessRows || '<p class="all-dashboards-note">No editable report access found.</p>'}</div><div class="add-people-block"><strong>Grant access to more reports</strong><p>Select reports to share with this person.</p>${availableReports.map(dashboard => `<label class="dashboard-check"><input type="checkbox" value="${esc(dashboard.id)}"><span>${esc(dashboard.title)}</span><small>${esc(dashboard.category)}</small></label>`).join('') || '<p class="all-dashboards-note">This person already has access to all manageable reports.</p>'}<div class="add-role-row"><label for="personNewRole">Access level</label><select id="personNewRole" class="role-select"><option value="VIEWER">Viewer</option><option value="EDITOR">Editor</option></select></div></div></div><div class="modal-footer"><button class="button button-quiet danger-text" id="revokeLivePerson">Revoke all access</button><span class="modal-footer-spacer"></span><button class="button button-secondary" data-close>Cancel</button><button class="button button-primary" id="saveLivePerson">Apply changes</button></div>`);
  $$('[data-close]').forEach(button => button.addEventListener('click', closeModal));
  $$('[data-live-user-remove]').forEach(button => button.addEventListener('click', async () => {
    closeModal();
    await applyLiveActions([{ action: 'remove', emails: [email], report_ids: [button.dataset.liveUserRemove] }]);
  }));
  $('#revokeLivePerson').addEventListener('click', async () => {
    if (!window.confirm(`Revoke ${email}'s access from all manageable reports?`)) return;
    closeModal();
    await applyLiveActions([{ action: 'remove', emails: [email], report_ids: reportsWithAccess.map(dashboard => dashboard.id) }]);
  });
  $('#saveLivePerson').addEventListener('click', async () => {
    const actions = [];
    const changesByRole = { EDITOR: [], VIEWER: [] };
    $$('.live-person-role').forEach(select => {
      if (select.value !== select.dataset.originalRole) changesByRole[select.value].push(select.dataset.dashboard);
    });
    Object.entries(changesByRole).forEach(([role, reportIds]) => {
      if (reportIds.length) actions.push({ action: 'set_role', role, emails: [email], report_ids: reportIds });
    });
    const reportIds = $$('input[type="checkbox"]:checked', $('#modalContent')).map(box => box.value);
    if (reportIds.length) actions.push({ action: 'grant', role: $('#personNewRole').value, emails: [email], report_ids: reportIds });
    if (!actions.length) { closeModal(); return; }
    closeModal();
    await applyLiveActions(actions);
  });
}

function openManagePerson(email) {
  const person = getPeople().find(item => item.email === email);
  if (!person) return;
  if (liveWorkspaceMode) { openLiveManagePerson(email); return; }
  openModal(`<div class="modal-header"><span class="avatar avatar-large ${personColor(email)}">${initialsFor(person.name)}</span><div class="modal-heading-copy"><span class="category-label">ACCESS PROFILE</span><h2 id="modalTitle">${esc(person.name)}</h2><p>${esc(person.email)}</p></div><button class="modal-close" data-close aria-label="Close">×</button></div><div class="modal-body"><div class="modal-section-title"><strong>Dashboard access</strong><span>${person.dashboards.length} DASHBOARDS</span></div><div class="modal-people">${dashboardData.filter(d => d.people.some(p => p.email === email)).map(d => { const access = d.people.find(p => p.email === email); return `<div class="modal-person"><span class="report-mark report-mark-mini mark-${d.color}"><span class="report-mark-inner">${d.initials}</span></span><span class="modal-person-copy"><strong>${esc(d.title)}</strong><small>${esc(d.category)}</small></span><select class="role-select person-role-select" data-dashboard="${d.id}"><option ${access.role === 'Editor' ? 'selected' : ''}>Editor</option><option ${access.role === 'Viewer' ? 'selected' : ''}>Viewer</option></select><button class="remove-person" data-user-remove="${d.id}" aria-label="Remove access from ${esc(d.title)}">×</button></div>`; }).join('')}</div><div class="add-people-block"><strong>Grant access to more dashboards</strong><p>Choose the dashboards this person can access.</p>${dashboardData.filter(d => !d.people.some(p => p.email === email)).map(d => `<label class="dashboard-check"><input type="checkbox" value="${d.id}"><span>${esc(d.title)}</span><small>${esc(d.category)}</small></label>`).join('') || '<p class="all-dashboards-note">This person already has access to all your dashboards.</p>'}<div class="add-role-row"><label for="personNewRole">Access level</label><select id="personNewRole" class="role-select"><option>Viewer</option><option>Editor</option></select></div></div></div><div class="modal-footer"><button class="button button-quiet danger-text" id="revokePerson">Revoke all access</button><span class="modal-footer-spacer"></span><button class="button button-secondary" data-close>Cancel</button><button class="button button-primary" id="savePersonChanges">Save changes</button></div>`);
  $$('[data-close]').forEach(button => button.addEventListener('click', closeModal));
  $$('[data-user-remove]').forEach(button => button.addEventListener('click', () => { const dashboard = dashboardData.find(item => item.id === button.dataset.userRemove); dashboard.people = dashboard.people.filter(item => item.email !== email); dashboard.grants = Math.max(dashboard.people.length, dashboard.grants - 1); renderAll(); if (getPeople().some(item => item.email === email)) openManagePerson(email); else closeModal(); }));
  $('#revokePerson').addEventListener('click', () => { dashboardData.forEach(d => { d.people = d.people.filter(item => item.email !== email); d.grants = Math.max(d.people.length, d.grants - 1); }); closeModal(); renderAll(); toast('Access removed from all dashboards.'); });
  $('#savePersonChanges').addEventListener('click', () => {
    $$('.person-role-select').forEach(select => { const dashboard = dashboardData.find(item => item.id === select.dataset.dashboard); const access = dashboard.people.find(item => item.email === email); if (access) access.role = select.value; });
    const role = $('#personNewRole').value;
    $$('input[type="checkbox"]', $('#modalContent')).filter(box => box.checked).forEach(box => { const dashboard = dashboardData.find(item => item.id === box.value); dashboard.people.push({ ...person, role }); dashboard.grants++; });
    closeModal(); renderAll(); toast('Person access updated.');
  });
}
function openInviteModal() {
  openModal(`<div class="modal-header"><div class="invite-icon"><svg viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M20 8v6m3-3h-6"/></svg></div><div class="modal-heading-copy"><span class="category-label">SHARE A REPORT</span><h2 id="modalTitle">Invite people</h2><p>Give someone access to a dashboard you manage.</p></div><button class="modal-close" data-close aria-label="Close">×</button></div><div class="modal-body"><div class="add-people-block"><label for="inviteDashboard"><strong>Dashboard</strong></label><select class="input-select" id="inviteDashboard">${dashboardData.map(d => `<option value="${esc(d.id)}">${esc(d.title)}</option>`).join('')}</select><label for="inviteEmails"><strong>Email addresses</strong></label><p>Separate multiple addresses with a comma or new line.</p><textarea id="inviteEmails" placeholder="colleague@company.com" autofocus></textarea><div class="add-role-row"><label for="inviteRole">Access level</label><select id="inviteRole" class="role-select"><option>Viewer</option><option>Editor</option></select></div></div></div><div class="modal-footer"><span class="modal-saved">${liveWorkspaceMode ? 'Access is applied directly in Google' : 'Demo mode - no email is sent'}</span><button class="button button-secondary" data-close>Cancel</button><button class="button button-primary" id="sendInvite">Grant access</button></div>`);
  $$('[data-close]').forEach(button => button.addEventListener('click', closeModal));
  $('#sendInvite').addEventListener('click', async () => {
    const dashboard = dashboardData.find(item => item.id === $('#inviteDashboard').value);
    const emails = $('#inviteEmails').value.split(/[\n,;]+/).map(value => value.trim().toLowerCase()).filter(value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value));
    if (!dashboard || !emails.length) { toast('Choose a report and enter at least one valid email.'); return; }
    if (liveWorkspaceMode) {
      closeModal();
      await applyLiveActions([{ action: 'grant', role: $('#inviteRole').value.toUpperCase(), emails, report_ids: [dashboard.id] }]);
      return;
    }
    const role = $('#inviteRole').value;
    const existing = new Set(dashboard.people.map(person => person.email));
    emails.forEach(email => { if (!existing.has(email)) dashboard.people.push({ name: email.split('@')[0].replace(/[._-]/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase()), email, role }); });
    dashboard.grants += emails.filter(email => !existing.has(email)).length;
    closeModal(); renderAll(); toast(`${emails.length} invite${emails.length === 1 ? '' : 's'} added in demo mode.`);
  });
}
function renderBulkDashboards() {
  $('#bulkDashboardList').innerHTML = dashboardData.map(d => `<label class="bulk-dashboard-row"><input type="checkbox" value="${esc(d.id)}" ${selectedDashboardIds.has(d.id) ? 'checked' : ''}><span class="mini-report mark-${d.color}">${d.initials}</span><span>${esc(d.title)}</span><small>${d.category}</small></label>`).join('');
  $$('.bulk-dashboard-row input').forEach(box => box.addEventListener('change', () => { box.checked ? selectedDashboardIds.add(box.value) : selectedDashboardIds.delete(box.value); updateBulkSummary(); }));
  updateBulkSummary();
}
function updateBulkSummary() {
  const typed = ($('#bulkEmails')?.value || '').split(/[\n,;]+/).map(item => item.trim()).filter(item => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(item));
  const count = new Set([...typed, ...selectedPeople]).size;
  $('#mathPeople').textContent = `${count} ${count === 1 ? 'person' : 'people'}`;
  $('#mathDashboards').textContent = `${selectedDashboardIds.size} ${selectedDashboardIds.size === 1 ? 'dashboard' : 'dashboards'}`;
  const total = count * selectedDashboardIds.size;
  $('#changeTotal').textContent = total;
  $('#reviewBulkButton').disabled = count === 0 || selectedDashboardIds.size === 0 || (liveWorkspaceMode && total > 500);
  if (liveWorkspaceMode && total > 500) $('.summary-note span:last-child').textContent = 'Live bulk changes are limited to 500 user-report pairs per request.';
  else if (liveWorkspaceMode) $('.summary-note span:last-child').textContent = 'Report owners are protected. Changes are sent to Google after confirmation.';
  $('#selectedPeopleChips').innerHTML = [...selectedPeople].map(email => `<button class="selected-chip" data-unselect="${esc(email)}">${esc(email)} <span>×</span></button>`).join('');
  $$('[data-unselect]').forEach(button => button.addEventListener('click', () => { selectedPeople.delete(button.dataset.unselect); updateBulkSummary(); }));
}
async function runBulkChange() {
  const emails = new Set([...selectedPeople, ...($('#bulkEmails').value || '').split(/[\n,;]+/).map(item => item.trim().toLowerCase()).filter(item => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(item))]);
  const action = $('input[name="bulkAction"]:checked').value;
  if (liveWorkspaceMode) {
    const selectedIds = [...selectedDashboardIds];
    const actionType = action === 'remove' ? 'remove' : 'grant';
    selectedPeople.clear(); selectedDashboardIds.clear(); $('#bulkEmails').value = ''; updateBulkSummary();
    await applyLiveActions([{ action: actionType, role: action === 'editor' ? 'EDITOR' : 'VIEWER', emails: [...emails], report_ids: selectedIds }]);
    setPage('dashboards');
    return;
  }
  let changes = 0;
  dashboardData.filter(d => selectedDashboardIds.has(d.id)).forEach(d => emails.forEach(email => {
    if (action === 'remove') { const before = d.people.length; d.people = d.people.filter(person => person.email !== email); if (before !== d.people.length) { d.grants = Math.max(d.people.length, d.grants - 1); changes++; } }
    else { const person = d.people.find(item => item.email === email); if (person) { person.role = action === 'editor' ? 'Editor' : 'Viewer'; } else { d.people.push({ name: email.split('@')[0], email, role: action === 'editor' ? 'Editor' : 'Viewer' }); d.grants++; } changes++; }
  }));
  selectedPeople.clear(); selectedDashboardIds.clear(); $('#bulkEmails').value = ''; renderAll(); setPage('dashboards'); toast(`${changes} access change${changes === 1 ? '' : 's'} applied in demo mode.`);
}
function toast(message) {
  const item = document.createElement('div'); item.className = 'toast'; item.innerHTML = `<span class="toast-check">✓</span>${esc(message)}`; $('#toastRegion').append(item); setTimeout(() => { item.classList.add('toast-out'); setTimeout(() => item.remove(), 250); }, 3000);
}
function renderAll() { renderStats(); renderDashboards(); if (currentPage === 'users') renderUsers(); }

$$('.nav-link').forEach(button => button.addEventListener('click', () => setPage(button.dataset.page)));
$('#openBulkButton').addEventListener('click', () => setPage('bulk'));
$('#dashboardSearch').addEventListener('input', renderDashboards);
$('#userSearch').addEventListener('input', renderUsers);
$('#roleFilter').addEventListener('click', () => { roleFilterMode = roleFilterMode === 'all' ? 'editor' : roleFilterMode === 'editor' ? 'viewer' : 'all'; const label = roleFilterMode === 'all' ? 'All roles' : roleFilterMode === 'editor' ? 'Editors only' : 'Viewers only'; $('#roleFilter').innerHTML = `<svg viewBox="0 0 24 24"><path d="M4 7h16M7 12h10m-7 5h4"/></svg>${label}<span class="small-chevron">⌄</span>`; renderUsers(); });
$('#sortButton').addEventListener('click', () => $('#sortMenu').classList.toggle('hidden')); 
$$('#sortMenu button').forEach(button => button.addEventListener('click', () => { sortMode = button.dataset.sort; $('#sortButton').innerHTML = `<svg viewBox="0 0 24 24"><path d="M4 7h16M7 12h10m-7 5h4"/></svg>${button.textContent}<span class="small-chevron">⌄</span>`; $('#sortMenu').classList.add('hidden'); renderDashboards(); }));
$('#syncButton').addEventListener('click', async () => {
  const button = $('#syncButton');
  button.classList.add('spinning');
  $('#syncText').textContent = 'Syncing…';
  if (liveWorkspaceMode || document.body.dataset.authenticated === 'true') {
    await loadWorkspace();
    button.classList.remove('spinning');
    return;
  }
  setTimeout(() => { button.classList.remove('spinning'); $('#syncText').textContent = 'Sample data'; toast('Demo data is local; connect a Workspace account for live reports.'); }, 500);
});
$('#inviteButton').addEventListener('click', openInviteModal);
$('#inviteUsersButton').addEventListener('click', openInviteModal);
$('#selectAllPeople').addEventListener('change', event => { $$('.person-select').forEach(box => { box.checked = event.target.checked; togglePerson(box.dataset.email, box.checked); }); });
$('#clearSelection').addEventListener('click', () => { selectedPeople.clear(); renderUsers(); });
$('#revokeSelectedButton').addEventListener('click', async () => {
  if (!selectedPeople.size) return;
  const emails = [...selectedPeople];
  if (liveWorkspaceMode) {
    const ids = dashboardData.filter(dashboard => dashboard.people.some(person => selectedPeople.has(person.email))).map(dashboard => dashboard.id);
    selectedPeople.clear();
    await applyLiveActions([{ action: 'remove', emails, report_ids: ids }]);
    return;
  }
  dashboardData.forEach(dashboard => { const before = dashboard.people.length; dashboard.people = dashboard.people.filter(person => !selectedPeople.has(person.email)); dashboard.grants = Math.max(dashboard.people.length, dashboard.grants - (before - dashboard.people.length)); });
  const count = selectedPeople.size; selectedPeople.clear(); renderAll(); toast(`Access revoked for ${count} people in demo mode.`);
});
$('#bulkEmails').addEventListener('input', updateBulkSummary);
$('#bulkDashboardList').addEventListener('change', updateBulkSummary);
$('#addExistingButton').addEventListener('click', () => openModal(`<div class="modal-header"><div class="invite-icon"><svg viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M20 8v6m3-3h-6"/></svg></div><div class="modal-heading-copy"><span class="category-label">WORKSPACE DIRECTORY</span><h2 id="modalTitle">Choose people</h2><p>Add existing people to your bulk change.</p></div><button class="modal-close" data-close aria-label="Close">×</button></div><div class="modal-body"><div class="modal-people">${getPeople().map(person => `<label class="existing-person"><input type="checkbox" value="${esc(person.email)}" ${selectedPeople.has(person.email) ? 'checked' : ''}><span class="avatar ${personColor(person.email)}">${initialsFor(person.name)}</span><span class="modal-person-copy"><strong>${esc(person.name)}</strong><small>${esc(person.email)}</small></span><span class="role-badge role-${person.role.toLowerCase()}"><span></span>${person.role}</span></label>`).join('')}</div></div><div class="modal-footer"><span class="modal-saved">Selection is ready for your bulk change</span><button class="button button-primary" id="confirmExistingPeople">Add selected</button></div>`));
$('#modalContent').addEventListener('click', event => { if (event.target.matches('[data-close]')) closeModal(); });
$('#modalBackdrop').addEventListener('click', event => { if (event.target === $('#modalBackdrop')) closeModal(); });
$('#toggleDashboards').addEventListener('click', () => { const allSelected = selectedDashboardIds.size === dashboardData.length; selectedDashboardIds = allSelected ? new Set() : new Set(dashboardData.map(d => d.id)); $('#toggleDashboards').textContent = allSelected ? 'Select all dashboards' : 'Clear selection'; renderBulkDashboards(); });
$('#reviewBulkButton').addEventListener('click', () => { const action = $('input[name="bulkAction"]:checked').value; const emails = new Set([...selectedPeople, ...($('#bulkEmails').value || '').split(/[\n,;]+/).map(item => item.trim()).filter(item => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(item))]); const actionText = { viewer: 'Grant viewer access', editor: 'Grant editor access', remove: 'Remove all access' }[action]; openModal(`<div class="modal-header"><div class="review-icon">✓</div><div class="modal-heading-copy"><span class="category-label">FINAL REVIEW</span><h2 id="modalTitle">Ready to make this change?</h2><p>Here’s a quick check before you continue.</p></div><button class="modal-close" data-close aria-label="Close">×</button></div><div class="modal-body"><div class="review-summary"><div><span>PEOPLE</span><strong>${emails.size} selected</strong></div><div><span>DASHBOARDS</span><strong>${selectedDashboardIds.size} selected</strong></div><div><span>ACTION</span><strong>${actionText}</strong></div></div><div class="summary-note"><span>ⓘ</span><span>${liveWorkspaceMode ? 'This applies to the selected Google reports. Owners stay protected.' : 'This demo updates only the sample data in your browser. Owners stay protected.'}</span></div></div><div class="modal-footer"><button class="button button-secondary" data-close>Go back</button><button class="button button-primary" id="confirmBulkChange">Apply changes <span>→</span></button></div>`); $('#confirmBulkChange').addEventListener('click', () => { closeModal(); runBulkChange(); }); $$('[data-close]').forEach(button => button.addEventListener('click', closeModal)); });
$('#modalContent').addEventListener('click', event => { if (event.target.id === 'confirmExistingPeople') { $$('input[type="checkbox"]:checked', $('#modalContent')).forEach(box => selectedPeople.add(box.value)); closeModal(); updateBulkSummary(); } });
$('#helpButton').addEventListener('click', () => toast(liveWorkspaceMode ? 'Check the Google API authorization and account permissions for this client.' : 'Connect Google to load live reports.'));
$('#profileButton').addEventListener('click', () => { if (document.body.dataset.authenticated === 'true') window.location.assign('/auth/credentials'); else toast('Sign in with Google to open account settings.'); });
$('#mobileMenu').addEventListener('click', () => $('#sidebar').classList.toggle('sidebar-open'));
document.addEventListener('keydown', event => { if (event.key === 'Escape') { closeModal(); $('#sortMenu').classList.add('hidden'); } if (event.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) { event.preventDefault(); (currentPage === 'users' ? $('#userSearch') : $('#dashboardSearch')).focus(); } });
renderAll();
if (document.body.dataset.authenticated === 'true') loadWorkspace(true);
else clearWorkspaceCache();
