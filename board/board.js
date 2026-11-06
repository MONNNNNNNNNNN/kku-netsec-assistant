/*
 * NetSec Board UI. Vanilla JS, no build step, no external requests (CSP connect-src 'self').
 * Log fields are attacker-controlled: every value is placed with textContent / text nodes.
 * This file never uses innerHTML, outerHTML, insertAdjacentHTML or document.write
 * (test/board.static.test.js enforces it).
 */
'use strict';
(function () {
  // ---------------------------------------------------------------- i18n
  const T = {
    th: {
      login: 'เข้าสู่ระบบ', username: 'ชื่อผู้ใช้', password: 'รหัสผ่าน', signin: 'เข้าสู่ระบบ', logout: 'ออกจากระบบ',
      search: 'ค้นหา (/)', collapseAll: 'ย่อทั้งหมด', expandAll: 'ขยายทั้งหมด', theme: 'ธีม', notifications: 'การแจ้งเตือน',
      otherOpen: 'อื่น ๆ ที่เปิดอยู่', critHigh: 'วิกฤต + สูง ที่ยังเปิดอยู่', bySeverity: 'ตามระดับความรุนแรง', last24: 'รายการใหม่ 24 ชม.',
      pinned: 'ปักหมุด', live: 'สด', viewOpen: 'เปิดอยู่', viewAcked: 'รับทราบแล้ว', viewAll: 'ทั้งหมด', empty: 'ไม่มีรายการ',
      pin: 'ปักหมุด', unpin: 'เลิกปักหมุด', ack: 'รับทราบ', unack: 'ยกเลิกรับทราบ', snooze: 'เลื่อน', unsnooze: 'ยกเลิกเลื่อน',
      expand: 'ขยาย', collapse: 'ย่อ', explain: 'ให้ AI อธิบาย', copy: 'คัดลอก', copied: 'คัดลอกแล้ว', openSource: 'เปิดที่ต้นทาง',
      notTriaged: 'AI ยังไม่ได้ตรวจ', queued: 'อยู่ในคิว AI', running: 'AI กำลังตรวจ', skipped: 'ข้าม (คิวเต็ม)', llmError: 'AI ผิดพลาด',
      injection: 'พยายามหลอก AI', untrusted: 'ข้อมูลที่ผู้โจมตีควบคุมได้', trusted: 'ข้อมูลจากอุปกรณ์',
      verdict: 'ผล AI (ผ่าน guard แล้ว)', guard: 'guard แก้ไข', pinnedBy: 'ปักหมุดโดย', ackedBy: 'รับทราบโดย', snoozedUntil: 'เลื่อนถึง', resolved: 'แก้ไขแล้ว',
      pullNow: 'ดึงตอนนี้', next: 'ครั้งถัดไป', lastOk: 'สำเร็จล่าสุด', received: 'รับแล้ว', dropped: 'ทิ้ง (ผู้ส่งไม่อยู่ใน allowlist/เกินอัตรา)', unsupported: 'รูปแบบไม่รองรับ',
      llmTitle: 'คิว AI', llmOff: 'ปิดอยู่ (บอร์ดใช้งานได้เต็มที่โดยไม่ต้องมี AI)', budget: 'งบต่อชั่วโมง', inQueue: 'ในคิว',
      config: 'การตั้งค่าไฟร์วอลล์', complete: 'วิเคราะห์ครบ', incomplete: 'วิเคราะห์ไม่ครบ', noConfig: 'ยังไม่มีไฟล์สำรองการตั้งค่า',
      markRead: 'อ่านทั้งหมด', desktop: 'เปิดการแจ้งเตือนบนเดสก์ท็อป', desktopOn: 'เปิดการแจ้งเตือนเดสก์ท็อปแล้ว', newFrom: (n, s) => `ใหม่ ${n} รายการจาก ${s}`,
      close: 'ปิด', sources: 'แหล่งข้อมูล', severity: 'ความรุนแรง', ago: (s) => `${s} ที่แล้ว`, inT: (s) => `อีก ${s}`, never: 'ยังไม่เคย',
      queuedAt: (n) => `เข้าคิว AI แล้ว (ลำดับที่ ${n})`, firstSeen: 'พบครั้งแรก', lastSeen: 'ล่าสุด',
      sev: { critical: 'วิกฤต', high: 'สูง', medium: 'กลาง', low: 'ต่ำ', info: 'ข้อมูล' },
      st: { ok: 'ปกติ', listening: 'รอรับ', running: 'กำลังดึง', degraded: 'มีปัญหา', down: 'ล่ม', off: 'ปิด', idle: 'รอ' },
    },
    en: {
      login: 'Sign in', username: 'Username', password: 'Password', signin: 'Sign in', logout: 'Sign out',
      search: 'Search (/)', collapseAll: 'Collapse all', expandAll: 'Expand all', theme: 'Theme', notifications: 'Notifications',
      otherOpen: 'other open', critHigh: 'Open critical + high', bySeverity: 'By severity', last24: 'New items, 24 h',
      pinned: 'Pinned', live: 'Live', viewOpen: 'Open', viewAcked: 'Acknowledged', viewAll: 'All', empty: 'Nothing here',
      pin: 'Pin', unpin: 'Unpin', ack: 'Acknowledge', unack: 'Un-acknowledge', snooze: 'Snooze', unsnooze: 'Unsnooze',
      expand: 'Expand', collapse: 'Collapse', explain: 'Explain (AI)', copy: 'Copy', copied: 'Copied', openSource: 'Open in source',
      notTriaged: 'not triaged', queued: 'queued for AI', running: 'AI running', skipped: 'skipped (queue full)', llmError: 'AI error',
      injection: 'tried to manipulate AI', untrusted: 'attacker-controllable', trusted: 'device fields',
      verdict: 'AI verdict (checked by the guard)', guard: 'guard changed', pinnedBy: 'pinned by', ackedBy: 'acked by', snoozedUntil: 'snoozed until', resolved: 'resolved',
      pullNow: 'Pull now', next: 'next', lastOk: 'last ok', received: 'received', dropped: 'dropped (not on allowlist / over rate)', unsupported: 'unsupported format',
      llmTitle: 'AI queue', llmOff: 'off (the board works fully without AI)', budget: 'budget per hour', inQueue: 'queued',
      config: 'Firewall config', complete: 'complete', incomplete: 'INCOMPLETE', noConfig: 'No configuration backup yet',
      markRead: 'Mark all read', desktop: 'Enable desktop notifications', desktopOn: 'Desktop notifications on', newFrom: (n, s) => `${n} new from ${s}`,
      close: 'Close', sources: 'Sources', severity: 'Severity', ago: (s) => `${s} ago`, inT: (s) => `in ${s}`, never: 'never',
      queuedAt: (n) => `Queued for AI (position ${n})`, firstSeen: 'first seen', lastSeen: 'last seen',
      sev: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' },
      st: { ok: 'ok', listening: 'listening', running: 'pulling', degraded: 'degraded', down: 'down', off: 'off', idle: 'idle' },
    },
  };
  const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const SRC_COLOR = { fortigate: '#f2415a', wazuh: '#5b9bff', zabbix: '#ff7a4d', syslog: '#2ed68a', configdrop: '#6c5ce7', generic: '#8c90a3' };
  const SRC_ABBR = { fortigate: 'FG', wazuh: 'WZ', zabbix: 'ZB', syslog: 'SL', configdrop: 'CF', generic: 'GN' };

  // ---------------------------------------------------------------- storage (per viewer, best effort)
  const store = {
    get(k, d) { try { const v = localStorage.getItem(`nsb-${k}`); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem(`nsb-${k}`, JSON.stringify(v)); } catch { /* private mode */ } },
  };

  const S = {
    me: null, csrf: null, items: new Map(), summary: null,
    lang: store.get('lang', null), theme: store.get('theme', 'auto'),
    q: '', fSources: new Set(store.get('fsrc', [])), fSevs: new Set(store.get('fsev', [])), view: store.get('view', 'open'),
    expanded: new Set(store.get('expanded', [])), notes: [], unread: 0, drawer: false, openGroups: new Set(), focusId: null,
  };
  const t = (k, ...a) => { const v = (T[S.lang] || T.th)[k]; return typeof v === 'function' ? v(...a) : v; };

  // ---------------------------------------------------------------- DOM helper (text only)
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'style') for (const [p, val] of Object.entries(v)) el.style.setProperty(p, val);
      else el.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return el;
  }
  const SVGNS = 'http://www.w3.org/2000/svg';
  function s(tag, attrs, ...kids) {
    const el = document.createElementNS(SVGNS, tag);
    // CSS variables are not valid in SVG presentation attributes: set those through CSSOM
    for (const [k, v] of Object.entries(attrs || {})) { if (/var\(|color-mix\(/.test(String(v))) el.style.setProperty(k, String(v)); else el.setAttribute(k, String(v)); }
    for (const c of kids) el.append(c);
    return el;
  }
  // small stroke icons (no emoji: many servers and kiosks have no emoji font)
  const ICON = {
    bell: 'M18 16v-5a6 6 0 1 0-12 0v5l-2 2h16zM10 20a2 2 0 0 0 4 0',
    pin: 'M9 3h6l-1 6 4 4H6l4-4zM12 13v8',
    moon: 'M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z',
  };
  const icon = (name) => s('svg', { viewBox: '0 0 24 24', width: 15, height: 15, fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', class: 'ic' }, s('path', { d: ICON[name] }));
  const app = document.getElementById('app');
  const toasts = document.getElementById('toasts');

  // ---------------------------------------------------------------- API
  async function api(method, path, body) {
    const res = await fetch(path, {
      method, credentials: 'same-origin',
      headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(method !== 'GET' && S.csrf ? { 'x-csrf-token': S.csrf } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch { /* empty */ }
    if (res.status === 401 && path !== '/api/login') { S.me = null; renderLogin(); throw new Error('login required'); }
    if (!res.ok) throw Object.assign(new Error((data && data.error) || `HTTP ${res.status}`), { status: res.status });
    return data;
  }

  // ---------------------------------------------------------------- time
  function dur(ms) {
    const s = Math.round(Math.abs(ms) / 1000);
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.round(s / 60)}m`;
    if (s < 86400) return `${Math.round(s / 3600)}h`;
    return `${Math.round(s / 86400)}d`;
  }
  const ago = (ts) => (ts ? t('ago', dur(Date.now() - ts)) : t('never'));
  const clock = (ts) => new Date(ts).toLocaleString(S.lang === 'th' ? 'th-TH' : 'en-GB', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: 'short' });

  // ---------------------------------------------------------------- theme
  function applyTheme() {
    if (S.theme === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', S.theme);
    document.documentElement.lang = S.lang || 'th';
  }

  // ---------------------------------------------------------------- login
  function renderLogin(msg) {
    applyTheme();
    app.replaceChildren();
    const err = h('p', { class: 'err', role: 'alert' }, msg || '');
    const u = h('input', { name: 'username', autocomplete: 'username', required: true, id: 'u' });
    const p = h('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true, id: 'p' });
    const form = h('form', {
      onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        try {
          const r = await api('POST', '/api/login', { username: u.value, password: p.value });
          S.csrf = r.csrf; S.me = r.user;
          start();
        } catch (ex) { err.textContent = ex.message; }
      },
    }, h('div', { class: 'lhero', 'aria-hidden': 'true' }), h('h1', { style: { margin: '0', 'font-size': '22px' } }, 'NetSec Board'),
    h('label', { for: 'u' }, t('username'), u), h('label', { for: 'p' }, t('password'), p), err, h('button', { class: 'btn primary', type: 'submit' }, t('signin')));
    app.append(h('div', { class: 'login' }, form));
    u.focus();
  }

  // ---------------------------------------------------------------- filters
  function visible(it) {
    const now = Date.now();
    const done = !!(it.ackedBy || it.resolvedAt || (it.snoozedUntil && it.snoozedUntil > now));
    if (S.view === 'open' && done) return false;
    if (S.view === 'acked' && !done) return false;
    if (S.fSources.size && !S.fSources.has(it.source)) return false;
    if (S.fSevs.size && !S.fSevs.has(it.severity)) return false;
    if (S.q) {
      const hay = `${it.title} ${it.source} ${it.kind} ${Object.values(it.trusted).join(' ')} ${Object.values(it.untrusted).join(' ')}`.toLowerCase();
      if (!S.q.toLowerCase().split(/\s+/).every((w) => hay.includes(w))) return false;
    }
    return true;
  }
  const order = (a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.lastSeen - a.lastSeen;

  // ---------------------------------------------------------------- shell
  let els = {};
  function renderShell() {
    applyTheme();
    const bellDot = h('span', { class: 'dot', hidden: true });
    const bell = h('button', { class: 'btn bell', 'aria-label': t('notifications'), onclick: () => toggleDrawer() }, icon('bell'), bellDot);
    const search = h('input', { type: 'search', placeholder: t('search'), 'aria-label': t('search'), value: S.q, oninput: (e) => { S.q = e.target.value; renderBoard(); } });
    const top = h('header', { class: 'top' },
      h('div', { class: 'brand' }, h('img', { src: '/icon.svg', alt: '' }), h('span', null, 'NetSec Board')),
      h('label', { class: 'search' }, '⌕', search),
      h('div', { class: 'tools' },
        h('button', { class: 'btn', onclick: () => setAll(false) }, t('collapseAll')),
        h('button', { class: 'btn', onclick: () => setAll(true) }, t('expandAll')),
        h('button', { class: 'btn', 'aria-label': 'TH/EN', onclick: () => { S.lang = S.lang === 'th' ? 'en' : 'th'; store.set('lang', S.lang); renderShell(); } }, S.lang === 'th' ? 'EN' : 'TH'),
        h('button', { class: 'btn', 'aria-label': t('theme'), onclick: cycleTheme }, S.theme === 'dark' ? '☾' : S.theme === 'light' ? '☀' : '◐'),
        bell,
        h('button', { class: 'btn ghost', onclick: logout }, `${S.me.username} · ${t('logout')}`)),
      els.chips = h('div', { class: 'chips', role: 'group', 'aria-label': `${t('sources')} / ${t('severity')}` }));
    els.hero = h('section', { class: 'bento', 'aria-label': 'summary' });
    els.pinned = h('div', { class: 'masonry' });
    els.live = h('div', { class: 'masonry' });
    els.pinCount = h('span', { class: 'n' }, '0');
    els.liveCount = h('span', { class: 'n' }, '0');
    const tabs = h('span', { class: 'viewtabs' }, ['open', 'acked', 'all'].map((v) => h('button', { class: 'chip-f', 'aria-pressed': String(S.view === v), onclick: () => { S.view = v; store.set('view', v); renderShell(); } }, t(`view${v[0].toUpperCase()}${v.slice(1)}`))));
    els.drawer = h('aside', { class: 'drawer', hidden: !S.drawer, 'aria-label': t('notifications') });
    els.bellDot = bellDot; els.search = search;
    app.replaceChildren(top, h('main', null,
      els.hero,
      h('h2', { class: 'sec' }, icon('pin'), t('pinned'), ' ', els.pinCount), els.pinned,
      h('h2', { class: 'sec' }, t('live'), ' ', els.liveCount, tabs), els.live), els.drawer);
    renderChips(); renderHero(); renderBoard(); renderDrawer(); renderBell();
  }

  function renderChips() {
    const srcs = [...new Set([...S.items.values()].map((i) => i.source).concat((S.summary ? S.summary.sources : []).filter((x) => x.enabled && !x.name.startsWith('hook:')).map((x) => x.name)))];
    const toggle = (set, key, v) => { set.has(v) ? set.delete(v) : set.add(v); store.set(key, [...set]); renderChips(); renderBoard(); };
    els.chips.replaceChildren(
      ...srcs.map((x) => h('button', { class: 'chip-f', 'aria-pressed': String(S.fSources.has(x)), onclick: () => toggle(S.fSources, 'fsrc', x) }, h('span', { class: 'sw', style: { background: SRC_COLOR[x] || '#8c90a3' } }), x)),
      ...SEVS.map((v) => h('button', { class: 'chip-f', 'aria-pressed': String(S.fSevs.has(v)), onclick: () => toggle(S.fSevs, 'fsev', v) }, h('span', { class: 'sw', style: { background: `var(--sev-${v})` } }), t('sev')[v])));
  }

  // ---------------------------------------------------------------- hero bento
  function renderHero() {
    const sm = S.summary;
    if (!sm || !els.hero) return;
    const c = sm.counts;
    const tiles = [];
    tiles.push(h('div', { class: 'tile hero w2 h2' }, h('h3', null, t('critHigh')), h('div', { class: 'big' }, String(c.critical + c.high)),
      h('div', { class: 'row' }, h('span', null, h('b', null, String(c.critical)), t('sev').critical), h('span', null, h('b', null, String(c.high)), t('sev').high), h('span', null, h('b', null, String(c.medium + c.low + c.info)), t('otherOpen'))), h('div', { class: 'blob', 'aria-hidden': 'true' })));
    // donut
    const total = SEVS.reduce((n, k) => n + c[k], 0);
    const svg = s('svg', { viewBox: '0 0 42 42', role: 'img', 'aria-label': SEVS.map((k) => `${k} ${c[k]}`).join(', ') });
    svg.append(s('circle', { cx: 21, cy: 21, r: 15.9, fill: 'none', stroke: 'var(--tile-2)', 'stroke-width': 6 }));
    let off = 25;
    for (const k of SEVS) {
      if (!c[k]) continue;
      const pct = (c[k] / total) * 100;
      svg.append(s('circle', { cx: 21, cy: 21, r: 15.9, fill: 'none', stroke: `var(--sev-${k})`, 'stroke-width': 6, 'stroke-dasharray': `${pct} ${100 - pct}`, 'stroke-dashoffset': off }));
      off -= pct;
    }
    const lbl = s('text', { x: 21, y: 24, 'text-anchor': 'middle', 'font-size': 9, 'font-weight': 700, fill: 'currentColor' });
    lbl.textContent = String(total);
    svg.append(lbl);
    tiles.push(h('div', { class: 'tile w2' }, h('h3', null, t('bySeverity')), h('div', { class: 'donut' }, svg, h('div', { class: 'legend' }, SEVS.map((k) => h('span', { style: { '--c': `var(--sev-${k})` } }, `${t('sev')[k]} ${c[k]}`))))));
    // sparkline
    const max = Math.max(1, ...sm.spark);
    const pts = sm.spark.map((v, i) => `${(i / 23) * 100},${30 - (v / max) * 26}`).join(' ');
    const sp = s('svg', { viewBox: '0 0 100 32', preserveAspectRatio: 'none', role: 'img', 'aria-label': `${t('last24')}: ${sm.spark.reduce((a, b) => a + b, 0)}` },
      s('polygon', { points: `0,32 ${pts} 100,32`, fill: 'color-mix(in srgb, var(--indigo) 18%, transparent)' }),
      s('polyline', { points: pts, fill: 'none', stroke: 'var(--indigo)', 'stroke-width': 1.6, 'vector-effect': 'non-scaling-stroke', 'stroke-linejoin': 'round' }));
    tiles.push(h('div', { class: 'tile w2 spark' }, h('h3', null, t('last24'), ` · ${sm.spark.reduce((a, b) => a + b, 0)}`), sp));
    // sources
    for (const src of sm.sources.filter((x) => x.enabled)) {
      const dropped = src.dropped ? Object.entries(src.droppedSenders || {}).map(([ip, n]) => `${ip}: ${n}`).join('\n') : '';
      tiles.push(h('div', { class: `tile src-tile st-${src.status}` },
        h('div', { class: 'name' }, h('span', { class: 'status-dot', 'aria-hidden': 'true' }), src.name),
        h('div', { class: 'meta' },
          h('span', null, `${(t('st')[src.status] || src.status)} · ${t('lastOk')} ${ago(src.lastOk)}`),
          src.nextRun ? h('span', null, `${t('next')} ${src.nextRun > Date.now() ? t('inT', dur(src.nextRun - Date.now())) : '…'}`) : null,
          h('span', null, `${t('received')} ${src.received || 0}`),
          src.dropped ? h('span', { class: 'warn', title: dropped }, `${t('dropped')}: ${src.dropped}`) : null,
          src.unsupported ? h('span', { class: 'warn' }, `${t('unsupported')}: ${src.unsupported}`) : null,
          src.lastError ? h('span', { class: 'warn', title: src.lastError }, src.lastError.slice(0, 60)) : null),
        src.mode === 'pull' && canOperate() ? h('button', { class: 'btn', onclick: (e) => pullNow(src.name, e.currentTarget) }, t('pullNow')) : null));
    }
    // config
    const cfg = sm.configs[0];
    tiles.push(h('div', { class: 'tile w2' }, h('h3', null, t('config')),
      cfg ? [h('div', { class: 'name' }, h('b', null, cfg.device), ` · ${cfg.model} ${cfg.version} · ${cfg.policies} policies`),
        h('div', { class: 'cfg-counts' }, ['critical', 'high', 'medium', 'low'].map((k) => h('span', { class: 'badge', style: { background: `color-mix(in srgb, var(--sev-${k}) 18%, transparent)` } }, `${t('sev')[k]} ${cfg.counts[k] || 0}`)),
          h('span', { class: `badge ${cfg.complete ? '' : 'inj'}` }, cfg.complete ? t('complete') : `${t('incomplete')} (${cfg.gaps})`)),
        h('div', { class: 'muted' }, `${cfg.file || ''} · ${ago(Date.parse(cfg.analyzedAt))}`)] : h('div', { class: 'muted' }, t('noConfig'))));
    // llm
    const l = sm.llm;
    tiles.push(h('div', { class: 'tile' }, h('h3', null, t('llmTitle')),
      l.enabled ? [h('div', null, h('b', null, l.model)), h('div', { class: 'bar', role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': l.budgetPerHour, 'aria-valuenow': l.used, 'aria-label': t('budget') }, h('i', { style: { width: `${Math.min(100, (l.used / l.budgetPerHour) * 100)}%` } })),
        h('div', { class: 'muted' }, `${l.used}/${l.budgetPerHour} ${t('budget')} · ${t('inQueue')} ${l.queued}`), l.lastError ? h('div', { class: 'muted', title: l.lastError }, `⚠ ${l.lastError.slice(0, 50)}`) : null]
        : h('div', { class: 'muted' }, t('llmOff'))));
    els.hero.replaceChildren(...tiles);
  }

  // ---------------------------------------------------------------- cards
  const canOperate = () => S.me && (S.me.role === 'operator' || S.me.role === 'admin');
  function subline(it) {
    const f = { ...it.trusted, ...it.untrusted };
    const parts = [];
    if (f.srcip || f.dstip) parts.push(`${f.srcip || '-'} → ${f.dstip || '-'}${f.dstport ? `:${f.dstport}` : ''}`);
    if (f['agent.name']) parts.push(`agent ${f['agent.name']}`);
    if (f['data.srcip']) parts.push(`src ${f['data.srcip']}`);
    if (f.hosts) parts.push(f.hosts);
    if (f.device && it.kind === 'config') parts.push(`${f.refs || ''}`);
    if (f.user) parts.push(`user ${f.user}`);
    if (f.msg && !parts.length) parts.push(f.msg);
    if (f.why) parts.push(f.why);
    return parts.join(' · ');
  }
  function llmBadge(it) {
    if (it.llmState === 'done' && it.llm) return h('span', { class: 'badge ai' }, `AI: ${it.llm.classification} / ${it.llm.recommended_action}`);
    const map = { none: 'notTriaged', queued: 'queued', running: 'running', skipped: 'skipped', error: 'llmError' };
    return h('span', { class: 'badge' }, t(map[it.llmState] || 'notTriaged'));
  }
  function card(it) {
    const ex = S.expanded.has(it.id);
    const now = Date.now();
    const snoozed = it.snoozedUntil && it.snoozedUntil > now;
    const op = canOperate();
    const cls = `card sev-${it.severity}${ex ? ' expanded' : ''}${it.ackedBy ? ' acked' : ''}${snoozed ? ' snoozed' : ''}${it.resolvedAt ? ' resolved' : ''}`;
    const el = h('article', { class: cls, id: `item-${it.id}`, tabindex: 0, 'data-id': it.id, 'aria-labelledby': `t-${it.id}` },
      h('div', { class: 'card-head' },
        h('span', { class: 'sev-chip' }, t('sev')[it.severity]),
        h('span', { class: 'src-badge' }, h('i', { style: { '--c': SRC_COLOR[it.source] || '#8c90a3' }, 'aria-hidden': 'true' }, SRC_ABBR[it.source] || '•'), it.source),
        it.count > 1 ? h('span', { class: 'count', title: `${t('firstSeen')} ${clock(it.firstSeen)}` }, `×${it.count}`) : null,
        h('span', { class: 'time', title: `${t('lastSeen')} ${clock(it.lastSeen)}` }, ago(it.lastSeen))),
      h('h3', { id: `t-${it.id}` }, it.title),
      h('p', { class: 'sub' }, subline(it)),
      h('div', { class: 'badges' },
        it.flags.length ? h('span', { class: 'badge inj', title: it.flags.join('\n') }, `⚠ ${t('injection')}`) : null,
        llmBadge(it),
        it.pinnedBy ? h('span', { class: 'badge pin' }, icon('pin'), ` ${t('pinnedBy')} ${it.pinnedBy}`) : null,
        it.ackedBy ? h('span', { class: 'badge' }, `✓ ${t('ackedBy')} ${it.ackedBy}`) : null,
        snoozed ? h('span', { class: 'badge' }, icon('moon'), ` ${t('snoozedUntil')} ${clock(it.snoozedUntil)}`) : null,
        it.resolvedAt ? h('span', { class: 'badge' }, `✔ ${t('resolved')}`) : null),
      ex ? details(it) : null,
      h('div', { class: 'actions' },
        h('button', { class: 'btn', 'aria-expanded': String(ex), 'aria-controls': `d-${it.id}`, onclick: () => toggle(it.id) }, ex ? `▴ ${t('collapse')}` : `▾ ${t('expand')}`),
        h('button', { class: 'btn', 'aria-pressed': String(!!it.pinnedBy), disabled: !op, onclick: () => act(it, 'pin', { pinned: !it.pinnedBy }) }, icon('pin'), it.pinnedBy ? t('unpin') : t('pin')),
        h('button', { class: 'btn', 'aria-pressed': String(!!it.ackedBy), disabled: !op, onclick: () => act(it, 'ack', { acked: !it.ackedBy }) }, `✓ ${it.ackedBy ? t('unack') : t('ack')}`),
        snoozed ? h('button', { class: 'btn', disabled: !op, onclick: () => act(it, 'snooze', { hours: 0 }) }, t('unsnooze'))
          : h('span', { class: 'snz', role: 'group', 'aria-label': t('snooze') }, [1, 8, 24].map((n) => h('button', { class: 'btn', disabled: !op, 'aria-label': `${t('snooze')} ${n}h`, onclick: () => act(it, 'snooze', { hours: n }) }, icon('moon'), `${n}h`))),
        ex && S.summary && S.summary.llm.enabled ? h('button', { class: 'btn', disabled: !op || it.llmState === 'queued' || it.llmState === 'running', onclick: () => explain(it) }, `✦ ${t('explain')}`) : null,
        ex ? h('button', { class: 'btn', onclick: (e) => copy(it, e.currentTarget) }, t('copy')) : null,
        ex && it.link && /^https?:\/\//i.test(it.link) ? h('a', { class: 'btn', href: it.link, target: '_blank', rel: 'noopener noreferrer' }, `↗ ${t('openSource')}`) : null));
    return el;
  }
  function details(it) {
    const rows = [];
    for (const [k, v] of Object.entries(it.trusted)) rows.push(h('tr', null, h('th', { scope: 'row' }, k), h('td', null, v)));
    for (const [k, v] of Object.entries(it.untrusted)) rows.push(h('tr', { class: 'untrusted', title: t('untrusted') }, h('th', { scope: 'row' }, k), h('td', null, v)));
    const v = it.llm;
    return h('div', { class: 'details', id: `d-${it.id}` },
      h('table', { class: 'fields' }, h('caption', { class: 'sr' }, `${t('trusted')} / ${t('untrusted')}`), h('tbody', null, rows)),
      it.flags.length ? h('div', { class: 'verdict' }, h('b', null, `⚠ ${t('injection')}`), h('ul', null, it.flags.map((f) => h('li', null, f)))) : null,
      v && v.classification ? h('div', { class: 'verdict' }, h('div', null, `${t('verdict')}: `, h('b', null, `${v.classification} / ${v.recommended_action}`), ` · ${Math.round((v.confidence || 0) * 100)}% · ${v.model || ''}`),
        h('div', null, v.reason), v.overridden && v.overridden.length ? h('ul', null, v.overridden.map((o) => h('li', null, `${t('guard')}: ${o}`))) : null)
        : v && v.error ? h('div', { class: 'verdict' }, `${t('llmError')}: ${v.error}`) : null,
      h('div', { class: 'muted', style: { 'margin-top': '6px' } }, `${t('firstSeen')} ${clock(it.firstSeen)} · ${t('lastSeen')} ${clock(it.lastSeen)} · ${it.kind}`));
  }

  // masonry: each card spans as many 8px rows as its height needs
  const ro = typeof ResizeObserver === 'function' ? new ResizeObserver((entries) => { for (const e of entries) span(e.target); }) : null;
  function span(el) {
    const gap = 16;
    el.style.gridRowEnd = `span ${Math.max(1, Math.ceil((el.getBoundingClientRect().height + gap) / 8))}`;
  }
  let raf = 0;
  function renderBoard() {
    if (raf) return;
    raf = requestAnimationFrame(() => { raf = 0; drawBoard(); });
  }
  function drawBoard() {
    if (!els.live) return;
    const focused = document.activeElement && document.activeElement.closest && document.activeElement.closest('.card');
    const focusId = focused ? focused.dataset.id : null;
    const all = [...S.items.values()].filter(visible).sort(order);
    const pinned = [...S.items.values()].filter((i) => i.pinnedBy && (S.fSources.size ? S.fSources.has(i.source) : true)).sort(order);
    const live = all.filter((i) => !i.pinnedBy);
    if (ro) ro.disconnect();
    const fill = (box, list) => {
      box.replaceChildren(...(list.length ? list.map(card) : [h('div', { class: 'empty' }, t('empty'))]));
      for (const c of box.querySelectorAll('.card')) { span(c); if (ro) ro.observe(c); }
    };
    fill(els.pinned, pinned);
    fill(els.live, live.slice(0, 400));
    els.pinCount.textContent = String(pinned.length);
    els.liveCount.textContent = String(live.length);
    if (focusId) { const c = document.getElementById(`item-${focusId}`); if (c) c.focus({ preventScroll: true }); }
  }

  function toggle(id) {
    S.expanded.has(id) ? S.expanded.delete(id) : S.expanded.add(id);
    store.set('expanded', [...S.expanded].slice(-300));
    if (S.expanded.has(id)) api('POST', `/api/items/${id}/view`, {}).catch(() => {});
    renderBoard();
  }
  function setAll(on) {
    if (on) for (const it of S.items.values()) { if (visible(it) || it.pinnedBy) S.expanded.add(it.id); }
    else S.expanded.clear();
    store.set('expanded', [...S.expanded].slice(-300));
    renderBoard();
  }
  async function act(it, action, body) {
    try { const r = await api('POST', `/api/items/${it.id}/${action}`, body); if (r.item) { S.items.set(r.item.id, r.item); renderBoard(); refreshSummary(); } }
    catch (e) { toast(null, e.message); }
  }
  async function explain(it) {
    try { const r = await api('POST', `/api/items/${it.id}/explain`, {}); toast(null, t('queuedAt', r.position)); }
    catch (e) { toast(null, e.message); }
  }
  async function pullNow(name, btn) {
    btn.disabled = true;
    try { await api('POST', `/api/sources/${encodeURIComponent(name)}/pull`, {}); } catch (e) { toast(null, e.message); }
    btn.disabled = false;
    refreshSummary();
  }
  function copy(it, btn) {
    const text = `[${it.severity.toUpperCase()}] ${it.source}: ${it.title}\n${subline(it)}\n${Object.entries({ ...it.trusted, ...it.untrusted }).map(([k, v]) => `${k}=${v}`).join('\n')}`;
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject(new Error('clipboard'))).then(() => { btn.textContent = t('copied'); }, () => {});
  }
  function cycleTheme() {
    S.theme = S.theme === 'auto' ? 'dark' : S.theme === 'dark' ? 'light' : 'auto';
    store.set('theme', S.theme);
    renderShell();
  }
  async function logout() {
    try { await api('POST', '/api/logout', {}); } catch { /* ignore */ }
    if (es) es.close();
    S.me = null; renderLogin();
  }

  // ---------------------------------------------------------------- notifications
  function toggleDrawer(force) {
    S.drawer = force ?? !S.drawer;
    if (S.drawer) { S.unread = 0; renderBell(); }
    renderDrawer();
  }
  function renderBell() {
    if (!els.bellDot) return;
    els.bellDot.hidden = !S.unread;
    els.bellDot.textContent = S.unread > 99 ? '99+' : String(S.unread);
  }
  function renderDrawer() {
    if (!els.drawer) return;
    els.drawer.hidden = !S.drawer;
    if (!S.drawer) return;
    const groups = new Map();
    for (const n of S.notes) { if (!groups.has(n.item.source)) groups.set(n.item.source, []); groups.get(n.item.source).push(n); }
    const perm = typeof Notification === 'function' ? Notification.permission : 'unsupported';
    els.drawer.replaceChildren(
      h('header', null, h('h2', null, t('notifications')),
        h('button', { class: 'btn', onclick: () => { for (const n of S.notes) n.read = true; renderDrawer(); } }, t('markRead')),
        h('button', { class: 'btn', 'aria-label': t('close'), onclick: () => toggleDrawer(false) }, '✕')),
      h('div', { class: 'list' },
        perm === 'default' ? h('button', { class: 'btn primary', style: { margin: '8px 0' }, onclick: () => Notification.requestPermission().then(renderDrawer) }, t('desktop')) : perm === 'granted' ? h('p', { class: 'muted' }, t('desktopOn')) : null,
        S.notes.length ? [...groups.entries()].map(([src, list]) => {
          const open = !S.openGroups.has(`closed:${src}`);
          return h('div', { class: 'ngroup' },
            h('button', { 'aria-expanded': String(open), onclick: () => { S.openGroups.has(`closed:${src}`) ? S.openGroups.delete(`closed:${src}`) : S.openGroups.add(`closed:${src}`); renderDrawer(); } },
              open ? '▾' : '▸', h('span', { class: 'src-badge' }, h('i', { style: { '--c': SRC_COLOR[src] || '#8c90a3' } }, SRC_ABBR[src] || '•'), src), h('span', { class: 'n' }, String(list.length))),
            open ? h('ul', null, list.slice(0, 50).map((n) => h('li', { class: n.read ? '' : 'unread' }, h('button', { onclick: () => jump(n.item.id) },
              h('span', { class: 'sev-chip', style: { '--sevc': `var(--sev-${n.item.severity})` } }, t('sev')[n.item.severity]), h('span', null, n.item.title), h('span', { class: 'muted' }, ago(n.at)))))) : null);
        }) : h('p', { class: 'empty' }, t('empty'))));
  }
  function jump(id) {
    toggleDrawer(false);
    S.expanded.add(id);
    const it = S.items.get(id);
    if (it && !visible(it) && !it.pinnedBy) { S.view = 'all'; S.q = ''; S.fSources.clear(); S.fSevs.clear(); renderShell(); }
    else renderBoard();
    requestAnimationFrame(() => requestAnimationFrame(() => { const c = document.getElementById(`item-${id}`); if (c) { c.scrollIntoView({ block: 'center' }); c.focus({ preventScroll: true }); } }));
  }

  // grouped toasts: one per source, collapsible, auto-dismiss unless hovered or expanded
  const tgroups = new Map();
  function toast(item, text) {
    if (!item) {
      const el = h('div', { class: 'toast' }, text);
      toasts.append(el);
      setTimeout(() => el.remove(), 4000);
      return;
    }
    let g = tgroups.get(item.source);
    if (!g) {
      const list = h('ul', { hidden: true });
      const head = h('span', null);
      const tog = h('button', { 'aria-expanded': 'false', 'aria-label': t('expand') }, '▾');
      const el = h('div', { class: 'toast' }, h('div', { class: 't-head' }, h('span', { class: 'sev-chip' }, item.source), head, tog, h('button', { 'aria-label': t('close'), onclick: () => close() }, '✕')), list);
      g = { el, list, head, tog, items: [], timer: null, hover: false };
      tog.addEventListener('click', () => { const on = list.hidden; list.hidden = !on; tog.setAttribute('aria-expanded', String(on)); tog.textContent = on ? '▴' : '▾'; arm(); });
      el.addEventListener('mouseenter', () => { g.hover = true; clearTimeout(g.timer); });
      el.addEventListener('mouseleave', () => { g.hover = false; arm(); });
      const close = () => { el.remove(); tgroups.delete(item.source); };
      const arm = () => { clearTimeout(g.timer); if (!g.hover && list.hidden) g.timer = setTimeout(close, 8000); };
      g.arm = arm;
      tgroups.set(item.source, g);
      toasts.append(el);
    }
    g.items.unshift(item);
    g.head.textContent = g.items.length === 1 ? `${t('sev')[item.severity]}: ${item.title}` : t('newFrom', g.items.length, item.source);
    g.list.replaceChildren(...g.items.slice(0, 8).map((i) => h('li', null, h('a', { href: `#item-${i.id}`, onclick: (e) => { e.preventDefault(); jump(i.id); } }, `${t('sev')[i.severity]} · ${i.title}`))));
    g.arm();
  }
  function onNotify(n) {
    const it = n.item;
    S.items.set(it.id, it);
    S.notes.unshift({ item: it, at: Date.now(), read: S.drawer });
    S.notes.length = Math.min(S.notes.length, 200);
    if (!S.drawer) S.unread++;
    renderBell(); renderDrawer();
    toast(it);
    if (typeof Notification === 'function' && Notification.permission === 'granted' && document.visibilityState !== 'visible') {
      try { const nn = new Notification(`NetSec ${t('sev')[it.severity]}`, { body: `${it.source}: ${it.title}`.slice(0, 180), tag: `item-${it.id}` }); nn.onclick = () => { window.focus(); jump(it.id); }; } catch { /* unsupported */ }
    }
  }

  // ---------------------------------------------------------------- data + live stream
  let es = null, sumTimer = 0;
  function refreshSummary() {
    clearTimeout(sumTimer);
    sumTimer = setTimeout(async () => {
      try { S.summary = await api('GET', '/api/summary'); renderHero(); renderChips(); } catch { /* shown on next call */ }
    }, 300);
  }
  async function loadItems() {
    const r = await api('GET', '/api/items');
    S.items = new Map(r.items.map((i) => [i.id, i]));
  }
  function connect() {
    if (es) es.close();
    es = new EventSource('/api/events');
    es.addEventListener('item', (e) => { const it = JSON.parse(e.data); S.items.set(it.id, it); renderBoard(); refreshSummary(); });
    es.addEventListener('notify', (e) => onNotify(JSON.parse(e.data)));
    es.addEventListener('source', refreshSummary);
    es.addEventListener('llm', refreshSummary);
    es.addEventListener('refresh', async () => { await loadItems(); renderBoard(); refreshSummary(); });
    es.onerror = () => { if (es.readyState === EventSource.CLOSED) setTimeout(() => { if (S.me) connect(); }, 3000); };
  }
  async function start() {
    const me = await api('GET', '/api/me');
    S.me = me.user; S.csrf = me.csrf;
    if (!S.lang) S.lang = me.lang === 'en' ? 'en' : 'th';
    [S.summary] = await Promise.all([api('GET', '/api/summary'), loadItems()]);
    renderShell();
    connect();
    setInterval(refreshSummary, 30000);
    if (location.hash.startsWith('#item-')) jump(Number(location.hash.slice(6)));
  }

  // ---------------------------------------------------------------- keyboard
  document.addEventListener('keydown', (e) => {
    if (!S.me || e.ctrlKey || e.metaKey || e.altKey) return;
    const tag = (e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea') { if (e.key === 'Escape') e.target.blur(); return; }
    const cards = [...document.querySelectorAll('.card')];
    const cur = document.activeElement && document.activeElement.closest ? document.activeElement.closest('.card') : null;
    const it = cur ? S.items.get(Number(cur.dataset.id)) : null;
    if (e.key === '/') { e.preventDefault(); els.search && els.search.focus(); }
    else if (e.key === 'j' || e.key === 'k') {
      e.preventDefault();
      const i = cur ? cards.indexOf(cur) : -1;
      const n = cards[Math.max(0, Math.min(cards.length - 1, i + (e.key === 'j' ? 1 : -1)))];
      if (n) { n.focus(); n.scrollIntoView({ block: 'nearest' }); }
    } else if (it && e.key === 'e') toggle(it.id);
    else if (it && e.key === 'p' && canOperate()) act(it, 'pin', { pinned: !it.pinnedBy });
    else if (it && e.key === 'a' && canOperate()) act(it, 'ack', { acked: !it.ackedBy });
    else if (e.key === 'Escape' && S.drawer) toggleDrawer(false);
  });

  applyTheme();
  start().catch(() => renderLogin());
})();
