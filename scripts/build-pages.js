#!/usr/bin/env node
'use strict';
/*
 * Builds the GitHub Pages site from one bilingual source:
 *   index.html      landing page (NetSec Board), Thai/English
 *   manual.html     operator + admin manual, Thai/English
 *   docs/manual.md  the manual in English, for offline / air-gapped use
 * Style and the TH/EN switch are taken from how-it-works.html, so the pages look alike.
 * Every section exists in both languages by construction (each text is a {th, en} pair).
 *   node scripts/build-pages.js
 */
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const REPO = 'https://github.com/MONNNNNNNNNNN/kku-netsec-assistant';
const PAGES = 'https://monnnnnnnnnnn.github.io/kku-netsec-assistant';
const INSTALL = 'curl -fsSL https://raw.githubusercontent.com/MONNNNNNNNNNN/kku-netsec-assistant/main/install.sh | sh';
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
// inline markup inside texts: `code` and **bold**
const inline = (s) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
const md = (s) => String(s); // markdown already uses `code` and **bold**

// ---------------------------------------------------------------- shared head (from how-it-works.html)
const hiw = fs.readFileSync(path.join(ROOT, 'how-it-works.html'), 'utf8');
const STYLE = hiw.slice(hiw.indexOf('<style>'), hiw.indexOf('</style>') + '</style>'.length);
const EXTRA_CSS = `<style>
.hero h1 { font-size: 30px; }
.cta { display: flex; flex-wrap: wrap; gap: 8px; }
.cta a { display: inline-block; padding: 9px 14px; border-radius: var(--r); border: 1px solid var(--line); text-decoration: none; font-weight: 600; font-size: 14px; color: var(--ink); background: var(--surface); }
.cta a.primary { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
.stats { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; }
.stat { border: 1px solid var(--line); border-radius: var(--r); padding: 12px; background: var(--sunk); }
.stat b { display: block; font: 700 24px/1.1 var(--f-display); color: var(--accent); }
.stat span { font-size: 13px; color: var(--muted); }
figure { margin: 0; } figure img { width: 100%; height: auto; border: 1px solid var(--line); border-radius: var(--r); display: block; }
figcaption { font-size: 13px; color: var(--muted); margin-top: 6px; }
.feat { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 10px; }
.sev { display: inline-block; min-width: 64px; text-align: center; border-radius: 999px; padding: 1px 8px; font: 600 12px/1.6 var(--f-display); color: #fff; }
.sev.c { background: var(--crit); } .sev.h { background: var(--high); } .sev.m { background: var(--med); } .sev.l { background: var(--low); } .sev.i { background: var(--muted); }
kbd { font: 12px var(--f-mono); border: 1px solid var(--line); border-bottom-width: 2px; border-radius: 4px; padding: 0 5px; background: var(--surface); }
</style>`;
const SCRIPT = hiw.slice(hiw.lastIndexOf('<script>'), hiw.lastIndexOf('</script>') + '</script>'.length).replace(/hiw-lang/g, 'nsb-lang');

function page({ title, description, sub, body, imgSelf = false }) {
  const csp = `default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${imgSelf ? "'self' " : ''}data:; connect-src 'none'; form-action 'none'; frame-src 'none'; base-uri 'none'`;
  return `<!doctype html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bai+Jamjuree:wght@500;600;700&family=IBM+Plex+Sans+Thai:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">
${STYLE}
${EXTRA_CSS}
</head>
<body>
<header class="top">
  <div class="wrap">
    <p class="brand"><a href="./">NetSec Board</a></p>
    <span class="sub">${bi(sub)}</span>
    <div class="lang" role="group" aria-label="Language">
      <button id="b-th" aria-pressed="true">ไทย</button>
      <button id="b-en" aria-pressed="false">English</button>
    </div>
  </div>
</header>
<div class="wrap">
<main>
${body}
</main>
</div>
${SCRIPT}
</body>
</html>
`;
}
const bi = (t, tag = 'span') => `<${tag} data-l="th">${inline(t.th)}</${tag}><${tag} data-l="en">${inline(t.en)}</${tag}>`;

// ---------------------------------------------------------------- blocks
const B = {
  p: (th, en) => ({ k: 'p', th, en }),
  ul: (items) => ({ k: 'ul', items }), // items: [[th, en]]
  pre: (code) => ({ k: 'pre', code }),
  note: (th, en, warn) => ({ k: 'note', th, en, warn }),
  table: (head, rows) => ({ k: 'table', head, rows }), // head: [[th,en]], rows: [[cell...]] cell = string | [th,en]
  h3: (th, en) => ({ k: 'h3', th, en }),
};
function htmlBlock(b) {
  if (b.k === 'p') return bi({ th: b.th, en: b.en }, 'p');
  if (b.k === 'h3') return bi({ th: b.th, en: b.en }, 'h3');
  if (b.k === 'pre') return `<pre>${esc(b.code)}</pre>`;
  if (b.k === 'note') return `<div class="note${b.warn ? ' warn' : ''}">${bi({ th: b.th, en: b.en }, 'p')}</div>`;
  if (b.k === 'ul') return `<ul>${b.items.map(([th, en]) => `<li>${bi({ th, en })}</li>`).join('')}</ul>`;
  if (b.k === 'table') {
    const cell = (c) => (Array.isArray(c) ? bi({ th: c[0], en: c[1] }) : inline(c));
    return `<div class="table"><table><thead><tr>${b.head.map((h) => `<th>${cell(h)}</th>`).join('')}</tr></thead><tbody>${b.rows.map((r) => `<tr>${r.map((c) => `<td>${cell(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  }
  throw new Error(`block ${b.k}`);
}
function mdBlock(b) {
  if (b.k === 'p') return md(b.en);
  if (b.k === 'h3') return `### ${b.en}`;
  if (b.k === 'pre') return `\`\`\`\n${b.code}\n\`\`\``;
  if (b.k === 'note') return `> ${b.warn ? '**Warning:** ' : ''}${md(b.en)}`;
  if (b.k === 'ul') return b.items.map(([, en]) => `- ${md(en)}`).join('\n');
  if (b.k === 'table') {
    const cell = (c) => (Array.isArray(c) ? c[1] : c).replace(/\|/g, '\\|');
    return [`| ${b.head.map(cell).join(' | ')} |`, `|${b.head.map(() => '---').join('|')}|`, ...b.rows.map((r) => `| ${r.map(cell).join(' | ')} |`)].join('\n');
  }
  throw new Error(`block ${b.k}`);
}

// ---------------------------------------------------------------- manual content
const S = (id, th, en, blocks) => ({ id, th, en, blocks });
const MANUAL = [
  S('intro', 'คู่มือนี้คืออะไร', 'About this manual', [
    B.p('NetSec Board คือกระดานติดตามเหตุการณ์ด้าน network และ security ที่ดึงข้อมูลจาก FortiGate, Wazuh และ Zabbix มาเองโดยอัตโนมัติ แสดงเป็นการ์ด และแจ้งเตือนเมื่อมีเรื่องสำคัญ ทำงานใน on-prem อ่านข้อมูลอย่างเดียว ไม่เขียนกลับไปที่อุปกรณ์',
      'NetSec Board is a monitoring board for network and security events. It pulls and receives data from FortiGate, Wazuh and Zabbix automatically, shows each event as a card, and notifies people when something matters. It runs on-prem and only reads; it never writes to a device.'),
    B.ul([
      ['**ผู้ปฏิบัติงาน (operator):** อ่านส่วน "ใช้งานประจำวัน" ทุกอย่างที่ต้องทำบนกระดานอยู่ที่นั่น', '**Operators:** read "Daily use": everything you do on the board is there.'],
      ['**ผู้ดูแลระบบ (admin):** อ่านส่วน "ติดตั้งและตั้งค่า" และ "แก้ปัญหา"', '**Admins:** read "Install and configure" and "Troubleshooting".'],
      ['ตัวเลขทั้งหมดในคู่มือนี้วัดจากระบบจริง ดู `results/real-data-eval.md`', 'Every number in this manual was measured on real systems: see `results/real-data-eval.md`.'],
    ]),
  ]),
  S('tour', 'ใช้งานประจำวัน 1: หน้ากระดาน', 'Daily use 1: the board', [
    B.p('เปิดกระดานด้วยเบราว์เซอร์แล้วเข้าสู่ระบบ ด้านบนเป็นแถบสรุป ด้านล่างเป็นการ์ด', 'Open the board in a browser and sign in. The top area summarises; the cards are below.'),
    B.table([['ส่วน', 'Part'], ['ใช้ทำอะไร', 'What it is for']], [
      [['เปิดอยู่ critical + high', 'Open critical + high'], ['จำนวนเรื่องสำคัญที่ยังไม่มีใคร acknowledge ดูอันนี้ก่อน', 'How many important items nobody has acknowledged yet. Look here first.']],
      [['ตามระดับความรุนแรง', 'By severity'], ['สัดส่วนการ์ดที่เปิดอยู่ในแต่ละระดับ', 'Open cards per severity.']],
      [['รายการใหม่ 24 ชม.', 'New items, 24 h'], ['กราฟการ์ดใหม่รายชั่วโมง ยอดพุ่งคือมีเหตุการณ์', 'New cards per hour: a spike means something happened.']],
      [['แหล่งข้อมูล', 'Sources'], ['สถานะของแต่ละแหล่ง (ok / degraded / down) และข้อความ error ที่บอกวิธีแก้', 'Each source\'s status (ok / degraded / down) with an error that says what to fix.']],
      [['คิว AI', 'AI queue'], ['งานที่รอให้ AI อธิบาย และงบต่อชั่วโมง', 'Cards waiting for the AI, and the hourly budget.']],
      [['ปักหมุด / สด', 'Pinned / Live'], ['การ์ดที่ปักหมุดไว้ อยู่บนสุดเสมอ ถัดมาคือการ์ดทั้งหมด', 'Pinned cards stay on top; all other cards follow.']],
    ]),
    B.p('ใช้ chip ด้านบนกรองตามแหล่งหรือระดับ ปุ่ม Open / Acknowledged / All สลับมุมมอง กด `/` เพื่อค้นหา', 'Use the chips to filter by source or severity, Open / Acknowledged / All to switch views, and `/` to search.'),
  ]),
  S('severity', 'ใช้งานประจำวัน 2: ระดับความรุนแรง', 'Daily use 2: what the severity means', [
    B.p('ระดับมาจาก field ที่อุปกรณ์สร้างเองเท่านั้น ข้อความที่ผู้โจมตีเขียนลงใน log ทำให้ระดับลดลงไม่ได้', 'Severity comes only from fields the device generates. Text an attacker writes into a log can never lower it.'),
    B.table([['ระดับ', 'Level'], ['ความหมาย', 'Meaning'], ['จะเกิดอะไรขึ้น', 'What happens']], [
      ['**critical**', ['ต้องดูทันที เช่น ransomware C2, IPS critical', 'Act now: e.g. ransomware C2, IPS critical'], ['แจ้งทุกช่องทาง, AI อธิบายให้อัตโนมัติ, ไม่ปิดเอง', 'All channels, automatic AI triage, never closes by itself']],
      ['**high**', ['สำคัญ เช่น brute force, Wazuh ระดับ 10-12', 'Important: brute force, Wazuh level 10-12'], ['แจ้งช่องทาง (ค่าเริ่มต้น), ไม่ปิดเอง', 'Channels (default), never closes by itself']],
      ['**medium**', ['ควรตรวจ เช่น การพยายามสั่ง AI ใน log', 'Worth a look: e.g. a log that tries to instruct the AI'], ['ขึ้นบนกระดาน, ปิดเองหลัง 72 ชม. ถ้าเงียบ', 'On the board; closes after 72 h of quiet']],
      ['**low**', ['ข้อมูลเสริม เช่น การสแกน SSH จากอินเทอร์เน็ต', 'Context: e.g. SSH scanning from the internet'], ['ขึ้นบนกระดาน, ปิดเองหลัง 24 ชม.', 'On the board; closes after 24 h']],
      ['**info**', ['ปกติ ถูกกรองออกตามค่าเริ่มต้น', 'Normal: filtered out by default'], ['-', '-']],
    ]),
  ]),
  S('actions', 'ใช้งานประจำวัน 3: จัดการการ์ด', 'Daily use 3: handling cards', [
    B.table([['ปุ่ม', 'Button'], ['ผล', 'Effect']], [
      ['Expand', ['เปิดดูทุก field ช่องที่มีเครื่องหมาย ⚠ คือข้อความที่คนภายนอกควบคุมได้', 'Show every field. Fields marked ⚠ hold text an outsider can control.']],
      ['Pin', ['ปักไว้บนสุด การ์ดที่ปักหมุดไม่ถูกปิดอัตโนมัติ', 'Keep on top. Pinned cards never auto-close.']],
      ['Acknowledge', ['บอกว่ามีคนรับเรื่องแล้ว การ์ดย้ายไปแท็บ Acknowledged', 'Someone owns it. The card moves to Acknowledged.']],
      ['Snooze 1h / 8h / 24h', ['ซ่อนชั่วคราว ระหว่างนี้ไม่แจ้งเตือน', 'Hide for a while, with no notifications meanwhile.']],
    ]),
    B.ul([
      ['**เกิดซ้ำ:** การ์ดที่ถูกปิด (resolved) แล้วเกิดอีก จะเปิดใหม่และแจ้งอีกครั้ง', '**Recurrence:** a resolved card that happens again re-opens and notifies again.'],
      ['**ระดับเพิ่มขึ้น:** ถ้าเหตุการณ์ซ้ำมีระดับสูงกว่าเดิม การ acknowledge และ snooze จะถูกล้างและแจ้งใหม่', '**Escalation:** a repeat with a higher severity clears acknowledge and snooze and notifies again.'],
      ['**re-arm:** การ์ดที่ acknowledge แล้วแต่เหตุการณ์กลับมาอีกหลังเงียบไป 24 ชม. จะแจ้งใหม่ (ปรับได้ที่ `board.rearmAfterHours`)', '**Re-arm:** an acknowledged card whose event comes back after 24 h of quiet notifies again (`board.rearmAfterHours`).'],
      ['**ปิดอัตโนมัติ:** การ์ด low/medium ที่เงียบไปจะถูกปิดเอง (24/72 ชม.) high และ critical ต้องให้คนปิด การ์ดที่ปักหมุดหรืออยู่ระหว่าง snooze จะไม่ถูกปิด', '**Auto-close:** quiet low/medium cards close by themselves (24/72 h); high and critical wait for a person. Pinned cards and cards inside a snooze stay open.'],
      ['คีย์ลัด: `j`/`k` เลื่อน, `e` เปิด/ปิด, `p` ปักหมุด, `a` acknowledge, `/` ค้นหา', 'Keys: `j`/`k` move, `e` expand, `p` pin, `a` acknowledge, `/` search.'],
    ]),
  ]),
  S('grouping', 'ใช้งานประจำวัน 4: การรวมการ์ด', 'Daily use 4: how events are grouped', [
    B.ul([
      ['เหตุการณ์เดียวกันซ้ำกันเป็นการ์ดเดียว พร้อมตัวนับ ×N', 'Repeats of one event are one card with a count ×N.'],
      ['ค่าที่ผู้โจมตีเปลี่ยนได้ (ชื่อผู้ใช้, URL) เก็บเป็น "ตัวอย่าง" สูงสุด 5 ค่า brute force ด้วยชื่อผู้ใช้สุ่มจึงยังเป็นการ์ดเดียว', 'Values an attacker can vary (user names, URLs) are kept as up to 5 samples, so a brute force with random user names stays one card.'],
      ['การสแกนระดับ low จากหลาย IP (เช่น Wazuh 5710) รวมเป็นการ์ดเดียวต่อกฎและเครื่อง ระดับ medium ขึ้นไปแยกตาม IP', 'Low-severity scanning from many IPs (e.g. Wazuh 5710) is one card per rule and host; medium and above stay one card per IP.'],
      ['**burst:** ถ้าแหล่งหนึ่งสร้างการ์ดใหม่เกิน 120 ใบต่อนาที เหตุการณ์ใหม่ที่ต่างกันจะรวมเป็นการ์ด "burst of distinct events" ใบเดียว', '**Burst:** above 120 new cards a minute from one source, further distinct events fold into one "burst of distinct events" card.'],
      ['**correlated:** IP เดียวกันที่ FortiGate และ Wazuh เห็นภายใน 1 ชม. ทั้งสองการ์ดได้ป้าย correlated และระดับเพิ่ม 1 ขั้น (สูงสุด high)', '**Correlated:** the same IP seen by FortiGate and Wazuh within an hour tags both cards "correlated" and raises them one level (at most high).'],
    ]),
  ]),
  S('ai', 'ใช้งานประจำวัน 5: AI อธิบาย', 'Daily use 5: Explain (AI)', [
    B.p('กด "Explain (AI)" บนการ์ดเพื่อให้โมเดลในเครื่อง (เช่น qwen2.5:3b) อธิบายและแนะนำว่าควรทำอะไร ใช้เวลาประมาณ 23 วินาทีต่อการ์ดบน CPU', 'Press "Explain (AI)" on a card: a local model (e.g. qwen2.5:3b) explains it and suggests an action, in about 23 s per card on a CPU.'),
    B.ul([
      ['AI ทำให้ระดับ**สูงขึ้น**ได้อย่างเดียว ไม่มีทางลดระดับ', 'The AI can only **raise** a card\'s severity, never lower it.'],
      ['ถ้า AI ยกระดับการ์ดที่อุปกรณ์ให้ระดับ low/info จะขึ้นบนกระดานเท่านั้น ไม่ส่งแจ้งเตือน แม้การ์ดจะเป็น medium เพราะมีข้อความพยายามสั่ง AI ก็ยังนับระดับจากอุปกรณ์ (กันผู้โจมตีหลอก AI ให้ปลุกทีมกลางดึก)', 'If the AI raises a card the device rated low/info, it shows on the board only, with no notification. A card that is medium only because its log tries to instruct the AI still counts as what the device said (so an attacker cannot trick the AI into paging the team).'],
      ['ป้าย "tried to manipulate AI" แปลว่า log มีข้อความพยายามสั่ง AI การ์ดนั้นจะเป็นอย่างน้อย medium และ guard จะไม่ยอมให้ AI ตอบว่าปลอดภัย', 'The "tried to manipulate AI" badge means the log contains text that tries to instruct the AI. Such a card is at least medium, and the guard never lets the AI call it safe.'],
      ['ในการทดสอบจริง โมเดลถูกหลอกให้ตอบ "benign" 1 ใน 4 ครั้ง และ guard แก้กลับทุกครั้ง', 'In real tests the model was fooled into "benign" once in 4 tries, and the guard overrode it every time.'],
    ]),
  ]),
  S('notify', 'ใช้งานประจำวัน 6: การแจ้งเตือน', 'Daily use 6: notifications', [
    B.ul([
      ['บนกระดาน: toast และกระดิ่ง (ระดับ high ขึ้นไปตามค่าเริ่มต้น)', 'On the board: toasts and the bell (high and above by default).'],
      ['ช่องทาง: ntfy, Telegram, LINE (สรุปเป็นรอบ), webhook แต่ละช่องตั้งระดับขั้นต่ำ ช่วงเงียบ และเพดานต่อวันได้', 'Channels: ntfy, Telegram, LINE (digests), webhook. Each has a minimum severity, quiet hours and a daily cap.'],
      ['ช่องทางคลาวด์ได้รับเฉพาะข้อความที่ปิดบังแล้ว: IP, ชื่อเครื่อง, ชื่อผู้ใช้ เป็น token (เช่น `HOSTNAME_1`) ทดสอบกับการ์ดจริง 30 ใบ ไม่รั่ว', 'Cloud channels only get masked text: IPs, host and user names become tokens (e.g. `HOSTNAME_1`). Tested on 30 real cards: no leaks.'],
      ['การดึงข้อมูลครั้งแรกของแต่ละแหล่งเป็นแบบเงียบ: เรื่องที่เปิดอยู่แล้วขึ้นเป็นการ์ด แต่ไม่ส่งแจ้งเตือน', 'The first pull of each source is quiet: what is already open appears as cards, without notifications.'],
    ]),
  ]),
  S('install', 'ติดตั้งและตั้งค่า 1: ติดตั้ง', 'Install and configure 1: install', [
    B.p('คำสั่งเดียว (Linux) ใช้ Docker ถ้ามี ถ้าไม่มีใช้ Node 22.13 ขึ้นไปพร้อม systemd service:', 'One command (Linux). It uses Docker if present, otherwise Node 22.13+ with a systemd service:'),
    B.pre(INSTALL),
    B.ul([
      ['ตัวช่วยตั้งค่าจะถามทีละข้อ และ**ทดสอบกับระบบจริงทันที**: IP ของ FortiGate, Wazuh indexer, Zabbix, โฟลเดอร์ backup, ช่องทางแจ้งเตือน, LLM', 'The wizard asks one question at a time and **tests each answer live**: FortiGate IP, Wazuh indexer, Zabbix, backup folder, a notification channel, the LLM.'],
      ['ผลลัพธ์: `netsec.json` (ไม่มีรหัสผ่านในไฟล์) และ `secrets.env` (สิทธิ์ 600) รหัสผ่าน admin แสดงครั้งเดียว', 'It writes `netsec.json` (no secrets inside) and `secrets.env` (mode 600), and shows the admin password once.'],
      ['รันซ้ำ = อัปเกรด เก็บ config และข้อมูลไว้ ใส่ `--reconfigure` ถ้าต้องการตอบคำถามใหม่', 'Running it again upgrades and keeps config and data; add `--reconfigure` to answer the questions again.'],
      ['ตัวเลือก: `sh -s -- --docker` หรือ `--node`, `--dir /srv/netsec-board`, `--non-interactive` (ใช้ตัวแปร `NETSEC_SETUP_*`)', 'Options: `sh -s -- --docker` or `--node`, `--dir /srv/netsec-board`, `--non-interactive` (with `NETSEC_SETUP_*` variables).'],
    ]),
    B.note('วัดจริง: ติดตั้ง 10 วินาที การ์ดจริงใบแรก 3.6 วินาทีหลังเริ่ม', 'Measured: install in 10 s, first real card 3.6 s after start.'),
  ]),
  S('fortigate', 'ติดตั้งและตั้งค่า 2: FortiGate', 'Install and configure 2: FortiGate', [
    B.p('FortiGate ส่ง syslog มาที่กระดาน (แนะนำ TCP) บน FortiGate CLI:', 'FortiGate sends syslog to the board (TCP recommended). On the FortiGate CLI:'),
    B.pre('config log syslogd setting\n    set status enable\n    set server "<board IP>"\n    set mode reliable\n    set port 5514\n    set format rfc5424\nend'),
    B.ul([
      ['ใส่ IP ของ FortiGate ใน `sources.syslog.allow` ผู้ส่งอื่นถูกทิ้ง', 'Put the FortiGate\'s IP in `sources.syslog.allow`; any other sender is dropped.'],
      ['UDP ปลอม IP ต้นทางได้และหายได้ ถ้าใช้ TCP ให้ตั้ง `"udp": false`', 'UDP sender addresses can be forged and packets can be lost: with TCP, set `"udp": false`.'],
      ['backup config: ให้งาน backup เดิมเขียนไฟล์ `.conf` ลงโฟลเดอร์ แล้วเปิด `sources.configdrop`', 'Config backups: let your existing backup job write `.conf` files into a folder and enable `sources.configdrop`.'],
    ]),
  ]),
  S('wazuh', 'ติดตั้งและตั้งค่า 3: Wazuh', 'Install and configure 3: Wazuh', [
    B.p('กระดานอ่านจาก Wazuh indexer (พอร์ต 9200) ด้วย user ที่อ่านได้อย่างเดียว สคริปต์อยู่ใน repo บนเครื่อง Wazuh all-in-one ให้ clone แล้วรันด้วย sudo **ก่อน**ติดตั้งกระดาน:', 'The board reads the Wazuh indexer (port 9200) with a read-only user. The scripts are in the repo: on a Wazuh all-in-one host, clone it and run them with sudo **before** installing the board:'),
    B.pre('git clone https://github.com/MONNNNNNNNNNN/kku-netsec-assistant && cd kku-netsec-assistant\nsudo sh lab/wazuh-prepare.sh       # read-only user netsec_board_ro; password and CA in /etc/netsec-board/\nsudo sh lab/wazuh-heap.sh 4g       # only if the indexer answers HTTP 429 circuit_breaking_exception'),
    B.ul([
      ['ตัวช่วยตั้งค่าถามรหัสผ่าน (ดูได้ด้วย `sudo cat /etc/netsec-board/wazuh-ro-password`) แล้วเก็บไว้ใน `secrets.env` (0600) ไม่ใช่ใน `netsec.json`', 'The wizard asks for the password (read it with `sudo cat /etc/netsec-board/wazuh-ro-password`) and keeps it in `secrets.env` (0600), not in `netsec.json`.'],
      ['ตัวติดตั้งคัดลอก CA ของ indexer (Wazuh ใช้ CA ที่ลงนามเอง) ไปที่ `certs/wazuh-root-ca.pem` ข้าง `netsec.json` ถ้าอ่านได้ ตัวช่วยตั้งค่าจะเสนอไฟล์นี้ให้ ใน Docker กระดานเห็นเฉพาะโฟลเดอร์ `certs/` นี้ ถ้าคัดลอกเองให้รัน installer ด้วย sudo หรือ `sudo cp /etc/netsec-board/wazuh-root-ca.pem certs/`', 'The installer copies the indexer CA (Wazuh uses a self-signed CA) to `certs/wazuh-root-ca.pem` next to `netsec.json` when it can read it, and the wizard offers that file. In Docker the board sees only this `certs/` folder; otherwise copy it yourself: `sudo cp /etc/netsec-board/wazuh-root-ca.pem certs/`.'],
      ['เลือก**อย่างใดอย่างหนึ่ง**: pull (ค่าเริ่มต้น) หรือ push ผ่าน integration (`deploy/custom-netsec-board.py`) ถ้าเปิดทั้งสองแบบ เหตุการณ์จะถูกนับซ้ำ (`check` จะเตือน)', 'Use **one of**: pull (default) or push through the integration (`deploy/custom-netsec-board.py`). With both, events count twice (`check` warns).'],
      ['Wazuh ส่ง alert เข้า indexer ผ่าน Filebeat ถ้า Filebeat หยุด กระดานจะไม่เห็น alert ใหม่', 'Alerts reach the indexer through Filebeat: if Filebeat is stopped, the board sees no new alerts.'],
    ]),
    B.note('วัดจริงกับ Wazuh 4.14.9: ดึงครบทุก alert, ไม่ซ้ำหลัง restart, alert ถึงกระดานใน 13 วินาที (pull) หรือ 1.3 วินาที (push)', 'Measured on Wazuh 4.14.9: every alert fetched, no duplicates after a restart, alert to card in 13 s (pull) or 1.3 s (push).'),
  ]),
  S('zabbix', 'ติดตั้งและตั้งค่า 4: Zabbix', 'Install and configure 4: Zabbix', [
    B.ul([
      ['สร้าง user ที่อ่านได้อย่างเดียว (User role, สิทธิ์ read บน host group ที่ต้องการ) และสร้าง API token ให้ user นั้น', 'Create a read-only user (User role, read on the host groups you want) and an API token for it.'],
      ['pull: ใส่ URL และ token ใน `sources.zabbix` ตัวช่วยตั้งค่าตรวจให้ และบอกถ้า web server ตัด header Authorization ทิ้ง', 'Pull: put the URL and token in `sources.zabbix`; the wizard checks it and tells you if the web server strips the Authorization header.'],
      ['push: สร้าง media type แบบ Webhook จาก `deploy/zabbix-media-webhook.js` ตั้งให้ **Enabled** (สร้างผ่าน API จะถูกปิดไว้) แล้วเพิ่ม action ทั้ง problem และ recovery', 'Push: create a Webhook media type from `deploy/zabbix-media-webhook.js`, make sure it is **Enabled** (one created through the API starts disabled), and add an action for problem and recovery.'],
    ]),
    B.note('วัดจริงกับ Zabbix 7.0.32: problem, recovery และการเกิดซ้ำถึงกระดานใน 3-6 วินาที ทั้ง pull และ push', 'Measured on Zabbix 7.0.32: problem, recovery and recurrence reach the board in 3-6 s, both pull and push.'),
  ]),
  S('tuning', 'ติดตั้งและตั้งค่า 5: ปรับระดับให้เข้ากับองค์กร', 'Install and configure 5: tuning severity', [
    B.p('`severityOverrides` ใน `netsec.json` จับคู่ด้วย regex บน field ที่อุปกรณ์สร้างเท่านั้น ข้อความใน log จึงสั่งกฎเหล่านี้ไม่ได้', '`severityOverrides` in `netsec.json` match regexes on device-generated fields only, so log text can never trigger them.'),
    B.pre(`"severityOverrides": [
  { "label": "config changes", "source": "fortigate", "match": { "logdesc": "^Configuration changed$" }, "severity": "high" },
  { "label": "core servers", "source": "wazuh", "match": { "agent.name": "^core-" }, "raise": 1 },
  { "label": "server VLAN", "source": "fortigate", "match": { "dstip": "cidr:10.20.0.0/16" }, "raise": 1 }
]`),
    B.ul([
      ['`severity` ตั้งระดับตายตัว (กฎแรกที่ตรงชนะ) `raise` เพิ่มระดับ (บวกกันได้, สูงสุด critical) เหตุการณ์ที่ถูกตั้งธงพยายามหลอก AI ไม่ต่ำกว่า medium', '`severity` sets a level (the first matching rule wins); `raise` adds levels (they add up, at most critical). An event flagged for manipulating the AI never goes below medium.'],
      ['ค่าอื่นที่ปรับได้: `board.rearmAfterHours` (24), `board.autoResolveAfterHours` (`{"info":24,"low":24,"medium":72}`), `board.newCardsPerMinute` (120), `sources.wazuh.perSourceCardsFrom` ("medium"), `sources.<name>.minSeverity` ("low")', 'Other knobs: `board.rearmAfterHours` (24), `board.autoResolveAfterHours` (`{"info":24,"low":24,"medium":72}`), `board.newCardsPerMinute` (120), `sources.wazuh.perSourceCardsFrom` ("medium"), `sources.<name>.minSeverity` ("low").'],
      ['หลังแก้ config รัน `node cli/board.js check` เพื่อตรวจกฎทุกข้อ', 'After editing, run `node cli/board.js check`: it validates every rule.'],
    ]),
  ]),
  S('ops', 'ติดตั้งและตั้งค่า 6: ผู้ใช้ สำรองข้อมูล และงานประจำ', 'Install and configure 6: users, backup and routine', [
    B.table([['งาน', 'Task'], ['คำสั่ง', 'Command']], [
      [['เพิ่มผู้ใช้', 'Add a user'], '`node cli/board.js user add <name> --role viewer|operator|admin`'],
      [['เปลี่ยนรหัสผ่าน', 'Change a password'], '`node cli/board.js user passwd <name>`'],
      [['ตรวจ config และการเชื่อมต่อ', 'Check config and connections'], '`node cli/board.js check`'],
      [['ทดสอบช่องทางแจ้งเตือน', 'Test a notification channel'], '`node cli/board.js test-notify <channel-name>`'],
      [['สำรองฐานข้อมูลขณะทำงาน', 'Back up the database while running'], '`node cli/board.js backup /secure/board-$(date +%F).db`'],
      [['ประวัติการใช้ AI', 'AI audit trail'], '`node cli/board.js audit-export --since 2026-11-01`'],
      [['อัปเกรด', 'Upgrade'], ['รันคำสั่งติดตั้งอีกครั้ง', 'Run the install command again']],
    ]),
    B.ul([
      ['สิทธิ์: viewer ดูอย่างเดียว, operator ปักหมุด/acknowledge/snooze/AI, admin ดู config ได้ด้วย', 'Roles: viewer reads; operator pins, acknowledges, snoozes and uses the AI; admin also sees the config.'],
      ['หลัง reverse proxy (Caddy) ตั้ง `"cookieSecure": true` และ `"trustProxy": true`', 'Behind a reverse proxy (Caddy) set `"cookieSecure": true` and `"trustProxy": true`.'],
      ['ฐานข้อมูลเก็บ IP และชื่อผู้ใช้จริง (ข้อมูลส่วนบุคคลตาม PDPA) เก็บ 30 วัน และบันทึกว่าใครดู/ทำอะไร', 'The database holds real IPs and user names (personal data under PDPA): kept 30 days, with an audit of who viewed or did what.'],
    ]),
  ]),
  S('trouble', 'แก้ปัญหา', 'Troubleshooting', [
    B.p('ทุกข้อในตารางนี้เกิดขึ้นจริงระหว่างการทดสอบกับระบบจริง', 'Every row here happened during the tests on real systems.'),
    B.table([['อาการ', 'Symptom'], ['สาเหตุ', 'Cause'], ['วิธีแก้', 'Fix']], [
      [['Wazuh: "out of heap memory (HTTP 429)"', 'Wazuh: "out of heap memory (HTTP 429)"'], ['heap ของ indexer เล็กเกินไป', 'The indexer heap is too small'], '`sudo sh lab/wazuh-heap.sh 4g`'],
      [['Wazuh: certificate / self-signed', 'Wazuh: certificate / self-signed'], ['ยังไม่ได้ตั้ง CA', 'No CA configured'], ['คัดลอก root CA ของ indexer ไปที่ `certs/wazuh-root-ca.pem` แล้วตั้ง `sources.wazuh.caFile` เป็น `certs/wazuh-root-ca.pem` (relative กับ `netsec.json`)', 'Copy the indexer root CA to `certs/wazuh-root-ca.pem` and set `sources.wazuh.caFile` to `certs/wazuh-root-ca.pem` (relative to `netsec.json`)']],
      [['Wazuh: ไม่มี alert ใหม่', 'Wazuh: no new alerts'], ['Filebeat หยุดทำงาน', 'Filebeat is stopped'], '`systemctl start filebeat` (root)'],
      [['agent ไม่ส่ง sshd', 'An agent sends no sshd events'], ['agent อ่าน journald แต่เครื่องเขียน `/var/log/auth.log`', 'The agent reads journald but the host logs to `/var/log/auth.log`'], ['เพิ่ม localfile ของ `/var/log/auth.log` ใน ossec.conf ของ agent', 'Add a `/var/log/auth.log` localfile to the agent\'s ossec.conf']],
      [['Zabbix: Not authorized', 'Zabbix: Not authorized'], ['web server ตัด header Authorization', 'The web server strips the Authorization header'], ['Apache `CGIPassAuth On` หรือ nginx `fastcgi_param HTTP_AUTHORIZATION $http_authorization;`', 'Apache `CGIPassAuth On`, or nginx `fastcgi_param HTTP_AUTHORIZATION $http_authorization;`']],
      [['Zabbix webhook ไม่มา', 'Zabbix webhook never arrives'], ['media type ถูกปิด (Media type disabled)', 'The media type is disabled'], ['เปิด media type ให้เป็น Enabled', 'Enable the media type']],
      [['"cannot listen ... already in use"', '"cannot listen ... already in use"'], ['มีโปรแกรมอื่นใช้พอร์ต 8480', 'Something else uses port 8480'], ['หยุดโปรแกรมนั้น หรือตั้ง `listen.port`', 'Stop it, or set `listen.port`']],
      [['"no admin user"', '"no admin user"'], ['ยังไม่ได้ตั้งค่า', 'Setup has not run'], '`node cli/board.js setup`'],
    ]),
  ]),
  S('limits', 'สิ่งที่ยังไม่ได้ทดสอบ', 'What is not yet verified', [
    B.ul([
      ['FortiGate จริงบน FortiOS รุ่นปัจจุบัน (ทดสอบด้วย log จริงจาก BOTSv1 ซึ่งเป็น FortiOS 5.x ปี 2016)', 'A real FortiGate on current FortiOS (tested with real BOTSv1 logs, FortiOS 5.x from 2016).'],
      ['Wazuh และ Zabbix ของ KKU เอง (ทดสอบกับ Wazuh 4.14.9 และ Zabbix 7.0.32 บน VM เดียว)', 'KKU\'s own Wazuh and Zabbix (tested with Wazuh 4.14.9 and Zabbix 7.0.32 on one VM).'],
      ['การใช้งานหลายเครื่องและปริมาณระดับองค์กร', 'Multi-node use and campus-scale volume.'],
    ]),
  ]),
];

// ---------------------------------------------------------------- render: manual
function sectionHtml(s, i) {
  return `<section id="${s.id}">
  <h2><span class="step-n">${i}</span> ${bi({ th: s.th, en: s.en })}</h2>
  ${s.blocks.map(htmlBlock).join('\n  ')}
</section>`;
}
function manualHtml() {
  const toc = `<section>
  <span class="eyebrow">NetSec Board · ${bi({ th: 'คู่มือ', en: 'manual' })}</span>
  ${bi({ th: 'คู่มือการใช้งาน NetSec Board', en: 'NetSec Board manual' }, 'h1')}
  ${bi({ th: 'สำหรับผู้ปฏิบัติงาน NOC (ใช้งานประจำวัน) และผู้ดูแลระบบ (ติดตั้ง ตั้งค่า แก้ปัญหา)', en: 'For NOC operators (daily use) and admins (install, configure, troubleshoot).' }, 'p')}
  <ul class="toc">${MANUAL.map((s, i) => `<li><a href="#${s.id}">${i}. ${bi({ th: s.th, en: s.en })}</a></li>`).join('')}</ul>
</section>`;
  const foot = `<footer>${bi({ th: `แหล่งที่มา: ${REPO} · เวอร์ชันภาษาอังกฤษแบบออฟไลน์: docs/manual.md`, en: `Source: ${REPO} · offline English copy: docs/manual.md` }, 'p')}</footer>`;
  return page({ title: 'Manual · NetSec Board', description: 'NetSec Board manual for operators and admins, in Thai and English.', sub: { th: 'คู่มือ', en: 'Manual' }, body: [toc, ...MANUAL.map((s, i) => sectionHtml(s, i)), foot].join('\n') });
}
function manualMd() {
  return [`# NetSec Board manual`, '', `Operators: sections 1-6. Admins: 7-12, then Troubleshooting. Thai/English web version: ${PAGES}/manual.html`, '',
    ...MANUAL.flatMap((s, i) => [`## ${i}. ${s.en}`, '', ...s.blocks.flatMap((b) => [mdBlock(b), ''])]),
    `---`, `Generated by scripts/build-pages.js from the same source as manual.html.`, ''].join('\n');
}

// ---------------------------------------------------------------- render: landing
function landingHtml() {
  const r = (f) => JSON.parse(fs.readFileSync(path.join(ROOT, 'results/real-data', f), 'utf8'));
  const x1 = r('x1-botsv1.json'), x3 = r('x3-wazuh-push.json'), x4 = r('x4-zabbix.json'), x5 = r('x5-llm-batch1.json'), x6 = r('x6-masking.json'), x7 = r('x7-install.json');
  const n = (v) => Number(v).toLocaleString('en-US');
  const stats = [
    [n(x1.offline.parsed), 'บรรทัด log FortiGate จริงที่ parse ได้ครบ', 'real FortiGate log lines, all parsed'],
    [`${x1.timeline.cards} / ${x1.timeline.spanDays} ${'d'}`, 'การ์ดจาก log จริง 28 วัน (ไม่ใช่หลายแสนใบ)', 'cards from 28 real days (not hundreds of thousands)'],
    [`${(x3.alertToCardMs.median / 1000).toFixed(1)} s`, 'จาก alert ของ Wazuh ถึงการ์ด (push)', 'from a Wazuh alert to its card (push)'],
    [`${x6.leaks}`, `ข้อมูลรั่วไปช่องทางคลาวด์ (การ์ดจริง ${x6.cards} ใบ)`, `leaks to cloud channels (${x6.cards} real cards)`],
    [`${Math.round(x7.installMs / 1000)} s`, 'ติดตั้งด้วยคำสั่งเดียว', 'one-command install'],
    [`${Math.round(x5.msPerCall.median / 1000)} s`, 'ต่อการ์ด สำหรับ AI ในเครื่อง (CPU)', 'per card for the local AI (CPU)'],
  ];
  const feats = [
    ['ดึงข้อมูลเอง', 'Pulls data by itself', 'FortiGate (syslog), Wazuh (indexer หรือ integration), Zabbix (API หรือ webhook) ตามตารางเวลา ไม่ต้อง import เอง', 'FortiGate (syslog), Wazuh (indexer or integration), Zabbix (API or webhook) on a schedule: no manual imports.'],
    ['กระดานที่อ่านง่าย', 'A board you can read', 'เหตุการณ์ซ้ำรวมเป็นการ์ดเดียว ปักหมุด acknowledge snooze ปิดเองเมื่อเงียบ เปิดใหม่เมื่อเกิดซ้ำ', 'Repeats become one card; pin, acknowledge, snooze; quiet cards close, recurrences re-open.'],
    ['ระดับที่ไว้ใจได้', 'Severity you can trust', 'มาจาก field ที่อุปกรณ์สร้างเท่านั้น ปรับตามองค์กรได้ (กฎ, เครื่องสำคัญ, VLAN) ข้อความใน log ลดระดับไม่ได้', 'From device fields only, tunable per site (rules, key servers, VLANs); log text can never lower it.'],
    ['AI ที่มี guard', 'AI with a guard', 'โมเดลในเครื่องอธิบายการ์ด guard ไม่ยอมให้ลดระดับ และไม่ให้ AI ปลุกทีมจากการ์ดระดับต่ำ', 'A local model explains cards; the guard never lets it lower severity or page the team from a low card.'],
    ['แจ้งเตือนอย่างระวัง', 'Careful notifications', 'ntfy, Telegram, LINE, webhook ปิดบัง IP และชื่อเครื่องก่อนส่งออกคลาวด์ มีเพดานและช่วงเงียบ', 'ntfy, Telegram, LINE, webhook; IPs and host names masked before anything leaves for the cloud; caps and quiet hours.'],
    ['ทดสอบกับของจริง', 'Tested on real systems', `Wazuh 4.14.9, Zabbix ${x4.zabbix}, log FortiGate จริง (BOTSv1, CC0), LLM ในเครื่อง`, `Wazuh 4.14.9, Zabbix ${x4.zabbix}, real FortiGate logs (BOTSv1, CC0), a local LLM.`],
  ];
  const body = `<section class="hero">
  <span class="eyebrow">KKU ODT · Network &amp; Cyber · v0.5</span>
  ${bi({ th: 'NetSec Board: กระดานเหตุการณ์ network และ security ที่ดึงข้อมูลเอง', en: 'NetSec Board: a network and security board that fetches its own data' }, 'h1')}
  ${bi({ th: 'รวม FortiGate, Wazuh และ Zabbix ไว้บนกระดานเดียว แจ้งเตือนเฉพาะเรื่องที่สำคัญ มี AI ในเครื่องช่วยอธิบาย ติดตั้งในองค์กร อ่านข้อมูลอย่างเดียว', en: 'FortiGate, Wazuh and Zabbix on one board, notifications only for what matters, a local AI that explains. Runs on-prem and only reads.' }, 'p')}
  <pre>${esc(INSTALL)}</pre>
  <div class="cta">
    <a class="primary" href="manual.html">${bi({ th: 'คู่มือ', en: 'Manual' })}</a>
    <a href="how-it-works.html">${bi({ th: 'ทำงานอย่างไร', en: 'How it works' })}</a>
    <a href="${REPO}/blob/main/results/real-data-eval.md">${bi({ th: 'ผลทดสอบกับระบบจริง', en: 'Real-system test report' })}</a>
    <a href="${REPO}/releases/latest">${bi({ th: 'ดาวน์โหลด', en: 'Release' })}</a>
    <a href="${REPO}">GitHub</a>
  </div>
</section>
<section>
  ${bi({ th: 'วัดจากระบบจริง', en: 'Measured on real systems' }, 'h2')}
  <div class="stats">${stats.map(([v, th, en]) => `<div class="stat"><b>${esc(v)}</b>${bi({ th, en })}</div>`).join('')}</div>
  <figure><img src="docs/screenshots/real-board.png" alt="NetSec Board on real data, identifiers masked" width="1440" height="1000" loading="lazy">
  <figcaption>${bi({ th: 'กระดานกับข้อมูลจริง (Wazuh บน VM นี้ ปิดบัง IP ชื่อเครื่อง ชื่อผู้ใช้แล้ว; log FortiGate จาก BOTSv1, CC0)', en: 'The board on real data (this VM\'s Wazuh, IPs, host and user names masked; FortiGate logs from BOTSv1, CC0).' })}</figcaption></figure>
</section>
<section>
  ${bi({ th: 'ทำอะไรได้', en: 'What it does' }, 'h2')}
  <div class="feat">${feats.map(([th, en, dth, den]) => `<div class="card">${bi({ th, en }, 'h3')}${bi({ th: dth, en: den }, 'p')}</div>`).join('')}</div>
</section>
<section>
  ${bi({ th: 'เดโมในเบราว์เซอร์ (v0.3)', en: 'Browser demo (v0.3)' }, 'h2')}
  ${bi({ th: 'ตรวจ config FortiGate เทียบ ISO/IEC 27001:2022 และห้องทดลอง log injection ทำงานในเบราว์เซอร์ทั้งหมด ข้อมูลสังเคราะห์', en: 'FortiGate config review against ISO/IEC 27001:2022 and a log-injection lab, running entirely in your browser on synthetic data.' }, 'p')}
  <div class="cta"><a href="demo.html">${bi({ th: 'เปิดเดโม', en: 'Open the demo' })}</a></div>
</section>
<footer>${bi({ th: `โอเพนซอร์ส (MIT) · ${REPO}`, en: `Open source (MIT) · ${REPO}` }, 'p')}</footer>`;
  return page({ title: 'NetSec Board', description: 'Self-hosted network and security board: FortiGate, Wazuh, Zabbix, a guarded local LLM. Thai and English.', sub: { th: 'กระดานเหตุการณ์ network และ security', en: 'Network and security board' }, body, imgSelf: true });
}

// ---------------------------------------------------------------- write
fs.writeFileSync(path.join(ROOT, 'manual.html'), manualHtml());
fs.mkdirSync(path.join(ROOT, 'docs'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'docs/manual.md'), manualMd());
fs.writeFileSync(path.join(ROOT, 'index.html'), landingHtml());
console.log(`manual.html (${MANUAL.length} sections), docs/manual.md, index.html`);
