// Flagged email review page: lists past flagged emails, explains each warning sign as a lesson, and quizzes the user.
// Everything is read from chrome.storage.local on this device. Email content is never shown as clickable links.
(function () {
  'use strict';
  const L = window.PG_Lessons, A = window.PG_Analyzer, D = window.PG_DATA;
  const KEY = L.STORAGE_KEY;
  const $ = (id) => document.getElementById(id);

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) if (c != null && c !== false) el.append(c.nodeType ? c : document.createTextNode(String(c)));
    return el;
  }

  const view = { records: [], trusted: [], blocked: [], filter: 'all', query: '', trick: null, selected: null, tab: 'explain', quiz: null };

  const VERDICT = {
    phishing: { title: 'Known phishing — confirmed scam', sub: 'The sender or a link was on a list of confirmed phishing attacks.' },
    malware: { title: 'Known malware — dangerous link', sub: 'A link was on a list of sites that spread viruses or ransomware.' },
    c2: { title: 'Known hacker server', sub: 'The email pointed to a server criminals use to control hacked computers.' },
    reported: { title: 'You reported this as phishing', sub: 'You reported this sender or site earlier on this computer.' },
    high: { title: 'Very suspicious — strong signs of phishing', sub: 'Not on a known-scam list, but it had serious warning signs.' },
    suspicious: { title: 'Suspicious', sub: 'It had warning signs, but wasn\'t a confirmed scam.' },
  };
  const verdictOf = (r) => r.known ? (VERDICT[r.threatCategory] || VERDICT.phishing) : r.high ? VERDICT.high : VERDICT.suspicious;
  const shortLabel = (r) => r.known ? 'Known ' + (r.threatCategory === 'c2' ? 'C2' : r.threatCategory === 'reported' ? 'reported' : (r.threatCategory || 'phishing'))
    : r.high ? 'Very suspicious' : 'Suspicious';
  const fmtDate = (t) => { try { return new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); } catch (e) { return ''; } };
  const who = (r) => r.sender.name || r.sender.email || '(unknown sender)';

  const TIPS = {
    phishing: ['Don\'t click links, open attachments or reply to emails like this.', 'Report it to your email provider, then delete it.',
      'Already clicked or typed a password? Change that password now, and contact the company through its official website.'],
    suspicious: ['Hover over links before clicking to see where they really go.', 'Check the full sender address, not only the name.',
      'Not expecting it? Confirm with the sender another way: phone them or use their official website.'],
  };

  // ---------- storage ----------
  async function load() {
    const s = await chrome.storage.local.get([KEY, 'trusted', 'blocked']);
    view.records = s[KEY] || [];
    view.trusted = s.trusted || [];
    view.blocked = s.blocked || [];
    if (view.selected && !view.records.some((r) => r.key === view.selected)) view.selected = null;
    render();
  }
  async function updateRecords(fn) {
    const s = await chrome.storage.local.get([KEY]);
    const next = fn(s[KEY] || []);
    await chrome.storage.local.set({ [KEY]: next });
    view.records = next;
  }
  async function markReviewed(key) {
    const r = view.records.find((x) => x.key === key);
    if (!r || r.reviewed) return;
    r.reviewed = true; // show it straight away, then save
    await updateRecords((list) => list.map((x) => x.key === key ? Object.assign({}, x, { reviewed: true }) : x));
    renderStats(); renderList();
  }
  async function editList(name, value, add) {
    const s = await chrome.storage.local.get([name]);
    const set = new Set(s[name] || []);
    add ? set.add(value.toLowerCase()) : set.delete(value.toLowerCase());
    await chrome.storage.local.set({ [name]: [...set] });
  }

  // ---------- filtering ----------
  function visible() {
    const q = view.query.trim().toLowerCase();
    return view.records.filter((r) => {
      if (view.filter === 'new' && r.reviewed) return false;
      if (view.filter === 'phishing' && r.level !== 'phishing') return false;
      if (view.filter === 'suspicious' && r.level !== 'suspicious') return false;
      if (view.trick && !r.signals.some((s) => s.id === view.trick)) return false;
      if (q && !(r.sender.name + ' ' + r.sender.email + ' ' + r.subject).toLowerCase().includes(q)) return false;
      return true;
    });
  }

  // ---------- render ----------
  function render() { renderStats(); renderList(); renderDetail(); }

  function renderStats() {
    const rs = view.records;
    const box = $('stats'); box.textContent = '';
    const stat = (cls, n, label) => h('div', { class: 'stat ' + cls }, h('b', {}, n), h('span', {}, label));
    box.append(stat('', rs.length, 'flagged emails'), stat('r', rs.filter((r) => r.level === 'phishing').length, 'known phishing'),
      stat('y', rs.filter((r) => r.level === 'suspicious').length, 'suspicious'), stat('n', rs.filter((r) => !r.reviewed).length, 'not reviewed yet'));
    $('clearAll').disabled = !rs.length;
  }

  function renderList() {
    const ul = $('list'); ul.textContent = '';
    const tf = $('trickFilter');
    tf.hidden = !view.trick; tf.textContent = '';
    if (view.trick) tf.append(h('span', {}, 'Showing emails with: ', h('b', {}, L.lessonFor(view.trick).skill)),
      h('button', { onclick: () => { view.trick = null; renderList(); } }, 'Show all'));
    const rs = visible();
    if (!rs.length) {
      ul.append(h('li', { class: 'empty' }, view.records.length ? 'No flagged emails match this filter.'
        : 'Nothing here yet. When Tripwire flags an email in your inbox, it shows up here so you can review it.'));
      return;
    }
    for (const r of rs) {
      ul.append(h('li', {}, h('button', { class: 'item' + (r.key === view.selected ? ' sel' : ''), onclick: () => select(r.key) },
        h('span', { class: 'bar ' + r.level }),
        h('span', {},
          h('div', { class: 'who' }, r.reviewed ? null : h('span', { class: 'dotnew', title: 'Not reviewed yet' }), who(r)),
          h('div', { class: 'subj' }, r.subject || '(no subject)'),
          h('div', { class: 'meta' }, `${shortLabel(r)} · ${fmtDate(r.lastSeen)}`)),
        h('span', { class: 'sc ' + r.level, title: 'Safety score: 0 = confirmed phishing, 100 = safe' }, r.score))));
    }
  }

  function select(key) {
    view.selected = key; view.tab = 'explain'; view.quiz = null;
    renderList(); renderDetail();
    markReviewed(key);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function renderDetail() {
    const box = $('detail'); box.textContent = '';
    const r = view.records.find((x) => x.key === view.selected);
    if (!r) { box.append(overview()); return; }
    const v = verdictOf(r);
    const marker = h('div', { class: 'marker' }); marker.style.left = r.score + '%';
    const facts = h('dl', { class: 'facts' },
      h('dt', {}, 'From'), h('dd', {}, r.sender.name ? r.sender.name + ' ' : '', h('code', {}, r.sender.email ? `<${r.sender.email}>` : '(address not shown)')),
      h('dt', {}, 'Subject'), h('dd', {}, r.subject || '(no subject)'),
      h('dt', {}, 'Seen'), h('dd', {}, fmtDate(r.firstSeen) + (r.lastSeen - r.firstSeen > 60000 ? ` (last ${fmtDate(r.lastSeen)})` : '') +
        (r.provider || r.site ? ` in ${r.provider || r.site}` : '')));
    const card = h('div', { class: 'card verdict ' + r.level },
      h('div', { class: 'vhead' }, h('div', { class: 't' }, h('h2', {}, v.title), h('p', {}, v.sub)),
        h('div', { class: 'num' }, r.score, h('small', {}, 'safety / 100'))),
      h('div', { class: 'meter' }, marker),
      h('div', { class: 'scale' }, h('span', {}, '0 · Phishing'), h('span', {}, 'Suspicious'), h('span', {}, 'Safe · 100')),
      facts,
      r.partial ? h('p', { class: 'note' }, 'Tripwire only saw this email in your inbox list (sender, subject and preview). Open it in your inbox to get the full check with links, and the review here will update.') : null,
      actions(r));
    box.append(card);

    const tabs = h('div', { class: 'tabs', role: 'tablist' },
      h('button', { class: 'tab' + (view.tab === 'explain' ? ' on' : ''), role: 'tab', onclick: () => { view.tab = 'explain'; renderDetail(); } }, 'Why it was flagged'),
      h('button', { class: 'tab' + (view.tab === 'quiz' ? ' on' : ''), role: 'tab', onclick: () => { view.tab = 'quiz'; renderDetail(); } }, 'Test yourself'));
    box.append(tabs, view.tab === 'quiz' ? quiz(r) : explain(r));
  }

  function actions(r) {
    const bar = h('div', { class: 'actions' });
    const email = r.sender.email;
    const isBlocked = email && (view.blocked.includes(email) || view.blocked.includes(A.registrableDomain(r.sender.domain)));
    if (email && !isBlocked && r.threatCategory !== 'reported') {
      bar.append(h('button', { class: 'btn', onclick: async () => {
        const reg = A.registrableDomain(r.sender.domain);
        const shared = !!r.verifiedBrand || D.FREE_MAIL.includes(reg);
        await editList('blocked', shared ? email : reg, true); // whole fake domain, but only the address on gmail.com etc.
        await editList('trusted', email, false);
      } }, 'Block this sender'));
    }
    if (email && !r.known) {
      bar.append(h('button', { class: 'btn ghost', onclick: async () => {
        if (!confirm(`Only do this if you are sure ${email} is someone you know.\n\nScammers often copy the names of people and companies you know. Trust this sender and remove the email from your history?`)) return;
        await editList('trusted', email, true);
        await updateRecords((list) => list.filter((x) => x.key !== r.key));
        view.selected = null; render();
      } }, 'I know this sender (not phishing)'));
    }
    bar.append(h('button', { class: 'btn danger', onclick: async () => {
      await updateRecords((list) => list.filter((x) => x.key !== r.key));
      view.selected = null; render();
    } }, 'Delete from history'));
    return bar;
  }

  function lessonCard(s) {
    const l = L.lessonFor(s.id);
    const known = s.category === 'known';
    const card = h('div', { class: 'lesson' + (known ? ' known' : '') },
      h('div', { class: 'lh' }, h('b', {}, s.title), h('span', { class: 'badge' + (known ? ' known' : ''), title: known ? 'Confirmed by a threat list' : 'How much this sign lowered the safety score before caps' },
        known ? 'Confirmed' : `−${s.weight} pts`)),
      h('p', {}, s.explain),
      s.evidence ? h('div', { class: 'saw' }, 'What Tripwire saw: ', h('span', { class: 'ev' }, s.evidence)) : null,
      h('div', { class: 'spot' }, h('b', {}, 'How to spot it yourself: '), l.spot));
    if (l.fake) card.append(h('div', { class: 'ex' }, h('span', { class: 'fk' }, 'Fake'), h('code', {}, l.fake), h('span', { class: 'rl' }, 'Real'), h('code', {}, l.real)));
    return card;
  }

  function explain(r) {
    const wrap = h('div', {});
    const n = r.signals.length;
    wrap.append(h('p', {}, n ? `Tripwire found ${n} warning sign${n === 1 ? '' : 's'} in this email. Here is each one, what it means, and how you can catch it yourself next time.`
      : 'No details were saved for this email.'));
    const groups = new Map();
    for (const s of r.signals) { const t = L.lessonFor(s.id).topic; if (!groups.has(t)) groups.set(t, []); groups.get(t).push(s); }
    const order = [...L.TOPIC_ORDER, ...[...groups.keys()].filter((t) => !L.TOPIC_ORDER.includes(t))];
    for (const t of order) {
      if (!groups.has(t)) continue;
      wrap.append(h('h3', {}, t === 'Known threats' ? 'Confirmed threats' : t === 'Wording' ? 'The wording' : t === 'Links' ? 'The links' : t === 'Sender' ? 'The sender' : t));
      groups.get(t).forEach((s) => wrap.append(lessonCard(s)));
    }
    if (r.links.length) {
      wrap.append(h('h3', {}, 'Risky links in this email'),
        h('table', { class: 'links' }, h('thead', {}, h('tr', {}, h('th', {}, 'The link said'), h('th', {}, 'It really went to'))),
          h('tbody', {}, r.links.map((l) => h('tr', {}, h('td', {}, l.text || '(no text)'), h('td', {}, h('code', {}, l.host || l.dest)))))),
        h('p', { class: 'muted' }, 'Shown as text only, so they can\'t be opened from here.'));
    }
    if (r.asks.length) wrap.append(h('h3', {}, 'What it wanted you to do'), h('ul', { class: 'plain' }, r.asks.map((a) => h('li', {}, a))));
    wrap.append(h('h3', {}, 'What to do with emails like this'), h('ul', { class: 'plain' }, TIPS[r.level === 'phishing' || r.high ? 'phishing' : 'suspicious'].map((t) => h('li', {}, t))));
    return wrap;
  }

  function quiz(r) {
    const wrap = h('div', { class: 'quiz' });
    const real = r.signals.filter((s) => L.LESSONS[s.id] && L.lessonFor(s.id).topic !== 'Known threats');
    if (!real.length) {
      wrap.append(h('p', {}, r.known ? 'This email was caught because the sender or a link was already on a list of confirmed attacks, so there is nothing to spot by eye. Switch to "Why it was flagged" for the details.'
        : 'There aren\'t enough details saved for a quiz on this email.'));
      return wrap;
    }
    if (!view.quiz || view.quiz.key !== r.key) view.quiz = { key: r.key, options: L.quizOptions(r), checked: false, picked: new Set() };
    const q = view.quiz;
    wrap.append(h('div', { class: 'clue' },
      h('p', {}, h('b', {}, 'From: '), r.sender.name ? r.sender.name + ' ' : '', h('code', {}, r.sender.email ? `<${r.sender.email}>` : '(address not shown)')),
      h('p', {}, h('b', {}, 'Subject: '), r.subject || '(no subject)'),
      r.links.length ? h('div', {}, h('b', {}, 'Links: '), h('ul', { class: 'plain' }, r.links.map((l) => h('li', {}, `"${l.text || 'link'}" → `, h('code', {}, l.host || l.dest))))) : null,
      real.some((s) => s.evidence && s.category !== 'link' && s.category !== 'sender')
        ? h('p', {}, h('b', {}, 'Wording used: '), real.filter((s) => s.evidence && s.category !== 'link' && s.category !== 'sender').map((s) => s.evidence).join(', ')) : null));
    wrap.append(h('p', {}, h('b', {}, 'Which of these warning signs does this email have? '), 'Tick every one you can find, then check your answers.'));
    const ids = new Set(real.map((s) => s.id));
    for (const o of q.options) {
      const correct = ids.has(o.id);
      const box = h('input', { type: 'checkbox', disabled: q.checked, onchange: (e) => { e.target.checked ? q.picked.add(o.id) : q.picked.delete(o.id); } });
      box.checked = q.picked.has(o.id);
      let cls = '', why = null;
      if (q.checked) {
        if (correct && q.picked.has(o.id)) { cls = ' right'; why = '✓ Yes, you spotted it.'; }
        else if (correct) { cls = ' missed'; why = '! You missed this one: ' + L.lessonFor(o.id).spot; }
        else if (q.picked.has(o.id)) { cls = ' wrong'; why = '✕ Not in this email.'; }
      }
      wrap.append(h('label', { class: 'opt' + cls }, box, h('span', {}, o.skill, why ? h('span', { class: 'why' }, why) : null)));
    }
    if (!q.checked) {
      wrap.append(h('button', { class: 'btn', onclick: () => { q.checked = true; renderDetail(); } }, 'Check my answers'));
    } else {
      const found = real.filter((s) => q.picked.has(s.id)).length;
      const wrong = [...q.picked].filter((id) => !ids.has(id)).length;
      const total = ids.size;
      const msg = found === total && !wrong ? 'Perfect. You caught every warning sign.'
        : found === total ? 'You caught them all, but also ticked some that weren\'t there. Look again at the ones marked in red.'
        : found ? 'Good start. Read the ones you missed above, then try another email.' : 'These are easy to miss. Read the tips above for each one.';
      wrap.append(h('div', { class: 'result' }, h('b', {}, `${found} of ${total}`), ' warning signs spotted', wrong ? ` · ${wrong} false alarm${wrong === 1 ? '' : 's'}` : '', h('br'), msg),
        h('div', { class: 'actions', style: 'padding-left:0;border:0' },
          h('button', { class: 'btn', onclick: () => { view.tab = 'explain'; renderDetail(); } }, 'See the full explanation'),
          h('button', { class: 'btn ghost', onclick: () => { view.quiz = null; renderDetail(); } }, 'Try again'),
          nextUnreviewed(r) ? h('button', { class: 'btn ghost', onclick: () => { select(nextUnreviewed(r).key); view.tab = 'quiz'; renderDetail(); } }, 'Quiz me on the next email') : null));
    }
    return wrap;
  }
  function nextUnreviewed(r) {
    const quizzable = (x) => x.key !== r.key && x.signals.some((s) => L.LESSONS[s.id] && L.lessonFor(s.id).topic !== 'Known threats');
    return view.records.find((x) => !x.reviewed && quizzable(x)) || view.records.find(quizzable);
  }

  // Shown when no email is selected: the tricks seen most, and the full lesson library.
  function overview() {
    const wrap = h('div', {});
    const counts = new Map();
    for (const r of view.records) for (const id of new Set(r.signals.map((s) => s.id))) counts.set(id, (counts.get(id) || 0) + 1);
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
    const card = h('div', { class: 'card pad' }, h('h2', { style: 'margin:0 0 4px;font-size:18px' }, 'The tricks used on you'));
    if (!top.length) {
      card.append(h('p', { class: 'muted' }, 'Once Tripwire flags some emails, this shows which tricks scammers use on you most. Until then, the lessons below cover every warning sign Tripwire checks for.'));
    } else {
      card.append(h('p', { class: 'muted' }, 'The warning signs that showed up most in your flagged emails. Click one to see those emails, or pick an email on the left to review it.'));
      const max = top[0][1];
      for (const [id, n] of top) {
        const bar = h('span', { class: 'tb' }); bar.style.width = Math.max(8, Math.round((n / max) * 100)) + '%';
        card.append(h('button', { class: 'trick', onclick: () => { view.trick = id; renderList(); } },
          h('span', {}, L.lessonFor(id).skill), h('span', {}, bar), h('span', { class: 'tc' }, n)));
      }
    }
    wrap.append(card, h('h3', {}, 'Lesson library: every warning sign Tripwire checks'));
    for (const t of L.TOPIC_ORDER) {
      const ids = Object.keys(L.LESSONS).filter((id) => L.LESSONS[id].topic === t);
      const d = h('details', { class: 'lib' }, h('summary', {}, `${t} (${ids.length})`));
      for (const id of ids) {
        const l = L.LESSONS[id];
        const c = h('div', { class: 'lesson' }, h('div', { class: 'lh' }, h('b', {}, l.skill)), h('div', { class: 'spot' }, h('b', {}, 'How to spot it: '), l.spot));
        if (l.fake) c.append(h('div', { class: 'ex' }, h('span', { class: 'fk' }, 'Fake'), h('code', {}, l.fake), h('span', { class: 'rl' }, 'Real'), h('code', {}, l.real)));
        d.append(c);
      }
      wrap.append(d);
    }
    return wrap;
  }

  // ---------- events ----------
  document.querySelectorAll('[data-filter]').forEach((b) => b.addEventListener('click', () => {
    view.filter = b.dataset.filter;
    document.querySelectorAll('[data-filter]').forEach((x) => x.classList.toggle('on', x === b));
    renderList();
  }));
  $('search').addEventListener('input', (e) => { view.query = e.target.value; renderList(); });
  $('clearAll').addEventListener('click', async () => {
    if (!confirm(`Delete all ${view.records.length} emails from your review history?\n\nThis doesn't change your blocked or trusted senders.`)) return;
    await chrome.storage.local.set({ [KEY]: [] });
    view.selected = null; load();
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && (changes[KEY] || changes.trusted || changes.blocked)) load();
  });
  load();
})();
