// Flag history + teaching content.
// - LESSONS: for every warning sign the analyzer can raise, a plain-language "how to spot it yourself" lesson.
// - buildRecord / mergeRecord: turn an analysis result into a small history record kept on this device.
//   Records hold the sender, subject, score, risky links and the reasons (with the short phrases that matched).
//   They never hold the email body or its summary.
// Used by the content script (to save records) and by popup/history.html (to review and learn from them).
(function (root) {
  'use strict';

  const MAX_RECORDS = 300;
  const STORAGE_KEY = 'flagHistory';

  // topic: groups lessons on the review page. skill: the short name used in the quiz.
  // spot: how to check for this yourself. fake/real: optional side-by-side example.
  const LESSONS = {
    // ----- known threats -----
    'known-bad-link': { topic: 'Known threats', skill: 'A link goes to a known scam or malware site',
      spot: 'You can\'t see this one by eye: the site is on a public list of confirmed attacks. That is why it is worth keeping a checker like Tripwire on, and why you should never "just have a look" at a link you don\'t trust.' },
    'known-bad-sender': { topic: 'Known threats', skill: 'The sender is on a known scam list',
      spot: 'The sender\'s domain (the part after the @) has already been used in attacks. Look at the full address every time, not only the name shown in your inbox.' },

    // ----- sender -----
    'lookalike-sender': { topic: 'Sender', skill: 'Look-alike sender address',
      spot: 'Read the domain after the @ letter by letter. Scammers swap "l" for "1", "o" for "0", "m" for "rn", or add words like "-secure" or "-support".',
      fake: 'service@paypa1-security.com', real: 'service@paypal.com' },
    'brand-freemail': { topic: 'Sender', skill: 'A company name sent from a free email account',
      spot: 'Big companies send from their own domain. "PayPal" or "Microsoft Support" writing from @gmail.com, @outlook.com or @yahoo.com is always fake.',
      fake: 'Microsoft 365 Support <it.helpdesk.office365@gmail.com>', real: 'Microsoft <account-security-noreply@accountprotection.microsoft.com>' },
    'brand-mismatch': { topic: 'Sender', skill: 'The sender name and address don\'t match',
      spot: 'Anyone can type any display name. Click or hover the name to see the real address, and check that its domain belongs to the company named.',
      fake: 'Chase Security <alerts@secure-notice.net>', real: 'Chase <no.reply.alerts@chase.com>' },
    'name-email-mismatch': { topic: 'Sender', skill: 'A fake address written in the sender name',
      spot: 'If the display name itself looks like an email address, it is a costume. The real address is the one in <angle brackets>, and it is different.',
      fake: '"support@paypal.com" <x83@mailer.ru>', real: 'PayPal <service@paypal.com>' },
    'unicode-sender': { topic: 'Sender', skill: 'Foreign look-alike letters in the sender address',
      spot: 'Some alphabets have letters that look exactly like English ones (Cyrillic "а" vs Latin "a"). If an address looks normal but Tripwire flags it, trust the check, not your eyes.' },
    'org-freemail': { topic: 'Sender', skill: 'A "department" writing from a personal account',
      spot: 'IT, HR, payroll and billing teams use the organisation\'s own email. "IT Support" from a Gmail address is a classic way to steal work passwords.' },
    'tld-sender': { topic: 'Sender', skill: 'Unusual ending on the sender address',
      spot: 'Endings like .top, .xyz, .click or .zip cost almost nothing, so scammers use them. Not proof on its own, but a reason to look closer.' },

    // ----- links -----
    'mismatch-link': { topic: 'Links', skill: 'The link text lies about where it goes',
      spot: 'Hover over a link (don\'t click) and look at the address your browser shows at the bottom of the window. If it differs from the text, it\'s a trick.',
      fake: 'Text "www.paypal.com" → goes to 198.51.100.23/secure', real: 'Text "www.paypal.com" → goes to www.paypal.com' },
    'brand-text-link': { topic: 'Links', skill: 'A "Log in to <brand>" button that goes somewhere else',
      spot: 'Buttons hide their address. Hover them first. A "Sign in to Microsoft" button should lead to a microsoft.com address, nothing else.' },
    'lookalike-link': { topic: 'Links', skill: 'A link to a fake copy of a real website',
      spot: 'The part of the address that matters is the end, just before the first "/". In "paypal.com.account-check.ru" the real site is account-check.ru.',
      fake: 'https://paypal.com.secure-login.ru/', real: 'https://www.paypal.com/' },
    'ip-link': { topic: 'Links', skill: 'A link to a number instead of a website name',
      spot: 'Real companies link to names like amazon.com, not to numbers like 203.0.113.50. A number address hides who runs the server.' },
    'punycode-link': { topic: 'Links', skill: 'Disguised characters in a link',
      spot: 'An address containing "xn--" is written in foreign characters and may display as a perfect copy of a real name. Type the company\'s address yourself instead.' },
    'at-link': { topic: 'Links', skill: 'An "@" trick in a link',
      spot: 'Browsers ignore everything before an "@" in a web address. "https://paypal.com@evil.example" really goes to evil.example.' },
    'short-link': { topic: 'Links', skill: 'A shortened link that hides the destination',
      spot: 'bit.ly, tinyurl and similar links hide where they go. Companies sending account warnings don\'t need them. Be extra careful with these.' },
    'tld-link': { topic: 'Links', skill: 'Unusual ending on a link address',
      spot: 'Cheap endings (.top, .xyz, .click…) show up a lot in scams. Combined with a login or payment request, treat it as a red flag.' },
    'http-link': { topic: 'Links', skill: 'A link without https',
      spot: 'Any page asking for a password or card number must start with https://. Plain http:// means anyone on the network could read what you type.' },
    'port-link': { topic: 'Links', skill: 'A link to an unusual port',
      spot: 'A ":8080" or similar number after the site name is unusual for normal websites and often points to a hacked or temporary server.' },
    'deep-link': { topic: 'Links', skill: 'A very long, layered web address',
      spot: 'Long addresses with many dots bury the real site name in the middle. Read the address from the right: the last two parts are who owns it.' },
    'js-link': { topic: 'Links', skill: 'A link that runs code',
      spot: 'A real email link opens a web page. A "javascript:" link runs code instead. There is never a good reason for one in an email.' },
    'data-link': { topic: 'Links', skill: 'A link with a whole page hidden inside it',
      spot: '"data:" links carry an entire fake page inside them, often a login form, so no website address shows at all. Never type passwords into one.' },
    form: { topic: 'Links', skill: 'A sign-in form inside the email',
      spot: 'Legitimate services never ask you to type a password into the email itself. Go to the website directly if you need to sign in.' },

    // ----- wording -----
    'content-urgency': { topic: 'Wording', skill: 'Pressure to act fast',
      spot: '"Within 24 hours", "immediately", "final notice": a deadline is there so you don\'t stop to think. A real company will still be there tomorrow.' },
    'content-fear': { topic: 'Wording', skill: 'Threats and scary warnings',
      spot: 'Account suspension, legal action, "unusual activity": fear makes people click. Check your account by opening the app or typing the address yourself.' },
    'content-credentials': { topic: 'Wording', skill: 'Asks for a password, code or ID',
      spot: 'No real company asks you to confirm a password, a one-time code or an ID number by email. Ever. A request like this is the scam.' },
    'content-financial': { topic: 'Wording', skill: 'Asks for money or payment details',
      spot: 'Unexpected invoices, small "delivery fees", wire transfers and gift cards are top fraud tricks. Confirm any payment request through a channel you already trust.' },
    'content-prize': { topic: 'Wording', skill: 'A prize, refund or windfall',
      spot: 'You can\'t win a contest you never entered. "Claim your reward" and surprise refunds are bait to collect your details.' },
    'content-greeting': { topic: 'Wording', skill: 'A generic greeting',
      spot: '"Dear Customer" or "Dear User" means the sender doesn\'t know your name, which suggests a mass message. Your bank usually uses your name.' },
    'content-secrecy': { topic: 'Wording', skill: 'Secrecy or a "quick favour"',
      spot: 'A boss or friend who suddenly needs gift cards, "can\'t talk right now" and asks you to keep it quiet is the classic CEO-fraud script. Call them on a known number.' },
    'risky-attachment': { topic: 'Wording', skill: 'A dangerous file type',
      spot: 'Files ending in .exe, .scr, .js, .iso, .html or macro-enabled Office files (.docm, .xlsm) can install malware. Don\'t open attachments you weren\'t expecting.' },
    'brand-impersonation': { topic: 'Wording', skill: 'Talks about a brand that didn\'t send it',
      spot: 'The email says it\'s about your PayPal (or Apple, or bank) account, but neither the sender nor the links belong to that company.' },
    'combo-pressure-ask': { topic: 'Wording', skill: 'Pressure combined with a sensitive request',
      spot: 'Pressure plus a request for information or money is the core phishing recipe. When you see both together, stop and verify through another channel.' },
  };

  const TOPIC_ORDER = ['Known threats', 'Sender', 'Links', 'Wording'];
  const GENERIC_LESSON = { topic: 'Other', skill: 'Other warning sign', spot: 'Read the explanation above, and when unsure, contact the company through its official app or website.' };

  function lessonFor(signalId) { return LESSONS[signalId] || GENERIC_LESSON; }

  const clip = (s, n) => { s = (s == null ? '' : String(s)).replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1) + '…' : s; };

  // Build a history record from an analyzer result. Deliberately leaves out the email body and summary.
  // meta: { key, subject, site, provider, partial, now }
  function buildRecord(result, meta) {
    const now = meta.now || Date.now();
    const sender = result.sender || {};
    return {
      key: meta.key,
      level: result.level,
      high: !!result.high,
      known: !!result.known,
      score: result.score,
      threatCategory: result.threatCategory || null,
      verifiedBrand: result.verifiedBrand || null,
      partial: !!meta.partial, // true = seen in the inbox list only, never opened
      sender: { name: clip(sender.name, 120), email: clip(sender.email, 200), domain: clip(sender.domain, 200) },
      subject: clip(meta.subject, 200),
      site: clip(meta.site, 120),
      provider: clip(meta.provider, 60),
      signals: (result.signals || []).filter((x) => x.weight > 0).slice(0, 12).map((x) => ({
        id: x.id, category: x.category, weight: x.weight, title: clip(x.title, 160), explain: clip(x.explain, 500),
        evidence: clip(x.evidence, 200), threatCategory: x.threatCategory || null })),
      links: (result.riskyLinks || []).slice(0, 6).map((l) => ({
        text: clip(l.text, 100), host: clip(l.host, 200), dest: clip(l.finalHref || l.href, 300), weight: l.weight, known: !!l.known })),
      asks: (result.asks || []).slice(0, 8),
      firstSeen: now,
      lastSeen: now,
      reviewed: false,
    };
  }

  const LEVEL_RANK = { safe: 0, suspicious: 1, phishing: 2 };

  // Combine a new sighting with what is already stored for the same email.
  function mergeRecord(old, rec) {
    if (!old) return rec;
    // A quick inbox-list check never replaces a full check of the opened email.
    if (rec.partial && !old.partial) return Object.assign({}, old, { lastSeen: rec.lastSeen });
    const worse = (LEVEL_RANK[rec.level] || 0) > (LEVEL_RANK[old.level] || 0);
    return Object.assign({}, rec, { firstSeen: old.firstSeen, reviewed: worse ? false : old.reviewed });
  }

  // Merge many new records into a stored list; newest first, capped.
  function mergeInto(list, recs) {
    const byKey = new Map((list || []).map((r) => [r.key, r]));
    for (const r of recs) byKey.set(r.key, mergeRecord(byKey.get(r.key), r));
    return [...byKey.values()].sort((a, b) => b.lastSeen - a.lastSeen).slice(0, MAX_RECORDS);
  }

  // Quiz: the real warning signs of a record plus a few that were NOT present.
  // Returns [{ id, skill, correct }] in shuffled order. rand is injectable for tests.
  function quizOptions(record, rand) {
    rand = rand || Math.random;
    // Known-threat hits can't be spotted by eye, so they are never quiz answers.
    const present = [...new Set((record.signals || []).map((s) => s.id))].filter((id) => LESSONS[id] && LESSONS[id].topic !== 'Known threats');
    const presentSkills = new Set(present.map((id) => LESSONS[id].skill));
    const others = Object.keys(LESSONS).filter((id) => !present.includes(id) && !presentSkills.has(LESSONS[id].skill)
      && LESSONS[id].topic !== 'Known threats');
    const shuffle = (arr) => { arr = arr.slice(); for (let i = arr.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [arr[i], arr[j]] = [arr[j], arr[i]]; } return arr; };
    const distractors = shuffle(others).slice(0, Math.max(3, Math.min(5, present.length + 1)));
    return shuffle([...present.map((id) => ({ id, skill: LESSONS[id].skill, correct: true })),
      ...distractors.map((id) => ({ id, skill: LESSONS[id].skill, correct: false }))]);
  }

  root.PG_Lessons = { LESSONS, TOPIC_ORDER, MAX_RECORDS, STORAGE_KEY, lessonFor, buildRecord, mergeRecord, mergeInto, quizOptions };
})(typeof globalThis !== 'undefined' ? globalThis : this);
