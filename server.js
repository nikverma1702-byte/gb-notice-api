// Gram Bharti College portal + VKSU result lookup proxy.
// Students enter Registration No + DOB on OUR site; this server asks vksuexams.com
// on their behalf and sends the result / marksheet back. Nothing is saved to disk or logged.
const express = require('express');
const cheerio = require('cheerio');
const path = require('path');
const crypto = require('crypto');

const BASE = 'https://vksuexams.com/';
const PAGE = BASE + 'results.aspx';
const UA = 'Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36';

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2kb' }));

/* ---------- tiny cookie jar + fetch helper ---------- */
class Jar {
  constructor() { this.c = {}; }
  add(res) {
    const list = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const s of list) {
      const kv = s.split(';')[0], i = kv.indexOf('=');
      if (i > 0) this.c[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
    }
  }
  header() { return Object.entries(this.c).map(([k, v]) => k + '=' + v).join('; '); }
}

async function req(url, jar, opt = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 25000);
  try {
    let method = opt.method || 'GET', body = opt.body, extra = opt.headers || {};
    for (let hop = 0; hop < 5; hop++) {
      if (new URL(url).hostname !== 'vksuexams.com') throw new Error('Blocked host');
      const r = await fetch(url, {
        method, body, redirect: 'manual', signal: ctl.signal,
        headers: { 'User-Agent': UA, Accept: '*/*', Cookie: jar.header(), ...extra }
      });
      jar.add(r);
      if ([301, 302, 303, 307, 308].includes(r.status) && r.headers.get('location')) {
        url = new URL(r.headers.get('location'), url).href;
        if (r.status !== 307 && r.status !== 308) { method = 'GET'; body = undefined; extra = {}; }
        continue;
      }
      return r;
    }
    throw new Error('Too many redirects');
  } finally { clearTimeout(timer); }
}

/* ---------- read the ASP.NET form ---------- */
function readForm($) {
  const f = $('form').first();
  const hidden = {}, texts = [];
  f.find('input').each((_, el) => {
    const t = ($(el).attr('type') || 'text').toLowerCase(), n = $(el).attr('name');
    if (!n) return;
    if (t === 'hidden') hidden[n] = $(el).attr('value') || '';
    else if (['text', 'tel', 'date', 'number', 'search'].includes(t)) texts.push(el);
  });
  const idn = el => ($(el).attr('name') || '') + ' ' + ($(el).attr('id') || '') + ' ' + ($(el).attr('placeholder') || '');
  const reg = texts.find(el => /reg/i.test(idn(el))) || texts[0];
  const dob = texts.find(el => el !== reg && /dob|birth|date/i.test(idn(el))) || texts.find(el => el !== reg);
  const btns = f.find('input[type=submit],input[type=button],input[type=image],button').toArray();
  const label = el => ($(el).attr('value') || '') + ' ' + $(el).text() + ' ' + idn(el);
  const btn = btns.find(el => /search|submit|result|show|view|get|go/i.test(label(el))) || btns[0];
  const captcha = $('[id*=aptcha],[name*=aptcha],img[src*=aptcha]').length > 0;
  return {
    hidden,
    reg: reg && $(reg).attr('name'),
    dob: dob && $(dob).attr('name'),
    btn: btn && { name: $(btn).attr('name') || '', value: $(btn).attr('value') || $(btn).text().trim() || 'Search' },
    captcha
  };
}

/* ---------- read the "RESULT AVAILABLE" table ---------- */
function readRows($) {
  let tbl = null;
  $('table').each((_, t) => {
    const head = $(t).find('tr').first().text();
    if (/marksheet/i.test(head) && /roll/i.test(head)) tbl = t;   // last (innermost) match wins
  });
  const rows = [], acts = [];
  if (!tbl) return { rows, acts };
  $(tbl).find('tr').each((_, tr) => {
    const tds = $(tr).children('td,th');
    if (tds.length < 5) return;
    const cells = tds.map((__, td) => $(td).text().replace(/\s+/g, ' ').trim()).get();
    if (!/^\d+$/.test(cells[0])) return;
    const last = tds.last();
    let act = null;
    const a = last.find('a').first();
    const inp = last.find('input[type=submit],input[type=image],input[type=button],button').first();
    if (a.length) {
      const h = a.attr('href') || '', oc = a.attr('onclick') || '';
      const m = (h + ' ' + oc).match(/__doPostBack\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)/);
      if (m) act = { k: 'pb', t: m[1], a: m[2] };
      else if (h && !h.startsWith('#') && !/^javascript/i.test(h)) act = { k: 'link', u: new URL(h, PAGE).href };
    } else if (inp.length && inp.attr('name')) {
      act = { k: 'btn', n: inp.attr('name'), v: inp.attr('value') || 'x' };
    }
    rows.push({ cells, has: !!act });
    acts.push(act);
  });
  return { rows, acts };
}

/* ---------- limits + sessions (memory only, 10 minutes) ---------- */
const sessions = new Map();
setInterval(() => { const n = Date.now(); for (const [k, v] of sessions) if (v.exp < n) sessions.delete(k); }, 60000).unref();
const hits = new Map();
function limited(ip) {
  const now = Date.now(), arr = (hits.get(ip) || []).filter(t => now - t < 600000);
  arr.push(now); hits.set(ip, arr);
  return arr.length > 20;
}
let busy = 0;

/* ---------- API ---------- */
app.post('/api/result', async (req_, res) => {
  const reg = String(req_.body.reg || '').trim(), dob = String(req_.body.dob || '').trim();
  if (!/^[A-Za-z0-9\-\/ ]{4,30}$/.test(reg)) return res.status(400).json({ error: 'Please enter a valid Registration Number.' });
  if (!/^\d{2}\/\d{2}\/\d{4}$/.test(dob)) return res.status(400).json({ error: 'Date of Birth must be dd/mm/yyyy.' });
  if (limited(req_.ip)) return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes and try again.' });
  if (busy >= 6) return res.status(503).json({ error: 'Server is busy. Please try again in a minute.' });
  busy++;
  try {
    const jar = new Jar();
    const g = await req(PAGE, jar);
    const form = readForm(cheerio.load(await g.text()));
    if (form.captcha) return res.status(503).json({ error: 'The university site is asking for a captcha, so results cannot be fetched here right now. Please use the official site.' });
    if (!form.reg || !form.dob || !form.btn) return res.status(502).json({ error: 'University result page has changed. Please use the official site for now.' });

    const body = new URLSearchParams({ ...form.hidden, [form.reg]: reg, [form.dob]: dob });
    if (form.btn.name) body.set(form.btn.name, form.btn.value);
    const p = await req(PAGE, jar, {
      method: 'POST', body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Referer: PAGE, Origin: 'https://vksuexams.com' }
    });
    const $ = cheerio.load(await p.text());
    const { rows, acts } = readRows($);
    if (!rows.length) {
      const msg = $('[id*=lbl],[id*=Msg],[id*=msg],[id*=Error],.alert').map((_, el) => $(el).text().trim()).get().filter(Boolean).join(' ');
      return res.json({ rows: [], message: msg || 'No result found for this Registration Number and Date of Birth. Please check and try again.' });
    }
    const after = readForm($);
    const token = crypto.randomBytes(16).toString('hex');
    sessions.set(token, {
      jar, acts, exp: Date.now() + 600000,
      fields: { ...after.hidden, [form.reg]: reg, [form.dob]: dob }
    });
    res.json({ token, rows });
  } catch (e) {
    res.status(502).json({ error: 'Could not reach the university site. Please try again later.' });
  } finally { busy--; }
});

app.get('/api/marksheet', async (req_, res) => {
  const s = sessions.get(String(req_.query.t || ''));
  const act = s && s.acts[parseInt(req_.query.i, 10)];
  if (!s || !act) return res.status(410).send('Session expired. Please search again.');
  try {
    let r;
    const hdr = { 'Content-Type': 'application/x-www-form-urlencoded', Referer: PAGE, Origin: 'https://vksuexams.com' };
    if (act.k === 'link') r = await req(act.u, s.jar, { headers: { Referer: PAGE } });
    else if (act.k === 'pb') r = await req(PAGE, s.jar, { method: 'POST', headers: hdr, body: new URLSearchParams({ ...s.fields, __EVENTTARGET: act.t, __EVENTARGUMENT: act.a }) });
    else r = await req(PAGE, s.jar, { method: 'POST', headers: hdr, body: new URLSearchParams({ ...s.fields, [act.n]: act.v, [act.n + '.x']: '1', [act.n + '.y']: '1' }) });

    const ct = r.headers.get('content-type') || 'application/octet-stream';
    let buf = Buffer.from(await r.arrayBuffer());
    res.set('Cache-Control', 'no-store');
    const cd = r.headers.get('content-disposition');
    if (cd) res.set('Content-Disposition', cd);
    if (/html/i.test(ct)) {
      let h = buf.toString('utf8');
      h = /<head[^>]*>/i.test(h) ? h.replace(/<head[^>]*>/i, m => m + '<base href="' + BASE + '">') : '<base href="' + BASE + '">' + h;
      return res.type('html').send(h);
    }
    res.type(ct).send(buf);
  } catch (e) { res.status(502).send('Could not fetch the marksheet. Please try again.'); }
});

// Shows what the server detected on the official page (no student data). Handy for fixing.
app.get('/api/health', async (_q, res) => {
  try {
    const jar = new Jar(), g = await req(PAGE, jar), f = readForm(cheerio.load(await g.text()));
    res.json({ ok: !!(f.reg && f.dob && f.btn), regField: f.reg, dobField: f.dob, button: f.btn, captcha: f.captcha, hiddenFields: Object.keys(f.hidden) });
  } catch (e) { res.status(502).json({ ok: false }); }
});

app.get('/', (_q, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(process.env.PORT || 3000, () => console.log('running'));
