/* Gram Bharti notice API for Render (Node 18+, no npm packages).
   Environment variables (Render > Environment):
     ADMIN_USER, ADMIN_PASS, JWT_SECRET   admin login + session signing key
     UPSTASH_URL, UPSTASH_TOKEN           from your free Upstash Redis database (REST API)
     ALLOWED_ORIGIN                       optional, e.g. https://your-site.onrender.com
   Public: GET /notices   Admin: POST /login, POST /notices, PUT /notices/:id, DELETE /notices/:id */
const http = require("http"), crypto = require("crypto");
const E = process.env;
const CATS = ["Admission", "Examination", "Result", "University", "Scholarship", "College"];
for (const k of ["ADMIN_USER", "ADMIN_PASS", "JWT_SECRET", "UPSTASH_URL", "UPSTASH_TOKEN"])
  if (!E[k]) console.error("Missing environment variable: " + k);

const sign = d => crypto.createHmac("sha256", E.JWT_SECRET || "").update(d).digest("base64url");
const h256 = x => crypto.createHash("sha256").update(String(x)).digest();
const same = (a, b) => crypto.timingSafeEqual(h256(a), h256(b));
async function db(cmd) {
  const r = await fetch(E.UPSTASH_URL, { method: "POST", headers: { Authorization: "Bearer " + E.UPSTASH_TOKEN }, body: JSON.stringify(cmd) });
  const d = await r.json(); if (d.error) throw new Error(d.error); return d.result;
}
const load = async () => JSON.parse(await db(["GET", "notices"]) || "[]");
const save = l => db(["SET", "notices", JSON.stringify(l)]);
const fails = new Map(); // ip -> {n, until}

http.createServer(async (req, res) => {
  const H = {
    "Access-Control-Allow-Origin": E.ALLOWED_ORIGIN || "*",
    "Access-Control-Allow-Headers": "Authorization,Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Content-Type": "application/json", "Cache-Control": "no-store"
  };
  const R = (d, s = 200) => { res.writeHead(s, H); res.end(JSON.stringify(d)); };
  if (req.method === "OPTIONS") { res.writeHead(204, H); return res.end(); }
  const body = () => new Promise((ok, no) => {
    let s = ""; req.on("data", c => { s += c; if (s.length > 2e4) { no(new Error("big")); req.destroy(); } });
    req.on("end", () => { try { ok(JSON.parse(s || "{}")); } catch (e) { no(e); } });
  });
  const p = req.url.split("?")[0].replace(/\/+$/, "") || "/";
  try {
    if (p === "/") return R({ ok: true });
    if (p === "/notices" && req.method === "GET") return R(await load());

    // ---- Authentication ----
    if (p === "/login" && req.method === "POST") {
      const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress).split(",")[0].trim();
      let f = fails.get(ip); if (f && f.until < Date.now()) f = null;
      if (f && f.n >= 5) return R({ error: "Too many attempts. Try again in 15 minutes." }, 429);
      const b = await body();
      const ok = same(b.username || "", E.ADMIN_USER) & same(b.password || "", E.ADMIN_PASS);
      if (!ok) { fails.set(ip, { n: (f ? f.n : 0) + 1, until: f ? f.until : Date.now() + 9e5 }); return R({ error: "Wrong username or password." }, 401); }
      fails.delete(ip);
      const d = Buffer.from(JSON.stringify({ role: "admin", exp: Date.now() + 2 * 36e5 })).toString("base64url");
      return R({ token: d + "." + sign(d) });
    }

    // ---- Authorization: writes need a valid admin token ----
    if (p.startsWith("/notices")) {
      const [d, s] = (req.headers.authorization || "").replace("Bearer ", "").split(".");
      if (!d || !s || !same(s, sign(d))) return R({ error: "Not authorized." }, 401);
      let c; try { c = JSON.parse(Buffer.from(d, "base64url").toString()); } catch { return R({ error: "Not authorized." }, 401); }
      if (c.role !== "admin" || c.exp < Date.now()) return R({ error: "Session expired." }, 401);

      const list = await load(), id = p.split("/")[2];
      if (req.method === "DELETE") { await save(list.filter(n => n.id !== id)); return R({ ok: true }); }
      if (req.method === "POST" || req.method === "PUT") {
        const b = await body();
        const t = String(b.t || "").trim().slice(0, 200), desc = String(b.desc || "").trim().slice(0, 1500), url = String(b.url || "").trim();
        if (!t || !CATS.includes(b.cat) || !/^\d{4}-\d{2}-\d{2}$/.test(b.date || "") || (url && !/^https?:\/\//i.test(url)))
          return R({ error: "Invalid notice data." }, 400);
        const n = { id: id || crypto.randomUUID(), t, date: b.date, cat: b.cat, desc, url };
        await save(req.method === "PUT" ? list.map(x => x.id === id ? n : x) : [n, ...list]);
        return R(n);
      }
    }
    R({ error: "Not found" }, 404);
  } catch (x) { console.error(x); R({ error: "Server error" }, 500); }
}).listen(E.PORT || 3000, () => console.log("Notice API running"));
