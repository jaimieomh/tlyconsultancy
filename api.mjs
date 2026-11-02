import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const SEC = () => process.env.AUTH_SECRET || "";
const OWNER = () => (process.env.OWNER_EMAIL || "").trim().toLowerCase();
const sign = p => crypto.createHmac("sha256", SEC()).update(p).digest("base64url");
const mk = e => { const p = Buffer.from(JSON.stringify({ e, x: Date.now() + 30 * 864e5 })).toString("base64url"); return p + "." + sign(p); };
const h = s => crypto.createHash("sha256").update(String(s)).digest();
const eq = (a, b) => crypto.timingSafeEqual(h(a), h(b));
function authed(req) {
  const [p, s] = (req.headers.get("authorization") || "").replace("Bearer ", "").split(".");
  if (!p || !s || !SEC() || !OWNER()) return false;
  const a = Buffer.from(s), b = Buffer.from(sign(p));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { const d = JSON.parse(Buffer.from(p, "base64url")); return d.x > Date.now() && d.e === OWNER(); } catch { return false; }
}
const idOk = id => /^[\w-]{1,40}$/.test(id || "");

export default async (req) => {
  const path = new URL(req.url).pathname.replace(/^\/api\/?/, "");
  const L = getStore("listings"), A = getStore("auth");

  if (path === "login" && req.method === "POST") {
    if (!OWNER() || !process.env.OWNER_PIN || !SEC()) return J({ error: "Server not configured." }, 500);
    const { email = "", pin = "" } = await req.json().catch(() => ({}));
    const st = (await A.get("fails", { type: "json" })) || { n: 0, t: 0 };
    const locked = st.n >= 5 && Date.now() - st.t < 9e5;
    if (locked) return J({ error: "Too many attempts. Try again in 15 minutes." }, 429);
    const e1 = eq(String(email).trim().toLowerCase(), OWNER()), e2 = eq(String(pin), process.env.OWNER_PIN);
    if (!(e1 && e2)) {
      await A.setJSON("fails", { n: (st.n >= 5 ? 0 : st.n) + 1, t: Date.now() });
      return J({ error: "Wrong email or password." }, 401);
    }
    await A.setJSON("fails", { n: 0, t: 0 });
    return J({ token: mk(OWNER()) });
  }

  if (path === "listings" && req.method === "GET") {
    const { blobs } = await L.list({ prefix: "l-" });
    const items = (await Promise.all(blobs.map(b => L.get(b.key, { type: "json" })))).filter(Boolean)
      .map(({ photos = [], ...x }) => ({ ...x, n: photos.length }))
      .sort((a, b) => String(b.id).localeCompare(String(a.id)));
    const settings = (await L.get("settings", { type: "json" })) || {};
    return J({ listings: items, settings });
  }

  if (path.startsWith("photos/") && req.method === "GET") {
    const x = await L.get("l-" + path.slice(7), { type: "json" });
    return J({ photos: x?.photos || [] });
  }

  if (path === "me") return J({ ok: authed(req) }, authed(req) ? 200 : 401);

  if (!authed(req)) return J({ error: "Not logged in." }, 401);

  if (path === "listing" && req.method === "POST") {
    const x = await req.json().catch(() => null);
    if (!x || !idOk(x.id) || !x.title) return J({ error: "Invalid listing." }, 400);
    await L.setJSON("l-" + x.id, x);
    return J({ ok: true });
  }
  if (path.startsWith("listing/") && req.method === "DELETE") {
    const id = path.slice(8);
    if (!idOk(id)) return J({ error: "Bad id." }, 400);
    await L.delete("l-" + id);
    return J({ ok: true });
  }
  if (path === "settings" && req.method === "POST") {
    const s = await req.json().catch(() => ({}));
    await L.setJSON("settings", { name: String(s.name || "").slice(0, 80), phone: String(s.phone || "").replace(/\D/g, "").slice(0, 20) });
    return J({ ok: true });
  }
  return J({ error: "Not found." }, 404);
};

export const config = { path: "/api/*" };
