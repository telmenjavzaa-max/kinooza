// Kinooza — QPay төлбөрийн функц
// POST {action:"create", plan: plans.code, movie_id?}  → нэхэмжлэх + QR
// POST {action:"check", payment_id}                         → төлөв шалгах
// GET/POST ?callback=1&payment_id=...                         → QPay-ийн callback
// Нууц тохиргоо (Supabase → Edge Functions → Secrets):
//   QPAY_USERNAME, QPAY_PASSWORD, QPAY_INVOICE_CODE, (сонголттой) QPAY_BASE_URL
//   QPAY2_USERNAME, QPAY2_PASSWORD, QPAY2_INVOICE_CODE

const SB_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const ANON = Deno.env.get("SUPABASE_ANON_KEY")!;
const QPAY_BASE = (Deno.env.get("QPAY_BASE_URL") || "https://merchant.qpay.mn").replace(/\/$/, "");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { ...CORS, "Content-Type": "application/json" } });

// ---- Supabase REST (service role) ----
async function db(path: string, init: RequestInit = {}) {
  const r = await fetch(`${SB_URL}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: SERVICE,
      Authorization: `Bearer ${SERVICE}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
      ...(init.headers || {}),
    },
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`db ${path}: ${r.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

async function currentUser(req: Request) {
  const auth = req.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  const r = await fetch(`${SB_URL}/auth/v1/user`, { headers: { apikey: ANON, Authorization: auth } });
  if (!r.ok) return null;
  const u = await r.json();
  return u?.id ? u : null;
}

// ---- QPay ----
// Token-ийг дахин ашиглана (QPay: хүчинтэй token байхад шинээр бүү ав)
const cachedBy: Record<number, { token: string; exp: number } | null> = { 1: null, 2: null };
const env2 = (acct: number, name: string) => Deno.env.get((acct === 2 ? "QPAY2_" : "QPAY_") + name);
const qpay2Enabled = () => !!(env2(2, "USERNAME") && env2(2, "PASSWORD") && env2(2, "INVOICE_CODE"));
async function qpayToken(acct = 1) {
  const cached = cachedBy[acct];
  if (cached && Date.now() < cached.exp) return cached.token;
  const user = env2(acct, "USERNAME")?.trim(), pass = env2(acct, "PASSWORD")?.trim();
  if (!user || !pass) throw new Error("QPay нууц тохиргоо (QPAY_USERNAME / QPAY_PASSWORD) алга байна");
  const r = await fetch(`${QPAY_BASE}/v2/auth/token`, {
    method: "POST",
    headers: { Authorization: "Basic " + btoa(`${user}:${pass}`), "Content-Type": "application/json" },
  });
  if (!r.ok) throw new Error(`QPay token: ${r.status} ${await r.text()}`);
  const t = await r.json();
  // expires_in нь секунд эсвэл unix хугацаа байж болно — аль алинд нь 1 минутын нөөцтэй
  let exp = Date.now() + 25 * 60 * 1000;
  const e = Number(t.expires_in);
  if (e > 1e9) exp = e * 1000 - 60_000; else if (e > 60) exp = Date.now() + (e - 60) * 1000;
  cachedBy[acct] = { token: t.access_token, exp };
  return t.access_token as string;
}

async function qpay(path: string, token: string, body: unknown, acct = 1) {
  const send = (t: string) => fetch(`${QPAY_BASE}${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${t}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let r = await send(token);
  if (r.status === 401) { cachedBy[acct] = null; r = await send(await qpayToken(acct)); } // хугацаа дууссан token
  const text = await r.text();
  if (!r.ok) throw new Error(`QPay ${path}: ${r.status} ${text}`);
  return JSON.parse(text);
}

// ---- Meta Conversions API (сервер талаас Purchase) ----
// Secrets: META_CAPI_TOKEN (заавал), META_PIXEL_ID (сонголттой). Токен байхгүй бол алгасна.
const sha256 = async (v: string) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)))).map((b) => b.toString(16).padStart(2, "0")).join("");
async function sendCapiPurchase(paymentId: string) {
  const token = Deno.env.get("META_CAPI_TOKEN");
  const pixel = Deno.env.get("META_PIXEL_ID") || "4602268083325312";
  if (!token) return;
  const [p] = await db(`payments?id=eq.${paymentId}&select=id,user_id,amount,plan_code,movie_id,paid_at,fbp,fbc,client_ua`);
  if (!p) return;
  // Хувийн мэдээлэл (имэйл, утас) илгээхгүй — зөвхөн кодолсон дотоод ID + Facebook cookie
  const ud: Record<string, unknown> = { external_id: [await sha256(p.user_id)] };
  if (p.fbp) ud.fbp = p.fbp;
  if (p.fbc) ud.fbc = p.fbc;
  if (p.client_ua) ud.client_user_agent = p.client_ua;
  const body = { data: [{
    event_name: "Purchase", event_time: Math.floor(new Date(p.paid_at || Date.now()).getTime() / 1000), event_id: p.id,
    action_source: "website", event_source_url: "https://kinooza.com/", user_data: ud,
    custom_data: { currency: "MNT", value: Number(p.amount) || 0, content_ids: [p.movie_id ? String(p.movie_id) : p.plan_code], content_type: "product" },
  }] };
  const r = await fetch(`https://graph.facebook.com/v21.0/${pixel}/events?access_token=${encodeURIComponent(token)}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!r.ok) console.error("capi", r.status, await r.text());
}

// QPay-ээс төлбөрийг шалгаж, төлөгдсөн бол эрх олгоно
async function verifyAndGrant(payment: { id: string; amount: number; status: string; qpay_invoice_id: string | null; qpay_account?: number | null }) {
  const acct = payment.qpay_account === 2 ? 2 : 1;
  if (payment.status === "paid") return "paid";
  if (!payment.qpay_invoice_id) return payment.status;
  const token = await qpayToken(acct);
  const res = await qpay("/v2/payment/check", token, {
    object_type: "INVOICE",
    object_id: payment.qpay_invoice_id,
    offset: { page_number: 1, page_limit: 100 },
  }, acct);
  const rows: { payment_status?: string; payment_amount?: number | string }[] = res?.rows || [];
  const paidRows = rows.filter((r) => String(r.payment_status).toUpperCase() === "PAID");
  const paidSum = paidRows.reduce((s, r) => s + Number(r.payment_amount || 0), 0);
  const paid = Math.max(paidSum, Number(res?.paid_amount || 0));
  if (paidRows.length && paid >= payment.amount) {
    const granted = await db("rpc/grant_payment", { method: "POST", body: JSON.stringify({ p_payment: payment.id }) });
    if (granted === true && acct !== 2) await sendCapiPurchase(payment.id).catch((e) => console.error("capi", e));
    return "paid";
  }
  return "pending";
}

const lastCheck = new Map<string, number>();

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  const url = new URL(req.url);

  try {
    // ---- QPay callback ----
    if (url.searchParams.get("callback")) {
      const id = url.searchParams.get("payment_id") || "";
      if (/^[0-9a-f-]{36}$/i.test(id)) {
        const [p] = await db(`payments?id=eq.${id}&select=id,amount,status,qpay_invoice_id,qpay_account`);
        if (p) await verifyAndGrant(p);
      }
      return new Response("SUCCESS", { status: 200, headers: CORS });
    }

    if (url.searchParams.get("ping")) {
      try { await qpayToken(); return json({ qpay: "ok" }); } catch (e) { return json({ qpay: "error", detail: String((e as Error).message).replace(/Basic \S+/g, "") }, 502); }
    }

    if (req.method !== "POST") return json({ error: "method" }, 405);
    const user = await currentUser(req);
    if (!user) return json({ error: "Нэвтэрнэ үү" }, 401);
    const body = await req.json().catch(() => ({}));

    // ---- Нэхэмжлэх үүсгэх ----
    if (body.action === "create") {
      const planCode = String(body.plan || "");
      if (!/^[a-z0-9_]{2,30}$/.test(planCode)) return json({ error: "Багц сонгоно уу" }, 400);
      const [plan] = await db(`plans?code=eq.${planCode}&active=eq.true&select=*`);
      if (!plan) return json({ error: "Багц олдсонгүй" }, 400);

      let movieId: number | null = null;
      let amount = plan.amount as number;
      let description = `Kinooza — ${plan.title}`;
      if (plan.kind === "rent") {
        movieId = Number(body.movie_id);
        if (!Number.isInteger(movieId)) return json({ error: "Кино сонгоно уу" }, 400);
        const [movie] = await db(`movies?id=eq.${movieId}&published=eq.true&select=id,title,rent_price`);
        if (!movie) return json({ error: "Кино олдсонгүй" }, 404);
        amount = movie.rent_price || amount;
        description = `Kinooza — ${movie.title} (${plan.hours} цаг)`;
      }

      let acct = 1;
      if (qpay2Enabled() && new Date(user.created_at).getTime() >= Date.parse("2026-11-17T20:58:00+08:00")) {
        const admin = await fetch(`${SB_URL}/rest/v1/rpc/is_admin`, { method: "POST", headers: { apikey: ANON, Authorization: req.headers.get("Authorization") || "", "Content-Type": "application/json" }, body: "{}" }).then((r) => r.ok ? r.json() : true).catch(() => true);
        if (admin !== true) acct = await db("rpc/next_qpay_account", { method: "POST", body: "{}" }).then((v) => (v === 2 ? 2 : 1)).catch(() => 1);
      }
      const [payment] = await db("payments", {
        method: "POST",
        body: JSON.stringify({
          user_id: user.id, plan_code: planCode, movie_id: movieId, amount, qpay_account: acct,
          fbp: /^fb\.\d\.\d+\.\d+$/.test(String(body.fbp || "")) ? body.fbp : null,
          fbc: /^fb\.\d\.\d+\.[\w-]{1,500}$/.test(String(body.fbc || "")) ? body.fbc : null,
          client_ua: (req.headers.get("user-agent") || "").slice(0, 400) || null,
        }),
      });

      const invoiceCode = env2(acct, "INVOICE_CODE")?.trim();
      if (acct === 2) description = "MB-" + String(parseInt(payment.id.replace(/-/g, "").slice(0, 8), 16) % 10000).padStart(4, "0");
      if (!invoiceCode) throw new Error("QPAY_INVOICE_CODE тохируулаагүй байна");
      const token = await qpayToken(acct);
      const inv = await qpay("/v2/invoice", token, {
        invoice_code: invoiceCode,
        sender_invoice_no: payment.id,
        invoice_receiver_code: "terminal",
        invoice_description: description,
        amount,
        callback_url: `${SB_URL}/functions/v1/qpay?callback=1&payment_id=${payment.id}`,
      }, acct);

      await db(`payments?id=eq.${payment.id}`, {
        method: "PATCH",
        body: JSON.stringify({ qpay_invoice_id: inv.invoice_id }),
      });

      return json({
        payment_id: payment.id,
        amount,
        description,
        hidden: acct === 2,
        qr_image: inv.qr_image || null,
        qr_text: inv.qr_text || null,
        short_url: inv.qPay_shortUrl || null,
        urls: (inv.urls || []).map((u: { name?: string; description?: string; logo?: string; link?: string }) => ({
          name: u.description || u.name, logo: u.logo, link: u.link,
        })),
      });
    }

    // ---- Төлөв шалгах ----
    if (body.action === "check") {
      const id = String(body.payment_id || "");
      if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "payment_id" }, 400);
      const [p] = await db(`payments?id=eq.${id}&user_id=eq.${user.id}&select=id,amount,status,qpay_invoice_id,qpay_account`);
      if (!p) return json({ error: "Төлбөр олдсонгүй" }, 404);
      if (p.status === "paid") return json({ status: "paid" });
      const last = lastCheck.get(id) || 0;
      if (Date.now() - last < 30_000) return json({ status: p.status, throttled: true });
      lastCheck.set(id, Date.now());
      const status = await verifyAndGrant(p);
      return json({ status });
    }

    return json({ error: "action" }, 400);
  } catch (e) {
    console.error(e);
    return json({ error: String((e as Error).message || e) }, 500);
  }
});
