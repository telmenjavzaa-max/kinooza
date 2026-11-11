// Kinooza — QPay төлбөрийн функц
// POST {action:"create", plan: plans.code, movie_id?}  → нэхэмжлэх + QR
// POST {action:"check", payment_id}                         → төлөв шалгах
// GET/POST ?callback=1&payment_id=...                         → QPay-ийн callback
// Нууц тохиргоо (Supabase → Edge Functions → Secrets):
//   QPAY_USERNAME, QPAY_PASSWORD, QPAY_INVOICE_CODE, (сонголттой) QPAY_BASE_URL

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
let cached: { token: string; exp: number } | null = null;
async function qpayToken() {
  if (cached && Date.now() < cached.exp) return cached.token;
  const user = Deno.env.get("QPAY_USERNAME"), pass = Deno.env.get("QPAY_PASSWORD");
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
  cached = { token: t.access_token, exp };
  return cached.token;
}

async function qpay(path: string, token: string, body: unknown) {
  const send = (t: string) => fetch(`${QPAY_BASE}${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${t}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let r = await send(token);
  if (r.status === 401) { cached = null; r = await send(await qpayToken()); } // хугацаа дууссан token
  const text = await r.text();
  if (!r.ok) throw new Error(`QPay ${path}: ${r.status} ${text}`);
  return JSON.parse(text);
}

// QPay-ээс төлбөрийг шалгаж, төлөгдсөн бол эрх олгоно
async function verifyAndGrant(payment: { id: string; amount: number; status: string; qpay_invoice_id: string | null }) {
  if (payment.status === "paid") return "paid";
  if (!payment.qpay_invoice_id) return payment.status;
  const token = await qpayToken();
  const res = await qpay("/v2/payment/check", token, {
    object_type: "INVOICE",
    object_id: payment.qpay_invoice_id,
    offset: { page_number: 1, page_limit: 100 },
  });
  const rows: { payment_status?: string; payment_amount?: number | string }[] = res?.rows || [];
  const paidRows = rows.filter((r) => String(r.payment_status).toUpperCase() === "PAID");
  const paidSum = paidRows.reduce((s, r) => s + Number(r.payment_amount || 0), 0);
  const paid = Math.max(paidSum, Number(res?.paid_amount || 0));
  if (paidRows.length && paid >= payment.amount) {
    await db("rpc/grant_payment", { method: "POST", body: JSON.stringify({ p_payment: payment.id }) });
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
        const [p] = await db(`payments?id=eq.${id}&select=id,amount,status,qpay_invoice_id`);
        if (p) await verifyAndGrant(p);
      }
      return new Response("SUCCESS", { status: 200, headers: CORS });
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

      const [payment] = await db("payments", {
        method: "POST",
        body: JSON.stringify({ user_id: user.id, plan_code: planCode, movie_id: movieId, amount }),
      });

      const invoiceCode = Deno.env.get("QPAY_INVOICE_CODE");
      if (!invoiceCode) throw new Error("QPAY_INVOICE_CODE тохируулаагүй байна");
      const token = await qpayToken();
      const inv = await qpay("/v2/invoice", token, {
        invoice_code: invoiceCode,
        sender_invoice_no: payment.id,
        invoice_receiver_code: "terminal",
        invoice_description: description,
        amount,
        callback_url: `${SB_URL}/functions/v1/qpay?callback=1&payment_id=${payment.id}`,
      });

      await db(`payments?id=eq.${payment.id}`, {
        method: "PATCH",
        body: JSON.stringify({ qpay_invoice_id: inv.invoice_id }),
      });

      return json({
        payment_id: payment.id,
        amount,
        description,
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
      const [p] = await db(`payments?id=eq.${id}&user_id=eq.${user.id}&select=id,amount,status,qpay_invoice_id`);
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
