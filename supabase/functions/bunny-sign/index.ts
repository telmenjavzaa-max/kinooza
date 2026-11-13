// Kinooza — Bunny Stream "Embed token authentication" холбоосыг серверт гарын үсэглэх
// POST {url} (Authorization: хэрэглэгчийн JWT) → { url: ".../embed/LIB/VID?token=...&expires=..." }
// Хэрэглэгч тухайн видеог үзэх эрхтэй (RLS) эсвэл энэ нь нийтэд нээлттэй трейлер бол л гарын үсэг зурна.
// Secret: BUNNY_TOKEN_KEY — Bunny → Stream → Library → Security → "Token authentication key"
const SB_URL = Deno.env.get("SUPABASE_URL")!;
const ANON = Deno.env.get("SUPABASE_ANON_KEY")!;
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (d: unknown, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { ...CORS, "Content-Type": "application/json" } });
const sha256 = async (v: string) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)))).map((b) => b.toString(16).padStart(2, "0")).join("");

// Хэрэглэгчийн эрхээр (RLS) асуух
async function rest(path: string, auth: string) {
  const r = await fetch(`${SB_URL}/rest/v1/${path}`, { headers: { apikey: ANON, Authorization: auth || `Bearer ${ANON}` } });
  return r.ok ? r.json() : [];
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  const key = Deno.env.get("BUNNY_TOKEN_KEY");
  if (!key) return json({ error: "Bunny тохируулаагүй байна" }, 500);
  const { url } = await req.json().catch(() => ({}));
  let u: URL; try { u = new URL(String(url)); } catch { return json({ error: "url" }, 400); }
  const host = u.hostname.replace(/^www\./, "");
  const parts = u.pathname.split("/").filter(Boolean);
  if (!/^(iframe|player)\.mediadelivery\.net$/.test(host) || !["embed", "play"].includes(parts[0]) || !/^\d+$/.test(parts[1] || "") || !/^[0-9a-f-]{36}$/i.test(parts[2] || "")) return json({ error: "Bunny холбоос биш" }, 400);
  const lib = parts[1], vid = parts[2];

  // Эрх шалгах: movie_videos / episode_videos нь RLS-ээр зөвхөн эрхтэй хэрэглэгчид харагдана; трейлер нийтэд нээлттэй
  const auth = req.headers.get("Authorization") || "";
  const like = encodeURIComponent(`*${vid}*`);
  const [mv, ev, tr] = await Promise.all([
    rest(`movie_videos?select=movie_id&video_url=ilike.${like}&limit=1`, auth),
    rest(`episode_videos?select=episode_id&video_url=ilike.${like}&limit=1`, auth),
    rest(`movies?select=id&published=eq.true&trailer_url=ilike.${like}&limit=1`, auth),
  ]);
  if (!mv.length && !ev.length && !tr.length) return json({ error: "Энэ видеог үзэх эрх алга" }, 403);

  const expires = Math.floor(Date.now() / 1000) + 6 * 3600; // 6 цаг
  const token = await sha256(key + vid + expires);
  return json({ url: `https://iframe.mediadelivery.net/embed/${lib}/${vid}?token=${token}&expires=${expires}` });
});
