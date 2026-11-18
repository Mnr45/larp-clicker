import { DurableObject } from "cloudflare:workers";
const encoder = new TextEncoder();
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const clean = (v, n = 180) => String(v ?? "").replace(/[<>]/g, "").trim().slice(0, n);
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 180000, hash: "SHA-256" }, key, 256);
  return b64u(bits);
}
async function signToken(payload, secret) {
  const head = b64u(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = b64u(encoder.encode(JSON.stringify(payload)));
  const data = `${head}.${body}`;
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return `${data}.${b64u(sig)}`;
}
async function verifyToken(token, secret) {
  try {
    if (!token || !secret) return null;
    const [h, p, s] = token.split("."); if (!h || !p || !s) return null;
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, fromB64u(s), encoder.encode(`${h}.${p}`));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(fromB64u(p)));
    if (!payload.sub || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}
async function getUser(request, env) {
  const auth = request.headers.get("authorization") || "";
  const bearer = auth.replace(/^Bearer\s+/i, "");
  const url = new URL(request.url);
  const token = bearer || (url.pathname === "/api/live" ? url.searchParams.get("token") : "");
  return verifyToken(token, env.AUTH_SECRET);
}
async function issueUser(row, env) {
  const token = await signToken({ sub: row.id, email: row.email, name: row.name, exp: Math.floor(Date.now()/1000) + 60*60*24*7 }, env.AUTH_SECRET);
  return { token, user: { id: row.id, email: row.email, name: row.name, token } };
}
async function notify(env, type = "refresh") {
  try {
    const id = env.LIVE_ROOM.idFromName("larp-global-room");
    await env.LIVE_ROOM.get(id).fetch("https://live.internal/broadcast", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ type, at: Date.now() }) });
  } catch (e) { console.error("Live broadcast failed", e); }
}
async function worldFor(user, env) {
  const me = await env.DB.prepare("SELECT save_json, updated_at FROM profiles WHERE user_id = ?").bind(user.sub).first();
  const players = await env.DB.prepare("SELECT user_id, name, save_json FROM profiles ORDER BY updated_at DESC LIMIT 60").all();
  const events = await env.DB.prepare("SELECT id,title,description,kind,starts_at,ends_at FROM events WHERE ends_at IS NULL OR ends_at > ? ORDER BY starts_at DESC LIMIT 30").bind(Date.now()).all();
  const messages = await env.DB.prepare("SELECT id,user_id,name,message,created_at,global_flag FROM messages ORDER BY created_at DESC LIMIT 60").all();
  const inbox = await env.DB.prepare("SELECT id,from_name,kind,amount,created_at FROM gifts WHERE to_user_id = ? AND claimed = 0 ORDER BY created_at DESC LIMIT 100").bind(user.sub).all();
  return {
    mySave: me?.save_json ? JSON.parse(me.save_json) : null,
    updatedAt: me?.updated_at || 0,
    players: (players.results || []).map(p => { const s = JSON.parse(p.save_json || "{}"); return { id: p.user_id, name: p.name, level: s.level || 1, kills: s.kills || 0, bossKills: s.bossKills || 0 }; }),
    events: (events.results || []).map(e => ({ id:e.id,title:e.title,description:e.description,kind:e.kind,startsAt:e.starts_at,endsAt:e.ends_at })),
    messages: (messages.results || []).reverse().map(m => ({ id:m.id,userId:m.user_id,name:m.name,message:m.message,at:m.created_at,global:!!m.global_flag })),
    inbox: (inbox.results || []).map(g => ({ id:g.id,fromName:g.from_name,kind:g.kind,amount:g.amount,at:g.created_at }))
  };
}
async function register(request, env) {
  const b = await request.json().catch(() => null); if (!b) return json({ error: "Corps de requête invalide." }, 400);
  const email = clean(b.email, 180).toLowerCase(), name = clean(b.name, 24), password = String(b.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Adresse e-mail invalide." }, 400);
  if (name.length < 3) return json({ error: "Le nom doit contenir au moins 3 caractères." }, 400);
  if (password.length < 10 || password.length > 128) return json({ error: "Le mot de passe doit contenir entre 10 et 128 caractères." }, 400);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await passwordHash(password, salt);
  const id = crypto.randomUUID();
  try {
    await env.DB.prepare("INSERT INTO accounts (id,email,name,password_salt,password_hash,created_at) VALUES (?,?,?,?,?,?)").bind(id,email,name,b64u(salt),hash,Date.now()).run();
  } catch { return json({ error: "Cet e-mail ou ce nom de joueur est déjà utilisé." }, 409); }
  const result = await issueUser({id,email,name}, env);
  return json(result, 201);
}
async function login(request, env) {
  const b = await request.json().catch(() => null); if (!b) return json({ error: "Corps de requête invalide." }, 400);
  const email = clean(b.email, 180).toLowerCase(), password = String(b.password || "");
  const row = await env.DB.prepare("SELECT id,email,name,password_salt,password_hash FROM accounts WHERE email = ?").bind(email).first();
  if (!row) return json({ error: "E-mail ou mot de passe incorrect." }, 401);
  const hash = await passwordHash(password, fromB64u(row.password_salt));
  if (hash !== row.password_hash) return json({ error: "E-mail ou mot de passe incorrect." }, 401);
  return json(await issueUser(row, env));
}
async function action(request, user, env) {
  const b = await request.json().catch(() => null); if (!b) return json({ error: "JSON invalide." }, 400);
  const now = Date.now();
  if (b.action === "sync") {
    const name = clean(b.name, 24) || user.name || "Aventurier"; const save = b.save;
    if (!save || typeof save !== "object" || JSON.stringify(save).length > 100000) return json({ error: "Sauvegarde invalide." }, 400);
    await env.DB.prepare("INSERT INTO profiles (user_id,name,save_json,updated_at,last_chat) VALUES (?,?,?, ?,0) ON CONFLICT(user_id) DO UPDATE SET name=excluded.name,save_json=excluded.save_json,updated_at=excluded.updated_at").bind(user.sub,name,JSON.stringify(save),now).run();
    await notify(env); return json({ updatedAt: now });
  }
  if (b.action === "chat") {
    const profile = await env.DB.prepare("SELECT name,last_chat FROM profiles WHERE user_id=?").bind(user.sub).first();
    if (!profile) return json({ error: "Synchronise d'abord ta sauvegarde." }, 400);
    if (now - (profile.last_chat || 0) < 2500) return json({ error: "Attends un peu avant d'envoyer un autre message." }, 429);
    const message = clean(b.message, 180); if (!message) return json({ error: "Message vide." }, 400);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO messages (id,user_id,name,message,created_at,global_flag) VALUES (?,?,?,?,?,0)").bind(crypto.randomUUID(),user.sub,profile.name,message,now),
      env.DB.prepare("UPDATE profiles SET last_chat=? WHERE user_id=?").bind(now,user.sub)
    ]);
    await notify(env,"chat"); return json({ message: "Message envoyé." });
  }
  if (b.action === "gift") {
    const targetName = clean(b.to,24).toLocaleLowerCase("fr");
    const target = await env.DB.prepare("SELECT p.user_id,p.name FROM profiles p WHERE lower(p.name)=lower(?) AND p.user_id<>? LIMIT 1").bind(targetName,user.sub).first();
    if (!target) return json({ error: "Joueur introuvable. Vérifie son nom exact." },404);
    const kind = b.kind === "gems" ? "gems" : "gold", amount = Math.floor(Number(b.amount));
    if (!Number.isFinite(amount) || amount < 1 || amount > 100000) return json({ error: "Montant invalide (1 à 100 000)." },400);
    const profile = await env.DB.prepare("SELECT name,save_json FROM profiles WHERE user_id=?").bind(user.sub).first();
    if (!profile) return json({ error: "Profil introuvable." },404);
    const save = b.save && typeof b.save === "object" ? b.save : JSON.parse(profile.save_json);
    if ((Number(save[kind])||0) < amount) return json({ error: "Tu n'as pas assez de ressources." },400);
    save[kind] = (Number(save[kind])||0)-amount;
    const updated = await env.DB.prepare("UPDATE profiles SET save_json=?,updated_at=? WHERE user_id=? AND CAST(json_extract(?, '$."+kind+"') AS INTEGER)>=?").bind(JSON.stringify(save),now,user.sub,JSON.stringify(b.save||JSON.parse(profile.save_json)),amount).run();
    if (!updated.meta?.changes) return json({ error: "Solde insuffisant ou sauvegarde modifiée. Réessaie." },409);
    await env.DB.prepare("INSERT INTO gifts (id,from_user_id,from_name,to_user_id,kind,amount,created_at,claimed) VALUES (?,?,?,?,?,?,?,0)").bind(crypto.randomUUID(),user.sub,profile.name,target.user_id,kind,amount,now).run();
    await notify(env,"gift"); return json({ message: "Cadeau envoyé." });
  }
  if (b.action === "claimGift") {
    const gift = await env.DB.prepare("SELECT id,kind,amount FROM gifts WHERE id=? AND to_user_id=? AND claimed=0").bind(String(b.giftId||""),user.sub).first();
    if (!gift) return json({ error: "Cadeau introuvable ou déjà récupéré." },404);
    const profile = await env.DB.prepare("SELECT save_json FROM profiles WHERE user_id=?").bind(user.sub).first();
    if (!profile) return json({ error: "Profil introuvable." },404);
    const save = JSON.parse(profile.save_json || "{}"); save[ gift.kind ] = (Number(save[gift.kind])||0)+gift.amount;
    const results = await env.DB.batch([
      env.DB.prepare("UPDATE gifts SET claimed=1,claimed_at=? WHERE id=? AND to_user_id=? AND claimed=0").bind(now,gift.id,user.sub),
      env.DB.prepare("UPDATE profiles SET save_json=?,updated_at=? WHERE user_id=? AND changes()=1").bind(JSON.stringify(save),now,user.sub)
    ]);
    if (!results[0]?.meta?.changes) return json({ error: "Ce cadeau a déjà été récupéré." },409);
    await notify(env,"gift"); return json({ save, message: "Cadeau récupéré." });
  }
  if (b.action === "admin") {
    if (!env.LARP_ADMIN_CODE || String(b.code||"") !== env.LARP_ADMIN_CODE) return json({ error: "Code admin incorrect ou LARP_ADMIN_CODE non configuré." },403);
    const type=b.type;
    if(type==="check") return json({message:"Accès admin autorisé."});
    if(type==="message"){
      const message=clean(b.message,220);if(!message)return json({error:"Message vide."},400);
      await env.DB.prepare("INSERT INTO messages (id,user_id,name,message,created_at,global_flag) VALUES (?,?,?,?,?,1)").bind(crypto.randomUUID(),"ADMIN","👑 ADMIN",message,now).run();
      await notify(env,"announcement");return json({message:"Annonce envoyée à tous les joueurs."});
    }
    if(type==="event"){
      const title=clean(b.title,60),description=clean(b.description,180),kind=["disco","doublegold","doublexp"].includes(b.kind)?b.kind:"normal",minutes=Math.max(1,Math.min(10080,Math.floor(Number(b.minutes)||30)));
      if(!title)return json({error:"Donne un nom à l'événement."},400);
      await env.DB.prepare("INSERT INTO events (id,title,description,kind,starts_at,ends_at,created_by) VALUES (?,?,?,?,?,?,?)").bind(crypto.randomUUID(),title,description,kind,now,now+minutes*60000,"ADMIN").run();
      await notify(env,"event");return json({message:"Événement mondial lancé ! Les joueurs connectés le reçoivent en direct."});
    }
    if(type==="endEvents"){
      await env.DB.prepare("DELETE FROM events").run();await notify(env,"event");return json({message:"Tous les événements ont été arrêtés."});
    }
    if(type==="rewardAll"||type==="givePlayer"){
      const gold=Math.max(0,Math.min(100000000,Math.floor(Number(b.gold)||0))),gems=Math.max(0,Math.min(100000,Math.floor(Number(b.gems)||0)));
      if(!gold&&!gems)return json({error:"Indique une récompense en or ou gemmes."},400);
      let targets=[];
      if(type==="rewardAll") targets=(await env.DB.prepare("SELECT user_id,name FROM profiles").all()).results||[];
      else { const p=await env.DB.prepare("SELECT p.user_id,p.name FROM profiles p WHERE lower(p.name)=lower(?) LIMIT 1").bind(clean(b.player,24)).first();if(!p)return json({error:"Joueur introuvable."},404);targets=[p]; }
      const batch=[];
      for(const p of targets){
        if(gold) batch.push(env.DB.prepare("INSERT INTO gifts (id,from_user_id,from_name,to_user_id,kind,amount,created_at,claimed) VALUES (?,?,?,?,?,?,?,0)").bind(crypto.randomUUID(),"ADMIN","👑 ADMIN",p.user_id,"gold",gold,now));
        if(gems) batch.push(env.DB.prepare("INSERT INTO gifts (id,from_user_id,from_name,to_user_id,kind,amount,created_at,claimed) VALUES (?,?,?,?,?,?,?,0)").bind(crypto.randomUUID(),"ADMIN","👑 ADMIN",p.user_id,"gems",gems,now));
      }
      if(batch.length) await env.DB.batch(batch);
      await env.DB.prepare("INSERT INTO messages (id,user_id,name,message,created_at,global_flag) VALUES (?,?,?,?,?,1)").bind(crypto.randomUUID(),"ADMIN","👑 ADMIN",type==="rewardAll"?`🎁 Cadeau global : ${gold} or et ${gems} gemmes dans vos boîtes aux cadeaux !`:`🎁 Une récompense admin vous attend, ${clean(b.player,24)} !`,now).run();
      await notify(env,"gift");return json({message:type==="rewardAll"?`Récompenses envoyées à ${targets.length} comptes (dans leur boîte aux cadeaux).`:`Récompense envoyée à ${targets[0].name}.`});
    }
    return json({error:"Action admin inconnue."},400);
  }
  return json({error:"Action inconnue."},400);
}
export default {
  async fetch(request, env) {
    const url=new URL(request.url);
    if(url.pathname==="/api/register"&&request.method==="POST") return register(request,env);
    if(url.pathname==="/api/login"&&request.method==="POST") return login(request,env);
    if(url.pathname.startsWith("/api/")){
      const user=await getUser(request,env);if(!user)return json({error:"Session invalide ou expirée. Reconnecte-toi."},401);
      if(url.pathname==="/api/me"&&request.method==="GET"){
        const row=await env.DB.prepare("SELECT id,email,name FROM accounts WHERE id=?").bind(user.sub).first();if(!row)return json({error:"Compte introuvable."},401);return json({user:{id:row.id,email:row.email,name:row.name}});
      }
      if(url.pathname==="/api/world"&&request.method==="GET") return json(await worldFor(user,env));
      if(url.pathname==="/api/action"&&request.method==="POST") return action(request,user,env);
      if(url.pathname==="/api/live"&&request.headers.get("Upgrade")==="websocket"){
        const id=env.LIVE_ROOM.idFromName("larp-global-room");const stub=env.LIVE_ROOM.get(id);
        const headers=new Headers(request.headers);headers.set("X-Authenticated-User",user.sub);
        return stub.fetch(new Request("https://live.internal/ws",{method:"GET",headers}));
      }
      return json({error:"Route API inconnue."},404);
    }
    return env.ASSETS.fetch(request);
  }
};
export class LiveRoom extends DurableObject {
  constructor(ctx, env) { super(ctx, env); this.ctx=ctx; this.env=env; }
  async fetch(request) {
    const url=new URL(request.url);
    if(url.pathname==="/broadcast"&&request.method==="POST"){
      const data=await request.json().catch(()=>({type:"refresh"}));
      const msg=JSON.stringify(data);
      for(const ws of this.ctx.getWebSockets()) { try{ws.send(msg);}catch{try{ws.close(1011,"broadcast failed")}catch{}} }
      return new Response("ok");
    }
    if(url.pathname==="/ws"){
      if(request.headers.get("Upgrade")!=="websocket")return new Response("WebSocket attendu",{status:426});
      if(!request.headers.get("X-Authenticated-User"))return new Response("Non autorisé",{status:401});
      const pair=new WebSocketPair();const client=pair[0],server=pair[1];
      this.ctx.acceptWebSocket(server);server.serializeAttachment({userId:request.headers.get("X-Authenticated-User")});
      server.send(JSON.stringify({type:"connected",at:Date.now()}));
      return new Response(null,{status:101,webSocket:client});
    }
    return new Response("Not found",{status:404});
  }
  webSocketMessage(ws,message){ if(message==="ping"||message instanceof ArrayBuffer && new TextDecoder().decode(message)==="ping") { try{ws.send("pong")}catch{} } }
  webSocketClose(ws){ try{ws.close()}catch{} }
  webSocketError(ws){ try{ws.close(1011,"socket error")}catch{} }
}
