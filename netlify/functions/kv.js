import { getStore } from "@netlify/blobs";

// Backend simples de key-value usando Netlify Blobs.
// GET  /.netlify/functions/kv?key=db        -> { value: "<json string>" | null }
// POST /.netlify/functions/kv?key=db  body:{ value: "<json string>" } -> { ok:true }
//      (POST exige o header "x-admin-key" batendo com a env var ADMIN_KEY)
//
// GET fica público de propósito: o app precisa dele pra validar login de
// usuários comuns sem precisar de um endpoint de autenticação server-side.
// Só a escrita (criação/revogação de keys, feita no painel admin) é protegida.
//
// IMPORTANTE: configure a env var ADMIN_KEY no painel do Netlify
// (Site settings > Environment variables) com o MESMO valor da constante
// `adminKey` no index.html. Sem essa env var configurada, toda escrita é
// recusada por padrão (fail-closed) — o site não fica gravável "por acidente".

export default async (req) => {
  const url = new URL(req.url);
  const key = url.searchParams.get("key");

  if (!key) {
    return new Response(JSON.stringify({ error: "missing ?key=" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const store = getStore("app-data");

  if (req.method === "GET") {
    const value = await store.get(key);
    return new Response(JSON.stringify({ value: value ?? null }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }

  if (req.method === "POST") {
    const adminKey = process.env.ADMIN_KEY;
    const provided = req.headers.get("x-admin-key");

    if (!adminKey || provided !== adminKey) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }

    let body;
    try {
      body = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: "invalid json body" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    await store.set(key, body.value ?? "");
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }

  return new Response(JSON.stringify({ error: "method not allowed" }), {
    status: 405,
    headers: { "Content-Type": "application/json" }
  });
};

export const config = { path: "/.netlify/functions/kv" };
