import { TunnelProxy } from "./do.js";

export { TunnelProxy };

const TOKEN = "1105074071";

// 固定分片数（Shard Count）
const SHARD_COUNT = 4;

// 限流参数
const MAX_CONCURRENT = 30; // 最大并发连接
const MAX_PER_MINUTE = 30; // 每分钟新建连接数

function fnv1a32(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/**
 * 选择分片（Shard）——不使用 IP
 * 优先级：
 * 1) ?shard=0..N-1 直接指定
 * 2) ?sk=xxx 自定义分片键
 * 3) Header: X-Shard-Key
 * 4) Sec-WebSocket-Key（WebSocket 握手自带，默认兜底）
 */
function pickShard(request) {
  const url = new URL(request.url);

  const shardParam = url.searchParams.get("shard");
  if (shardParam != null) {
    const n = Number(shardParam);
    if (Number.isFinite(n)) return ((n % SHARD_COUNT) + SHARD_COUNT) % SHARD_COUNT;
  }

  const sk = url.searchParams.get("sk");
  if (sk) return fnv1a32(sk) % SHARD_COUNT;

  const headerKey = request.headers.get("X-Shard-Key");
  if (headerKey) return fnv1a32(headerKey) % SHARD_COUNT;

  const wsKey = request.headers.get("Sec-WebSocket-Key") || "fallback";
  return fnv1a32(wsKey) % SHARD_COUNT;
}

async function rateLimitAcquire(env, token, connId) {
  const limiterId = env.TUNNEL_PROXY.idFromName("limiter");
  const limiter = env.TUNNEL_PROXY.get(limiterId);

  return limiter.fetch("https://limiter/rl/acquire", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      token,
      connId,
      maxConcurrent: MAX_CONCURRENT,
      maxPerMinute: MAX_PER_MINUTE,
    }),
  });
}

async function rateLimitRelease(env, token, connId) {
  const limiterId = env.TUNNEL_PROXY.idFromName("limiter");
  const limiter = env.TUNNEL_PROXY.get(limiterId);

  // best-effort
  await limiter
    .fetch("https://limiter/rl/release", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, connId }),
    })
    .catch(() => {});
}

export default {
  async fetch(request, env, ctx) {
    try {
      const upgradeHeader = request.headers.get("Upgrade");

      // 非 WebSocket 请求：保持原行为
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
        return new URL(request.url).pathname === "/"
          ? new Response("Welcome to nginx!", {
              status: 200,
              headers: { "Content-Type": "text/html" },
            })
          : new Response("Expected WebSocket", { status: 426 });
      }

      // 鉴权：保持原行为（Sec-WebSocket-Protocol 必须等于 TOKEN）
      const proto = request.headers.get("Sec-WebSocket-Protocol");
      if (TOKEN && proto !== TOKEN) return new Response("Unauthorized", { status: 401 });

      // 先申请限流令牌
      const connId = crypto.randomUUID();
      const rlResp = await rateLimitAcquire(env, proto || "default", connId);
      if (!rlResp.ok) {
        const msg = await rlResp.text().catch(() => "Rate limited");
        return new Response(msg, { status: rlResp.status || 429 });
      }

      // 固定分片路由
      const shard = pickShard(request);
      const id = env.TUNNEL_PROXY.idFromName(`shard-${shard}`);
      const stub = env.TUNNEL_PROXY.get(id);

      // 把 connId / token 传给 DO，便于 close 时释放
      const newHeaders = new Headers(request.headers);
      newHeaders.set("X-Conn-Id", connId);
      newHeaders.set("X-Auth-Token", proto || "default");

      const forwarded = new Request(request, { headers: newHeaders });

      const resp = await stub.fetch(forwarded);

      // 如果升级失败，释放令牌（避免占用并发计数）
      if (resp.status !== 101) {
        ctx.waitUntil(rateLimitRelease(env, proto || "default", connId));
      }

      return resp;
    } catch (err) {
      return new Response(err?.toString?.() || "Internal Error", { status: 500 });
    }
  },
};
