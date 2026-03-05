import { TunnelProxy } from "./do.js";

export { TunnelProxy };

// 鉴权 token：保持你原来的逻辑
const TOKEN = "1105074071";

// ✅ 固定分片数（Shard Count）= 4
const SHARD_COUNT = 4;

/** FNV-1a 32-bit hash：轻量、稳定 */
function fnv1a32(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/**
 * 选择分片（Shard）——不使用 IP（IP），不改客户端也能用
 * 优先级：
 * 1) ?shard=0..N-1 直接指定
 * 2) ?sk=xxx 自定义分片键
 * 3) X-Shard-Key header
 * 4) Sec-WebSocket-Key（WebSocket（WS）握手必带）
 */
function pickShard(request) {
  const url = new URL(request.url);

  // 1) 强制分片号（调试/固定路由）
  const shardParam = url.searchParams.get("shard");
  if (shardParam != null) {
    const n = Number(shardParam);
    if (Number.isFinite(n)) {
      return ((n % SHARD_COUNT) + SHARD_COUNT) % SHARD_COUNT;
    }
  }

  // 2) 自定义分片键（sk）
  const sk = url.searchParams.get("sk");
  if (sk) return fnv1a32(sk) % SHARD_COUNT;

  // 3) Header 自定义分片键
  const headerKey = request.headers.get("X-Shard-Key");
  if (headerKey) return fnv1a32(headerKey) % SHARD_COUNT;

  // 4) 兜底：WebSocket（WS）握手必带的 Sec-WebSocket-Key
  const wsKey = request.headers.get("Sec-WebSocket-Key") || "fallback";
  return fnv1a32(wsKey) % SHARD_COUNT;
}

export default {
  async fetch(request, env, ctx) {
    try {
      const upgradeHeader = request.headers.get("Upgrade");

      // 非 WebSocket（WS）请求：保持原行为
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
        return new URL(request.url).pathname === "/"
          ? new Response("Welcome to nginx!", {
              status: 200,
              headers: { "Content-Type": "text/html" },
            })
          : new Response("Expected WebSocket", { status: 426 });
      }

      // 鉴权：保持原行为（要求 Sec-WebSocket-Protocol == token）
      if (TOKEN && request.headers.get("Sec-WebSocket-Protocol") !== TOKEN) {
        return new Response("Unauthorized", { status: 401 });
      }

      // ✅ 固定分片：idFromName("shard-x")，不再 newUniqueId()
      const shard = pickShard(request);
      const id = env.TUNNEL_PROXY.idFromName(`shard-${shard}`);
      const stub = env.TUNNEL_PROXY.get(id);

      return stub.fetch(request);
    } catch (err) {
      return new Response(err?.toString?.() || "Internal Error", { status: 500 });
    }
  },
};
