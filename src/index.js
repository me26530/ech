var __defProp = Object.defineProperty;
var __name = (target, value) =>
  __defProp(target, "name", { value, configurable: true });

// src/index.js
import { DurableObject } from "cloudflare:workers";
import { connect } from "cloudflare:sockets";

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

/**
 * ECH-Workers 客户端身份令牌
 * 对应客户端里的：身份令牌
 */
var CLIENT_TOKEN = "1105074071";

/**
 * 管理接口令牌
 * /api/cleanup/list?admin=CHANGE_ME_ADMIN_TOKEN
 * POST /api/cleanup?admin=CHANGE_ME_ADMIN_TOKEN
 * 如果不想管理接口鉴权，可以改成：var ADMIN_TOKEN = "";
 */
var ADMIN_TOKEN = "CHANGE_ME_ADMIN_TOKEN";

/** cleanup/list 最多返回最近多少条 */
var CLEANUP_LIST_LIMIT = 100;

/** 默认清理多久以前的记录：1 天 */
var CLEANUP_RETENTION_MS = 24 * 60 * 60 * 1000;

/** Cloudflare fallback IP，保留 ECH 原版逻辑 */
const CF_FALLBACK_IPS = ["fdip.houyitfg.top"];

const encoder = new TextEncoder();

var TcpProxy = class extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
  }

  /**
   * ECH-Workers 客户端协议：
   * WebSocket URL：wss://你的域名/
   * Header：Sec-WebSocket-Protocol: 身份令牌
   * 首帧：CONNECT:host:port|firstData
   * 后续：binary frame / DATA:xxx / CLOSE
   */
  async fetch(request) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get("Upgrade");

    if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
      return url.pathname === "/"
        ? new Response("WebSocket Proxy Server", { status: 200 })
        : new Response("Expected WebSocket", { status: 426 });
    }

    const protocol = request.headers.get("Sec-WebSocket-Protocol");
    if (CLIENT_TOKEN && protocol !== CLIENT_TOKEN) {
      return new Response("Unauthorized", { status: 401 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    server.accept();

    this.handleSession(server).catch((err) => {
      console.error("[DO] session error:", err?.message || err);
      safeCloseWebSocket(server);
    });

    const responseInit = { status: 101, webSocket: client };

    if (CLIENT_TOKEN) {
      responseInit.headers = { "Sec-WebSocket-Protocol": CLIENT_TOKEN };
    }

    return new Response(null, responseInit);
  }

  async handleSession(webSocket) {
    let remoteSocket = null;
    let remoteWriter = null;
    let remoteReader = null;
    let connected = false;
    let isClosed = false;
    let writeChain = Promise.resolve();

    const cleanup = () => {
      if (isClosed) return;
      isClosed = true;
      try { remoteWriter?.releaseLock(); } catch {}
      try { remoteReader?.releaseLock(); } catch {}
      try { remoteSocket?.close(); } catch {}
      remoteWriter = null;
      remoteReader = null;
      remoteSocket = null;
      safeCloseWebSocket(webSocket);
    };

    const writeToRemote = async (chunk) => {
      if (!remoteWriter || isClosed) return;
      writeChain = writeChain.then(async () => {
        if (!remoteWriter || isClosed) return;
        await remoteWriter.write(chunk);
      });
      return writeChain;
    };

    const pumpRemoteToWebSocket = async () => {
      try {
        while (!isClosed && remoteReader) {
          const { done, value } = await remoteReader.read();
          if (done) break;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) break;
          if (value?.byteLength > 0) webSocket.send(value);
        }
      } catch {}

      if (!isClosed) {
        try { webSocket.send("CLOSE"); } catch {}
        cleanup();
      }
    };

    const connectToRemote = async (targetAddr, firstFrameData = "") => {
      if (connected) throw new Error("Already connected");

      const { host, port } = parseAddress(targetAddr);
      if (!host || isNaN(port) || port <= 0 || port > 65535) {
        throw new Error("Invalid target address");
      }

      const attempts = [null, ...CF_FALLBACK_IPS];
      let lastError = null;

      for (let i = 0; i < attempts.length; i++) {
        try {
          let hostname = attempts[i] || host;

          if (!attempts[i]) {
            if (hostname.startsWith("[") && hostname.endsWith("]")) {
              hostname = hostname.slice(1, -1);
            }
            if (hostname.includes(":")) {
              hostname = `${hostname.replace(/:/g, "-")}.sslip.io`;
            }
          }

          remoteSocket = connect({ hostname, port });
          if (remoteSocket.opened) await remoteSocket.opened;

          remoteSocket.closed.catch((err) => {
            if (err?.message?.includes("currently being piped to")) return;
            if (!isClosed) {
              console.error("[TCP] socket closed with error:", err?.message || err);
            }
          });

          remoteWriter = remoteSocket.writable.getWriter();
          remoteReader = remoteSocket.readable.getReader();
          connected = true;

          await this.updateTarget(`${host}:${port}`);

          if (firstFrameData) {
            await writeToRemote(encoder.encode(firstFrameData));
          }

          webSocket.send("CONNECTED");
          pumpRemoteToWebSocket();
          return;
        } catch (err) {
          lastError = err;
          try { remoteWriter?.releaseLock(); } catch {}
          try { remoteReader?.releaseLock(); } catch {}
          try { remoteSocket?.close(); } catch {}
          remoteWriter = null;
          remoteReader = null;
          remoteSocket = null;

          if (!isCFError(err) || i === attempts.length - 1) {
            throw err;
          }
        }
      }

      throw lastError || new Error("TCP connect failed");
    };

    webSocket.addEventListener("message", async (event) => {
      if (isClosed) return;

      try {
        const data = event.data;

        if (typeof data === "string") {
          if (data.startsWith("CONNECT:")) {
            const sep = data.indexOf("|", 8);
            const targetAddr = sep >= 0 ? data.substring(8, sep) : data.substring(8);
            const firstFrameData = sep >= 0 ? data.substring(sep + 1) : "";
            await connectToRemote(targetAddr, firstFrameData);
            return;
          }

          if (data.startsWith("DATA:")) {
            if (remoteWriter) await writeToRemote(encoder.encode(data.substring(5)));
            return;
          }

          if (data === "CLOSE") {
            cleanup();
            return;
          }

          return;
        }

        if (data instanceof ArrayBuffer && remoteWriter) {
          await writeToRemote(new Uint8Array(data));
          return;
        }

        if (data instanceof Uint8Array && remoteWriter) {
          await writeToRemote(data);
          return;
        }
      } catch (err) {
        try { webSocket.send("ERROR:" + (err?.message || String(err))); } catch {}
        cleanup();
      }
    });

    webSocket.addEventListener("close", cleanup);
    webSocket.addEventListener("error", cleanup);
  }

  /** 连接成功后更新 ECH_DB 里的 target。 */
  async updateTarget(target) {
    try {
      if (!this.env?.ECH_DB) return;
      await this.env.ECH_DB.prepare(
        "UPDATE do_instances SET target = ? WHERE id = ?"
      )
        .bind(target, this.ctx.id.toString())
        .run();
    } catch (e) {
      console.error("[D1] Failed to update target:", e?.message || e);
    }
  }

  /** RPC: 清理此 DO 实例的所有持久化存储。 */
  async cleanup() {
    await this.ctx.storage.deleteAll();
    return { ok: true };
  }
};

__name(TcpProxy, "TcpProxy");

var src_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const upgradeHeader = request.headers.get("Upgrade");
    const isWebSocket = upgradeHeader && upgradeHeader.toLowerCase() === "websocket";

    /** 只要是 WebSocket Upgrade，就交给 Durable Object：ECH_DL。 */
    if (isWebSocket) {
      const id = env.ECH_DL.newUniqueId();
      const stub = env.ECH_DL.get(id);

      try {
        await env.ECH_DB.prepare(
          "INSERT INTO do_instances (id, created_at, target) VALUES (?, ?, ?)"
        )
          .bind(id.toString(), new Date().toISOString(), "unknown")
          .run();
      } catch (e) {
        console.error("[D1] Failed to record DO instance:", e?.message || e);
      }

      return stub.fetch(request);
    }

    if (path === "/") {
      return new Response("WebSocket Proxy Server", { status: 200 });
    }

    /** GET /api/cleanup/list?admin=CHANGE_ME_ADMIN_TOKEN */
    if (path === "/api/cleanup/list" && request.method === "GET") {
      if (!checkAdmin(request, url)) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }

      try {
        const totalResult = await env.ECH_DB.prepare(
          "SELECT COUNT(*) AS total FROM do_instances"
        ).first();

        const result = await env.ECH_DB.prepare(
          "SELECT id, created_at, target FROM do_instances ORDER BY created_at DESC LIMIT ?"
        )
          .bind(CLEANUP_LIST_LIMIT)
          .all();

        return Response.json({
          total: totalResult?.total || 0,
          returned: result.results.length,
          limit: CLEANUP_LIST_LIMIT,
          instances: result.results,
        });
      } catch (e) {
        return Response.json({ error: e.message }, { status: 500 });
      }
    }

    /** POST /api/cleanup?admin=... 或 POST /api/cleanup?all=1&admin=... */
    if (path === "/api/cleanup" && request.method === "POST") {
      if (!checkAdmin(request, url)) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }

      try {
        const cleanAll = url.searchParams.get("all") === "1";
        const summary = await cleanInstances(env, {
          cleanAll,
          olderThanMs: CLEANUP_RETENTION_MS,
        });
        return Response.json(summary);
      } catch (e) {
        return Response.json({ error: e.message }, { status: 500 });
      }
    }

    return new Response("Not Found", { status: 404 });
  },

  /** 定时任务：自动清理 1 天前的 do_instances 记录。 */
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      cleanInstances(env, {
        cleanAll: false,
        olderThanMs: CLEANUP_RETENTION_MS,
        source: "scheduled",
      })
    );
  },
};

function checkAdmin(request, url) {
  if (!ADMIN_TOKEN) return true;
  const queryToken = url.searchParams.get("admin");
  const headerToken = request.headers.get("X-Admin-Token");
  return queryToken === ADMIN_TOKEN || headerToken === ADMIN_TOKEN;
}

async function cleanInstances(
  env,
  { cleanAll = false, olderThanMs = CLEANUP_RETENTION_MS, source = "manual" } = {}
) {
  const cutoff = new Date(Date.now() - olderThanMs).toISOString();

  const result = cleanAll
    ? await env.ECH_DB.prepare("SELECT id FROM do_instances").all()
    : await env.ECH_DB.prepare("SELECT id FROM do_instances WHERE created_at < ?")
        .bind(cutoff)
        .all();

  const ids = result.results.map((r) => r.id);
  let cleaned = 0;
  let failed = 0;
  const errors = [];

  for (const hexId of ids) {
    try {
      const doId = env.ECH_DL.idFromString(hexId);
      const stub = env.ECH_DL.get(doId);
      await stub.cleanup();

      await env.ECH_DB.prepare("DELETE FROM do_instances WHERE id = ?")
        .bind(hexId)
        .run();

      cleaned++;
    } catch (e) {
      failed++;
      const errorItem = { id: hexId, error: e?.message || String(e) };
      errors.push(errorItem);
      console.error("[Cleanup] Failed:", errorItem);
    }
  }

  const summary = {
    source,
    mode: cleanAll ? "all" : "older_than_1_day",
    cutoff: cleanAll ? null : cutoff,
    matched: ids.length,
    cleaned,
    failed,
    errors,
  };

  console.log("[Cleanup] summary:", summary);
  return summary;
}

function parseAddress(addr) {
  if (!addr) throw new Error("Empty target address");

  /** IPv6：[2606:4700::6810:85e5]:443 */
  if (addr[0] === "[") {
    const end = addr.indexOf("]");
    if (end < 0) throw new Error("Invalid IPv6 address");
    return {
      host: addr.substring(1, end),
      port: parseInt(addr.substring(end + 2), 10),
    };
  }

  /** IPv4 / 域名：example.com:443 */
  const sep = addr.lastIndexOf(":");
  if (sep < 0) throw new Error("Missing port");
  return {
    host: addr.substring(0, sep),
    port: parseInt(addr.substring(sep + 1), 10),
  };
}

function isCFError(err) {
  const msg = err?.message?.toLowerCase() || "";
  return (
    msg.includes("proxy request") ||
    msg.includes("cannot connect") ||
    msg.includes("cloudflare")
  );
}

function safeCloseWebSocket(ws) {
  try {
    if (
      ws.readyState === WS_READY_STATE_OPEN ||
      ws.readyState === WS_READY_STATE_CLOSING
    ) {
      ws.close(1000, "Server closed");
    }
  } catch {}
}

export { TcpProxy, src_default as default };
