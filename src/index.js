var __defProp = Object.defineProperty;
var __name = (target, value) =>
  __defProp(target, "name", { value, configurable: true });

// src/index.js
import { DurableObject } from "cloudflare:workers";

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

/** Cloudflare fallback IP，裸 IPv6，不带 [] */
const CF_FALLBACK_IPS = ["fdip.houyitfg.top"];

const encoder = new TextEncoder();

/**
 * 使用你指定的参数
 */
const CFG = {
  id: "2523c510-9ff0-415b-9582-93949bfae7e3",
  chunk: 64 * 1024,
  dnPack: 32 * 1024,
  dnTail: 512,
  dnMs: 0,
  upPack: 16 * 1024,
  upQMax: 256 * 1024,
  maxED: 8 * 1024,
  concur: 4,
};

function toU8(data) {
  if (data instanceof Uint8Array) return data;

  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }

  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }

  return encoder.encode(String(data));
}

/**
 * 上行队列：
 * WebSocket -> TCP
 */
function mkQ(cap, qCap = cap, itemsMax = Math.max(1, qCap >> 8)) {
  let q = [];
  let h = 0;
  let qB = 0;
  let buf = null;

  const trim = () => {
    if (h > 32 && h * 2 >= q.length) {
      q = q.slice(h);
      h = 0;
    }
  };

  const take = () => {
    if (h >= q.length) return null;

    const d = q[h];
    q[h++] = undefined;
    qB -= d.byteLength;

    trim();
    return d;
  };

  return {
    get bytes() {
      return qB;
    },

    get size() {
      return q.length - h;
    },

    get empty() {
      return h >= q.length;
    },

    clear() {
      q = [];
      h = 0;
      qB = 0;
      buf = null;
    },

    sow(d) {
      const n = d?.byteLength || 0;

      if (!n) return 1;

      if (qB + n > qCap || q.length - h >= itemsMax) {
        return 0;
      }

      q.push(d);
      qB += n;
      return 1;
    },

    bundle(d) {
      d ||= take();

      if (!d || h >= q.length || d.byteLength >= cap) {
        return [d, 0];
      }

      let n = d.byteLength;
      let e = h;

      while (e < q.length) {
        const x = q[e];
        const nn = n + x.byteLength;

        if (nn > cap) break;

        n = nn;
        e++;
      }

      if (e === h) {
        return [d, 0];
      }

      const out = buf ||= new Uint8Array(cap);
      out.set(d);

      for (let o = d.byteLength; h < e;) {
        const x = q[h];

        q[h++] = undefined;
        qB -= x.byteLength;

        out.set(x, o);
        o += x.byteLength;
      }

      trim();

      return [out.subarray(0, n), 1];
    },
  };
}

/**
 * 下行打包：
 * TCP -> WebSocket
 *
 * 注意：这里没有背压，没有 bufferedAmount 等待。
 */
function mkDn(w) {
  const cap = CFG.dnPack;
  const tail = CFG.dnTail;
  const low = Math.max(4096, tail << 3);

  let pb = new Uint8Array(cap);
  let p = 0;
  let tp = 0;
  let mq = 0;
  let gen = 0;
  let qk = 0;
  let qr = 0;

  const reap = () => {
    if (tp) {
      clearTimeout(tp);
      tp = 0;
    }

    mq = 0;

    if (!p) return;

    if (w.readyState === WS_READY_STATE_OPEN) {
      w.send(pb.subarray(0, p).slice());
    }

    pb = new Uint8Array(cap);
    p = 0;
    qr = 0;
  };

  const ripen = () => {
    if (tp || mq) return;

    mq = 1;
    qk = gen;

    queueMicrotask(() => {
      mq = 0;

      if (!p || tp) return;

      if (cap - p < tail) {
        reap();
        return;
      }

      tp = setTimeout(() => {
        tp = 0;

        if (!p) return;

        if (cap - p < tail) {
          reap();
          return;
        }

        if (qr < 2 && (gen !== qk || p < low)) {
          qr++;
          qk = gen;
          ripen();
          return;
        }

        reap();
      }, Math.max(CFG.dnMs, 1));
    });
  };

  return {
    send(u) {
      let o = 0;
      const n = u?.byteLength || 0;

      if (!n) return;

      while (o < n) {
        if (!p && n - o >= cap) {
          const m = Math.min(cap, n - o);

          if (w.readyState === WS_READY_STATE_OPEN) {
            w.send(o || m !== n ? u.subarray(o, o + m) : u);
          }

          o += m;
          continue;
        }

        const m = Math.min(cap - p, n - o);

        pb.set(u.subarray(o, o + m), p);

        p += m;
        o += m;
        gen++;

        if (p === cap || cap - p < tail) {
          reap();
        } else {
          ripen();
        }
      }
    },

    reap,

    cancel() {
      if (tp) {
        clearTimeout(tp);
        tp = 0;
      }

      p = 0;
      mq = 0;
      qr = 0;
    },
  };
}

/**
 * BYOB 下行读取：
 * TCP readable -> WebSocket
 *
 * 不加背压。
 */
async function mill(readable, webSocket, onDone) {
  let reader = null;
  let byob = false;
  const tx = mkDn(webSocket);
  let buf = new ArrayBuffer(CFG.chunk);

  try {
    try {
      reader = readable.getReader({ mode: "byob" });
      byob = true;
    } catch {
      reader = readable.getReader();
      byob = false;
    }

    for (;;) {
      let done;
      let v;

      if (byob) {
        if (!buf || buf.byteLength < CFG.chunk) {
          buf = new ArrayBuffer(CFG.chunk);
        }

        const res = await reader.read(new Uint8Array(buf, 0, CFG.chunk));

        done = res.done;
        v = res.value;
      } else {
        const res = await reader.read();

        done = res.done;
        v = res.value;
      }

      if (done) break;

      if (webSocket.readyState !== WS_READY_STATE_OPEN) break;
      if (!v?.byteLength) continue;

      if (v.byteLength >= CFG.chunk >> 1) {
        tx.reap();

        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          webSocket.send(v);
        }

        buf = new ArrayBuffer(CFG.chunk);
      } else {
        tx.send(v.slice());

        try {
          buf = v.buffer;
        } catch {
          buf = new ArrayBuffer(CFG.chunk);
        }
      }
    }

    tx.reap();
  } catch {
  } finally {
    try {
      tx.reap();
    } catch {}

    try {
      reader?.releaseLock();
    } catch {}

    if (onDone) {
      onDone();
    }
  }
}

/**
 * 使用 request.fetcher.connect()
 */
function sprout(fetcher, hostname, port) {
  const s = fetcher.connect({ hostname, port });

  if (s.opened) {
    return s.opened.then(() => s);
  }

  return Promise.resolve(s);
}

function raceSprout(fetcher, hostname, port) {
  if (!fetcher?.connect) {
    return Promise.reject(new Error("request.fetcher.connect unavailable"));
  }

  if (CFG.concur <= 1) {
    return sprout(fetcher, hostname, port);
  }

  const tasks = Array.from(
    { length: CFG.concur },
    () => sprout(fetcher, hostname, port)
  );

  return Promise.any(tasks).then((winner) => {
    for (const task of tasks) {
      task.then(
        (s) => {
          if (s !== winner) {
            try {
              s.close();
            } catch {}
          }
        },
        () => {}
      );
    }

    return winner;
  });
}

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

    const fetcher = request.fetcher;

    if (!fetcher?.connect) {
      return new Response("request.fetcher.connect unavailable", {
        status: 500,
      });
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    try {
      server.accept({ allowHalfOpen: true });
    } catch {
      server.accept();
    }

    try {
      server.binaryType = "arraybuffer";
    } catch {}

    this.handleSession(server, fetcher).catch((err) => {
      console.error("[DO] session error:", err?.message || err);
      safeCloseWebSocket(server);
    });

    const responseInit = { status: 101, webSocket: client };

    if (CLIENT_TOKEN) {
      responseInit.headers = {
        "Sec-WebSocket-Protocol": CLIENT_TOKEN,
      };
    }

    return new Response(null, responseInit);
  }

  async handleSession(webSocket, fetcher) {
    let remoteSocket = null;
    let remoteWriter = null;
    let connected = false;
    let isClosed = false;
    let busy = false;

    const uq = mkQ(CFG.upPack, CFG.upQMax, CFG.upQMax >> 8);

    const cleanup = () => {
      if (isClosed) return;

      isClosed = true;

      uq.clear();

      try {
        remoteWriter?.releaseLock();
      } catch {}

      try {
        remoteSocket?.close();
      } catch {}

      remoteWriter = null;
      remoteSocket = null;

      safeCloseWebSocket(webSocket);
    };

    const enqueueUpload = (data) => {
      const u = toU8(data);
      const n = u.byteLength;

      if (!n) return true;

      if (uq.sow(u)) {
        return true;
      }

      cleanup();
      return false;
    };

    const drainUpload = async () => {
      if (busy || isClosed) return;

      busy = true;

      try {
        for (;;) {
          if (isClosed) break;
          if (!remoteWriter) break;

          const [d] = uq.bundle();

          if (!d) break;

          await remoteWriter.write(d);
        }
      } catch (err) {
        console.error("[WS->TCP] upload drain error:", err?.message || err);
        cleanup();
      } finally {
        busy = false;

        if (!uq.empty && !isClosed && remoteWriter) {
          queueMicrotask(() => {
            drainUpload().catch(() => cleanup());
          });
        }
      }
    };

    const connectToRemote = async (targetAddr, firstFrameData = "") => {
      if (connected) {
        throw new Error("Already connected");
      }

      const { host, port } = parseAddress(targetAddr);

      if (!host || isNaN(port) || port <= 0 || port > 65535) {
        throw new Error("Invalid target address");
      }

      const attempts = [null, ...CF_FALLBACK_IPS];
      let lastError = null;

      for (let i = 0; i < attempts.length; i++) {
        try {
          let hostname = attempts[i] || host;

          if (hostname.startsWith("[") && hostname.endsWith("]")) {
            hostname = hostname.slice(1, -1);
          }

          if (!attempts[i] && hostname.includes(":")) {
            hostname = `${hostname.replace(/:/g, "-")}.sslip.io`;
          }

          remoteSocket = await raceSprout(fetcher, hostname, port);

          remoteSocket.closed.catch((err) => {
            if (err?.message?.includes("currently being piped to")) return;

            if (!isClosed) {
              console.error("[TCP] socket closed with error:", err?.message || err);
            }
          });

          remoteWriter = remoteSocket.writable.getWriter();
          connected = true;

          /**
           * 不阻塞建连
           */
          this.ctx.waitUntil(this.updateTarget(`${host}:${port}`));

          if (firstFrameData) {
            enqueueUpload(encoder.encode(firstFrameData));
            drainUpload().catch(() => cleanup());
          }

          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            webSocket.send("CONNECTED");
          }

          mill(remoteSocket.readable, webSocket, cleanup).catch(() => cleanup());

          return;
        } catch (err) {
          lastError = err;

          try {
            remoteWriter?.releaseLock();
          } catch {}

          try {
            remoteSocket?.close();
          } catch {}

          remoteWriter = null;
          remoteSocket = null;
          connected = false;

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
            if (remoteWriter) {
              if (enqueueUpload(encoder.encode(data.substring(5)))) {
                drainUpload().catch(() => cleanup());
              }
            }

            return;
          }

          if (data === "CLOSE") {
            cleanup();
            return;
          }

          return;
        }

        if (remoteWriter) {
          if (enqueueUpload(data)) {
            drainUpload().catch(() => cleanup());
          }
        }
      } catch (err) {
        try {
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            webSocket.send("ERROR:" + (err?.message || String(err)));
          }
        } catch {}

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
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const upgradeHeader = request.headers.get("Upgrade");
    const isWebSocket = upgradeHeader && upgradeHeader.toLowerCase() === "websocket";

    /**
     * 只要是 WebSocket Upgrade，就交给 Durable Object：ECH_DL。
     */
    if (isWebSocket) {
      const id = env.ECH_DL.newUniqueId();
      const stub = env.ECH_DL.get(id);

      if (env.ECH_DB) {
        ctx.waitUntil(
          env.ECH_DB.prepare(
            "INSERT INTO do_instances (id, created_at, target) VALUES (?, ?, ?)"
          )
            .bind(id.toString(), new Date().toISOString(), "unknown")
            .run()
            .catch((e) => {
              console.error("[D1] Failed to record DO instance:", e?.message || e);
            })
        );
      }

      return stub.fetch(request);
    }

    if (path === "/") {
      return new Response("WebSocket Proxy Server", { status: 200 });
    }

    /**
     * GET /api/cleanup/list?admin=CHANGE_ME_ADMIN_TOKEN
     */
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

    /**
     * POST /api/cleanup?admin=...
     * POST /api/cleanup?all=1&admin=...
     */
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

  /**
   * 定时任务：自动清理 1 天前的 do_instances 记录。
   */
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

      const errorItem = {
        id: hexId,
        error: e?.message || String(e),
      };

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

  /**
   * IPv6：[2606:4700::6810:85e5]:443
   */
  if (addr[0] === "[") {
    const end = addr.indexOf("]");

    if (end < 0) throw new Error("Invalid IPv6 address");

    return {
      host: addr.substring(1, end),
      port: parseInt(addr.substring(end + 2), 10),
    };
  }

  /**
   * IPv4 / 域名：example.com:443
   */
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
