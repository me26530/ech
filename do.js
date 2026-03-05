import { connect } from "cloudflare:sockets";

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

const CF_FALLBACK_IPS = ["proxyip.cmliussss.net:443"];
const encoder = new TextEncoder();

/** limiter 参数 */
const WINDOW_MS = 60_000;                 // 60s 计数窗口
const CONN_TTL_MS = 2 * 60 * 60 * 1000;   // 2h 连接 TTL，防泄漏

/** 你的参数 */
const IDLE_TIMEOUT_MS = 10 * 60 * 1000;   // 10 分钟空闲超时
const BATCH_MAX_BYTES = 32 * 1024;        // 32KB 批处理阈值
const BATCH_MAX_DELAY_MS = 5;             // 5ms 合并延时

export class TunnelProxy {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);

    // --- limiter endpoints ---
    if (url.pathname === "/rl/acquire") return this.rlAcquire(request);
    if (url.pathname === "/rl/release") return this.rlRelease(request);

    // --- websocket tunnel ---
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    server.accept();
    this.handleSession(server, request).catch(() => this.safeCloseWebSocket(server));

    return new Response(null, { status: 101, webSocket: client });
  }

  // ======================
  // 限流（Rate Limit）
  // ======================

  _rlKey(token) {
    return `rl:${token}`;
  }

  async rlAcquire(request) {
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

    const now = Date.now();
    const body = await request.json().catch(() => null);
    if (!body?.token || !body?.connId) return new Response("Bad Request", { status: 400 });

    const token = String(body.token);
    const connId = String(body.connId);

    const maxConcurrent = Number(body.maxConcurrent ?? 30);
    const maxPerMinute = Number(body.maxPerMinute ?? 30);

    const key = this._rlKey(token);

    const result = await this.state.storage.transaction(async (txn) => {
      const cur = (await txn.get(key)) || { conns: {}, recent: [] };

      // prune stale conns
      for (const [id, ts] of Object.entries(cur.conns)) {
        if (typeof ts !== "number" || now - ts > CONN_TTL_MS) delete cur.conns[id];
      }

      // prune recent window
      cur.recent = (cur.recent || []).filter((t) => typeof t === "number" && now - t <= WINDOW_MS);

      const concurrent = Object.keys(cur.conns).length;
      if (concurrent >= maxConcurrent) {
        return { status: 429, msg: `Too many concurrent connections (>${maxConcurrent})` };
      }

      const perMin = cur.recent.length;
      if (perMin >= maxPerMinute) {
        return { status: 429, msg: `Too many new connections per minute (>${maxPerMinute}/min)` };
      }

      // acquire
      cur.conns[connId] = now;
      cur.recent.push(now);

      await txn.put(key, cur);
      return { status: 200, msg: "OK" };
    });

    return new Response(result.msg, { status: result.status });
  }

  async rlRelease(request) {
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

    const body = await request.json().catch(() => null);
    if (!body?.token || !body?.connId) return new Response("Bad Request", { status: 400 });

    const token = String(body.token);
    const connId = String(body.connId);
    const key = this._rlKey(token);

    await this.state.storage.transaction(async (txn) => {
      const cur = (await txn.get(key)) || { conns: {}, recent: [] };
      if (cur?.conns && cur.conns[connId]) delete cur.conns[connId];
      await txn.put(key, cur);
    });

    return new Response("OK", { status: 200 });
  }

  // ======================
  // 隧道（Tunnel）
  // ======================

  async handleSession(webSocket, request) {
    let remoteSocket;
    let remoteWriter;
    let remoteReader;
    let isClosed = false;

    const connId = request.headers.get("X-Conn-Id") || "";
    const authToken = request.headers.get("X-Auth-Token") || "default";

    // --- 空闲超时（10 分钟）---
    let idleTimer = null;
    const touch = () => {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(async () => {
        try { webSocket.send("CLOSE"); } catch {}
        await cleanup();
      }, IDLE_TIMEOUT_MS);
    };
    touch();

    // limiter stub（同 namespace）
    const limiterStub = () => {
      const id = this.env.TUNNEL_PROXY.idFromName("limiter");
      return this.env.TUNNEL_PROXY.get(id);
    };

    const releaseOnce = (() => {
      let released = false;
      return async () => {
        if (released) return;
        released = true;
        if (!connId) return;
        await limiterStub()
          .fetch("https://limiter/rl/release", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ token: authToken, connId }),
          })
          .catch(() => {});
      };
    })();

    // --- WS → TCP 批处理（32KB + 5ms）---
    let pendingChunks = [];
    let pendingBytes = 0;
    let flushTimer = null;
    let flushing = false;

    const resetFlushTimer = () => {
      if (flushTimer) clearTimeout(flushTimer);
      flushTimer = setTimeout(() => {
        flushTimer = null;
        flushToRemote().catch(() => {});
      }, BATCH_MAX_DELAY_MS);
    };

    const enqueueToRemote = (u8) => {
      if (!remoteWriter || !u8 || u8.byteLength === 0) return;

      pendingChunks.push(u8);
      pendingBytes += u8.byteLength;

      if (pendingBytes >= BATCH_MAX_BYTES) {
        if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
        flushToRemote().catch(() => {});
      } else {
        resetFlushTimer();
      }
    };

    const flushToRemote = async () => {
      if (flushing || !remoteWriter) return;
      if (pendingBytes === 0) return;

      flushing = true;
      try {
        const merged = new Uint8Array(pendingBytes);
        let offset = 0;
        for (const chunk of pendingChunks) {
          merged.set(chunk, offset);
          offset += chunk.byteLength;
        }
        pendingChunks = [];
        pendingBytes = 0;

        await remoteWriter.write(merged);
      } catch {
        await cleanup();
      } finally {
        flushing = false;
      }
    };

    // --- cleanup ---
    const cleanup = async () => {
      if (isClosed) return;
      isClosed = true;

      try { if (idleTimer) clearTimeout(idleTimer); } catch {}
      try { if (flushTimer) clearTimeout(flushTimer); } catch {}
      idleTimer = null;
      flushTimer = null;

      try { await flushToRemote(); } catch {}

      try { remoteWriter?.releaseLock(); } catch {}
      try { remoteReader?.releaseLock(); } catch {}
      try { remoteSocket?.close(); } catch {}

      remoteWriter = null;
      remoteReader = null;
      remoteSocket = null;

      this.safeCloseWebSocket(webSocket);
      await releaseOnce();
    };

    const pumpRemoteToWebSocket = async () => {
      try {
        while (!isClosed && remoteReader) {
          const { done, value } = await remoteReader.read();
          if (done) break;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) break;

          if (value?.byteLength > 0) {
            webSocket.send(value);
            touch();
          }
        }
      } catch {}

      if (!isClosed) {
        try { webSocket.send("CLOSE"); } catch {}
        await cleanup();
      }
    };

    const parseAddress = (addr, defaultPort = null) => {
      if (addr.startsWith("[")) {
        const end = addr.indexOf("]");
        if (end === -1) return { host: addr, port: defaultPort };
        const host = addr.substring(1, end);
        const portPart = addr.substring(end + 1);
        if (portPart.startsWith(":")) {
          const port = parseInt(portPart.substring(1), 10);
          return { host, port: Number.isNaN(port) ? defaultPort : port };
        }
        return { host, port: defaultPort };
      }

      const sep = addr.lastIndexOf(":");
      const colonCount = (addr.match(/:/g) || []).length;
      if (colonCount > 1) return { host: addr, port: defaultPort };

      if (sep !== -1) {
        const port = parseInt(addr.substring(sep + 1), 10);
        if (!Number.isNaN(port)) return { host: addr.substring(0, sep), port };
      }

      return { host: addr, port: defaultPort };
    };

    const isCFError = (err) => {
      const msg = err?.message?.toLowerCase?.() || "";
      return msg.includes("proxy request") || msg.includes("cannot connect") || msg.includes("cloudflare");
    };

    const connectToRemote = async (targetAddr, firstFrameData) => {
      const { host: targetHost, port: targetPort } = parseAddress(targetAddr);
      if (!targetHost || !targetPort) throw new Error("Invalid CONNECT target, expected host:port");

      const attempts = [null, ...CF_FALLBACK_IPS];

      for (let i = 0; i < attempts.length; i++) {
        try {
          const attempt = attempts[i];
          let hostname, port;

          if (attempt) {
            const parsed = parseAddress(attempt, targetPort);
            hostname = parsed.host;
            port = parsed.port;
          } else {
            hostname = targetHost;
            port = targetPort;
          }

          remoteSocket = connect({ hostname, port });
          if (remoteSocket.opened) await remoteSocket.opened;

          remoteWriter = remoteSocket.writable.getWriter();
          remoteReader = remoteSocket.readable.getReader();

          if (firstFrameData) await remoteWriter.write(encoder.encode(firstFrameData));

          webSocket.send("CONNECTED");
          touch();
          pumpRemoteToWebSocket();
          return;
        } catch (err) {
          try { remoteWriter?.releaseLock(); } catch {}
          try { remoteReader?.releaseLock(); } catch {}
          try { remoteSocket?.close(); } catch {}
          remoteWriter = null;
          remoteReader = null;
          remoteSocket = null;

          if (!isCFError(err) || i === attempts.length - 1) throw err;
        }
      }
    };

    webSocket.addEventListener("message", async (event) => {
      if (isClosed) return;
      touch();

      try {
        const data = event.data;

        if (typeof data === "string") {
          if (data.startsWith("CONNECT:")) {
            const sep = data.indexOf("|", 8);
            if (sep < 0) throw new Error("Invalid CONNECT frame");
            await connectToRemote(data.substring(8, sep), data.substring(sep + 1));
          } else if (data.startsWith("DATA:")) {
            enqueueToRemote(encoder.encode(data.substring(5)));
          } else if (data === "CLOSE") {
            await cleanup();
          }
        } else if (data instanceof ArrayBuffer) {
          enqueueToRemote(new Uint8Array(data));
        }
      } catch (err) {
        try { webSocket.send("ERROR:" + (err?.message || "Unknown")); } catch {}
        await cleanup();
      }
    });

    webSocket.addEventListener("close", () => { cleanup(); });
    webSocket.addEventListener("error", () => { cleanup(); });
  }

  safeCloseWebSocket(ws) {
    try {
      if (ws.readyState === WS_READY_STATE_OPEN || ws.readyState === WS_READY_STATE_CLOSING) {
        ws.close(1000, "Server closed");
      }
    } catch {}
  }
}
