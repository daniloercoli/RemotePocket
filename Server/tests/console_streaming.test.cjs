const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../app/static/console.js"), "utf8");
const jpeg = new Uint8Array([0xff, 0xd8, 0, 0xfe, 0xff, 0xd9]);

function frame(overrides = {}) {
  const header = new TextEncoder().encode(JSON.stringify({
    type: "screen_frame", sessionId: "session", frameId: 1,
    width: 100, height: 200, format: "jpeg", note: "caffè ☕", ...overrides,
  }));
  const buffer = new ArrayBuffer(4 + header.length + jpeg.length);
  new DataView(buffer).setUint32(0, header.length, true);
  new Uint8Array(buffer, 4, header.length).set(header);
  new Uint8Array(buffer, 4 + header.length).set(jpeg);
  return buffer;
}

function consoleApp() {
  const elements = new Map();
  const blobs = new Map();
  const revoked = [];
  const storage = new Map();
  let nextUrl = 0;
  class FakeWebSocket {
    constructor() { this.binaryType = "blob"; }
    close() {}
    deliver(data) {
      // Emulate the browser default so a missing binaryType assignment fails.
      this.onmessage({ data: data instanceof ArrayBuffer && this.binaryType === "blob"
        ? new Blob([data]) : data });
    }
  }
  const scope = vm.createContext({
    Blob, ArrayBuffer, Uint8Array, DataView, TextDecoder,
    setInterval() {}, setTimeout() {}, clearTimeout() {},
    console: { info() {}, debug() {}, error() {} },
    localStorage: { getItem: key => storage.get(key), removeItem(key) {storage.delete(key);}, setItem(key,value) {storage.set(key,value);} },
    navigator: {locks: {request: (_name, work) => work()}},
    location: { protocol: "http:", host: "localhost" },
    WebSocket: FakeWebSocket,
    URL: {
      createObjectURL(blob) {
        const url = `blob:frame-${++nextUrl}`;
        blobs.set(url, blob);
        return url;
      },
      revokeObjectURL: (url) => revoked.push(url),
    },
    document: {
      createElement() { return { setAttribute() {}, appendChild() {} }; },
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, { appendChild() {}, removeAttribute(name) { delete this[name]; } });
        return elements.get(id);
      },
      querySelectorAll: () => [],
    },
  });
  vm.runInContext(source, scope);
  vm.runInContext("state.token = 'test'; connectConsoleWs();", scope);
  const ws = vm.runInContext("state.ws", scope);
  const start = (socket = ws, sessionId = "session") => {
    vm.runInContext("state.pendingDeviceAuth.set('device', {ws: state.ws, serverProof: 'test-server-proof'})", scope);
    return socket.deliver(JSON.stringify({
      type: "session_started", sessionId, deviceId: "device", serverProof: "test-server-proof",
    }));
  };
  return { ws, scope, elements, blobs, revoked, start };
}

test("binary WebSocket frames render the exact JPEG with UTF-8 metadata", async () => {
  const app = consoleApp();
  app.start();
  app.ws.deliver(frame());
  const image = app.elements.get("screenImage");
  assert.equal(image.hidden, false);
  assert.equal(app.elements.get("screenEmpty").hidden, true);
  assert.equal(app.elements.get("frameInfo").textContent, "frame 1 - 100x200");
  const blob = app.blobs.get(image.src);
  assert.equal(blob.type, "image/jpeg");
  assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), jpeg);
  assert.equal(vm.runInContext("state.frameWidth", app.scope), 100);
  assert.equal(vm.runInContext("state.frameHeight", app.scope), 200);
});

test("invalid binary packets leave the displayed frame intact", () => {
  const app = consoleApp();
  app.start();
  app.ws.deliver(frame());
  const firstUrl = app.elements.get("screenImage").src;
  const wrongLength = frame();
  new DataView(wrongLength).setUint32(0, 0xffffffff, true);
  for (const buffer of [new ArrayBuffer(0), new ArrayBuffer(4), wrongLength,
    frame({ width: 0 }), frame({ height: true }), frame({ format: "png" }),
    frame({ frameId: -1 }), frame({ type: "heartbeat" })]) {
    app.ws.deliver(buffer);
    assert.equal(app.elements.get("screenImage").src, firstUrl);
  }
  assert.equal(app.blobs.size, 1);
});

test("frames from absent, other or ended sessions are ignored", () => {
  const app = consoleApp();
  app.ws.deliver(frame());
  app.start();
  app.ws.deliver(frame({ sessionId: "other" }));
  app.ws.deliver(JSON.stringify({ type: "session_end", sessionId: "session", reason: "user_closed" }));
  app.ws.deliver(frame());
  assert.equal(app.blobs.size, 0);
  assert.equal(app.elements.get("screenImage").hidden, true);
});

test("object URLs are released on replacement, session end and disconnect", () => {
  const app = consoleApp();
  app.start();
  app.ws.deliver(frame());
  app.ws.deliver(frame({ frameId: 2 }));
  assert.deepEqual(app.revoked, ["blob:frame-1"]);
  app.ws.deliver(JSON.stringify({ type: "session_end", sessionId: "session", reason: "user_closed" }));
  assert.deepEqual(app.revoked, ["blob:frame-1", "blob:frame-2"]);
  assert.equal(app.elements.get("screenImage").src, undefined);
  app.start();
  app.ws.deliver(frame());
  app.ws.onclose();
  assert.deepEqual(app.revoked, ["blob:frame-1", "blob:frame-2", "blob:frame-3"]);
  assert.equal(vm.runInContext("state.sessionId", app.scope), "");
});

test("events from a replaced socket cannot clear the new session", () => {
  const app = consoleApp();
  vm.runInContext("connectConsoleWs();", app.scope);
  const current = vm.runInContext("state.ws", app.scope);
  app.start(current, "new-session");
  current.deliver(frame({ sessionId: "new-session" }));
  app.ws.onclose();
  app.ws.deliver(JSON.stringify({ type: "session_end", reason: "old-socket" }));
  assert.equal(vm.runInContext("state.sessionId", app.scope), "new-session");
  assert.equal(app.elements.get("screenImage").hidden, false);
  assert.deepEqual(app.revoked, []);
});


test("logout refreshes an expired access token before revoking the session", async () => {
  const app = consoleApp();
  const requests = [];
  app.scope.fetch = async (url, options) => {
    requests.push({ url, options });
    const expired = requests.length === 1;
    return { ok: !expired, status: expired ? 401 : 200,
      json: async () => url === "/api/auth/refresh"
        ? { access_token: "renewed-access", refresh_token: "rotated-refresh" }
        : { detail: "Expired" } };
  };
  vm.runInContext("saveTokens({access_token: 'test', refresh_token: 'original-refresh'});", app.scope);
  await vm.runInContext("logout()", app.scope);
  assert.deepEqual(requests.map(r => r.url), ["/api/auth/logout", "/api/auth/refresh", "/api/auth/logout"]);
  assert.equal(requests[2].options.headers.Authorization, "Bearer renewed-access");
  assert.equal(JSON.parse(requests[2].options.body).refresh_token, "rotated-refresh");
  assert.equal(vm.runInContext("state.token", app.scope), "");
  assert.equal(vm.runInContext("state.refreshToken", app.scope), "");
});

test("logout clears local credentials and reports an unconfirmed server revocation", async () => {
  const app = consoleApp();
  app.scope.fetch = async () => { throw new Error("network unavailable"); };
  vm.runInContext("saveTokens({access_token: 'test', refresh_token: 'original-refresh'});", app.scope);
  await assert.rejects(vm.runInContext("logout()", app.scope), /revoca sul server non confermata/);
  assert.equal(vm.runInContext("state.token", app.scope), "");
  assert.equal(vm.runInContext("state.refreshToken", app.scope), "");
});


test("three sessions keep separate frames and closing A preserves B", () => {
  const app = consoleApp();
  for (const id of ["A", "B", "C"]) { app.start(app.ws, id); app.ws.deliver(frame({sessionId: id})); }
  vm.runInContext("selectSession('B')", app.scope);
  const before = app.elements.get("screenImage").src;
  app.ws.deliver(JSON.stringify({type: "session_end", sessionId: "A", reason: "closed"}));
  assert.equal(app.elements.get("screenImage").src, before);
  assert.equal(vm.runInContext("state.sessions.size", app.scope), 2);
  app.ws.deliver(frame({sessionId: "C", frameId: 2}));
  assert.equal(app.elements.get("screenImage").src, before);
  assert.equal(app.revoked.length, 2);
});

test("concurrent HTTP requests share a single refresh", async () => {
  const app = consoleApp(); let refreshes = 0;
  vm.runInContext("saveTokens({access_token: 'test', refresh_token: 'refresh'});", app.scope);
  app.scope.fetch = async (url, options) => {
    if (url === "/api/auth/refresh") { refreshes++; return {ok:true,json:async()=>({access_token:"new",refresh_token:"next"})}; }
    const ok = options.headers.Authorization === "Bearer new";
    return {ok,status:ok?200:401,json:async()=>({})};
  };
  await Promise.all([vm.runInContext("getJson('/a')", app.scope), vm.runInContext("getJson('/b')", app.scope)]);
  assert.equal(refreshes, 1);
});

test("a refresh completing after logout cannot restore credentials", async () => {
  const app = consoleApp(); let resolveFetch;
  app.scope.fetch = (url) => url === '/api/auth/refresh'
    ? new Promise(resolve => { resolveFetch = resolve; })
    : Promise.resolve({ok:true,json:async()=>({})});
  vm.runInContext("saveTokens({access_token: 'test', refresh_token: 'old-refresh'});", app.scope);
  const pending = vm.runInContext("refreshAuth()", app.scope);
  vm.runInContext("state.authEpoch += 1; state.token = ''; state.refreshToken = '';", app.scope);
  resolveFetch({ok:true,json:async()=>({access_token:'stale-access',refresh_token:'stale-refresh'})});
  await assert.rejects(pending, /Autenticazione sostituita/);
  assert.equal(vm.runInContext("state.token", app.scope), '');
  assert.equal(vm.runInContext("state.refreshToken", app.scope), '');
});

test("uncertain mutations are never replayed", async () => {
  const app = consoleApp(); let calls = 0;
  app.scope.fetch = async () => { calls++; throw new Error('Response lost'); };
  await assert.rejects(vm.runInContext("postJson('/api/devices/test/revoke', {})", app.scope), /Response lost/);
  assert.equal(calls, 1);
});
