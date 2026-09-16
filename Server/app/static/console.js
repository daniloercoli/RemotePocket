const AUTH_STORAGE_KEY = "mydesk.auth";
function savedTokens() {
  try {
    const record = localStorage.getItem(AUTH_STORAGE_KEY);
    if (record) return JSON.parse(record);
  } catch { return {}; }
  return {access_token: localStorage.getItem("mydesk.ownerToken") || "",
    refresh_token: localStorage.getItem("mydesk.refreshToken") || ""};
}
function loginSession(tokens) {
  if (tokens.session_id) return tokens.session_id;
  try { return JSON.parse(atob(tokens.access_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).sid || ""; }
  catch { return ""; }
}
function initialAuthentication() {
  const tokens = savedTokens();
  return {token: tokens.access_token || "", refreshToken: tokens.refresh_token || "", loginSessionId: loginSession(tokens)};
}
const state = {
  ...initialAuthentication(),
  ws: null,
  sessions: new Map(),
  activeSessionId: "",
  sessionId: "",
  devices: [],
  authEpoch: 0,
  authContextEpoch: 0,
  challenge: "",
  wsAuthRetried: false,
  pendingDevices: new Set(),
  pendingDeviceAuth: new Map(),
  reconnectDelay: 1000,
  reconnectTimer: null,
  refreshPromise: null,
  devicesLoading: false,
  deviceId: "",
  frameWidth: 0,
  frameHeight: 0,
  lastFrameUrl: null,
};

const $ = (id) => document.getElementById(id);

function log(message) {
  $("log").textContent = `${new Date().toLocaleTimeString()}  ${message}`;
}

function saveTokens(data, persist = true) {
  state.token = data.access_token;
  state.refreshToken = data.refresh_token || "";
  state.loginSessionId = loginSession(data);
  if (!persist) return;
  localStorage.setItem("mydesk.ownerToken", state.token);
  localStorage.setItem("mydesk.refreshToken", state.refreshToken);
  // Publish both tokens atomically; legacy keys are retained for existing installations.
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify({...data, session_id: state.loginSessionId}));
}

async function refreshAuth() {
  if (!state.refreshToken) throw Object.assign(new Error("Accedi nuovamente."), {status: 401});
  if (!state.refreshPromise) {
    const epoch = state.authEpoch;
    const original = {refresh_token: state.refreshToken, session_id: state.loginSessionId};
    const denied = message => Object.assign(new Error(message), {status: 401});
    const rotate = async () => {
      if (epoch !== state.authEpoch) throw new Error("Autenticazione sostituita.");
      const saved = savedTokens();
      if (saved.refresh_token !== original.refresh_token) {
        if (original.session_id && loginSession(saved) === original.session_id && !saved.refresh_pending) {
          saveTokens(saved, false);
          return;
        }
        syncStoredAuthentication();
        throw denied("Sessione modificata in un'altra scheda. Accedi nuovamente.");
      }
      if (saved.refresh_pending) throw denied("Rinnovo non confermato. Accedi nuovamente.");
      // A crash or lost response must never cause another tab to replay this token.
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify({...saved, refresh_pending: true}));
      let data;
      try { data = await postJson("/api/auth/refresh", {refresh_token: saved.refresh_token}, false); }
      catch (error) {
        // These responses precede token consumption (rate-limit dependency).
        if ([429, 503].includes(error.status)) {
          if (savedTokens().refresh_token === saved.refresh_token) localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(saved));
          throw error;
        }
        syncStoredAuthentication();
        throw denied("Rinnovo non confermato. Accedi nuovamente.");
      }
      if (epoch !== state.authEpoch || savedTokens().refresh_token !== saved.refresh_token) {
        if (epoch === state.authEpoch) syncStoredAuthentication();
        await discardTokens(data);
        throw new Error("Autenticazione sostituita.");
      }
      saveTokens(data);
    };
    const pending = (globalThis.navigator?.locks
      ? navigator.locks.request("mydesk-refresh", rotate)
      : Promise.reject(denied("Rinnovo automatico non disponibile. Usa HTTPS o accedi nuovamente.")))
      .finally(() => { if (state.refreshPromise === pending) state.refreshPromise = null; });
    state.refreshPromise = pending;
  }
  return state.refreshPromise;
}

async function requestJson(url, method = "GET", body, authenticated = true, accessToken) {
  const epoch = state.authEpoch;
  if (authenticated && accessToken === undefined && state.refreshPromise) {
    await state.refreshPromise;
    if (epoch !== state.authEpoch) throw new Error("Autenticazione sostituita.");
  }
  const response = await fetch(url, {
    method,
    ...(url === "/api/auth/refresh" && globalThis.AbortSignal?.timeout ? {signal: AbortSignal.timeout(15000)} : {}),
    headers: {"Content-Type": "application/json", ...(authenticated ? {Authorization: `Bearer ${accessToken ?? state.token}`} : {})},
    ...(body === undefined ? {} : {body: JSON.stringify(body)}),
  });
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(typeof data.detail === "string" ? data.detail : "Richiesta non valida");
    error.status = response.status;
    throw error;
  }
  return data;
}

async function postJson(url, body, authenticated = true) {
  // Mutations are never replayed automatically after an uncertain result.
  return requestJson(url, "POST", body, authenticated);
}

async function getJson(url) {
  const token = state.token;
  const epoch = state.authEpoch;
  try { return await requestJson(url); }
  catch (error) {
    if (error.status !== 401 || epoch !== state.authEpoch) throw error;
    if (state.token === token) await refreshAuth();
    if (epoch !== state.authEpoch) throw new Error("Autenticazione sostituita.");
    return requestJson(url);
  }
}

function clearCredentials(message = "Accedi nuovamente.", {automatic = false, preserveStored = false} = {}) {
  state.authEpoch += 1;
  // Automatic expiry invalidates session requests, but can precede the HTTP
  // response carrying newly generated MFA recovery codes for this account.
  if (!automatic) state.authContextEpoch += 1;
  state.token = "";
  state.refreshToken = "";
  state.loginSessionId = "";
  state.refreshPromise = null;
  state.challenge = "";
  state.wsAuthRetried = false;
  if (!preserveStored) {
    localStorage.removeItem("mydesk.ownerToken");
    localStorage.removeItem("mydesk.refreshToken");
    localStorage.removeItem(AUTH_STORAGE_KEY);
  }
  if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
  state.reconnectTimer = null;
  const ws = state.ws;
  state.ws = null;
  if (ws) ws.close();
  clearSession(message);
  state.devices = [];
  state.devicesLoading = false;
  $("devices").textContent = "";
  $("pairingCode").textContent = "Nessun codice generato.";
  $("connectionBadge").textContent = "non connesso";
  $("connectionBadge").className = "status";
  for (const id of ["username", "password", "email", "loginCode", "textInput", "deviceSearch"]) $(id).value = "";
  $("mfaLogin").hidden = true;
  if (typeof clearAccountState === "function") clearAccountState({preserveRecovery: automatic});
}

function syncStoredAuthentication() {
  if (!state.token) return;
  const saved = savedTokens();
  if (saved.refresh_token === state.refreshToken ||
      (state.loginSessionId && loginSession(saved) === state.loginSessionId)) {
    if (saved.access_token && !saved.refresh_pending) saveTokens(saved, false);
    return;
  }
  clearCredentials("Sessione modificata in un'altra scheda. Accedi nuovamente.",
    {automatic: true, preserveStored: true});
}
globalThis.addEventListener?.("storage", event => {
  if (event.key === AUTH_STORAGE_KEY || event.key === null) syncStoredAuthentication();
});

async function revokeTokens(tokens) {
  if (!tokens.access_token || !tokens.refresh_token) return;
  const revoke = data => requestJson("/api/auth/logout", "POST", {refresh_token: data.refresh_token}, true, data.access_token);
  try {
    try { await revoke(tokens); }
    catch (error) {
      if (error.status !== 401) throw error;
      // Refresh only the captured session, without installing it in the console.
      const renewed = await postJson("/api/auth/refresh", {refresh_token: tokens.refresh_token}, false);
      await revoke(renewed);
    }
  } catch (error) { if (error.status !== 401) throw error; }
}

async function discardTokens(data) {
  try { await revokeTokens(data); }
  catch { console.error("Revoca della sessione obsoleta non confermata."); }
}

async function acceptAuthentication(data, epoch) {
  if (epoch !== state.authEpoch) { await discardTokens(data); return false; }
  if (data.mfa_required) {
    state.challenge = data.challenge_token;
    $("mfaLogin").hidden = false;
    $("loginCode").focus();
    $("password").value = "";
    return false;
  }
  clearCredentials();
  saveTokens(data);
  const acceptedEpoch = state.authEpoch;
  connectConsoleWs();
  await refreshDevices();
  if (acceptedEpoch !== state.authEpoch) return false;
  log("Owner autenticato.");
  return true;
}

async function login(endpoint, credentials) {
  credentials ??= {username: $("username").value, password: $("password").value,
    ...(endpoint.endsWith("bootstrap") && $("email").value ? {email: $("email").value} : {})};
  clearCredentials();
  const epoch = state.authEpoch;
  try {
    return await acceptAuthentication(await postJson(endpoint, credentials, false), epoch);
  } catch (error) {
    if (epoch === state.authEpoch) $("authStatus").textContent = error.message;
    throw error;
  }
}

async function logout() {
  const tokens = {access_token: state.token, refresh_token: state.refreshToken};
  clearCredentials("Logout completato.");
  try { await revokeTokens(tokens); }
  catch (error) { throw new Error(`Credenziali locali rimosse; revoca sul server non confermata: ${error.message}`); }
}

function connectConsoleWs() {
  if (!state.token) return;
  if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
  state.reconnectTimer = null;
  if (state.ws) state.ws.close();
  clearSession("Connessione console in corso.");
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${protocol}://${location.host}/console/ws`, ["mydesk", `bearer.${state.token}`]);
  const reconnectDelayOnConnect = state.reconnectDelay;
  let opened = false;
  ws.binaryType = "arraybuffer";
  state.ws = ws;

  const retryLater = () => {
    if (state.ws !== ws || !state.token) return;
    if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
    state.reconnectTimer = setTimeout(() => {
      if (state.ws !== ws || !state.token) return;
      state.reconnectTimer = null;
      connectConsoleWs();
    }, state.reconnectDelay);
    state.reconnectDelay = Math.min(30000, state.reconnectDelay * 2);
  };

  ws.onopen = () => {
    if (state.ws !== ws) return;
    opened = true;
    state.wsAuthRetried = false;
    state.reconnectDelay = 1000;
    $("connectionBadge").textContent = "console connessa";
    $("connectionBadge").className = "status online";
    console.info("Console WebSocket connected");
    ws.send(JSON.stringify({ type: "device_list_request" }));
  };

  ws.onclose = (event = {}) => {
    if (state.ws !== ws) return;
    clearSession("Connessione console chiusa.");
    $("connectionBadge").textContent = "non connesso";
    $("connectionBadge").className = "status";
    console.info("Console WebSocket disconnected");
    if (!state.token) return;
    if ([4429, 1013].includes(event.code)) {
      state.reconnectDelay = Math.max(5000, reconnectDelayOnConnect);
      log("Limite di connessione o servizio temporaneamente non disponibile. Riprovo tra poco.");
      retryLater();
      return;
    }
    const authDenied = [4001, 4003, 4401, 4403, 1008].includes(event.code);
    // Browsers also report transient upgrade failures as 1006. Try refreshing
    // once, but keep reconnecting with backoff if credentials were renewed.
    if (authDenied || (!opened && !state.wsAuthRetried && state.refreshToken)) {
      if (state.wsAuthRetried || !state.refreshToken) {
        clearCredentials("Accedi nuovamente.", {automatic: true});
        return;
      }
      state.wsAuthRetried = true;
      refreshAuth().then(() => { if (state.ws === ws) connectConsoleWs(); })
        .catch(error => {
          if (state.ws !== ws) return;
          if (error.status === 401 || error.status === 403) {
            clearCredentials("Accedi nuovamente.", {automatic: true});
            return;
          }
          // A rejected, unconsumed refresh can be retried after backoff.
          state.wsAuthRetried = false;
          retryLater();
        });
    } else {
      retryLater();
    }
  };

  ws.onmessage = (event) => {
    if (state.ws !== ws) return;
    if (event.data instanceof ArrayBuffer) {
      handleBinaryMessage(event.data);
    } else {
      return handleWsMessage(JSON.parse(event.data));
    }
  };
}

function handleWsMessage(message) {
  if (message.type === "device_list") {
    renderDevices(message.devices);
  } else if (message.type === "session_challenge") {
    return answerDeviceChallenge(message);
  } else if (message.type === "session_started") {
    const pending = state.pendingDeviceAuth.get(message.deviceId);
    if (!pending || pending.ws !== state.ws || !pending.serverProof || pending.serverProof !== message.serverProof) {
      state.ws?.close();
      clearSession("Verifica del server fallita. Riconnetti la console.");
      return;
    }
    forgetDeviceAuth(message.deviceId);
    if (!state.sessions.has(message.sessionId)) {
      state.sessions.set(message.sessionId, {sessionId: message.sessionId, deviceId: message.deviceId,
        frameWidth: 0, frameHeight: 0, frameId: -1, lastFrameUrl: null, closing: false});
    }
    selectSession(message.sessionId);
    const card = Array.from($("devices").children || []).find(node => node.dataset.id === message.deviceId);
    if (card) card.querySelector("[data-error]").textContent = "Sessione aperta.";
    log("Sessione aperta.");
  } else if (message.type === "session_end") {
    closeSession(message.sessionId);
    log(`Sessione chiusa: ${message.reason}`);
  } else if (message.type === "session_error" || message.type === "error_event") {
    forgetDeviceAuth(message.deviceId);
    const errorText = message.message || message.code || "Errore sessione";
    const card = Array.from($("devices").children || []).find(node => node.dataset.id === message.deviceId);
    if (card) card.querySelector("[data-error]").textContent = errorText;
    log(errorText);
  }
}

function handleBinaryMessage(buffer) {
  try {
    if (buffer.byteLength < 4) throw new Error("Missing frame header length");
    const view = new DataView(buffer);
    const headerLength = view.getUint32(0, true);
    if (!headerLength || headerLength > 16 * 1024 || 4 + headerLength >= buffer.byteLength) {
      throw new Error("Invalid frame header length or empty image");
    }
    const headerBytes = new Uint8Array(buffer, 4, headerLength);
    const headerText = new TextDecoder("utf-8", { fatal: true }).decode(headerBytes);
    const header = JSON.parse(headerText);
    if (!header || header.type !== "screen_frame" || header.format !== "jpeg" ||
        !Number.isInteger(header.width) || header.width <= 0 ||
        !Number.isInteger(header.height) || header.height <= 0 ||
        !Number.isInteger(header.frameId) || header.frameId < 0) {
      throw new Error("Invalid screen frame header");
    }
    const session = state.sessions.get(header.sessionId);
    if (!session || session.closing || header.frameId <= session.frameId) return;

    session.frameWidth = header.width;
    session.frameHeight = header.height;
    session.frameId = header.frameId;
    const jpegData = new Uint8Array(buffer, 4 + headerLength);
    const url = URL.createObjectURL(new Blob([jpegData], {type: "image/jpeg"}));
    if (session.lastFrameUrl) URL.revokeObjectURL(session.lastFrameUrl);
    session.lastFrameUrl = url;
    if (state.activeSessionId === session.sessionId) showSession();
  } catch (error) {
    console.error("Failed to parse binary message:", error);
  }
}

async function refreshDevices() {
  if (!state.token || state.devicesLoading) return;
  state.devicesLoading = true;
  const epoch = state.authEpoch;
  try {
    const data = await getJson("/api/devices");
    if (epoch === state.authEpoch && state.token) renderDevices(data.devices);
  }
  finally { if (epoch === state.authEpoch) state.devicesLoading = false; }
}

function renderDevices(devices) {
  state.devices = devices;
  const root = $("devices");
  const existing = new Map(Array.from(root.children || []).map(node => [node.dataset.id, node]));
  const search = ($("deviceSearch").value || "").toLocaleLowerCase();
  const status = $("deviceStatus").value;
  const sorted = [...devices].sort((a, b) => $("deviceSort").value === "seen"
    ? (b.last_seen_at || "").localeCompare(a.last_seen_at || "") : a.name.localeCompare(b.name));
  let position = 0;
  for (const device of sorted) {
    let item = existing.get(device.id);
    if (!item) {
      item = document.createElement("div");
      item.className = "device-card";
      item.dataset.id = device.id;
      item.innerHTML = `<h3></h3><span class="status"></span>
        <label>Nome<input data-name="${escapeHtml(device.id)}" maxlength="200" /></label>
        <button data-rename="${escapeHtml(device.id)}">Rinomina</button>
        <label>Password dispositivo<input type="password" autocomplete="off" data-password="${escapeHtml(device.id)}" /></label>
        <div class="row"><button data-start="${escapeHtml(device.id)}">Apri sessione</button>
        <button class="danger" data-revoke="${escapeHtml(device.id)}">Revoca</button></div>
        <details><summary>Dettagli</summary><pre></pre></details><p data-error role="status"></p>`;
      item.querySelector("[data-name]").value = device.name;
    }
    item.querySelector("h3").textContent = device.name;
    item.querySelector(".status").textContent = device.status;
    item.querySelector("[data-start]").disabled = device.status !== "online" || state.pendingDevices.has(device.id) || Array.from(state.sessions.values()).some(session => session.deviceId === device.id);
    item.querySelector("[data-revoke]").disabled = !!device.revoked_at;
    item.querySelector("pre").textContent = JSON.stringify({id: device.id, capacita: device.capabilities,
      creato: device.created_at, ultima_presenza: device.last_seen_at}, null, 2);
    item.hidden = (!!status && status !== device.status) || !`${device.name} ${device.id}`.toLocaleLowerCase().includes(search);
    // Move existing nodes without replacing editable fields.
    if (root.children[position] !== item) root.insertBefore(item, root.children[position] || null);
    position += 1;
    existing.delete(device.id);
  }
  for (const node of existing.values()) node.remove();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char];
  });
}

function sendWs(message) {
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
    log("WebSocket console non connessa.");
    return;
  }
  const session = state.sessions.get(message.sessionId);
  if (message.type.startsWith("input_") && (!session || session.closing || session.sessionId !== state.activeSessionId)) return;
  state.ws.send(JSON.stringify(message));
  return true;
}

function forgetDeviceAuth(deviceId) {
  const pending = state.pendingDeviceAuth.get(deviceId);
  if (pending) {
    pending.key = null;
    clearTimeout(pending.timer);
    state.pendingDeviceAuth.delete(deviceId);
  }
  state.pendingDevices.delete(deviceId);
}

function deviceAuthIsCurrent(deviceId, pending) {
  return state.pendingDeviceAuth.get(deviceId) === pending &&
    state.ws === pending.ws && state.authEpoch === pending.epoch;
}

function failDeviceAuth(deviceId, pending, message) {
  if (!deviceAuthIsCurrent(deviceId, pending)) return;
  handleWsMessage({type: "session_error", deviceId, message});
  const card = Array.from($("devices").children || []).find(node => node.dataset.id === deviceId);
  if (card) card.querySelector("[data-start]").disabled = false;
}

async function startDeviceSession(deviceId, field) {
  if (state.pendingDevices.has(deviceId)) return;
  if (!globalThis.crypto?.subtle) {
    field.value = "";
    throw new Error("Per aprire una sessione usa la console su HTTPS o localhost.");
  }
  const bytes = new TextEncoder().encode(field.value);
  field.value = "";
  const pending = {ws: state.ws, epoch: state.authEpoch, clientNonce: DeviceAuth.nonce(), key: null};
  state.pendingDevices.add(deviceId);
  state.pendingDeviceAuth.set(deviceId, pending);
  pending.timer = setTimeout(() => failDeviceAuth(deviceId, pending, "Autenticazione scaduta. Riprova."), 60000);
  try {
    const key = await DeviceAuth.importPassword(bytes);
    if (!deviceAuthIsCurrent(deviceId, pending)) return;
    pending.key = key;
    if (!sendWs({type: "session_challenge_request", deviceId, clientNonce: pending.clientNonce})) {
      failDeviceAuth(deviceId, pending, "WebSocket console non connessa.");
    }
  } catch {
    failDeviceAuth(deviceId, pending, "Autenticazione dispositivo non disponibile.");
  } finally { bytes.fill(0); }
}

async function answerDeviceChallenge(message) {
  const pending = state.pendingDeviceAuth.get(message.deviceId);
  if (!pending || !pending.key || pending.busy || !deviceAuthIsCurrent(message.deviceId, pending)) return;
  pending.busy = true;
  const key = pending.key;
  pending.key = null;
  try {
    if (message.clientNonce !== pending.clientNonce || !/^[a-f0-9]{128}$/.test(message.nonce) ||
        !message.nonce.startsWith(pending.clientNonce) || message.iterations !== 600000 ||
        typeof message.challengeId !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(message.challengeId)) {
      throw new Error("Invalid challenge");
    }
    const result = await DeviceAuth.proof(key, message);
    if (!deviceAuthIsCurrent(message.deviceId, pending)) return;
    pending.serverProof = result.serverProof;
    if (!sendWs({type: "session_start_request", deviceId: message.deviceId,
      challengeId: message.challengeId, proof: result.proof})) {
      failDeviceAuth(message.deviceId, pending, "WebSocket console non connessa.");
    }
  } catch {
    failDeviceAuth(message.deviceId, pending, "Challenge dispositivo non valida.");
  }
}

function clearFrame() {
  state.frameWidth = 0;
  state.frameHeight = 0;
  $("screenImage").removeAttribute("src");
  if (state.lastFrameUrl) URL.revokeObjectURL(state.lastFrameUrl);
  state.lastFrameUrl = null;
  $("screenImage").hidden = true;
  $("screenEmpty").hidden = false;
  $("frameInfo").textContent = "nessun frame";
  $("frameInfo").className = "status";
}

function renderTabs() {
  const root = $("sessionTabs");
  root.textContent = "";
  for (const session of state.sessions.values()) {
    const button = document.createElement("button");
    button.textContent = `${state.devices.find(device => device.id === session.deviceId)?.name || session.deviceId}${session.closing ? " (chiusura)" : ""}`;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-selected", String(session.sessionId === state.activeSessionId));
    button.onclick = () => selectSession(session.sessionId);
    root.appendChild(button);
  }
}

function showSession() {
  const session = state.sessions.get(state.activeSessionId);
  state.sessionId = session?.sessionId || "";
  state.deviceId = session?.deviceId || "";
  state.frameWidth = session?.frameWidth || 0;
  state.frameHeight = session?.frameHeight || 0;
  state.lastFrameUrl = session?.lastFrameUrl || null;
  $("sessionTitle").textContent = session ? `Sessione ${state.devices.find(device => device.id === session.deviceId)?.name || session.deviceId}` : "Nessuna sessione";
  $("screenImage").hidden = !state.lastFrameUrl;
  $("screenEmpty").hidden = !!state.lastFrameUrl;
  if (state.lastFrameUrl) $("screenImage").src = state.lastFrameUrl;
  else $("screenImage").removeAttribute("src");
  $("frameInfo").textContent = session?.lastFrameUrl ? `frame ${session.frameId} - ${session.frameWidth}x${session.frameHeight}` : "nessun frame";
  $("endSessionButton").disabled = !session || session.closing;
  $("sendTextButton").disabled = !session || session.closing;
  document.querySelectorAll("[data-action]").forEach(button => { button.disabled = !session || session.closing; });
}

function selectSession(id) {
  state.activeSessionId = id;
  showSession();
  renderTabs();
}

function closeSession(id) {
  const session = state.sessions.get(id);
  if (!session) return;
  if (session.lastFrameUrl) URL.revokeObjectURL(session.lastFrameUrl);
  state.sessions.delete(id);
  if (state.activeSessionId === id) state.activeSessionId = state.sessions.keys().next().value || "";
  showSession();
  renderTabs();
}

function clearSession(reason) {
  for (const session of state.sessions.values()) if (session.lastFrameUrl) URL.revokeObjectURL(session.lastFrameUrl);
  state.sessions.clear();
  for (const deviceId of state.pendingDeviceAuth.keys()) forgetDeviceAuth(deviceId);
  state.pendingDevices.clear();
  state.activeSessionId = "";
  showSession();
  renderTabs();
  log(reason);
}

$("logoutButton").onclick = () => logout().catch((error) => log(error.message));
$("loginButton").onclick = () => login("/api/auth/login").catch((error) => log(error.message));
$("bootstrapButton").onclick = () => login("/api/auth/bootstrap").catch((error) => log(error.message));

$("pairingButton").onclick = async () => {
  const epoch = state.authEpoch;
  try {
    const data = await postJson("/api/pairing-codes", {});
    if (epoch !== state.authEpoch) return;
    $("pairingCode").textContent = `Codice: ${data.code}\nScade: ${data.expires_at}`;
    log("Pairing code generato.");
  } catch (error) {
    if (epoch === state.authEpoch) log(error.message);
  }
};

$("refreshButton").onclick = () => refreshDevices().catch((error) => log(error.message));

$("devices").onclick = async (event) => {
  const startId = event.target.dataset.start;
  const revokeId = event.target.dataset.revoke;
  if (startId) {
    event.target.disabled = true;
    const error = event.target.closest(".device-card").querySelector("[data-error]");
    error.textContent = "Apertura in corso…";
    try { await startDeviceSession(startId, document.querySelector(`[data-password="${startId}"]`)); }
    catch (failure) { error.textContent = failure.message; event.target.disabled = false; }
  }
  const renameId = event.target.dataset.rename;
  if (renameId) {
    try {
      await requestJson(`/api/devices/${renameId}`, "PATCH", {name: event.target.closest(".device-card").querySelector("[data-name]").value});
      await refreshDevices();
    } catch (error) { log(error.message); }
  }
  if (revokeId && confirm("Revocare questo dispositivo e terminare la sua sessione?")) {
    try {
      await postJson(`/api/devices/${revokeId}/revoke`, {});
      await refreshDevices();
      log("Device revocato.");
    } catch (error) {
      log(error.message);
    }
  }
};

$("screenImage").onclick = (event) => {
  if (!state.sessionId || !state.frameWidth || !state.frameHeight) return;
  const rect = event.currentTarget.getBoundingClientRect();
  const x = Math.round(((event.clientX - rect.left) / rect.width) * state.frameWidth);
  const y = Math.round(((event.clientY - rect.top) / rect.height) * state.frameHeight);
  sendWs({
    type: "input_tap",
    sessionId: state.sessionId,
    x,
    y,
    screenWidth: state.frameWidth,
    screenHeight: state.frameHeight,
  });
};

document.querySelectorAll("[data-action]").forEach((button) => {
  button.onclick = () => {
    if (!state.sessionId) return;
    sendWs({ type: "input_global_action", sessionId: state.sessionId, action: button.dataset.action });
  };
});

$("sendTextButton").onclick = () => {
  if (!state.sessionId) return;
  sendWs({ type: "input_text", sessionId: state.sessionId, text: $("textInput").value });
};

$("endSessionButton").onclick = () => {
  if (!state.sessionId) return;
  sendWs({ type: "session_end", sessionId: state.sessionId, reason: "user_closed" });
  state.sessions.get(state.sessionId).closing = true;
  showSession();
  renderTabs();
};

if (state.token) {
  const epoch = state.authEpoch;
  connectConsoleWs();
  refreshDevices().catch(error => {
    if (epoch !== state.authEpoch) return;
    if (error.status === 401 || error.status === 403) clearCredentials("Accedi nuovamente.", {automatic: true});
    else log(error.message);
  });
}

for (const id of ["deviceSearch", "deviceStatus", "deviceSort"]) $(id).oninput = () => renderDevices(state.devices);
setInterval(() => { if (!document.hidden && state.token) refreshDevices().catch(error => log(error.message)); }, 5000);

$("sessionTabs").onkeydown = (event) => {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key) || !state.sessions.size) return;
  event.preventDefault();
  const ids = [...state.sessions.keys()];
  let index = ids.indexOf(state.activeSessionId);
  index = event.key === "Home" ? 0 : event.key === "End" ? ids.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + ids.length) % ids.length;
  selectSession(ids[index]);
  $("sessionTabs").children[index].focus();
};
showSession();
