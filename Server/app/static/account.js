let linkToken = "", linkAction = "", recoveryEpoch = 0, qrUrl = null, activityCursor = null, activityLoading = false;
let activityEpoch = 0, activityFilterKey = null, activityPages = 0;
const activityFilterIds = ["activityStart", "activityEnd", "activityType", "activityDevice"];
const fragment = new URLSearchParams(location.hash.slice(1));
for (const action of ["reset", "verify"]) if (fragment.has(action)) { linkToken = fragment.get(action); linkAction = action; }
if (location.hash) history.replaceState(null, "", location.pathname + location.search);
$("recoveryPanel").open = !!linkAction;
$("consumeReset").hidden = linkAction !== "reset";
$("consumeVerify").hidden = linkAction !== "verify";
function actionButton(id, statusId, operation) {
  $(id).onclick = async () => {
    const currentEpoch = () => statusId === "recoveryStatus" ? recoveryEpoch : statusId === "activityError" ? activityEpoch : state.authEpoch;
    const epoch = currentEpoch();
    $(id).disabled = true; $(statusId).textContent = "Operazione in corso…";
    try { await operation(epoch); if (epoch === currentEpoch() && $(statusId).textContent === "Operazione in corso…") $(statusId).textContent = "Operazione completata."; }
    catch (error) { if (epoch === currentEpoch()) $(statusId).textContent = error.message; }
    finally { $(id).disabled = false; }
  };
}
function factor(value) { return /^\d{6}$/.test(value.trim()) ? {code: value.trim()} : {recovery_code: value.trim()}; }
function confirmation() { return {password: $("currentPassword").value, ...($("factorCode").value ? factor($("factorCode").value) : {})}; }
function clearAccountState({preserveRecovery = false} = {}) {
  for (const id of ["currentPassword", "factorCode", "newEmail",
    "activityStart", "activityEnd", "activityType", "activityDevice"]) $(id).value = "";
  for (const id of ["authStatus", "accountStatus", "accountError", "manualSecret", "recoveryCodes",
    "activityEvents", "activitySummary", "activityError"]) $(id).textContent = "";
  for (const id of ["qrImage", "confirmMfa", "dismissCodes", "activityMore"]) $(id).hidden = true;
  $("qrImage").removeAttribute("src");
  if (qrUrl) URL.revokeObjectURL(qrUrl);
  qrUrl = null;
  resetActivity();
  // Expired stored credentials must not erase an email link opened to recover
  // access. Explicit logout and login replacement still clear the whole form.
  if (!preserveRecovery) {
    recoveryEpoch += 1;
    linkToken = ""; linkAction = "";
    for (const id of ["recoveryEmail", "newPassword"]) $(id).value = "";
    for (const id of ["consumeReset", "consumeVerify"]) $(id).hidden = true;
    $("recoveryStatus").textContent = "";
  }
}
function showCodes(data) {
  clearCredentials();
  $("recoveryCodes").textContent = "Salva questi codici monouso: saranno mostrati una sola volta.\n" + data.recovery_codes.join("\n");
  $("dismissCodes").hidden = false; $("recoveryCodes").focus();
}
async function requestRecoveryCodes(url, body) {
  // These two mutations revoke the session themselves. Accept their one-time
  // result after automatic cleanup, but never after logout or a new login.
  const epoch = state.authContextEpoch;
  const data = await postJson(url, body);
  if (epoch === state.authContextEpoch) showCodes(data);
}
async function showAccount() {
  const epoch = state.authEpoch;
  const a = await getJson("/api/auth/me");
  if (epoch !== state.authEpoch) return;
  $("accountStatus").textContent = `${a.username} · ${a.email || "Nessuna email"} · ${a.email_verified ? "verificata" : "Recupero password non disponibile senza email verificata"} · In attesa: ${a.pending_email || "nessuna"} · TOTP ${a.totp_enabled ? "attiva" : "disattivata"}`;
}
actionButton("registerButton", "authStatus", async () => {
  const credentials = {username: $("username").value, password: $("password").value, ...($("email").value ? {email: $("email").value} : {})};
  clearCredentials();
  const epoch = state.authEpoch;
  try {
    await postJson("/api/auth/register", credentials, false);
    if (epoch !== state.authEpoch) return;
    if (await login("/api/auth/login", credentials)) await showAccount();
  } catch (error) { if (epoch === state.authEpoch) $("authStatus").textContent = error.message; }
});
actionButton("verifyMfaButton", "authStatus", async epoch => {
  const data = await postJson("/api/auth/mfa/verify", {challenge_token: state.challenge, ...factor($("loginCode").value)}, false);
  if (await acceptAuthentication(data, epoch)) await showAccount();
});
actionButton("accountRefresh", "accountError", showAccount);
actionButton("changeEmail", "accountError", async epoch => { await postJson("/api/auth/email-change-request", {email: $("newEmail").value, ...confirmation()}); if (epoch !== state.authEpoch) return; $("currentPassword").value = ""; $("factorCode").value = ""; await showAccount(); });
actionButton("resendEmail", "accountError", () => postJson("/api/auth/email-verification-request", {}));
actionButton("requestReset", "recoveryStatus", async epoch => { const data = await postJson("/api/auth/password-reset-request", {email: $("recoveryEmail").value}, false); if (epoch === recoveryEpoch) $("recoveryStatus").textContent = data.message; });
actionButton("consumeReset", "recoveryStatus", async epoch => {
  await postJson("/api/auth/password-reset", {token: linkToken, new_password: $("newPassword").value}, false);
  if (epoch !== recoveryEpoch) return;
  linkToken = ""; $("newPassword").value = ""; $("consumeReset").hidden = true; clearCredentials();
  $("recoveryStatus").textContent = "Password aggiornata. Accedi nuovamente con il secondo fattore, se attivo.";
});
actionButton("consumeVerify", "recoveryStatus", async epoch => { await postJson("/api/auth/email-verify", {token: linkToken}, false); if (epoch !== recoveryEpoch) return; linkToken = ""; $("consumeVerify").hidden = true; });
actionButton("setupMfa", "accountError", async epoch => {
  const data = await postJson("/api/auth/mfa/setup", {password: $("currentPassword").value});
  if (epoch !== state.authEpoch) return;
  if (qrUrl) URL.revokeObjectURL(qrUrl);
  qrUrl = URL.createObjectURL(new Blob([data.qr_svg], {type: "image/svg+xml"})); $("qrImage").src = qrUrl; $("qrImage").hidden = false;
  $("manualSecret").textContent = `Segreto manuale (10 minuti): ${data.secret}`; $("confirmMfa").hidden = false;
  $("accountError").textContent = "Aggiungi MyDesk all'autenticatore e inserisci il codice nel campo TOTP.";
});
actionButton("confirmMfa", "accountError", () => requestRecoveryCodes("/api/auth/mfa/confirm", factor($("factorCode").value)));
actionButton("regenerateMfa", "accountError", () => requestRecoveryCodes("/api/auth/mfa/recovery-codes/regenerate", confirmation()));
actionButton("disableMfa", "accountError", async epoch => { await postJson("/api/auth/mfa/disable", confirmation()); if (epoch === state.authEpoch) clearCredentials(); });
$("dismissCodes").onclick = () => { $("recoveryCodes").textContent = ""; $("dismissCodes").hidden = true; $("username").focus(); };
function currentActivityFilters() {
  return JSON.stringify(activityFilterIds.map(id => $(id).value));
}
function resetActivity() {
  activityEpoch += 1;
  activityFilterKey = currentActivityFilters();
  activityCursor = null; activityLoading = false; activityPages = 0;
  for (const id of ["activityEvents", "activitySummary", "activityError", "activityRefreshStatus"]) $(id).textContent = "";
  $("activityMore").hidden = true;
}
for (const id of activityFilterIds) {
  $(id).oninput = $(id).onchange = () => {
    if (currentActivityFilters() !== activityFilterKey) resetActivity();
  };
}
async function refreshActivity(more = false, {automatic = false} = {}) {
  if (currentActivityFilters() !== activityFilterKey) resetActivity();
  if (!state.token || activityLoading || (automatic && activityPages > 1)) return;
  if (more && activityPages > 0 && !activityCursor) return;
  const epoch = state.authEpoch;
  const viewEpoch = activityEpoch, filterKey = activityFilterKey;
  const current = () => epoch === state.authEpoch && viewEpoch === activityEpoch && filterKey === currentActivityFilters();
  const append = more && activityPages > 0;
  activityLoading = true;
  try {
    const params = new URLSearchParams();
    for (const [id, key] of [["activityStart", "start"], ["activityEnd", "end"]]) if ($(id).value) params.set(key, new Date($(id).value).toISOString());
    for (const [id, key] of [["activityType", "event_type"], ["activityDevice", "device_id"]]) if ($(id).value) params.set(key, $(id).value);
    const summaryQuery = params.toString();
    if (append) params.set("cursor", activityCursor);
    const [events, summary] = await Promise.all([getJson(`/api/activity?${params}`), getJson(`/api/activity/summary?${summaryQuery}`)]);
    if (!current()) return;
    if (!append) $("activityEvents").textContent = "";
    for (const event of events.events) { const row = document.createElement("p"); row.textContent = `${new Date(event.created_at).toLocaleString()} · ${event.event_type} · ${event.device_id || "account"} · ${JSON.stringify(event.details)}`; $("activityEvents").appendChild(row); }
    activityCursor = events.next_cursor; $("activityMore").hidden = !activityCursor;
    activityPages = append ? activityPages + 1 : 1;
    $("activityRefreshStatus").textContent = activityPages > 1
      ? "Aggiornamento automatico sospeso durante la consultazione. Premi Aggiorna attività per tornare agli eventi recenti." : "";
    $("activitySummary").textContent = `Dispositivi: ${summary.devices} · Connessi: ${summary.connected_devices} · Sessioni attive: ${summary.active_sessions} · Avviate nel periodo: ${summary.sessions_started} · Autenticazioni fallite: ${summary.authentication_failures}`;
  } catch (error) {
    if (current()) throw error;
  } finally { if (epoch === state.authEpoch && viewEpoch === activityEpoch) activityLoading = false; }
}
actionButton("activityRefresh", "activityError", () => refreshActivity());
actionButton("activityMore", "activityError", () => refreshActivity(true));
setInterval(() => {
  if (!document.hidden && state.token) {
    const pending = refreshActivity(false, {automatic: true});
    const epoch = activityEpoch;
    return pending.catch(error => { if (epoch === activityEpoch) $("activityError").textContent = error.message; });
  }
}, 30000);
requestJson("/api/auth/config", "GET", undefined, false).then(config => {
  $("bootstrapButton").hidden = !config.bootstrap_available; $("setupMfa").disabled = !config.totp_available;
  for (const id of ["requestReset", "changeEmail", "resendEmail"]) $(id).disabled = !config.email_available;
}).catch(error => { $("accountError").textContent = error.message; });
