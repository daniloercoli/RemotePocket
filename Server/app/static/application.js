/* Page navigation and presentation. Authentication and remote control live in console.js. */
(() => {
  "use strict";
  const pages = new Map([
    ["/app", ["dashboard", "Panoramica"]], ["/app/devices", ["devices", "Dispositivi"]],
    ["/app/sessions", ["sessions", "Sessioni remote"]], ["/app/activity", ["activity", "Attività"]],
    ["/app/account", ["account", "Account e sicurezza"]], ["/app/help", ["help", "Guida rapida"]],
  ]);
  const publicPages = new Set(["/login", "/register", "/setup", "/forgot-password", "/reset-password", "/verify-email", "/two-factor", "/recovery-codes"]);
  let ready = false, account = null, config = state.publicConfig || null;
  let destination = pages.has(new URLSearchParams(location.search).get("next")) ? new URLSearchParams(location.search).get("next") : "/app";
  let toastTimer, pairing = null, confirmationResolve = null, loginLoading = false;
  let loginListEpoch = 0, loginListLoading = false, passwordBusy = false;
  let recoveryCompleted = false, dashboardKey = "";
  const icon = name => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const date = value => value ? new Intl.DateTimeFormat("it-IT", {dateStyle: "medium", timeStyle: "short"}).format(new Date(value)) : "Mai collegato";
  const statusLabel = value => ({online: "Online", offline: "Offline", in_session: "In sessione", revoked: "Revocato"})[value] || "Sconosciuto";
  const safeStatus = value => ["online", "offline", "in_session", "revoked"].includes(value) ? value : "";
  function notify(message) {
    if (!ready || !message || ["Owner autenticato.", "Connessione console in corso.", "Accedi nuovamente."].includes(message)) return;
    $("toast").textContent = message; $("toast").hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { $("toast").hidden = true; }, 6500);
  }
  function navigate(path, {replace = false, focus = true} = {}) {
    if (!pages.has(path) && !publicPages.has(path)) path = state.token ? "/app" : "/login";
    if (path !== location.pathname || location.search) history[replace ? "replaceState" : "pushState"]({}, "", path);
    renderRoute(focus);
  }
  function renderRoute(focus = false) {
    if (!ready) return;
    let path = location.pathname;
    if (path === "/") return navigate(linkAction === "reset" ? "/reset-password" : linkAction === "verify" ? "/verify-email" : state.token ? "/app" : config?.bootstrap_available ? "/setup" : "/login", {replace: true, focus: false});
    if (pages.has(path) && !state.token) {
      destination = path;
      history.replaceState({}, "", "/login?next=" + encodeURIComponent(path));
      path = "/login";
    }
    if (state.token && ["/login", "/register", "/setup", "/two-factor"].includes(path)) return navigate(destination, {replace: true});
    if (path === "/two-factor" && !state.challenge) return navigate("/login", {replace: true});
    if (path === "/recovery-codes" && !$("recoveryCodes").textContent) return navigate("/login", {replace: true});
    if (path === "/setup" && config && !config.bootstrap_available) return navigate("/register", {replace: true});
    const protectedPage = pages.has(path);
    $("bootScreen").hidden = true;
    $("authShell").hidden = protectedPage; $("appShell").hidden = !protectedPage;
    $("appShell").classList.remove("menu-open"); $("menuButton").setAttribute("aria-expanded", "false");
    document.querySelectorAll("dialog[open]").forEach(dialog => dialog.close());
    document.querySelectorAll("[data-page]").forEach(page => { page.hidden = !protectedPage || page.dataset.page !== pages.get(path)[0]; });
    for (const id of ["credentialsPage", "mfaLogin", "recoveryPanel", "codesPage"]) $(id).hidden = true;
    if (protectedPage) {
      const [page, title] = pages.get(path);
      document.title = `${title} · RemotePocket`;
      $("breadcrumbTitle").textContent = title;
      document.querySelectorAll(".sidebar a[data-route]").forEach(link => {
        if (link.getAttribute("href") === path) link.setAttribute("aria-current", "page");
        else link.removeAttribute("aria-current");
      });
      renderDashboard();
      if (page === "devices") renderDevices(state.devices);
      if (page === "account") { loadAccount(); loadLogins(); }
      if (page === "activity") refreshActivity().catch(error => { $("activityError").textContent = error.message; });
    } else if (["/login", "/register", "/setup"].includes(path)) {
      $("credentialsPage").hidden = false;
      const creating = path !== "/login", setup = path === "/setup";
      $("authEyebrow").textContent = setup ? "IL PRIMO PASSO" : creating ? "IL TUO NUOVO SPAZIO" : "BENTORNATO";
      $("authTitle").textContent = setup ? "Benvenuto in RemotePocket." : creating ? "Tutto parte da qui." : "Il tuo spazio di controllo.";
      $("authDescription").textContent = setup ? "Crea il primo account e prepara il tuo spazio di gestione." : creating ? "Crea un account per associare e gestire i tuoi dispositivi." : "Accedi per ritrovare i tuoi dispositivi, ovunque siano.";
      $("credentialsSubmitLabel").textContent = setup ? "Crea il primo account" : creating ? "Crea account" : "Accedi";
      $("newAccountFields").hidden = !creating; $("emailField").hidden = !creating;
      $("passwordConfirm").required = creating; $("password").minLength = creating ? 8 : 1;
      $("password").autocomplete = creating ? "new-password" : "current-password";
      $("email").disabled = !creating; $("passwordConfirm").disabled = !creating;
      $("loginLinks").hidden = creating; $("registrationLink").hidden = creating; $("signInLink").hidden = !creating;
      $("setupNotice").hidden = !config?.bootstrap_available || creating;
      $("setupNotice").innerHTML = 'Questa è una nuova installazione. <a href="/setup" data-route>Crea il primo account</a> per iniziare.';
      document.title = `${setup ? "Primo accesso" : creating ? "Crea account" : "Accedi"} · RemotePocket`;
    } else if (path === "/two-factor") {
      $("mfaLogin").hidden = false; document.title = "Verifica accesso · RemotePocket";
    } else if (path === "/recovery-codes") {
      $("codesPage").hidden = false; document.title = "Codici di recupero · RemotePocket";
    } else {
      renderRecovery(path); document.title = `${$("recoveryTitle").textContent} · RemotePocket`;
    }
    applyAvailability();
    if (focus) {
      const heading = protectedPage ? document.querySelector(`[data-page="${pages.get(path)[0]}"] h1`) : document.querySelector("#authContent > section:not([hidden]) h1");
      if (heading) { heading.tabIndex = -1; heading.focus({preventScroll: true}); }
      window.scrollTo({top: 0, behavior: "instant"});
    }
  }
  function renderRecovery(path) {
    $("recoveryPanel").hidden = false;
    const reset = path === "/reset-password", verify = path === "/verify-email";
    const hasToken = !!linkToken && linkAction === (reset ? "reset" : "verify");
    $("recoveryTitle").textContent = reset ? "Una nuova password." : verify ? "Conferma la tua email." : "Ritrova il tuo accesso.";
    $("recoveryDescription").textContent = reset ? "Scegli una password sicura per tornare nel tuo spazio." : verify ? "Conferma questo indirizzo per ricevere le comunicazioni e recuperare il tuo account." : "Ti invieremo un link all’indirizzo email verificato del tuo account.";
    $("recoveryEyebrow").textContent = verify ? "VERIFICA EMAIL" : "RECUPERO ACCOUNT";
    $("recoveryEmailField").hidden = reset || verify; $("recoveryEmail").required = !reset && !verify;
    $("resetFields").hidden = !reset || !hasToken; $("newPassword").required = reset && hasToken;
    $("newPasswordConfirm").required = reset && hasToken;
    $("invalidLink").hidden = !(reset || verify) || hasToken || recoveryCompleted;
    $("newRecoveryLink").hidden = !reset || hasToken || recoveryCompleted;
    $("requestReset").hidden = reset || verify;
    $("consumeReset").hidden = !reset || !hasToken; $("consumeVerify").hidden = !verify || !hasToken;
    $("emailUnavailable").hidden = reset || verify || config?.email_available !== false;
  }
  function applyAvailability() {
    const emailEnabled = !!config?.email_available;
    for (const id of ["requestReset", "changeEmail", "resendEmail"]) $(id).disabled = !emailEnabled;
    $("accountEmailUnavailable").hidden = !config || emailEnabled;
    $("totpUnavailable").hidden = !config || !!config.totp_available;
    $("setupMfa").disabled = !config?.totp_available;
    $("credentialsSubmit").disabled = loginLoading || !config;
    if (location.pathname === "/forgot-password") $("emailUnavailable").hidden = !config || emailEnabled;
  }
  async function loadAccount() {
    if (!state.token) return;
    const epoch = state.authEpoch;
    try { await showAccount(); }
    catch (error) {
      if (epoch !== state.authEpoch) return;
      if ([401, 403].includes(error.status)) clearCredentials("La sessione è scaduta. Accedi nuovamente.", {automatic: true});
      else $("accountError").textContent = error.message;
    }
  }
  function accountLoaded(data) {
    account = data;
    for (const id of ["profileName", "accountUsername"]) $(id).textContent = data.username;
    for (const id of ["profileAvatar", "accountAvatar"]) $(id).textContent = data.username.slice(0, 2).toLocaleUpperCase();
    $("welcomeTitle").textContent = `Benvenuto, ${data.username}.`;
    $("accountEmail").textContent = data.email || "Nessuna email associata";
    $("emailBadge").textContent = data.email_verified ? "Email verificata" : "Email non verificata";
    $("emailBadge").className = "status " + (data.email_verified ? "online" : "offline");
    $("pendingEmail").hidden = !data.pending_email;
    $("pendingEmail").textContent = data.pending_email ? `Conferma in attesa per ${data.pending_email}. Apri il link ricevuto via email.` : "";
    $("mfaBadge").textContent = data.totp_enabled ? "Attiva" : "Non attiva";
    $("mfaBadge").className = "status " + (data.totp_enabled ? "online" : "offline");
    $("setupMfa").hidden = data.totp_enabled;
    $("disableMfa").hidden = $("regenerateMfa").hidden = !data.totp_enabled;
    $("resendEmail").hidden = !data.pending_email;
  }
  function renderDashboard() {
    const active = state.devices.filter(device => !device.revoked_at);
    $("statDevices").textContent = active.length;
    $("statOnline").textContent = active.filter(device => device.status === "online" || device.status === "in_session").length;
    sessionsChanged();
    const nextKey = JSON.stringify(active.map(({id, name, status, last_seen_at}) => ({id, name, status, last_seen_at})));
    if (dashboardKey === nextKey) return;
    dashboardKey = nextKey;
    const root = $("dashboardDevices"); root.replaceChildren();
    if (!active.length) {
      root.innerHTML = `<div class="empty-state"><span class="empty-icon">${icon("phone")}</span><h2>Il tuo primo dispositivo ti aspetta.</h2><p>Associa un dispositivo Android per ritrovarlo qui e collegarti quando ne hai bisogno.</p><button data-pairing>Associa un dispositivo ${icon("plus")}</button></div>`;
      return;
    }
    for (const device of active.slice(0, 5)) {
      const row = document.createElement("div"); row.className = "device-summary";
      row.innerHTML = `<span class="feature-icon">${icon("phone")}</span><div><strong></strong><small></small></div><span class="status ${safeStatus(device.status)}"></span><a href="/app/devices" data-route aria-label="Gestisci dispositivo">${icon("arrow")}</a>`;
      row.querySelector("strong").textContent = device.name;
      row.querySelector("small").textContent = device.last_seen_at ? `Ultima presenza: ${date(device.last_seen_at)}` : "In attesa del primo collegamento";
      row.querySelector(".status").textContent = statusLabel(device.status);
      root.appendChild(row);
    }
  }
  function devicesChanged() {
    renderDashboard();
    const total = state.devices.length, visible = Array.from($("devices").children).filter(item => !item.hidden).length;
    $("devicesCount").textContent = total ? `${visible} ${visible === 1 ? "dispositivo" : "dispositivi"} · ${total} totali` : "";
    $("devicesEmpty").hidden = visible > 0;
    $("devicesEmptyTitle").textContent = total ? "Nessun dispositivo trovato." : "Qui troverai i tuoi dispositivi.";
    $("devicesEmptyDescription").textContent = total ? "Prova un altro nome o modifica il filtro dello stato." : "Associa il primo dispositivo Android per iniziare.";
    $("emptyPairing").hidden = !!total;
  }
  function sessionsChanged() {
    $("statSessions").textContent = state.sessions.size;
    $("sessionCount").textContent = state.sessions.size;
    $("sessionCount").hidden = !state.sessions.size;
    const connected = !!state.activeSessionId;
    $("screenEmpty").querySelector("h2").textContent = connected ? "Collegamento aperto." : "Pronto quando lo sei tu.";
    $("screenEmpty").querySelector("p").textContent = connected ? "In attesa dello schermo. Verifica che il dispositivo sia sbloccato e che l’accessibilità sia attiva." : "Apri una sessione dalla pagina Dispositivi. Lo schermo Android apparirà qui.";
    $("screenEmpty").querySelector("a").hidden = connected;
  }
  async function loadLogins() {
    if (!state.token || loginListLoading) return;
    const epoch = state.authEpoch, listEpoch = ++loginListEpoch;
    loginListLoading = true; $("loginSessionsStatus").textContent = "";
    try {
      const result = await getJson("/api/auth/sessions");
      if (epoch !== state.authEpoch || listEpoch !== loginListEpoch) return;
      $("loginSessions").replaceChildren();
      for (const item of result.sessions) {
        const row = document.createElement("div"); row.className = "login-session";
        const agent = item.user_agent || "Browser sconosciuto";
        const browserName = /Edg\//.test(agent) ? "Microsoft Edge" : /Firefox\//.test(agent) ? "Firefox" : /Chrome\//.test(agent) ? "Chrome" : /Safari\//.test(agent) ? "Safari" : "Browser / client";
        row.innerHTML = `${icon("screen")}<div><h3></h3><p></p></div>${item.current ? '<span class="status online">Questo accesso</span>' : '<button class="danger">Disconnetti</button>'}`;
        row.querySelector("h3").textContent = browserName;
        row.querySelector("p").textContent = `${item.ip_address || "IP non disponibile"} · Accesso: ${date(item.created_at)} · Scadenza: ${date(item.expires_at)}`;
        if (!item.current) row.querySelector("button").onclick = async event => {
          if (!await confirmAction("Disconnettere questo accesso?", "Quel browser dovrà effettuare nuovamente l’accesso. Le sue sessioni remote verranno interrotte.", "Disconnetti")) return;
          const actionEpoch = state.authEpoch;
          event.target.disabled = true;
          try {
            await postJson(`/api/auth/sessions/${encodeURIComponent(item.id)}/revoke`, {});
            if (actionEpoch !== state.authEpoch) return;
            notify("Accesso disconnesso."); await loadLogins();
          } catch (error) { if (actionEpoch === state.authEpoch) $("loginSessionsStatus").textContent = error.message; }
          finally { event.target.disabled = false; }
        };
        $("loginSessions").appendChild(row);
      }
    } catch (error) { if (epoch === state.authEpoch) $("loginSessionsStatus").textContent = error.message; }
    finally { if (listEpoch === loginListEpoch) loginListLoading = false; }
  }
  const eventNames = {
    user_registered: "Account creato", login_success: "Accesso effettuato", login_failed: "Tentativo di accesso non riuscito", login_blocked: "Accesso temporaneamente bloccato",
    device_registered: "Dispositivo associato", pairing_code_created: "Codice di associazione generato", device_renamed: "Dispositivo rinominato", device_revoked: "Dispositivo revocato", device_connected: "Dispositivo connesso", device_disconnected: "Dispositivo disconnesso",
    session_opened: "Sessione remota aperta", session_closed: "Sessione remota chiusa", session_ended: "Sessione remota terminata", session_failed: "Sessione non riuscita", session_revoked: "Accesso revocato",
    mfa_enabled: "Verifica in due passaggi attivata", mfa_disabled: "Verifica in due passaggi disattivata", mfa_failed: "Verifica del codice non riuscita", mfa_recovery_used: "Codice di recupero utilizzato", mfa_recovery_regenerated: "Codici di recupero rigenerati",
    password_changed: "Password modificata", password_reset: "Password reimpostata", email_change_requested: "Modifica email richiesta", email_verified: "Email verificata", device_woken: "Dispositivo attivato", agent_configured: "Configurazione dispositivo aggiornata",
    wake_message_created: "Messaggio di attivazione generato", account_confirmation_failed: "Conferma identità non riuscita", session_fingerprint_changed: "Rete o browser dell’accesso modificati",
  };
  function appendActivity(event) {
    const row = document.createElement("article"); row.className = "event-row";
    row.innerHTML = `<span class="feature-icon">${icon("activity")}</span><div><h3></h3><p></p></div><time></time>`;
    row.querySelector("h3").textContent = eventNames[event.event_type] || event.event_type.replaceAll("_", " ");
    const device = state.devices.find(item => item.id === event.device_id);
    const details = Object.values(event.details || {}).filter(value => typeof value === "string").join(" · ");
    row.querySelector("p").textContent = [device?.name || event.device_id || "Account personale", details].filter(Boolean).join(" · ");
    row.querySelector("time").dateTime = event.created_at; row.querySelector("time").textContent = date(event.created_at);
    $("activityEvents").appendChild(row);
  }
  function confirmAction(title, description, accept = "Conferma") {
    if (confirmationResolve) confirmationResolve(false);
    $("confirmTitle").textContent = title; $("confirmDescription").textContent = description;
    $("acceptConfirmation").textContent = accept; $("confirmDialog").showModal();
    $("cancelConfirmation").focus();
    return new Promise(resolve => { confirmationResolve = resolve; });
  }
  function finishConfirmation(accepted) {
    const resolve = confirmationResolve; confirmationResolve = null; $("confirmDialog").close(); resolve?.(accepted);
  }
  function openPairing() {
    if (!state.token) return;
    $("pairingStatus").textContent = ""; $("pairingDialog").showModal();
  }
  function pairingCreated(data) {
    pairing = data;
    $("pairingCode").textContent = data.code; $("pairingCode").classList.add("generated");
    $("pairingExpiry").textContent = `Valido fino al ${date(data.expires_at)}. Usalo una sola volta.`;
    $("copyPairing").disabled = false; $("pairingButton").textContent = "Genera un altro codice";
    $("pairingStatus").textContent = "";
  }
  async function copyText(text, fallback) {
    try { await navigator.clipboard.writeText(text); notify("Copiato negli appunti."); }
    catch { if (fallback) { const range = document.createRange(); range.selectNodeContents(fallback); const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); } notify("Copia automatica non disponibile. Seleziona e copia il testo."); }
  }
  function signedOut({message, automatic}) {
    account = null; loginListEpoch++; loginListLoading = false; pairing = null;
    for (const id of ["passwordConfirm", "newPasswordConfirm", "accountNewPassword", "accountPasswordConfirm"]) $(id).value = "";
    for (const id of ["loginSessions", "loginSessionsStatus", "passwordChangeStatus", "mfaStatus"]) $(id).textContent = "";
    $("mfaSetupPanel").hidden = true; $("copyPairing").disabled = true; $("pairingExpiry").textContent = "";
    $("pairingCode").classList.remove("generated"); $("pairingButton").textContent = "Genera codice";
    $("password").type = "password";
    document.querySelectorAll("[data-reveal]").forEach(button => { button.textContent = "Mostra"; button.setAttribute("aria-pressed", "false"); button.setAttribute("aria-label", "Mostra password"); });
    $("profileName").textContent = "Il tuo account"; $("welcomeTitle").textContent = "Tutto sotto controllo.";
    renderDashboard();
    if (pages.has(location.pathname)) { destination = location.pathname; navigate("/login", {replace: true}); }
    else if (location.pathname === "/two-factor") navigate("/login", {replace: true});
    if (automatic) { $("authStatus").textContent = message; notify(message); }
  }
  function bindForm(formId, buttonId, validate = () => true) {
    const form = $(formId), button = $(buttonId), operation = button.onclick;
    let busy = false;
    const run = async event => {
      event?.preventDefault();
      if (busy || button.disabled || !validate() || !form.reportValidity()) return;
      busy = true; button.disabled = true; button.setAttribute("aria-busy", "true");
      try { await operation(); }
      finally { busy = false; button.disabled = false; button.removeAttribute("aria-busy"); applyAvailability(); }
    };
    button.type = "submit"; button.onclick = run; form.onsubmit = run;
  }
  function matchPasswords(first, second) {
    $(second).setCustomValidity($(first).value === $(second).value ? "" : "Le password non coincidono.");
    return $(second).reportValidity();
  }
  globalThis.RemotePocketUI = {
    notify, signedOut, accountLoaded, devicesChanged, sessionsChanged, pairingCreated, appendActivity, confirmAction,
    pairingError: message => { $("pairingStatus").textContent = message; },
    authenticated: () => { if (config) config.bootstrap_available = false; recoveryCompleted = false; ready = true; navigate(destination, {replace: true}); loadAccount(); },
    challenge: () => { navigate("/two-factor"); $("loginCode").focus(); },
    sessionOpened: () => navigate("/app/sessions"),
    recoveryCodes: () => { navigate("/recovery-codes", {replace: true}); },
    codesDismissed: () => navigate("/login", {replace: true}),
    mfaSetup: () => { $("mfaSetupPanel").hidden = false; },
    configured: value => { config = value; applyAvailability(); if (ready) renderRoute(); },
    configFailed: () => { $("authStatus").textContent = "Configurazione non disponibile. Ricarica la pagina per riprovare."; },
    recoveryCompleted: ({action}) => {
      recoveryCompleted = true; $("recoveryStatus").className = "notice success";
      if (action === "verify") $("recoveryStatus").textContent = "Email verificata. Puoi tornare al tuo account.";
      $("newPasswordConfirm").value = "";
      if (["/reset-password", "/verify-email"].includes(location.pathname)) renderRecovery(location.pathname);
    },
    actionFinished: ({id, statusId}) => {
      if (id === "verifyMfaButton") $("mfaStatus").textContent = $("authStatus").textContent;
      if (statusId === "accountError") notify($("accountError").textContent);
      applyAvailability();
    },
    activityLoaded: ({events, append}) => {
      if (!append && !events.events.length) $("activityEvents").innerHTML = `<div class="empty-state"><span class="empty-icon">${icon("activity")}</span><h2>Nessun evento in questo intervallo.</h2><p>Prova a modificare le date o i filtri. Le nuove attività compariranno qui.</p></div>`;
    },
  };
  // Links preserve active remote sessions: navigation never reloads the application.
  document.addEventListener("click", event => {
    const pairingButton = event.target.closest("[data-pairing]");
    if (pairingButton) { event.preventDefault(); openPairing(); return; }
    const close = event.target.closest("[data-close-dialog]");
    if (close) { $(close.dataset.closeDialog).close(); return; }
    const link = event.target.closest("a[data-route]");
    if (!link || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || event.button !== 0) return;
    event.preventDefault();
    let path = link.getAttribute("href");
    if (path === "/") path = state.token ? "/app" : "/login";
    if (path === "/login" && state.challenge) { state.challenge = ""; $("loginCode").value = ""; }
    $("authStatus").textContent = ""; $("authStatus").className = "notice error";
    navigate(path);
  });
  window.addEventListener("popstate", () => renderRoute(true));
  $("menuButton").onclick = () => { const opened = $("appShell").classList.toggle("menu-open"); $("menuButton").setAttribute("aria-expanded", String(opened)); };
  document.addEventListener("keydown", event => { if (event.key === "Escape") { $("appShell").classList.remove("menu-open"); $("menuButton").setAttribute("aria-expanded", "false"); } });
  $("cancelConfirmation").onclick = () => finishConfirmation(false);
  $("acceptConfirmation").onclick = () => finishConfirmation(true);
  $("confirmDialog").addEventListener("cancel", event => { event.preventDefault(); finishConfirmation(false); });
  $("confirmDialog").addEventListener("close", () => { const resolve = confirmationResolve; confirmationResolve = null; resolve?.(false); });
  document.querySelectorAll("[data-reveal]").forEach(button => {
    button.onclick = () => { const field = $(button.dataset.reveal), show = field.type === "password"; field.type = show ? "text" : "password"; button.textContent = show ? "Nascondi" : "Mostra"; button.setAttribute("aria-pressed", String(show)); button.setAttribute("aria-label", show ? "Nascondi password" : "Mostra password"); };
  });
  for (const [first, second] of [["password", "passwordConfirm"], ["newPassword", "newPasswordConfirm"], ["accountNewPassword", "accountPasswordConfirm"]]) {
    for (const id of [first, second]) $(id).addEventListener("input", () => $(second).setCustomValidity(""));
  }
  for (const id of activityFilterIds) $(id).addEventListener("change", () => {
    if (state.token) $("activityRefreshStatus").textContent = "Filtri modificati. Premi Aggiorna attività per applicarli.";
  });
  $("credentialsForm").onsubmit = async event => {
    event.preventDefault();
    if (loginLoading || !config) return;
    const path = location.pathname, creating = path !== "/login";
    if (creating && !matchPasswords("password", "passwordConfirm")) return;
    const credentials = {username: $("username").value.trim(), password: $("password").value, ...(creating && $("email").value ? {email: $("email").value.trim()} : {})};
    loginLoading = true; applyAvailability(); $("credentialsSubmit").setAttribute("aria-busy", "true"); $("authStatus").textContent = ""; $("authStatus").className = "notice error";
    try {
      if (path === "/register") {
        clearCredentials();
        const epoch = state.authEpoch;
        await postJson("/api/auth/register", credentials, false);
        if (epoch !== state.authEpoch) return;
        if (await login("/api/auth/login", credentials)) notify("Account creato. Benvenuto in RemotePocket.");
      } else await login(path === "/setup" ? "/api/auth/bootstrap" : "/api/auth/login", credentials);
    } catch (error) {
      $("authStatus").textContent = error.message === "Failed to fetch" ? "Connessione al server non disponibile. Controlla la rete e riprova." : error.message;
      $("username").value = credentials.username;
      if (credentials.email) $("email").value = credentials.email;
    } finally { loginLoading = false; $("credentialsSubmit").removeAttribute("aria-busy"); applyAvailability(); }
  };
  bindForm("mfaForm", "verifyMfaButton");
  // Recovery uses one form, with a distinct operation for each dedicated route.
  const recoveryOperations = Object.fromEntries(["requestReset", "consumeReset", "consumeVerify"].map(id => [id, $(id).onclick]));
  let recoveryBusy = false;
  const recover = async event => {
    event.preventDefault();
    const id = location.pathname === "/reset-password" ? "consumeReset" : location.pathname === "/verify-email" ? "consumeVerify" : "requestReset";
    if (recoveryBusy || $(id).disabled || $(id).hidden) return;
    if (id === "consumeReset" && !matchPasswords("newPassword", "newPasswordConfirm")) return;
    if (!$("recoveryForm").reportValidity()) return;
    recoveryBusy = true;
    try { await recoveryOperations[id](); }
    finally { recoveryBusy = false; applyAvailability(); }
  };
  $("recoveryForm").onsubmit = recover;
  for (const id of Object.keys(recoveryOperations)) $(id).onclick = recover;
  bindForm("emailChangeForm", "changeEmail", () => {
    $("newEmail").required = true;
    if (!$("currentPassword").value) { $("accountError").textContent = "Inserisci la password attuale nella conferma dell’identità."; $("currentPassword").focus(); return false; }
    return true;
  });
  // Make sensitive settings explicit before committing their existing API mutations.
  for (const [id, title, description, label] of [
    ["disableMfa", "Disattivare la verifica in due passaggi?", "L’account sarà protetto dalla sola password. Dovrai accedere nuovamente su tutti i browser.", "Disattiva"],
    ["regenerateMfa", "Generare nuovi codici di recupero?", "I codici precedenti non funzioneranno più. Salva quelli nuovi prima di effettuare nuovamente l’accesso.", "Genera nuovi codici"],
  ]) {
    const operation = $(id).onclick;
    $(id).onclick = async () => { if (await confirmAction(title, description, label)) await operation(); };
  }
  const generate = $("pairingButton").onclick;
  $("pairingButton").onclick = async () => { $("pairingButton").disabled = true; try { await generate(); } finally { $("pairingButton").disabled = false; } };
  $("copyPairing").onclick = () => { if (pairing && Date.now() < Date.parse(pairing.expires_at)) copyText(pairing.code, $("pairingCode")); };
  setInterval(() => {
    if (pairing && Date.now() >= Date.parse(pairing.expires_at)) { $("copyPairing").disabled = true; $("pairingExpiry").textContent = "Codice scaduto. Generane uno nuovo per continuare."; }
  }, 1000);
  $("copyRecoveryCodes").onclick = () => copyText($("recoveryCodes").textContent, $("recoveryCodes"));
  $("refreshLogins").onclick = loadLogins;
  $("changePasswordForm").onsubmit = async event => {
    event.preventDefault();
    if (passwordBusy || !matchPasswords("accountNewPassword", "accountPasswordConfirm")) return;
    if (!$("currentPassword").value) { $("passwordChangeStatus").textContent = "Inserisci la password attuale nella conferma dell’identità."; $("currentPassword").focus(); return; }
    passwordBusy = true; $("changePasswordButton").disabled = true; $("passwordChangeStatus").textContent = "";
    const epoch = state.authContextEpoch;
    const body = {...confirmation(), new_password: $("accountNewPassword").value};
    try {
      await postJson("/api/auth/password-change", body);
      if (epoch !== state.authContextEpoch) return;
      clearCredentials("Password aggiornata."); navigate("/login", {replace: true});
      $("authStatus").textContent = "Password aggiornata. Accedi con la nuova password.";
      $("authStatus").className = "notice success";
    } catch (error) { if (epoch === state.authContextEpoch) $("passwordChangeStatus").textContent = error.message; }
    finally { passwordBusy = false; $("changePasswordButton").disabled = false; }
  };
  const sendText = $("sendTextButton").onclick;
  $("sendTextButton").onclick = event => { event?.preventDefault(); sendText(); };
  $("remoteTextForm").onsubmit = event => { event.preventDefault(); sendText(); };
  document.querySelector(".skip-link").onclick = event => { event.preventDefault(); const target = state.token ? $("mainContent") : $("authContent"); target.tabIndex = -1; target.focus(); };
  // Tokens from email fragments stay in memory, are consumed only by an explicit action,
  // and never appear in URLs, storage, analytics or a request before confirmation.
  async function initialize() {
    if (linkAction) history.replaceState({}, "", linkAction === "reset" ? "/reset-password" : "/verify-email");
    if (state.token) await loadAccount();
    ready = true; renderRoute();
  }
  initialize();
})();
