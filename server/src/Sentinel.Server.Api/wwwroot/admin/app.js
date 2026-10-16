"use strict";

let token = null;
let identity = null;
let activeSection = "dashboard";
let selectedScope = "global";
let selectedTarget = "";
let loadedPolicy = null;
let toastTimer = 0;
let serverStatusTimer = 0;

const $ = (selector, root = document) => root.querySelector(selector);
const view = $("#view");
const navigation = $("#navigation");
const sectionTitles = {
  dashboard: "Dashboard", devices: "Urządzenia", groups: "Grupy urządzeń", events: "Zdarzenia i incydenty",
  policies: "Polityki bezpieczeństwa", users: "Administratorzy i role", audit: "Dziennik audytowy",
  models: "Modele AI", knowledge: "Baza wiedzy", diagnostics: "Diagnostyka", backups: "Kopie zapasowe", server: "Ustawienia serwera"
};
const navItems = [
  ["dashboard", "home", "Dashboard"], ["devices", "devices", "Urządzenia"], ["groups", "groups", "Grupy urządzeń"],
  ["events", "events", "Zdarzenia"], ["policies", "settings", "Polityki"], ["models", "settings", "Modele AI"], ["knowledge", "groups", "Baza wiedzy"],
  ["users", "users", "Administratorzy"], ["diagnostics", "events", "Diagnostyka"], ["audit", "audit", "Audyt"], ["backups", "devices", "Kopie zapasowe"], ["server", "settings", "Ustawienia serwera"]
];
const unavailableSources = {
  diagnostics: { title: "Diagnostyka serwera jest ograniczona", detail: "Dostępne są publiczne healthz i readyz. API nie udostępnia dziennika błędów technicznych ani diagnostyki hosta.", source: "Dostępne tylko GET /healthz i GET /readyz; brak endpointu diagnostycznego." },
  server: { title: "Konfiguracja serwera poza panelem", detail: "Konfigurację hosta, TLS, certyfikatu i katalogu danych ustawia administrator systemu poza aplikacją.", source: "Brak API zarządzania konfiguracją wdrożenia." }
};
const iconPaths = {
  home: "M3 10.5 12 3l9 7.5M5.5 9v11h13V9M9.5 20v-6h5v6",
  devices: "M3 4h18v12H3zM8 20h8M12 16v4M6 7h6",
  groups: "M16 20v-1.5a3.5 3.5 0 0 0-3.5-3.5h-5A3.5 3.5 0 0 0 4 18.5V20M10 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7M16 4.2a3.5 3.5 0 0 1 0 6.8M18 15h1a3 3 0 0 1 3 3v2",
  events: "M12 3 2.8 19h18.4L12 3zM12 9v4M12 16.5h.01",
  settings: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-1.7 2.94-.08-.03a1.7 1.7 0 0 0-1.85.38l-.06.06h-3.4l-.04-.08a1.7 1.7 0 0 0-1.5-1.05 1.7 1.7 0 0 0-1.5 1.05l-.04.08h-3.4l-.06-.06a1.7 1.7 0 0 0-1.85-.38l-.08.03-1.7-2.94.06-.06A1.7 1.7 0 0 0 3.94 15l-.08-.04v-3.4l.08-.04a1.7 1.7 0 0 0 .34-1.88l-.06-.06 1.7-2.94.08.03a1.7 1.7 0 0 0 1.85-.38l.06-.06h3.4l.04.08a1.7 1.7 0 0 0 1.5 1.05 1.7 1.7 0 0 0 1.5-1.05l.04-.08h3.4l.06.06a1.7 1.7 0 0 0 1.85.38l.08-.03 1.7 2.94-.06.06a1.7 1.7 0 0 0-.34 1.88l.08.04v3.4z",
  users: "M16 20v-1.5a3.5 3.5 0 0 0-3.5-3.5h-5A3.5 3.5 0 0 0 4 18.5V20M10 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7M17 8h5M19.5 5.5v5",
  audit: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"
};

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}
function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true"); svg.setAttribute("focusable", "false");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path"); path.setAttribute("d", iconPaths[name]); path.setAttribute("fill", "none"); path.setAttribute("stroke", "currentColor"); path.setAttribute("stroke-width", "1.8"); path.setAttribute("stroke-linecap", "round"); path.setAttribute("stroke-linejoin", "round"); svg.append(path); return svg;
}
function actionButton(text, action, variant = "secondary") {
  const button = node("button", `button ${variant}`, text);
  button.type = "button";
  button.addEventListener("click", action);
  return button;
}
function toast(message, kind = "success") {
  const target = $("#toast"); target.textContent = message; target.className = `toast ${kind}`; target.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { target.hidden = true; }, 4500);
}
async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let response;
  try { response = await fetch(`/api/v1/admin${path}`, { ...options, headers, cache: "no-store" }); }
  catch { throw new Error("Nie można połączyć się z serwerem. Sprawdź jego stan i połączenie."); }
  if (response.status === 401 && token) { clearSession(); throw new Error("Sesja wygasła. Zaloguj się ponownie."); }
  if (response.status === 204) return null;
  const payload = await response.json().catch(() => null);
  if (!response.ok) throw new Error(payload?.detail || payload?.error || payload?.title || `Żądanie nie powiodło się (HTTP ${response.status}).`);
  return payload;
}
function clearSession() {
  clearInterval(serverStatusTimer); serverStatusTimer = 0;
  if ($("#password-dialog").open) $("#password-dialog").close();
  token = null; identity = null;
  $("#shell").hidden = true; $("#login").hidden = false; $("#password").value = "";
}
function buildNavigation() {
  navigation.replaceChildren();
  const visibleItems = navItems.filter(([key]) => key !== "audit" || canSecurity()).filter(([key]) => key !== "users" || canSystem());
  for (const [key, glyph, label] of visibleItems) {
    const button = node("button", "nav-button"); button.type = "button"; button.dataset.section = key;
    button.setAttribute("aria-current", activeSection === key ? "page" : "false");
    const glyphNode = node("span", "nav-glyph"); glyphNode.append(icon(glyph)); button.append(glyphNode, node("span", "", label));
    button.addEventListener("click", () => { $("#sidebar").classList.remove("open"); void showSection(key); });
    navigation.append(button);
  }
}
function showError(error, retry) {
  view.replaceChildren();
  const box = node("div", "error-state"); const content = node("div");
  content.append(node("strong", "", "Nie udało się wczytać danych"), node("p", "muted", error.message));
  if (retry) content.append(actionButton("Spróbuj ponownie", retry, "primary"));
  box.append(content); view.append(box);
}
function pageHeading(title, description, right = null) {
  const heading = node("div", "page-heading"); const text = node("div");
  text.append(node("h2", "", title), node("p", "muted", description)); heading.append(text);
  if (right) heading.append(right);
  return heading;
}
function statCard(label, value, note, badge = null) {
  const card = node("article", "card stat-card");
  card.append(node("div", "stat-label", label), node("div", "stat-value", value), node("div", "stat-note", note));
  if (badge) card.append(badge);
  return card;
}
function statusBadge(text, kind = "info") { return node("span", `badge ${kind}`, text); }
function tableCell(value, sub = null) {
  const cell = node("td");
  if (value instanceof Node) cell.append(value); else cell.append(node("span", "cell-main", value ?? "—"));
  if (sub) cell.append(node("span", "cell-sub", sub));
  return cell;
}
function pagedTable(container, rows, columns, getSearchText, emptyTitle = "Brak danych", emptyDescription = "Gdy pojawią się dane, zobaczysz je tutaj.", filters = []) {
  container.replaceChildren();
  const tools = node("div", "table-tools"); const search = node("input");
  search.type = "search"; search.placeholder = "Szukaj…"; search.setAttribute("aria-label", "Szukaj w tabeli"); tools.append(search); container.append(tools);
  const filterControls = filters.map(filter => {
    const select = node("select"); select.setAttribute("aria-label", filter.label);
    for (const [value, label] of filter.options) { const option = node("option", "", label); option.value = value; select.append(option); }
    select.addEventListener("change", () => { page = 0; draw(); }); tools.append(select); return { filter, select };
  });
  const wrap = node("div", "table-wrap"); const table = node("table"); const thead = node("thead"); const header = node("tr");
  let sortKey = ""; let sortDirection = 1;
  for (const column of columns) {
    const th = node("th");
    if (column.key) {
      const sort = actionButton(`${column.title} ↕`, () => {
        if (sortKey === column.key) sortDirection *= -1; else { sortKey = column.key; sortDirection = 1; }
        draw();
      });
      sort.className = "table-sort"; sort.setAttribute("aria-label", `Sortuj według: ${column.title}`); th.append(sort);
    } else th.textContent = column.title;
    header.append(th);
  }
  thead.append(header); const tbody = node("tbody"); table.append(thead, tbody); wrap.append(table); container.append(wrap);
  const pager = node("div", "pagination"); const previous = actionButton("Poprzednia", () => { page = Math.max(0, page - 1); draw(); });
  const counter = node("span"); let page = 0; const pageSize = 20;
  const next = actionButton("Następna", () => { page++; draw(); }); pager.append(previous, counter, next); container.append(pager);
  function draw() {
    const needle = search.value.trim().toLocaleLowerCase("pl");
    const filtered = rows.filter(row => (!needle || getSearchText(row).toLocaleLowerCase("pl").includes(needle)) && filterControls.every(({filter,select}) => select.value === "all" || String(filter.getValue(row)) === select.value));
    if (sortKey) filtered.sort((a, b) => String(a[sortKey] ?? "").localeCompare(String(b[sortKey] ?? ""), "pl", { numeric: true, sensitivity: "base" }) * sortDirection);
    const pages = Math.max(1, Math.ceil(filtered.length / pageSize)); page = Math.min(page, pages - 1); tbody.replaceChildren();
    for (const row of filtered.slice(page * pageSize, (page + 1) * pageSize)) {
      const tr = node("tr"); for (const column of columns) tr.append(column.render ? column.render(row) : tableCell(row[column.key])); tbody.append(tr);
    }
    if (!filtered.length) { const tr = node("tr"); const td = node("td"); td.colSpan = columns.length; td.append(node("div", "empty-state", emptyTitle), node("p", "muted", emptyDescription)); tr.append(td); tbody.append(tr); }
    counter.textContent = `${filtered.length ? page * pageSize + 1 : 0}–${Math.min((page + 1) * pageSize, filtered.length)} z ${filtered.length}`;
    previous.disabled = page === 0; next.disabled = page >= pages - 1;
  }
  search.addEventListener("input", () => { page = 0; draw(); }); draw();
}
async function showSection(section) {
  activeSection = section; $("#section-title").textContent = sectionTitles[section]; buildNavigation();
  view.replaceChildren(); view.append(node("div", "loading-state", "Ładowanie danych…"));
  try {
    if (section === "dashboard") await renderDashboard();
    else if (section === "devices") await renderDevices();
    else if (section === "groups") await renderGroups();
    else if (section === "events") await renderEvents();
    else if (section === "policies") await renderPolicies();
    else if (section === "users") await renderUsers();
    else if (section === "audit") await renderAudit();
    else if (section === "knowledge") await renderKnowledge();
    else if (section === "models") await renderModels();
    else if (section === "backups") await renderBackups();
    else if (unavailableSources[section]) renderUnavailable(section);
  } catch (error) { showError(error, () => showSection(section)); }
}
async function renderModels() {
  const config = await request("/ai/configuration");
  let models = [];
  let discoveryError = "";
  try { models = await request("/ai/models"); } catch (error) { discoveryError = error.message; }
  view.replaceChildren(pageHeading("Lokalny model AI serwera", "Provider jest ograniczony do Ollama działającego na loopback serwera. Model nie jest pobierany. Sam zapis nazwy nie oznacza gotowości — wykonaj test syntetyczny."));
  const card = node("section", "card");
  card.append(node("p", "notice", config.enabled ? "Konfiguracja włączona; dostępność wymaga testu." : "Provider wyłączony. Analizy serwerowe korzystają z reguł."));
  if (discoveryError) card.append(node("p", "field-help", `Nie można teraz pobrać listy modeli: ${discoveryError}`));
  const endpointLabel = node("label", "field-label", "Lokalny adres usługi na serwerze");
  const endpoint = node("input"); endpoint.type = "url"; endpoint.value = config.endpoint; endpoint.maxLength = 2000;
  endpoint.setAttribute("aria-label", endpointLabel.textContent);
  const modelLabel = node("label", "field-label", "Model zainstalowany lokalnie");
  const model = node("select"); model.setAttribute("aria-label", modelLabel.textContent);
  for (const item of models) { const option = node("option", "", item.displayName); option.value = item.name; model.append(option); }
  const known = models.some(item => item.name === config.model);
  if (known) model.value = config.model;
  else if (config.model) { const option = node("option", "", `${config.model} · nie wykryto na serwerze`); option.value = config.model; model.prepend(option); model.value = config.model; }
  const enabled = node("input"); enabled.type = "checkbox"; enabled.checked = config.enabled; enabled.disabled = !canSystem();
  const enableLine = node("label", "notice"); enableLine.append(enabled, node("span", "", "Włącz lokalny model przy analizie urządzeń, które mają zgodę polityki"));
  const timeoutLabel = node("label", "field-label", "Limit czasu odpowiedzi (sekundy, 3–120)");
  const timeout = node("input"); timeout.type = "number"; timeout.min = "3"; timeout.max = "120"; timeout.value = config.timeoutSeconds;
  const result = node("p", "muted", "Nie wykonano testu w tej sesji.");
  const save = actionButton("Zapisz konfigurację", async () => {
    try {
      await request("/ai/configuration", { method: "PUT", body: JSON.stringify({ endpoint: endpoint.value, model: model.value, enabled: enabled.checked, timeoutSeconds: Number(timeout.value), expectedVersion: config.version }) });
      toast("Konfigurację AI zapisano. Dostępność nadal wymaga testu."); await renderModels();
    } catch (error) { toast(error.message, "error"); }
  }, "primary");
  const test = actionButton("Testuj połączenie i syntetyczną analizę", async () => {
    if (!model.value) { toast("Najpierw wykryj i wybierz lokalny model.", "warning"); return; }
    try {
      const output = await request("/ai/test", { method: "POST", body: JSON.stringify({ model: model.value }) });
      result.textContent = `Test odpowiedział: ${output.risk} / ${output.category}. ${output.explanation} To test syntetyczny, nie ocena poprawności modelu.`;
      result.className = "notice";
    } catch (error) { result.textContent = error.message; result.className = "error-state"; }
  });
  if (!canSystem()) { save.disabled = true; test.disabled = true; }
  card.append(endpointLabel, endpoint, modelLabel, model, enableLine, timeoutLabel, timeout, save, test, result);
  if (models.length) {
    const list = node("div", "grid");
    for (const item of models) list.append(node("p", "muted small", item.displayName));
    card.append(node("h3", "", `Lokalnie wykryte modele (${models.length})`), list);
  }
  view.append(card);
}
async function renderKnowledge() {
  const documents = await request("/knowledge/documents");
  const heading = pageHeading("Centralna baza wiedzy", "Dokumenty są zapisywane lokalnie na serwerze i indeksowane przez SQLite FTS5. Wyszukiwanie jest pełnotekstowe, nie semantyczne.");
  view.replaceChildren(heading);
  const controls = node("section", "card");
  controls.append(node("h3", "", "Dodaj źródło"), node("p", "muted", "Formaty: TXT, Markdown i DOCX · limit 10 MB · PDF i embeddingi nie są dostępne."));
  const file = node("input"); file.type = "file"; file.accept = ".txt,.md,.docx"; file.setAttribute("aria-label", "Wybierz plik wiedzy");
  const importButton = actionButton("Importuj dokument", async () => {
    if (!file.files?.length) { toast("Wybierz dokument do importu.", "warning"); return; }
    const selected = file.files[0];
    try {
      const response = await fetch("/api/v1/admin/knowledge/documents", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/octet-stream", "X-Sentinel-Filename": selected.name }, body: selected, cache: "no-store" });
      const payload = await response.json().catch(() => null);
      if (response.status === 401) { clearSession(); throw new Error("Sesja wygasła. Zaloguj się ponownie."); }
      if (!response.ok) throw new Error(payload?.error || payload?.detail || `Import nie powiódł się (HTTP ${response.status}).`);
      toast(`Zaindeksowano ${payload.name}: ${payload.chunkCount} fragmentów.`); await renderKnowledge();
    } catch (error) { toast(error.message || "Nie udało się zaimportować dokumentu.", "error"); }
  }, "primary");
  if (!canSecurity()) importButton.disabled = true;
  controls.append(file, importButton); view.append(controls);
  const list = node("section", "card"); list.append(node("h3", "", `Źródła (${documents.length})`));
  if (documents.length === 0) list.append(node("p", "muted", "Brak zaimportowanych dokumentów."));
  for (const document of documents) {
    const row = node("article", "notice"); const content = node("div");
    content.append(node("strong", "", document.name), node("p", "muted small", `${document.chunkCount} fragmentów · ${new Date(document.importedAt).toLocaleString("pl-PL")}`)); row.append(content);
    if (canSecurity()) row.append(actionButton("Usuń", async () => { if (!confirm(`Usunąć dokument „${document.name}” z indeksu?`)) return; await request(`/knowledge/documents/${encodeURIComponent(document.id)}`, { method: "DELETE" }); toast("Dokument usunięty."); await renderKnowledge(); }));
    list.append(row);
  }
  view.append(list);
  const search = node("section", "card"); search.append(node("h3", "", "Test wyszukiwania"));
  const input = node("input"); input.type = "search"; input.maxLength = 4000; input.placeholder = "Wpisz słowa kluczowe"; input.setAttribute("aria-label", "Zapytanie do lokalnej bazy wiedzy");
  const results = node("div"); const submit = actionButton("Szukaj", async () => {
    const query = input.value.trim(); if (!query) { toast("Wpisz słowa do wyszukania.", "warning"); return; }
    const hits = await request(`/knowledge/search?query=${encodeURIComponent(query)}&limit=10`); results.replaceChildren();
    if (!hits.length) results.append(node("p", "muted", "Brak pasujących fragmentów; brak wyniku nie oznacza bezpieczeństwa."));
    for (const hit of hits) { const item = node("article", "notice"); item.append(node("strong", "", hit.sourceName), node("p", "muted", `Fragment ${hit.chunkNumber + 1}`), node("p", "", hit.excerpt)); results.append(item); }
  }, "primary");
  search.append(input, submit, results); view.append(search);
}
async function renderDashboard() {
  const [devices, events, audit, health, documents, aiConfig] = await Promise.all([
    request("/devices"), request("/events?limit=100"), canSecurity() ? request("/audit?limit=5") : Promise.resolve([]), fetch("/readyz", { cache: "no-store" }).then(r => r.ok ? r.json() : null).catch(() => null), request("/knowledge/documents"), request("/ai/configuration")
  ]);
  view.replaceChildren(pageHeading("Centrum bezpieczeństwa", "Rzeczywisty stan floty i ostatnich zdarzeń.", statusBadge(health?.status === "ready" ? "Serwer gotowy" : "Serwer niedostępny", health?.status === "ready" ? "success" : "danger")));
  const active = devices.filter(d => !d.revoked); const online = active.filter(d => d.isOnline); const needsAttention = active.filter(d => d.lastError);
  const stats = node("div", "grid stats");
  stats.append(statCard("Zarejestrowane urządzenia", String(active.length), "Bez unieważnionych tożsamości"), statCard("Aktywne teraz", String(online.length), "Heartbeat w ostatnich 2 minutach"), statCard("Wymagają uwagi", String(needsAttention.length), "Zgłoszony kod błędu"), statCard("Ostatnie zdarzenia", String(events.length), "Maksymalnie 100 wpisów z serwera"), statCard("Konfiguracja AI", aiConfig.enabled ? "Włączona" : "Wyłączona", aiConfig.enabled ? "Gotowość sprawdź testem modelu" : "Analiza bez modelu"), statCard("Dokumenty wiedzy", String(documents.length), "Centralny indeks FTS5"));
  view.append(stats);
  const row = node("div", "grid two-col");
  const incidentsCard = node("section", "card"); const incidentsHead = node("div", "section-head"); incidentsHead.append(node("h2", "", "Ostatnie zdarzenia")); incidentsCard.append(incidentsHead);
  if (!events.length) { incidentsCard.append(node("div", "empty-state", "Nie ma jeszcze zdarzeń")); }
  else {
    const list = node("div", "grid");
    for (const event of events.slice(0, 5)) { const item = node("div", "notice"); item.append(node("strong", "", `${event.category} · ryzyko ${event.riskLevel}/4`), node("div", "muted small", `${event.ruleCode} · ${new Date(event.occurredAt).toLocaleString("pl-PL")}`)); list.append(item); }
    incidentsCard.append(list);
  }
  const auditCard = node("section", "card"); const auditHead = node("div", "section-head"); auditHead.append(node("h2", "", "Ostatnie operacje administratorów")); auditCard.append(auditHead);
  if (!audit.length) auditCard.append(node("div", "empty-state", "Brak wpisów audytowych"));
  else for (const item of audit) { const line = node("div", "notice"); line.append(node("strong", "", item.action), node("span", "cell-sub", `${item.actorUsername || "system"} · ${new Date(item.timestamp).toLocaleString("pl-PL")}`)); auditCard.append(line); }
  row.append(incidentsCard);
  const errorsCard = node("section", "card"); errorsCard.append(node("h2", "", "Ostatnie błędy techniczne"));
  if (!needsAttention.length) errorsCard.append(node("div", "empty-state", "Urządzenia nie zgłaszają błędów."));
  else for (const device of needsAttention.slice(0, 5)) { const line = node("div", "notice"); line.append(node("strong", "", device.name), node("div", "muted small", `${device.lastError} · ${device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString("pl-PL") : "brak czasu"}`)); errorsCard.append(line); }
  row.append(errorsCard); if (canSecurity()) row.append(auditCard); view.append(row);
  const severity = node("section", "card threat-summary"); severity.append(node("h2", "", "Ryzyko w ostatnich zdarzeniach"), node("p", "muted small", "Rozkład maksymalnie 100 ostatnich wpisów; nie jest to pełny licznik incydentów."));
  const labels = [[4,"Krytyczne"],[3,"Wysokie"],[2,"Średnie"],[1,"Niskie"],[0,"Informacyjne"]];
  for (const [level,label] of labels) { const count = events.filter(e => Number(e.riskLevel) === level).length; const line = node("div", "severity-row"); line.append(node("span", "severity-name", label), node("span", "severity-count", String(count))); const meter = node("div", "severity-meter"); const fill = node("span", `severity-fill level-${level}`); fill.style.width = `${events.length ? Math.round(count / events.length * 100) : 0}%`; meter.append(fill); line.append(meter); severity.append(line); }
  view.append(severity);
  setServerStatus(health?.status === "ready");
}
function setServerStatus(ready) {
  const dot = $("#server-dot"); dot.classList.toggle("green", ready); dot.classList.toggle("red", !ready);
  $("#api-status").textContent = ready ? "gotowy · API v1" : "brak odpowiedzi";
}
async function refreshServerStatus() {
  try { const response = await fetch("/readyz", { cache: "no-store" }); const result = response.ok ? await response.json() : null; setServerStatus(result?.status === "ready"); }
  catch { setServerStatus(false); }
}
function renderUnavailable(section) {
  const info = unavailableSources[section];
  view.replaceChildren(pageHeading(sectionTitles[section], "Zakres dostępny w bieżącym API."));
  const card = node("section", "card unavailable-state");
  card.append(node("h2", "", info.title), node("p", "muted", info.detail));
  const source = node("p", "field-help", `Źródło danych: ${info.source}`); card.append(source); view.append(card);
}
async function renderBackups() {
  view.replaceChildren(pageHeading("Kopie zapasowe", "Twórz spójne kopie bazy serwera. Pliki zawierają dane administracyjne i powinny być przechowywane w bezpiecznym miejscu."));
  const card = node("section", "card");
  card.append(node("h2", "", "Utwórz kopię bazy"), node("p", "muted", "Kopia zawiera urządzenia, zdarzenia, polityki, konta administratorów i dziennik audytowy. Dostęp ma wyłącznie administrator systemu."));
  const create = actionButton("Utwórz kopię zapasową", async () => {
    create.disabled = true;
    try {
      const result = await request("/backups", { method: "POST" });
      const response = await fetch(result.downloadUrl, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
      if (!response.ok) throw new Error("Nie udało się pobrać utworzonej kopii.");
      const link = document.createElement("a"); link.href = URL.createObjectURL(await response.blob()); link.download = result.fileName; link.click();
      setTimeout(() => URL.revokeObjectURL(link.href), 30000); toast("Kopia została utworzona i pobrana.");
    } catch (error) { toast(error.message, "error"); }
    finally { create.disabled = false; }
  }, "primary");
  card.append(create, node("p", "field-help", "Tworzenie używa mechanizmu SQLite online backup i sprawdza integralność pliku. Przywracanie wymaga zatrzymania usługi i nie jest dostępne w panelu."));
  view.append(card);
}
async function renderDevices() {
  const [devices, groups] = await Promise.all([request("/devices"), request("/groups")]);
  view.replaceChildren(pageHeading("Urządzenia", "Przeglądaj łączność i przypisanie. Otwórz szczegóły, aby zmienić grupę."));
  const tableHost = node("section", "card"); view.append(tableHost);
  const columns = [
    { title: "Urządzenie", render: d => tableCell(d.name, d.id) }, { title: "Grupa", key: "group" }, { title: "Klient", key: "clientVersion" },
    { title: "Połączenie", render: d => tableCell(statusBadge(d.revoked ? "Unieważnione / odrzucone" : !d.approved ? "Oczekuje na akceptację" : d.isOnline ? "Online" : "Offline", d.revoked ? "danger" : !d.approved ? "warning" : d.isOnline ? "success" : "warning")) },
    { title: "Ostatni sygnał", render: d => tableCell(d.lastSeenAt ? new Date(d.lastSeenAt).toLocaleString("pl-PL") : "Brak") },
    { title: "Błąd", render: d => tableCell(d.lastError || "—") },
    { title: "Działania", render: d => { const cell = node("td"); cell.append(actionButton("Szczegóły", () => showDeviceDetails(d, groups))); if (!d.revoked && canSecurity() && !d.approved) { cell.append(actionButton("Zatwierdź", () => setDeviceApproval(d, true))); cell.append(actionButton("Odrzuć", () => setDeviceApproval(d, false))); } else if (!d.revoked && canSecurity()) cell.append(actionButton("Odłącz", () => revokeDevice(d))); return cell; } }
  ];
  pagedTable(tableHost, devices, columns, d => `${d.name} ${d.id} ${d.group} ${d.clientVersion} ${d.lastError || ""}`, "Nie zarejestrowano urządzeń", "Utwórz zaproszenie w sekcji Grupy urządzeń.", [{ label: "Filtruj według stanu połączenia", options: [["all","Wszystkie stany"],["online","Online"],["offline","Offline"],["pending","Oczekuje na akceptację"],["revoked","Unieważnione / odrzucone"]], getValue: d => d.revoked ? "revoked" : !d.approved ? "pending" : d.isOnline ? "online" : "offline" }]);
}
async function setDeviceApproval(device, approved) {
  const message = approved ? `Zatwierdzić urządzenie „${device.name}”?` : `Odrzucić urządzenie „${device.name}” i unieważnić jego poświadczenie?`;
  if (!window.confirm(message)) return;
  try { await request(`/devices/${encodeURIComponent(device.id)}/approval`, { method: "PUT", body: JSON.stringify({ approved }) }); toast(approved ? "Urządzenie zatwierdzone." : "Urządzenie odrzucone i unieważnione."); await renderDevices(); }
  catch (error) { toast(error.message, "error"); }
}
async function showDeviceDetails(device, groups) {
  const detail = node("section", "card"); const modal = node("dialog"); modal.className = "details-dialog";
  modal.append(pageHeading(device.name, device.id));
  const fields = node("div", "grid two-col");
  for (const [name, value] of [["Grupa", device.group], ["Wersja klienta", device.clientVersion], ["Zarejestrowano", new Date(device.registeredAt).toLocaleString("pl-PL")], ["Ostatnia komunikacja", device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString("pl-PL") : "Brak"], ["Stan", device.revoked ? "Unieważnione / odrzucone" : !device.approved ? "Oczekuje na akceptację" : device.isOnline ? "Online" : "Offline"], ["Ostatni błąd", device.lastError || "Brak"]]) { const card = node("div", "notice"); card.append(node("span", "muted small", name), node("div", "cell-main", value)); fields.append(card); }
  modal.append(fields);
  if (canSecurity() && !device.revoked && !device.approved) {
    const approvals = node("section", "card"); approvals.append(node("h3", "", "Wymagana akceptacja administratora"));
    approvals.append(actionButton("Zatwierdź urządzenie", async () => { await setDeviceApproval(device, true); modal.close(); }, "primary"));
    approvals.append(actionButton("Odrzuć urządzenie", async () => { await setDeviceApproval(device, false); modal.close(); }, "danger")); modal.append(approvals);
  }
  if (canSecurity() && !device.revoked) {
    const assign = node("form", "card"); assign.append(node("h3", "", "Przypisz do grupy"));
    const select = node("select"); select.required = true; for (const group of groups) { const option = node("option", "", group.name); option.value = group.id; if (group.name === device.group) option.selected = true; select.append(option); }
    const save = actionButton("Zapisz grupę", async () => { try { await request(`/devices/${encodeURIComponent(device.id)}/group`, { method: "PUT", body: JSON.stringify({ groupId: select.value }) }); modal.close(); toast("Zmieniono przypisanie urządzenia."); await renderDevices(); } catch (error) { toast(error.message, "error"); } }, "primary");
    assign.append(select, save); modal.append(assign);
  }
  const effective = await request(`/devices/${encodeURIComponent(device.id)}/policy`).catch(() => null);
  if (effective) { const policy = node("section", "card"); policy.append(node("h3", "", "Efektywna konfiguracja"), node("p", "muted small", `Wersja globalna ${effective.globalVersion} · grupa ${effective.groupVersion} · urządzenie ${effective.deviceVersion}`)); const pre = node("pre", "code-box", JSON.stringify(effective.effective, null, 2)); policy.append(pre); modal.append(policy); }
  modal.append(actionButton("Zamknij", () => modal.close())); document.body.append(modal); modal.addEventListener("close", () => modal.remove()); modal.showModal();
}
async function revokeDevice(device) {
  if (!window.confirm(`Unieważnić urządzenie „${device.name}”? Jego poświadczenie przestanie działać natychmiast.`)) return;
  try { await request(`/devices/${encodeURIComponent(device.id)}`, { method: "DELETE" }); toast("Unieważniono urządzenie."); await renderDevices(); }
  catch (error) { toast(error.message, "error"); }
}
async function renderGroups() {
  const groups = await request("/groups");
  view.replaceChildren(pageHeading("Grupy urządzeń", "Grupy przypisują urządzenia i stanowią warstwę dziedziczenia polityk."));
  const row = node("div", "grid two-col"); const listCard = node("section", "card"); listCard.append(node("h2", "", "Zarządzane grupy"));
  const tableHost = node("div"); listCard.append(tableHost);
  pagedTable(tableHost, groups, [{ title: "Nazwa", key: "name" }, { title: "Utworzono", render: g => tableCell(new Date(g.createdAt).toLocaleDateString("pl-PL")) }, { title: "Wersja polityki", key: "policyVersion" }, { title: "Działania", render: g => { const td = node("td"); td.append(actionButton("Polityka", () => { selectedScope = "group"; selectedTarget = g.id; void showSection("policies"); })); return td; } }], g => `${g.name} ${g.id}`, "Brak grup", "Utwórz grupę, aby przypisywać do niej urządzenia.", [{ label: "Filtruj według wersji polityki", options: [["all","Wszystkie grupy"],["0","Wersja 0"],["changed","Zmienione polityki"]], getValue: g => Number(g.policyVersion) === 0 ? "0" : "changed" }]);
  row.append(listCard);
  if (canSecurity()) {
    const actions = node("div", "grid"); const createCard = node("form", "card"); createCard.append(node("h2", "", "Nowa grupa")); const name = inputField("Nazwa grupy", "name", "text", 80); const save = node("button", "button primary", "Utwórz grupę"); save.type = "submit"; createCard.append(name.label, name.input, save);
    createCard.addEventListener("submit", async e => { e.preventDefault(); try { await request("/groups", { method: "POST", body: JSON.stringify({ name: name.input.value.trim() }) }); toast("Utworzono grupę."); await renderGroups(); } catch (error) { toast(error.message, "error"); } }); actions.append(createCard);
    const inviteCard = node("form", "card"); inviteCard.append(node("h2", "", "Zaproszenie do rejestracji")); const group = inputField("Grupa", "group", "select"); for (const item of groups) { const opt = node("option", "", item.name); opt.value = item.name; group.input.append(opt); }
    const days = inputField("Ważność (dni)", "days", "number", 30); days.input.min = "1"; days.input.value = "7"; const max = inputField("Maksymalna liczba rejestracji", "maximumRegistrations", "number", 1000); max.input.min = "1"; max.input.value = "1";
    const approvalLabel = node("label", "field-label", "Wymagaj ręcznej akceptacji administratora"); const approval = node("input"); approval.type = "checkbox"; approvalLabel.prepend(approval);
    const submit = node("button", "button primary", "Utwórz kod"); submit.type = "submit"; inviteCard.append(group.label, group.input, days.label, days.input, max.label, max.input, approvalLabel, submit);
    const output = node("div"); inviteCard.append(output);
    inviteCard.addEventListener("submit", async e => { e.preventDefault(); try { const expiry = new Date(Date.now() + Number(days.input.value) * 86400000).toISOString(); const result = await request("/invitations", { method: "POST", body: JSON.stringify({ group: group.input.value, expiresAt: expiry, maximumRegistrations: Number(max.input.value), requiresApproval: approval.checked }) }); output.replaceChildren(node("p", "notice success", result.requiresApproval ? "Kod utworzy urządzenie oczekujące na akceptację administratora. Kod jest widoczny tylko teraz." : "Kod jest widoczny tylko teraz. Skopiuj go do bezpiecznego procesu wdrożeniowego."), node("div", "code-box", result.registrationCode)); toast("Utworzono zaproszenie. Kod nie zostanie ponownie wyświetlony."); } catch (error) { toast(error.message, "error"); } });
    actions.append(inviteCard); row.append(actions);
  }
  view.append(row);
}
function inputField(labelText, name, type = "text", maxLength = 200) {
  const label = node("label", "", labelText); const input = type === "select" ? node("select") : node("input"); input.id = `field-${name}`; input.name = name;
  if (type !== "select") { input.type = type; if (type !== "number") input.maxLength = maxLength; }
  label.htmlFor = input.id; return { label, input };
}
async function renderEvents() {
  const events = await request("/events?limit=500");
  view.replaceChildren(pageHeading("Zdarzenia i incydenty", "Metadane reguł z urządzeń. Surowa treść użytkownika nie jest przechowywana."));
  const card = node("section", "card"); const host = node("div"); card.append(host); view.append(card);
  pagedTable(host, events, [
    { title: "Czas", render: e => tableCell(new Date(e.occurredAt).toLocaleString("pl-PL")) }, { title: "Urządzenie", key: "deviceId" },
    { title: "Kategoria", key: "category" }, { title: "Ryzyko", render: e => tableCell(statusBadge(`${e.riskLevel}/4`, e.riskLevel >= 3 ? "danger" : e.riskLevel >= 2 ? "warning" : "info")) },
    { title: "Reguła", key: "ruleCode" }, { title: "Status", render: e => tableCell(statusBadge(e.status, e.status === "open" ? "warning" : e.status === "false_positive" ? "danger" : "success")) },
    { title: "Oznacz", render: e => { const td = node("td"); if (canSecurity() && e.status !== "false_positive") td.append(actionButton("Fałszywy alarm", async () => { await setEventStatus(e, "false_positive"); })); if (canSecurity() && e.status !== "resolved") td.append(actionButton("Rozwiązane", async () => { await setEventStatus(e, "resolved"); })); return td; } }
  ], e => `${e.deviceId} ${e.category} ${e.ruleCode} ${e.status}`, "Brak zdarzeń", "Serwer nie otrzymał jeszcze metadanych zdarzeń.", [
    { label: "Filtruj według statusu", options: [["all","Wszystkie statusy"],["open","Otwarte"],["resolved","Rozwiązane"],["false_positive","Fałszywe alarmy"]], getValue: e => e.status },
    { label: "Filtruj według poziomu ryzyka", options: [["all","Każde ryzyko"],["4","Krytyczne"],["3","Wysokie"],["2","Średnie"],["1","Niskie"],["0","Informacyjne"]], getValue: e => e.riskLevel }
  ]);
}
async function setEventStatus(event, status) {
  try { await request(`/events/${encodeURIComponent(event.deviceId)}/${encodeURIComponent(event.eventId)}/status`, { method: "PUT", body: JSON.stringify({ status }) }); toast("Zmieniono status zdarzenia."); await renderEvents(); }
  catch (error) { toast(error.message, "error"); }
}
async function renderPolicies() {
  const [groups, devices] = await Promise.all([request("/groups"), request("/devices")]);
  view.replaceChildren(pageHeading("Polityki bezpieczeństwa", "Hierarchia: urządzenie → grupa → globalnie → wartości bezpieczne. Null oznacza dziedziczenie."));
  const card = node("section", "card"); const controls = node("div", "form-grid");
  const scopeLabel = node("label", "", "Zakres"); const scope = node("select");
  for (const [value, text] of [["global", "Globalnie"], ["group", "Grupa"], ["device", "Urządzenie"]]) { const option = node("option", "", text); option.value = value; scope.append(option); }
  scope.value = selectedScope; const targetLabel = node("label", "", "Cel"); const target = node("select");
  controls.append(scopeLabel, scope, targetLabel, target); card.append(controls);
  const help = node("p", "field-help", "Zapis zastępuje dokument tej warstwy. Użyj null dla ustawienia dziedziczonego i [] dla jawnie pustej listy."); card.append(help);
  const editorLabel = node("label", "", "Dokument polityki (JSON)"); const editor = node("textarea"); editor.spellcheck = false; card.append(editorLabel, editor);
  const confirmationLabel = node("label", "field-help", "Zmiana trybu serwerowego/hybrydowego lub wysyłania kontekstu wymaga administratora systemowego i jawnego potwierdzenia.");
  const actions = node("div", "form-actions"); const load = actionButton("Wczytaj", loadSelectedPolicy); const save = actionButton("Zapisz politykę", saveSelectedPolicy, "primary"); save.disabled = !canSecurity(); actions.append(load, save); card.append(confirmationLabel, actions); view.append(card);
  function refreshTargets() {
    selectedScope = scope.value; target.replaceChildren();
    if (scope.value === "group") for (const group of groups) { const option = node("option", "", group.name); option.value = group.id; target.append(option); }
    if (scope.value === "device") for (const device of devices.filter(d => !d.revoked)) { const option = node("option", "", `${device.name} · ${device.group}`); option.value = device.id; target.append(option); }
    target.disabled = scope.value === "global" || target.options.length === 0;
    if (scope.value === "global") target.append(new Option("Globalna polityka", ""));
    if (selectedTarget && [...target.options].some(o => o.value === selectedTarget)) target.value = selectedTarget; else selectedTarget = target.value;
  }
  scope.addEventListener("change", () => { selectedTarget = ""; refreshTargets(); void loadSelectedPolicy(); });
  target.addEventListener("change", () => { selectedTarget = target.value; void loadSelectedPolicy(); });
  refreshTargets(); await loadSelectedPolicy();
  async function loadSelectedPolicy() {
    selectedTarget = target.value;
    const path = scope.value === "global" ? "/policies/global" : scope.value === "group" ? `/groups/${encodeURIComponent(selectedTarget)}/policy` : `/devices/${encodeURIComponent(selectedTarget)}/policy/override`;
    if (scope.value !== "global" && !selectedTarget) { editor.value = ""; loadedPolicy = null; return; }
    try { loadedPolicy = await request(path); editor.value = JSON.stringify(loadedPolicy.policy || {}, null, 2); help.textContent = `Aktualna wersja tej warstwy: ${loadedPolicy.version}. Zmiany są audytowane i wymagają zgodnego expectedVersion.`; }
    catch (error) { loadedPolicy = null; editor.value = ""; toast(error.message, "error"); }
  }
  async function saveSelectedPolicy() {
    if (!loadedPolicy) { toast("Najpierw wczytaj istniejącą warstwę polityki.", "error"); return; }
    let policy; try { policy = JSON.parse(editor.value); if (!policy || Array.isArray(policy) || typeof policy !== "object") throw new Error(); }
    catch { toast("Polityka musi być poprawnym obiektem JSON.", "error"); return; }
    const sensitive = policy.includeContext === true || ["server", "hybrid"].includes(policy.analysisMode);
    if (sensitive && !window.confirm("Ta polityka może przesyłać dane do serwera. Kontynuować? Serwer wymaga roli administratora systemowego.")) return;
    const path = scope.value === "global" ? "/policies/global" : scope.value === "group" ? `/groups/${encodeURIComponent(selectedTarget)}/policy` : `/devices/${encodeURIComponent(selectedTarget)}/policy`;
    try { await request(path, { method: "PUT", body: JSON.stringify({ policy, expectedVersion: loadedPolicy.version, confirmedSensitiveChange: sensitive }) }); toast("Zapisano i zarejestrowano zmianę polityki."); await loadSelectedPolicy(); }
    catch (error) { toast(error.message, "error"); }
  }
}
function canSecurity() { return ["SystemAdministrator", "SecurityAdministrator"].includes(identity?.role); }
function canSystem() { return identity?.role === "SystemAdministrator"; }
async function renderUsers() {
  const users = await request("/users"); view.replaceChildren(pageHeading("Administratorzy i role", "Konta, role i dostęp do operacji administracyjnych."));
  const card = node("section", "card"); const host = node("div"); card.append(host); view.append(card);
  const columns = [{ title: "Użytkownik", key: "username" }, { title: "Rola", render: u => tableCell(u.role) }, { title: "Status", render: u => tableCell(statusBadge(u.disabled ? "Wyłączony" : "Aktywny", u.disabled ? "danger" : "success")) }, { title: "Działania", render: u => {
    const td = node("td"); if (canSystem() && u.id !== identity.id) {
      const role = node("select"); for (const r of ["SystemAdministrator", "SecurityAdministrator", "Operator", "ReadOnly"]) { const o = node("option", "", r); o.value = r; o.selected = r === u.role; role.append(o); }
      const save = actionButton("Zapisz rolę", async () => { try { await request(`/users/${encodeURIComponent(u.id)}/role`, { method: "PUT", body: JSON.stringify({ role: role.value }) }); toast("Zmieniono rolę."); await renderUsers(); } catch (error) { toast(error.message, "error"); } });
      const disabled = actionButton(u.disabled ? "Włącz" : "Wyłącz", async () => { if (!window.confirm(`${u.disabled ? "Włączyć" : "Wyłączyć"} konto ${u.username}?`)) return; try { await request(`/users/${encodeURIComponent(u.id)}/disabled`, { method: "PUT", body: JSON.stringify({ disabled: !u.disabled }) }); toast("Zmieniono stan konta."); await renderUsers(); } catch (error) { toast(error.message, "error"); } });
      td.append(role, save, disabled);
    }
    return td;
  } }];
  pagedTable(host, users, columns, u => `${u.username} ${u.role} ${u.disabled}`, "Brak kont administratorów", "Utwórz konto administratora, aby przyznać dostęp.", [
    { label: "Filtruj według roli", options: [["all","Wszystkie role"],["SystemAdministrator","Administrator systemu"],["SecurityAdministrator","Administrator bezpieczeństwa"],["Operator","Operator"],["ReadOnly","Odczyt"]], getValue: u => u.role },
    { label: "Filtruj według stanu konta", options: [["all","Wszystkie konta"],["active","Aktywne"],["disabled","Wyłączone"]], getValue: u => u.disabled ? "disabled" : "active" }
  ]);
  if (canSystem()) {
    const form = node("form", "card"); form.append(node("h2", "", "Dodaj administratora")); const username = inputField("Nazwa użytkownika", "username", "text", 64); username.input.minLength = 3;
    const password = inputField("Hasło tymczasowe (14–128 znaków)", "password", "password", 128); password.input.minLength = 14;
    const role = inputField("Rola", "role", "select"); for (const r of ["SystemAdministrator", "SecurityAdministrator", "Operator", "ReadOnly"]) { const o = node("option", "", r); o.value = r; role.input.append(o); }
    const submit = node("button", "button primary", "Utwórz konto"); submit.type = "submit"; form.append(username.label, username.input, password.label, password.input, role.label, role.input, submit);
    form.addEventListener("submit", async e => { e.preventDefault(); try { await request("/users", { method: "POST", body: JSON.stringify({ username: username.input.value, password: password.input.value, role: role.input.value }) }); password.input.value = ""; toast("Utworzono konto administratora."); await renderUsers(); } catch (error) { toast(error.message, "error"); } }); view.append(form);
  }
}
async function renderAudit() {
  const entries = await request("/audit?limit=500"); view.replaceChildren(pageHeading("Dziennik audytowy", "Operacje administratorów i zmiany stanu. Sekrety oraz treści zdarzeń nie są zapisywane."));
  const card = node("section", "card"); const host = node("div"); card.append(host); view.append(card);
  const actions = [...new Set(entries.map(e => e.action).filter(Boolean))].sort((a,b) => a.localeCompare(b,"pl"));
  pagedTable(host, entries, [{ title: "Czas", render: e => tableCell(new Date(e.timestamp).toLocaleString("pl-PL")) }, { title: "Wykonawca", key: "actorUsername" }, { title: "Operacja", key: "action" }, { title: "Cel", key: "targetId" }], e => `${e.actorUsername || ""} ${e.action} ${e.targetId || ""}`, "Dziennik jest pusty", "Zdarzenia administracyjne pojawią się po wykonaniu operacji.", [{ label: "Filtruj według operacji", options: [["all","Wszystkie operacje"], ...actions.map(action => [action,action])], getValue: e => e.action }]);
}

$("#login-form").addEventListener("submit", async event => {
  event.preventDefault(); const errorBox = $("#login-error"); errorBox.hidden = true;
  const username = $("#username").value; const password = $("#password").value;
  try {
    const response = await fetch("/api/v1/admin/auth/login", { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify({ username, password }), cache: "no-store" });
    const result = await response.json().catch(() => null);
    if (!response.ok) throw new Error("Nie udało się zalogować. Sprawdź nazwę i hasło albo odczekaj po zbyt wielu próbach.");
    token = result.accessToken; identity = result.user; $("#password").value = ""; $("#account-name").textContent = `${identity.username} · ${identity.role}`;
    $("#login").hidden = true; $("#shell").hidden = false; await refreshServerStatus(); clearInterval(serverStatusTimer); serverStatusTimer = setInterval(() => { if (token) void refreshServerStatus(); }, 30000); await showSection("dashboard");
  } catch (error) { errorBox.textContent = error.message; errorBox.hidden = false; }
});
$("#logout").addEventListener("click", async () => { try { await request("/auth/logout", { method: "POST" }); } catch { /* token is cleared in memory even if the server is unreachable */ } clearSession(); });
$("#change-password").addEventListener("click", () => { $("#password-error").hidden = true; $("#password-dialog").showModal(); });
$("#password-cancel").addEventListener("click", () => $("#password-dialog").close());
$("#password-form").addEventListener("submit", async event => {
  event.preventDefault(); const error = $("#password-error"); error.hidden = true;
  try {
    await request("/auth/password", { method: "PUT", body: JSON.stringify({ currentPassword: $("#current-password").value, newPassword: $("#new-password").value }) });
    $("#password-dialog").close(); $("#password-form").reset(); clearSession();
    const loginError = $("#login-error"); loginError.textContent = "Hasło zmieniono. Zaloguj się ponownie."; loginError.className = "notice success"; loginError.hidden = false;
  } catch (failure) { error.textContent = failure.message; error.hidden = false; }
});
$("#menu-toggle").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
