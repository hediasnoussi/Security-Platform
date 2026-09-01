const state = { incidents: [], selectedIncidentId: null, refreshing: false };

const elements = {
  incidentsBody: document.querySelector("#incidents-body"),
  alertsBody: document.querySelector("#alerts-body"),
  severity: document.querySelector("#severity-filter"),
  category: document.querySelector("#category-filter"),
  refresh: document.querySelector("#refresh-button"),
  error: document.querySelector("#error-message"),
  status: document.querySelector("#connection-status"),
  updated: document.querySelector("#last-updated"),
  distribution: document.querySelector("#severity-distribution"),
  drawer: document.querySelector("#incident-drawer"),
  backdrop: document.querySelector("#drawer-backdrop"),
  detail: document.querySelector("#incident-detail"),
  detailTitle: document.querySelector("#detail-title"),
};

function text(value, fallback = "-") {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function formatTimestamp(value) {
  if (!value) return "-";
  const normalized = String(value).replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return text(value);
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  }).format(date);
}

function severityClass(value) {
  const normalized = text(value, "neutral").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(normalized) ? normalized : "neutral";
}

function createBadge(value) {
  const badge = document.createElement("span");
  badge.className = `badge badge-${severityClass(value)}`;
  badge.textContent = text(value);
  return badge;
}

function createCell(value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = text(value);
  if (className) cell.className = className;
  return cell;
}

function createEmptyRow(body, columns, message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = columns;
  cell.className = "empty-cell";
  cell.textContent = message;
  row.append(cell);
  body.replaceChildren(row);
}

async function request(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

function setKpis(stats) {
  [["total", "total_incidents"], ["critical", "critical"], ["high", "high"], ["medium", "medium"], ["low", "low"]]
    .forEach(([id, key]) => { document.querySelector(`#kpi-${id}`).textContent = text(stats[key], "0"); });
}

function renderSeverityDistribution(stats) {
  const entries = [["Critical", "critical"], ["High", "high"], ["Medium", "medium"], ["Low", "low"]];
  const total = Math.max(Number(stats.total_incidents) || 0, 1);
  const fragment = document.createDocumentFragment();
  entries.forEach(([label, key]) => {
    const count = Number(stats[key]) || 0;
    const row = document.createElement("div"); row.className = "severity-bar-row";
    const name = document.createElement("span"); name.textContent = label;
    const track = document.createElement("div"); track.className = "severity-bar-track";
    const fill = document.createElement("div"); fill.className = `severity-bar-fill ${key}`;
    fill.style.width = `${Math.min((count / total) * 100, 100)}%`;
    track.append(fill);
    const countNode = document.createElement("strong"); countNode.textContent = String(count);
    row.append(name, track, countNode); fragment.append(row);
  });
  elements.distribution.replaceChildren(fragment);
}

function populateCategories(incidents) {
  const selected = elements.category.value;
  const categories = [...new Set(incidents.map(item => text(item.category, "Unclassified")))].sort();
  elements.category.replaceChildren(new Option("All", ""));
  categories.forEach(category => elements.category.add(new Option(category, category)));
  elements.category.value = categories.includes(selected) ? selected : "";
}

function filteredIncidents() {
  return [...state.incidents]
    .filter(item => (!elements.severity.value || item.severity === elements.severity.value)
      && (!elements.category.value || item.category === elements.category.value))
    .sort((left, right) => Number(right.risk_score || 0) - Number(left.risk_score || 0));
}

function renderIncidents() {
  const incidents = filteredIncidents();
  if (!incidents.length) return createEmptyRow(elements.incidentsBody, 9, "No incidents match the current filters.");
  const fragment = document.createDocumentFragment();
  incidents.forEach(incident => {
    const row = document.createElement("tr");
    row.dataset.incidentId = text(incident.incident_id, "");
    row.tabIndex = 0;
    if (incident.incident_id === state.selectedIncidentId) row.classList.add("selected");
    const severity = createCell("", "severity-cell"); severity.append(createBadge(incident.severity));
    row.append(
      createCell(incident.incident_id), severity, createCell(incident.risk_score), createCell(incident.category),
      createCell(incident.subcategory), createCell(incident.agent_name || incident.agent_id),
      createCell(formatTimestamp(incident.first_seen)), createCell(formatTimestamp(incident.last_seen)), createCell(incident.status),
    );
    row.addEventListener("click", () => openIncident(incident.incident_id));
    row.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openIncident(incident.incident_id); }
    });
    fragment.append(row);
  });
  elements.incidentsBody.replaceChildren(fragment);
}

function renderAlerts(alerts) {
  const recent = [...alerts].sort((left, right) => String(right.timestamp || "").localeCompare(String(left.timestamp || ""))).slice(0, 20);
  if (!recent.length) return createEmptyRow(elements.alertsBody, 7, "No recent alerts available.");
  const fragment = document.createDocumentFragment();
  recent.forEach(alert => {
    const row = document.createElement("tr");
    const level = createCell("", "risk-cell"); level.append(createBadge(alert.risk_level));
    row.append(
      createCell(formatTimestamp(alert.timestamp)), createCell(alert.rule_id), createCell(alert.rule_description),
      createCell(alert.category), createCell(alert.risk_score), level, createCell(alert.agent_name || alert.agent_id),
    );
    fragment.append(row);
  });
  elements.alertsBody.replaceChildren(fragment);
}

function appendDetailField(container, label, value) {
  const item = document.createElement("div");
  const labelNode = document.createElement("span");
  const valueNode = document.createElement("strong");
  labelNode.textContent = label; valueNode.textContent = text(value);
  item.append(labelNode, valueNode); container.append(item);
}

function renderEventIds(eventIds) {
  const section = document.createElement("section"); section.className = "detail-section";
  const heading = document.createElement("h3"); heading.textContent = `Linked Events (${eventIds.length})`;
  const chips = document.createElement("div"); chips.className = "event-chips";
  const toggle = document.createElement("button"); toggle.type = "button"; toggle.className = "link-button";
  let expanded = false;
  const render = () => {
    chips.replaceChildren();
    (expanded ? eventIds : eventIds.slice(0, 3)).forEach(eventId => {
      const chip = document.createElement("span"); chip.className = "event-chip"; chip.textContent = text(eventId); chips.append(chip);
    });
    if (eventIds.length > 3) { toggle.textContent = expanded ? "Show fewer" : `+${eventIds.length - 3} more`; toggle.setAttribute("aria-expanded", String(expanded)); }
  };
  if (eventIds.length > 3) toggle.addEventListener("click", () => { expanded = !expanded; render(); });
  render(); section.append(heading, chips); if (eventIds.length > 3) section.append(toggle); return section;
}

function renderRecommendations(recommendations) {
  const section = document.createElement("section"); section.className = "detail-section recommendations-section";
  const heading = document.createElement("h3"); heading.textContent = `Recommendations (${recommendations.length})`; section.append(heading);
  let expandedIndex = null;
  const cards = recommendations.map((recommendation, index) => {
    const card = document.createElement("article"); card.className = "recommendation";
    const button = document.createElement("button"); button.type = "button"; button.className = "recommendation-toggle";
    const title = document.createElement("span"); title.className = "recommendation-title"; title.textContent = text(recommendation.title);
    const indicator = document.createElement("span"); indicator.className = "recommendation-indicator";
    button.append(createBadge(recommendation.priority), title, indicator);
    const content = document.createElement("div"); content.className = "recommendation-content"; content.hidden = true;
    const description = document.createElement("p"); description.textContent = text(recommendation.description);
    const rationaleTitle = document.createElement("h4"); rationaleTitle.textContent = "Why this matters";
    const rationale = document.createElement("p"); rationale.textContent = text(recommendation.rationale);
    const actionsTitle = document.createElement("h4"); actionsTitle.textContent = "Recommended actions";
    const actions = document.createElement("ol");
    (Array.isArray(recommendation.actions) ? recommendation.actions : []).forEach(action => {
      const item = document.createElement("li"); item.textContent = text(action); actions.append(item);
    });
    content.append(description, rationaleTitle, rationale, actionsTitle, actions);
    button.addEventListener("click", () => {
      expandedIndex = expandedIndex === index ? null : index;
      cards.forEach((item, itemIndex) => {
        const isExpanded = itemIndex === expandedIndex;
        item.button.setAttribute("aria-expanded", String(isExpanded));
        item.content.hidden = !isExpanded; item.card.classList.toggle("expanded", isExpanded);
      });
    });
    button.setAttribute("aria-expanded", "false"); card.append(button, content);
    return { card, button, content };
  });
  if (!cards.length) { const message = document.createElement("p"); message.textContent = "No recommendations available."; section.append(message); }
  cards.forEach(item => section.append(item.card)); return section;
}

function renderIncidentDetail(incident) {
  elements.detailTitle.textContent = text(incident.incident_id, "Incident detail");
  const content = document.createDocumentFragment();
  const hero = document.createElement("section"); hero.className = "detail-hero";
  const severity = createBadge(incident.severity);
  const title = document.createElement("h3"); title.textContent = text(incident.title);
  const description = document.createElement("p"); description.textContent = text(incident.description);
  hero.append(severity, title, description); content.append(hero);
  const grid = document.createElement("div"); grid.className = "detail-summary";
  appendDetailField(grid, "Incident ID", incident.incident_id); appendDetailField(grid, "Title", incident.title);
  appendDetailField(grid, "Severity", incident.severity); appendDetailField(grid, "Risk score", incident.risk_score);
  appendDetailField(grid, "Status", incident.status);
  appendDetailField(grid, "Category", incident.category); appendDetailField(grid, "Subcategory", incident.subcategory);
  appendDetailField(grid, "Agent", incident.agent_name || incident.agent_id);
  appendDetailField(grid, "First seen", formatTimestamp(incident.first_seen)); appendDetailField(grid, "Last seen", formatTimestamp(incident.last_seen));
  content.append(grid);
  const categories = document.createElement("section"); categories.className = "detail-section";
  const categoriesTitle = document.createElement("h3"); categoriesTitle.textContent = "Categories";
  const categoriesText = document.createElement("p");
  categoriesText.textContent = (Array.isArray(incident.categories) ? incident.categories : []).map(value => text(value)).join(", ") || text(incident.category);
  categories.append(categoriesTitle, categoriesText); content.append(categories);
  content.append(renderEventIds(Array.isArray(incident.event_ids) ? incident.event_ids : []));
  content.append(renderRecommendations(Array.isArray(incident.recommendations) ? incident.recommendations : []));
  elements.detail.replaceChildren(content);
}

function openIncident(incidentId) {
  const incident = state.incidents.find(item => item.incident_id === incidentId);
  if (!incident) return;
  state.selectedIncidentId = incidentId; renderIncidents(); renderIncidentDetail(incident);
  elements.drawer.classList.add("open"); elements.drawer.setAttribute("aria-hidden", "false"); elements.backdrop.hidden = false;
}

function closeDrawer() {
  elements.drawer.classList.remove("open"); elements.drawer.setAttribute("aria-hidden", "true"); elements.backdrop.hidden = true;
}

async function refreshDashboard() {
  if (state.refreshing) return;
  state.refreshing = true; elements.refresh.disabled = true; elements.status.textContent = "Refreshing"; elements.error.hidden = true;
  try {
    const [health, stats, incidents, alerts] = await Promise.all([request("/health"), request("/statistics"), request("/incidents"), request("/alerts")]);
    state.incidents = Array.isArray(incidents) ? incidents : [];
    setKpis(stats || {}); renderSeverityDistribution(stats || {}); populateCategories(state.incidents); renderIncidents(); renderAlerts(Array.isArray(alerts) ? alerts : []);
    const healthy = health && health.status === "ok";
    elements.status.textContent = healthy ? "Healthy" : "Unavailable"; elements.status.className = healthy ? "healthy" : "unavailable";
    elements.updated.textContent = `Last updated: ${formatTimestamp(new Date().toISOString())}`;
    if (state.selectedIncidentId) { const selected = state.incidents.find(item => item.incident_id === state.selectedIncidentId); if (selected) renderIncidentDetail(selected); }
  } catch (error) {
    elements.status.textContent = "Unavailable"; elements.status.className = "unavailable";
    elements.error.textContent = `Unable to refresh dashboard data. ${text(error.message, "Please try again.")}`; elements.error.hidden = false;
  } finally { state.refreshing = false; elements.refresh.disabled = false; }
}

elements.refresh.addEventListener("click", refreshDashboard);
elements.severity.addEventListener("change", renderIncidents); elements.category.addEventListener("change", renderIncidents);
document.querySelector("#drawer-close").addEventListener("click", closeDrawer); elements.backdrop.addEventListener("click", closeDrawer);
refreshDashboard(); window.setInterval(refreshDashboard, 15000);
