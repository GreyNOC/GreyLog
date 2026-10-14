(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const numberFormat = new Intl.NumberFormat();
  const clockFormat = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  const timeFormat = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  const dateTimeFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });
  const knownAlertSeverities = new Set(["critical", "high", "medium", "low", "info"]);
  const knownEventSeverities = new Set(["critical", "error", "warning", "info", "debug"]);
  const knownSourceStatuses = new Set(["live", "active", "healthy", "connected", "online", "idle", "error", "offline", "stale", "disconnected", "warning", "degraded"]);
  const STALE_AFTER_MS = 5000;
  const MAX_RENDERED_EVENTS = 200;

  let snapshot = null;
  let eventSource = null;
  let streamOpen = false;
  let streamError = false;
  let streamUnavailable = false;
  let streamOpenedAt = 0;
  let lastStreamAt = 0;
  let lastVisibleAt = 0;
  let paused = false;
  let bootstrapFailed = false;
  let locked = false;
  let authProbeTimer = null;
  let authProbeInFlight = false;
  let lastAuthProbeAt = 0;
  let startupInFlight = false;
  let unlockInFlight = false;
  let gatewaySaving = false;
  let gatewayOptionsKey = "";

  function stringValue(value, fallback = "—") {
    if (value === null || value === undefined || value === "") return fallback;
    if (typeof value === "object") return fallback;
    return String(value);
  }

  function safeNumber(value) {
    if (value === null || value === undefined || value === "") return null;
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 ? number : null;
  }

  function metricValue(value) {
    const number = safeNumber(value);
    return number === null ? "—" : numberFormat.format(number);
  }

  function dateValue(value) {
    if (value === null || value === undefined || value === "") return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function shortTime(value) {
    const date = dateValue(value);
    return date ? timeFormat.format(date) : "—";
  }

  function absoluteTime(value) {
    const date = dateValue(value);
    return date ? dateTimeFormat.format(date) : "Unknown time";
  }

  function relativeTime(value) {
    const date = dateValue(value);
    if (!date) return "Never";
    const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (seconds < 5) return "Just now";
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return dateTimeFormat.format(date);
  }

  function node(tag, className, content) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (content !== undefined) element.textContent = stringValue(content, "");
    return element;
  }

  function emptyState(message) {
    return node("div", "empty-state", message);
  }

  function normalizeSnapshot(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Invalid snapshot");
    return {
      now: data.now,
      metrics: data.metrics && typeof data.metrics === "object" ? data.metrics : {},
      traffic: Array.isArray(data.traffic) ? data.traffic : [],
      sources: Array.isArray(data.sources) ? data.sources : [],
      alerts: Array.isArray(data.alerts) ? data.alerts : [],
      events: Array.isArray(data.events) ? data.events : [],
      gateway: data.gateway && typeof data.gateway === "object" ? data.gateway : null,
    };
  }

  function acceptSnapshot(data, fromStream = false) {
    try {
      snapshot = normalizeSnapshot(data);
      if (fromStream) lastStreamAt = Date.now();
      bootstrapFailed = false;
      $("pause-button").disabled = false;
      if (!paused) renderSnapshot();
      renderConnection();
    } catch (error) {
      console.error("GreyLog ignored an invalid snapshot:", error);
    }
  }

  function showUnlock(message) {
    locked = true;
    if (eventSource) eventSource.close();
    eventSource = null;
    if (authProbeTimer) clearTimeout(authProbeTimer);
    authProbeTimer = null;
    streamOpen = false;
    streamError = false;
    streamOpenedAt = 0;
    lastStreamAt = 0;
    lastVisibleAt = 0;
    snapshot = null;
    paused = false;
    const pauseButton = $("pause-button");
    pauseButton.disabled = true;
    pauseButton.setAttribute("aria-pressed", "false");
    pauseButton.classList.remove("is-paused");
    $("pause-label").textContent = "Pause";
    $("app-shell").hidden = true;
    $("unlock-screen").hidden = false;
    $("unlock-error").textContent = message || "";
    $("unlock-error").classList.remove("is-error");
    $("unlock-token").value = "";
    $("unlock-token").focus();
  }

  function hideUnlock() {
    locked = false;
    $("unlock-screen").hidden = true;
    $("app-shell").hidden = false;
    $("unlock-error").textContent = "";
    $("unlock-error").classList.remove("is-error");
    $("page-title").focus();
  }

  function connectionState() {
    if (!streamOpen) return streamError ? "offline" : "connecting";
    if (!lastStreamAt) return streamOpenedAt && Date.now() - streamOpenedAt > STALE_AFTER_MS ? "stale" : "connecting";
    if (Date.now() - lastStreamAt > STALE_AFTER_MS) return "stale";
    if (paused) return "paused";
    return "connected";
  }

  function renderConnection() {
    const state = connectionState();
    const pill = $("connection-pill");
    const label = $("connection-label");
    const banner = $("signal-banner");
    const bannerText = $("signal-banner-text");
    const retry = $("retry-button");
    const staleBadge = $("chart-stale");
    pill.className = `connection-pill ${state}`;
    const names = { connected: "Connected", connecting: "Connecting", stale: "Stale", offline: "Disconnected", paused: "Paused" };
    label.textContent = names[state];
    banner.hidden = state === "connected" || state === "connecting";
    retry.hidden = state !== "offline" || streamUnavailable;
    if (state === "offline") {
      bannerText.textContent = streamUnavailable
        ? "Stream unavailable"
        : snapshot
        ? "Disconnected · Last snapshot shown"
        : bootstrapFailed ? "Connection failed · Retry" : "Connecting";
    } else if (state === "stale") {
      bannerText.textContent = "Stale · No update for 5s";
    } else if (state === "paused") {
      bannerText.textContent = "Paused · Updates continue";
    }
    staleBadge.hidden = state === "connected" || state === "connecting";
    staleBadge.textContent = state === "paused" ? "PAUSED" : state === "offline" ? "DISCONNECTED" : "STALE";
    if (snapshot && lastVisibleAt) {
      $("updated-label").textContent = `${paused ? "Paused" : "Synced"} ${relativeTime(lastVisibleAt)}`;
    } else {
      $("updated-label").textContent = state === "offline" ? "Disconnected" : "Connecting";
    }
  }

  function renderMetrics() {
    const metrics = snapshot.metrics;
    $("metric-epm").textContent = metricValue(metrics.eventsPerMinute);
    $("metric-alerts").textContent = metricValue(metrics.openAlerts);
    $("metric-sources").textContent = metricValue(metrics.activeSources);
    $("metric-total").textContent = metricValue(metrics.totalEvents);
    const total = safeNumber(metrics.totalSources);
    $("metric-sources-caption").textContent = total !== null
      ? `${numberFormat.format(total)} total · 60s`
      : "Last 60s";
  }

  function renderGateway() {
    const gateway = snapshot.gateway;
    const panel = $("gateway-panel");
    panel.hidden = !gateway;
    if (!gateway) return;
    const state = $("gateway-state");
    const current = gateway.current && typeof gateway.current === "object" ? gateway.current : null;
    const status = stringValue(gateway.status, "checking");
    state.classList.toggle("warning", status !== "detected");
    state.textContent = status === "detected" ? "Route detected"
      : status === "not-in-routes" ? "Route not found"
      : status === "unavailable" ? "Lookup unavailable" : "Checking";
    const selected = gateway.selection && typeof gateway.selection === "object" ? gateway.selection : { gateway: "auto", interface: null };
    if (status === "unavailable") {
      $("gateway-detail").textContent = `Local route lookup failed${gateway.error ? `: ${stringValue(gateway.error)}` : "."}`;
    } else if (current) {
      $("gateway-detail").textContent = `${stringValue(current.gateway)} via ${stringValue(current.interface, "unknown interface")} · ${stringValue(current.family)} · metric ${metricValue(current.metric)} · checked ${relativeTime(gateway.checkedAt)}`;
    } else if (selected.gateway && selected.gateway !== "auto") {
      $("gateway-detail").textContent = `${stringValue(selected.gateway)} is not in this computer's current default routes. Entered addresses are kept as selections, but route health is not confirmed.`;
    } else {
      $("gateway-detail").textContent = "No default gateway route detected on this computer.";
    }
    if ((current && current.family === "IPv6") || (selected.gateway && String(selected.gateway).includes(":"))) {
      $("gateway-detail").textContent += " Gateway syslog reception supports IPv4 senders only.";
    }
    const reachability = gateway.reachability && typeof gateway.reachability === "object" ? gateway.reachability : {};
    $("gateway-reachability").textContent = !reachability.enabled
      ? "ICMP echo check is off. Opt in at startup with --gateway-ping-interval 30."
      : reachability.status === "reply"
        ? `ICMP echo reply from ${stringValue(reachability.gateway)} · checked ${relativeTime(reachability.checkedAt)}. This does not test internet connectivity.`
        : reachability.status === "no-reply"
          ? `No ICMP echo reply from ${stringValue(reachability.gateway)} · checked ${relativeTime(reachability.checkedAt)}. Routers may block ICMP; this does not prove an outage.`
          : `ICMP echo status unknown${reachability.error ? `: ${stringValue(reachability.error)}` : "."}`;
    const syslog = gateway.syslog && typeof gateway.syslog === "object" ? gateway.syslog : {};
    $("gateway-syslog").textContent = syslog.enabled
      ? `Router log listener: UDP ${stringValue(syslog.bind)}:${stringValue(syslog.port)}. Configure the router to forward syslog to this computer's LAN IP and that port. Only the selected IPv4 gateway sender is accepted.`
      : "Router log listener is off. Enable it at startup with --syslog-port 5514 (or the installer SyslogPort option), then configure router syslog forwarding to this computer's LAN IP.";
    const routes = Array.isArray(gateway.routes) ? gateway.routes : [];
    const choices = routes.filter((route) => route && typeof route === "object" && typeof route.gateway === "string")
      .map((route) => ({
        value: JSON.stringify({ gateway: route.gateway, interface: route.interface || null }),
        label: `${route.gateway} · ${stringValue(route.interface, "unknown interface")} · metric ${metricValue(route.metric)}`,
      }));
    const selectedValue = selected.gateway === "auto" ? "auto" : JSON.stringify({ gateway: selected.gateway, interface: selected.interface || null });
    if (selectedValue !== "auto" && !choices.some((choice) => choice.value === selectedValue)) {
      choices.push({ value: selectedValue, label: `Manual: ${stringValue(selected.gateway)}` });
    }
    const key = JSON.stringify(choices);
    const select = $("gateway-select");
    if (key !== gatewayOptionsKey) {
      select.replaceChildren(new Option("Automatic (lowest route metric)", "auto"),
        ...choices.map((choice) => new Option(choice.label, choice.value)));
      gatewayOptionsKey = key;
    }
    if (!gatewaySaving) select.value = selectedValue;
  }

  async function saveGateway(selection) {
    if (gatewaySaving) return;
    gatewaySaving = true;
    const feedback = $("gateway-feedback");
    const select = $("gateway-select");
    select.disabled = true;
    feedback.classList.remove("is-error");
    feedback.textContent = "Saving selection";
    try {
      const response = await fetch("/api/gateways", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(selection),
      });
      if (response.status === 401) { showUnlock("Session expired"); return; }
      const data = await response.json();
      if (!response.ok) throw new Error(stringValue(data.error, "Gateway selection failed"));
      if (snapshot) snapshot.gateway = data;
      feedback.textContent = "Gateway selection saved";
      $("gateway-custom").value = "";
    } catch (error) {
      feedback.textContent = error.message || "Gateway selection failed";
      feedback.classList.add("is-error");
    } finally {
      gatewaySaving = false;
      select.disabled = false;
      if (snapshot) renderGateway();
    }
  }

  function makeSvg(tag, attributes = {}) {
    const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
    return element;
  }

  function renderTraffic() {
    const raw = snapshot.traffic;
    const grid = $("chart-grid");
    const line = $("chart-line");
    const area = $("chart-area");
    const glow = $("chart-glow");
    const dot = $("chart-end-dot");
    const empty = $("chart-empty");
    const width = 960;
    const top = 12;
    const bottom = 190;
    const height = bottom - top;
    grid.replaceChildren();
    for (let i = 0; i <= 3; i += 1) {
      const y = top + (height / 3) * i;
      grid.appendChild(makeSvg("line", { x1: 0, y1: y, x2: width, y2: y, class: `chart-grid-line${i === 3 ? " baseline" : ""}` }));
    }

    if (!snapshot.sources.length && safeNumber(snapshot.metrics.totalEvents) === 0) {
      line.setAttribute("d", "");
      area.setAttribute("d", "");
      glow.setAttribute("d", "");
      dot.hidden = true;
      empty.hidden = false;
      empty.textContent = "No sources";
      $("traffic-peak").textContent = "Peak —";
      $("traffic-summary").textContent = "No sources";
      $("traffic-chart-description").textContent = "No sources are configured. Traffic volume is unavailable.";
      return;
    }

    const points = raw.map((sample) => ({
      time: dateValue(sample && sample.time),
      count: safeNumber(sample && sample.count),
    })).filter((sample) => sample.count !== null);

    if (!points.length) {
      line.setAttribute("d", "");
      area.setAttribute("d", "");
      glow.setAttribute("d", "");
      dot.hidden = true;
      empty.hidden = false;
      empty.textContent = "No traffic";
      $("traffic-peak").textContent = "Peak —";
      $("traffic-summary").textContent = "No traffic";
      $("traffic-chart-description").textContent = "No traffic readings are available.";
      return;
    }

    empty.hidden = true;
    const peak = Math.max(...points.map((point) => point.count));
    const scale = Math.max(1, peak);
    const now = dateValue(snapshot.now) || points[points.length - 1].time || new Date();
    const windowStart = now.getTime() - 59000;
    const useTimes = points.every((point) => point.time !== null);
    const plotted = points.map((point, index) => {
      const x = useTimes
        ? Math.min(width, Math.max(0, ((point.time.getTime() - windowStart) / 59000) * width))
        : (points.length === 1 ? width : (index / (points.length - 1)) * width);
      const y = bottom - (point.count / scale) * height;
      return { x, y, count: point.count, time: point.time };
    });

    // A missing second is a gap, rather than a zero-volume measurement.
    const groups = [];
    let group = [];
    for (const point of plotted) {
      if (group.length && useTimes && point.time.getTime() - group[group.length - 1].time.getTime() > 1500) {
        groups.push(group);
        group = [];
      }
      group.push(point);
    }
    if (group.length) groups.push(group);
    const linePath = groups.map((segment) => segment.map((point, index) => `${index ? "L" : "M"}${point.x.toFixed(2)},${point.y.toFixed(2)}`).join(" ")).join(" ");
    const areaPath = groups.map((segment) => {
      const first = segment[0];
      const last = segment[segment.length - 1];
      return `M${first.x.toFixed(2)},${bottom} ` + segment.map((point) => `L${point.x.toFixed(2)},${point.y.toFixed(2)}`).join(" ") + ` L${last.x.toFixed(2)},${bottom} Z`;
    }).join(" ");
    line.setAttribute("d", linePath);
    glow.setAttribute("d", linePath);
    area.setAttribute("d", areaPath);
    const last = plotted[plotted.length - 1];
    dot.setAttribute("cx", last.x);
    dot.setAttribute("cy", last.y);
    dot.hidden = false;
    $("traffic-peak").textContent = `Peak ${numberFormat.format(peak)} / sec`;
    $("traffic-summary").textContent = `Latest ${numberFormat.format(last.count)} / sec`;
    $("traffic-chart-description").textContent = `${points.length} per-second readings in the last 60 seconds. Latest ${last.count} events per second. Peak ${peak} events per second.${groups.length > 1 ? " Missing intervals appear as gaps." : ""}`;
  }

  function renderSources() {
    const list = $("source-list");
    const sources = snapshot.sources;
    $("sources-count").textContent = String(sources.length);
    if (!sources.length) {
      list.replaceChildren(emptyState("No sources"));
      return;
    }
    const fragment = document.createDocumentFragment();
    for (const source of sources) {
      if (!source || typeof source !== "object") continue;
      const item = node("div", "source-item");
      const reportedStatus = stringValue(source.status, "unknown").toLowerCase();
      const status = reportedStatus === "stale" && !source.lastPoll ? "idle" : reportedStatus;
      item.appendChild(node("span", `source-led ${knownSourceStatuses.has(status) ? status : ""}`));
      const main = node("div", "source-main");
      const name = node("div", "source-name", source.name);
      name.title = stringValue(source.name);
      main.appendChild(name);
      const meta = node("div", "source-meta");
      const format = stringValue(source.format, "Unknown format");
      const errors = safeNumber(source.errors);
      const lastEvent = source.lastSeen ? `Last event ${relativeTime(source.lastSeen)}` : "No events";
      const lastPoll = source.lastPoll ? ` · Checked ${relativeTime(source.lastPoll)}` : "";
      meta.textContent = `${format} · ${lastEvent}${lastPoll}${errors ? ` · ${numberFormat.format(errors)} errors` : ""}`;
      main.appendChild(meta);
      if (status === "error" && source.lastError) {
        const detail = stringValue(source.lastError, "");
        const error = node("div", "source-error", `Error: ${detail}`);
        error.title = detail;
        main.appendChild(error);
      }
      item.appendChild(main);
      const right = node("div", "source-right");
      const stateLabel = node("span", "source-status", status);
      if (status === "idle") stateLabel.title = "No recent push events";
      if (status === "stale") stateLabel.title = "No recent collector check";
      right.appendChild(stateLabel);
      const events = safeNumber(source.events);
      right.appendChild(node("span", "source-events", events === null ? "— events" : `${numberFormat.format(events)} events`));
      item.appendChild(right);
      fragment.appendChild(item);
    }
    list.replaceChildren(fragment);
  }

  function evidenceText(evidence) {
    if (evidence === null || evidence === undefined || evidence === "") return "No evidence";
    if (typeof evidence === "string") return evidence;
    try { return JSON.stringify(evidence, null, 2); }
    catch { return "Evidence could not be displayed."; }
  }

  function renderAlerts() {
    const list = $("alert-list");
    const alerts = snapshot.alerts.filter((alert) => alert && typeof alert === "object");
    const openDetails = new Set(Array.from(list.querySelectorAll("details[open]"), (element) => element.dataset.alertId));
    const scrollTop = list.scrollTop;
    $("alerts-count").textContent = String(alerts.length);
    if (!alerts.length) {
      list.replaceChildren(emptyState("No alerts"));
      return;
    }
    const fragment = document.createDocumentFragment();
    for (const alert of alerts) {
      const severity = stringValue(alert.severity, "info").toLowerCase();
      const severityClass = knownAlertSeverities.has(severity) ? severity : "info";
      const details = node("details", `alert-card ${severityClass}`);
      details.dataset.alertId = stringValue(alert.id, "");
      details.open = openDetails.has(details.dataset.alertId);
      const summary = node("summary");
      const head = node("div", "alert-head");
      head.appendChild(node("span", `severity-pill ${severityClass}`, severity));
      const time = node("span", "alert-time", relativeTime(alert.lastSeen));
      time.title = absoluteTime(alert.lastSeen);
      head.appendChild(time);
      summary.appendChild(head);
      summary.appendChild(node("span", "alert-title", alert.rule));
      summary.appendChild(node("span", "alert-message", alert.message));
      const meta = node("div", "alert-meta");
      meta.appendChild(node("span", "", stringValue(alert.source, "Unknown source")));
      const count = safeNumber(alert.count);
      if (count !== null) meta.appendChild(node("span", "", `${numberFormat.format(count)} event${count === 1 ? "" : "s"}`));
      meta.appendChild(node("span", "", stringValue(alert.status, "unknown").toUpperCase()));
      summary.appendChild(meta);
      details.appendChild(summary);
      const body = node("div", "alert-detail");
      body.appendChild(node("div", "alert-detail-title", "EVIDENCE"));
      body.appendChild(node("pre", "alert-evidence", evidenceText(alert.evidence)));
      body.appendChild(node("div", "alert-detail-meta", `First seen: ${absoluteTime(alert.firstSeen)} · Last seen: ${absoluteTime(alert.lastSeen)} · Alert ID: ${stringValue(alert.id)}`));
      details.appendChild(body);
      fragment.appendChild(details);
    }
    list.replaceChildren(fragment);
    list.scrollTop = scrollTop;
  }

  function sourceOptions() {
    const select = $("source-filter");
    const selected = select.value;
    const sourceIds = new Set();
    for (const source of snapshot.sources) {
      if (source && source.name !== null && source.name !== undefined && source.name !== "") sourceIds.add(String(source.name));
    }
    for (const event of snapshot.events) {
      if (event && event.sourceId !== null && event.sourceId !== undefined && event.sourceId !== "") sourceIds.add(String(event.sourceId));
    }
    const options = [new Option("All sources", "")];
    for (const id of [...sourceIds].sort((a, b) => a.localeCompare(b))) options.push(new Option(id, id));
    select.replaceChildren(...options);
    select.value = sourceIds.has(selected) ? selected : "";
  }

  function searchableText(event) {
    const fields = [event.sourceId, event.vendor, event.kind, event.severity, event.actor, event.target, event.action, event.outcome, event.message];
    if (event.attributes && typeof event.attributes === "object") {
      try { fields.push(JSON.stringify(event.attributes)); } catch { /* skip malformed attributes */ }
    }
    return fields.map((value) => stringValue(value, "")).join(" ").toLowerCase();
  }

  function renderEvents() {
    const body = $("event-table-body");
    const allEvents = snapshot.events.filter((event) => event && typeof event === "object");
    const query = $("event-search").value.trim().toLowerCase();
    const source = $("source-filter").value;
    const severity = $("severity-filter").value;
    const filtered = allEvents.filter((event) =>
      (!source || String(event.sourceId) === source) &&
      (!severity || String(event.severity).toLowerCase() === severity) &&
      (!query || searchableText(event).includes(query))
    );
    filtered.sort((a, b) =>
      (dateValue(b.receivedAt || b.timestamp)?.getTime() || 0) -
      (dateValue(a.receivedAt || a.timestamp)?.getTime() || 0)
    );
    const shown = filtered.slice(0, MAX_RENDERED_EVENTS);
    $("events-count").textContent = String(allEvents.length);
    $("event-results").textContent = allEvents.length
      ? `${numberFormat.format(shown.length)} / ${numberFormat.format(filtered.length)} matches`
      : "No events";
    if (!shown.length) {
      const row = node("tr");
      const cell = node("td", "table-empty", allEvents.length ? "No matches" : "No events");
      cell.colSpan = 6;
      row.appendChild(cell);
      body.replaceChildren(row);
      return;
    }
    const fragment = document.createDocumentFragment();
    for (const event of shown) {
      const row = node("tr");
      const time = node("td", "", shortTime(event.receivedAt || event.timestamp));
      time.title = `Received: ${absoluteTime(event.receivedAt)} · Event time: ${absoluteTime(event.timestamp)}`;
      row.appendChild(time);
      const sourceCell = node("td", "", event.sourceId);
      sourceCell.title = stringValue(event.sourceId);
      row.appendChild(sourceCell);
      const eventCell = node("td");
      const eventName = stringValue(event.message, stringValue(event.action, stringValue(event.kind)));
      const eventText = node("span", "event-message", eventName);
      eventText.title = eventName;
      eventCell.appendChild(eventText);
      row.appendChild(eventCell);
      const actorTarget = [stringValue(event.actor, ""), stringValue(event.target, "")].filter(Boolean).join(" → ") || "—";
      const relation = node("td", "event-subtext", actorTarget);
      relation.title = actorTarget;
      row.appendChild(relation);
      const outcome = stringValue(event.outcome, "unknown").toLowerCase();
      const outcomeClass = ["success", "failure", "denied", "error"].includes(outcome) ? outcome : "unknown";
      row.appendChild(node("td", `outcome-${outcomeClass}`, outcome));
      const eventSeverity = stringValue(event.severity, "info").toLowerCase();
      const severityClass = knownEventSeverities.has(eventSeverity) ? eventSeverity : "info";
      row.appendChild(node("td", `event-severity ${severityClass}`, eventSeverity));
      fragment.appendChild(row);
    }
    body.replaceChildren(fragment);
  }

  function renderSnapshot() {
    if (!snapshot) return;
    lastVisibleAt = Date.now();
    renderMetrics();
    renderGateway();
    renderTraffic();
    renderSources();
    renderAlerts();
    sourceOptions();
    renderEvents();
    renderConnection();
  }

  async function loadBootstrap() {
    try {
      const response = await fetch("/api/bootstrap", { cache: "no-store", credentials: "same-origin" });
      if (response.status === 401) return "unauthorized";
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (!lastStreamAt) acceptSnapshot(data);
      return "ok";
    } catch (error) {
      bootstrapFailed = true;
      console.error("GreyLog bootstrap failed:", error);
      renderConnection();
      return "error";
    }
  }

  async function startDashboard() {
    if (startupInFlight || locked) return;
    startupInFlight = true;
    try {
      const result = await loadBootstrap();
      if (result === "unauthorized") {
        showUnlock("");
        return;
      }
      if (!locked) connectStream();
    } finally {
      startupInFlight = false;
    }
  }

  function scheduleAuthProbe(source) {
    if (locked || authProbeInFlight || authProbeTimer) return;
    const delay = Math.max(0, 3000 - (Date.now() - lastAuthProbeAt));
    authProbeTimer = setTimeout(async () => {
      authProbeTimer = null;
      if (locked || eventSource !== source) return;
      authProbeInFlight = true;
      lastAuthProbeAt = Date.now();
      try {
        const response = await fetch("/api/bootstrap", { cache: "no-store", credentials: "same-origin" });
        if (!locked && eventSource === source && response.status === 401) showUnlock("Session expired");
      } catch {
        // EventSource handles transport retry.
      } finally {
        authProbeInFlight = false;
      }
    }, delay);
  }

  function connectStream() {
    if (locked) return;
    if (eventSource) eventSource.close();
    if (!("EventSource" in window)) {
      streamOpen = false;
      streamError = true;
      streamUnavailable = true;
      renderConnection();
      return;
    }
    streamOpen = false;
    streamError = false;
    streamUnavailable = false;
    streamOpenedAt = 0;
    lastStreamAt = 0;
    const source = new EventSource("/api/stream", { withCredentials: true });
    eventSource = source;
    source.addEventListener("open", () => {
      if (eventSource !== source) return;
      streamOpen = true;
      streamError = false;
      streamOpenedAt = Date.now();
      renderConnection();
    });
    source.addEventListener("snapshot", (message) => {
      if (eventSource !== source) return;
      try { streamOpen = true; acceptSnapshot(JSON.parse(message.data), true); }
      catch (error) { console.error("GreyLog stream snapshot was invalid:", error); }
    });
    source.addEventListener("error", () => {
      if (eventSource !== source) return;
      streamOpen = false;
      streamError = true;
      renderConnection();
      scheduleAuthProbe(source);
    });
  }

  async function exportRecords(kind) {
    const button = $(`${kind}-export`);
    const status = $(`${kind}-export-status`);
    if (button.disabled || locked) return;
    button.disabled = true;
    status.textContent = "Preparing";
    let handle = null;
    try {
      if (typeof window.showSaveFilePicker === "function") {
        try {
          handle = await window.showSaveFilePicker({
            suggestedName: `greylog-${kind}.jsonl`,
            types: [{ description: "JSON Lines", accept: { "application/x-ndjson": [".jsonl"] } }],
          });
        } catch (error) {
          if (error && error.name === "AbortError") {
            status.textContent = "Cancelled";
            return;
          }
          // Browser download remains available when the picker cannot run.
        }
      }
      status.textContent = "Exporting";
      const endpoint = `/api/export/${kind}`;
      if (!handle) {
        const session = await fetch("/api/bootstrap", { cache: "no-store", credentials: "same-origin" });
        if (session.status === 401) {
          showUnlock("Session expired");
          return;
        }
        if (!session.ok) throw new Error("Session unavailable");
        const anchor = document.createElement("a");
        anchor.href = endpoint;
        anchor.download = `greylog-${kind}.jsonl`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        status.textContent = "Download started";
        return;
      }
      const response = await fetch(endpoint, { cache: "no-store", credentials: "same-origin" });
      if (response.status === 401) {
        showUnlock("Session expired");
        return;
      }
      if (!response.ok || !response.headers.get("content-type")?.toLowerCase().includes("application/x-ndjson")) {
        throw new Error("Export unavailable");
      }
      const writable = await handle.createWritable();
      if (response.body) await response.body.pipeTo(writable);
      else {
        await writable.write(await response.blob());
        await writable.close();
      }
      status.textContent = "Saved";
    } catch {
      status.textContent = "Export failed";
    } finally {
      button.disabled = false;
    }
  }

  $("pause-button").addEventListener("click", () => {
    paused = !paused;
    const button = $("pause-button");
    button.setAttribute("aria-pressed", String(paused));
    button.classList.toggle("is-paused", paused);
    $("pause-label").textContent = paused ? "Resume" : "Pause";
    if (!paused) renderSnapshot();
    renderConnection();
  });
  $("retry-button").addEventListener("click", startDashboard);
  $("events-export").addEventListener("click", () => exportRecords("events"));
  $("alerts-export").addEventListener("click", () => exportRecords("alerts"));
  $("unlock-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (unlockInFlight) return;
    const input = $("unlock-token");
    const submit = $("unlock-submit");
    const error = $("unlock-error");
    const suppliedToken = input.value;
    const trimmedToken = suppliedToken.trim();
    if (!trimmedToken) {
      error.textContent = "Dashboard token required";
      error.classList.add("is-error");
      input.focus();
      return;
    }
    unlockInFlight = true;
    submit.disabled = true;
    error.textContent = "Checking";
    error.classList.remove("is-error");
    try {
      const requestSession = (token) => fetch("/api/session", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const pending = requestSession(suppliedToken);
      input.value = "";
      let response = await pending;
      if (response.status === 401 && suppliedToken !== trimmedToken) {
        response = await requestSession(trimmedToken);
      }
      if (!response.ok) {
        error.textContent = response.status === 401 ? "Invalid dashboard token. Check this server's generated or configured dashboard token." : "Unlock failed";
        error.classList.add("is-error");
        return;
      }
      const result = await loadBootstrap();
      if (result !== "ok") {
        error.textContent = result === "unauthorized" ? "Session failed" : "Connection failed";
        error.classList.add("is-error");
        return;
      }
      hideUnlock();
      connectStream();
    } catch {
      error.textContent = "Connection failed";
      error.classList.add("is-error");
    } finally {
      input.value = "";
      submit.disabled = false;
      unlockInFlight = false;
    }
  });
  $("event-search").addEventListener("input", renderEvents);
  $("source-filter").addEventListener("change", renderEvents);
  $("gateway-select").addEventListener("change", () => {
    const value = $("gateway-select").value;
    if (!value) return;
    saveGateway(value === "auto" ? { gateway: "auto" } : JSON.parse(value));
  });
  $("gateway-custom-form").addEventListener("submit", (event) => {
    event.preventDefault();
    saveGateway({ gateway: $("gateway-custom").value.trim() });
  });
  $("severity-filter").addEventListener("change", renderEvents);
  window.addEventListener("pagehide", () => { if (eventSource) eventSource.close(); });
  window.addEventListener("pageshow", (event) => { if (event.persisted && !locked) startDashboard(); });

  function tick() {
    $("clock").textContent = clockFormat.format(new Date());
    renderConnection();
  }
  tick();
  setInterval(tick, 1000);
  startDashboard();
})();
