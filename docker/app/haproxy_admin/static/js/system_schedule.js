(function () {
  "use strict";
  const app = document.getElementById("schedule-app");
  if (!app) return;
  const clock = window.EasyHaProxyTime, t = window.t || ((value) => value);
  const el = (id) => document.getElementById("plan-" + id);
  const pages = Object.fromEntries(["updates", "security", "backups", "geoip"].map((name) => [name, app.dataset[name + "Page"]]));
  function node(tag, text, className) {
    const result = document.createElement(tag);
    if (text !== undefined) result.textContent = text;
    if (className) result.className = className;
    return result;
  }
  function svg(tag, attrs, text) {
    const result = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attrs)) result.setAttribute(key, value);
    if (text !== undefined) result.textContent = text;
    return result;
  }
  const when = (task) => clock.dateTime(task.start) + (task.end ? " – " + clock.dateTime(task.end) : "");
  function draw(model) {
    el("period").textContent = `${clock.dateTime(model.now)} – ${clock.dateTime(model.until)}`;
    const timeline = el("timeline"); timeline.replaceChildren();
    const label = node("div", t("Task"), "plan-axis-label"); timeline.append(label);
    const width = 1000, x = (value) => Math.max(0, Math.min(width, (value - model.now) / (model.until - model.now) * width));
    const axis = svg("svg", {viewBox: `0 0 ${width} 32`, class: "plan-axis", "aria-hidden": "true"});
    const ticks = [0, 6, 12, 18, 24];
    for (const hour of ticks) axis.append(svg("text", {x: hour / 24 * width, y: 20, "text-anchor": hour === 0 ? "start" : hour === 24 ? "end" : "middle"},
      clock.formatter({hour: "2-digit", minute: "2-digit"}).format(model.now + hour * 3600000)));
    timeline.append(axis);
    for (const task of model.visible) {
      const link = node("a", task.label, "plan-task-label"); link.href = pages[task.page];
      if (task.detail) link.append(node("small", task.detail));
      const title = `${task.label}: ${when(task)} · ${task.condition}`;
      link.title = title; timeline.append(link);
      const chart = svg("svg", {viewBox: `0 0 ${width} 40`, class: "plan-track", role: "img", "aria-label": title});
      chart.append(svg("title", {}, title));
      for (const hour of ticks) chart.append(svg("line", {x1: hour / 24 * width, x2: hour / 24 * width, y1: 0, y2: 40, class: "plan-grid"}));
      if (task.end) chart.append(svg("rect", {x: x(task.start), y: 11, width: Math.max(3, x(task.end) - x(task.start)), height: 18, rx: 4, class: "plan-window"}));
      else chart.append(svg("circle", {cx: Math.max(6, Math.min(width - 6, x(task.start))), cy: 20, r: 6, class: "plan-point"}));
      timeline.append(chart);
    }
    el("empty").hidden = model.visible.length > 0;
    el("rows").replaceChildren();
    for (const task of model.tasks) {
      const tr = node("tr"), name = node("td", task.label);
      if (task.detail) name.append(node("small", task.detail, "plan-detail"));
      const settings = node("td"), link = node("a", t("Open settings")); link.href = pages[task.page]; settings.append(link);
      tr.append(name, node("td", when(task)), node("td", task.condition), settings); el("rows").append(tr);
    }
    el("disabled").replaceChildren();
    for (const item of model.disabled) {
      const li = node("li"), link = node("a", item.label); link.href = pages[item.page];
      li.append(link, document.createTextNode(` · ${item.condition}${item.detail ? " · " + item.detail : ""}`)); el("disabled").append(li);
    }
    el("disabled-details").hidden = !model.disabled.length;
  }
  let busy = false;
  async function refresh() {
    if (busy || document.hidden) return;
    busy = true; el("refresh").disabled = true;
    const names = ["updates", "security", "backups", "geoip"], data = {}, errors = [];
    await Promise.all(names.map(async (name) => {
      const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 12000);
      try {
        const response = await fetch(app.dataset[name + "Url"], {credentials: "same-origin", headers: {Accept: "application/json"}, signal: controller.signal});
        const body = await response.json();
        if (!response.ok || body.ok === false) throw new Error("unavailable");
        data[name] = body;
      } catch (_) {
        errors.push(t({updates: "Project updates", security: "OS security", backups: "Backups", geoip: "GeoIP database"}[name]));
      } finally { clearTimeout(timeout); }
    }));
    el("errors").textContent = errors.length ? t("Could not read schedules: {names}", {names: errors.join(", ")}) : "";
    draw(window.EasyHaProxySchedule.build(data, clock, clock.now(), t));
    busy = false; el("refresh").disabled = false;
  }
  el("refresh").addEventListener("click", refresh);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  setInterval(refresh, 30000); refresh();
})();
