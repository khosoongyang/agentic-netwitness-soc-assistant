// Dependency-free SVG/HTML chart primitives for the Operations Overview
// analytics. Every chart takes already-aggregated data from
// GET /api/dashboard/analytics and renders it as-is: nothing here invents,
// rounds away or smooths a value.
//
// Conventions shared by every chart:
//   - Hover and keyboard focus show the same tooltip (one shared element,
//     filled with textContent -- labels such as IPs come from incident data).
//   - Marks that can drive a Recent Cases filter are focusable buttons
//     (role="button"); the rest are plain focusable marks with a tooltip.
//   - Each chart also renders a visually hidden data table, so no value is
//     reachable only through colour or hover.
//   - SVG charts are drawn at the container's measured CSS width (not a
//     scaled viewBox), so text stays at UI size at any width or zoom level.

import { escapeHTML, formatCount } from "../ui.js";

const SVG_NS = "http://www.w3.org/2000/svg";

// ── Formatting ───────────────────────────────────────────────────────────

export function formatPercent(count, total) {
  if (!total) return "0%";
  const value = (count / total) * 100;
  if (value === 0) return "0%";
  if (value < 0.1) return "<0.1%";
  return `${value.toFixed(value < 10 ? 1 : 0)}%`;
}

function compact(value) {
  if (Math.abs(value) >= 1e6) return `${+(value / 1e6).toFixed(1)}M`;
  if (Math.abs(value) >= 1e3) return `${+(value / 1e3).toFixed(1)}K`;
  return String(value);
}

const UTC_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// "2026-07-27T07:37:48" (naive UTC) -> "27 Jul 2026, 07:37 UTC". Formatted
// by hand so the browser's local timezone can never shift it.
export function formatUTC(stamp, { time = true } = {}) {
  const match = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}))?/.exec(String(stamp || ""));
  if (!match) return "—";
  const [, year, month, day, hour = "00", minute = "00"] = match;
  const date = `${Number(day)} ${UTC_MONTHS[Number(month) - 1]} ${year}`;
  return time ? `${date}, ${hour}:${minute} UTC` : date;
}

function niceStep(max, targetTicks) {
  const raw = Math.max(max, 1) / targetTicks;
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((factor) => factor * magnitude).find((value) => value >= raw);
  return Math.max(1, step);
}

// Integer ticks from 0 to a clean ceiling above max.
function niceTicks(max, targetTicks = 4) {
  const step = Math.ceil(niceStep(max, targetTicks));
  const top = Math.max(step, Math.ceil(max / step) * step);
  const ticks = [];
  for (let value = 0; value <= top; value += step) ticks.push(value);
  return { ticks, top };
}

function svgEl(name, attributes = {}, text = "") {
  const element = document.createElementNS(SVG_NS, name);
  Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
  if (text) element.textContent = text;
  return element;
}

// Column with a 4px rounded data-end and a square baseline.
function columnPath(x, y, width, height, radius = 4) {
  if (height <= 0) return "";
  const r = Math.min(radius, width / 2, height);
  return `M${x},${y + height}V${y + r}Q${x},${y} ${x + r},${y}H${x + width - r}Q${x + width},${y} ${x + width},${y + r}V${y + height}Z`;
}

// Wrapped in a clipped div: a <table> ignores the 1px width of .sr-only and
// would otherwise widen the page.
function srTable(caption, headers, rows) {
  return `<div class="sr-only"><table><caption>${escapeHTML(caption)}</caption><thead><tr>${headers.map((header) => `<th scope="col">${escapeHTML(header)}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${escapeHTML(cell)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

// ── Tooltip ──────────────────────────────────────────────────────────────

let tooltipElement = null;

function tooltip() {
  if (tooltipElement?.isConnected) return tooltipElement;
  tooltipElement = document.createElement("div");
  tooltipElement.className = "chart-tooltip";
  tooltipElement.setAttribute("role", "status");
  tooltipElement.hidden = true;
  document.body.appendChild(tooltipElement);
  return tooltipElement;
}

/**
 * content: { title, rows: [{ value, label, color }], note, hint }
 * anchor: a pointer event (follows the pointer) or an element (keyboard focus).
 */
export function showTooltip(anchor, content) {
  const element = tooltip();
  element.replaceChildren();
  if (content.title) {
    const title = document.createElement("div");
    title.className = "chart-tooltip-title";
    title.textContent = content.title;
    element.appendChild(title);
  }
  (content.rows || []).forEach((row) => {
    const line = document.createElement("div");
    line.className = "chart-tooltip-row";
    if (row.color) {
      const key = document.createElement("span");
      key.className = "chart-tooltip-key";
      key.style.background = row.color;
      line.appendChild(key);
    }
    const value = document.createElement("strong");
    value.textContent = row.value;
    const label = document.createElement("span");
    label.textContent = row.label || "";
    line.append(value, label);
    element.appendChild(line);
  });
  [["note", "chart-tooltip-note"], ["hint", "chart-tooltip-hint"]].forEach(([key, className]) => {
    if (!content[key]) return;
    const line = document.createElement("div");
    line.className = className;
    line.textContent = content[key];
    element.appendChild(line);
  });
  element.hidden = false;

  let x;
  let y;
  if (anchor && "clientX" in anchor) {
    x = anchor.clientX + 14;
    y = anchor.clientY + 14;
  } else {
    const rect = anchor.getBoundingClientRect();
    x = rect.left + rect.width / 2;
    y = rect.bottom + 8;
  }
  const { width, height } = element.getBoundingClientRect();
  const maxX = window.innerWidth - width - 8;
  const maxY = window.innerHeight - height - 8;
  if (x > maxX) x = anchor && "clientX" in anchor ? anchor.clientX - width - 14 : maxX;
  if (y > maxY) y = anchor && "clientY" in anchor ? anchor.clientY - height - 14 : maxY;
  element.style.left = `${Math.max(8, x)}px`;
  element.style.top = `${Math.max(8, y)}px`;
}

export function hideTooltip() {
  if (tooltipElement) tooltipElement.hidden = true;
}

/**
 * Wire hover + focus tooltips and optional activation on every element in
 * `root` matching `selector`. `describe(element)` returns tooltip content;
 * `activate(element)` (optional) runs on click / Enter / Space.
 */
function bindMarks(root, selector, describe, activate) {
  const marks = root.querySelectorAll(selector);
  marks.forEach((mark) => {
    mark.addEventListener("pointermove", (event) => showTooltip(event, describe(mark)));
    mark.addEventListener("pointerleave", hideTooltip);
    mark.addEventListener("focus", () => showTooltip(mark, describe(mark)));
    mark.addEventListener("blur", hideTooltip);
    if (!activate || mark.getAttribute("role") !== "button") return;
    mark.addEventListener("click", () => { hideTooltip(); activate(mark); });
    mark.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      hideTooltip();
      activate(mark);
    });
  });
}

/** Re-render `render(width)` whenever the container's width changes. */
export function renderResponsive(container, render) {
  let lastWidth = -1;
  const draw = () => {
    const width = Math.floor(container.clientWidth);
    if (width <= 0 || width === lastWidth) return;
    lastWidth = width;
    render(width);
  };
  draw();
  if (typeof ResizeObserver === "undefined") return;
  const observer = new ResizeObserver(() => {
    if (!container.isConnected) {
      observer.disconnect();
      return;
    }
    draw();
  });
  observer.observe(container);
}

// ── Donut (part-to-whole) ────────────────────────────────────────────────

/**
 * items: [{ key, label, count, color, filterable }]; zero-count items stay in
 * the legend (an empty level is information) but draw no arc.
 */
export function donutChart(container, { items, total, centerLabel, caption, hint, onSelect }) {
  const size = 168;
  const radius = 72;
  const thickness = 20;
  const inner = radius - thickness;
  const center = size / 2;
  let angle = -Math.PI / 2;
  const gap = items.filter((item) => item.count > 0).length > 1 ? 0.012 : 0;
  const arcs = items.map((item, index) => {
    if (!item.count) return "";
    const sweep = (item.count / total) * Math.PI * 2;
    const start = angle + gap / 2;
    const end = angle + sweep - gap / 2;
    angle += sweep;
    if (sweep >= Math.PI * 2 - 1e-6) {
      return `<circle class="chart-mark" data-index="${index}" cx="${center}" cy="${center}" r="${radius - thickness / 2}" fill="none" stroke="${item.color}" stroke-width="${thickness}"></circle>`;
    }
    if (end <= start) return "";
    const large = end - start > Math.PI ? 1 : 0;
    const point = (r, a) => `${(center + r * Math.cos(a)).toFixed(2)},${(center + r * Math.sin(a)).toFixed(2)}`;
    const d = `M${point(radius, start)}A${radius},${radius} 0 ${large} 1 ${point(radius, end)}L${point(inner, end)}A${inner},${inner} 0 ${large} 0 ${point(inner, start)}Z`;
    return `<path class="chart-mark" data-index="${index}" d="${d}" fill="${item.color}"></path>`;
  }).join("");

  const legend = items.map((item, index) => {
    const clickable = item.filterable && item.count > 0 && onSelect;
    const attributes = clickable
      ? `role="button" tabindex="0" aria-label="${escapeHTML(`${item.label}: ${formatCount(item.count)} incidents. Filter Recent cases`)}"`
      : `tabindex="0"`;
    return `<li class="donut-legend-row chart-mark${clickable ? " is-clickable" : ""}" data-index="${index}" ${attributes}>
      <span class="legend-swatch" style="background:${item.color}"></span>
      <span class="donut-legend-label">${escapeHTML(item.label)}</span>
      <span class="donut-legend-value">${formatCount(item.count)} <span class="chart-muted">(${formatPercent(item.count, total)})</span></span>
    </li>`;
  }).join("");

  container.innerHTML = `<div class="donut-chart">
      <div class="donut-figure">
        <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" aria-hidden="true">
          <circle cx="${center}" cy="${center}" r="${radius - thickness / 2}" fill="none" stroke="#16233a" stroke-width="${thickness}"></circle>
          ${arcs}
        </svg>
        <div class="donut-center"><strong>${formatCount(total)}</strong><span>${escapeHTML(centerLabel)}</span></div>
      </div>
      <ul class="donut-legend">${legend}</ul>
    </div>
    ${srTable(caption, ["Level", "Incidents", "Share"], items.map((item) => [item.label, formatCount(item.count), formatPercent(item.count, total)]))}`;

  const describe = (mark) => {
    const item = items[Number(mark.dataset.index)];
    const clickable = item.filterable && item.count > 0 && onSelect;
    return {
      title: item.label,
      rows: [{ value: formatCount(item.count), label: `incidents · ${formatPercent(item.count, total)}`, color: item.color }],
      note: item.note,
      hint: clickable ? hint : "",
    };
  };
  // Hovering an arc or its legend row highlights both.
  container.querySelectorAll(".chart-mark").forEach((mark) => {
    const toggle = (on) => container.querySelectorAll(`[data-index="${mark.dataset.index}"]`)
      .forEach((peer) => peer.classList.toggle("is-hover", on));
    mark.addEventListener("pointerenter", () => toggle(true));
    mark.addEventListener("pointerleave", () => toggle(false));
    mark.addEventListener("focus", () => toggle(true));
    mark.addEventListener("blur", () => toggle(false));
  });
  bindMarks(container, ".chart-mark", describe, (mark) => onSelect(items[Number(mark.dataset.index)]));
  container.querySelectorAll("path.chart-mark, circle.chart-mark").forEach((arc) => {
    const item = items[Number(arc.dataset.index)];
    if (item.filterable && onSelect) {
      arc.classList.add("is-clickable");
      arc.addEventListener("click", () => { hideTooltip(); onSelect(item); });
    }
  });
}

// ── Stacked columns (stage x state) ──────────────────────────────────────

/**
 * items: [{ key, label, shortLabel, count, segments: [{ key, label, count, color }] }]
 */
export function stackedColumnChart(container, { items, caption, hint, onSelect }) {
  renderResponsive(container, (width) => {
    const angled = (width - 38) / items.length < 48;
    const height = angled ? 232 : 212;
    const margin = { top: 22, right: 4, bottom: angled ? 54 : 34, left: 34 };
    const plotWidth = Math.max(80, width - margin.left - margin.right);
    const plotHeight = height - margin.top - margin.bottom;
    const max = Math.max(0, ...items.map((item) => item.count));
    const { ticks, top } = niceTicks(max, 4);
    const band = plotWidth / items.length;
    const columnWidth = Math.min(40, band * 0.6);
    const y = (value) => margin.top + plotHeight - (value / top) * plotHeight;

    const svg = svgEl("svg", { width, height, class: "chart-svg", role: "group", "aria-label": caption });
    ticks.forEach((tick) => {
      svg.appendChild(svgEl("line", { x1: margin.left, x2: width - margin.right, y1: y(tick), y2: y(tick), class: tick ? "chart-grid" : "chart-axis" }));
      svg.appendChild(svgEl("text", { x: margin.left - 8, y: y(tick) + 4, "text-anchor": "end", class: "chart-tick" }, compact(tick)));
    });
    items.forEach((item, index) => {
      const x = margin.left + band * index + (band - columnWidth) / 2;
      const group = svgEl("g", { class: "chart-column", "data-index": index });
      let base = 0;
      const drawn = item.segments.filter((segment) => segment.count > 0);
      drawn.forEach((segment, segmentIndex) => {
        const yTop = y(base + segment.count);
        // 2px surface gap between stacked segments.
        const segmentHeight = y(base) - yTop - (segmentIndex > 0 ? 2 : 0);
        const isTop = segmentIndex === drawn.length - 1;
        const d = isTop
          ? columnPath(x, yTop, columnWidth, segmentHeight)
          : `M${x},${yTop}h${columnWidth}v${segmentHeight}h${-columnWidth}Z`;
        if (segmentHeight > 0) group.appendChild(svgEl("path", { d, fill: segment.color }));
        base += segment.count;
      });
      svg.appendChild(group);
      svg.appendChild(svgEl("text", { x: x + columnWidth / 2, y: y(item.count) - 6, "text-anchor": "middle", class: "chart-value" }, formatCount(item.count)));
      const label = band >= 74 ? item.shortLabel : item.tinyLabel || item.shortLabel;
      const labelX = margin.left + band * index + band / 2;
      const labelY = height - margin.bottom + 18;
      // Too narrow for upright labels: angle them instead of overlapping.
      svg.appendChild(svgEl("text", band >= 48
        ? { x: labelX, y: labelY, "text-anchor": "middle", class: "chart-tick chart-x-label" }
        : { x: labelX, y: labelY - 6, "text-anchor": "end", transform: `rotate(-40 ${labelX} ${labelY - 6})`, class: "chart-tick chart-x-label" }, label));
      // Full-band hit target, bigger than the mark.
      const hit = svgEl("rect", {
        x: margin.left + band * index, y: margin.top, width: band, height: plotHeight + 24,
        class: `chart-hit${item.count && onSelect ? " is-clickable" : ""}`, "data-index": index,
        tabindex: 0, focusable: "true",
      });
      if (item.count && onSelect) {
        hit.setAttribute("role", "button");
        hit.setAttribute("aria-label", `${item.label}: ${item.count} incidents. Filter Recent cases`);
      }
      svg.appendChild(hit);
    });

    container.replaceChildren(svg);
    container.insertAdjacentHTML("beforeend", srTable(caption, ["Stage", "Incidents", ...items[0].segments.map((segment) => segment.label)],
      items.map((item) => [item.label, formatCount(item.count), ...item.segments.map((segment) => formatCount(segment.count))])));

    const describe = (mark) => {
      const item = items[Number(mark.dataset.index)];
      return {
        title: item.label,
        rows: [
          { value: formatCount(item.count), label: "incidents at this stage" },
          ...item.segments.filter((segment) => segment.count > 0)
            .map((segment) => ({ value: formatCount(segment.count), label: segment.label, color: segment.color })),
        ],
        hint: item.count && onSelect ? hint : "",
      };
    };
    container.querySelectorAll(".chart-hit").forEach((hit) => {
      const column = container.querySelector(`.chart-column[data-index="${hit.dataset.index}"]`);
      const toggle = (on) => column?.classList.toggle("is-hover", on);
      hit.addEventListener("pointerenter", () => toggle(true));
      hit.addEventListener("pointerleave", () => toggle(false));
      hit.addEventListener("focus", () => toggle(true));
      hit.addEventListener("blur", () => toggle(false));
    });
    bindMarks(container, ".chart-hit", describe, (mark) => onSelect(items[Number(mark.dataset.index)]));
  });
}

// ── Area trend (change over time) ────────────────────────────────────────

/**
 * buckets: [{ key, label, longLabel, count, partial }] in time order.
 */
export function areaTrendChart(container, { buckets, caption, valueLabel, hint, onSelect, color }) {
  renderResponsive(container, (width) => {
    const height = 212;
    const margin = { top: 14, right: 12, bottom: 30, left: 40 };
    const plotWidth = Math.max(60, width - margin.left - margin.right);
    const plotHeight = height - margin.top - margin.bottom;
    const max = Math.max(0, ...buckets.map((bucket) => bucket.count));
    const { ticks, top } = niceTicks(max, 4);
    const step = buckets.length > 1 ? plotWidth / (buckets.length - 1) : 0;
    const x = (index) => margin.left + (buckets.length > 1 ? step * index : plotWidth / 2);
    const y = (value) => margin.top + plotHeight - (value / top) * plotHeight;
    const gradientId = `trend-fill-${Math.random().toString(36).slice(2, 8)}`;

    const svg = svgEl("svg", {
      width, height, class: "chart-svg chart-trend", tabindex: 0, role: "group",
      "aria-label": `${caption}. Use the left and right arrow keys to read each period.`,
    });
    const defs = svgEl("defs");
    const gradient = svgEl("linearGradient", { id: gradientId, x1: 0, x2: 0, y1: 0, y2: 1 });
    gradient.append(svgEl("stop", { offset: "0%", "stop-color": color, "stop-opacity": 0.32 }),
      svgEl("stop", { offset: "100%", "stop-color": color, "stop-opacity": 0.02 }));
    defs.appendChild(gradient);
    svg.appendChild(defs);
    ticks.forEach((tick) => {
      svg.appendChild(svgEl("line", { x1: margin.left, x2: width - margin.right, y1: y(tick), y2: y(tick), class: tick ? "chart-grid" : "chart-axis" }));
      svg.appendChild(svgEl("text", { x: margin.left - 8, y: y(tick) + 4, "text-anchor": "end", class: "chart-tick" }, compact(tick)));
    });
    // X labels: as many as fit (~64px each), always including the last.
    const every = Math.max(1, Math.ceil(buckets.length / Math.max(1, Math.floor(plotWidth / 64))));
    buckets.forEach((bucket, index) => {
      if (index % every !== 0 && index !== buckets.length - 1) return;
      if (index !== buckets.length - 1 && buckets.length - 1 - index < every) return;
      svg.appendChild(svgEl("text", { x: x(index), y: height - 10, "text-anchor": index === 0 && buckets.length > 1 ? "start" : index === buckets.length - 1 && buckets.length > 1 ? "end" : "middle", class: "chart-tick" }, bucket.label));
    });
    const points = buckets.map((bucket, index) => `${x(index).toFixed(1)},${y(bucket.count).toFixed(1)}`);
    if (buckets.length > 1) {
      svg.appendChild(svgEl("path", { d: `M${points[0]}L${points.slice(1).join("L")}L${x(buckets.length - 1)},${y(0)}L${x(0)},${y(0)}Z`, fill: `url(#${gradientId})` }));
      svg.appendChild(svgEl("path", { d: `M${points.join("L")}`, fill: "none", stroke: color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }));
    }
    // Markers only when sparse enough to read; the peak is always marked.
    const peak = buckets.reduce((best, bucket, index) => (bucket.count > (buckets[best]?.count ?? -1) ? index : best), 0);
    buckets.forEach((bucket, index) => {
      if (buckets.length > 40 && index !== peak) return;
      svg.appendChild(svgEl("circle", { cx: x(index), cy: y(bucket.count), r: 3.5, fill: color, class: "chart-dot" }));
    });
    if (max > 0) {
      const anchor = x(peak) > width - 60 ? "end" : x(peak) < margin.left + 40 ? "start" : "middle";
      svg.appendChild(svgEl("text", { x: x(peak), y: Math.max(11, y(max) - 9), "text-anchor": anchor, class: "chart-value" }, formatCount(max)));
    }
    const crosshair = svgEl("line", { y1: margin.top, y2: margin.top + plotHeight, class: "chart-crosshair", visibility: "hidden" });
    const focusDot = svgEl("circle", { r: 5, fill: color, class: "chart-dot chart-dot-focus", visibility: "hidden" });
    svg.append(crosshair, focusDot);
    const overlay = svgEl("rect", {
      x: margin.left - step / 2, y: margin.top, width: plotWidth + step, height: plotHeight,
      class: `chart-hit${onSelect ? " is-clickable" : ""}`,
    });
    svg.appendChild(overlay);

    container.replaceChildren(svg);
    container.insertAdjacentHTML("beforeend", srTable(caption, ["Period (UTC)", valueLabel], buckets.map((bucket) => [bucket.longLabel, formatCount(bucket.count)])));

    let current = -1;
    const describe = (index) => {
      const bucket = buckets[index];
      return {
        title: bucket.longLabel,
        rows: [{ value: formatCount(bucket.count), label: valueLabel, color }],
        note: bucket.partial ? "Partial period: clipped to the selected time range." : "",
        hint: bucket.count && onSelect ? hint : "",
      };
    };
    const focusIndex = (index, anchor) => {
      current = Math.max(0, Math.min(buckets.length - 1, index));
      const cx = x(current);
      crosshair.setAttribute("x1", cx);
      crosshair.setAttribute("x2", cx);
      crosshair.setAttribute("visibility", "visible");
      focusDot.setAttribute("cx", cx);
      focusDot.setAttribute("cy", y(buckets[current].count));
      focusDot.setAttribute("visibility", "visible");
      showTooltip(anchor || focusDot, describe(current));
    };
    const clear = () => {
      crosshair.setAttribute("visibility", "hidden");
      focusDot.setAttribute("visibility", "hidden");
      hideTooltip();
    };
    const indexAt = (event) => {
      const rect = svg.getBoundingClientRect();
      return step ? Math.round((event.clientX - rect.left - margin.left) / step) : 0;
    };
    overlay.addEventListener("pointermove", (event) => focusIndex(indexAt(event), event));
    overlay.addEventListener("pointerleave", clear);
    overlay.addEventListener("click", (event) => {
      const bucket = buckets[Math.max(0, Math.min(buckets.length - 1, indexAt(event)))];
      if (onSelect && bucket?.count) { clear(); onSelect(bucket); }
    });
    svg.addEventListener("focus", () => focusIndex(current < 0 ? buckets.length - 1 : current));
    svg.addEventListener("blur", clear);
    svg.addEventListener("keydown", (event) => {
      const moves = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity };
      if (event.key in moves) {
        event.preventDefault();
        const delta = moves[event.key];
        focusIndex(Number.isFinite(delta) ? current + delta : delta < 0 ? 0 : buckets.length - 1);
      } else if ((event.key === "Enter" || event.key === " ") && onSelect && buckets[current]?.count) {
        event.preventDefault();
        clear();
        onSelect(buckets[current]);
      }
    });
  });
}

// ── Ranked horizontal bars (top-N) ───────────────────────────────────────

/**
 * items: [{ label, count }] already sorted; `other` is the remainder beyond
 * the top N (omitted when 0). Shares are of `total`.
 */
export function rankedBars(container, { items, other = 0, otherLabel = "Other", total, color, caption, labelHeader, mono = false }) {
  const rows = [...items.map((item) => ({ ...item, color })),
    ...(other ? [{ label: otherLabel, count: other, color: "var(--chart-other)", isOther: true }] : [])];
  const max = Math.max(1, ...rows.map((row) => row.count));
  container.innerHTML = `<ol class="ranked-bars">${rows.map((row, index) => `
      <li class="ranked-bar-row chart-mark" data-index="${index}" tabindex="0">
        <span class="ranked-bar-label${mono && !row.isOther ? " mono" : ""}" title="${escapeHTML(row.label)}">${escapeHTML(row.label)}</span>
        <span class="ranked-bar-track"><span class="ranked-bar-fill" style="width:${Math.max(row.count ? 1.5 : 0, (row.count / max) * 100).toFixed(2)}%;background:${row.color}"></span></span>
        <span class="ranked-bar-value">${formatCount(row.count)} <span class="chart-muted">(${formatPercent(row.count, total)})</span></span>
      </li>`).join("")}</ol>
    ${srTable(caption, [labelHeader, "Incidents", "Share"], rows.map((row) => [row.label, formatCount(row.count), formatPercent(row.count, total)]))}`;
  bindMarks(container, ".ranked-bar-row", (mark) => {
    const row = rows[Number(mark.dataset.index)];
    return {
      title: row.label,
      rows: [{ value: formatCount(row.count), label: `incidents · ${formatPercent(row.count, total)}`, color: row.color }],
      note: row.note,
    };
  });
}

// ── Heatmap (day of week x hour of day) ─────────────────────────────────

export function heatmapChart(container, { days, cells, max, caption }) {
  const hours = Array.from({ length: 24 }, (_, hour) => hour);
  // Linear intensity on one hue; zero stays the empty-cell colour so "no
  // incidents" never looks like "a few".
  const level = (count) => (count && max ? 0.14 + 0.86 * (count / max) : 0);
  const hourLabel = (hour) => `${String(hour).padStart(2, "0")}:00`;
  container.innerHTML = `<div class="heatmap" role="group" aria-label="${escapeHTML(caption)}">
      ${days.map((day, row) => `<span class="heatmap-day" aria-hidden="true">${escapeHTML(day)}</span>
        ${hours.map((hour) => {
          const count = cells[row][hour];
          return `<span class="heatmap-cell chart-mark${count ? "" : " is-empty"}" data-row="${row}" data-hour="${hour}" tabindex="${row === 0 && hour === 0 ? 0 : -1}" style="--heat:${level(count).toFixed(3)}"></span>`;
        }).join("")}`).join("")}
      <span aria-hidden="true"></span>
      ${hours.map((hour) => `<span class="heatmap-hour${hour % 6 ? " heatmap-hour-minor" : ""}" aria-hidden="true">${hour % 2 === 0 ? hour : ""}</span>`).join("")}
    </div>
    <div class="heatmap-footer" aria-hidden="true"><span>Hour of day (UTC)</span><span class="heatmap-scale"><span>0</span><span class="heatmap-gradient"></span><span>${formatCount(max)}</span></span></div>
    ${srTable(caption, ["Day", ...hours.map(hourLabel)], days.map((day, row) => [day, ...cells[row].map(formatCount)]))}`;

  const grid = container.querySelector(".heatmap");
  const describe = (cell) => {
    const row = Number(cell.dataset.row);
    const hour = Number(cell.dataset.hour);
    return {
      title: `${days[row]} ${hourLabel(hour)}–${hourLabel((hour + 1) % 24).replace(/^00/, "24")} UTC`,
      rows: [{ value: formatCount(cells[row][hour]), label: "incidents created" }],
    };
  };
  bindMarks(container, ".heatmap-cell", describe);
  // One tab stop; arrow keys move between cells.
  grid.addEventListener("keydown", (event) => {
    const cell = event.target.closest(".heatmap-cell");
    const moves = { ArrowLeft: [0, -1], ArrowRight: [0, 1], ArrowUp: [-1, 0], ArrowDown: [1, 0] };
    if (!cell || !(event.key in moves)) return;
    event.preventDefault();
    const [dRow, dHour] = moves[event.key];
    const row = Math.max(0, Math.min(days.length - 1, Number(cell.dataset.row) + dRow));
    const hour = Math.max(0, Math.min(23, Number(cell.dataset.hour) + dHour));
    const next = grid.querySelector(`.heatmap-cell[data-row="${row}"][data-hour="${hour}"]`);
    cell.tabIndex = -1;
    next.tabIndex = 0;
    next.focus();
  });
}
