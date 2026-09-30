// Operations Overview query assistance for the topbar search: free-text vs
// structured-query detection, autocomplete, syntax help and inline query
// errors.
//
// The backend (backend/services/case_query.py) is the only authority on
// what a query means. This module mirrors just enough of its tokenizer to
// (a) tell free text from a structured query, so structured queries run on
// Enter instead of while half-typed, and (b) know what sits at the cursor.
// Field names, values and examples come from GET /api/cases/query-schema;
// no display -> backend mapping is duplicated here.
//
// The pure helpers touch no DOM so they can be unit-tested in Node.

import { fetchJSON } from "../api.js";
import { escapeHTML } from "../ui.js";

const KEYWORDS = ["AND", "OR", "NOT"];
const OPERATOR_SCAN = [">=", "<=", ">", "<", "="];
const WORD_BREAKS = '()"';
const MAX_SUGGESTIONS = 8;
const DATE_OPERATORS = [
  { insert: ">=", detail: "on or after" },
  { insert: "<", detail: "before" },
  { insert: ">", detail: "after" },
  { insert: "<=", detail: "on or before" },
];

const isSpace = (char) => /\s/.test(char);
const isIdentStart = (char) => /[A-Za-z_]/.test(char);
const isIdentChar = (char) => /[A-Za-z0-9_]/.test(char);

// ── Schema ─────────────────────────────────────────────────────────────────

const fieldIndexes = new WeakMap();

// name or alias (lower-case) -> field spec from the schema.
export function fieldIndex(schema) {
  if (!schema) return new Map();
  if (!fieldIndexes.has(schema)) {
    const index = new Map();
    (schema.fields || []).forEach((field) => {
      index.set(field.name, field);
      (field.aliases || []).forEach((alias) => index.set(alias, field));
    });
    fieldIndexes.set(schema, index);
  }
  return fieldIndexes.get(schema);
}

let schemaPromise = null;

export function loadQuerySchema() {
  schemaPromise ||= fetchJSON("/api/cases/query-schema").catch(() => {
    schemaPromise = null;
    return null;
  });
  return schemaPromise;
}

// ── Tokenizer (mirror of case_query.tokenize, never throws) ────────────────

function readQuoted(text, start) {
  let value = "";
  let index = start + 1;
  while (index < text.length) {
    const char = text[index];
    if (char === "\\" && index + 1 < text.length && '"\\'.includes(text[index + 1])) {
      value += text[index + 1];
      index += 2;
    } else if (char === '"') {
      return { value, end: index + 1, closed: true };
    } else {
      value += char;
      index += 1;
    }
  }
  return { value, end: text.length, closed: false };
}

// `name:` is a field expression when name is a known field / hinted name,
// or when a value follows the colon directly (so `random_field:x` is a
// query error, while `Alerts: ESA`, `C:\x`, `http://x` stay free text).
function isFieldSyntax(name, following, schema) {
  const lower = name.toLowerCase();
  if (fieldIndex(schema).has(lower) || Object.hasOwn(schema?.hints || {}, lower)) return true;
  return Boolean(following) && !isSpace(following) && !"/\\:)".includes(following);
}

function wordEnd(text, start) {
  let end = start;
  while (end < text.length && !isSpace(text[end]) && !WORD_BREAKS.includes(text[end])) end += 1;
  return end;
}

export function lexQuery(text, schema) {
  const tokens = [];
  let index = 0;
  while (index < text.length) {
    const char = text[index];
    if (isSpace(char)) {
      index += 1;
    } else if (char === "(" || char === ")") {
      tokens.push({ kind: char === "(" ? "LPAREN" : "RPAREN", start: index, end: index + 1 });
      index += 1;
    } else if (char === '"') {
      const quoted = readQuoted(text, index);
      tokens.push({ kind: "QUOTED", start: index, end: quoted.end, value: quoted.value, closed: quoted.closed });
      index = quoted.end;
    } else {
      let nameEnd = index;
      if (isIdentStart(char)) {
        nameEnd += 1;
        while (nameEnd < text.length && isIdentChar(text[nameEnd])) nameEnd += 1;
      }
      if (nameEnd > index && text[nameEnd] === ":" && isFieldSyntax(text.slice(index, nameEnd), text[nameEnd + 1] || "", schema)) {
        const token = { kind: "FIELD", start: index, field: text.slice(index, nameEnd), op: "", value: "", valueKind: "", closed: true };
        let cursor = nameEnd + 1;
        const op = OPERATOR_SCAN.find((symbol) => text.startsWith(symbol, cursor));
        if (op) {
          token.op = op;
          cursor += op.length;
        }
        token.valueStart = cursor;
        if (text[cursor] === '"') {
          const quoted = readQuoted(text, cursor);
          Object.assign(token, { value: quoted.value, valueKind: "quoted", closed: quoted.closed });
          cursor = quoted.end;
        } else if (text[cursor] === "(") {
          token.valueKind = "group";
          cursor += 1;
        } else if (cursor < text.length && !isSpace(text[cursor]) && !WORD_BREAKS.includes(text[cursor])) {
          const end = wordEnd(text, cursor);
          Object.assign(token, { value: text.slice(cursor, end), valueKind: "word" });
          cursor = end;
        }
        token.end = cursor;
        tokens.push(token);
        index = cursor;
      } else {
        const end = wordEnd(text, index);
        const word = text.slice(index, end);
        const upper = word.toUpperCase();
        tokens.push({ kind: KEYWORDS.includes(upper) ? upper : "WORD", start: index, end, value: word });
        index = end;
      }
    }
  }
  return tokens;
}

// Structured = contains at least one field expression. Everything else --
// including `command and control` -- is a legacy free-text search.
export function isStructuredQuery(text, schema) {
  return lexQuery(String(text || ""), schema).some((token) => token.kind === "FIELD");
}

// ── Suggestions ────────────────────────────────────────────────────────────

function completesTerm(token) {
  if (!token) return false;
  if (token.kind === "FIELD") return (token.valueKind === "word" || token.valueKind === "quoted") && token.closed;
  if (token.kind === "QUOTED") return token.closed;
  return token.kind === "WORD" || token.kind === "RPAREN";
}

function toneClass(field, value) {
  return field.name === "severity" || field.name === "verdict" ? `tone-${String(value.key).toLowerCase()}` : "";
}

function valueItems(field, typed) {
  const prefix = typed.toLowerCase();
  const matches = (candidate) => String(candidate).toLowerCase().startsWith(prefix);
  return (field.values || [])
    .filter((value) => matches(value.value) || matches(value.label) || matches(value.key))
    .filter((value) => value.value.toLowerCase() !== prefix)
    .map((value) => ({
      kind: "value",
      label: value.value,
      detail: value.label !== value.value ? value.label : "",
      insert: `${value.insert} `,
      tone: toneClass(field, value),
    }));
}

function fieldItems(schema, prefix) {
  const items = [];
  (schema.fields || []).forEach((field) => {
    [field.name, ...(field.aliases || [])].forEach((name) => {
      if (name.startsWith(prefix) && name !== prefix) {
        items.push({
          kind: "field",
          label: `${name}:`,
          detail: name === field.name ? field.description : `Alias of ${field.name}:`,
          insert: `${name}:`,
        });
      }
    });
  });
  return items;
}

function keywordItems(prefix = "") {
  return KEYWORDS
    .filter((keyword) => keyword.startsWith(prefix.toUpperCase()) && keyword !== prefix.toUpperCase())
    .map((keyword) => ({ kind: "keyword", label: keyword, detail: "Boolean operator", insert: `${keyword} ` }));
}

// The field whose value list `field:( … )` is still open at the end of tokens.
function openGroupField(tokens) {
  const open = [];
  tokens.forEach((token) => {
    if (token.kind === "LPAREN" || (token.kind === "FIELD" && token.valueKind === "group")) open.push(token);
    else if (token.kind === "RPAREN") open.pop();
  });
  const innermost = open[open.length - 1];
  return innermost?.kind === "FIELD" ? innermost : null;
}

// Suggestions for the text before `cursor`: { from, to, items[] } where
// choosing an item replaces text.slice(from, to) with item.insert.
export function suggestionsAt(text, cursor, schema) {
  const none = { from: cursor, to: cursor, items: [] };
  if (!schema?.fields?.length) return none;
  const tokens = lexQuery(text.slice(0, cursor), schema);
  const structured = isStructuredQuery(text, schema);
  const last = tokens[tokens.length - 1];
  const touching = Boolean(last) && last.end === cursor;
  const fields = fieldIndex(schema);
  const result = (from, items) => ({ from, to: cursor, items: items.slice(0, MAX_SUGGESTIONS) });

  // A field's value: `severity:`, `severity:HI`, `workflow_status:"Awaiting Ap`, `created:`.
  if (last?.kind === "FIELD" && touching && last.valueKind !== "group" && !(last.valueKind === "quoted" && last.closed)) {
    const field = fields.get(last.field.toLowerCase());
    if (!field) return none;
    if (field.kind === "enum") return result(last.valueStart, valueItems(field, last.value));
    if (field.kind === "date" && !last.op && !last.value) {
      return result(last.valueStart, DATE_OPERATORS.map((op) => ({
        kind: "operator", label: op.insert, detail: `${op.detail} · YYYY-MM-DD (UTC)`, insert: op.insert,
      })));
    }
    return none;
  }

  // Inside a value list: `severity:(HIGH OR CR`.
  const group = openGroupField(tokens);
  if (group) {
    const field = fields.get(group.field.toLowerCase());
    if (!field || field.kind !== "enum") return none;
    if (touching && last.kind === "WORD") return result(last.start, valueItems(field, last.value));
    if (last === group || (last.kind === "OR" && !touching)) return result(cursor, valueItems(field, ""));
    if (!touching && completesTerm(last)) return result(cursor, keywordItems().filter((item) => item.label === "OR"));
    return none;
  }

  // A partly typed word: field names, plus AND / OR / NOT once structured.
  if (touching && (last.kind === "WORD" || KEYWORDS.includes(last.kind))) {
    const prefix = last.value.toLowerCase();
    const previous = tokens[tokens.length - 2];
    const items = [];
    if (structured && completesTerm(previous)) items.push(...keywordItems(prefix));
    if (prefix.length >= 2 || structured) items.push(...fieldItems(schema, prefix));
    return result(last.start, items);
  }

  // After a space in a structured query.
  if (!touching && structured && last) {
    if (completesTerm(last)) return result(cursor, keywordItems());
    if (["AND", "OR", "NOT", "LPAREN"].includes(last.kind)) {
      const not = last.kind === "NOT" ? [] : keywordItems().filter((item) => item.label === "NOT");
      return result(cursor, [...not, ...fieldItems(schema, "")]);
    }
  }
  return none;
}

export function applySuggestion(text, suggestions, item) {
  const next = text.slice(0, suggestions.from) + item.insert + text.slice(suggestions.to);
  return { text: next, cursor: suggestions.from + item.insert.length };
}

// ── Markup ─────────────────────────────────────────────────────────────────

export function errorHTML(error, query) {
  const details = error?.details || {};
  const start = Number.isInteger(details.start) ? details.start : -1;
  const end = Number.isInteger(details.end) ? details.end : -1;
  const snippet = start >= 0 && end > start && end <= query.length
    ? `<code class="query-error-snippet">${escapeHTML(query.slice(0, start))}<mark>${escapeHTML(query.slice(start, end))}</mark>${escapeHTML(query.slice(end))}</code>`
    : "";
  const hint = details.hint ? `<span class="query-error-hint">${escapeHTML(details.hint)}</span>` : "";
  return `<strong class="query-error-message">${escapeHTML(error?.message || "The query is not valid.")}</strong>${hint}${snippet}`;
}

function suggestionsHTML(items, active) {
  return items.map((item, index) => `<li class="query-suggestion${index === active ? " is-active" : ""}" role="option" id="query-suggestion-${index}" data-index="${index}" aria-selected="${index === active}">
      <span class="query-suggestion-label${item.tone ? ` ${item.tone}` : ""}">${escapeHTML(item.label)}</span>
      ${item.detail ? `<span class="query-suggestion-detail">${escapeHTML(item.detail)}</span>` : ""}
    </li>`).join("");
}

export function helpHTML(schema) {
  if (!schema) {
    return `<p class="query-help-intro">Query help is unavailable right now. Plain text search still works.</p>`;
  }
  const fieldRows = schema.fields.map((field) => {
    const names = [field.name, ...(field.aliases || [])].map((name) => `<code>${escapeHTML(name)}:</code>`).join(" ");
    const values = field.values?.length
      ? field.values.map((value) => escapeHTML(value.value)).join(", ")
      : escapeHTML(field.description);
    return `<tr><th scope="row">${names}</th><td>${values}</td></tr>`;
  }).join("");
  const examples = schema.examples.map((example) => `<li><button type="button" class="query-help-example" data-query="${escapeHTML(example.query)}"><span>${escapeHTML(example.label)}</span><code>${escapeHTML(example.query)}</code></button></li>`).join("");
  return `
    <p class="query-help-intro">Type plain text to search case titles and IDs, or filter with <code>field:value</code>.</p>
    <h3>Fields</h3>
    <table class="query-help-fields"><tbody>${fieldRows}</tbody></table>
    <h3>Operators</h3>
    <p><code>AND</code> <code>OR</code> <code>NOT</code> <code>( )</code> · terms side by side mean AND · values with spaces need quotes, e.g. <code>workflow_status:"Awaiting Approval"</code></p>
    <p>Comparisons <code>&gt;</code> <code>&gt;=</code> <code>&lt;</code> <code>&lt;=</code> work on severity, created and updated, e.g. <code>severity:&gt;=HIGH</code>.</p>
    <ul class="query-help-notes">${schema.notes.map((note) => `<li>${escapeHTML(note)}</li>`).join("")}</ul>
    <h3>Examples</h3>
    <ul class="query-help-examples">${examples}</ul>`;
}

// ── DOM controller ─────────────────────────────────────────────────────────

export function createQueryAssist({ input, onRun }) {
  const box = input.closest(".topbar-search");
  if (!box) return null;
  let schema = null;
  let suggestions = { from: 0, to: 0, items: [] };
  let active = -1;
  let dismissed = false;
  let error = null;
  let pending = false;

  const panel = document.createElement("div");
  panel.className = "query-assist";
  panel.hidden = true;
  panel.innerHTML = `<div class="query-assist-error" role="alert" hidden></div>
    <ul class="query-suggestions" id="query-suggestions" role="listbox" aria-label="Query suggestions"></ul>
    <p class="query-assist-hint" hidden>Press <kbd>Enter</kbd> to run this query.</p>`;
  const errorBox = panel.querySelector(".query-assist-error");
  const list = panel.querySelector(".query-suggestions");
  const hint = panel.querySelector(".query-assist-hint");

  const helpToggle = document.createElement("button");
  helpToggle.type = "button";
  helpToggle.className = "query-help-toggle";
  helpToggle.textContent = "?";
  helpToggle.title = "Query syntax";
  helpToggle.setAttribute("aria-label", "Query syntax help");
  helpToggle.setAttribute("aria-expanded", "false");
  helpToggle.setAttribute("aria-controls", "query-help");

  const help = document.createElement("div");
  help.className = "case-popover query-help";
  help.id = "query-help";
  help.hidden = true;
  help.setAttribute("role", "dialog");
  help.setAttribute("aria-label", "Query syntax");

  box.append(helpToggle, panel, help);
  const originalAria = ["role", "aria-autocomplete", "aria-controls", "aria-expanded", "aria-activedescendant", "aria-invalid"]
    .map((name) => [name, input.getAttribute(name)]);
  input.setAttribute("role", "combobox");
  input.setAttribute("aria-autocomplete", "list");
  input.setAttribute("aria-controls", "query-suggestions");
  input.setAttribute("aria-expanded", "false");

  loadQuerySchema().then((loaded) => {
    schema = loaded;
    if (!help.hidden) help.innerHTML = `<h2>Query syntax</h2>${helpHTML(schema)}`;
  });

  function render() {
    const showList = !dismissed && suggestions.items.length > 0 && document.activeElement === input;
    list.innerHTML = showList ? suggestionsHTML(suggestions.items, active) : "";
    list.hidden = !showList;
    errorBox.hidden = !error;
    errorBox.innerHTML = error ? errorHTML(error.error, error.query) : "";
    hint.hidden = !pending || Boolean(error);
    panel.hidden = !showList && errorBox.hidden && hint.hidden;
    input.setAttribute("aria-expanded", String(showList));
    if (showList && active >= 0) input.setAttribute("aria-activedescendant", `query-suggestion-${active}`);
    else input.removeAttribute("aria-activedescendant");
  }

  function refresh() {
    suggestions = suggestionsAt(input.value, input.selectionStart ?? input.value.length, schema);
    active = -1;
    render();
  }

  function choose(index) {
    const item = suggestions.items[index];
    if (!item) return;
    const next = applySuggestion(input.value, suggestions, item);
    input.value = next.text;
    input.setSelectionRange(next.cursor, next.cursor);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function openHelp() {
    help.innerHTML = `<h2>Query syntax</h2>${helpHTML(schema)}`;
    help.hidden = false;
    helpToggle.setAttribute("aria-expanded", "true");
  }

  function closeHelp(returnFocus = false) {
    if (help.hidden) return;
    help.hidden = true;
    helpToggle.setAttribute("aria-expanded", "false");
    if (returnFocus) helpToggle.focus();
  }

  helpToggle.addEventListener("click", () => (help.hidden ? openHelp() : closeHelp()));
  help.addEventListener("click", (event) => {
    const example = event.target.closest("[data-query]");
    if (!example) return;
    closeHelp();
    input.value = example.dataset.query;
    input.focus();
    onRun(example.dataset.query);
  });
  list.addEventListener("pointerdown", (event) => {
    const option = event.target.closest("[data-index]");
    if (!option) return;
    event.preventDefault();  // keep focus in the search box
    choose(Number(option.dataset.index));
  });

  function onFocus() {
    dismissed = false;
    refresh();
  }
  function onBlur() {
    render();
  }
  function onDocumentPointerDown(event) {
    if (!help.hidden && !event.target.closest("#query-help, .query-help-toggle")) closeHelp();
  }
  function onDocumentKeydown(event) {
    if (event.key === "Escape" && !help.hidden) {
      event.preventDefault();
      closeHelp(true);
    }
  }
  input.addEventListener("focus", onFocus);
  input.addEventListener("blur", onBlur);
  document.addEventListener("pointerdown", onDocumentPointerDown);
  document.addEventListener("keydown", onDocumentKeydown);

  return {
    isStructured: (text) => isStructuredQuery(text, schema),
    // Called on every input event, after the caller decides debounce vs Enter.
    onInput() {
      dismissed = false;
      error = null;
      input.removeAttribute("aria-invalid");
      refresh();
    },
    refresh,
    // True when the key was consumed by the suggestion list.
    handleKeydown(event) {
      const open = !list.hidden && suggestions.items.length > 0;
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        if (!open) {
          dismissed = false;
          refresh();
          if (!suggestions.items.length) return false;
        }
        const count = suggestions.items.length;
        active = event.key === "ArrowDown" ? (active + 1) % count : (active - 1 + count) % count;
        event.preventDefault();
        render();
        return true;
      }
      if (event.key === "Enter" && open && active >= 0) {
        event.preventDefault();
        choose(active);
        return true;
      }
      if (event.key === "Escape" && open) {
        event.preventDefault();
        dismissed = true;
        render();
        return true;
      }
      if (event.key === "Tab" && open) {
        dismissed = true;
        render();
      }
      return false;
    },
    setPending(value) {
      pending = Boolean(value);
      render();
    },
    showError(apiError, query) {
      error = { error: apiError, query };
      pending = false;
      input.setAttribute("aria-invalid", "true");
      render();
    },
    clearError() {
      if (!error) return;
      error = null;
      input.removeAttribute("aria-invalid");
      render();
    },
    destroy() {
      input.removeEventListener("focus", onFocus);
      input.removeEventListener("blur", onBlur);
      document.removeEventListener("pointerdown", onDocumentPointerDown);
      document.removeEventListener("keydown", onDocumentKeydown);
      originalAria.forEach(([name, value]) => (value === null ? input.removeAttribute(name) : input.setAttribute(name, value)));
      helpToggle.remove();
      panel.remove();
      help.remove();
    },
  };
}
