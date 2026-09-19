// Minimal, dependency-free block-aware editor for the Reporting stage's
// structured content model (heading/paragraph/bullet_list/table/page_break —
// see backend/services/report_service.py::_validate_blocks and
// agents/reporting/reporting/structured_report.py). No rich-text framework,
// no build step: this is a small factory that returns a mountable DOM
// element plus a handful of accessors, consistent with this app's existing
// vanilla-JS page modules.
//
// Deliberately does NOT support inline bold/italic/underline/links or a
// numbered-list block type in this phase: the existing DOCX/PDF writer
// (agents/reporting/reporting/editable_reports.py::_docx_write_blocks /
// _pdf_write_blocks) only understands whole-block styling today, so a
// toolbar button for inline formatting would either silently do nothing on
// export or leak raw markup into the exported document. Structural editing
// (headings, paragraphs, bullet lists with nesting, tables, page breaks,
// reordering, undo/redo) is fully supported and round-trips correctly
// through the existing save/export path unchanged.

const MAX_HISTORY = 50;

function cloneBlocks(blocks) {
  return JSON.parse(JSON.stringify(blocks || []));
}

function blocksEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function clampLevel(level) {
  return Math.min(2, Math.max(0, Number(level) || 0));
}

function newHeadingBlock() { return { type: "heading", level: 2, text: "" }; }
function newParagraphBlock() { return { type: "paragraph", text: "" }; }
function newBulletListBlock() { return { type: "bullet_list", items: [{ text: "", level: 0 }] }; }
function newTableBlock() { return { type: "table", columns: ["Column 1", "Column 2"], rows: [["", ""]] }; }
function newPageBreakBlock() { return { type: "page_break" }; }

// Keeps pasted content as plain text — contenteditable would otherwise carry
// over the source's rich HTML, which the editor would visually render but
// silently drop on save (only .textContent is ever persisted), a confusing
// "it looked formatted, then it wasn't" trap.
function forcePlainTextPaste(el) {
  el.addEventListener("paste", (event) => {
    event.preventDefault();
    const text = (event.clipboardData || window.clipboardData).getData("text/plain");
    document.execCommand("insertText", false, text);
  });
}

export function createBlockEditor(initialBlocks) {
  let blocks = cloneBlocks(initialBlocks);
  const savedBlocks = cloneBlocks(initialBlocks);
  let undoStack = [];
  let redoStack = [];

  const root = document.createElement("div");
  root.className = "block-editor-root";
  root.innerHTML = `
    <div class="block-editor-toolbar">
      <div class="block-editor-toolbar-group">
        <button type="button" class="action-button" data-add="heading">+ Heading</button>
        <button type="button" class="action-button" data-add="paragraph">+ Paragraph</button>
        <button type="button" class="action-button" data-add="bullet_list">+ Bullet list</button>
        <button type="button" class="action-button" data-add="table">+ Table</button>
        <button type="button" class="action-button" data-add="page_break">+ Page break</button>
      </div>
      <div class="block-editor-toolbar-group">
        <button type="button" class="action-button" data-action="undo" title="Undo" disabled>↶ Undo</button>
        <button type="button" class="action-button" data-action="redo" title="Redo" disabled>↷ Redo</button>
        <button type="button" class="action-button" data-action="preview">Preview</button>
      </div>
    </div>
    <div class="block-editor-surface"></div>`;

  const toolbar = root.querySelector(".block-editor-toolbar");
  const surface = root.querySelector(".block-editor-surface");
  const changeListeners = [];
  const previewListeners = [];

  function notifyChange() {
    changeListeners.forEach((fn) => fn(cloneBlocks(blocks)));
  }

  function applyChange(mutator) {
    undoStack.push(cloneBlocks(blocks));
    if (undoStack.length > MAX_HISTORY) undoStack.shift();
    redoStack = [];
    mutator();
    render();
    notifyChange();
  }

  function moveBlock(index, delta) {
    const target = index + delta;
    if (target < 0 || target >= blocks.length) return;
    applyChange(() => {
      const [item] = blocks.splice(index, 1);
      blocks.splice(target, 0, item);
    });
  }

  function deleteBlock(index) {
    applyChange(() => { blocks.splice(index, 1); });
  }

  function blockControls(index) {
    return `
      <div class="editor-block-controls">
        <button type="button" class="editor-block-btn" data-move-up="${index}" title="Move up" ${index === 0 ? "disabled" : ""}>↑</button>
        <button type="button" class="editor-block-btn" data-move-down="${index}" title="Move down" ${index === blocks.length - 1 ? "disabled" : ""}>↓</button>
        <button type="button" class="editor-block-btn editor-block-btn-danger" data-delete-block="${index}" title="Delete block">✕</button>
      </div>`;
  }

  function renderHeading(block, index) {
    const wrap = document.createElement("div");
    wrap.className = "editor-block editor-block-heading";
    wrap.innerHTML = `
      ${blockControls(index)}
      <div class="editor-block-body">
        <select class="editor-heading-level" data-heading-level="${index}">
          <option value="2">Heading 2</option>
          <option value="3">Heading 3</option>
          <option value="4">Heading 4</option>
        </select>
        <div class="editor-text editor-heading-text" contenteditable="true" data-field="heading-text" data-index="${index}">${block.text || ""}</div>
      </div>`;
    wrap.querySelector(".editor-heading-level").value = String(block.level || 2);
    return wrap;
  }

  function renderParagraph(block, index) {
    const wrap = document.createElement("div");
    wrap.className = "editor-block editor-block-paragraph";
    wrap.innerHTML = `
      ${blockControls(index)}
      <div class="editor-block-body">
        <div class="editor-text" contenteditable="true" data-field="paragraph-text" data-index="${index}" data-placeholder="Paragraph text…">${block.text || ""}</div>
      </div>`;
    return wrap;
  }

  function renderBulletList(block, index) {
    const wrap = document.createElement("div");
    wrap.className = "editor-block editor-block-list";
    const items = block.items || [];
    wrap.innerHTML = `
      ${blockControls(index)}
      <div class="editor-block-body">
        <ul class="editor-list">
          ${items.map((item, itemIndex) => `
            <li class="editor-list-item" style="margin-left:${clampLevel(item.level) * 1.4}rem">
              <div class="editor-text" contenteditable="true" data-field="list-item-text" data-index="${index}" data-item="${itemIndex}">${item.text || ""}</div>
              <div class="editor-list-item-controls">
                <button type="button" class="editor-block-btn" data-outdent="${index}:${itemIndex}" title="Outdent" ${clampLevel(item.level) === 0 ? "disabled" : ""}>&lt;</button>
                <button type="button" class="editor-block-btn" data-indent="${index}:${itemIndex}" title="Indent" ${clampLevel(item.level) === 2 ? "disabled" : ""}>&gt;</button>
                <button type="button" class="editor-block-btn editor-block-btn-danger" data-remove-item="${index}:${itemIndex}" title="Remove item">✕</button>
              </div>
            </li>`).join("")}
        </ul>
        <button type="button" class="action-button" data-add-item="${index}">+ Item</button>
      </div>`;
    return wrap;
  }

  function renderTable(block, index) {
    const wrap = document.createElement("div");
    wrap.className = "editor-block editor-block-table";
    const columns = block.columns || [];
    const rows = block.rows || [];
    wrap.innerHTML = `
      ${blockControls(index)}
      <div class="editor-block-body">
        <div class="table-wrap">
          <table class="editor-table">
            <thead><tr>${columns.map((col, colIndex) => `<th class="editor-text" contenteditable="true" data-field="table-col" data-index="${index}" data-col="${colIndex}">${col || ""}</th>`).join("")}</tr></thead>
            <tbody>
              ${rows.map((row, rowIndex) => `<tr>${columns.map((_, colIndex) => `<td class="editor-text" contenteditable="true" data-field="table-cell" data-index="${index}" data-row="${rowIndex}" data-col="${colIndex}">${(row[colIndex] ?? "")}</td>`).join("")}<td class="editor-table-row-actions"><button type="button" class="editor-block-btn editor-block-btn-danger" data-remove-row="${index}:${rowIndex}" title="Remove row">✕</button></td></tr>`).join("")}
            </tbody>
          </table>
        </div>
        <div class="block-editor-toolbar-group">
          <button type="button" class="action-button" data-add-row="${index}">+ Row</button>
          <button type="button" class="action-button" data-add-col="${index}">+ Column</button>
          <button type="button" class="action-button" data-remove-col="${index}" ${columns.length <= 1 ? "disabled" : ""}>− Last column</button>
        </div>
      </div>`;
    return wrap;
  }

  function renderPageBreak(block, index) {
    const wrap = document.createElement("div");
    wrap.className = "editor-block editor-block-page-break";
    wrap.innerHTML = `${blockControls(index)}<div class="editor-block-body"><hr><span class="muted">Page break</span></div>`;
    return wrap;
  }

  function renderBlockNode(block, index) {
    if (block.type === "heading") return renderHeading(block, index);
    if (block.type === "paragraph") return renderParagraph(block, index);
    if (block.type === "bullet_list") return renderBulletList(block, index);
    if (block.type === "table") return renderTable(block, index);
    if (block.type === "page_break") return renderPageBreak(block, index);
    const wrap = document.createElement("div");
    wrap.className = "editor-block";
    wrap.innerHTML = `${blockControls(index)}<div class="editor-block-body muted">Unsupported block type: ${block.type}</div>`;
    return wrap;
  }

  function render() {
    const scrollTop = surface.scrollTop;
    surface.innerHTML = "";
    if (!blocks.length) {
      surface.innerHTML = `<p class="muted editor-empty">No content yet — use the buttons above to add a heading, paragraph, list, table or page break.</p>`;
    } else {
      blocks.forEach((block, index) => surface.appendChild(renderBlockNode(block, index)));
      bindTextFields();
    }
    surface.scrollTop = scrollTop;
    const undoBtn = toolbar.querySelector('[data-action="undo"]');
    const redoBtn = toolbar.querySelector('[data-action="redo"]');
    undoBtn.disabled = undoStack.length === 0;
    redoBtn.disabled = redoStack.length === 0;
  }

  function bindTextFields() {
    surface.querySelectorAll(".editor-text[contenteditable]").forEach((el) => {
      forcePlainTextPaste(el);
      el.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && el.dataset.field !== "paragraph-text") event.preventDefault();
      });
      el.addEventListener("blur", () => {
        const field = el.dataset.field;
        const index = Number(el.dataset.index);
        const text = el.textContent;
        if (field === "heading-text" && blocks[index]?.text !== text) {
          applyChange(() => { blocks[index].text = text; });
        } else if (field === "paragraph-text" && blocks[index]?.text !== text) {
          applyChange(() => { blocks[index].text = text; });
        } else if (field === "list-item-text") {
          const itemIndex = Number(el.dataset.item);
          if (blocks[index]?.items?.[itemIndex]?.text !== text) {
            applyChange(() => { blocks[index].items[itemIndex].text = text; });
          }
        } else if (field === "table-col") {
          const colIndex = Number(el.dataset.col);
          if (blocks[index]?.columns?.[colIndex] !== text) {
            applyChange(() => { blocks[index].columns[colIndex] = text; });
          }
        } else if (field === "table-cell") {
          const rowIndex = Number(el.dataset.row);
          const colIndex = Number(el.dataset.col);
          if (blocks[index]?.rows?.[rowIndex]?.[colIndex] !== text) {
            applyChange(() => { blocks[index].rows[rowIndex][colIndex] = text; });
          }
        }
      });
    });
  }

  toolbar.addEventListener("click", (event) => {
    const addType = event.target.closest("[data-add]")?.dataset.add;
    if (addType) {
      const factory = { heading: newHeadingBlock, paragraph: newParagraphBlock, bullet_list: newBulletListBlock, table: newTableBlock, page_break: newPageBreakBlock }[addType];
      if (factory) applyChange(() => { blocks.push(factory()); });
      return;
    }
    const action = event.target.closest("[data-action]")?.dataset.action;
    if (action === "undo" && undoStack.length) {
      redoStack.push(cloneBlocks(blocks));
      blocks = undoStack.pop();
      render();
      notifyChange();
    } else if (action === "redo" && redoStack.length) {
      undoStack.push(cloneBlocks(blocks));
      blocks = redoStack.pop();
      render();
      notifyChange();
    } else if (action === "preview") {
      previewListeners.forEach((fn) => fn(cloneBlocks(blocks)));
    }
  });

  toolbar.querySelector('[data-action="undo"]').disabled = true;
  toolbar.querySelector('[data-action="redo"]').disabled = true;

  surface.addEventListener("click", (event) => {
    const target = event.target;
    const moveUp = target.closest("[data-move-up]");
    const moveDown = target.closest("[data-move-down]");
    const del = target.closest("[data-delete-block]");
    const addItem = target.closest("[data-add-item]");
    const removeItem = target.closest("[data-remove-item]");
    const indent = target.closest("[data-indent]");
    const outdent = target.closest("[data-outdent]");
    const addRow = target.closest("[data-add-row]");
    const removeRow = target.closest("[data-remove-row]");
    const addCol = target.closest("[data-add-col]");
    const removeCol = target.closest("[data-remove-col]");

    if (moveUp) moveBlock(Number(moveUp.dataset.moveUp), -1);
    else if (moveDown) moveBlock(Number(moveDown.dataset.moveDown), 1);
    else if (del) deleteBlock(Number(del.dataset.deleteBlock));
    else if (addItem) {
      const index = Number(addItem.dataset.addItem);
      applyChange(() => { blocks[index].items.push({ text: "", level: 0 }); });
    } else if (removeItem) {
      const [index, itemIndex] = removeItem.dataset.removeItem.split(":").map(Number);
      applyChange(() => { blocks[index].items.splice(itemIndex, 1); });
    } else if (indent) {
      const [index, itemIndex] = indent.dataset.indent.split(":").map(Number);
      applyChange(() => { blocks[index].items[itemIndex].level = clampLevel((blocks[index].items[itemIndex].level || 0) + 1); });
    } else if (outdent) {
      const [index, itemIndex] = outdent.dataset.outdent.split(":").map(Number);
      applyChange(() => { blocks[index].items[itemIndex].level = clampLevel((blocks[index].items[itemIndex].level || 0) - 1); });
    } else if (addRow) {
      const index = Number(addRow.dataset.addRow);
      applyChange(() => { blocks[index].rows.push(new Array(blocks[index].columns.length).fill("")); });
    } else if (removeRow) {
      const [index, rowIndex] = removeRow.dataset.removeRow.split(":").map(Number);
      applyChange(() => { blocks[index].rows.splice(rowIndex, 1); });
    } else if (addCol) {
      const index = Number(addCol.dataset.addCol);
      applyChange(() => {
        blocks[index].columns.push(`Column ${blocks[index].columns.length + 1}`);
        blocks[index].rows.forEach((row) => row.push(""));
      });
    } else if (removeCol) {
      const index = Number(removeCol.dataset.removeCol);
      if (blocks[index].columns.length <= 1) return;
      applyChange(() => {
        blocks[index].columns.pop();
        blocks[index].rows.forEach((row) => row.pop());
      });
    }
  });

  surface.addEventListener("change", (event) => {
    const select = event.target.closest("[data-heading-level]");
    if (!select) return;
    const index = Number(select.dataset.headingLevel);
    applyChange(() => { blocks[index].level = Number(select.value); });
  });

  render();

  return {
    element: root,
    getBlocks: () => cloneBlocks(blocks),
    isDirty: () => !blocksEqual(blocks, savedBlocks),
    markSaved: () => { savedBlocks.length = 0; savedBlocks.push(...cloneBlocks(blocks)); },
    onChange: (fn) => changeListeners.push(fn),
    onPreview: (fn) => previewListeners.push(fn),
  };
}
