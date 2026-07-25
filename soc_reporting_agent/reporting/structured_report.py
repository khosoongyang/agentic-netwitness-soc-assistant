from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def clean_inline(value: Any) -> str:
    text = str(value or "")
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"__([^_]+)__", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^\)]*\)", r"\1", text)
    text = text.replace("<br>", " ").replace("<br/>", " ").replace("<br />", " ")
    text = re.sub(re.escape("attempt. scenario"), "attempt scenario", text, flags=re.IGNORECASE)
    text = re.sub(re.escape("if approved.."), "if approved.", text, flags=re.IGNORECASE)
    text = re.sub(r"\.{2,}", ".", text)
    text = re.sub(r"\s+([,.;:])", r"\1", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _is_separator_row(line: str) -> bool:
    stripped = line.strip()
    cells = [c.strip() for c in stripped.strip("|").split("|")]
    return len(cells) >= 2 and all(re.fullmatch(r":?-{2,}:?", c or "") for c in cells)


def _is_table_row(line: str) -> bool:
    stripped = line.strip()
    return stripped.count("|") >= 1 and not _is_separator_row(stripped)


def _cells(line: str) -> list[str]:
    return [clean_inline(c) for c in line.strip().strip("|").split("|")]


def _looks_like_plain_table_row(line: str) -> bool:
    stripped = line.strip()
    if stripped.startswith("|") and stripped.endswith("|"):
        return _is_table_row(stripped) or _is_separator_row(stripped)
    return not stripped.startswith("- ") and stripped.count("|") >= 1


def _plain_cells(line: str) -> list[str]:
    return [clean_inline(c) for c in line.strip().strip("|").split("|")]


def parse_pipe_table(lines: list[str], start: int) -> tuple[dict[str, Any] | None, int]:
    """Parse a Markdown or plain pipe table beginning at *start*.

    Generated Jinja reports can place blank lines between rows, so a single blank
    line is tolerated when the next non-blank line has the same column count.
    Two blank lines, prose, headings, and differently-shaped rows end the table.
    """
    if start >= len(lines) or not _looks_like_plain_table_row(lines[start]):
        return None, start
    first_cells = _plain_cells(lines[start])
    if len(first_cells) < 2:
        return None, start
    first_line = lines[start].strip()
    if first_line.count("|") == 1 and (
        any(len(cell) > 80 for cell in first_cells)
        or any(re.search(r"[.!?]$", cell) for cell in first_cells)
    ):
        return None, start

    rows: list[list[str]] = [first_cells]
    separator_seen = False
    width = len(first_cells)
    i = start + 1
    while i < len(lines):
        blanks = 0
        while i < len(lines) and not lines[i].strip():
            blanks += 1
            i += 1
        if blanks >= 2 or i >= len(lines):
            break
        candidate = lines[i].strip()
        if _is_separator_row(candidate):
            if len(_plain_cells(candidate)) != width or len(rows) != 1:
                break
            separator_seen = True
            i += 1
            continue
        if not _looks_like_plain_table_row(candidate):
            break
        cells = _plain_cells(candidate)
        if len(cells) > width or len(cells) < 2:
            break
        cells += [""] * (width - len(cells))
        rows.append(cells)
        i += 1

    if len(rows) < 2:
        return None, start
    # Markdown tables are anchored by their separator. Plain tables require a
    # consistent header plus at least one body row; casual single-pipe prose is
    # therefore left alone.
    columns, body = rows[0], rows[1:]
    if not separator_seen and not body:
        return None, start
    return {"type": "table", "columns": columns, "rows": body}, i


def paragraph_contains_raw_pipe_table(text: Any) -> bool:
    """Return True only for multi-column table syntax, not a casual single pipe."""
    lines = str(text or "").replace("\r", "").splitlines()
    if any(_is_separator_row(line) for line in lines if line.strip()):
        return True
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        cells = _plain_cells(stripped)
        if stripped.startswith("|") and stripped.endswith("|") and len(cells) >= 2:
            return True
        if stripped.count("|") >= 2 and len(cells) >= 3:
            return True
    return False


def _separator_cell(value: str) -> bool:
    return bool(re.fullmatch(r":?-{2,}:?", str(value or "").strip()))


def _collapsed_markdown_table(text: str) -> dict[str, Any] | None:
    """Recover a Markdown table whose newlines were flattened into one paragraph."""
    raw = str(text or "").strip()
    if raw.count("|") < 2:
        return None
    tokens = [clean_inline(part) for part in raw.split("|")]
    separator_runs: list[tuple[int, int]] = []
    i = 0
    while i < len(tokens):
        if not _separator_cell(tokens[i]):
            i += 1
            continue
        start = i
        while i < len(tokens) and _separator_cell(tokens[i]):
            i += 1
        separator_runs.append((start, i))
    if not separator_runs:
        return None

    # A valid flattened Markdown table has one separator run whose width agrees
    # with the immediately preceding non-empty header cells.
    for sep_start, sep_end in separator_runs:
        width = sep_end - sep_start
        before = [value for value in tokens[:sep_start] if value]
        if width < 1 or len(before) < width:
            continue
        columns = before[-width:]
        if len(columns) != width or any(_separator_cell(value) for value in columns):
            continue
        remaining = [value for value in tokens[sep_end:] if value]
        if remaining and len(remaining) % width:
            continue
        rows = [remaining[pos:pos + width] for pos in range(0, len(remaining), width)]
        return {"type": "table", "columns": columns, "rows": rows}
    return None


def _single_pipe_row(text: str, width: int) -> list[str] | None:
    stripped = str(text or "").strip()
    if not _looks_like_plain_table_row(stripped) or _is_separator_row(stripped):
        return None
    cells = _plain_cells(stripped)
    if len(cells) > width or len(cells) < 1:
        return None
    return cells + [""] * (width - len(cells))


def repair_pipe_tables_in_blocks(blocks: list[dict[str, Any]] | Any) -> list[dict[str, Any]]:
    """Recover pipe tables from legacy structured paragraph blocks.

    This is deliberately conservative: tables need either a Markdown separator
    or at least two consistently shaped pipe-row paragraphs.
    """
    if not isinstance(blocks, list):
        return []
    repaired: list[dict[str, Any]] = []
    i = 0
    while i < len(blocks):
        block = blocks[i]
        if not isinstance(block, dict) or block.get("type") != "paragraph":
            repaired.append(block)
            i += 1
            continue
        collapsed = _collapsed_markdown_table(str(block.get("text") or ""))
        if collapsed:
            columns = list(collapsed["columns"])
            rows = list(collapsed["rows"])
            width = len(columns)
            j = i + 1
            # Earlier parsing can incorrectly make the first data row the
            # columns of a table block. Promote it back into the body.
            if j < len(blocks) and isinstance(blocks[j], dict) and blocks[j].get("type") == "table":
                following = blocks[j]
                following_columns = [clean_inline(value) for value in following.get("columns") or []]
                if len(following_columns) <= width:
                    rows.append(following_columns + [""] * (width - len(following_columns)))
                    for raw_row in following.get("rows") or []:
                        values = [clean_inline(value) for value in raw_row or []]
                        if len(values) <= width:
                            rows.append(values + [""] * (width - len(values)))
                    j += 1
            while j < len(blocks):
                following = blocks[j]
                if not isinstance(following, dict) or following.get("type") != "paragraph":
                    break
                row = _single_pipe_row(str(following.get("text") or ""), width)
                if row is None:
                    break
                rows.append(row)
                j += 1
            if rows:
                repaired.append({"type": "table", "columns": columns, "rows": rows})
                i = j
                continue
        run: list[str] = []
        j = i
        while j < len(blocks):
            current = blocks[j]
            if not isinstance(current, dict) or current.get("type") != "paragraph":
                break
            text = str(current.get("text") or "").strip()
            if not _looks_like_plain_table_row(text):
                break
            run.append(text)
            j += 1
        table, consumed = parse_pipe_table(run, 0) if run else (None, 0)
        if table and consumed == len(run):
            repaired.append(table)
            i = j
        else:
            repaired.append(block)
            i += 1
    return repaired


# Backwards-compatible name for callers added by the first structured-table fix.
repair_structured_blocks = repair_pipe_tables_in_blocks


def _flush_plain_table(rows: list[list[str]], blocks: list[dict[str, Any]]) -> None:
    if len(rows) < 2:
        return
    filtered = [row for row in rows if row and not all(re.fullmatch(r":?-{2,}:?", str(c).strip()) for c in row)]
    if len(filtered) < 2:
        return
    columns = filtered[0]
    body = filtered[1:]
    width = max(len(columns), *(len(row) for row in body))
    columns = columns + [""] * (width - len(columns))
    normalised_body = [row + [""] * (width - len(row)) for row in body]
    blocks.append({"type": "table", "columns": columns, "rows": normalised_body})


def _flush_paragraph(blocks: list[dict[str, Any]], paragraph: list[str]) -> None:
    if not paragraph:
        return
    text = clean_inline(" ".join(p.strip() for p in paragraph if p.strip()))
    if text:
        blocks.append({"type": "paragraph", "text": text})
    paragraph.clear()


def _flush_bullets(blocks: list[dict[str, Any]], bullets: list[dict[str, Any]]) -> None:
    if not bullets:
        return
    items = [{"text": clean_inline(b.get("text")), "level": int(b.get("level") or 0)}
             for b in bullets if clean_inline(b.get("text"))]
    if items:
        blocks.append({"type": "bullet_list", "items": items})
    bullets.clear()


def markdown_to_blocks(markdown_text: Any) -> list[dict[str, Any]]:
    """Convert the existing Jinja2 Markdown-like report into structured report blocks.

    The dashboard, DOCX exporter and PDF exporter render these blocks as real
    headings, paragraphs, lists and tables. Markdown pipe tables are not shown as
    literal text anywhere in the final UI/export path.
    """
    text = str(markdown_text or "").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"```[\s\S]*?```", lambda m: m.group(0).strip("`"), text)
    lines = text.split("\n")
    blocks: list[dict[str, Any]] = []
    paragraph: list[str] = []
    bullets: list[dict[str, Any]] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.strip()
        if not line:
            _flush_paragraph(blocks, paragraph)
            _flush_bullets(blocks, bullets)
            i += 1
            continue
        if re.fullmatch(r"-{3,}", line):
            _flush_paragraph(blocks, paragraph)
            _flush_bullets(blocks, bullets)
            i += 1
            continue
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            _flush_paragraph(blocks, paragraph)
            _flush_bullets(blocks, bullets)
            level = min(len(heading.group(1)), 4)
            blocks.append({"type": "heading", "level": level, "text": clean_inline(heading.group(2))})
            i += 1
            continue
        bullet = re.match(r"^[-*+]\s+(.*)$", line)
        if bullet:
            _flush_paragraph(blocks, paragraph)
            indent = len(raw) - len(raw.lstrip(" \t"))
            level = min(3, indent // 2)
            bullets.append({"text": bullet.group(1), "level": level})
            i += 1
            continue
        # No blockquote rendering exists in this report's exporters — a stray
        # "> " marker (list-style notes, or an LLM narrative line that starts
        # with one) always reads as a plain bullet, never a raw ">" glyph.
        quote = re.match(r"^>\s*(.*)$", line)
        if quote:
            _flush_paragraph(blocks, paragraph)
            bullets.append({"text": quote.group(1), "level": 0})
            i += 1
            continue
        table, next_i = parse_pipe_table(lines, i)
        if table:
            _flush_paragraph(blocks, paragraph)
            _flush_bullets(blocks, bullets)
            blocks.append(table)
            i = next_i
            continue
        # Preserve numbered section titles generated without markdown if present.
        numbered_heading = re.match(r"^(\d+(?:\.\d+)*)\.\s+(.+)$", line)
        if numbered_heading and len(line) < 120:
            _flush_paragraph(blocks, paragraph)
            _flush_bullets(blocks, bullets)
            blocks.append({"type": "heading", "level": 2, "text": clean_inline(line)})
            i += 1
            continue
        paragraph.append(line)
        i += 1
    _flush_paragraph(blocks, paragraph)
    _flush_bullets(blocks, bullets)
    return blocks


def blocks_to_plain_text(blocks: list[dict[str, Any]] | Any) -> str:
    if not isinstance(blocks, list):
        return clean_inline(blocks)
    out: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        t = block.get("type")
        if t == "heading":
            if out:
                out.append("")
            out.append(clean_inline(block.get("text")))
        elif t == "paragraph":
            text = clean_inline(block.get("text"))
            if text:
                out.append(text)
        elif t == "bullet_list":
            for item in block.get("items") or []:
                if isinstance(item, dict):
                    item_text = clean_inline(item.get("text"))
                    level = int(item.get("level") or 0)
                else:
                    item_text, level = clean_inline(item), 0
                if item_text:
                    out.append(f"{'  ' * level}- {item_text}")
        elif t == "table":
            cols = [clean_inline(c) for c in block.get("columns") or []]
            rows = block.get("rows") or []
            if len(cols) == 2:
                for row in rows:
                    cells = [clean_inline(c) for c in (row or [])]
                    if len(cells) >= 2:
                        out.append(f"{cells[0]}: {cells[1]}")
            else:
                if cols:
                    out.append(" | ".join(cols))
                for row in rows:
                    cells = [clean_inline(c) for c in (row or [])]
                    if cells:
                        out.append(" | ".join(cells))
        else:
            text = clean_inline(block.get("text"))
            if text:
                out.append(text)
    text = "\n".join(out)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def save_blocks(path: Path, blocks: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(blocks or [], indent=2, ensure_ascii=False), encoding="utf-8")


def load_blocks(path: str | Path | None) -> list[dict[str, Any]]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("blocks"), list):
            return data["blocks"]
    except Exception:
        return []
    return []


def blocks_from_text(text: str) -> list[dict[str, Any]]:
    # Fallback parser for saved plain text. It detects simple "Field: Value" runs
    # and turns them into a two-column table if there are at least three lines.
    raw = str(text or "")
    lines = [ln.strip() for ln in raw.splitlines()]
    blocks: list[dict[str, Any]] = []
    i = 0
    while i < len(lines):
        if not lines[i]:
            i += 1
            continue
        table, next_i = parse_pipe_table(lines, i)
        if table:
            blocks.append(table)
            i = next_i
            continue
        if len(lines[i]) < 120 and (
            re.match(r"^\d+(?:\.\d+)+(?:\.)?\s+[A-Z]", lines[i])
            or re.match(r"^(\d+(\.\d+)*\.\s+)?[A-Z][A-Za-z0-9 /&,-]+$", lines[i])
        ):
            blocks.append({"type": "heading", "level": 2, "text": clean_inline(lines[i])})
            i += 1
            continue
        kv_rows = []
        start = i
        while i < len(lines) and ":" in lines[i] and len(lines[i].split(":", 1)[0]) < 50:
            a, b = lines[i].split(":", 1)
            kv_rows.append([clean_inline(a), clean_inline(b)])
            i += 1
        if len(kv_rows) >= 3:
            blocks.append({"type": "table", "columns": ["Field", "Value"], "rows": kv_rows})
            continue
        if kv_rows:
            # Fewer than three key/value lines are ordinary prose. Advance here
            # so a lone sentence containing a colon cannot stall the parser.
            blocks.append({"type": "paragraph", "text": clean_inline(lines[start])})
            i = start + 1
            continue
        i = start
        para = []
        while (
            i < len(lines)
            and lines[i]
            and not (":" in lines[i] and len(lines[i].split(":", 1)[0]) < 50)
            and parse_pipe_table(lines, i)[0] is None
            and not re.match(r"^\d+(?:\.\d+)+(?:\.)?\s+[A-Z]", lines[i])
        ):
            para.append(lines[i]); i += 1
        textp = clean_inline(" ".join(para))
        if textp:
            blocks.append({"type": "paragraph", "text": textp})
    return blocks
