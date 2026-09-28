"""Canonical OpenAI integration API.

client.py moved here from soc_reporting_agent/backend/openai_client.py in
Phase 8 - it was the shared OpenAI helper reached (in-process) by
workflow/engine.py's AI-summary calls and (bare-import, in-subprocess) by
agents/reporting/reporting/template_document_exporter.py's PDF-export text
extraction. Both previously reached it via a `backend.openai_client` bare
import, which collided in-process with Aegis's own top-level backend/
package once that package had already been imported (no `openai_client`
submodule there) - this move, and repointing both call sites at
integrations.openai.client directly, is what actually fixes that collision
rather than merely relocating it. Models, prompts, timeouts, fallback
behaviour and structured-output logic are unchanged; broader OpenAI-call
consolidation across the rest of the codebase is Phase 9 work.
"""

from .client import (
    build_client,
    extract_json_object,
    invoke_openai_text,
    is_placeholder_key,
    latest_model,
    supports_temperature,
)

__all__ = [
    "build_client",
    "extract_json_object",
    "invoke_openai_text",
    "is_placeholder_key",
    "latest_model",
    "supports_temperature",
]
