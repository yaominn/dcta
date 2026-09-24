"""
Agent Service — the LLM parser. (brief Section 8: backend/agent/)

Responsibility: turn the ASR transcript into a schema-constrained IntentPlan
(symbolic, with mentions). Output handling: generate -> validate against the
Pydantic schema -> reject and retry, bounded retries. (brief Section 8)

Pipeline inside this package:
    context.build_context   stored rows -> opaque-ID prompt view (sanitizer)
    prompts                 the output contract as a prompt
    provider.get_provider   Hunyuan when creds exist, deterministic stub else
    parser.parse_transcript generate -> schema-validate -> bounded retry

TRUST BOUNDARY (enforced by the import-boundary test in tests/):
    backend/agent/  MUST NOT transitively import  backend/gateway/  or  backend/auth/
The agent writes drafts to the draft store. It has NO gateway credentials and
no code path to execution. Even fully compromised, the worst it can do is emit
a wrong draft the user then declines. (brief Section 4.2 / 3)

Note: this package is deliberately DB-free — main.py fetches stored rows and
hands plain dicts to build_context(), so the sanitizer is the single chokepoint
between stored third-party data and any prompt.
"""
from backend.agent.context import PromptContext, build_context, scan_stored_text
from backend.agent.parser import (MAX_ATTEMPTS, ParseFailure, extract_json,
                                  parse_contact_edit, parse_transcript)
from backend.agent.router import classify_request
from backend.agent.provider import LLMProvider, get_provider
from backend.agent.errors import ProviderError, ProviderUnavailable
from backend.agent.stub import StubProvider

__all__ = [
    "PromptContext", "build_context", "scan_stored_text",
    "MAX_ATTEMPTS", "ParseFailure", "extract_json", "parse_transcript",
    "parse_contact_edit", "classify_request",
    "LLMProvider", "get_provider", "StubProvider",
    "ProviderError", "ProviderUnavailable",
]
