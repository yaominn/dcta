"""
Agent-layer error types.

ProviderError is raised when the *provider* fails — bad credentials, a rate
limit, a timeout, a transport error, an empty response. It is deliberately
distinct from the ValueError/ValidationError family, which means "the model
answered, but the answer was not a valid plan".

The distinction matters at two points:

  - parse_transcript retries a ProviderError (transient failures are worth a
    second attempt) but does not feed it back into the prompt — there is no
    model output to correct.
  - /api/plan maps it to 502 Bad Gateway, not 500. An upstream outage is not
    an internal error, and a stack trace is not a useful response to the user.
"""
from __future__ import annotations


class ProviderError(RuntimeError):
    """The LLM provider could not be reached, or returned nothing usable."""


class ProviderUnavailable(RuntimeError):
    """Every attempt failed because the provider could not be reached.

    Distinct from ParseFailure, which means the model answered and the answers
    were not valid plans. The endpoint maps this to 502 (upstream problem) and
    ParseFailure to 422 (we could not build a draft) — different causes,
    different fixes, and neither is a 500.
    """

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))
