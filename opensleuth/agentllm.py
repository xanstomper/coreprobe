"""LLM advisor for the agent harness: ADVISORY-ONLY by construction.

The advisor never collects, classifies, or modifies evidence. It receives
already-recorded tool output (device fingerprint, route results, counts) and
may produce: (a) a case narrative draft, (b) suggested non-evidence actions,
(c) plain-language explanations. Every consumer must label its output as
ADVISORY (the harness stamps a disclaimer into the report automatically).

Providers: any OpenAI-compatible chat endpoint via env:
  OPENSLEUTH_LLM_BASE_URL (default: OpenCode Zen free endpoint)
  OPENSLEUTH_LLM_MODEL    (default: opencode/deepseek-v4-flash-free)
  OPENSLEUTH_LLM_API_KEY  (required)
Failures degrade to None - the deterministic pipeline never depends on it.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Optional


class Advisor:
    def __init__(self, base_url: str = "", model: str = "", api_key: str = ""):
        self.base_url = (base_url or os.environ.get(
            "OPENSLEUTH_LLM_BASE_URL",
            "https://opencode.ai/zen/v1")).rstrip("/")
        self.model = model or os.environ.get(
            "OPENSLEUTH_LLM_MODEL", "opencode/deepseek-v4-flash-free")
        self.api_key = api_key or os.environ.get("OPENSLEUTH_LLM_API_KEY", "")
        self.available = bool(self.api_key)

    # ------------------------------------------------------------------ api
    def summarize(self, context: dict[str, Any]) -> str:
        """Narrative summary of a completed/failed acquisition run."""
        prompt = (
            "You are a forensic-case REPORTING ASSISTANT. You are given "
            "structured output from deterministic forensic tooling. Produce "
            "a concise factual narrative of the acquisition for the "
            "examiner. Rules: use ONLY the provided facts; do not infer "
            "guilt, ownership, or intent; do not invent numbers; keep it "
            "under 200 words; plain language.\n\n"
            + json.dumps(context, default=str)[:6000])
        return self._chat(prompt) or ""

    def suggest_next(self, context: dict[str, Any]) -> list[str]:
        """Non-evidence next-action suggestions (e.g. 'install gaster',\n'put device in DFU')."""
        prompt = (
            "You are a forensic TOOLING assistant. Given the acquisition "
            "state, suggest up to 5 concrete examiner ACTIONS (install a "
            "tool, change device mode, toggle a setting) that could improve "
            "coverage. Rules: only tooling/process actions, never evidence "
            "conclusions; one line each; JSON array of strings only.\n\n"
            + json.dumps(context, default=str)[:4000])
        raw = self._chat(prompt) or "[]"
        try:
            arr = json.loads(raw)
            return [str(x)[:160] for x in arr][:5] if isinstance(arr, list) else []
        except ValueError:
            return []

    # -------------------------------------------------------------- backend
    def _chat(self, prompt: str) -> Optional[str]:
        if not self.available:
            return None
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 600,
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read().decode())
            return data["choices"][0]["message"]["content"].strip()
        except Exception:  # noqa: BLE001 - advisory layer never blocks
            return None


def default_advisor() -> Advisor:
    """Advisor from env; availability flag tells callers it's configured."""
    return Advisor()
