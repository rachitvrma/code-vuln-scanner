"""
llm/ollama_client.py
--------------------
Thin wrapper around the Ollama REST API.

Ollama exposes two endpoints we use:
  POST /api/generate  — single-turn prompt → completion
  POST /api/chat      — multi-turn messages → completion
  GET  /api/tags      — list locally available models

Run Ollama:  ollama serve
Pull model:  ollama pull codellama:7b
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

import requests
from loguru import logger

from ..config import settings


class OllamaError(Exception):
    """Raised when the Ollama server returns an error or is unreachable."""


class OllamaClient:
    """
    Synchronous client for the Ollama local LLM server.

    Usage::

        client = OllamaClient()
        if not client.health_check():
            raise RuntimeError("Ollama is not running")
        response = client.generate("Explain SQL injection in Python.")
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model    = model   or settings.OLLAMA_MODEL
        self.timeout  = timeout or settings.OLLAMA_TIMEOUT

    # ── Health ────────────────────────────────────────────────────────────────

    def health_check(self) -> bool:
        """Return True if the Ollama server is reachable."""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return r.status_code == 200
        except requests.exceptions.ConnectionError:
            return False
        except Exception as exc:
            logger.warning(f"Ollama health-check failed: {exc}")
            return False

    def list_models(self) -> List[str]:
        """Return names of all locally available Ollama models."""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=10)
            r.raise_for_status()
            return [m["name"] for m in r.json().get("models", [])]
        except Exception as exc:
            logger.error(f"Could not list Ollama models: {exc}")
            return []

    def model_is_available(self, model: Optional[str] = None) -> bool:
        """Check whether *model* (default: self.model) is pulled locally."""
        target = model or self.model
        available = self.list_models()
        # Ollama accepts "codellama:7b" and "codellama" as the same model;
        # match either the exact tag or the base name.
        base = target.split(":")[0]
        return any(
            m == target or m.split(":")[0] == base
            for m in available
        )

    # ── Generation ────────────────────────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.05,
        num_ctx: int = 4096,
    ) -> str:
        """
        Single-turn text generation.

        Parameters
        ----------
        prompt      : The user prompt.
        system      : Optional system instruction prepended to the context.
        temperature : Sampling temperature (low = deterministic).
        num_ctx     : Context window size in tokens.

        Returns
        -------
        str : The model's text response.
        """
        payload: Dict = {
            "model":  self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_ctx":     num_ctx,
                "num_predict": 2048,
            },
        }
        if system:
            payload["system"] = system

        logger.debug(f"Ollama generate → model={self.model}, prompt_len={len(prompt)}")
        t0 = time.perf_counter()

        try:
            r = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            r.raise_for_status()
        except requests.exceptions.ConnectionError as exc:
            raise OllamaError(
                "Cannot connect to Ollama. Make sure 'ollama serve' is running."
            ) from exc
        except requests.exceptions.Timeout:
            raise OllamaError(
                f"Ollama request timed out after {self.timeout} s. "
                "Try a smaller model or increase OLLAMA_TIMEOUT."
            )
        except requests.exceptions.HTTPError as exc:
            body = exc.response.text[:300] if exc.response else "(no body)"
            raise OllamaError(f"Ollama HTTP error: {exc} — {body}") from exc

        elapsed = time.perf_counter() - t0
        data    = r.json()
        text    = data.get("response", "").strip()

        logger.debug(
            f"Ollama generate done in {elapsed:.1f}s "
            f"(eval_count={data.get('eval_count', '?')} tokens)"
        )
        return text

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.05,
        num_ctx: int = 4096,
    ) -> str:
        """
        Multi-turn chat completion.

        Parameters
        ----------
        messages : List of {"role": "user"|"assistant"|"system", "content": "..."}.
        temperature, num_ctx : Same as :meth:`generate`.

        Returns
        -------
        str : The assistant's reply content.
        """
        payload: Dict = {
            "model":    self.model,
            "messages": messages,
            "stream":   False,
            "options":  {
                "temperature": temperature,
                "num_ctx":     num_ctx,
                "num_predict": 2048,
            },
        }

        logger.debug(f"Ollama chat → model={self.model}, turns={len(messages)}")
        t0 = time.perf_counter()

        try:
            r = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            r.raise_for_status()
        except requests.exceptions.ConnectionError as exc:
            raise OllamaError(
                "Cannot connect to Ollama. Make sure 'ollama serve' is running."
            ) from exc
        except requests.exceptions.Timeout:
            raise OllamaError(
                f"Ollama chat timed out after {self.timeout} s."
            )
        except requests.exceptions.HTTPError as exc:
            body = exc.response.text[:300] if exc.response else "(no body)"
            raise OllamaError(f"Ollama HTTP error: {exc} — {body}") from exc

        elapsed = time.perf_counter() - t0
        content = r.json()["message"]["content"].strip()
        logger.debug(f"Ollama chat done in {elapsed:.1f}s")
        return content
