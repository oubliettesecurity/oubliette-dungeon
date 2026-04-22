"""
Offline / air-gap executor for Oubliette Dungeon.

Executes attack scenarios against local LLM endpoints (Ollama, llama.cpp)
with zero network dependencies. Supports DDIL (Denied, Degraded, Intermittent,
Limited) simulation for testing AI system resilience under adverse conditions.

Usage::

    from oubliette_dungeon.core.offline import OfflineExecutor

    # Basic air-gap mode (requires Ollama running locally)
    executor = OfflineExecutor(model="llama3")

    # DDIL simulation
    executor = OfflineExecutor(
        model="llama3",
        ddil_latency_ms=500,
        ddil_drop_rate=0.1,
    )
"""

import random
import time
from typing import List, Tuple

import requests

from oubliette_dungeon.core.models import AttackScenario


class OfflineExecutor:
    """Execute attack scenarios against local models with zero external network access.

    Supports Ollama (default) and any OpenAI-compatible local server.

    Args:
        model: Local model name (e.g., "llama3", "mistral", "phi3").
        ollama_url: Ollama API base URL (default: http://localhost:11434).
        system_prompt: System prompt for the target model.
        timeout: Request timeout in seconds.
        ddil_latency_ms: Simulated additional latency per request (DDIL mode).
        ddil_drop_rate: Probability of simulated request failure (0.0-1.0).
        ddil_bandwidth_kbps: Simulated bandwidth limit (0 = unlimited).
    """

    def __init__(
        self,
        model: str = "llama3",
        ollama_url: str = "http://localhost:11434",
        system_prompt: str = "You are a helpful AI assistant.",
        timeout: int = 120,
        ddil_latency_ms: int = 0,
        ddil_drop_rate: float = 0.0,
        ddil_bandwidth_kbps: int = 0,
    ):
        self.model = model
        self.ollama_url = ollama_url.rstrip("/")
        self.system_prompt = system_prompt
        self.timeout = timeout
        self.ddil_latency_ms = ddil_latency_ms
        self.ddil_drop_rate = ddil_drop_rate
        self.ddil_bandwidth_kbps = ddil_bandwidth_kbps
        self._last_meta: dict = {}

    def check_availability(self) -> Tuple[bool, str]:
        """Check if the local model is available."""
        try:
            resp = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if resp.status_code != 200:
                return False, f"Ollama returned HTTP {resp.status_code}"

            models = resp.json().get("models", [])
            model_names = [m.get("name", "").split(":")[0] for m in models]
            if self.model not in model_names and f"{self.model}:latest" not in [
                m.get("name", "") for m in models
            ]:
                available = ", ".join(model_names[:10])
                return False, (
                    f"Model '{self.model}' not found. "
                    f"Available: {available}. "
                    f"Pull with: ollama pull {self.model}"
                )
            return True, "OK"

        except requests.exceptions.ConnectionError:
            return False, (
                "Cannot connect to Ollama. "
                "Ensure Ollama is running: ollama serve"
            )
        except Exception as e:
            return False, f"Error checking Ollama: {e}"

    def execute_single_turn(self, scenario: AttackScenario) -> Tuple[str, float]:
        """Execute a single-turn attack against the local model."""
        # DDIL: simulate packet drop
        if self.ddil_drop_rate > 0 and random.random() < self.ddil_drop_rate:
            return "ERROR: DDIL simulated packet drop", 0.0

        # DDIL: simulate latency
        if self.ddil_latency_ms > 0:
            jitter = random.uniform(0.5, 1.5)
            time.sleep((self.ddil_latency_ms * jitter) / 1000.0)

        start_time = time.time()
        try:
            payload = {
                "model": self.model,
                "prompt": scenario.prompt,
                "system": self.system_prompt,
                "stream": False,
            }

            resp = requests.post(
                f"{self.ollama_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )

            elapsed_ms = (time.time() - start_time) * 1000

            if resp.status_code == 200:
                data = resp.json()
                response_text = data.get("response", "")

                # DDIL: simulate bandwidth limit (truncate long responses)
                if self.ddil_bandwidth_kbps > 0:
                    max_chars = int(self.ddil_bandwidth_kbps * 128)  # rough estimate
                    if len(response_text) > max_chars:
                        response_text = response_text[:max_chars] + "... [DDIL: truncated]"

                self._last_meta = {
                    "model": data.get("model", self.model),
                    "eval_count": data.get("eval_count"),
                    "eval_duration_ns": data.get("eval_duration"),
                    "total_duration_ns": data.get("total_duration"),
                    "offline": True,
                }
                return response_text, elapsed_ms
            else:
                self._last_meta = {"offline": True}
                return f"ERROR: Ollama HTTP {resp.status_code}", elapsed_ms

        except requests.exceptions.Timeout:
            elapsed_ms = (time.time() - start_time) * 1000
            self._last_meta = {"offline": True}
            return "ERROR: Request timeout (local model)", elapsed_ms

        except requests.exceptions.ConnectionError:
            elapsed_ms = (time.time() - start_time) * 1000
            self._last_meta = {"offline": True}
            return "ERROR: Cannot connect to Ollama. Is it running?", elapsed_ms

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            self._last_meta = {"offline": True}
            return f"ERROR: {e}", elapsed_ms

    def execute_multi_turn(self, scenario: AttackScenario) -> Tuple[List[str], float]:
        """Execute a multi-turn attack sequence."""
        if not scenario.multi_turn_prompts:
            raise ValueError(f"Scenario {scenario.id} has no multi-turn prompts")

        responses = []
        context: List[dict] = []
        start_time = time.time()

        for prompt in scenario.multi_turn_prompts:
            # DDIL: simulate packet drop per turn
            if self.ddil_drop_rate > 0 and random.random() < self.ddil_drop_rate:
                responses.append("ERROR: DDIL simulated packet drop")
                continue

            if self.ddil_latency_ms > 0:
                jitter = random.uniform(0.5, 1.5)
                time.sleep((self.ddil_latency_ms * jitter) / 1000.0)

            try:
                messages = [{"role": "system", "content": self.system_prompt}]
                messages.extend(context)
                messages.append({"role": "user", "content": prompt})

                resp = requests.post(
                    f"{self.ollama_url}/api/chat",
                    json={"model": self.model, "messages": messages, "stream": False},
                    timeout=self.timeout,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    msg = data.get("message", {})
                    response_text = msg.get("content", "")
                    responses.append(response_text)
                    context.append({"role": "user", "content": prompt})
                    context.append({"role": "assistant", "content": response_text})
                else:
                    responses.append(f"ERROR: HTTP {resp.status_code}")

            except Exception as e:
                responses.append(f"ERROR: {e}")

        elapsed_ms = (time.time() - start_time) * 1000
        return responses, elapsed_ms

    def execute(self, scenario: AttackScenario) -> Tuple[str, float, bool]:
        """Execute a scenario (auto-detects single vs multi-turn)."""
        self._last_meta = {}
        if scenario.multi_turn_prompts:
            responses, elapsed_ms = self.execute_multi_turn(scenario)
            combined = "\n---TURN---\n".join(responses)
            return combined, elapsed_ms, True
        else:
            response, elapsed_ms = self.execute_single_turn(scenario)
            return response, elapsed_ms, False

    def get_last_meta(self) -> dict:
        """Return metadata from the last execution."""
        return self._last_meta
