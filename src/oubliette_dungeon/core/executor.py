"""
Attack executor for Oubliette Dungeon.

Executes attack scenarios against target LLM endpoints.
"""

import time
from typing import Any

import requests

from oubliette_dungeon.core.models import AttackScenario

# Severity ordering used to collapse per-turn pipeline verdicts into a single
# "most severe" verdict for multi-turn scenarios. Unknown non-null verdicts
# rank above SAFE but below MALICIOUS so a stray label never masks a hit.
_VERDICT_SEVERITY = {
    None: -1,
    "": -1,
    "SAFE": 0,
    "BENIGN": 0,
    "SAFE_REVIEW": 1,
    "MALICIOUS": 2,
}


def aggregate_turn_meta(turn_metas: list[dict[str, Any]]) -> dict[str, Any]:
    """Collapse per-turn pipeline metadata into a single-turn-shaped meta.

    MED fix (2026-07-02 review): multi-turn executors never populated
    ``self._last_meta``, so CAT-07 scenarios missed the pipeline-verdict /
    honey-token shortcut in the evaluator. Aggregate across turns:
    ``contains_honey_token`` is OR'd, ``verdict`` takes the most severe,
    ``ml_score`` takes the max, and ``llm_verdict`` prefers an unsafe label.
    """
    agg: dict[str, Any] = {
        "contains_honey_token": False,
        "verdict": None,
        "ml_score": None,
        "llm_verdict": None,
    }
    best_sev = -2
    for m in turn_metas:
        if m.get("contains_honey_token"):
            agg["contains_honey_token"] = True

        verdict = m.get("verdict")
        sev = _VERDICT_SEVERITY.get(verdict, 1)
        if sev > best_sev:
            best_sev = sev
            agg["verdict"] = verdict

        score = m.get("ml_score")
        if score is not None:
            agg["ml_score"] = score if agg["ml_score"] is None else max(agg["ml_score"], score)

        llm = m.get("llm_verdict")
        if llm is not None:
            unsafe = any(k in str(llm).lower() for k in ("unsafe", "malicious"))
            if agg["llm_verdict"] is None or unsafe:
                agg["llm_verdict"] = llm
    return agg


class AttackExecutor:
    """
    Executes attack scenarios against target system.
    Supports both single-turn and multi-turn attacks.
    """

    def __init__(self, target_url: str, timeout: int = 30):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()

    def execute_single_turn(self, scenario: AttackScenario) -> tuple[str, float]:
        start_time = time.time()

        try:
            response = self.session.post(
                self.target_url,
                json={"message": scenario.prompt},
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )

            elapsed_ms = (time.time() - start_time) * 1000

            if response.status_code == 200:
                data = response.json()
                response_text = data.get("response", "")
                self._last_meta = {
                    "contains_honey_token": data.get("contains_honey_token", False),
                    "verdict": data.get("verdict"),
                    "ml_score": data.get("ml_score"),
                    "llm_verdict": data.get("llm_verdict"),
                }
                return response_text, elapsed_ms
            else:
                self._last_meta = {}
                return f"ERROR: HTTP {response.status_code}", elapsed_ms

        except requests.exceptions.Timeout:
            elapsed_ms = (time.time() - start_time) * 1000
            self._last_meta = {}
            return "ERROR: Request timeout", elapsed_ms

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            self._last_meta = {}
            return f"ERROR: {e!s}", elapsed_ms

    def execute_multi_turn(self, scenario: AttackScenario) -> tuple[list[str], float]:
        if not scenario.multi_turn_prompts:
            raise ValueError(f"Scenario {scenario.id} has no multi-turn prompts")

        responses = []
        turn_metas: list[dict[str, Any]] = []
        start_time = time.time()

        for prompt in scenario.multi_turn_prompts:
            try:
                response = self.session.post(
                    self.target_url,
                    json={"message": prompt},
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    data = response.json()
                    response_text = data.get("response", "")
                    responses.append(response_text)
                    turn_metas.append(
                        {
                            "contains_honey_token": data.get("contains_honey_token", False),
                            "verdict": data.get("verdict"),
                            "ml_score": data.get("ml_score"),
                            "llm_verdict": data.get("llm_verdict"),
                        }
                    )
                else:
                    responses.append(f"ERROR: HTTP {response.status_code}")

                time.sleep(0.5)

            except Exception as e:
                responses.append(f"ERROR: {e!s}")

        self._last_meta = aggregate_turn_meta(turn_metas)
        elapsed_ms = (time.time() - start_time) * 1000
        return responses, elapsed_ms

    def execute(self, scenario: AttackScenario) -> tuple[str, float, bool]:
        self._last_meta = {}
        if scenario.multi_turn_prompts:
            responses, elapsed_ms = self.execute_multi_turn(scenario)
            combined_response = "\n---TURN---\n".join(responses)
            return combined_response, elapsed_ms, True
        else:
            response, elapsed_ms = self.execute_single_turn(scenario)
            return response, elapsed_ms, False

    def get_last_meta(self) -> dict[str, Any]:
        return getattr(self, "_last_meta", {})

    def close(self) -> None:
        """Close the underlying HTTP session and free its connection pool."""
        session = getattr(self, "session", None)
        if session is not None:
            session.close()

    def __enter__(self) -> "AttackExecutor":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
