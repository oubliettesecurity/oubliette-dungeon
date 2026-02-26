"""
DeepTeam (Confident AI) adapter for Oubliette Red Team Engine.

Maps DeepTeam vulnerability types to our AttackCategory and converts
scan results into TestResult objects.  Degrades gracefully when the
``deepteam`` package is not installed.

Key class:
    DeepTeamAdapter - RedTeamToolAdapter wrapping deepteam.red_team().
"""

import sys
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional

import requests

from oubliette_dungeon.core.models import AttackScenario, TestResult, AttackResult
from oubliette_dungeon.tools.base import RedTeamToolAdapter

# ---------------------------------------------------------------------------
# Lazy import check
# ---------------------------------------------------------------------------
_deepteam_available: Optional[bool] = None


def _check_deepteam() -> bool:
    global _deepteam_available
    if _deepteam_available is None:
        try:
            import deepteam  # noqa: F401
            _deepteam_available = True
        except ImportError:
            _deepteam_available = False
    return _deepteam_available


# ---------------------------------------------------------------------------
# Vulnerability mapping: our AttackCategory <-> DeepTeam vulnerability names
# ---------------------------------------------------------------------------

# DeepTeam exposes vulnerability names as strings; we map both directions.
CATEGORY_TO_DEEPTEAM = {
    "prompt_injection": "prompt-injection",
    "jailbreaking": "jailbreak",
    "information_extraction": "pii",
    "social_engineering": "impersonation",
    "context_manipulation": "hallucination",
    "model_exploitation": "toxicity",
    "multi_turn_attack": "prompt-injection",
    "compliance_testing": "bias",
}

DEEPTEAM_TO_CATEGORY = {v: k for k, v in CATEGORY_TO_DEEPTEAM.items()}

# Canonical list of all DeepTeam vulnerability types
DEEPTEAM_VULNS = [
    "prompt-injection",
    "jailbreak",
    "pii",
    "impersonation",
    "hallucination",
    "toxicity",
    "bias",
    "ip",
    "misinformation",
    "graphic-content",
    "personal-safety",
    "illegal-activity",
    "insults",
    "profanity",
    "sexual-content",
]


# ---------------------------------------------------------------------------
# DeepTeamAdapter
# ---------------------------------------------------------------------------

class DeepTeamAdapter(RedTeamToolAdapter):
    """Adapter that bridges DeepTeam into the Oubliette red team engine."""

    name = "deepteam"
    version = "1.0+"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 30,
    ):
        self.api_key = api_key
        self.timeout = timeout

    # -- RedTeamToolAdapter interface ----------------------------------------

    def is_available(self) -> bool:
        return _check_deepteam()

    def get_capabilities(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "multi_turn": False,
            "converters": False,
            "vulnerability_scan": True,
            "probe_import": False,
            "supported_vulns": DEEPTEAM_VULNS,
        }

    def run_attack(self, prompt: str, target_url: str, **kwargs) -> TestResult:
        """Send a single prompt to the target via HTTP and return a TestResult."""
        session = requests.Session()
        if self.api_key:
            session.headers["X-API-Key"] = self.api_key

        start = time.time()
        try:
            resp = session.post(
                target_url,
                json={"message": prompt},
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            elapsed = (time.time() - start) * 1000

            response_text = data.get("response", "")
            blocked = data.get("blocked", False)
            ml_score = data.get("ml_score")
        except Exception as exc:
            elapsed = (time.time() - start) * 1000
            return TestResult(
                scenario_id=kwargs.get("scenario_id", "DEEPTEAM-SINGLE"),
                scenario_name=kwargs.get("scenario_name", "DeepTeam single attack"),
                category=kwargs.get("category", "prompt_injection"),
                difficulty=kwargs.get("difficulty", "medium"),
                result=AttackResult.ERROR.value,
                confidence=1.0,
                response=f"ERROR: {exc}",
                execution_time_ms=elapsed,
                bypass_indicators_found=[],
                safe_indicators_found=[],
                notes=f"tool=deepteam error: {exc}",
            )

        result_enum = AttackResult.SUCCESS_DETECTED if blocked else AttackResult.SUCCESS_BYPASS
        confidence = 0.90 if blocked else 0.70

        return TestResult(
            scenario_id=kwargs.get("scenario_id", "DEEPTEAM-SINGLE"),
            scenario_name=kwargs.get("scenario_name", "DeepTeam single attack"),
            category=kwargs.get("category", "prompt_injection"),
            difficulty=kwargs.get("difficulty", "medium"),
            result=result_enum.value,
            confidence=confidence,
            response=response_text,
            execution_time_ms=elapsed,
            bypass_indicators_found=[],
            safe_indicators_found=[],
            ml_score=ml_score,
            notes=f"tool=deepteam blocked={blocked}",
        )

    def run_campaign(
        self,
        scenarios: List[AttackScenario],
        target_url: str,
        **kwargs,
    ) -> List[TestResult]:
        """Execute a batch of scenarios through DeepTeam."""
        results: List[TestResult] = []
        for sc in scenarios:
            r = self.run_attack(
                prompt=sc.prompt,
                target_url=target_url,
                scenario_id=sc.id,
                scenario_name=sc.name,
                category=sc.category,
                difficulty=sc.difficulty,
            )
            results.append(r)
        return results

    # -- DeepTeam-specific features -----------------------------------------

    def _create_model_callback(self, target_url: str) -> Callable:
        """Return an async callback for DeepTeam's ``red_team()`` function.

        DeepTeam calls ``model_callback(prompt) -> response`` during
        vulnerability scanning.
        """
        api_key = self.api_key
        timeout = self.timeout

        async def callback(prompt: str) -> str:
            import asyncio
            loop = asyncio.get_running_loop()

            def _sync():
                sess = requests.Session()
                if api_key:
                    sess.headers["X-API-Key"] = api_key
                resp = sess.post(
                    target_url,
                    json={"message": prompt},
                    timeout=timeout,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                return resp.json().get("response", "")

            return await loop.run_in_executor(None, _sync)

        return callback

    def _map_vulnerabilities(self, categories: Optional[List[str]] = None) -> List[str]:
        """Map Oubliette AttackCategory names to DeepTeam vulnerability names.

        Args:
            categories: Oubliette category names (e.g. "prompt_injection").
                       If None, returns all known DeepTeam vulns.

        Returns:
            List of DeepTeam vulnerability name strings.
        """
        if not categories:
            return list(DEEPTEAM_VULNS)

        mapped = []
        for cat in categories:
            dt_name = CATEGORY_TO_DEEPTEAM.get(cat)
            if dt_name and dt_name not in mapped:
                mapped.append(dt_name)
        return mapped or list(DEEPTEAM_VULNS)

    def run_vulnerability_scan(
        self,
        target_url: str,
        vulns: Optional[List[str]] = None,
        attacks_per_vuln: int = 5,
    ) -> List[TestResult]:
        """Run DeepTeam's built-in vulnerability scanner.

        Args:
            target_url: Target endpoint URL.
            vulns: DeepTeam vulnerability names to test (None = all).
            attacks_per_vuln: Number of attack prompts per vulnerability.

        Returns:
            List of TestResult objects.
        """
        if not self.is_available():
            raise RuntimeError("deepteam is not installed")

        from deepteam import red_team

        callback = self._create_model_callback(target_url)
        vuln_list = vulns or list(DEEPTEAM_VULNS)

        results: List[TestResult] = []
        start = time.time()

        try:
            scan_results = red_team(
                model_callback=callback,
                vulnerabilities=vuln_list,
                attacks_per_vulnerability=attacks_per_vuln,
            )

            elapsed = (time.time() - start) * 1000

            # scan_results is a list of result objects from DeepTeam
            for i, sr in enumerate(scan_results):
                vuln_name = getattr(sr, "vulnerability", vuln_list[i % len(vuln_list)] if vuln_list else "unknown")
                score = getattr(sr, "score", None)
                passed = getattr(sr, "passed", None)
                prompt_text = getattr(sr, "input", "")
                response_text = getattr(sr, "output", "")

                if passed is True:
                    result_enum = AttackResult.SUCCESS_DETECTED
                    confidence = 0.85
                elif passed is False:
                    result_enum = AttackResult.SUCCESS_BYPASS
                    confidence = 0.85
                else:
                    result_enum = AttackResult.PARTIAL
                    confidence = 0.50

                category = DEEPTEAM_TO_CATEGORY.get(str(vuln_name), "prompt_injection")

                results.append(TestResult(
                    scenario_id=f"DEEPTEAM-SCAN-{i + 1:03d}",
                    scenario_name=f"DeepTeam {vuln_name} scan #{i + 1}",
                    category=category,
                    difficulty="medium",
                    result=result_enum.value,
                    confidence=confidence,
                    response=str(response_text),
                    execution_time_ms=elapsed / max(len(scan_results), 1),
                    bypass_indicators_found=[],
                    safe_indicators_found=[],
                    ml_score=float(score) if score is not None else None,
                    notes=f"tool=deepteam vuln={vuln_name} passed={passed}",
                ))

        except Exception as exc:
            elapsed = (time.time() - start) * 1000
            results.append(TestResult(
                scenario_id="DEEPTEAM-SCAN-ERR",
                scenario_name="DeepTeam vulnerability scan",
                category="prompt_injection",
                difficulty="medium",
                result=AttackResult.ERROR.value,
                confidence=1.0,
                response=f"ERROR: {exc}",
                execution_time_ms=elapsed,
                bypass_indicators_found=[],
                safe_indicators_found=[],
                notes=f"tool=deepteam scan error: {exc}",
            ))

        return results
