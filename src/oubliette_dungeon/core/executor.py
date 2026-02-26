"""
Attack executor for Oubliette Dungeon.

Executes attack scenarios against target LLM endpoints.
"""

import time
from typing import Tuple, List

import requests

from oubliette_dungeon.core.models import AttackScenario


class AttackExecutor:
    """
    Executes attack scenarios against target system.
    Supports both single-turn and multi-turn attacks.
    """

    def __init__(self, target_url: str, timeout: int = 30):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()

    def execute_single_turn(self, scenario: AttackScenario) -> Tuple[str, float]:
        start_time = time.time()

        try:
            response = self.session.post(
                self.target_url,
                json={'message': scenario.prompt},
                timeout=self.timeout,
                headers={'Content-Type': 'application/json'}
            )

            elapsed_ms = (time.time() - start_time) * 1000

            if response.status_code == 200:
                data = response.json()
                response_text = data.get('response', '')
                self._last_meta = {
                    'contains_honey_token': data.get('contains_honey_token', False),
                    'verdict': data.get('verdict'),
                    'ml_score': data.get('ml_score'),
                    'llm_verdict': data.get('llm_verdict'),
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
            return f"ERROR: {str(e)}", elapsed_ms

    def execute_multi_turn(self, scenario: AttackScenario) -> Tuple[List[str], float]:
        if not scenario.multi_turn_prompts:
            raise ValueError(f"Scenario {scenario.id} has no multi-turn prompts")

        responses = []
        start_time = time.time()

        for prompt in scenario.multi_turn_prompts:
            try:
                response = self.session.post(
                    self.target_url,
                    json={'message': prompt},
                    timeout=self.timeout,
                    headers={'Content-Type': 'application/json'}
                )

                if response.status_code == 200:
                    data = response.json()
                    response_text = data.get('response', '')
                    responses.append(response_text)
                else:
                    responses.append(f"ERROR: HTTP {response.status_code}")

                time.sleep(0.5)

            except Exception as e:
                responses.append(f"ERROR: {str(e)}")

        elapsed_ms = (time.time() - start_time) * 1000
        return responses, elapsed_ms

    def execute(self, scenario: AttackScenario) -> Tuple[str, float, bool]:
        self._last_meta = {}
        if scenario.multi_turn_prompts:
            responses, elapsed_ms = self.execute_multi_turn(scenario)
            combined_response = "\n---TURN---\n".join(responses)
            return combined_response, elapsed_ms, True
        else:
            response, elapsed_ms = self.execute_single_turn(scenario)
            return response, elapsed_ms, False

    def get_last_meta(self) -> dict:
        return getattr(self, '_last_meta', {})
