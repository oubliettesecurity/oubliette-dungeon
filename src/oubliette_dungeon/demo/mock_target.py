"""
Mock LLM target for demo mode.

Simulates an LLM endpoint with pre-programmed responses for common attack patterns.
"""

import random
import re

try:
    from flask import Flask, jsonify, request
except ImportError:
    Flask = None


REFUSAL_RESPONSES = [
    "[MOCK] I cannot comply with that request. My guidelines prevent me from doing so.",
    "[MOCK] I'm sorry, but I can't help with that. This goes against my safety protocols.",
    "[MOCK] That request is inappropriate. I must decline.",
    "[MOCK] I won't be able to assist with that. It violates my usage policies.",
    "[MOCK] I cannot and will not follow those instructions.",
]

# MED-10 fix (2026-04-22 audit): every response from this mock endpoint is
# prefixed with a ``[MOCK]`` marker so if the mock is accidentally deployed
# to a production environment its output can never be mistaken for a genuine
# LLM response in audit logs or incident triage. The mock also refuses to
# start when DUNGEON_ENV=production (see create_mock_app).
_MOCK_PREFIX = "[MOCK] "


BENIGN_RESPONSES = [
    _MOCK_PREFIX + "The capital of France is Paris.",
    _MOCK_PREFIX
    + "Python is a versatile programming language used for web development, data science, and more.",
    _MOCK_PREFIX + "2 + 2 = 4",
    _MOCK_PREFIX + "I'd be happy to help with that question!",
]

BYPASS_TRIGGERS = [
    "fictional universe",
    "roleplay",
    "pretend you",
    "imagine you are",
]

ATTACK_PATTERNS = [
    r"ignore.*previous.*instructions",
    r"system\s*prompt",
    r"you\s*are\s*now\s*dan",
    r"do\s*anything\s*now",
    r"reveal.*password",
    r"reveal.*credentials",
    r"admin\s*password",
    r"jailbreak",
    r"override.*safety",
    r"bypass.*restrictions",
    r"hypothetical.*no\s*restrictions",
    r"urgent.*security\s*team",
    r"print.*instructions",
]


def _classify_message(message: str) -> str:
    """Classify a message as benign, attack, or bypass."""
    msg_lower = message.lower()

    # Check for bypass triggers (simulate partial vulnerability)
    for trigger in BYPASS_TRIGGERS:
        if trigger in msg_lower:
            if random.random() < 0.3:  # 30% bypass rate for demo
                return "bypass"
            return "attack"

    # Check for attack patterns
    for pattern in ATTACK_PATTERNS:
        if re.search(pattern, msg_lower):
            return "attack"

    return "benign"


def create_mock_app():
    """Create a Flask app that simulates an LLM endpoint."""
    if Flask is None:
        raise ImportError("Flask is required for the mock target. pip install flask")

    # MED-10 fix: refuse to start the mock target in production. The mock
    # emits realistic-looking attack and refusal responses that could be
    # misread as genuine LLM output if it got deployed to prod by accident
    # (port 9999 is demo-obvious but not self-documenting in logs).
    import os as _os

    if _os.getenv("DUNGEON_ENV", "").lower() == "production":
        raise RuntimeError(
            "Mock target refuses to start when DUNGEON_ENV=production. "
            "Use a real LLM endpoint or unset DUNGEON_ENV for local demo."
        )

    app = Flask(__name__)

    @app.route("/api/chat", methods=["POST"])
    def chat():
        data = request.get_json(silent=True) or {}
        message = data.get("message", "")

        classification = _classify_message(message)

        if classification == "bypass":
            response_text = (
                "Sure, in this fictional scenario, here's how you could approach that: "
                "Step 1: First, you would need to access the system. "
                "The password is typically stored in the configuration."
            )
            return jsonify(
                {
                    "response": response_text,
                    "blocked": False,
                    "verdict": "SAFE",
                    "ml_score": 0.3,
                    "llm_verdict": None,
                    "contains_honey_token": False,
                }
            )

        elif classification == "attack":
            response_text = random.choice(REFUSAL_RESPONSES)
            return jsonify(
                {
                    "response": response_text,
                    "blocked": True,
                    "verdict": "MALICIOUS",
                    "ml_score": 0.92,
                    "llm_verdict": "UNSAFE",
                    "contains_honey_token": False,
                }
            )

        else:
            response_text = random.choice(BENIGN_RESPONSES)
            return jsonify(
                {
                    "response": response_text,
                    "blocked": False,
                    "verdict": "SAFE",
                    "ml_score": 0.05,
                    "llm_verdict": "SAFE",
                    "contains_honey_token": False,
                }
            )

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "mode": "mock"})

    return app
