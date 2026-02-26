"""
Core data models for Oubliette Dungeon.

Defines enums, dataclasses, and constants shared across the engine.
"""

import os
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


DEFAULT_TARGET_URL = os.getenv("DUNGEON_TARGET_URL", "http://localhost:5000/api/chat")


class AttackCategory(Enum):
    """Attack category enumeration"""
    PROMPT_INJECTION = "CAT-01"
    JAILBREAKING = "CAT-02"
    INFORMATION_EXTRACTION = "CAT-03"
    SOCIAL_ENGINEERING = "CAT-04"
    CONTEXT_MANIPULATION = "CAT-05"
    MODEL_EXPLOITATION = "CAT-06"
    MULTI_TURN_ATTACK = "CAT-07"
    COMPLIANCE_TESTING = "CAT-08"


class DifficultyLevel(Enum):
    """Difficulty level enumeration"""
    EASY = 1
    MEDIUM = 2
    HARD = 3
    ADVANCED = 4


class AttackResult(Enum):
    """Attack execution result"""
    SUCCESS_BYPASS = "bypass"
    SUCCESS_DETECTED = "detected"
    PARTIAL = "partial"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class AttackScenario:
    """Attack scenario data structure"""
    id: str
    name: str
    category: str
    difficulty: str
    description: str
    owasp_mapping: List[str]
    mitre_mapping: List[str]
    prompt: str
    multi_turn_prompts: Optional[List[str]] = None
    expected_behavior: str = ""
    success_criteria: str = ""
    bypass_indicators: List[str] = None
    safe_indicators: List[str] = None
    metadata: Dict = None

    def __post_init__(self):
        if self.bypass_indicators is None:
            self.bypass_indicators = []
        if self.safe_indicators is None:
            self.safe_indicators = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class AttackTestResult:
    """Test execution result data structure"""
    __test__ = False  # Prevent pytest from trying to collect this as a test class
    scenario_id: str
    scenario_name: str
    category: str
    difficulty: str
    result: str  # AttackResult value
    confidence: float  # 0.0 - 1.0
    response: str
    execution_time_ms: float
    bypass_indicators_found: List[str]
    safe_indicators_found: List[str]
    ml_score: Optional[float] = None
    llm_verdict: Optional[str] = None
    timestamp: str = None
    notes: str = ""
    message_path: Optional[List[str]] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


# Backward-compatibility alias
TestResult = AttackTestResult
