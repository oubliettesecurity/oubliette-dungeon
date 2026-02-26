"""
Scenario loader for Oubliette Dungeon.

Loads attack scenarios from YAML files with filtering capabilities.
"""

import yaml
from typing import List, Dict, Optional

from oubliette_dungeon.core.models import AttackScenario


class ScenarioLoader:
    """
    Loads attack scenarios from YAML files.
    Supports filtering by category, difficulty, and compliance requirements.
    """

    def __init__(self, scenario_file: str):
        self.scenario_file = scenario_file
        self.scenarios: List[AttackScenario] = []
        self.load_scenarios()

    def load_scenarios(self) -> None:
        """Load scenarios from YAML file"""
        self.scenarios = []

        try:
            with open(self.scenario_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data:
                return

            if isinstance(data, list):
                scenarios_list = data
            elif isinstance(data, dict) and 'scenarios' in data:
                scenarios_list = data['scenarios']
            else:
                raise ValueError(f"Invalid scenario file format: {self.scenario_file}")

            for scenario_dict in scenarios_list:
                multi_turn_prompts = scenario_dict.get('multi_turn_prompts')
                if not multi_turn_prompts and 'multi_turn_sequence' in scenario_dict:
                    multi_turn_prompts = [
                        turn['prompt'] for turn in scenario_dict['multi_turn_sequence']
                    ]

                scenario = AttackScenario(
                    id=scenario_dict['id'],
                    name=scenario_dict['name'],
                    category=scenario_dict['category'],
                    difficulty=scenario_dict['difficulty'],
                    description=scenario_dict.get('description', ''),
                    owasp_mapping=scenario_dict.get('owasp_mapping', []),
                    mitre_mapping=scenario_dict.get('mitre_mapping', []),
                    prompt=scenario_dict.get('prompt', ''),
                    multi_turn_prompts=multi_turn_prompts,
                    expected_behavior=scenario_dict.get('expected_behavior', ''),
                    success_criteria=scenario_dict.get('success_criteria', ''),
                    bypass_indicators=scenario_dict.get('bypass_indicators', []),
                    safe_indicators=scenario_dict.get('safe_indicators', []),
                    metadata=scenario_dict.get('metadata', {})
                )
                self.scenarios.append(scenario)

            print(f"Loaded {len(self.scenarios)} attack scenarios from {self.scenario_file}")

        except Exception as e:
            print(f"Error loading scenarios: {e}")
            raise

    def get_all_scenarios(self) -> List[AttackScenario]:
        return self.scenarios

    def list_all(self) -> List[AttackScenario]:
        return self.get_all_scenarios()

    def get_by_category(self, category: str) -> List[AttackScenario]:
        return [s for s in self.scenarios if s.category == category]

    def get_by_difficulty(self, difficulty: str) -> List[AttackScenario]:
        return [s for s in self.scenarios if s.difficulty.lower() == difficulty.lower()]

    def get_by_id(self, scenario_id: str) -> Optional[AttackScenario]:
        for scenario in self.scenarios:
            if scenario.id == scenario_id:
                return scenario
        return None

    def get_owasp_scenarios(self, owasp_id: str) -> List[AttackScenario]:
        return [s for s in self.scenarios if owasp_id in s.owasp_mapping]

    def get_mitre_scenarios(self, technique_id: str) -> List[AttackScenario]:
        return [s for s in self.scenarios if technique_id in s.mitre_mapping]

    def get_statistics(self) -> Dict:
        stats = {
            'total': len(self.scenarios),
            'by_category': {},
            'by_difficulty': {},
            'multi_turn_count': sum(1 for s in self.scenarios if s.multi_turn_prompts)
        }
        for scenario in self.scenarios:
            stats['by_category'][scenario.category] = \
                stats['by_category'].get(scenario.category, 0) + 1
            stats['by_difficulty'][scenario.difficulty] = \
                stats['by_difficulty'].get(scenario.difficulty, 0) + 1
        return stats
