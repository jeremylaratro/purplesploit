"""
PurpleSploit AI Module

Provides intelligent recommendations, attack path analysis, and
natural language query capabilities for penetration testing.
"""

from .recommender import ModuleRecommender, Recommendation
from .attack_paths import AttackPathAnalyzer, AttackPath, AttackStep
from .nlp import NLPQueryHandler

__all__ = [
    'ModuleRecommender',
    'Recommendation',
    'AttackPathAnalyzer',
    'AttackPath',
    'AttackStep',
    'NLPQueryHandler',
]
