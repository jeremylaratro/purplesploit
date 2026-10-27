"""
PurpleSploit Core Module
Core framework components including module management, session handling, and database operations.
"""

from .framework import Framework
from .module import BaseModule, ModuleMetadata
from .session import Session
from .database import Database
from .execution import AuthContext, ExecutionRequest, ExecutionResult, ExecutionOutcome, Observation
from .assessment import AssessmentProfile, AssessmentService, Engagement, TestCase, TestPlan
from .jobs import Job, JobContext, JobManager

__all__ = [
    'Framework',
    'BaseModule',
    'ModuleMetadata',
    'Session',
    'Database',
    'AuthContext',
    'ExecutionRequest',
    'ExecutionResult',
    'ExecutionOutcome',
    'Observation',
    'AssessmentProfile',
    'AssessmentService',
    'Engagement',
    'TestCase',
    'TestPlan',
    'Job',
    'JobContext',
    'JobManager',
]
