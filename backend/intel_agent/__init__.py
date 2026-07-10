"""intel_agent: self-contained LLM-security intelligence collection agent.

A Claude Agent SDK-native, loop-engineered, self-evolving intelligence collector.
This package has ZERO dependency on the legacy ``sufe_saads_crewai`` package: it
carries its own schemas, source clients, relevance filter, persistence, and the
agentic loop / playbook memory that make it self-contained and independently
runnable.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
