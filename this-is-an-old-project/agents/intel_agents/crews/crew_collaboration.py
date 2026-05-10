from __future__ import annotations

from collections import defaultdict
from importlib import import_module
import logging
import os
from typing import Any

from ..tools.llm_client_factory import LlmProfile, resolve_model_pool

_LOGGER = logging.getLogger(__name__)


class CrewCollaborationService:
    """Optional CrewAI collaboration layer for collection coordination.

    When CrewAI is installed, this service can create a lightweight coordinator flow to
    assign focus to source plans. When CrewAI is unavailable, it returns a deterministic
    fallback summary so the rest of the orchestration path remains stable.
    """

    def __init__(self) -> None:
        self._crewai_available = self._detect_crewai()

    @property
    def crewai_available(self) -> bool:
        return self._crewai_available

    def coordinate(
        self,
        source_plans: list[dict[str, Any]],
        *,
        run_mode: str,
        trace_id: str,
        planning_audits: list[dict[str, Any]] | None = None,
        reflection_audits: list[dict[str, Any]] | None = None,
        llm_model: str | None = None,
        llm_temperature: float = 0.0,
        llm_runtime_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not source_plans:
            return {
                "engine": "fallback",
                "crewai_available": self.crewai_available,
                "collector_agents": [],
                "assignments": [],
                "summary": "No source plans to coordinate.",
                "llm_profile_id": None,
                "llm_profile": None,
                "llm_model": None,
                "llm_route_labels": [],
            }

        crewai_profile, route_meta = self._resolve_crewai_profile(
            llm_model=llm_model,
            llm_runtime_config=llm_runtime_config,
        )

        if self.crewai_available:
            try:
                return self._coordinate_with_crewai(
                    source_plans,
                    run_mode=run_mode,
                    trace_id=trace_id,
                    planning_audits=planning_audits,
                    reflection_audits=reflection_audits,
                    crewai_profile=crewai_profile,
                    route_meta=route_meta,
                    llm_temperature=llm_temperature,
                )
            except Exception as exc:
                return self._fallback_plan(
                    source_plans,
                    planning_audits=planning_audits,
                    reflection_audits=reflection_audits,
                    summary=f"CrewAI coordination failed, fallback engaged: {exc}",
                    crewai_profile=crewai_profile,
                    route_meta=route_meta,
                )

        return self._fallback_plan(
            source_plans,
            planning_audits=planning_audits,
            reflection_audits=reflection_audits,
            summary="CrewAI not installed; using deterministic coordination fallback.",
            crewai_profile=crewai_profile,
            route_meta=route_meta,
        )

    def _coordinate_with_crewai(
        self,
        source_plans: list[dict[str, Any]],
        *,
        run_mode: str,
        trace_id: str,
        planning_audits: list[dict[str, Any]] | None,
        reflection_audits: list[dict[str, Any]] | None,
        crewai_profile: LlmProfile | None,
        route_meta: dict[str, Any],
        llm_temperature: float,
    ) -> dict[str, Any]:
        crewai_module = import_module("crewai")
        Agent = crewai_module.Agent
        Crew = crewai_module.Crew
        LLM = crewai_module.LLM
        Process = crewai_module.Process
        Task = crewai_module.Task

        collector_blueprints = self._collector_blueprints(
            source_plans,
            planning_audits=planning_audits,
            reflection_audits=reflection_audits,
        )
        crewai_llm = None
        if crewai_profile is not None:
            crewai_llm = LLM(
                model=crewai_profile.model,
                temperature=llm_temperature,
                base_url=crewai_profile.base_url,
                api_base=crewai_profile.base_url,
                api_key=crewai_profile.api_key,
            )
            _LOGGER.warning(
                "wp11_crewai_profile_selected %s",
                {
                    "trace_id": trace_id,
                    "profile_id": crewai_profile.profile_id,
                    "profile": crewai_profile.profile,
                    "model": crewai_profile.model,
                    "base_url": crewai_profile.base_url,
                    "route_labels": list(route_meta.get("selected_route_labels", [])),
                },
            )
        else:
            _LOGGER.warning(
                "wp11_crewai_profile_unresolved %s",
                {
                    "trace_id": trace_id,
                    "message": "CrewAI coordination fell back to CrewAI/OpenAI defaults outside the WP11 profile pool.",
                },
            )
        coordinator = Agent(
            role="WP1-1 Collection Coordinator",
            goal="Assign collection focus and verify source coverage for the current run.",
            backstory=(
                "You coordinate multiple collection specialists, ensuring each source plan "
                "has a clear purpose, target query, and execution priority."
            ),
            verbose=False,
            allow_delegation=False,
            llm=crewai_llm,
        )
        specialist_agents = [
            Agent(
                role=blueprint["agent_name"],
                goal=blueprint["goal"],
                backstory=blueprint["backstory"],
                verbose=False,
                allow_delegation=False,
                llm=crewai_llm,
            )
            for blueprint in collector_blueprints
        ]
        tasks = []
        for blueprint, agent in zip(collector_blueprints, specialist_agents):
            tasks.append(
                Task(
                    description=(
                        "Review and prepare the following source plans for execution.\n"
                        f"run_mode={run_mode}\ntrace_id={trace_id}\n"
                        f"collector_role={blueprint['collector_role']}\n"
                        f"assigned_sources={blueprint['source_names']}\n"
                        f"execution_hints={blueprint['execution_hints']}\n"
                        f"plans={blueprint['plans']}"
                    ),
                    expected_output=(
                        "A concise execution note covering query intent, priority, and any "
                        "source-specific caveats for this collector."
                    ),
                    agent=agent,
                )
            )
        crew = Crew(
            agents=[coordinator, *specialist_agents],
            tasks=tasks,
            process=Process.sequential,
            verbose=False,
        )
        try:
            result = crew.kickoff()
        except Exception as exc:
            if crewai_profile is not None:
                failure_payload = {
                    "trace_id": trace_id,
                    "profile_id": crewai_profile.profile_id,
                    "profile": crewai_profile.profile,
                    "model": crewai_profile.model,
                    "base_url": crewai_profile.base_url,
                    "route_labels": list(route_meta.get("selected_route_labels", [])),
                    "error_type": exc.__class__.__name__,
                    "error": str(exc)[:300],
                }
                _LOGGER.error("wp11_crewai_profile_failed %s", failure_payload)
                raise RuntimeError(
                    "CrewAI coordination failed via profile "
                    f"{crewai_profile.profile_id}/{crewai_profile.profile} "
                    f"model={crewai_profile.model}: {exc}"
                ) from exc
            _LOGGER.error(
                "wp11_crewai_default_failed %s",
                {
                    "trace_id": trace_id,
                    "error_type": exc.__class__.__name__,
                    "error": str(exc)[:300],
                },
            )
            raise
        return {
            "engine": "crewai",
            "crewai_available": True,
            "collector_agents": self._collector_agents_payload(
                collector_blueprints, active_engine="crewai"
            ),
            "assignments": self._fallback_assignments(
                source_plans,
                planning_audits=planning_audits,
                reflection_audits=reflection_audits,
            ),
            "summary": str(result),
            "llm_profile_id": crewai_profile.profile_id if crewai_profile else None,
            "llm_profile": crewai_profile.profile if crewai_profile else None,
            "llm_model": crewai_profile.model if crewai_profile else None,
            "llm_route_labels": list(route_meta.get("selected_route_labels", [])),
        }

    def _fallback_plan(
        self,
        source_plans: list[dict[str, Any]],
        *,
        planning_audits: list[dict[str, Any]] | None,
        reflection_audits: list[dict[str, Any]] | None,
        summary: str,
        crewai_profile: LlmProfile | None,
        route_meta: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "engine": "fallback",
            "crewai_available": self.crewai_available,
            "collector_agents": self._collector_agents_payload(
                self._collector_blueprints(
                    source_plans,
                    planning_audits=planning_audits,
                    reflection_audits=reflection_audits,
                ),
                active_engine="fallback",
            ),
            "assignments": self._fallback_assignments(
                source_plans,
                planning_audits=planning_audits,
                reflection_audits=reflection_audits,
            ),
            "summary": summary,
            "llm_profile_id": crewai_profile.profile_id if crewai_profile else None,
            "llm_profile": crewai_profile.profile if crewai_profile else None,
            "llm_model": crewai_profile.model if crewai_profile else None,
            "llm_route_labels": list(route_meta.get("selected_route_labels", [])),
        }

    @staticmethod
    def _resolve_crewai_profile(
        *,
        llm_model: str | None,
        llm_runtime_config: dict[str, Any] | None,
    ) -> tuple[LlmProfile | None, dict[str, Any]]:
        runtime_config = llm_runtime_config or {}
        profiles, route_meta = resolve_model_pool(
            task_name="planning",
            default_model=llm_model,
            base_url=os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL"),
            api_key=os.getenv("OPENAI_API_KEY"),
            runtime_config=runtime_config,
        )
        for profile in profiles:
            if profile.api_key or profile.base_url:
                return profile, route_meta
        return None, route_meta

    @staticmethod
    def _fallback_assignments(
        source_plans: list[dict[str, Any]],
        *,
        planning_audits: list[dict[str, Any]] | None,
        reflection_audits: list[dict[str, Any]] | None,
    ) -> list[dict[str, Any]]:
        assignments: list[dict[str, Any]] = []
        latest_planning = (planning_audits or [])[-1] if planning_audits else {}
        latest_reflection = (reflection_audits or [])[-1] if reflection_audits else {}
        for plan in source_plans:
            collector_role = _collector_role_for(plan.get("source_type", "structured"))
            execution_profile, source_hint = _execution_profile_for(plan)
            assignments.append(
                {
                    "source_name": plan["source_name"],
                    "query_count": len(plan.get("queries", [])),
                    "query_intent": plan.get("query_intent", "broad_recall"),
                    "priority": plan.get("priority", 0.0),
                    "collector_role": collector_role,
                    "collector_agent": f"{collector_role}Agent",
                    "execution_profile": execution_profile,
                    "source_specific_hint": source_hint,
                    "execution_notes": _build_execution_notes(
                        plan,
                        planning_audit=latest_planning,
                        reflection_audit=latest_reflection,
                    ),
                    "planning_signal": latest_planning.get("strategy_executed"),
                    "reflection_signal": latest_reflection.get("diagnosis"),
                }
            )
        return assignments

    @classmethod
    def _collector_blueprints(
        cls,
        source_plans: list[dict[str, Any]],
        *,
        planning_audits: list[dict[str, Any]] | None,
        reflection_audits: list[dict[str, Any]] | None,
    ) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for plan in source_plans:
            grouped[_collector_role_for(plan.get("source_type", "structured"))].append(
                plan
            )

        blueprints: list[dict[str, Any]] = []
        latest_planning = (planning_audits or [])[-1] if planning_audits else {}
        latest_reflection = (reflection_audits or [])[-1] if reflection_audits else {}
        for collector_role, plans in grouped.items():
            blueprint = _collector_blueprint_for(collector_role)
            blueprints.append(
                {
                    "collector_role": collector_role,
                    "agent_name": blueprint["agent_name"],
                    "goal": blueprint["goal"],
                    "backstory": blueprint["backstory"],
                    "source_names": [plan["source_name"] for plan in plans],
                    "execution_hints": [
                        _build_execution_notes(
                            plan,
                            planning_audit=latest_planning,
                            reflection_audit=latest_reflection,
                        )
                        for plan in plans
                    ],
                    "plans": plans,
                }
            )
        blueprints.sort(key=lambda item: item["collector_role"])
        return blueprints

    @staticmethod
    def _collector_agents_payload(
        collector_blueprints: list[dict[str, Any]],
        *,
        active_engine: str,
    ) -> list[dict[str, Any]]:
        return [
            {
                "collector_role": item["collector_role"],
                "agent_name": item["agent_name"],
                "assigned_sources": item["source_names"],
                "execution_hints": item.get("execution_hints", []),
                "engine": active_engine,
            }
            for item in collector_blueprints
        ]

    @staticmethod
    def _detect_crewai() -> bool:
        try:
            import_module("crewai")

            return True
        except Exception:
            return False


def _collector_role_for(source_type: str) -> str:
    if source_type == "paper":
        return "PaperIntelCollector"
    if source_type == "community":
        return "CommunitySignalCollector"
    if source_type == "code":
        return "CodeSecurityCollector"
    if source_type == "advisory":
        return "AdvisoryCollector"
    return "StructuredIntelCollector"


def _collector_blueprint_for(collector_role: str) -> dict[str, str]:
    blueprints = {
        "StructuredIntelCollector": {
            "agent_name": "Structured Intel Collector Agent",
            "goal": "Handle structured vulnerability, KEV, and ATT&CK-like source plans.",
            "backstory": "You specialize in structured feeds with stable schemas and high-confidence metadata.",
        },
        "CodeSecurityCollector": {
            "agent_name": "Code Security Collector Agent",
            "goal": "Handle advisories, packages, and code-hosting security signals.",
            "backstory": "You analyze code ecosystem advisories and package-level security disclosures.",
        },
        "PaperIntelCollector": {
            "agent_name": "Paper Intel Collector Agent",
            "goal": "Handle paper and report source plans with research-oriented query intent.",
            "backstory": "You specialize in extracting security-relevant findings from research papers and reports.",
        },
        "CommunitySignalCollector": {
            "agent_name": "Community Signal Collector Agent",
            "goal": "Handle community and discussion source plans for weak-signal collection.",
            "backstory": "You monitor community chatter and can separate early signals from ordinary noise.",
        },
        "AdvisoryCollector": {
            "agent_name": "Advisory Collector Agent",
            "goal": "Handle advisory-style feeds and vendor bulletin source plans.",
            "backstory": "You process semi-structured advisories and turn them into actionable collection notes.",
        },
    }
    return blueprints.get(
        collector_role,
        {
            "agent_name": f"{collector_role} Agent",
            "goal": "Handle assigned collection plans.",
            "backstory": "You are a specialized collection agent.",
        },
    )


def _execution_profile_for(plan: dict[str, Any]) -> tuple[str, str]:
    query_intent = str(plan.get("query_intent", "broad_recall"))
    source_type = str(plan.get("source_type", "structured"))
    if query_intent == "precision_probe":
        return (
            "precision_hunt",
            "Prioritize exact advisory phrasing and exploit indicators.",
        )
    if query_intent == "weak_signal_probe":
        return (
            "weak_signal_scan",
            "Prefer discussion language, symptom phrasing, and emerging chatter.",
        )
    if query_intent == "evidence_corroboration":
        return (
            "corroboration_pass",
            "Seek confirmatory evidence and cross-source support.",
        )
    if query_intent == "source_specific_rewrite":
        return (
            "source_specific_probe",
            "Use source-native syntax and phrasing patterns.",
        )
    if query_intent == "component_anchor":
        return (
            "component_focus",
            "Anchor query around affected component or framework names.",
        )
    if query_intent == "taxonomy_anchor":
        return (
            "taxonomy_focus",
            "Anchor query around attack taxonomy labels and family names.",
        )
    if source_type == "community":
        return (
            "weak_signal_scan",
            "Use broad discovery language but tolerate noisier discussion terms.",
        )
    return "broad_discovery", "Cast a broad but source-aware recall net."


def _build_execution_notes(
    plan: dict[str, Any],
    *,
    planning_audit: dict[str, Any] | None,
    reflection_audit: dict[str, Any] | None,
) -> str:
    execution_profile, source_hint = _execution_profile_for(plan)
    parts = [
        f"profile={execution_profile}",
        f"intent={plan.get('query_intent', 'broad_recall')}",
        source_hint,
    ]
    if plan.get("rewrite_reason"):
        parts.append(f"rewrite_reason={plan['rewrite_reason']}")
    if planning_audit and planning_audit.get("strategy_executed"):
        parts.append(f"planning={planning_audit['strategy_executed']}")
    if reflection_audit and reflection_audit.get("diagnosis"):
        parts.append(f"reflection={reflection_audit['diagnosis']}")
    return " | ".join(parts)
