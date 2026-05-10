from __future__ import annotations

from crewai import Agent, Crew, Process, Task
from crewai.agent.planning_config import PlanningConfig
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from sufe_saads_crewai.llms import build_glm_llm
from sufe_saads_crewai.schemas import (
    CollectionBatchOutput,
    CompletenessDecisionOutput,
    CoverageAnalysisOutput,
    PlannerDecisionOutput,
    RewriteDecisionOutput,
    SourceProposalBatchOutput,
    YieldAssessmentOutput,
)
from sufe_saads_crewai.tools import RegisteredApiSourceSearchTool


def medium_planning_config() -> PlanningConfig:
    return PlanningConfig(reasoning_effort="medium")


@CrewBase
class SufeSaadsCrewai:
    """CrewAI definitions for the adaptive LLM security intelligence crew."""

    agents: list[BaseAgent]
    tasks: list[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def autonomous_planner(self) -> Agent:
        return Agent(
            config=self.agents_config["autonomous_planner"],  # type: ignore[index]
            llm=build_glm_llm("main"),
            function_calling_llm=build_glm_llm("fast"),
            planning_config=medium_planning_config(),
            max_retry_limit=0,
            verbose=True,
        )

    @agent
    def source_intelligence_collector(self) -> Agent:
        return Agent(
            config=self.agents_config["source_intelligence_collector"],  # type: ignore[index]
            llm=build_glm_llm("fast"),
            function_calling_llm=build_glm_llm("fast"),
            tools=[RegisteredApiSourceSearchTool()],
            max_retry_limit=0,
            verbose=True,
        )

    @agent
    def reflection_coverage_critic(self) -> Agent:
        return Agent(
            config=self.agents_config["reflection_coverage_critic"],  # type: ignore[index]
            llm=build_glm_llm("main"),
            function_calling_llm=build_glm_llm("fast"),
            planning_config=medium_planning_config(),
            max_retry_limit=0,
            verbose=True,
        )

    @task
    def select_next_actions_task(self) -> Task:
        return Task(
            config=self.tasks_config["select_next_actions_task"],  # type: ignore[index]
            output_pydantic=PlannerDecisionOutput,
        )

    @task
    def search_registered_sources_task(self) -> Task:
        return Task(
            config=self.tasks_config["search_registered_sources_task"],  # type: ignore[index]
            output_pydantic=CollectionBatchOutput,
        )

    @task
    def assess_collection_yield_task(self) -> Task:
        return Task(
            config=self.tasks_config["assess_collection_yield_task"],  # type: ignore[index]
            output_pydantic=YieldAssessmentOutput,
        )

    @task
    def analyze_coverage_gaps_task(self) -> Task:
        return Task(
            config=self.tasks_config["analyze_coverage_gaps_task"],  # type: ignore[index]
            output_pydantic=CoverageAnalysisOutput,
        )

    @task
    def propose_new_sources_task(self) -> Task:
        return Task(
            config=self.tasks_config["propose_new_sources_task"],  # type: ignore[index]
            output_pydantic=SourceProposalBatchOutput,
        )

    @task
    def rewrite_search_strategy_task(self) -> Task:
        return Task(
            config=self.tasks_config["rewrite_search_strategy_task"],  # type: ignore[index]
            output_pydantic=RewriteDecisionOutput,
        )

    @task
    def evaluate_search_completeness_task(self) -> Task:
        return Task(
            config=self.tasks_config["evaluate_search_completeness_task"],  # type: ignore[index]
            output_pydantic=CompletenessDecisionOutput,
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
