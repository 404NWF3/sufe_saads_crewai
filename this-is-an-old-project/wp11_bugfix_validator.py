from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel

from backend.agents.intel_agents.services.dedup_memory_service import (
    DedupMemoryService,
    _normalize_score_origin,
)
from backend.agents.intel_agents.tools import llm_client_factory as llm_factory
from backend.agents.intel_agents.tools.llm_bom_resolver_tools import (
    LangChainLlmBomResolver,
)
from backend.agents.intel_agents.tools.llm_coverage_analyst_tools import (
    LangChainLlmCoverageAnalyst,
)
from backend.agents.intel_agents.tools.llm_dedup_adjudication_tools import (
    LangChainLlmDedupAdjudicator,
)
from backend.agents.intel_agents.tools.llm_merge_judge_tools import (
    LangChainLlmMergeJudge,
)
from backend.agents.intel_agents.tools.llm_search_reflection_tools import (
    LangChainLlmSearchReflectionAgent,
)
from backend.agents.intel_agents.tools.llm_standardization_tools import (
    LangChainLlmStandardizer,
)
from backend.agents.intel_agents.tools.llm_supervisor_planning_tools import (
    LangChainLlmSupervisorPlanner,
)
from backend.agents.intel_agents.tools.llm_client_factory import (
    LlmInvocationError,
    describe_model_pool,
    invoke_structured_with_model_pool,
    recommended_task_concurrency,
    resolve_model_pool,
)
from backend.db.connection import connection_context
from backend.db.typing import SqlContext
from backend.db.unit_of_work import UnitOfWork

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN_GLYPHS = (
    "\u2713",
    "\u2717",
    "\u25cb",
    "\u26a0",
    "\u26a1",
    "\u2705",
    "\u274c",
    "\U0001f4ca",
    "\U0001f680",
    "\U0001f4a3",
)


@dataclass(slots=True)
class ValidationContext:
    token: str
    trace_id: str
    source_name: str
    source_id: str | None = None
    task_id: str | None = None
    raw_id: str | None = None
    rule_name: str = ""
    attack_code_prefix: str = ""
    created_attack_codes: list[str] = field(default_factory=list)


def run_wp11_bugfix_suite(*, verbose: bool = False) -> int:
    token = f"tmpw11{uuid4().hex[:8]}"
    ctx = ValidationContext(
        token=token,
        trace_id=f"wp11-bugfix-validator-{token}",
        source_name=f"{token}-source",
        rule_name=f"validate_wp11_bugfixes_{token}",
        attack_code_prefix=f"TMPW11_{token}_",
    )
    failures: list[str] = []
    _emit("INFO", f"starting wp11 bugfix validation suite token={token}")
    try:
        _validate_bug2(failures)
        _create_live_fixture(ctx)
        _validate_persist_with_valid_raw(ctx, failures)
        _validate_persist_without_valid_raw(ctx, failures)
        _validate_transaction_isolation(ctx, failures)
        _validate_append_audits(ctx, failures)
        _validate_ascii_outputs(failures)
        _validate_score_origin_helper(failures)
        if verbose and not failures:
            _emit("INFO", "all bugfix checks passed")
    except Exception as exc:
        failures.append(f"validation suite crashed: {exc}")
        _emit("FAIL", str(failures[-1]))
    finally:
        _cleanup_live_fixture(ctx)
    if failures:
        _emit("FAIL", f"wp11 bugfix validation failed with {len(failures)} issue(s)")
        for failure in failures:
            _emit("FAIL", failure)
        return 1
    _emit("OK", "wp11 bugfix validation passed")
    return 0


def run_wp11_persist_robustness_suite(*, verbose: bool = False) -> int:
    token = f"tmpw11p{uuid4().hex[:8]}"
    ctx = ValidationContext(
        token=token,
        trace_id=f"wp11-persist-validator-{token}",
        source_name=f"{token}-source",
        rule_name=f"validate_wp11_persist_{token}",
        attack_code_prefix=f"TMPW11P_{token}_",
    )
    failures: list[str] = []
    _emit("INFO", f"starting wp11 persistence robustness suite token={token}")
    try:
        _create_live_fixture(ctx)
        _validate_persist_summary_and_dead_letter(ctx, failures)
        _validate_audit_summary(ctx, failures)
        if verbose and not failures:
            _emit("INFO", "all persistence robustness checks passed")
    except Exception as exc:
        failures.append(f"persistence robustness suite crashed: {exc}")
        _emit("FAIL", str(failures[-1]))
    finally:
        _cleanup_live_fixture(ctx)
    if failures:
        _emit(
            "FAIL",
            f"wp11 persistence robustness validation failed with {len(failures)} issue(s)",
        )
        for failure in failures:
            _emit("FAIL", failure)
        return 1
    _emit("OK", "wp11 persistence robustness validation passed")
    return 0


def run_wp11_llm_pool_suite(*, verbose: bool = False) -> int:
    failures: list[str] = []
    _emit("INFO", "starting wp11 llm pool validation suite")
    try:
        _validate_llm_pool_file_loading(failures)
        _validate_llm_pool_label_expansion(failures)
        _validate_llm_pool_failover_and_wait(failures)
        if verbose and not failures:
            _emit("INFO", "all llm pool checks passed")
    except Exception as exc:
        failures.append(f"llm pool suite crashed: {exc}")
        _emit("FAIL", str(failures[-1]))
    if failures:
        _emit("FAIL", f"wp11 llm pool validation failed with {len(failures)} issue(s)")
        for failure in failures:
            _emit("FAIL", failure)
        return 1
    _emit("OK", "wp11 llm pool validation passed")
    return 0


def _validate_bug2(failures: list[str]) -> None:
    sentinel = f"validator-model-{uuid4().hex[:8]}"
    previous = os.environ.get("OPENAI_MODEL")
    os.environ["OPENAI_MODEL"] = sentinel
    classes: list[tuple[str, Callable[..., Any]]] = [
        ("planning", LangChainLlmSupervisorPlanner),
        ("standardization", LangChainLlmStandardizer),
        ("dedup_merge", LangChainLlmMergeJudge),
        ("bom_resolution", LangChainLlmBomResolver),
        ("coverage", LangChainLlmCoverageAnalyst),
        ("dedup_adjudication", LangChainLlmDedupAdjudicator),
        ("reflection", LangChainLlmSearchReflectionAgent),
    ]
    try:
        for label, cls in classes:
            instance = cls()
            _check(
                instance.model == sentinel,
                f"{label} model inherited OPENAI_MODEL",
                f"{label} model expected {sentinel!r}, got {instance.model!r}",
                failures,
            )
    finally:
        if previous is None:
            os.environ.pop("OPENAI_MODEL", None)
        else:
            os.environ["OPENAI_MODEL"] = previous


def _create_live_fixture(ctx: ValidationContext) -> None:
    with UnitOfWork(
        context=SqlContext(trace_id=ctx.trace_id, agent_name="wp11_bugfix_fixture")
    ) as uow:
        source = uow.sources.upsert_source(
            source_name=ctx.source_name,
            source_type="api",
            base_uri=f"validator://{ctx.token}",
            trust_level=5,
            default_qps=1.0,
            enabled=True,
        )
        task = uow.sources.create_collection_task(
            source_id=str(source.source_id),
            task_mode="fast",
            trigger_type="manual",
            task_status="queued",
            created_by="wp11_bugfix_validator",
            trace_id=ctx.trace_id,
        )
        raw = uow.sources.insert_raw_intel_record(
            source_id=str(source.source_id),
            task_id=str(task.task_id),
            source_uri=f"validator://{ctx.token}/raw",
            title="wp11 bugfix validator raw",
            content_hash=hashlib.sha256(ctx.token.encode("utf-8")).hexdigest(),
            raw_format="json",
            payload_uri=f"validator://{ctx.token}/payload",
            language_code="en",
            relevance_score=1.0,
            parser_status="pending",
            fetched_at=datetime.now(timezone.utc),
            is_deleted=False,
        )
        ctx.source_id = str(source.source_id)
        ctx.task_id = str(task.task_id)
        ctx.raw_id = str(raw.raw_id)
    _emit("OK", f"created live fixture raw_id={ctx.raw_id}")


def _validate_persist_with_valid_raw(
    ctx: ValidationContext,
    failures: list[str],
) -> None:
    if ctx.raw_id is None:
        failures.append("live fixture raw_id is missing")
        return
    attack_code = f"{ctx.attack_code_prefix}GOOD"
    service = DedupMemoryService()
    summary = service.persist_records(
        [_build_record(attack_code=attack_code, related_raw_ids=[ctx.raw_id])],
        trace_id=ctx.trace_id,
    )
    ctx.created_attack_codes.append(attack_code)
    _check(
        summary["attempted_count"] == 1
        and summary["persisted_count"] == 1
        and summary["failed_count"] == 0,
        f"persist summary captured success for {attack_code}",
        f"unexpected persist summary for {attack_code}: {summary}",
        failures,
    )
    attack = _get_attack_by_code(attack_code)
    _check(
        attack is not None,
        f"persisted attack_entry {attack_code}",
        f"attack_entry missing after persist_records for {attack_code}",
        failures,
    )
    if attack is None:
        return
    evidence_count = _fetch_scalar(
        "SELECT COUNT(*) FROM wp11.attack_evidence WHERE attack_id = %s",
        (attack["attack_id"],),
    )
    _check(
        evidence_count == 1,
        f"persisted evidence for {attack_code}",
        f"expected 1 evidence row for {attack_code}, got {evidence_count}",
        failures,
    )
    cvss_row = _fetch_row(
        """
        SELECT score_origin, source_raw_id
        FROM wp11.attack_cvss_assessment
        WHERE attack_id = %s
        ORDER BY score_id DESC
        LIMIT 1
        """,
        (attack["attack_id"],),
    )
    _check(
        cvss_row is not None
        and cvss_row["score_origin"] == "estimated"
        and str(cvss_row["source_raw_id"]) == ctx.raw_id,
        f"normalized valid-raw CVSS for {attack_code}",
        f"unexpected CVSS row for {attack_code}: {cvss_row}",
        failures,
    )


def _validate_persist_without_valid_raw(
    ctx: ValidationContext,
    failures: list[str],
) -> None:
    attack_code = f"{ctx.attack_code_prefix}NORAW"
    service = DedupMemoryService()
    summary = service.persist_records(
        [
            _build_record(
                attack_code=attack_code,
                related_raw_ids=["not-a-uuid", "db_synth_invalid"],
            )
        ],
        trace_id=ctx.trace_id,
    )
    ctx.created_attack_codes.append(attack_code)
    _check(
        summary["attempted_count"] == 1
        and summary["persisted_count"] == 1
        and summary["failed_count"] == 0,
        f"persist summary captured no-raw success for {attack_code}",
        f"unexpected no-raw summary for {attack_code}: {summary}",
        failures,
    )
    attack = _get_attack_by_code(attack_code)
    _check(
        attack is not None,
        f"persisted attack_entry without valid raw_id for {attack_code}",
        f"attack_entry missing for no-raw record {attack_code}",
        failures,
    )
    if attack is None:
        return
    evidence_count = _fetch_scalar(
        "SELECT COUNT(*) FROM wp11.attack_evidence WHERE attack_id = %s",
        (attack["attack_id"],),
    )
    _check(
        evidence_count == 0,
        f"skipped evidence when raw_id was invalid for {attack_code}",
        f"expected 0 evidence rows for {attack_code}, got {evidence_count}",
        failures,
    )
    cvss_row = _fetch_row(
        """
        SELECT score_origin, source_raw_id
        FROM wp11.attack_cvss_assessment
        WHERE attack_id = %s
        ORDER BY score_id DESC
        LIMIT 1
        """,
        (attack["attack_id"],),
    )
    _check(
        cvss_row is not None
        and cvss_row["score_origin"] == "estimated"
        and cvss_row["source_raw_id"] is None,
        f"normalized no-raw CVSS for {attack_code}",
        f"unexpected no-raw CVSS row for {attack_code}: {cvss_row}",
        failures,
    )


def _validate_transaction_isolation(
    ctx: ValidationContext,
    failures: list[str],
) -> None:
    bad_code = f"{ctx.attack_code_prefix}BADTX"
    good_code = f"{ctx.attack_code_prefix}GOODTX"
    service = DedupMemoryService()
    summary = service.persist_records(
        [
            _build_record(
                attack_code=bad_code,
                severity_level="bogus",
                related_raw_ids=[ctx.raw_id] if ctx.raw_id else [],
            ),
            _build_record(
                attack_code=good_code,
                related_raw_ids=[ctx.raw_id] if ctx.raw_id else [],
            ),
        ],
        trace_id=ctx.trace_id,
    )
    ctx.created_attack_codes.extend([bad_code, good_code])
    _check(
        summary["attempted_count"] == 2
        and summary["persisted_count"] == 1
        and summary["failed_count"] == 1
        and summary["dead_letter_count"] >= 1,
        f"persist summary isolated failure for {bad_code}",
        f"unexpected transaction-isolation summary: {summary}",
        failures,
    )
    bad_attack = _get_attack_by_code(bad_code)
    good_attack = _get_attack_by_code(good_code)
    _check(
        bad_attack is None,
        f"rejected malformed record {bad_code}",
        f"malformed record unexpectedly persisted: {bad_code}",
        failures,
    )
    _check(
        good_attack is not None,
        f"persisted later record despite earlier failure {good_code}",
        f"later record did not persist after earlier failure: {good_code}",
        failures,
    )


def _validate_append_audits(ctx: ValidationContext, failures: list[str]) -> None:
    if ctx.raw_id is None:
        failures.append("cannot validate append_audits without a live raw_id")
        return
    matched_code = f"{ctx.attack_code_prefix}GOOD"
    attack = _get_attack_by_code(matched_code)
    if attack is None:
        failures.append(f"cannot validate append_audits, missing {matched_code}")
        return
    service = DedupMemoryService()
    summary = service.append_audits(
        [
            {
                "candidate_raw_id": "not-a-uuid",
                "matched_attack_id": attack["attack_id"],
                "similarity_score": 0.55,
                "rule_name": ctx.rule_name,
                "decision": "review",
            },
            {
                "candidate_raw_id": ctx.raw_id,
                "matched_attack_id": attack["attack_id"],
                "similarity_score": 0.91,
                "rule_name": ctx.rule_name,
                "decision": "review",
            },
        ],
        trace_id=ctx.trace_id,
    )
    _check(
        summary["attempted_count"] == 2
        and summary["persisted_count"] == 1
        and summary["invalid_candidate_count"] == 1,
        "append_audits summary captured invalid row skip",
        f"unexpected audit summary: {summary}",
        failures,
    )
    count = _fetch_scalar(
        "SELECT COUNT(*) FROM wp11.dedup_audit WHERE rule_name = %s",
        (ctx.rule_name,),
    )
    _check(
        count == 1,
        "append_audits inserted only the valid audit row",
        f"expected 1 audit row for {ctx.rule_name}, got {count}",
        failures,
    )


def _validate_ascii_outputs(failures: list[str]) -> None:
    targets = [
        ROOT / "main.py",
        ROOT / "backend" / "wp11_bugfix_validator.py",
        ROOT / "scripts" / "validate_wp11_bugfixes.py",
    ]
    for path in targets:
        content = path.read_text(encoding="utf-8")
        present = sorted({glyph for glyph in FORBIDDEN_GLYPHS if glyph in content})
        _check(
            not present,
            f"forbidden console glyph scan clean for {path.name}",
            f"forbidden glyphs found in {path.name}: {present}",
            failures,
        )


def _validate_score_origin_helper(failures: list[str]) -> None:
    _check(
        _normalize_score_origin("db_primary") == "estimated",
        "score origin helper maps db_primary to estimated",
        "score origin helper failed to normalize db_primary",
        failures,
    )


def _validate_llm_pool_file_loading(failures: list[str]) -> None:
    model_pool = describe_model_pool(
        default_model=os.getenv("OPENAI_MODEL"),
        base_url=os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL"),
        api_key=os.getenv("OPENAI_API_KEY"),
        runtime_config={"llm_route_preset": "default", "llm_task_routes": {}},
    )
    profiles_source = model_pool.get("profiles_source") or {}
    routes_source = model_pool.get("route_presets_source") or {}
    profiles = model_pool.get("profiles") or []
    route_presets = model_pool.get("route_presets") or {}
    _check(
        profiles_source.get("source") == "file"
        and str(profiles_source.get("path", "")).endswith("wp11_llm_profiles.json"),
        "llm profiles loaded from root json file",
        f"unexpected profiles source: {profiles_source}",
        failures,
    )
    _check(
        routes_source.get("source") == "file"
        and str(routes_source.get("path", "")).endswith("wp11_llm_route_presets.json"),
        "llm route presets loaded from root json file",
        f"unexpected route preset source: {routes_source}",
        failures,
    )
    _check(
        bool(profiles),
        "llm profile catalog is not empty",
        "llm profile catalog is empty",
        failures,
    )
    valid_labels = {"cheap_fast", "balanced", "fallback"}
    for profile in profiles:
        profile_id = str(profile.get("profile_id", ""))
        label = str(profile.get("profile", ""))
        _check(
            profile_id.isdigit(),
            f"profile_id {profile_id} is numeric",
            f"profile_id is not numeric: {profile_id!r}",
            failures,
        )
        _check(
            label in valid_labels,
            f"profile label valid for {profile_id}",
            f"profile label invalid for {profile_id}: {label!r}",
            failures,
        )
    invalid_routes = [
        (preset_name, task_name, route)
        for preset_name, preset in route_presets.items()
        for task_name, route in preset.items()
        if any(label not in valid_labels for label in route)
    ]
    _check(
        not invalid_routes,
        "route presets only reference profile labels",
        f"invalid route preset labels found: {invalid_routes}",
        failures,
    )


def _validate_llm_pool_label_expansion(failures: list[str]) -> None:
    runtime_config = {
        "llm_route_preset": "default",
        "llm_task_routes": {"bom_resolution": ["cheap_fast"]},
    }
    profiles, meta = resolve_model_pool(
        task_name="bom_resolution",
        default_model=os.getenv("OPENAI_MODEL"),
        base_url=os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL"),
        api_key=os.getenv("OPENAI_API_KEY"),
        runtime_config=runtime_config,
    )
    cheap_profiles = [profile for profile in profiles if profile.profile == "cheap_fast"]
    cheap_ids = [profile.profile_id for profile in cheap_profiles]
    expected_ids = sorted(cheap_ids, key=int)
    _check(
        len(cheap_profiles) >= 2,
        "cheap_fast label expands to multiple concrete profiles",
        f"expected at least two cheap_fast profiles, got {cheap_ids}",
        failures,
    )
    _check(
        meta.get("selected_route_labels") == ["cheap_fast"],
        "task route override uses profile labels",
        f"unexpected selected route labels: {meta.get('selected_route_labels')}",
        failures,
    )
    _check(
        cheap_ids == expected_ids,
        "cheap_fast profiles expand in numeric profile_id order",
        f"cheap_fast expansion order mismatch: {cheap_ids} vs {expected_ids}",
        failures,
    )
    expected_budget = sum(
        max(1, int(profile.max_concurrency))
        for profile in cheap_profiles
        if profile.enabled
        and profile.supports_structured_output
        and (profile.api_key or profile.base_url)
    )
    actual_budget = recommended_task_concurrency(
        task_name="bom_resolution",
        default_model=os.getenv("OPENAI_MODEL"),
        base_url=os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL"),
        api_key=os.getenv("OPENAI_API_KEY"),
        runtime_config=runtime_config,
        upper_bound=32,
    )
    _check(
        actual_budget == max(1, expected_budget),
        "task concurrency budget sums expanded cheap_fast profiles",
        f"unexpected concurrency budget: actual={actual_budget}, expected={expected_budget}",
        failures,
    )


def _validate_llm_pool_failover_and_wait(failures: list[str]) -> None:
    runtime_config = {
        "llm_route_preset": "default",
        "llm_task_routes": {"bom_resolution": ["cheap_fast"]},
        "llm_retry_attempts": 1,
        "llm_short_wait_threshold_seconds": 0.01,
    }
    profiles, _ = resolve_model_pool(
        task_name="bom_resolution",
        default_model=os.getenv("OPENAI_MODEL"),
        base_url=os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL"),
        api_key=os.getenv("OPENAI_API_KEY"),
        runtime_config=runtime_config,
    )
    cheap_profiles = [profile for profile in profiles if profile.profile == "cheap_fast"]
    if len(cheap_profiles) < 2:
        failures.append("cannot validate failover without at least two cheap_fast profiles")
        _emit("FAIL", failures[-1])
        return

    previous_builder = llm_factory.build_structured_chat_openai
    llm_factory._PROFILE_ACTIVE_COUNT.clear()
    llm_factory._PROFILE_COOLDOWN_UNTIL.clear()

    try:
        first_profile = cheap_profiles[0]
        llm_factory._PROFILE_ACTIVE_COUNT[first_profile.profile_id] = first_profile.max_concurrency
        llm_factory.build_structured_chat_openai = _fake_build_structured_chat_openai
        result, meta = invoke_structured_with_model_pool(
            task_name="bom_resolution",
            prompt=_FakePrompt(),
            schema=_FakeStructuredResult,
            payload={"message": "validator"},
            default_model=os.getenv("OPENAI_MODEL"),
            temperature=0.0,
            base_url=os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL"),
            api_key=os.getenv("OPENAI_API_KEY"),
            runtime_config=runtime_config,
        )
        _check(
            meta.get("profile_id") == cheap_profiles[1].profile_id,
            "llm pool fails over to the next cheap_fast profile when the first is full",
            f"unexpected failover target: {meta}",
            failures,
        )
        _check(
            meta.get("profile") == "cheap_fast"
            and meta.get("selected_route_labels") == ["cheap_fast"]
            and meta.get("attempted_profile_labels") == ["cheap_fast"],
            "llm invocation meta records profile label routing",
            f"unexpected llm invocation meta: {meta}",
            failures,
        )
        _check(
            result.get("value") == cheap_profiles[1].model,
            "fake llm invocation returned the second cheap_fast model",
            f"unexpected fake llm result: {result}",
            failures,
        )

        llm_factory._PROFILE_ACTIVE_COUNT.clear()
        fail_once_builder = _make_fail_first_builder()
        llm_factory.build_structured_chat_openai = fail_once_builder
        result, meta = invoke_structured_with_model_pool(
            task_name="bom_resolution",
            prompt=_FakePrompt(),
            schema=_FakeStructuredResult,
            payload={"message": "validator"},
            default_model=os.getenv("OPENAI_MODEL"),
            temperature=0.0,
            base_url=os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL"),
            api_key=os.getenv("OPENAI_API_KEY"),
            runtime_config=runtime_config,
        )
        failed_profile_errors = list(meta.get("failed_profile_errors", []) or [])
        _check(
            meta.get("profile_id") == cheap_profiles[1].profile_id
            and result.get("value") == cheap_profiles[1].model,
            "llm pool retries the next cheap_fast profile after a real invocation failure",
            f"unexpected invocation-failover result: meta={meta}, result={result}",
            failures,
        )
        _check(
            len(failed_profile_errors) == 1
            and failed_profile_errors[0].get("profile_id") == cheap_profiles[0].profile_id
            and failed_profile_errors[0].get("error_family") == "fatal",
            "successful failover preserves the failed profile id in llm meta",
            f"unexpected failed_profile_errors payload: {failed_profile_errors}",
            failures,
        )

        llm_factory._PROFILE_ACTIVE_COUNT.clear()
        for profile in cheap_profiles:
            llm_factory._PROFILE_ACTIVE_COUNT[profile.profile_id] = profile.max_concurrency
        exhausted = None
        try:
            invoke_structured_with_model_pool(
                task_name="bom_resolution",
                prompt=_FakePrompt(),
                schema=_FakeStructuredResult,
                payload={"message": "validator"},
                default_model=os.getenv("OPENAI_MODEL"),
                temperature=0.0,
                base_url=os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL"),
                api_key=os.getenv("OPENAI_API_KEY"),
                runtime_config=runtime_config,
            )
        except LlmInvocationError as exc:
            exhausted = exc
        _check(
            exhausted is not None
            and exhausted.error_family == "pool_exhausted"
            and "max_concurrency" in str(exhausted),
            "llm pool waits then reports pool_exhausted when all cheap_fast profiles are full",
            f"unexpected all-full behavior: {exhausted!r}",
            failures,
        )
    finally:
        llm_factory.build_structured_chat_openai = previous_builder
        llm_factory._PROFILE_ACTIVE_COUNT.clear()
        llm_factory._PROFILE_COOLDOWN_UNTIL.clear()


def _validate_persist_summary_and_dead_letter(
    ctx: ValidationContext,
    failures: list[str],
) -> None:
    if ctx.raw_id is None:
        failures.append("live fixture raw_id is missing for persistence summary check")
        return
    good_code = f"{ctx.attack_code_prefix}ROBUSTGOOD"
    bad_code = f"{ctx.attack_code_prefix}ROBUSTBAD"
    service = DedupMemoryService()
    summary = service.persist_records(
        [
            _build_record(attack_code=good_code, related_raw_ids=[ctx.raw_id]),
            _build_record(
                attack_code=bad_code,
                related_raw_ids=[ctx.raw_id],
                severity_level="bogus",
            ),
        ],
        trace_id=ctx.trace_id,
    )
    ctx.created_attack_codes.extend([good_code, bad_code])
    dead_letter_path = summary.get("dead_letter_path")
    _check(
        summary["attempted_count"] == 2
        and summary["persisted_count"] == 1
        and summary["failed_count"] == 1,
        "persist summary counts reflect one success and one failure",
        f"unexpected persist summary counts: {summary}",
        failures,
    )
    _check(
        bool(dead_letter_path) and Path(str(dead_letter_path)).exists(),
        "persist failures wrote a dead-letter file",
        f"expected dead-letter file, got {dead_letter_path!r}",
        failures,
    )
    if dead_letter_path:
        content = Path(str(dead_letter_path)).read_text(encoding="utf-8")
        _check(
            bad_code in content and ctx.trace_id in content,
            "dead-letter file includes failed attack context",
            f"dead-letter file missing expected content for {bad_code}",
            failures,
        )


def _validate_audit_summary(ctx: ValidationContext, failures: list[str]) -> None:
    if ctx.raw_id is None:
        failures.append("cannot validate audit summary without a live raw_id")
        return
    matched_code = f"{ctx.attack_code_prefix}GOOD"
    attack = _get_attack_by_code(matched_code)
    if attack is None:
        service = DedupMemoryService()
        service.persist_records(
            [_build_record(attack_code=matched_code, related_raw_ids=[ctx.raw_id])],
            trace_id=ctx.trace_id,
        )
        ctx.created_attack_codes.append(matched_code)
        attack = _get_attack_by_code(matched_code)
    if attack is None:
        failures.append(f"cannot validate audit summary, missing {matched_code}")
        return
    service = DedupMemoryService()
    summary = service.append_audits(
        [
            {
                "candidate_raw_id": "not-a-uuid",
                "matched_attack_id": attack["attack_id"],
                "similarity_score": 0.22,
                "rule_name": ctx.rule_name,
                "decision": "review",
            },
            {
                "candidate_raw_id": str(uuid4()),
                "matched_attack_id": attack["attack_id"],
                "similarity_score": 0.31,
                "rule_name": ctx.rule_name,
                "decision": "review",
            },
            {
                "candidate_raw_id": ctx.raw_id,
                "matched_attack_id": attack["attack_id"],
                "similarity_score": 0.94,
                "rule_name": ctx.rule_name,
                "decision": "review",
            },
        ],
        trace_id=ctx.trace_id,
    )
    _check(
        summary["attempted_count"] == 3
        and summary["persisted_count"] == 1
        and summary["invalid_candidate_count"] == 1
        and summary["missing_candidate_count"] == 1
        and summary["failed_count"] == 0,
        "audit summary counts classify invalid, missing, and persisted rows",
        f"unexpected audit summary counts: {summary}",
        failures,
    )


def _build_record(
    *,
    attack_code: str,
    related_raw_ids: list[str],
    severity_level: str = "high",
) -> dict[str, Any]:
    name = f"validator attack {attack_code}"
    return {
        "stable_attack_id": attack_code,
        "stable_attack_code": attack_code,
        "canonical_name": name,
        "attack_family": "prompt_injection",
        "severity_level": severity_level,
        "summary": name,
        "description": f"{name} description",
        "taxonomy_items": [],
        "cvss_hint": {
            "cvss_version": "3.1",
            "base_score": 8.1,
            "severity_label": "High",
            "score_origin": "db_primary",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        },
        "bom_mentions": [],
        "evidence_refs": [],
        "source_coverage": ["validator"],
        "related_raw_ids": related_raw_ids,
        "member_attack_codes": [attack_code],
        "last_decision": "merge",
        "confidence_score": 0.9,
    }


def _get_attack_by_code(attack_code: str) -> dict[str, Any] | None:
    with UnitOfWork(
        context=SqlContext(
            trace_id=f"wp11-bugfix-read-{attack_code}",
            agent_name="wp11_bugfix_validator_read",
        ),
        read_only=True,
    ) as uow:
        attack = uow.attacks.get_attack_by_code(attack_code)
        if attack is None:
            return None
        return {
            "attack_id": str(attack.attack_id),
            "attack_code": attack.attack_code,
            "canonical_name": attack.canonical_name,
        }


def _fetch_scalar(query: str, params: tuple[Any, ...]) -> Any:
    with connection_context() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            return row[0] if row else None


def _fetch_row(query: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    with connection_context() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            if row is None:
                return None
            columns = [desc.name for desc in cur.description]
            return dict(zip(columns, row))


def _cleanup_live_fixture(ctx: ValidationContext) -> None:
    try:
        with connection_context() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM wp11.dedup_audit WHERE rule_name LIKE %s",
                    (f"{ctx.rule_name}%",),
                )
                cur.execute(
                    "DELETE FROM wp11.attack_entry WHERE attack_code LIKE %s",
                    (f"{ctx.attack_code_prefix}%",),
                )
                if ctx.raw_id:
                    cur.execute(
                        "DELETE FROM wp11.raw_intel_record WHERE raw_id = %s",
                        (ctx.raw_id,),
                    )
                if ctx.task_id:
                    cur.execute(
                        "DELETE FROM wp11.collection_task WHERE task_id = %s",
                        (ctx.task_id,),
                    )
                if ctx.source_id:
                    cur.execute(
                        "DELETE FROM wp11.intel_source WHERE source_id = %s",
                        (ctx.source_id,),
                    )
            conn.commit()
        _emit("OK", "cleaned up validator fixture")
    except Exception as exc:
        _emit("WARN", f"cleanup encountered an issue: {exc}")


def _check(
    condition: bool,
    success_message: str,
    failure_message: str,
    failures: list[str],
) -> None:
    if condition:
        _emit("OK", success_message)
        return
    failures.append(failure_message)
    _emit("FAIL", failure_message)


def _emit(level: str, message: str) -> None:
    print(f"[{level}] {message}")


class _FakeStructuredResult(BaseModel):
    value: str


class _FakeStructuredTarget:
    def __init__(
        self,
        model: str,
        *,
        should_fail: bool = False,
        failure_message: str = "synthetic failure",
    ) -> None:
        self.model = model
        self.should_fail = should_fail
        self.failure_message = failure_message


class _FakeChain:
    def __init__(self, target: _FakeStructuredTarget) -> None:
        self._target = target

    def invoke(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._target.should_fail:
            raise RuntimeError(self._target.failure_message)
        return {"value": self._target.model}


class _FakePrompt:
    def __or__(self, target: _FakeStructuredTarget) -> _FakeChain:
        return _FakeChain(target)


class _FakeStructuredLlm:
    def __init__(
        self,
        model: str,
        *,
        should_fail: bool = False,
        failure_message: str = "synthetic failure",
    ) -> None:
        self._model = model
        self._should_fail = should_fail
        self._failure_message = failure_message

    def with_structured_output(
        self,
        schema: type[Any],
        method: str = "function_calling",
    ) -> _FakeStructuredTarget:
        return _FakeStructuredTarget(
            self._model,
            should_fail=self._should_fail,
            failure_message=self._failure_message,
        )


def _fake_build_structured_chat_openai(
    *,
    model: str,
    temperature: float,
    base_url: str | None,
    api_key: str | None,
) -> _FakeStructuredLlm:
    return _FakeStructuredLlm(model)


def _make_fail_first_builder() -> Callable[..., _FakeStructuredLlm]:
    state = {"count": 0}

    def _builder(
        *,
        model: str,
        temperature: float,
        base_url: str | None,
        api_key: str | None,
    ) -> _FakeStructuredLlm:
        state["count"] += 1
        return _FakeStructuredLlm(
            model,
            should_fail=state["count"] == 1,
            failure_message="synthetic first-profile failure",
        )

    return _builder
