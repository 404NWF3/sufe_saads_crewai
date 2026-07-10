"""Distill high-yield source calls of a round into Playbook techniques.

A call earns a technique when its yield (new relevant items per call) clears a
threshold. The technique text is a deterministic, human-readable template by
default; an optional ``distiller`` callable can rewrite it with a fast LLM. This
keeps harvesting robust and testable while still allowing NL enrichment.
"""

from __future__ import annotations

from typing import Any, Callable

from ..analysis import operator_signature
from .playbook import PlaybookStore

Distiller = Callable[[dict[str, Any]], str]

MIN_REWARD_TO_HARVEST = 0.5


def _describe_params(params: dict[str, Any]) -> str:
    active = {key: value for key, value in params.items() if value not in (None, "", [], {})}
    if not active:
        return "base query (no advanced operators)"
    return ", ".join(f"{key}={value}" for key, value in sorted(active.items()))


def _default_technique_text(call: dict[str, Any], topic_bucket: str) -> str:
    source = call["source_name"]
    query_text = call.get("query_text", "")
    operators = _describe_params(call.get("params") or {})
    new_relevant = call.get("new_relevant", 0)
    scope = f" within {call['time_scope_hint']}" if call.get("time_scope_hint") else ""
    return (
        f"For '{topic_bucket}'{scope}: query {source} with {operators}"
        + (f" (text: \"{query_text[:80]}\")" if query_text else "")
        + f" -- yielded {new_relevant} new relevant item(s) per call."
    )


def harvest_round(
    store: PlaybookStore,
    run_id: str,
    executed_calls: list[dict[str, Any]],
    topic_bucket: str,
    time_scope_hint: str | None = None,
    distiller: Distiller | None = None,
    min_reward: float = MIN_REWARD_TO_HARVEST,
) -> list[str]:
    """Upsert techniques for calls that cleared the yield bar. Returns entry ids used."""
    used_ids: list[str] = []
    for call in executed_calls:
        reward = float(call.get("new_relevant", 0))
        params = call.get("params") or {}
        signature = operator_signature(call["source_name"], params)
        produced = reward > 0
        if reward < min_reward:
            continue
        call = {**call, "time_scope_hint": time_scope_hint}
        technique_text = (
            distiller(call) if distiller is not None else _default_technique_text(call, topic_bucket)
        )
        entry = store.upsert(
            technique_text=technique_text,
            source_name=call["source_name"],
            operator_signature=signature,
            topic_bucket=topic_bucket,
            reward=reward,
            run_id=run_id,
            params_example=params,
            time_scope_hint=time_scope_hint,
            produced_relevant=produced,
        )
        used_ids.append(entry.entry_id)
    return used_ids
