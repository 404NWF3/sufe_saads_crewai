from __future__ import annotations

import warnings
from uuid import uuid4

from .unit_of_work import UnitOfWork


def insert_attack_entry(source: str, title: str, description: str) -> str:
    """Deprecated compatibility wrapper.

    Use AttackRepository / AttackMergeService instead.
    """

    warnings.warn(
        "insert_attack_entry() is deprecated. Use UnitOfWork().attacks or services instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    summary = description[:500] if description else title
    with UnitOfWork() as uow:
        attack = uow.attacks.create_attack_entry(
            attack_code=f"LEGACY-{uuid4().hex[:20].upper()}",
            canonical_name=title or "legacy-entry",
            attack_family=source or "legacy",
            severity_level="medium",
            entry_status="draft",
            summary=summary,
            description=description or title or "legacy entry",
            exploit_preconditions=None,
            impact_scope=None,
            confidence_score=0.5,
            first_seen_at=None,
            last_seen_at=None,
            stix_type=None,
            stix_payload=None,
        )
    return str(attack.attack_id)

