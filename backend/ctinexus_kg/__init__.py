"""Self-contained CTINexus item-level KG generation.

No dependency on the legacy crew package or on intel_agent. Consume collected
intel items via :mod:`ctinexus_kg.pipeline` after a collection run finishes.
"""

from .ctinexus_adapter import CtinexusKgGenerator
from .eligibility import assess_kg_eligibility
from .feedback import append_triplet_feedback, load_triplet_feedback
from .pipeline import generate_for_item, generate_for_run, list_kg_ready
from .prompting import build_ctinexus_input_text
from .schemas import (
    ItemKnowledgeGraphRecord,
    KgEligibilityDecision,
    KgGenerationConfig,
    KnowledgeGraphManifest,
    RawIntelItem,
    TripletFeedbackRecord,
    coerce_raw_item,
)

__all__ = [
    "CtinexusKgGenerator",
    "ItemKnowledgeGraphRecord",
    "KgEligibilityDecision",
    "KgGenerationConfig",
    "KnowledgeGraphManifest",
    "RawIntelItem",
    "TripletFeedbackRecord",
    "append_triplet_feedback",
    "assess_kg_eligibility",
    "build_ctinexus_input_text",
    "coerce_raw_item",
    "generate_for_item",
    "generate_for_run",
    "list_kg_ready",
    "load_triplet_feedback",
]
