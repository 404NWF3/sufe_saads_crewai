"""Post-LLM rule-based validator and fuser for Phase 3 standardization.

The ``RuleValidatorFuser`` runs **after** the LLM primary extractor.
It does NOT extract — it only validates, constrains, normalises, and fuses.

Responsibilities
----------------
1. Validate taxonomy codes are well-formed and recognized.
2. Verify CVSS ranges (0.0–10.0) and severity↔CVSS consistency.
3. Check BOM mention shapes (non-empty names, valid component_layer).
4. Enforce exactly-one-primary taxonomy.
5. Detect severity/CVSS conflicts.
6. Normalise fields (strip, case) that the LLM may have returned in odd casing.
7. Fuse: if LLM returned ``"unknown"`` for a field and the rule fallback can
   provide a plausible value, inject it but record the substitution in
   ``normalization_trace``.
8. Produce ``validation_findings``, ``conflict_flags``, ``normalization_trace``.
"""

from __future__ import annotations

import re
from typing import Any

# Recognised taxonomy code patterns
_OWASP_LLM_RE = re.compile(r"^OWASP-LLM-(?:0[1-9]|10)$")
_CWE_RE = re.compile(r"^CWE-\d{1,5}$")
_CAPEC_RE = re.compile(r"^CAPEC-\d{1,5}$")
_ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_VALID_TAXONOMY_TYPES = {"OWASP_LLM", "CWE", "CAPEC", "ATTACK"}
_VALID_SEVERITY_LEVELS = {"info", "low", "medium", "high", "critical"}
_VALID_COMPONENT_LAYERS = {
    "vendor_platform",
    "model_family",
    "framework",
    "plugin",
    "runtime",
    "vector_stack",
    "unknown",
}


class RuleValidatorFuser:
    """Post-LLM validation, constraint enforcement, and field fusion."""

    def validate_and_fuse(
        self,
        llm_projection: dict[str, Any],
        *,
        rule_fallback: dict[str, Any] | None = None,
        allow_field_fusion: bool = False,
    ) -> dict[str, Any]:
        """Validate *llm_projection* and return an enriched copy.

        Parameters
        ----------
        llm_projection:
            Dict from ``LlmStandardizationResult.model_dump()`` (or equivalent).
        rule_fallback:
            Optional dict from the old rule-based extractor.  Used only to
            fill ``"unknown"`` fields when LLM cannot determine a value.
        allow_field_fusion:
            When ``True``, rule fallback values may populate missing semantic
            fields. The default is ``False`` so the validator stays
            evidence-constrained and does not replace LLM semantics.

        Returns
        -------
        dict
            The projection with added/modified keys:
            - ``validation_findings``: list[str]
            - ``conflict_flags``: list[str]
            - ``normalization_trace``: list[str]
            - ``rule_validation_passed``: bool
        """
        rule_fallback = rule_fallback or {}
        findings: list[str] = []
        conflicts: list[str] = []
        trace: list[str] = []

        proj = dict(llm_projection)

        # --- 1. Severity level normalisation ----------------------------------
        severity = str(proj.get("severity_level", "")).strip().lower()
        if severity not in _VALID_SEVERITY_LEVELS:
            findings.append(
                f"severity_level '{severity}' invalid, defaulting to 'medium'"
            )
            severity = "medium"
            trace.append("severity_level=rule_defaulted_medium")
        proj["severity_level"] = severity

        # --- 2. Taxonomy validation -------------------------------------------
        taxonomy_items = proj.get("taxonomy_items") or []
        validated_taxonomy: list[dict[str, Any]] = []
        for idx, item in enumerate(taxonomy_items):
            tax_type = str(item.get("taxonomy_type", ""))
            tax_code = str(item.get("taxonomy_code", ""))
            if tax_type not in _VALID_TAXONOMY_TYPES:
                findings.append(
                    f"taxonomy_items[{idx}].taxonomy_type '{tax_type}' unrecognized"
                )
                continue
            if not _is_valid_taxonomy_code(tax_type, tax_code):
                findings.append(
                    f"taxonomy_items[{idx}].taxonomy_code '{tax_code}' malformed for type '{tax_type}'"
                )
                # Keep it but flag
            confidence = float(item.get("confidence_score", 0.5))
            confidence = max(0.0, min(1.0, confidence))
            validated_taxonomy.append(
                {
                    **item,
                    "confidence_score": round(confidence, 3),
                }
            )
        # Enforce exactly one primary
        primaries = [i for i, t in enumerate(validated_taxonomy) if t.get("is_primary")]
        if len(primaries) == 0 and validated_taxonomy:
            validated_taxonomy[0]["is_primary"] = True
            trace.append("taxonomy_primary=auto_assigned_first")
        elif len(primaries) > 1:
            for i in primaries[1:]:
                validated_taxonomy[i]["is_primary"] = False
            conflicts.append("taxonomy_multiple_primary_corrected")
            trace.append("taxonomy_primary=deduplicated")
        proj["taxonomy_items"] = validated_taxonomy

        # --- 3. CVSS validation -----------------------------------------------
        cvss_hint = proj.get("cvss_hint")
        if cvss_hint is not None:
            base_score = float(cvss_hint.get("base_score", 0.0))
            if not (0.0 <= base_score <= 10.0):
                findings.append(f"cvss base_score {base_score} out of range [0,10]")
                base_score = max(0.0, min(10.0, base_score))
                cvss_hint["base_score"] = base_score
            # Severity/CVSS consistency
            if severity == "low" and base_score >= 7.0:
                conflicts.append("severity_cvss_mismatch_low_vs_high_score")
            if severity == "critical" and base_score < 7.0:
                conflicts.append("severity_cvss_mismatch_critical_vs_low_score")
            proj["cvss_hint"] = cvss_hint

        # --- 4. BOM mention shape validation ----------------------------------
        bom_mentions = proj.get("bom_mentions") or []
        validated_bom: list[dict[str, Any]] = []
        seen_bom_names: set[str] = set()
        for idx, mention in enumerate(bom_mentions):
            name = str(mention.get("mentioned_name", "")).strip()
            if not name:
                findings.append(
                    f"bom_mentions[{idx}] has empty mentioned_name, dropped"
                )
                continue
            name_lower = name.lower()
            if name_lower in seen_bom_names:
                findings.append(f"bom_mentions duplicate '{name}' dropped")
                continue
            seen_bom_names.add(name_lower)
            layer = str(mention.get("component_layer", "unknown"))
            if layer not in _VALID_COMPONENT_LAYERS:
                findings.append(
                    f"bom_mentions[{idx}].component_layer '{layer}' invalid, set to 'unknown'"
                )
                mention = {**mention, "component_layer": "unknown"}
            confidence = float(mention.get("confidence_score", 0.5))
            confidence = max(0.0, min(1.0, confidence))
            validated_bom.append({**mention, "confidence_score": round(confidence, 3)})
        proj["bom_mentions"] = validated_bom

        # --- 5. Optional field-level fusion with rule fallback -----------------
        for field_name in ("canonical_name", "attack_family", "summary", "description"):
            value = str(proj.get(field_name, "")).strip()
            if value.lower() not in ("unknown", ""):
                continue
            if allow_field_fusion:
                fallback_value = str(rule_fallback.get(field_name, "")).strip()
                if fallback_value and fallback_value.lower() != "unknown":
                    proj[field_name] = fallback_value
                    trace.append(f"{field_name}=rule_fallback_substituted")
                    continue
            if value == "":
                proj[field_name] = "unknown"
                trace.append(f"{field_name}=remained_unknown")

        # --- 6. Pack results ---------------------------------------------------
        proj["validation_findings"] = findings
        proj["conflict_flags"] = conflicts
        proj["normalization_trace"] = trace
        proj["rule_validation_passed"] = len(findings) == 0

        return proj


def _is_valid_taxonomy_code(tax_type: str, tax_code: str) -> bool:
    """Check whether a taxonomy code is well-formed for its type."""
    if tax_type == "OWASP_LLM":
        return bool(_OWASP_LLM_RE.match(tax_code))
    if tax_type == "CWE":
        return bool(_CWE_RE.match(tax_code))
    if tax_type == "CAPEC":
        return bool(_CAPEC_RE.match(tax_code))
    if tax_type == "ATTACK":
        return bool(_ATTACK_RE.match(tax_code))
    return False
