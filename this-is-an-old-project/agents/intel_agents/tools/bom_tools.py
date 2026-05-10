from __future__ import annotations

import re
from typing import Iterable

from backend.db.repositories.component_repository import normalize_component_alias


_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+){0,3}(?:[-_a-zA-Z0-9]+)?")


def normalize_vendor_name(vendor_name: str | None) -> str | None:
    if not vendor_name:
        return None
    cleaned = re.sub(r"[^a-z0-9]+", " ", vendor_name.lower()).strip()
    if not cleaned:
        return None
    alias_map = {
        "hf": "huggingface",
        "lang chain": "langchain",
        "open ai": "openai",
    }
    return alias_map.get(cleaned, cleaned.replace(" ", ""))


def normalize_version_constraint(version_text: str | None) -> str | None:
    if not version_text:
        return None
    raw = re.sub(r"\s+", " ", version_text.strip().lower())
    if not raw:
        return None
    compact = raw.replace(" ", "")
    if any(token in compact for token in (">", "<", "=", ",")):
        return compact
    version_match = _VERSION_TOKEN_RE.search(raw)
    if version_match is None:
        return None
    version = version_match.group(0)
    patterns = [
        (("before", "prior to", "earlier than", "older than"), f"<{version}"),
        (("through", "up to", "or earlier", "and earlier", "at most"), f"<={version}"),
        (("after", "later than", "newer than"), f">{version}"),
        (("and later", "or later", "at least", "from"), f">={version}"),
        (("fixed in", "patched in"), f">={version}"),
    ]
    for tokens, normalized in patterns:
        if any(token in raw for token in tokens):
            return normalized
    return f"=={version}"


def trigram_similarity(left: str, right: str) -> float:
    left_grams = _trigrams(left)
    right_grams = _trigrams(right)
    if not left_grams and not right_grams:
        return 1.0
    if not left_grams or not right_grams:
        return 0.0
    return round(len(left_grams & right_grams) / len(left_grams | right_grams), 4)


def normalize_aliases(*values: str | None) -> list[str]:
    normalized: list[str] = []
    for value in values:
        if not value:
            continue
        alias = normalize_component_alias(value)
        if alias and alias not in normalized:
            normalized.append(alias)
    return normalized


def best_alias_match(
    mention_aliases: Iterable[str],
    candidate_aliases: Iterable[str],
) -> tuple[str, float]:
    best_mode = "embedding"
    best_score = 0.0
    candidate_list = [alias for alias in candidate_aliases if alias]
    for mention in mention_aliases:
        for candidate in candidate_list:
            if mention == candidate:
                return "alias", 0.97
            score = trigram_similarity(mention, candidate)
            if score > best_score:
                best_mode = "trigram"
                best_score = score
    return best_mode, round(best_score, 4)


def _trigrams(value: str) -> set[str]:
    normalized = normalize_component_alias(value)
    if len(normalized) < 3:
        return {normalized} if normalized else set()
    return {normalized[idx : idx + 3] for idx in range(len(normalized) - 2)}
