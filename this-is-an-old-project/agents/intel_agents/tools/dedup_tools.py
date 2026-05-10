from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from difflib import SequenceMatcher
from typing import Any


TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-\.]{2,}")


def build_dedup_text(item: dict[str, Any]) -> str:
    parts = [
        item.get("canonical_name", ""),
        item.get("summary", ""),
        item.get("description", ""),
        item.get("attack_family", ""),
        " ".join(str(ref) for ref in item.get("evidence_refs", [])),
        " ".join(
            str(label.get("taxonomy_code", ""))
            for label in item.get("taxonomy_items", [])
        ),
        " ".join(
            str(bom.get("mentioned_name", "")) for bom in item.get("bom_mentions", [])
        ),
    ]
    return " ".join(part for part in parts if part).strip().lower()


def tokenize_text(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def compute_content_hash(item: dict[str, Any]) -> str:
    if item.get("artifact_ref"):
        return hashlib.sha256(
            f"{item.get('artifact_ref')}|{item.get('raw_id')}".encode("utf-8")
        ).hexdigest()
    return hashlib.sha256(build_dedup_text(item).encode("utf-8")).hexdigest()


def compute_simhash(text: str) -> int:
    tokens = tokenize_text(text)
    if not tokens:
        return 0
    weights = [0] * 64
    counts = Counter(tokens)
    for token, weight in counts.items():
        digest = hashlib.sha256(token.encode("utf-8")).digest()[:8]
        value = int.from_bytes(digest, "big")
        for i in range(64):
            bit = (value >> i) & 1
            weights[i] += weight if bit else -weight
    signature = 0
    for i, score in enumerate(weights):
        if score > 0:
            signature |= 1 << i
    return signature


def simhash_similarity(left: int, right: int) -> float:
    if left == right:
        return 1.0
    xor = left ^ right
    distance = xor.bit_count()
    return round(1.0 - (distance / 64.0), 4)


def compute_minhash(text: str, num_hashes: int = 16) -> list[int]:
    tokens = tokenize_text(text)
    if not tokens:
        return [0] * num_hashes
    signatures: list[int] = []
    for seed in range(num_hashes):
        minimum = None
        for token in tokens:
            value = int(
                hashlib.sha256(f"{seed}:{token}".encode("utf-8")).hexdigest()[:16], 16
            )
            minimum = value if minimum is None else min(minimum, value)
        signatures.append(minimum or 0)
    return signatures


def minhash_similarity(left: list[int], right: list[int]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    matches = sum(1 for l_val, r_val in zip(left, right) if l_val == r_val)
    return round(matches / len(left), 4)


def generate_embedding(text: str) -> list[float]:
    tokens = tokenize_text(text)
    if not tokens:
        return [0.0] * 32
    counts = Counter(tokens)
    vector = [0.0] * 32
    for token, count in counts.items():
        idx = int(hashlib.sha256(token.encode("utf-8")).hexdigest()[:2], 16) % 32
        vector[idx] += float(count)
    norm = math.sqrt(sum(val * val for val in vector)) or 1.0
    return [round(val / norm, 6) for val in vector]


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    dot = sum(l_val * r_val for l_val, r_val in zip(left, right))
    left_norm = math.sqrt(sum(l_val * l_val for l_val in left)) or 1.0
    right_norm = math.sqrt(sum(r_val * r_val for r_val in right)) or 1.0
    return round(dot / (left_norm * right_norm), 4)


def taxonomy_overlap_score(left: dict[str, Any], right: dict[str, Any]) -> float:
    left_codes = {
        item.get("taxonomy_code")
        for item in left.get("taxonomy_items", [])
        if item.get("taxonomy_code")
    }
    right_codes = {
        item.get("taxonomy_code")
        for item in right.get("taxonomy_items", [])
        if item.get("taxonomy_code")
    }
    return jaccard_score(left_codes, right_codes)


def cve_overlap_score(left: dict[str, Any], right: dict[str, Any]) -> float:
    left_cves = set(left.get("source_metadata", {}).get("cve_refs", []))
    right_cves = set(right.get("source_metadata", {}).get("cve_refs", []))
    return jaccard_score(left_cves, right_cves)


def bom_overlap_score(left: dict[str, Any], right: dict[str, Any]) -> float:
    left_bom = {
        str(item.get("mentioned_name", "")).lower()
        for item in left.get("bom_mentions", [])
        if item.get("mentioned_name")
    }
    right_bom = {
        str(item.get("mentioned_name", "")).lower()
        for item in right.get("bom_mentions", [])
        if item.get("mentioned_name")
    }
    return jaccard_score(left_bom, right_bom)


def rerank_similarity(left: dict[str, Any], right: dict[str, Any]) -> float:
    name_score = SequenceMatcher(
        None, left.get("canonical_name", ""), right.get("canonical_name", "")
    ).ratio()
    family_score = (
        1.0 if left.get("attack_family") == right.get("attack_family") else 0.0
    )
    text_score = SequenceMatcher(
        None, build_dedup_text(left), build_dedup_text(right)
    ).ratio()
    return round((name_score * 0.25) + (family_score * 0.2) + (text_score * 0.55), 4)


def jaccard_score(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return round(len(left & right) / len(left | right), 4)


def describe_bom_delta(
    left: dict[str, Any], right: dict[str, Any]
) -> tuple[bool, list[str]]:
    left_bom = {
        str(item.get("mentioned_name", "")).lower()
        for item in left.get("bom_mentions", [])
        if item.get("mentioned_name")
    }
    right_bom = {
        str(item.get("mentioned_name", "")).lower()
        for item in right.get("bom_mentions", [])
        if item.get("mentioned_name")
    }
    added = sorted(right_bom - left_bom)
    removed = sorted(left_bom - right_bom)
    reasons: list[str] = []
    if added:
        reasons.append(f"bom_added={','.join(added)}")
    if removed:
        reasons.append(f"bom_removed={','.join(removed)}")
    return bool(added or removed), reasons
