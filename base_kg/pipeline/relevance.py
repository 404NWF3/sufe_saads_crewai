"""Cheap relevance pre-filter: skip documents unrelated to LLM security.

Three tiers, cheapest first:
1. category whitelist (OWASP / cnki / other corpora are curated LLM-security sources)
2. title keyword fast path (no LLM call)
3. flash-model classification on title + opening text

Decisions are appended to output/relevance.jsonl; already-decided docs are
skipped, so the stage is resumable and re-runnable.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .config import PROMPTS_DIR, BaseKgConfig
from .corpus import load_corpus
from .llm import LLMClient

WHITELIST_CATEGORIES = {"OWASP", "cnki", "other"}

_TITLE_KEYWORDS = re.compile(
    r"llm|large.?language|language.?model|foundation.?model|gpt|bert|chatbot"
    r"|prompt|jailbreak|instruction|in.?context|rlhf|alignment|agent"
    r"|大模型|大语言|智能体",
    re.IGNORECASE,
)


def load_relevance(path: Path) -> dict[str, dict]:
    decisions: dict[str, dict] = {}
    if path.is_file():
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    record = json.loads(line)
                    decisions[record["doc_id"]] = record
    return decisions


def _title_from_doc_id(doc_id: str) -> str:
    # corpus doc_ids look like "2022_Adversarial_Cheap_Talk"
    return re.sub(r"^\d{4}_+", "", doc_id).replace("_", " ").strip()


def run_filter(cfg: BaseKgConfig, limit: int | None = None) -> dict[str, int]:
    docs = load_corpus(cfg.corpus_path, limit=limit)
    decisions = load_relevance(cfg.relevance_path)
    llm = LLMClient(cfg)
    prompt_template = (PROMPTS_DIR / "relevance_filter.txt").read_text(encoding="utf-8")
    counts = {"whitelist": 0, "keyword": 0, "llm_relevant": 0, "llm_irrelevant": 0, "skipped": 0}
    cfg.relevance_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg.relevance_path, "a", encoding="utf-8") as fh:
        for doc in docs:
            if doc["doc_id"] in decisions:
                counts["skipped"] += 1
                continue
            title = _title_from_doc_id(doc["doc_id"])
            if doc["category"] in WHITELIST_CATEGORIES:
                record = {
                    "doc_id": doc["doc_id"],
                    "relevant": True,
                    "method": "category_whitelist",
                    "reason": f"curated category: {doc['category']}",
                }
                counts["whitelist"] += 1
            elif _TITLE_KEYWORDS.search(title):
                record = {
                    "doc_id": doc["doc_id"],
                    "relevant": True,
                    "method": "title_keyword",
                    "reason": "title matches LLM-security keywords",
                }
                counts["keyword"] += 1
            else:
                prompt = prompt_template.replace("[[TITLE]]", title).replace(
                    "[[SNIPPET]]", doc["text"][:1500]
                )
                try:
                    verdict = llm.chat_json(prompt, model=cfg.filter_model)
                except Exception as exc:  # noqa: BLE001 - undecided docs stay extractable
                    print(f"[filter] failed (left undecided): {doc['doc_id']}: {exc}")
                    continue
                relevant = bool(verdict.get("relevant", True))
                record = {
                    "doc_id": doc["doc_id"],
                    "relevant": relevant,
                    "method": "llm_filter",
                    "reason": str(verdict.get("reason", ""))[:300],
                }
                counts["llm_relevant" if relevant else "llm_irrelevant"] += 1
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
    return counts
