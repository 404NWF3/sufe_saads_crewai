"""Configuration for the standalone base-KG construction pipeline.

This module is intentionally independent from the sufe_saads_crewai package.
LLM credentials fall back in the same order as the main project:
BASEKG_* -> OPENAI_* -> GLM_*.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_KG_DIR = REPO_ROOT / "base_kg"
SCHEMA_PATH = BASE_KG_DIR / "schema" / "llm_security_schema.json"
PROMPTS_DIR = BASE_KG_DIR / "prompts"
DEFAULT_SOURCE_DIR = REPO_ROOT / "data" / "kg-source"
DEFAULT_OUTPUT_DIR = BASE_KG_DIR / "output"


def _load_dotenv(path: Path = REPO_ROOT / ".env") -> None:
    """Load .env into os.environ (existing variables win).

    The pipeline runs outside the crew entry points, so nothing else loads
    .env for us. Minimal parser to avoid a python-dotenv dependency.
    """
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and value:
            os.environ.setdefault(key, value)


def _first_env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return default


def _collect_api_keys() -> list[str]:
    """Collect the API key pool for parallel extraction.

    BASEKG_LLM_API_KEYS (comma-separated) wins; otherwise gather GLM_API_KEY
    plus GLM_API_KEY_1..9; otherwise fall back to the single resolved key.
    """
    explicit = _first_env("BASEKG_LLM_API_KEYS")
    if explicit:
        return [k.strip() for k in explicit.split(",") if k.strip()]
    keys: list[str] = []
    for name in ["GLM_API_KEY"] + [f"GLM_API_KEY_{i}" for i in range(1, 10)]:
        value = os.environ.get(name, "").strip()
        if value and value not in keys:
            keys.append(value)
    if keys:
        return keys
    single = _first_env("BASEKG_LLM_API_KEY", "OPENAI_API_KEY")
    return [single] if single else []


@dataclass
class BaseKgConfig:
    llm_model: str = "glm-4.7"
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_api_keys: list[str] = field(default_factory=list)
    llm_temperature: float = 0.1
    # Stage-specific models: fast model for NER/standardization, strong model
    # for relation extraction, cheapest for relevance filtering.
    ner_model: str = "GLM-4.7-FlashX"
    std_model: str = "GLM-4.7-FlashX"
    re_model: str = "glm-4.7"
    filter_model: str = "glm-4.7-flash"
    disable_thinking: bool = False
    concurrency: int = 8
    embedding_model: str = "text-embedding-3-large"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    source_dir: Path = field(default_factory=lambda: DEFAULT_SOURCE_DIR)
    output_dir: Path = field(default_factory=lambda: DEFAULT_OUTPUT_DIR)
    max_chunk_chars: int = 24000
    entity_redundancy_threshold: float = 0.85
    max_eval_sentences: int = 120
    request_interval: float = 2.0  # seconds between requests on the SAME key

    @classmethod
    def from_env(cls) -> "BaseKgConfig":
        _load_dotenv()
        api_key = _first_env("BASEKG_LLM_API_KEY", "OPENAI_API_KEY", "GLM_API_KEY")
        api_keys = _collect_api_keys() or ([api_key] if api_key else [])
        concurrency = int(
            _first_env("BASEKG_CONCURRENCY", default=str(min(8, 2 * max(1, len(api_keys)))))
        )
        return cls(
            llm_model=_first_env("BASEKG_LLM_MODEL", default="glm-4.7"),
            llm_base_url=_first_env("BASEKG_LLM_BASE_URL", "OPENAI_BASE_URL", "GLM_BASE_URL"),
            llm_api_key=api_key,
            llm_api_keys=api_keys,
            llm_temperature=float(_first_env("BASEKG_LLM_TEMPERATURE", default="0.1")),
            ner_model=_first_env("BASEKG_NER_MODEL", default="GLM-4.7-FlashX"),
            std_model=_first_env("BASEKG_STD_MODEL", default="GLM-4.7-FlashX"),
            re_model=_first_env("BASEKG_RE_MODEL", default="glm-4.7"),
            filter_model=_first_env("BASEKG_FILTER_MODEL", default="glm-4.7-flash"),
            disable_thinking=_first_env("BASEKG_DISABLE_THINKING", default="0").lower()
            in ("1", "true", "yes"),
            concurrency=max(1, concurrency),
            embedding_model=_first_env("BASEKG_EMBEDDING_MODEL", default="text-embedding-3-large"),
            neo4j_uri=_first_env("NEO4J_URI", default="bolt://localhost:7687"),
            neo4j_user=_first_env("NEO4J_USER", default="neo4j"),
            neo4j_password=_first_env("NEO4J_PASSWORD"),
            source_dir=Path(_first_env("BASEKG_SOURCE_DIR", default=str(DEFAULT_SOURCE_DIR))),
            output_dir=Path(_first_env("BASEKG_OUTPUT_DIR", default=str(DEFAULT_OUTPUT_DIR))),
            request_interval=float(_first_env("BASEKG_REQUEST_INTERVAL", default="2")),
        )

    @property
    def corpus_path(self) -> Path:
        return self.output_dir / "corpus.jsonl"

    @property
    def extractions_dir(self) -> Path:
        return self.output_dir / "extractions"

    @property
    def relevance_path(self) -> Path:
        return self.output_dir / "relevance.jsonl"

    @property
    def evaluation_path(self) -> Path:
        return self.output_dir / "evaluation.json"
