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


@dataclass
class BaseKgConfig:
    llm_model: str = "glm-4.7"
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_temperature: float = 0.1
    embedding_model: str = "text-embedding-3-large"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    source_dir: Path = field(default_factory=lambda: DEFAULT_SOURCE_DIR)
    output_dir: Path = field(default_factory=lambda: DEFAULT_OUTPUT_DIR)
    max_chunk_chars: int = 24000
    entity_redundancy_threshold: float = 0.85
    max_eval_sentences: int = 120
    request_interval: float = 5.0  # seconds between LLM/embedding requests

    @classmethod
    def from_env(cls) -> "BaseKgConfig":
        _load_dotenv()
        return cls(
            llm_model=_first_env("BASEKG_LLM_MODEL", default="glm-4.7"),
            llm_base_url=_first_env("BASEKG_LLM_BASE_URL", "OPENAI_BASE_URL", "GLM_BASE_URL"),
            llm_api_key=_first_env("BASEKG_LLM_API_KEY", "OPENAI_API_KEY", "GLM_API_KEY"),
            llm_temperature=float(_first_env("BASEKG_LLM_TEMPERATURE", default="0.1")),
            embedding_model=_first_env("BASEKG_EMBEDDING_MODEL", default="text-embedding-3-large"),
            neo4j_uri=_first_env("NEO4J_URI", default="bolt://localhost:7687"),
            neo4j_user=_first_env("NEO4J_USER", default="neo4j"),
            neo4j_password=_first_env("NEO4J_PASSWORD"),
            source_dir=Path(_first_env("BASEKG_SOURCE_DIR", default=str(DEFAULT_SOURCE_DIR))),
            output_dir=Path(_first_env("BASEKG_OUTPUT_DIR", default=str(DEFAULT_OUTPUT_DIR))),
            request_interval=float(_first_env("BASEKG_REQUEST_INTERVAL", default="5")),
        )

    @property
    def corpus_path(self) -> Path:
        return self.output_dir / "corpus.jsonl"

    @property
    def extractions_dir(self) -> Path:
        return self.output_dir / "extractions"

    @property
    def evaluation_path(self) -> Path:
        return self.output_dir / "evaluation.json"
