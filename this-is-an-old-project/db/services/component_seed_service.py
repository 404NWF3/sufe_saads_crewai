from __future__ import annotations

from copy import deepcopy
from typing import Any

from ..repositories.component_repository import normalize_component_alias
from ..unit_of_work import UnitOfWork


def _seed(
    component_code: str,
    component_name: str,
    *,
    layer: str,
    component_type: str,
    vendor_name: str | None = None,
    modality: str | None = None,
    purl: str | None = None,
    homepage_uri: str | None = None,
    aliases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "component_code": component_code,
        "component_name": component_name,
        "layer": layer,
        "component_type": component_type,
        "vendor_name": vendor_name,
        "modality": modality,
        "purl": purl,
        "homepage_uri": homepage_uri,
        "aliases": aliases or [],
    }


_VENDOR_PLATFORM_SEEDS: list[dict[str, Any]] = [
    _seed(
        "CMP-OPENAI-API",
        "OpenAI API",
        layer="vendor_platform",
        component_type="agent_tool",
        vendor_name="OpenAI",
        purl="pkg:pypi/openai",
        homepage_uri="https://platform.openai.com/",
        aliases=[
            {"alias_name": "openai sdk", "alias_type": "package", "is_preferred": True},
            {"alias_name": "openai python", "alias_type": "package"},
            {"alias_name": "chatgpt api", "alias_type": "common"},
            {"alias_name": "open ai api", "alias_type": "vendor"},
        ],
    ),
    _seed(
        "CMP-OPENAI-AGENTS",
        "OpenAI Agents SDK",
        layer="vendor_platform",
        component_type="agent_tool",
        vendor_name="OpenAI",
        purl="pkg:pypi/openai-agents",
        homepage_uri="https://openai.github.io/openai-agents-python/",
        aliases=[
            {
                "alias_name": "openai agents",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "openai agents sdk", "alias_type": "package"},
        ],
    ),
    _seed(
        "CMP-AZURE-OPENAI",
        "Azure OpenAI",
        layer="vendor_platform",
        component_type="agent_tool",
        vendor_name="Microsoft",
        purl="pkg:pypi/openai",
        homepage_uri="https://azure.microsoft.com/products/ai-services/openai-service",
        aliases=[
            {
                "alias_name": "azure openai service",
                "alias_type": "vendor",
                "is_preferred": True,
            },
            {"alias_name": "azure open ai", "alias_type": "vendor"},
            {"alias_name": "azure openai sdk", "alias_type": "package"},
        ],
    ),
    _seed(
        "CMP-ANTHROPIC-API",
        "Anthropic API",
        layer="vendor_platform",
        component_type="agent_tool",
        vendor_name="Anthropic",
        purl="pkg:pypi/anthropic",
        homepage_uri="https://www.anthropic.com/api",
        aliases=[
            {"alias_name": "claude api", "alias_type": "common", "is_preferred": True},
            {"alias_name": "claude sdk", "alias_type": "package"},
            {"alias_name": "anthropic sdk", "alias_type": "package"},
        ],
    ),
    _seed(
        "CMP-GEMINI-API",
        "Google Gemini API",
        layer="vendor_platform",
        component_type="agent_tool",
        vendor_name="Google",
        purl="pkg:pypi/google-generativeai",
        homepage_uri="https://ai.google.dev/",
        aliases=[
            {"alias_name": "gemini api", "alias_type": "common", "is_preferred": True},
            {"alias_name": "google ai studio", "alias_type": "vendor"},
            {"alias_name": "google generative ai", "alias_type": "package"},
        ],
    ),
    _seed(
        "CMP-VERTEX-AI",
        "Vertex AI",
        layer="vendor_platform",
        component_type="agent_tool",
        vendor_name="Google",
        purl="pkg:pypi/google-cloud-aiplatform",
        homepage_uri="https://cloud.google.com/vertex-ai",
        aliases=[
            {
                "alias_name": "vertex ai studio",
                "alias_type": "vendor",
                "is_preferred": True,
            },
            {"alias_name": "google vertex ai", "alias_type": "vendor"},
            {"alias_name": "vertex ai api", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-BEDROCK",
        "Amazon Bedrock",
        layer="vendor_platform",
        component_type="agent_tool",
        vendor_name="AWS",
        purl="pkg:pypi/boto3",
        homepage_uri="https://aws.amazon.com/bedrock/",
        aliases=[
            {"alias_name": "bedrock api", "alias_type": "common", "is_preferred": True},
            {"alias_name": "amazon bedrock", "alias_type": "vendor"},
            {"alias_name": "aws bedrock", "alias_type": "vendor"},
        ],
    ),
    _seed(
        "CMP-MISTRAL-API",
        "Mistral API",
        layer="vendor_platform",
        component_type="agent_tool",
        vendor_name="Mistral",
        purl="pkg:pypi/mistralai",
        homepage_uri="https://docs.mistral.ai/",
        aliases=[
            {
                "alias_name": "mistral sdk",
                "alias_type": "package",
                "is_preferred": True,
            },
            {"alias_name": "mistral api", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-OLLAMA",
        "Ollama",
        layer="vendor_platform",
        component_type="agent_tool",
        vendor_name="Ollama",
        purl="pkg:generic/ollama",
        homepage_uri="https://ollama.com/",
        aliases=[
            {
                "alias_name": "ollama server",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "ollama api", "alias_type": "common"},
        ],
    ),
]


_MODEL_FAMILY_SEEDS: list[dict[str, Any]] = [
    _seed(
        "CMP-QWEN",
        "Qwen",
        layer="model_family",
        component_type="model",
        vendor_name="Alibaba",
        modality="text",
        homepage_uri="https://qwenlm.github.io/",
        aliases=[
            {"alias_name": "qwen model", "alias_type": "common", "is_preferred": True},
            {"alias_name": "tongyi qianwen", "alias_type": "research_name"},
        ],
    ),
    _seed(
        "CMP-DEEPSEEK",
        "DeepSeek",
        layer="model_family",
        component_type="model",
        vendor_name="DeepSeek",
        modality="text",
        homepage_uri="https://www.deepseek.com/",
        aliases=[
            {
                "alias_name": "deepseek model",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "deep seek", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-LLAMA-MODELS",
        "Llama Models",
        layer="model_family",
        component_type="model",
        vendor_name="Meta",
        modality="text",
        homepage_uri="https://www.llama.com/",
        aliases=[
            {"alias_name": "meta llama", "alias_type": "vendor", "is_preferred": True},
            {"alias_name": "llama 3", "alias_type": "research_name"},
            {"alias_name": "llama 2", "alias_type": "research_name"},
        ],
    ),
    _seed(
        "CMP-GEMMA",
        "Gemma",
        layer="model_family",
        component_type="model",
        vendor_name="Google",
        modality="text",
        homepage_uri="https://ai.google.dev/gemma",
        aliases=[
            {"alias_name": "gemma model", "alias_type": "common", "is_preferred": True},
            {"alias_name": "google gemma", "alias_type": "vendor"},
        ],
    ),
    _seed(
        "CMP-MISTRAL-MODELS",
        "Mistral Models",
        layer="model_family",
        component_type="model",
        vendor_name="Mistral",
        modality="text",
        homepage_uri="https://mistral.ai/",
        aliases=[
            {
                "alias_name": "mistral model",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "mixtral", "alias_type": "research_name"},
        ],
    ),
]


_FRAMEWORK_SEEDS: list[dict[str, Any]] = [
    _seed(
        "CMP-LANGCHAIN",
        "LangChain",
        layer="framework",
        component_type="framework",
        vendor_name="LangChain",
        purl="pkg:pypi/langchain",
        homepage_uri="https://www.langchain.com/",
        aliases=[
            {"alias_name": "lang chain", "alias_type": "common", "is_preferred": True},
            {"alias_name": "langchain-core", "alias_type": "package"},
            {"alias_name": "langchain community", "alias_type": "package"},
            {"alias_name": "langchain python", "alias_type": "package"},
        ],
    ),
    _seed(
        "CMP-LLAMAINDEX",
        "LlamaIndex",
        layer="framework",
        component_type="framework",
        purl="pkg:pypi/llama-index",
        homepage_uri="https://www.llamaindex.ai/",
        aliases=[
            {"alias_name": "llama index", "alias_type": "common", "is_preferred": True},
            {"alias_name": "gpt index", "alias_type": "research_name"},
            {"alias_name": "llamaindex python", "alias_type": "package"},
        ],
    ),
    _seed(
        "CMP-CREWAI",
        "CrewAI",
        layer="framework",
        component_type="framework",
        vendor_name="CrewAI",
        purl="pkg:pypi/crewai",
        homepage_uri="https://www.crewai.com/",
        aliases=[
            {"alias_name": "crew ai", "alias_type": "common", "is_preferred": True},
            {"alias_name": "crewai framework", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-AUTOGEN",
        "AutoGen",
        layer="framework",
        component_type="framework",
        vendor_name="Microsoft",
        purl="pkg:pypi/autogen-agentchat",
        homepage_uri="https://microsoft.github.io/autogen/",
        aliases=[
            {
                "alias_name": "microsoft autogen",
                "alias_type": "vendor",
                "is_preferred": True,
            },
            {"alias_name": "autogen framework", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-HF-TRANSFORMERS",
        "HuggingFace Transformers",
        layer="framework",
        component_type="framework",
        vendor_name="HuggingFace",
        purl="pkg:pypi/transformers",
        homepage_uri="https://huggingface.co/docs/transformers",
        aliases=[
            {
                "alias_name": "transformers",
                "alias_type": "package",
                "is_preferred": True,
            },
            {"alias_name": "hf transformers", "alias_type": "package"},
            {"alias_name": "transformers library", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-VLLM",
        "vLLM",
        layer="framework",
        component_type="framework",
        purl="pkg:pypi/vllm",
        homepage_uri="https://docs.vllm.ai/",
        aliases=[
            {"alias_name": "vllm", "alias_type": "package", "is_preferred": True},
            {"alias_name": "vllm runtime", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-LITELLM",
        "LiteLLM",
        layer="framework",
        component_type="framework",
        purl="pkg:pypi/litellm",
        homepage_uri="https://www.litellm.ai/",
        aliases=[
            {"alias_name": "lite llm", "alias_type": "common", "is_preferred": True},
            {"alias_name": "litellm proxy", "alias_type": "common"},
        ],
    ),
]


_PLUGIN_SEEDS: list[dict[str, Any]] = [
    _seed(
        "CMP-RETRIEVAL-PLUGIN",
        "Retrieval Plugin",
        layer="plugin",
        component_type="plugin",
        homepage_uri="https://platform.openai.com/docs/plugins",
        aliases=[
            {
                "alias_name": "retrieval plugin",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "plugin", "alias_type": "common"},
            {"alias_name": "tooling layer", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-OPENAI-PLUGINS",
        "OpenAI Plugins",
        layer="plugin",
        component_type="plugin",
        vendor_name="OpenAI",
        homepage_uri="https://platform.openai.com/docs/plugins",
        aliases=[
            {
                "alias_name": "chatgpt plugins",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "openai plugins", "alias_type": "vendor"},
        ],
    ),
    _seed(
        "CMP-MCP",
        "Model Context Protocol",
        layer="plugin",
        component_type="plugin",
        homepage_uri="https://modelcontextprotocol.io/",
        aliases=[
            {"alias_name": "mcp server", "alias_type": "common", "is_preferred": True},
            {"alias_name": "model context protocol", "alias_type": "research_name"},
            {"alias_name": "mcp tool", "alias_type": "common"},
        ],
    ),
]


_RUNTIME_SEEDS: list[dict[str, Any]] = [
    _seed(
        "CMP-LANGGRAPH",
        "LangGraph",
        layer="runtime",
        component_type="framework",
        vendor_name="LangChain",
        purl="pkg:pypi/langgraph",
        homepage_uri="https://www.langchain.com/langgraph",
        aliases=[
            {"alias_name": "lang graph", "alias_type": "common", "is_preferred": True},
            {"alias_name": "langgraph runtime", "alias_type": "common"},
            {"alias_name": "langgraph python", "alias_type": "package"},
        ],
    ),
    _seed(
        "CMP-LANGSMITH",
        "LangSmith",
        layer="runtime",
        component_type="agent_tool",
        vendor_name="LangChain",
        purl="pkg:pypi/langsmith",
        homepage_uri="https://www.langchain.com/langsmith",
        aliases=[
            {
                "alias_name": "langsmith tracing",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "langsmith sdk", "alias_type": "package"},
        ],
    ),
    _seed(
        "CMP-LLAMAPARSE",
        "LlamaParse",
        layer="runtime",
        component_type="agent_tool",
        vendor_name="LlamaIndex",
        homepage_uri="https://www.llamaindex.ai/llamaparse",
        aliases=[
            {"alias_name": "llama parse", "alias_type": "common", "is_preferred": True},
            {"alias_name": "llamaparse api", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-AGENT-TOOLS",
        "Agent Tools",
        layer="runtime",
        component_type="agent_tool",
        aliases=[
            {"alias_name": "agent tool", "alias_type": "common", "is_preferred": True},
            {"alias_name": "tool calling", "alias_type": "common"},
            {"alias_name": "function calling", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-SEMANTIC-KERNEL",
        "Semantic Kernel",
        layer="runtime",
        component_type="framework",
        vendor_name="Microsoft",
        purl="pkg:pypi/semantic-kernel",
        homepage_uri="https://learn.microsoft.com/semantic-kernel/overview/",
        aliases=[
            {
                "alias_name": "semantic kernel",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "microsoft semantic kernel", "alias_type": "vendor"},
        ],
    ),
]


_VECTOR_STACK_SEEDS: list[dict[str, Any]] = [
    _seed(
        "CMP-QDRANT",
        "Qdrant",
        layer="vector_stack",
        component_type="vector_db",
        vendor_name="Qdrant",
        purl="pkg:pypi/qdrant-client",
        homepage_uri="https://qdrant.tech/",
        aliases=[
            {
                "alias_name": "qdrant vector db",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "qdrant client", "alias_type": "package"},
        ],
    ),
    _seed(
        "CMP-PINECONE",
        "Pinecone",
        layer="vector_stack",
        component_type="vector_db",
        vendor_name="Pinecone",
        purl="pkg:pypi/pinecone",
        homepage_uri="https://www.pinecone.io/",
        aliases=[
            {
                "alias_name": "pinecone vector db",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "pinecone index", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-WEAVIATE",
        "Weaviate",
        layer="vector_stack",
        component_type="vector_db",
        vendor_name="Weaviate",
        purl="pkg:pypi/weaviate-client",
        homepage_uri="https://weaviate.io/",
        aliases=[
            {
                "alias_name": "weaviate vector db",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "weaviate cluster", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-CHROMA",
        "Chroma",
        layer="vector_stack",
        component_type="vector_db",
        vendor_name="Chroma",
        purl="pkg:pypi/chromadb",
        homepage_uri="https://www.trychroma.com/",
        aliases=[
            {"alias_name": "chromadb", "alias_type": "package", "is_preferred": True},
            {"alias_name": "chroma db", "alias_type": "common"},
        ],
    ),
    _seed(
        "CMP-MILVUS",
        "Milvus",
        layer="vector_stack",
        component_type="vector_db",
        vendor_name="Zilliz",
        purl="pkg:pypi/pymilvus",
        homepage_uri="https://milvus.io/",
        aliases=[
            {
                "alias_name": "milvus vector db",
                "alias_type": "common",
                "is_preferred": True,
            },
            {"alias_name": "zilliz milvus", "alias_type": "vendor"},
        ],
    ),
    _seed(
        "CMP-FAISS",
        "FAISS",
        layer="vector_stack",
        component_type="agent_tool",
        vendor_name="Meta",
        purl="pkg:pypi/faiss-cpu",
        homepage_uri="https://github.com/facebookresearch/faiss",
        aliases=[
            {
                "alias_name": "facebook faiss",
                "alias_type": "vendor",
                "is_preferred": True,
            },
            {"alias_name": "faiss index", "alias_type": "common"},
        ],
    ),
]


_DEFAULT_COMPONENT_SEEDS: list[dict[str, Any]] = [
    *_VENDOR_PLATFORM_SEEDS,
    *_MODEL_FAMILY_SEEDS,
    *_FRAMEWORK_SEEDS,
    *_PLUGIN_SEEDS,
    *_RUNTIME_SEEDS,
    *_VECTOR_STACK_SEEDS,
]


class AiComponentSeedService:
    _bootstrapped_signatures: set[int] = set()

    def __init__(
        self, uow: UnitOfWork, *, seeds: list[dict[str, Any]] | None = None
    ) -> None:
        self.uow = uow
        self.seeds = deepcopy(seeds or _DEFAULT_COMPONENT_SEEDS)

    @classmethod
    def default_seeds(cls) -> list[dict[str, Any]]:
        return deepcopy(_DEFAULT_COMPONENT_SEEDS)

    def ensure_seeded(
        self, *, trace_id: str | None = None, force: bool = False
    ) -> dict[str, Any]:
        signature = id(self.uow.conn)
        if not force and signature in self._bootstrapped_signatures:
            return {"seeded_components": 0, "seeded_aliases": 0, "skipped": True}
        report = self.bootstrap(force=force)
        self._bootstrapped_signatures.add(signature)
        return report

    def bootstrap(self, *, force: bool = False) -> dict[str, Any]:
        seeded_components = 0
        seeded_aliases = 0
        for seed in self.seeds:
            component = self.uow.components.upsert_component(
                component_code=seed["component_code"],
                component_name=seed["component_name"],
                component_layer=seed.get("layer"),
                vendor_name=seed.get("vendor_name"),
                component_type=seed["component_type"],
                modality=seed.get("modality"),
                purl=seed.get("purl"),
                homepage_uri=seed.get("homepage_uri"),
                lifecycle_status=seed.get("lifecycle_status", "active"),
            )
            seeded_components += 1
            canonical_aliases = [
                {
                    "alias_name": seed["component_name"],
                    "alias_type": "common",
                    "is_preferred": True,
                },
                *seed.get("aliases", []),
                *self._derived_aliases(seed),
            ]
            seen_aliases: set[str] = set()
            for alias in canonical_aliases:
                normalized_alias = normalize_component_alias(
                    alias["alias_name"],
                    seed.get("vendor_name")
                    if alias.get("alias_type") == "vendor"
                    else None,
                )
                if not normalized_alias or normalized_alias in seen_aliases:
                    continue
                seen_aliases.add(normalized_alias)
                self.uow.components.upsert_component_alias(
                    component_id=str(component.component_id),
                    alias_name=alias["alias_name"],
                    alias_type=alias.get("alias_type", "common"),
                    normalized_alias=normalized_alias,
                    vendor_name=seed.get("vendor_name"),
                    is_preferred=bool(alias.get("is_preferred", False)),
                )
                seeded_aliases += 1
        return {
            "seeded_components": seeded_components,
            "seeded_aliases": seeded_aliases,
            "skipped": False,
        }

    def _derived_aliases(self, seed: dict[str, Any]) -> list[dict[str, Any]]:
        component_name = str(seed["component_name"])
        vendor_name = seed.get("vendor_name")
        aliases: list[dict[str, Any]] = []
        lower_name = component_name.lower()
        if seed.get("component_type") == "agent_tool" and "api" not in lower_name:
            aliases.append(
                {"alias_name": f"{component_name} api", "alias_type": "common"}
            )
            aliases.append(
                {"alias_name": f"{component_name} sdk", "alias_type": "package"}
            )
        if seed.get("component_type") == "framework":
            aliases.append(
                {"alias_name": f"{component_name} framework", "alias_type": "common"}
            )
            aliases.append(
                {"alias_name": f"{component_name} runtime", "alias_type": "common"}
            )
        if seed.get("component_type") == "vector_db":
            aliases.append(
                {"alias_name": f"{component_name} vector db", "alias_type": "common"}
            )
            aliases.append(
                {"alias_name": f"{component_name} database", "alias_type": "common"}
            )
        if vendor_name:
            aliases.append(
                {
                    "alias_name": f"{vendor_name} {component_name}",
                    "alias_type": "vendor",
                }
            )
        return aliases
