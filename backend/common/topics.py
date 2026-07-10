"""Shared LLM-security topic taxonomy (Core + Extended).

Only topic constants and pure helpers live here. No dependency on intel_agent
or ctinexus_kg — both packages import from this module.
"""

from __future__ import annotations

import re

# Coverage / critic hard targets (full mode open_gaps).
CORE_SECURITY_TOPICS: list[str] = [
    "prompt injection",
    "jailbreak",
    "agent tool abuse",
    "data leakage",
    "model supply chain",
    "rag poisoning",
    "insecure output handling",
    "excessive agency",
    "model denial of service",
    "unbounded consumption",
    "model backdoor",
    "agent loop and cascading failure",
    "multi-agent communication attack",
    "unsafe code generation and execution",
    "sandbox escape",
    "plugin and mcp trust attack",
    "authentication and authorization bypass",
    "unsafe file handling",
]

# Searchable / labelable topics beyond Core (do not drive coverage quotas).
EXTENDED_SECURITY_TOPICS: list[str] = [
    "training and fine-tuning data poisoning",
    "adversarial examples",
    "model extraction",
    "membership inference",
    "model inversion",
    "training data extraction",
    "system prompt leakage",
    "context isolation failure",
    "memory poisoning",
    "agent impersonation",
    "server-side request forgery",
    "internal network reconnaissance",
    "misinformation and citation fabrication",
    "insufficient logging and monitoring",
    "model routing and downgrade attack",
]

ALL_SECURITY_TOPICS: list[str] = list(CORE_SECURITY_TOPICS) + list(EXTENDED_SECURITY_TOPICS)

# Backward-compatible alias: historically meant "all searchable topics".
TARGET_SECURITY_TOPICS: list[str] = list(ALL_SECURITY_TOPICS)

TOPIC_KEYWORDS: dict[str, tuple[str, ...]] = {
    "prompt injection": (
        "prompt injection",
        "indirect prompt",
        "instruction injection",
        "prompt override",
    ),
    "jailbreak": (
        "jailbreak",
        "policy bypass",
        "guardrail bypass",
        "dan prompt",
        "safety bypass",
    ),
    "agent tool abuse": (
        "agent tool",
        "tool abuse",
        "plugin abuse",
        "function calling",
        "tool invocation attack",
        "confused deputy",
    ),
    "data leakage": (
        "data leakage",
        "secret exfiltration",
        "pii leak",
        "cross-tenant",
        "sensitive data exposure",
    ),
    "model supply chain": (
        "model supply chain",
        "model artifact",
        "unsafe model",
        "pickle",
        "model hub",
        "malicious model",
        "supply chain vulnerability",
    ),
    "rag poisoning": (
        "rag poisoning",
        "retrieval poisoning",
        "knowledge base poisoning",
        "vector database poison",
        "embedding poison",
    ),
    "insecure output handling": (
        "insecure output handling",
        "llm output injection",
        "xss via llm",
        "unsanitized model output",
        "output handling",
    ),
    "excessive agency": (
        "excessive agency",
        "over-permissioned agent",
        "unrestricted agent",
        "agent autonomy abuse",
    ),
    "model denial of service": (
        "model denial of service",
        "llm dos",
        "model dos",
        "resource exhaustion llm",
        "context flooding",
    ),
    "unbounded consumption": (
        "unbounded consumption",
        "token exhaustion",
        "runaway token",
        "cost amplification",
        "quota abuse llm",
    ),
    "model backdoor": (
        "model backdoor",
        "trojaned model",
        "backdoored llm",
        "sleeper agent model",
        "trigger phrase backdoor",
    ),
    "agent loop and cascading failure": (
        "agent loop",
        "cascading failure",
        "infinite agent loop",
        "recursive agent",
        "runaway agent",
    ),
    "multi-agent communication attack": (
        "multi-agent",
        "agent communication attack",
        "inter-agent",
        "agent message injection",
        "swarm attack",
    ),
    "unsafe code generation and execution": (
        "unsafe code generation",
        "code execution",
        "llm generated malware",
        "execute generated code",
        "eval generated code",
    ),
    "sandbox escape": (
        "sandbox escape",
        "container escape",
        "jail escape llm",
        "breakout sandbox",
    ),
    "plugin and mcp trust attack": (
        "mcp trust",
        "mcp attack",
        "plugin trust",
        "malicious mcp",
        "tool server compromise",
        "model context protocol",
    ),
    "authentication and authorization bypass": (
        "auth bypass",
        "authorization bypass",
        "authentication bypass",
        "privilege escalation llm",
        "broken access control llm",
    ),
    "unsafe file handling": (
        "unsafe file handling",
        "path traversal llm",
        "arbitrary file read",
        "file upload llm",
        "insecure file access",
    ),
    "training and fine-tuning data poisoning": (
        "training data poisoning",
        "fine-tuning poison",
        "finetune poison",
        "poisoned dataset",
        "data poisoning attack",
    ),
    "adversarial examples": (
        "adversarial example",
        "adversarial attack",
        "adversarial prompt",
        "input perturbation",
    ),
    "model extraction": (
        "model extraction",
        "model stealing",
        "functionality extraction",
        "api model theft",
    ),
    "membership inference": (
        "membership inference",
        "membership attack",
        "training set membership",
    ),
    "model inversion": (
        "model inversion",
        "inversion attack",
        "reconstruct training",
    ),
    "training data extraction": (
        "training data extraction",
        "memorization attack",
        "extract training data",
        "verbatim memorization",
    ),
    "system prompt leakage": (
        "system prompt leak",
        "system prompt leakage",
        "prompt disclosure",
        "reveal system prompt",
    ),
    "context isolation failure": (
        "context isolation",
        "cross-context leak",
        "session isolation failure",
        "tenant isolation llm",
    ),
    "memory poisoning": (
        "memory poisoning",
        "agent memory poison",
        "long-term memory attack",
        "memory injection",
    ),
    "agent impersonation": (
        "agent impersonation",
        "spoofed agent",
        "fake agent identity",
    ),
    "server-side request forgery": (
        "ssrf",
        "server-side request forgery",
        "llm ssrf",
    ),
    "internal network reconnaissance": (
        "internal network reconnaissance",
        "network recon llm",
        "internal scanning agent",
        "lateral movement llm",
    ),
    "misinformation and citation fabrication": (
        "citation fabrication",
        "hallucinated citation",
        "misinformation llm",
        "fabricated reference",
    ),
    "insufficient logging and monitoring": (
        "insufficient logging",
        "llm monitoring",
        "audit trail llm",
        "undetected llm abuse",
    ),
    "model routing and downgrade attack": (
        "model routing",
        "model downgrade",
        "router attack",
        "force weaker model",
    ),
}

TOPIC_ANCHORS: dict[str, list[str]] = {
    "prompt injection": [
        "An attacker embeds malicious instructions in content that a large language model processes, overriding the system prompt.",
        "Indirect prompt injection hides adversarial instructions in web pages, documents, or tool outputs consumed by an LLM application.",
    ],
    "jailbreak": [
        "A jailbreak prompt bypasses the safety alignment of a large language model to elicit prohibited content.",
        "Adversarial prompting techniques defeat refusal behavior and guardrails of aligned chat models.",
    ],
    "agent tool abuse": [
        "An autonomous LLM agent is tricked into invoking dangerous tools such as shell commands or code execution.",
        "A confused-deputy attack abuses the permissions of an AI agent's plugins, function calling, or MCP servers.",
    ],
    "data leakage": [
        "A large language model leaks sensitive training data, secrets, or personal information in its responses.",
        "Cross-tenant or session data exposure occurs in an LLM application, revealing other users' prompts or documents.",
    ],
    "model supply chain": [
        "Malicious or tampered model artifacts execute code on load, for example through unsafe pickle deserialization.",
        "A compromised package or model hub distribution channel delivers backdoored AI components.",
    ],
    "rag poisoning": [
        "An attacker poisons the document corpus or vector database of a retrieval-augmented generation system to manipulate answers.",
        "Embedding or knowledge-base poisoning injects adversarial passages that are retrieved and trusted by an LLM.",
    ],
    "insecure output handling": [
        "Downstream systems execute or render unsanitized LLM output, enabling XSS, command injection, or privilege abuse.",
        "Insecure output handling treats model text as trusted without validation or encoding.",
    ],
    "excessive agency": [
        "An LLM agent is granted excessive permissions and takes high-impact actions without adequate human oversight.",
        "Over-permissioned tool access lets an agent modify production systems beyond the intended scope.",
    ],
    "model denial of service": [
        "Adversarial inputs exhaust model or serving resources, causing denial of service for legitimate users.",
        "Context flooding and pathological prompts degrade latency or availability of an LLM endpoint.",
    ],
    "unbounded consumption": [
        "Attackers force unbounded token usage or recursive tool calls that amplify cloud cost and quota burn.",
        "Missing rate limits allow runaway consumption of LLM inference budget.",
    ],
    "model backdoor": [
        "A trojaned or backdoored model activates malicious behavior when a hidden trigger phrase appears.",
        "Supply-chain or fine-tuning backdoors implant sleeper behaviors into deployed LLMs.",
    ],
    "agent loop and cascading failure": [
        "Agents enter infinite planning or tool loops that cascade into system-wide failure.",
        "Recursive multi-step agent workflows amplify errors until the session collapses.",
    ],
    "multi-agent communication attack": [
        "Malicious messages between agents inject instructions or corrupt shared plans in a multi-agent system.",
        "Inter-agent channels are abused to spread compromised goals across a swarm.",
    ],
    "unsafe code generation and execution": [
        "An LLM generates and executes unsafe code that compromises the host or exfiltrates data.",
        "Automatic execution of model-written scripts enables remote code execution via the agent.",
    ],
    "sandbox escape": [
        "Code or tools invoked by an LLM agent escape the intended sandbox or container isolation.",
        "Sandbox breakout turns a constrained agent runtime into host-level compromise.",
    ],
    "plugin and mcp trust attack": [
        "A malicious MCP server or plugin abuses trust to steal context, escalate tools, or alter agent behavior.",
        "Compromised tool servers in the Model Context Protocol path become a confused-deputy channel.",
    ],
    "authentication and authorization bypass": [
        "LLM-mediated workflows bypass authentication or authorization checks through prompt or tool abuse.",
        "Broken access control in agent apps lets users reach privileged actions via crafted requests.",
    ],
    "unsafe file handling": [
        "Agents read or write arbitrary files through path traversal or unsafe upload handling.",
        "LLM tool file APIs expose sensitive host paths without adequate validation.",
    ],
    "training and fine-tuning data poisoning": [
        "Poisoned fine-tuning or pretraining data implants targeted behaviors into the resulting model.",
        "Adversaries contaminate datasets used to train or align large language models.",
    ],
    "adversarial examples": [
        "Small input perturbations cause large language or multimodal models to misclassify or misbehave.",
        "Adversarial examples craft near-imperceptible changes that defeat model robustness.",
    ],
    "model extraction": [
        "Attackers query an API repeatedly to steal or approximate a proprietary model's functionality.",
        "Model extraction reconstructs decision boundaries from black-box access.",
    ],
    "membership inference": [
        "Membership inference determines whether a specific record was in the model's training set.",
        "Privacy attacks infer training-set membership from model confidence patterns.",
    ],
    "model inversion": [
        "Model inversion reconstructs sensitive training attributes or examples from model outputs.",
        "Inversion attacks recover private information encoded in model parameters or responses.",
    ],
    "training data extraction": [
        "Training data extraction recovers verbatim memorized text from a deployed language model.",
        "Memorization attacks elicit confidential documents that were present in training data.",
    ],
    "system prompt leakage": [
        "Users coerce the model into revealing hidden system prompts or developer instructions.",
        "System prompt leakage discloses proprietary policies and tool configurations.",
    ],
    "context isolation failure": [
        "Failures in context isolation leak data across users, tenants, or sessions in an LLM app.",
        "Shared caches or windows mix confidential contexts between unrelated conversations.",
    ],
    "memory poisoning": [
        "Attackers poison an agent's long-term memory so future sessions follow malicious instructions.",
        "Persistent memory stores become a durable channel for prompt injection.",
    ],
    "agent impersonation": [
        "An attacker spoofs agent identity to issue trusted commands inside a multi-agent system.",
        "Agent impersonation abuses weak identity binding between collaborating agents.",
    ],
    "server-side request forgery": [
        "LLM tools that fetch URLs are abused for SSRF against internal services.",
        "Server-side request forgery via agent browsing reaches cloud metadata or intranet hosts.",
    ],
    "internal network reconnaissance": [
        "Compromised agents scan internal networks and map services beyond the intended perimeter.",
        "Tool-enabled LLMs perform reconnaissance that reveals private infrastructure.",
    ],
    "misinformation and citation fabrication": [
        "Models fabricate citations and spread misinformation that looks authoritative.",
        "Citation fabrication invents papers and URLs that do not exist.",
    ],
    "insufficient logging and monitoring": [
        "Insufficient logging leaves LLM abuse, prompt injection, and tool misuse undetectable.",
        "Missing audit trails prevent incident response for agentic systems.",
    ],
    "model routing and downgrade attack": [
        "Attackers manipulate routers to force weaker or unaligned models for sensitive tasks.",
        "Model downgrade attacks bypass stronger safety tiers by steering traffic to cheaper models.",
    ],
}

STOPWORDS = {
    "a", "about", "ai", "and", "for", "in", "large", "language", "llm", "llms",
    "model", "models", "of", "on", "or", "security", "the", "to", "with",
}


def detect_topics(text: str) -> list[str]:
    normalized = text.lower()
    return [
        topic
        for topic, keywords in TOPIC_KEYWORDS.items()
        if any(keyword in normalized for keyword in keywords)
    ]


def tokenize(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}", text.lower())
        if token not in STOPWORDS
    }


def build_gap_query(topics: list[str]) -> str:
    topic_text = " OR ".join(topics)
    return f"{topic_text} LLM vulnerability evidence advisory paper"


def is_core_topic(topic: str) -> bool:
    return topic in CORE_SECURITY_TOPICS
