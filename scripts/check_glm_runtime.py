from __future__ import annotations

import argparse
import json
from typing import Any

from pydantic import BaseModel

from sufe_saads_crewai.llms import (
    build_glm_llm,
    configure_glm_runtime,
    describe_glm_runtime,
)


class DiagnosticResponse(BaseModel):
    ok: bool
    model_family: str
    message: str


def _coerce_response(value: Any) -> DiagnosticResponse:
    if isinstance(value, DiagnosticResponse):
        return value
    if isinstance(value, str):
        return DiagnosticResponse.model_validate_json(value)
    return DiagnosticResponse.model_validate(value)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify that CrewAI can call the GLM model configured in .env."
    )
    parser.add_argument(
        "--profile",
        choices=["main", "fast", "cheap_fast"],
        default="fast",
        help="GLM profile to test.",
    )
    args = parser.parse_args()

    runtime = configure_glm_runtime(enable_agent_kickoff=True)
    llm = build_glm_llm(args.profile)
    print(describe_glm_runtime())
    print(
        json.dumps(
            {
                "profile": args.profile,
                "model": getattr(llm, "model", None),
                "base_url": getattr(llm, "base_url", None)
                or getattr(llm, "api_base", None),
                "timeout": getattr(llm, "timeout", None),
                "max_retries": getattr(llm, "max_retries", None),
                "agent_kickoff": runtime["agent_kickoff"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    result = llm.call(
        [
            {
                "role": "user",
                "content": (
                    "Return only JSON matching this schema: "
                    '{"ok": true, "model_family": "glm", "message": "pong"}'
                ),
            }
        ],
        response_model=DiagnosticResponse,
    )
    parsed = _coerce_response(result)
    print(parsed.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
