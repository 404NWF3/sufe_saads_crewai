"""Offline smoke: ctinexus_kg pipeline + TraceSink callback + import boundaries."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


def _check_imports() -> None:
    import ctinexus_kg
    import intel_agent
    from ctinexus_kg import generate_for_run
    from intel_agent.observability import TraceSink

    assert ctinexus_kg is not None
    assert intel_agent is not None
    assert callable(generate_for_run)
    assert TraceSink is not None
    # Boundary: no runtime import of the other backend package
    assert "intel_agent" not in getattr(ctinexus_kg, "__dict__", {})
    import ctinexus_kg.pipeline as pipe

    text = Path(pipe.__file__).read_text(encoding="utf-8")
    import_lines = [
        line for line in text.splitlines()
        if line.lstrip().startswith(("import ", "from "))
    ]
    joined = "\n".join(import_lines)
    assert "intel_agent" not in joined
    assert "sufe_saads" not in joined


def _check_kg_pipeline() -> None:
    from ctinexus_kg import KgGenerationConfig, RawIntelItem, generate_for_run

    with TemporaryDirectory() as tmp:
        def fake(**kwargs):
            out = Path(kwargs["output"])
            payload = {
                "IE": {"triplets": [{"subject": "a", "relation": "r", "object": "b"}]},
                "EA": {"aligned_triplets": []},
                "LP": {"predicted_links": []},
            }
            out.write_text(json.dumps(payload), encoding="utf-8")
            return payload

        item = RawIntelItem(
            item_id="nvd:smoke",
            source_name="nvd_cve_api",
            source_uri="https://example/smoke",
            summary="prompt injection against a large language model",
            relevance_score=0.9,
            metadata={"topics": ["prompt injection"]},
        )
        records = generate_for_run(
            "smoke-run",
            [item],
            config=KgGenerationConfig(output_root=tmp),
            process_func=fake,
        )
        assert records[0].status == "succeeded"
        assert (Path(tmp) / "smoke-run_kg" / "manifest.json").exists()


def _check_trace_callback() -> None:
    from intel_agent.observability import TraceSink

    with TemporaryDirectory() as tmp:
        seen: list[dict] = []
        sink = TraceSink(console=False, trace_dir=Path(tmp), on_event=seen.append)
        sink.bind_run("smoke-trace")
        sink.emit("round_start", round=1, max_rounds=2, mode="bootstrap", open_gaps=[])
        sink.close()
        assert seen and seen[0]["event"] == "round_start"


def main() -> int:
    try:
        _check_imports()
        print("OK imports + boundary")
        _check_kg_pipeline()
        print("OK kg pipeline (fake process)")
        _check_trace_callback()
        print("OK TraceSink on_event")
        print("SMOKE PASSED")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"SMOKE FAILED: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
