"""Probe which GLM key (GLM_API_KEY, GLM_API_KEY_1..9) works on the Anthropic endpoint.

Sends a minimal /v1/messages request per key and prints status only — never the key.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

from _env import GLM_ANTHROPIC_BASE_URL, load_dotenv_values


def probe(key_name: str, key: str, model: str) -> str:
    payload = json.dumps(
        {
            "model": model,
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{GLM_ANTHROPIC_BASE_URL}/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = json.loads(response.read().decode("utf-8"))
            text = "".join(
                block.get("text", "") for block in body.get("content", []) if isinstance(block, dict)
            )
            return f"HTTP 200 model={body.get('model')} text={text[:40]!r}"
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200]
        return f"HTTP {exc.code} {detail}"
    except Exception as exc:  # noqa: BLE001
        return f"{exc.__class__.__name__}: {exc}"


def main() -> None:
    model = sys.argv[1] if len(sys.argv) > 1 else "glm-4.7"
    values = load_dotenv_values()
    names = ["GLM_API_KEY"] + [f"GLM_API_KEY_{i}" for i in range(1, 10)]
    for name in names:
        key = values.get(name, "").strip()
        if not key:
            continue
        print(f"{name}: {probe(name, key, model)}", flush=True)


if __name__ == "__main__":
    main()
