"""Build the document corpus from data/kg-source PDFs.

Following the paper's chunking design, each document becomes a single chunk so
that all entities and relations extracted from it stay within one case context.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from pypdf import PdfReader

# Directory names on disk -> canonical category labels used in provenance.
CATEGORY_LABELS = {"知网": "cnki", "其他": "other"}

_WHITESPACE = re.compile(r"[ \t　]+")
_BLANK_LINES = re.compile(r"\n{3,}")
_CJK = re.compile(r"[一-鿿]")
# Broken PDFs can yield lone surrogates and control chars that are not valid
# UTF-8; strip them so the chunk stays JSON-serializable.
_INVALID_CHARS = re.compile(r"[\ud800-\udfff\x00-\x08\x0b\x0c\x0e-\x1f]")
# Bibliography headers; only honored in the tail of the text to avoid cutting
# at in-text phrases like "see References".
_REFERENCES_HEADER = re.compile(
    r"\n\s*(References|REFERENCES|Bibliography|参考文献)\s*[:：]?\s*\n"
)


def _trim_references(text: str) -> str:
    tail_start = int(len(text) * 0.4)
    match = _REFERENCES_HEADER.search(text, tail_start)
    return text[: match.start()].rstrip() if match else text


@dataclass
class DocChunk:
    doc_id: str
    category: str
    lang: str
    n_pages: int
    n_chars: int
    text: str


def extract_pdf_text(path: Path, max_chars: int) -> tuple[str, int]:
    reader = PdfReader(str(path))
    pages: list[str] = []
    total = 0
    for page in reader.pages:
        text = page.extract_text() or ""
        pages.append(text)
        total += len(text)
        if total >= max_chars:
            break
    merged = "\n".join(pages)
    merged = _INVALID_CHARS.sub("", merged)
    merged = _WHITESPACE.sub(" ", merged)
    merged = _BLANK_LINES.sub("\n\n", merged)
    merged = _trim_references(merged)
    return merged[:max_chars].strip(), len(reader.pages)


def detect_lang(text: str) -> str:
    sample = text[:4000]
    if not sample:
        return "unknown"
    cjk = len(_CJK.findall(sample))
    return "zh" if cjk / len(sample) > 0.05 else "en"


def iter_pdfs(source_dir: Path):
    for category_dir in sorted(p for p in source_dir.iterdir() if p.is_dir()):
        label = CATEGORY_LABELS.get(category_dir.name, category_dir.name)
        for pdf in sorted(category_dir.glob("*.pdf")):
            yield label, pdf


def build_corpus(
    source_dir: Path, out_path: Path, max_chars: int, limit: int | None = None
) -> dict[str, int]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    counts = {"written": 0, "failed": 0}
    with open(out_path, "w", encoding="utf-8") as fh:
        for label, pdf in iter_pdfs(source_dir):
            if limit is not None and counts["written"] >= limit:
                break
            try:
                text, n_pages = extract_pdf_text(pdf, max_chars)
            except Exception as exc:  # noqa: BLE001 - any broken PDF is skipped
                print(f"[corpus] failed: {pdf.name}: {exc}")
                counts["failed"] += 1
                continue
            if len(text) < 200:
                print(f"[corpus] skipped (too little text): {pdf.name}")
                counts["failed"] += 1
                continue
            chunk = DocChunk(
                doc_id=pdf.stem,
                category=label,
                lang=detect_lang(text),
                n_pages=n_pages,
                n_chars=len(text),
                text=text,
            )
            fh.write(json.dumps(asdict(chunk), ensure_ascii=False) + "\n")
            counts["written"] += 1
    return counts


def load_corpus(corpus_path: Path, limit: int | None = None) -> list[dict]:
    docs: list[dict] = []
    with open(corpus_path, encoding="utf-8") as fh:
        for line in fh:
            if limit is not None and len(docs) >= limit:
                break
            line = line.strip()
            if line:
                docs.append(json.loads(line))
    return docs
