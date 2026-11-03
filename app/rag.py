"""Tiny keyword retrieval over docs/*.md (TF-IDF style, no extra libraries).

Docs are re-read on every request, so you can edit files in docs/ without restarting.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass

from . import config

TOKEN_RE = re.compile(r"[a-z0-9]+")
STOPWORDS = set(
    """a an and are as at be by can do does for from has have how i if in is it its
    me my of on or our please so that the their them then there this to us was we
    what when where which who why will with you your""".split()
)


@dataclass
class Doc:
    name: str
    text: str
    score: float = 0.0


def tokenize(text: str) -> list[str]:
    tokens = []
    for t in TOKEN_RE.findall(text.lower()):
        if t in STOPWORDS or len(t) < 2:
            continue
        if len(t) > 3 and t.endswith("s") and not t.endswith("ss"):
            t = t[:-1]  # crude plural stripping: refunds -> refund
        tokens.append(t)
    return tokens


def load_docs() -> list[Doc]:
    return [Doc(p.name, p.read_text(encoding="utf-8")) for p in sorted(config.DOCS_DIR.glob("*.md"))]


def retrieve(query: str, k: int | None = None) -> list[Doc]:
    """Return up to k docs that share words with the query, best match first."""
    k = k or config.RAG_TOP_K
    docs = load_docs()
    query_terms = set(tokenize(query))
    if not docs or not query_terms:
        return []

    # Filename words count too (vendor_update.md -> "vendor", "update").
    term_counts = [Counter(tokenize(d.name.replace("_", " ") + " " + d.text)) for d in docs]
    doc_freq = Counter()
    for counts in term_counts:
        doc_freq.update(set(counts))

    n = len(docs)
    results = []
    for doc, counts in zip(docs, term_counts):
        length = sum(counts.values()) or 1
        score = sum(
            (counts[t] / length) * math.log(1 + n / doc_freq[t]) for t in query_terms if counts[t]
        )
        if score > 0:
            results.append(Doc(doc.name, doc.text, round(score, 4)))

    results.sort(key=lambda d: d.score, reverse=True)
    return results[:k]
