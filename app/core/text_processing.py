import re
from html import unescape as html_unescape

from markupsafe import Markup, escape

from app.core.llm_profiles import (
    DEFAULT_CHUNK_TOKENS,
    DEFAULT_CHUNK_OVERLAP,
    MAX_SUMMARY_TOKENS,
    SUMMARY_MIN_TOKENS,
    SUMMARY_TOKEN_RATIO,
)


def chunk_text_with_overlap(
    text: str,
    max_tokens: int = DEFAULT_CHUNK_TOKENS,
    overlap: int = DEFAULT_CHUNK_OVERLAP,
) -> list[str]:
    tokens = (text or "").split()
    if not tokens:
        return []

    max_tokens = max(1, max_tokens)
    overlap = max(0, min(overlap, max_tokens - 1))
    step = max_tokens - overlap if max_tokens > overlap else 1

    chunks: list[str] = []
    start = 0
    while start < len(tokens):
        end = min(len(tokens), start + max_tokens)
        chunks.append(" ".join(tokens[start:end]))
        if end >= len(tokens):
            break
        start += step
    return chunks


def estimate_summary_max_tokens(
    text: str,
    max_tokens: int = MAX_SUMMARY_TOKENS,
    min_tokens: int = SUMMARY_MIN_TOKENS,
    ratio: float = SUMMARY_TOKEN_RATIO,
) -> int:
    word_count = len((text or "").split())
    target = int(word_count * ratio)
    if target <= 0:
        target = min_tokens
    return max(min_tokens, min(max_tokens, target))


def simple_format_note(text: str) -> Markup:
    lines = html_unescape(text or "").splitlines()
    html_parts: list[str] = []
    in_list = False

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            html_parts.append("</ul>")
            in_list = False

    def fmt_inline(txt: str) -> str:
        esc = escape(txt)
        esc = re.sub(r"\*\*(.+?)\*\*", lambda m: f"<strong>{escape(m.group(1))}</strong>", esc)
        esc = re.sub(r"\*(.+?)\*", lambda m: f"<em>{escape(m.group(1))}</em>", esc)
        return esc

    for line in lines:
        stripped = line.strip()
        if not stripped:
            close_list()
            continue
        if stripped == "---":
            close_list()
            html_parts.append("<hr />")
        elif stripped.startswith("###"):
            close_list()
            html_parts.append(f"<h4>{fmt_inline(stripped.lstrip('#').strip())}</h4>")
        elif stripped.startswith("##"):
            close_list()
            html_parts.append(f"<h3>{fmt_inline(stripped.lstrip('#').strip())}</h3>")
        elif stripped.startswith("#"):
            close_list()
            html_parts.append(f"<h2>{fmt_inline(stripped.lstrip('#').strip())}</h2>")
        elif stripped.startswith(("* ", "- ")):
            if not in_list:
                html_parts.append("<ul>")
                in_list = True
            html_parts.append(f"<li>{fmt_inline(stripped[2:].strip())}</li>")
        else:
            close_list()
            html_parts.append(f"<p>{fmt_inline(stripped)}</p>")

    close_list()
    return Markup("".join(html_parts))
