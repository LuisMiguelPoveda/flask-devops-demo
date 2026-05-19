from __future__ import annotations

from app.core.llm_profiles import DEFAULT_CHUNK_OVERLAP, DEFAULT_CHUNK_TOKENS
from app.core.text_processing import chunk_text_with_overlap


def build_note_chunks_map(
    user_id: int,
    notes: list,
    max_tokens: int = DEFAULT_CHUNK_TOKENS,
    overlap: int = DEFAULT_CHUNK_OVERLAP,
) -> dict[int, dict]:
    from app.models import Job

    if not notes:
        return {}

    note_ids = {n.id for n in notes if n.id}
    jobs = Job.query.filter(Job.user_id == user_id, Job.type == "note_ai_chunk").all()
    by_note: dict[int, list[tuple[int, str, int]]] = {}
    for job in jobs:
        payload = job.payload or {}
        note_id = payload.get("note_id")
        if note_id not in note_ids:
            continue
        try:
            idx = max(0, int(payload.get("chunk_index") or 0))
        except (ValueError, TypeError):
            idx = 0
        try:
            total = max(1, int(payload.get("total_chunks") or 1))
        except (ValueError, TypeError):
            total = 1
        text = payload.get("text") or ""
        by_note.setdefault(note_id, []).append((idx, text, total))

    result: dict[int, dict] = {}
    for note in notes:
        if note.id in by_note:
            chunks_info = sorted(by_note[note.id], key=lambda t: t[0])
            chunks = [t[1] for t in chunks_info if t[1]]
            total_max = max((t[2] for t in chunks_info if t[2]), default=len(chunks))
            result[note.id] = {"chunks": chunks, "total": total_max or len(chunks) or 1}
            continue

        chunks = chunk_text_with_overlap(note.content or "", max_tokens=max_tokens, overlap=overlap)
        result[note.id] = {"chunks": chunks or [note.content or ""], "total": len(chunks) or 1}

    return result
