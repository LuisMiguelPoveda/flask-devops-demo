import json


def _parse_and_validate_flashcards_json(raw: str, expected_count: int) -> list[dict]:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.replace("json\n", "", 1).strip()

    data = json.loads(cleaned)

    if not isinstance(data, list) or len(data) != expected_count:
        raise ValueError(f"El JSON debe ser una lista de {expected_count} flashcards.")

    for i, card in enumerate(data, start=1):
        if not isinstance(card, dict):
            raise ValueError(f"Flashcard {i} no es un objeto JSON.")
        q = card.get("question")
        opts = card.get("options")
        idx = card.get("correct_index")
        if not isinstance(q, str) or not q.strip():
            raise ValueError(f"Flashcard {i} tiene 'question' inválida.")
        if not isinstance(opts, list) or len(opts) != 4 or not all(
            isinstance(o, str) and o.strip() for o in opts
        ):
            raise ValueError(f"Flashcard {i} debe tener 4 'options' (strings).")
        if not isinstance(idx, int) or idx < 0 or idx > 3:
            raise ValueError(f"Flashcard {i} debe tener 'correct_index' entre 0 y 3.")
    return data
