import requests

from app.core.flashcard_validation import _parse_and_validate_flashcards_json
from app.core.llm_profiles import DEFAULT_LLM_LIMITS, DEFAULT_LLM_PROFILE, LLM_OFFLINE_LABEL, LLM_PROFILE_PRESETS


class LLMClient:
    def __init__(self, api_base: str, timeout: int):
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Low-level HTTP
    # ------------------------------------------------------------------

    def fetch_models(self) -> list[str]:
        try:
            resp = requests.get(f"{self.api_base}/models", timeout=5)
            resp.raise_for_status()
            data = resp.json()
            all_ids = [m["id"] for m in data.get("data", [])]
            models = [mid for mid in all_ids if not mid.startswith("text-embedding-")]
            return models or [LLM_OFFLINE_LABEL]
        except Exception:
            return [LLM_OFFLINE_LABEL]

    def chat(
        self,
        model: str,
        messages: list[dict],
        response_format: dict | None = None,
        max_tokens: int | None = None,
        temperature: float = 0.4,
    ) -> str:
        payload: dict = {"model": model, "messages": messages, "temperature": temperature}
        if response_format:
            payload["response_format"] = response_format
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        resp = requests.post(f"{self.api_base}/chat/completions", json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    # ------------------------------------------------------------------
    # Higher-level domain operations
    # ------------------------------------------------------------------

    def summarize(
        self,
        model: str,
        subject: str,
        title: str,
        exam_date: str,
        filename: str,
        text: str,
        max_tokens: int,
        chunk_index: int | None = None,
        total_chunks: int | None = None,
    ) -> str:
        system_prompt = (
            "Eres un especialista en pedagogía y diseño instruccional con experiencia en TDAH y carga cognitiva.\n\n"
            "IMPORTANTE: Empieza tu respuesta DIRECTAMENTE con el formato indicado. "
            "No incluyas análisis, razonamiento interno, ni meta-comentarios sobre estas instrucciones. "
            "No repitas ni parafrasees estas instrucciones en tu respuesta.\n\n"
            "Tu tarea es transformar el TEXTO FUENTE en APUNTES GUIADOS altamente estructurados,\n"
            "optimizados para estudiantes con déficit de atención.\n\n"
            "REGLAS GENERALES (obligatorias):\n"
            "1. Mantén SIEMPRE la misma macroestructura y los mismos encabezados.\n"
            "2. Usa fragmentación cognitiva (chunking): bloques cortos y visualmente claros.\n"
            "3. Reduce texto continuo: prioriza bullets jerárquicos, tablas y esquemas.\n"
            "4. Señaliza explícitamente lo importante (clave, confusión común, examinable).\n"
            "5. No añadas información nueva: solo reorganiza y clarifica el texto dado.\n"
            "6. Lenguaje claro, directo, sin metáforas ni digresiones.\n"
            "7. Cada bloque debe poder leerse de forma independiente en <30 segundos.\n"
            "8. Máximo 12–15 líneas por sección principal.\n"
            "9. Usa siempre palabras clave antes de explicaciones breves.\n"
            "10. Evita listas planas: mínimo dos niveles de jerarquía cuando haya listas.\n\n"
            "FORMATO FIJO (NO MODIFICAR):\n\n"
            "────────────────────────\n"
            " TEMA:\n"
            "[Nombre claro y conciso del tema]\n\n"
            " IDEA CENTRAL (1 frase):\n"
            "• [Qué es / para qué sirve]\n\n"
            "────────────────────────\n"
            " CONCEPTOS CLAVE:\n"
            "• Concepto 1\n"
            "  – Definición corta\n"
            "  – Ejemplo mínimo (si aplica)\n"
            "• Concepto 2\n"
            "  – Definición corta\n"
            "  – Ejemplo mínimo\n\n"
            "────────────────────────\n"
            " RELACIONES IMPORTANTES:\n"
            "• [Concepto A] → [Concepto B]\n"
            "  – Tipo de relación (causa, consecuencia, contraste, parte–todo)\n\n"
            "────────────────────────\n"
            " PASOS / PROCESO / ESTRUCTURA (si aplica):\n"
            "1. Paso 1 — palabra clave\n"
            "   – Qué ocurre\n"
            "2. Paso 2 — palabra clave\n"
            "   – Qué ocurre\n\n"
            "────────────────────────\n"
            " ERRORES O CONFUSIONES COMUNES:\n"
            "• Error frecuente\n"
            "  – Por qué es incorrecto\n\n"
            "────────────────────────\n"
            " LO QUE SÍ ENTRA EN EXAMEN / EVALUACIÓN:\n"
            "• Hecho, definición o relación clave\n\n"
            "────────────────────────\n"
            " HUECOS PARA COMPLETAR (guided notes):\n"
            "• _______________________________\n"
            "• _______________________________\n\n"
            "────────────────────────\n"
            " CONEXIÓN CON OTROS APUNTES:\n"
            "• Se relaciona con: [tema previo / tema siguiente]\n"
            "• Idea puente: ____________________\n\n"
            "────────────────────────\n\n"
            "ENTRADA:\n"
            "[TEXTO FUENTE AQUÍ]\n\n"
            "SALIDA:\n"
            "Apuntes siguiendo EXACTAMENTE el formato indicado."
        )
        chunk_meta_line = ""
        if total_chunks and total_chunks > 1:
            human_idx = (chunk_index or 0) + 1
            chunk_meta_line = f"Parte: {human_idx}/{total_chunks} (solo para contexto; no lo menciones en tu respuesta)."
        user_prompt = (
            f"Asignatura: {subject}\n"
            f"Título: {title}\n"
            f"Fecha de examen: {exam_date}\n"
            f"Archivo: {filename}\n"
            f"{chunk_meta_line}\n\n"
            f"TEXTO A RESUMIR:\n{text}"
        )
        result = self.chat(
            model,
            [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
            max_tokens=max_tokens,
        )
        # Some reasoning models leak chain-of-thought before the actual output.
        # Strip everything before the first format separator or TEMA header.
        for marker in ("────────────────────────", " TEMA:", "TEMA:"):
            idx = result.find(marker)
            if idx > 0:
                result = result[idx:]
                break
        return result

    def generate_flashcards(
        self,
        model: str,
        subject_name: str,
        note_title: str,
        exam_date_str: str,
        text: str,
        count: int = 5,
    ) -> list[dict]:
        count = max(1, min(count, 50))
        system_prompt = (
            f"Genera exactamente {count} flashcards de examen a partir del texto. "
            "Devuelve SOLO un JSON válido (sin texto extra, sin markdown). "
            "Formato: "
            "["
            '{"question":"...","options":["A","B","C","D"],"correct_index":0},'
            "..."
            "]. "
            "Las preguntas deben ser autocontenidas: no uses referencias como "
            "\"según el texto\", \"en el fragmento\", \"¿qué se mencionó?\" o similares."
        )
        user_prompt = (
            f"Asignatura: {subject_name}\n"
            f"Título: {note_title}\n"
            f"Fecha de examen: {exam_date_str}\n\n"
            f"TEXTO:\n{text}\n\n"
            "Crea preguntas potenciales de examen que se entiendan sin contexto adicional, "
            "4 opciones, solo 1 correcta. No uses referencias al texto o a un fragmento, "
            "y no añadas contexto externo."
        )
        schema = {
            "type": "array",
            "minItems": count,
            "maxItems": count,
            "items": {
                "type": "object",
                "properties": {
                    "question": {"type": "string", "minLength": 1},
                    "options": {
                        "type": "array",
                        "minItems": 4,
                        "maxItems": 4,
                        "items": {"type": "string", "minLength": 1},
                    },
                    "correct_index": {"type": "integer", "minimum": 0, "maximum": 3},
                },
                "required": ["question", "options", "correct_index"],
                "additionalProperties": False,
            },
        }
        raw = self.chat(
            model,
            [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
            response_format={"type": "json_schema", "json_schema": {"name": "flashcards", "schema": schema}},
            temperature=0.2,
        )
        cards = _parse_and_validate_flashcards_json(raw, expected_count=count)
        if len(cards) != count:
            raise ValueError(f"El modelo devolvió {len(cards)} flashcards, se esperaban {count}.")
        return cards


# ------------------------------------------------------------------
# LLM profile helpers (need DB access, called before constructing LLMClient)
# ------------------------------------------------------------------

def resolve_llm_profile(user_id: int | None) -> str:
    from app.models import StudentProfile
    if not user_id:
        return DEFAULT_LLM_PROFILE
    profile = StudentProfile.query.filter_by(user_id=user_id).first()
    if profile and profile.llm_profile:
        candidate = profile.llm_profile.strip()
        if candidate in LLM_PROFILE_PRESETS:
            return candidate
    return DEFAULT_LLM_PROFILE


def get_llm_limits(user_id: int | None) -> dict:
    profile_key = resolve_llm_profile(user_id)
    return LLM_PROFILE_PRESETS.get(profile_key, DEFAULT_LLM_LIMITS)
