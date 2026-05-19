LLM_PROFILE_CHOICES = [
    {
        "id": "vram_4gb",
        "label": "4 GB (conservador)",
        "chunk_tokens": 1500,
        "chunk_overlap": 250,
        "summary_max_tokens": 1200,
        "summary_min_tokens": 120,
        "summary_ratio": 0.35,
    },
    {
        "id": "vram_8gb",
        "label": "8 GB (equilibrado)",
        "chunk_tokens": 2200,
        "chunk_overlap": 350,
        "summary_max_tokens": 2200,
        "summary_min_tokens": 120,
        "summary_ratio": 0.45,
    },
    {
        "id": "vram_16gb",
        "label": "16 GB (alto)",
        "chunk_tokens": 3000,
        "chunk_overlap": 500,
        "summary_max_tokens": 3500,
        "summary_min_tokens": 120,
        "summary_ratio": 0.5,
    },
]
LLM_PROFILE_PRESETS: dict = {choice["id"]: choice for choice in LLM_PROFILE_CHOICES}

DEFAULT_LLM_PROFILE = "vram_4gb"
DEFAULT_LLM_LIMITS: dict = LLM_PROFILE_PRESETS[DEFAULT_LLM_PROFILE]

MAX_SUMMARY_TOKENS: int = DEFAULT_LLM_LIMITS["summary_max_tokens"]
SUMMARY_MIN_TOKENS: int = DEFAULT_LLM_LIMITS["summary_min_tokens"]
SUMMARY_TOKEN_RATIO: float = DEFAULT_LLM_LIMITS["summary_ratio"]
DEFAULT_CHUNK_TOKENS: int = DEFAULT_LLM_LIMITS["chunk_tokens"]
DEFAULT_CHUNK_OVERLAP: int = DEFAULT_LLM_LIMITS["chunk_overlap"]

FLASHCARD_CHUNK_COUNTS = (5, 10, 15, 20)
FLASHCARD_CHUNK_DEFAULT = FLASHCARD_CHUNK_COUNTS[0]

LLM_OFFLINE_LABEL = "Motor LLM no encontrado"

TASK_WINDOW_OPTIONS = [
    {"value": 0, "label": "Todos"},
    {"value": 7, "label": "1 semana"},
    {"value": 14, "label": "2 semanas"},
    {"value": 30, "label": "1 mes"},
]
TASK_WINDOW_VALUES: set = {opt["value"] for opt in TASK_WINDOW_OPTIONS}
TASK_WINDOW_LABELS: dict = {opt["value"]: opt["label"] for opt in TASK_WINDOW_OPTIONS}
TASK_WINDOW_DEFAULT = 14
