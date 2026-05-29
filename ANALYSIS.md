# Flask DevOps Demo — Technical Analysis

## What it is

A full-stack educational web app for students to manage study notes, flashcards, tasks, and exams. The distinguishing feature is **local LLM integration** via LM Studio — all AI processing (summarization, flashcard generation, tutoring) runs against a locally-hosted model, not a cloud API.

---

## Architecture Overview

```
Browser ──► Flask app (Gunicorn, 2 workers, 4 threads, 300s timeout)
                │
                ├── SQLAlchemy ORM → PostgreSQL 16 (docker-compose) / SQLite (dev)
                ├── Background worker thread → Job queue (polls DB every 0.5–2s)
                └── HTTP client (requests) → LM Studio API (host.docker.internal:1234)
```

The app is a **traditional server-rendered MVC** app (Jinja2 templates, no SPA framework). Interactivity is handled by 3 small vanilla JS modules.

---

## Project Structure

```
flask-devops-demo/
├── app/
│   ├── __init__.py             # App factory + background worker bootstrap (~290 lines)
│   ├── config.py               # BaseConfig / Development / Testing / Production
│   ├── extensions.py           # Flask-Limiter and Flask-Migrate singletons
│   ├── models.py               # SQLAlchemy models (~231 lines)
│   ├── utils.py                # Shared helpers (utcnow, profe lock, history pruning, etc.)
│   ├── blueprints/             # HTTP route layer (9 blueprints)
│   │   ├── auth.py             # Login, register, logout, multi-step setup wizard
│   │   ├── main.py             # Dashboard, health, job cancel
│   │   ├── calendar.py         # Tasks + exam dates
│   │   ├── notes.py            # Notes CRUD + merge + source-file download
│   │   ├── flashcards.py       # Decks CRUD + study mode
│   │   ├── challenge.py        # Reto Diario (quiz + blitz over decks)
│   │   ├── profe.py            # AI tutor chat
│   │   ├── options.py          # Profile/preferences + account reset
│   │   └── api.py              # JSON endpoints polled by frontend JS
│   ├── core/                   # Framework-free domain logic (pure functions)
│   │   ├── file_extraction.py  # PDF/PPTX/TXT extraction, upload validation
│   │   ├── flashcard_validation.py  # JSON parsing/validation for LLM output
│   │   ├── llm_profiles.py     # VRAM presets, task-window options, chunk sizes
│   │   └── text_processing.py  # Chunking with overlap, token estimation, simple formatter
│   ├── services/               # Stateful coordinators that depend on the DB / LLM
│   │   ├── llm_client.py       # LLMClient class + profile resolution helpers
│   │   ├── job_service.py      # process_job() dispatcher + queue group helpers
│   │   ├── note_service.py     # build_note_chunks_map() for chunked note merging
│   │   └── calendar_service.py # Calendar windows + items
│   ├── templates/              # 20 Jinja2 HTML templates
│   └── static/
│       ├── scss/main.scss      # SCSS source
│       ├── css/main.css        # Compiled output (minified)
│       └── js/                 # nav.js, file_drop.js, mascot.js
├── migrations/                 # Flask-Migrate schema history (Alembic)
│   └── versions/               # 3 migrations: initial schema, challenge_results, per_exam_stats
├── tests/
│   ├── test_basic.py           # Integration tests against the Flask app
│   └── unit/                   # Pure-function tests for app/core modules
├── Dockerfile                  # Multi-stage build (Node/Sass → Python)
├── docker-compose.yml          # Flask + PostgreSQL 16 + secrets
├── secrets/secret_key.txt      # Session key (gitignored Docker secret)
├── requirements.txt            # 11 Python packages
├── requirements-dev.txt        # pytest, pytest-cov, ruff
├── pyproject.toml              # ruff + pytest + coverage config
├── package.json                # Sass compiler (npm)
└── .github/workflows/ci.yml    # GitHub Actions CI/CD
```

The codebase was refactored from a monolithic `app/__init__.py` (~3,500 lines) into the layered structure above. `__init__.py` now only wires the factory, registers blueprints, and starts the background worker.

---

## Database Models

12 models with the following relationships:

```
User ─┬─ StudentProfile     (1:1)
      ├─ Subject ─────────── SubjectExam   (1:N)
      ├─ Note ────────────── NoteSourceFile (1:1, stores raw file bytes)
      ├─ FlashcardDeck      (JSON column: [{question, options[4], correct_index}])
      ├─ Job                (background task queue)
      ├─ AskProfeMessage    (chat history)
      ├─ ProfeSessionLock   (mutex for AI tutor, time-based)
      ├─ TaskItem           (calendar tasks)
      └─ ChallengeResult    (Reto Diario scores)
```

### Model Details

| Model | Key Fields |
|---|---|
| **User** | `id`, `username`, `password_hash` |
| **StudentProfile** | `student_name`, `age`, `personality_notes`, `llm_profile` (4/8/16gb), `default_model`, `task_window_days` |
| **Subject** | `name`, `color` (hex); unique per user |
| **SubjectExam** | `exam_date`, `tema` (topic); unique per subject+date+topic |
| **Note** | `title`, `content`, `exam_date`, `ai_used`, `original_filename` |
| **NoteSourceFile** | `filename`, `content_type`, `data` (LargeBinary — raw file bytes) |
| **FlashcardDeck** | `title`, `exam_date`, `flashcards` (JSON array), `source_note_id` |
| **Job** | `type`, `status` (pending/running/success/error/cancelled), `payload` (JSON), `notified` |
| **AskProfeMessage** | `role` (user/assistant), `content` |
| **ProfeSessionLock** | `starts_at`, `ends_at` (5-min window mutex) |
| **TaskItem** | `title`, `due_date`, `notes`, `subject_id` (nullable) |
| **ChallengeResult** | `deck_ids`, `subject_ids`, `exam_dates`, `quiz_correct/total`, `blitz_correct/total`, `blitz_seconds`, `per_exam_stats` |

---

## Routes Summary

### Auth ([app/blueprints/auth.py](app/blueprints/auth.py))
| Route | Endpoint | Description |
|---|---|---|
| `GET/POST /` | `login` | Login; redirects to setup or dashboard |
| `GET/POST /register` | `register` | User registration (pbkdf2:sha256) |
| `GET /logout` | `logout` | Clear session |
| `GET/POST /setup` | `setup` | Profile: name, age, personality, VRAM profile |
| `GET/POST /setup/subjects` | `setup_subjects` | Define subjects and exam dates |
| `GET/POST /setup/generate` | `setup_generate` | Bulk file upload; queues AI generation jobs |
| `GET /setup/next` | `setup_next` | Marks setup complete; redirect to dashboard |

Endpoints are registered as `auth.login`, etc. The factory also adds short aliases (`login`, `register`, …) so templates and `flask-login`'s `login_view` keep working without prefix changes.

### Dashboard / Health ([app/blueprints/main.py](app/blueprints/main.py))
| Route | Endpoint | Description |
|---|---|---|
| `GET /dashboard` | `dashboard` | Main hub: greeting, job status, calendar preview |
| `POST /jobs/cancel` | `cancel_jobs` | Cancel pending/running jobs (and clean up partial outputs) |
| `GET /health` | `health` | Liveness probe used by the Docker `HEALTHCHECK` |

### Calendar ([app/blueprints/calendar.py](app/blueprints/calendar.py))
| Route | Endpoint | Description |
|---|---|---|
| `GET /calendar` | `task_calendar` | Full calendar; task window selector (0/7/14/30 days) |
| `POST /calendar/window` | `task_calendar_window_update` | Update window preference |
| `POST /calendar/tasks` | `calendar_task_create` | Add task |
| `POST /calendar/tasks/<id>/update` | `calendar_task_update` | Edit task |
| `POST /calendar/tasks/<id>/delete` | `calendar_task_delete` | Delete task |
| `POST /calendar/exams` | `calendar_exam_create` | Add exam (can create new subject on-the-fly) |

### Notes ([app/blueprints/notes.py](app/blueprints/notes.py))
| Route | Endpoint | Description |
|---|---|---|
| `GET/POST /add-notes` | `add_notes` | Create notes: manual, single-file AI, or multi-file AI |
| `GET /notes` | `notes_list` | List with filters (subject, exam date, title search) |
| `GET /notes/<id>/source-file` | `note_source_file` | Download original uploaded file |
| `GET/POST /notes/<id>/edit` | `note_edit` | Edit content and metadata |
| `POST /notes/<id>/delete` | `note_delete` | Delete note and cascade cleanup |
| `POST /notes/merge` | `notes_merge` | Merge content of two notes |

### Flashcards ([app/blueprints/flashcards.py](app/blueprints/flashcards.py))
| Route | Endpoint | Description |
|---|---|---|
| `GET/POST /flashcards/create` | `flashcards_create` | Create deck: manual (4-option MC) or AI from note |
| `GET /flashcards` | `flashcards_list` | List decks with filters |
| `GET/POST /flashcards/<id>/edit` | `flashcards_edit` | Edit cards; merge decks; append AI cards |
| `GET /flashcards/<id>/study` | `flashcards_study` | Single-deck study UI |
| `POST /flashcards/<id>/delete` | `flashcards_delete` | Delete deck |

### Challenge ([app/blueprints/challenge.py](app/blueprints/challenge.py))
| Route | Endpoint | Description |
|---|---|---|
| `GET /challenge` | `challenge` | Reto Diario: quiz + blitz over decks in the active window (requires ≥2 subjects) |
| `POST /challenge/save` | `challenge_save` | Persist `ChallengeResult` (per-exam stats included) |

### AI Tutor ([app/blueprints/profe.py](app/blueprints/profe.py))
| Route | Endpoint | Description |
|---|---|---|
| `GET/POST /ask-profe` | `ask_profe` | Chat interface; blocked if jobs pending; 12-message history |

### Settings ([app/blueprints/options.py](app/blueprints/options.py))
| Route | Endpoint | Description |
|---|---|---|
| `GET /options` | `options` | Options menu |
| `GET/POST /options/profile` | `profile_edit` | Edit profile and preferences |
| `POST /options/reset` | `reset_account` | Delete all user data (cascade) |

### Internal API ([app/blueprints/api.py](app/blueprints/api.py))
| Route | Description |
|---|---|
| `GET /api/exam-dates` | Exam dates and topics for a subject |
| `GET /api/titles` | Note titles for a subject/exam |
| `GET /api/jobs/queue` | Latest job groups (for mascot queue display) |
| `GET /api/jobs/updates` | Completed jobs needing notification |
| `GET /api/profe/status` | Profe busy and LLM busy flags |

---

## Background Worker

A **single background thread** launched at app startup (protected by a file lock in `tempfile.gettempdir()` to prevent duplicates across Gunicorn workers and the Flask reloader) processes the `Job` table.

**Job types** (dispatched by [app/services/job_service.py](app/services/job_service.py)):
- `note_ai` / `note_ai_chunk` — Summarize text chunks into study notes
- `flashcards_ai_new` / `flashcards_ai_append` / `flashcards_ai_chunk` — Generate flashcard decks
- `file_import` — Bulk file processing during setup

The worker polls every 0.5–2s, pauses while an `ProfeSessionLock` is active, retries errored jobs after `JOB_RETRY_SECONDS` (30s), and supports cancellation (cleans up partial notes/decks). It also recovers gracefully from `OperationalError("database is locked")` on SQLite. The mascot in the UI polls `/api/jobs/updates` every 15 seconds and animates to notify the user when jobs complete.

---

## LLM Integration

All AI calls go through [`LLMClient`](app/services/llm_client.py), attached to `app.extensions["llm_client"]` during factory init. Three VRAM profiles ([app/core/llm_profiles.py](app/core/llm_profiles.py)) configure chunk sizes and token limits:

| Profile | Chunk size | Overlap | Max summary tokens |
|---|---|---|---|
| 4 GB (`vram_4gb`) | 1,500 tokens | 250 | 1,200 |
| 8 GB (`vram_8gb`) | 2,200 tokens | 350 | 2,200 |
| 16 GB (`vram_16gb`) | 3,000 tokens | 500 | 3,500 |

**Key `LLMClient` methods:**
- `fetch_models()` — GET `/models`; filters out embedding models; returns `["[LM Studio offline]"]` on failure
- `chat()` — POST `/chat/completions` with system prompt + history + optional JSON schema
- `summarize()` — Structured study notes; strips leaked chain-of-thought before the format header
- `generate_flashcards()` — JSON-schema-constrained MC flashcards, validated by [`_parse_and_validate_flashcards_json`](app/core/flashcard_validation.py)

Text is split into **overlapping chunks** via `chunk_text_with_overlap()` ([app/core/text_processing.py](app/core/text_processing.py)) before being sent to the LLM. Large documents (PDF, PPTX) produce multiple `*_chunk` jobs that are merged on completion.

**Supported file formats:** `.pdf` (PyPDF2), `.pptx` (python-pptx, extracts slide text + tables), `.txt`.

**Docker networking:** In docker-compose, LM Studio runs on the host machine. The container reaches it via `host.docker.internal` (mapped to `host-gateway` in `extra_hosts`). LM Studio must have "Listen on all interfaces" enabled.

---

## Frontend

No JS framework — 3 vanilla JS modules:

| File | Responsibility |
|---|---|
| [app/static/js/mascot.js](app/static/js/mascot.js) | Animated sprite, tip bubbles, job polling (15s), profe status polling (10s), localStorage state |
| [app/static/js/file_drop.js](app/static/js/file_drop.js) | Drag-and-drop file upload with visual feedback |
| [app/static/js/nav.js](app/static/js/nav.js) | Keyboard navigation (arrow keys + Enter) for dropdown menus |

CSS is compiled from SCSS ([app/static/scss/main.scss](app/static/scss/main.scss)) via `npm run build-css`.

---

## Deployment Pipeline

### CI (GitHub Actions — `.github/workflows/ci.yml`)
1. Python 3.12 setup → `pytest`
2. Node setup → `npm install` → `npm run build-css`
3. `docker build`

### Docker (Multi-stage `Dockerfile`)
- **Stage 1 (Node 22 Alpine):** Compile SCSS → CSS (compressed, no source maps)
- **Stage 2 (Python 3.12-slim):** Install dependencies, copy `app/` + `migrations/`, expose port 5000
- **ENV:** `FLASK_APP=app`
- **HEALTHCHECK:** `urllib.request.urlopen('http://localhost:5000/health')` every 30s
- **CMD:** `flask db upgrade && gunicorn -b 0.0.0.0:5000 --timeout 300 --workers 2 --threads 4 'app:create_app()'`

Each worker calls `create_app()` independently and reads `SECRET_KEY` from the same Docker secret file — consistent keys without shared pre-fork connections. `--preload` is not used because it caused workers to inherit PostgreSQL connections opened in the master process, corrupting the libpq protocol state after `fork()`.

### docker-compose.yml
```yaml
services:
  db:  postgres:16-alpine
       POSTGRES_DB=flask_devops, USER=flask_user
       volume: postgres_data (persistent)

  app: Flask
       DB_HOST=db, DB_NAME=flask_devops, DB_USER=flask_user
       DB_PASSWORD_FILE=/run/secrets/postgres_password
       LMSTUDIO_API_BASE=http://host.docker.internal:1234/v1
       SECRET_KEY_FILE=/run/secrets/secret_key
       extra_hosts: host.docker.internal:host-gateway
       secrets: secret_key, postgres_password

volumes:
  postgres_data   # survives docker compose up --build and docker compose down
                  # deleted by docker compose down -v
```

### Environment Variables
| Variable | Default | Description |
|---|---|---|
| `FLASK_ENV` | `production` | Selects `DevelopmentConfig` / `TestingConfig` / `ProductionConfig` |
| `SECRET_KEY_FILE` | `/run/secrets/secret_key` | Path to session key file (Docker secret) |
| `SECRET_KEY` | — | Direct key override (dev only; falls back to ephemeral with a warning if neither set) |
| `SQLALCHEMY_DATABASE_URI` | `sqlite:///app.db` | DB connection string (overridden by `DB_*` vars below) |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD_FILE` | — | Build a `postgresql+psycopg2://…` URI when `DB_HOST` is set |
| `LMSTUDIO_API_BASE` | `http://127.0.0.1:1234/v1` (dev) / `http://host.docker.internal:1234/v1` (Docker) | LM Studio endpoint |
| `LMSTUDIO_MODEL` | `google/gemma-3-1b` | Default model name |
| `LMSTUDIO_TIMEOUT` | `300` | LLM request timeout (seconds) |
| `ASK_PROFE_SESSION_SECONDS` | `300` | Chat session duration |
| `UPLOAD_DIR` | `<instance_path>/uploads` | File upload directory |
| `MAX_CONTENT_LENGTH` | 50 MB (set in `BaseConfig`) | Max upload size |

---

## Data Persistence

| Action | Data |
|---|---|
| `docker compose up --build` | Survives (volume untouched) |
| `docker compose down` + `up` | Survives |
| `docker compose down -v` | Lost (volume deleted) |
| New deploy with model schema changes | Handled by `flask db upgrade` at container startup |

File uploads (`NoteSourceFile.data`) are stored as blobs inside PostgreSQL, so they live in the same volume and require no separate mount.

---

## Testing

**Framework:** pytest + pytest-cov
**Config:** [pyproject.toml](pyproject.toml) — `testpaths = ["tests"]`, coverage `fail_under = 34`, ignored: `app/static/*`, `app/templates/*`

**Integration tests** ([tests/test_basic.py](tests/test_basic.py)):
- `flask_app` fixture — Ephemeral SQLite DB in tmpdir; `LMSTUDIO_TIMEOUT=1`; built via `create_app(TestingConfig)`
- `authed_client` fixture — Pre-registers user "ada" with profile, subject, and exam
- Coverage: auth/dashboard guards, Ask Profe (busy redirect, per-user history isolation), Notes CRUD (create/list/edit/delete with subject change), setup enforcement, flash message formatting

**Unit tests** ([tests/unit/](tests/unit/)) — Pure functions, no Flask app required:
- `test_file_extraction.py` — PDF/PPTX extraction, upload size limits, allowed-extension checks
- `test_flashcard_validation.py` — JSON parsing/validation of LLM flashcard output
- `test_text_processing.py` — Chunking with overlap, token estimation, formatter behavior

**Linting:** [ruff](https://docs.astral.sh/ruff/) — rules `E`, `F`, `W`, `UP`; line-length 120; `E501` ignored.

---

## Dependencies

**Python (`requirements.txt`):**
```
Flask
gunicorn
Flask-SQLAlchemy
Flask-Login
Flask-WTF          # CSRF protection
Flask-Limiter      # Rate limiting (login, register, ask-profe)
Flask-Migrate      # Schema migrations (Alembic)
requests
PyPDF2
python-pptx
psycopg2-binary    # PostgreSQL driver
```

**Python dev (`requirements-dev.txt`):**
```
-r requirements.txt
pytest
pytest-cov
ruff
```

**Node (`package.json`):** `sass ^1.95.0` (devDependency, SCSS compiler).

---

## Security Posture

| Area | Status |
|---|---|
| CSRF protection | Flask-WTF on all POST forms (disabled only in `TestingConfig`) |
| Session key | Docker secret (`SECRET_KEY_FILE`); ephemeral fallback in dev (warns) |
| Session cookies | `HttpOnly`, `SameSite=Lax` everywhere; `Secure` in production |
| Password hashing | werkzeug pbkdf2:sha256, salt_length=16 |
| Multi-worker session consistency | All workers read same `SECRET_KEY_FILE` independently |
| DB connection health after fork | `pool_pre_ping=True` for PostgreSQL; WAL + busy_timeout for SQLite |
| `app.db` in git | Removed (gitignored) |
| Rate limiting | Flask-Limiter: login 10/min, register 5/h, ask-profe 20/min (per IP) |
| File blobs in DB | Up to 50 MB per file stored as `LargeBinary`; oversized uploads return a friendly flash |
| Schema migrations | Flask-Migrate (Alembic); `flask db upgrade` runs at container startup |
| `POSTGRES_PASSWORD` in docker-compose | Docker secret (`POSTGRES_PASSWORD_FILE`) |

---

## Notable Design Decisions

- **Layered split (blueprints / services / core)** — Routes live under `app/blueprints/`, stateful coordinators under `app/services/`, framework-free pure functions under `app/core/`. The `core` layer has no Flask or SQLAlchemy imports, which is what makes the `tests/unit/` suite fast and isolated.
- **Endpoint aliasing** — Blueprints prefix endpoints (e.g. `auth.login`). The factory copies each rule under its bare name (`login`) so templates and `LoginManager.login_view` keep working without prefix changes.
- **DB-based job queue** — No Redis/Celery dependency; the `Job` table + background thread is self-contained. Trade-off: polling overhead, no distributed workers.
- **File-lock guarded worker** — `fcntl.flock` on `tempfile.gettempdir()/flask-devops-demo-worker.lock` (non-blocking) ensures only one worker thread runs across forks/reloads.
- **`ProfeSessionLock` as DB mutex** — Time-based session slots prevent concurrent AI tutor use without needing Redis or an external lock service. The worker also pauses while a lock is active.
- **File blobs in DB** — `NoteSourceFile.data` stores raw file bytes as `LargeBinary`. Simple but can inflate DB size significantly at scale.
- **`host.docker.internal` for LM Studio** — Allows the containerized app to reach the host's LM Studio server on Linux via Docker's `host-gateway`.
- **Reto Diario (Challenge)** — Quiz + blitz mode pulling flashcards from decks whose `exam_date` falls inside the user's active calendar window; requires ≥2 subjects so cross-subject mixing is meaningful. Per-exam stats are persisted for later analytics.

---

*Updated: 2026-05-20*
