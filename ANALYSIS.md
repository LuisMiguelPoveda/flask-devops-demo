# Flask DevOps Demo — Technical Analysis

## What it is

A full-stack educational web app for students to manage study notes, flashcards, tasks, and exams. The distinguishing feature is **local LLM integration** via LM Studio — all AI processing (summarization, flashcard generation, tutoring) runs against a locally-hosted model, not a cloud API.

---

## Architecture Overview

```
Browser ──► Flask app (Gunicorn, 2 workers, 4 threads, --preload)
                │
                ├── SQLAlchemy ORM → PostgreSQL 16 (docker-compose) / SQLite (dev)
                ├── Background worker thread → Job queue (polls DB every 1–2s)
                └── HTTP client (requests) → LM Studio API (host.docker.internal:1234)
```

The app is a **traditional server-rendered MVC** app (Jinja2 templates, no SPA framework). Interactivity is handled by 3 small vanilla JS modules.

---

## Project Structure

```
flask-devops-demo/
├── app/
│   ├── __init__.py         # Everything: factory, all routes, worker logic (~3,573 lines)
│   ├── models.py           # SQLAlchemy models (~211 lines)
│   ├── templates/          # 18 Jinja2 HTML templates
│   └── static/
│       ├── scss/main.scss  # SCSS source (1,030 lines)
│       ├── css/main.css    # Compiled output (minified)
│       └── js/             # nav.js, file_drop.js, mascot.js
├── tests/test_basic.py     # pytest suite
├── Dockerfile              # Multi-stage build (Node/Sass → Python)
├── docker-compose.yml      # Flask + PostgreSQL 16 + secrets
├── secrets/secret_key.txt  # Session key (gitignored Docker secret)
├── requirements.txt        # 9 Python packages
├── package.json            # Sass compiler (npm)
└── .github/workflows/ci.yml # GitHub Actions CI/CD
```

---

## Database Models

11 models with the following relationships:

```
User ─┬─ StudentProfile   (1:1)
      ├─ Subject ──────── SubjectExam   (1:N)
      ├─ Note ─────────── NoteSourceFile (1:1, stores raw file bytes)
      ├─ FlashcardDeck    (JSON column: [{question, options[4], correct_index}])
      ├─ Job              (background task queue)
      ├─ AskProfeMessage  (chat history)
      ├─ ProfeSessionLock (mutex for AI tutor, time-based)
      └─ TaskItem         (calendar tasks)
```

### Model Details

| Model | Key Fields |
|---|---|
| **User** | `id`, `username`, `password_hash` |
| **StudentProfile** | `student_name`, `age`, `personality_notes`, `llm_profile` (4/8/16gb), `task_window_days` |
| **Subject** | `name`, `color` (hex); unique per user |
| **SubjectExam** | `exam_date`, `tema` (topic); unique per subject+date+topic |
| **Note** | `title`, `content`, `exam_date`, `ai_used`, `original_filename` |
| **NoteSourceFile** | `filename`, `content_type`, `data` (LargeBinary — raw file bytes) |
| **FlashcardDeck** | `title`, `exam_date`, `flashcards` (JSON array) |
| **Job** | `type`, `status` (pending/running/success/error/cancelled), `payload` (JSON) |
| **AskProfeMessage** | `role` (user/assistant), `content` |
| **ProfeSessionLock** | `starts_at`, `ends_at` (5-min window mutex) |
| **TaskItem** | `title`, `due_date`, `notes`, `subject_id` (nullable) |

---

## Routes Summary

### Auth
| Route | Handler | Description |
|---|---|---|
| `GET/POST /` | `login()` | Login; redirects to setup or dashboard |
| `GET/POST /register` | `register()` | User registration (pbkdf2:sha256) |
| `POST /logout` | `logout()` | Clear session |

### Setup Wizard
| Route | Handler | Description |
|---|---|---|
| `GET/POST /setup` | `setup()` | Profile: name, age, personality, VRAM profile |
| `GET/POST /setup/subjects` | `setup_subjects()` | Define subjects and exam dates |
| `GET/POST /setup/generate` | `setup_generate()` | Bulk file upload; queues AI generation jobs |
| `GET /setup/next` | `setup_next()` | Marks setup complete; redirect to dashboard |

### Dashboard & Calendar
| Route | Handler | Description |
|---|---|---|
| `GET /dashboard` | `dashboard()` | Main hub: greeting, job status, calendar preview |
| `GET /calendar` | `task_calendar()` | Full calendar; task window selector (0/7/14/30 days) |
| `POST /calendar/window` | `task_calendar_window_update()` | Update window preference |
| `POST /calendar/tasks` | `calendar_task_create()` | Add task |
| `POST /calendar/tasks/<id>/update` | `calendar_task_update()` | Edit task |
| `POST /calendar/tasks/<id>/delete` | `calendar_task_delete()` | Delete task |
| `POST /calendar/exams` | `calendar_exam_create()` | Add exam (can create new subject on-the-fly) |

### Notes
| Route | Handler | Description |
|---|---|---|
| `GET/POST /add-notes` | `add_notes()` | Create notes: manual, single-file AI, or multi-file AI |
| `GET /notes` | `notes_list()` | List with filters (subject, exam date, title search) |
| `GET /notes/<id>/source-file` | `notes_source_file_download()` | Download original uploaded file |
| `GET/POST /notes/<id>/edit` | `notes_edit()` | Edit content and metadata |
| `POST /notes/<id>/delete` | `notes_delete()` | Delete note and cascade cleanup |
| `POST /notes/merge` | `notes_merge()` | Merge content of two notes |

### Flashcards
| Route | Handler | Description |
|---|---|---|
| `GET/POST /flashcards/create` | `flashcards_create()` | Create deck: manual (4-option MC) or AI from note |
| `GET /flashcards` | `flashcards_list()` | List decks with filters |
| `GET/POST /flashcards/<id>/edit` | `flashcards_edit()` | Edit cards; merge decks; append AI cards |
| `POST /flashcards/<id>/delete` | `flashcards_delete()` | Delete deck |

### AI Tutor
| Route | Handler | Description |
|---|---|---|
| `GET/POST /ask-profe` | `ask_profe()` | Chat interface; blocked if jobs pending; 12-message history |

### Settings
| Route | Handler | Description |
|---|---|---|
| `GET /options` | `options()` | Options menu |
| `GET/POST /options/profile` | `options_profile()` | Edit profile and preferences |
| `POST /options/reset` | `options_reset()` | Delete all user data (cascade) |

### Internal API (polled by frontend JS)
| Route | Description |
|---|---|
| `GET /api/exam-dates` | Exam dates and topics for a subject |
| `GET /api/titles` | Note titles for a subject/exam |
| `GET /api/jobs/queue` | Latest job groups (for mascot queue display) |
| `GET /api/jobs/updates` | Completed jobs needing notification |
| `GET /api/profe/status` | Profe busy and LLM busy flags |

---

## Background Worker

A **single background thread** launched at app startup (protected by a file lock to prevent duplicates across Gunicorn workers) processes the `Job` table.

**Job types:**
- `note_ai` / `note_ai_chunk` — Summarize text chunks into study notes
- `flashcards_ai_new` / `flashcards_ai_append` / `flashcards_ai_chunk` — Generate flashcard decks
- `file_import` — Bulk file processing during setup

The worker polls the DB every 1–2 seconds, retries errored jobs after 30 seconds, and supports cancellation (cleans up partial notes/decks). The mascot in the UI polls `/api/jobs/updates` every 15 seconds and animates to notify the user when jobs complete.

---

## LLM Integration

All AI calls go to a local LM Studio instance. Three VRAM profiles configure chunk sizes and token limits:

| Profile | Chunk size | Overlap | Max summary tokens |
|---|---|---|---|
| 4 GB (`vram_4gb`) | 1,500 tokens | 250 | 1,200 |
| 8 GB (`vram_8gb`) | 2,200 tokens | 350 | 2,200 |
| 16 GB (`vram_16gb`) | 3,000 tokens | 500 | 3,500 |

**Key LLM functions:**
- `fetch_models()` — GET `/models` from LM Studio
- `lmstudio_chat()` — POST `/chat/completions` with system prompt + history + optional JSON schema
- `lmstudio_summarize_text()` — Structured study notes; configurable token limits per profile
- `lmstudio_generate_flashcards()` — JSON-format flashcards with validation

Text is split into **overlapping chunks** via `chunk_text_with_overlap()` before being sent to the LLM. Large documents (PDF, PPTX) produce multiple `*_chunk` jobs that are merged on completion.

**Supported file formats:**
- `.pdf` — PyPDF2
- `.pptx` — python-pptx (extracts slide text and tables)
- `.txt` — direct read

**Docker networking:** In docker-compose, LM Studio runs on the host machine. The container reaches it via `host.docker.internal` (mapped to `host-gateway` in `extra_hosts`). LM Studio must have "Listen on all interfaces" enabled.

---

## Frontend

No JS framework — 3 vanilla JS modules (~400 lines total):

| File | Responsibility |
|---|---|
| [app/static/js/mascot.js](app/static/js/mascot.js) | Animated sprite, tip bubbles, job polling (15s), profe status polling (10s), localStorage state |
| [app/static/js/file_drop.js](app/static/js/file_drop.js) | Drag-and-drop file upload with visual feedback |
| [app/static/js/nav.js](app/static/js/nav.js) | Keyboard navigation (arrow keys + Enter) for dropdown menus |

CSS is compiled from SCSS ([app/static/scss/main.scss](app/static/scss/main.scss)) via `npm run build-css`. Source: 1,030 lines → minified output in [app/static/css/main.css](app/static/css/main.css).

---

## Deployment Pipeline

### CI (GitHub Actions — `.github/workflows/ci.yml`)
1. Python 3.12 setup → `pytest`
2. Node setup → `npm install` → `npm run build-css`
3. `docker build`

### Docker (Multi-stage `Dockerfile`)
- **Stage 1 (Node 22 Alpine):** Compile SCSS → CSS (compressed, no source maps)
- **Stage 2 (Python 3.12-slim):** Install dependencies, copy compiled CSS, expose port 5000
- **CMD:** `gunicorn` — 2 workers, 4 threads, 300s timeout, no `--preload`

Each worker calls `create_app()` independently and reads `SECRET_KEY` from the same Docker secret file — consistent keys without shared pre-fork connections. `--preload` was removed because it caused workers to inherit PostgreSQL connections opened in the master process, corrupting the libpq protocol state after `fork()`.

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
| `SECRET_KEY_FILE` | `/run/secrets/secret_key` | Path to session key file (Docker secret) |
| `SECRET_KEY` | — | Direct key override (dev only; falls back to ephemeral if neither set) |
| `SQLALCHEMY_DATABASE_URI` | `sqlite:///app.db` | DB connection string |
| `LMSTUDIO_API_BASE` | `http://127.0.0.1:1234/v1` (dev) / `http://host.docker.internal:1234/v1` (Docker) | LM Studio endpoint |
| `LMSTUDIO_MODEL` | `google/gemma-3-1b` | Default model name |
| `LMSTUDIO_TIMEOUT` | `300` | LLM request timeout (seconds) |
| `ASK_PROFE_SESSION_SECONDS` | `300` | Chat session duration |
| `UPLOAD_DIR` | `<instance_path>/uploads` | File upload directory |
| `MAX_CONTENT_LENGTH` | 50 MB | Max upload size |

---

## Data Persistence

| Action | Data |
|---|---|
| `docker compose up --build` | Survives (volume untouched) |
| `docker compose down` + `up` | Survives |
| `docker compose down -v` | Lost (volume deleted) |
| New deploy with model schema changes | Risk — no migration system |

File uploads (`NoteSourceFile.data`) are stored as blobs inside PostgreSQL, so they live in the same volume and require no separate mount.

---

## Testing

**Framework:** pytest  
**File:** [tests/test_basic.py](tests/test_basic.py)

**Fixtures:**
- `flask_app` — Ephemeral SQLite DB in tmpdir; sets `LMSTUDIO_TIMEOUT=1`
- `authed_client` — Pre-registers user "ada" with profile, subject, and exam

**Test coverage:**
- Auth: dashboard login requirement, dashboard rendering
- Ask Profe: redirect when busy, history isolation per user
- Notes CRUD: create, list, edit (with subject change), delete
- Integration: setup enforcement, flash message formatting

---

## Dependencies

**Python (`requirements.txt`):**
```
Flask
gunicorn
Flask-SQLAlchemy
Flask-Login
Flask-WTF          # CSRF protection
requests
PyPDF2
python-pptx
psycopg2-binary    # PostgreSQL driver
```

**Node (`package.json`):**
```
sass ^1.95.0       # SCSS compiler (devDependency)
```

---

## Security Posture

| Area | Status |
|---|---|
| CSRF protection | Flask-WTF on all POST forms |
| Session key | Docker secret (`SECRET_KEY_FILE`); ephemeral fallback in dev |
| Password hashing | werkzeug pbkdf2:sha256, salt_length=16 |
| Multi-worker session consistency | All workers read same `SECRET_KEY_FILE` independently |
| DB connection health after fork | `pool_pre_ping=True` for PostgreSQL |
| `app.db` in git | Removed (gitignored) |
| Rate limiting | Not implemented |
| File blobs in DB | Up to 50 MB per file stored as `LargeBinary` |
| Schema migrations | Manual (`ensure_profile_schema`); no Flask-Migrate |
| `POSTGRES_PASSWORD` in docker-compose | Docker secret (`POSTGRES_PASSWORD_FILE`) |

---

## Notable Design Decisions

- **Monolithic `__init__.py`** (~3,573 lines) — all routes and business logic in one file. Would benefit from Flask blueprints as the codebase grows.
- **DB-based job queue** — no Redis/Celery dependency; the `Job` table + background thread is self-contained. Trade-off: polling overhead, no distributed workers.
- **`ProfeSessionLock` as DB mutex** — time-based session slots prevent concurrent AI tutor use without needing Redis or an external lock service.
- **File blobs in DB** — `NoteSourceFile.data` stores raw file bytes as `LargeBinary`. Simple but can inflate DB size significantly at scale.
- **`--preload` in Gunicorn** — ensures `create_app()` runs once in master before forking, so `SECRET_KEY` is identical across all workers.
- **`host.docker.internal` for LM Studio** — allows the containerized app to reach the host's LM Studio server on Linux via Docker's `host-gateway`.

---

*Updated: 2026-05-19*
