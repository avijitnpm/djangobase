# djangoninja

Django modular-monolith platform.

## Prerequisites

- Python 3.14+
- Git 2.55+
- Docker 29+ and Docker Compose 5.3+ (for later phases)

## Setup

```bash
git clone <repo-url> djangoninja
cd djangoninja
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

## Running

```bash
python manage.py check
python manage.py runserver
```

Environment overrides (optional):

```bash
DJANGO_SECRET_KEY=your-secret DJANGO_DEBUG=False DJANGO_ALLOWED_HOSTS=example.com python manage.py check
```

## Project Status

Phase 1 — Django bootstrap complete. Standard Django project `config` with env-based settings, SQLite for development. No platform or business modules yet.
