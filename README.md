# DEMS - Digital Evidence Management System

FastAPI + PostgreSQL (SQLite locally) + plain HTML/JS. No build step.

## Run locally
    pip install -r requirements.txt
    uvicorn app.main:app --reload
Open http://localhost:8000 and sign in with `admin` / `admin123`.

## Deploy on Render
1. Push this folder to a GitHub repo.
2. Render dashboard > New > Blueprint > pick the repo. `render.yaml` creates the web service and a Postgres database.
3. After deploy, open the service > Environment, copy `ADMIN_PASSWORD`, and sign in as `admin`.
4. Do NOT change `SECRET_KEY` later. It is the encryption key, and old files become unreadable.
