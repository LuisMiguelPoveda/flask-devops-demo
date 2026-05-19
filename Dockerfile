# =========================
# Stage 1: Build CSS (Sass)
# =========================
FROM node:22-alpine AS css-builder

WORKDIR /app

COPY package.json package-lock.json* ./

RUN npm install

COPY app/static/scss ./app/static/scss

RUN npx sass app/static/scss:app/static/css --no-source-map --style=compressed


# =========================
# Stage 2: Python runtime
# =========================
FROM python:3.12-slim

WORKDIR /code

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY migrations ./migrations

COPY --from=css-builder /app/app/static/css ./app/static/css

EXPOSE 5000

ENV FLASK_APP=app

CMD ["sh", "-c", "flask db upgrade && gunicorn -b 0.0.0.0:5000 --timeout 300 --workers 2 --threads 4 'app:create_app()'"]
