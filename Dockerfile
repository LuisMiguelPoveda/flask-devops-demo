# =========================
# Stage 1: Build CSS (Sass)
# =========================
FROM node:22-alpine AS css-builder

WORKDIR /app

# Copiamos solo lo necesario para npm
COPY package.json package-lock.json* ./

RUN npm install

# Copiamos los archivos SCSS
COPY app/static/scss ./app/static/scss

# Compilamos SCSS -> CSS
RUN npx sass app/static/scss:app/static/css --no-source-map --style=compressed


# =========================
# Stage 2: Python runtime
# =========================
FROM python:3.12-slim

WORKDIR /code

# Instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código de la app
COPY app ./app

# Copiar CSS compilado desde el stage anterior
COPY --from=css-builder /app/app/static/css ./app/static/css

EXPOSE 5000

# Gunicorn con timeout largo para LM Studio y más concurrencia
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--timeout", "300", "--workers", "2", "--threads", "4", "app:create_app()"]
