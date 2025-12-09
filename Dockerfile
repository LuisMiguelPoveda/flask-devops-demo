# 1) Base image
FROM python:3.12-slim

# 2) Environment
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 3) Workdir
WORKDIR /code

# 4) Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5) Copy project files
COPY . .

# 6) Expose port
EXPOSE 5000

# 7) Run with gunicorn using the app factory
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:create_app()"]
