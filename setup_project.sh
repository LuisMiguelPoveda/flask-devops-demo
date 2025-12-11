#!/usr/bin/env bash
set -euo pipefail

### CONFIG ###

# GitHub repo URL (change here if you ever rename/move it)
REPO_URL="https://github.com/LuisMiguelPoveda/flask-devops-demo.git"
PROJECT_DIR="flask-devops-demo"

#########################
# 0. System preparation #
#########################

echo "==> Updating apt and installing base packages..."
sudo apt update

sudo apt install -y \
  python3-full \
  python3-venv \
  python3-pip \
  python-is-python3 \
  git \
  curl \
  nodejs \
  npm \
  docker.io

echo "==> Ensuring current user is in the docker group..."
if ! groups "$USER" | grep -q "\bdocker\b"; then
  sudo usermod -aG docker "$USER" || true
  echo "   -> Added $USER to docker group. You may need to log out and log back in"
  echo "      before 'docker' commands work without sudo."
fi

#########################
# 1. Clone / update repo #
#########################

cd "${HOME}/Desktop"

if [ -d "$PROJECT_DIR/.git" ]; then
  echo "==> Project directory already exists, pulling latest changes..."
  cd "$PROJECT_DIR"
  git pull
else
  echo "==> Cloning repository: $REPO_URL"
  git clone "$REPO_URL"
  cd "$PROJECT_DIR"
fi

PROJECT_ROOT="$(pwd)"
echo "==> Working in $PROJECT_ROOT"

#################################
# 2. Create & activate venv     #
#################################

if [ ! -d ".venv" ]; then
  echo "==> Creating Python virtual environment (.venv)..."
  python -m venv .venv
else
  echo "==> Virtual environment (.venv) already exists, reusing it..."
fi

# shellcheck source=/dev/null
source .venv/bin/activate
echo "==> Using Python: $(python --version)"

#################################
# 3. Install Python dependencies #
#################################

if [ -f "requirements.txt" ]; then
  echo "==> Installing Python dependencies from requirements.txt..."
  python -m pip install --upgrade pip
  pip install -r requirements.txt
else
  echo "!! requirements.txt not found, skipping Python deps install"
fi

#################################
# 4. Install Node deps & build CSS #
#################################

if [ -f "package.json" ]; then
  echo "==> Installing Node dependencies (npm install)..."
  npm install

  echo "==> Building CSS from Sass (npm run build-css)..."
  npm run build-css
else
  echo "!! package.json not found, skipping npm install and CSS build"
fi

########################
# 5. Run Python tests  #
########################

if command -v pytest >/dev/null 2>&1; then
  echo "==> Running tests with pytest..."
  if ! pytest; then
    echo "!! Tests failed (pytest returned non-zero)."
    echo "   Script will continue, but you should fix tests."
  fi
else
  echo "==> Installing pytest..."
  pip install pytest
  echo "==> Running tests with pytest..."
  if ! pytest; then
    echo "!! Tests failed (pytest returned non-zero)."
    echo "   Script will continue, but you should fix tests."
  fi
fi

########################################
# 6. Optionally create an initial user #
########################################

if [ -f "create_user.py" ]; then
  echo
  read -r -p "Do you want to create an initial user now? [y/N] " CREATE_USER
  if [[ "${CREATE_USER:-N}" =~ ^[Yy]$ ]]; then
    echo "==> Running create_user.py..."
    python create_user.py
  else
    echo "==> Skipping user creation for now."
  fi
else
  echo "!! create_user.py not found, skipping user creation step."
fi

########################
# 7. Build Docker image #
########################

if command -v docker >/dev/null 2>&1; then
  echo "==> Building Docker image 'flask-devops-demo'..."
  if ! docker build -t flask-devops-demo .; then
    echo "!! Docker build failed. Check Docker daemon and Dockerfile."
  fi
else
  echo "!! docker command not found. Is Docker installed correctly?"
fi

#################################
# 8. Final instructions summary #
#################################

cat <<EOF

========================================================
Setup complete for project at:
  $PROJECT_ROOT
========================================================

Common commands you'll use next:

# Activate virtual environment
cd "$PROJECT_ROOT"
source .venv/bin/activate

# Run Flask app (dev mode)
export FLASK_APP=app
export FLASK_RUN_HOST=0.0.0.0
flask run

# Run tests
pytest

# Rebuild CSS after editing SCSS
npm run build-css

# Build Docker image (if you change code)
docker build -t flask-devops-demo .

# Run Docker container
docker run --rm -p 5000:5000 flask-devops-demo

Then open in browser:
  http://127.0.0.1:5000
or
  http://localhost:5000

========================================================
NOTE: If 'docker' commands fail with a permissions error,
log out and log back in so the 'docker' group change
takes effect, then try again.
========================================================

EOF
