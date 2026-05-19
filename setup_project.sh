#!/usr/bin/env bash
set -euo pipefail

### CONFIG ###

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

##################################
# 0b. Ensure Docker Compose V2   #
##################################

if ! docker compose version >/dev/null 2>&1; then
  echo "==> Docker Compose V2 not found, installing as CLI plugin..."
  DOCKER_CONFIG="${DOCKER_CONFIG:-$HOME/.docker}"
  mkdir -p "$DOCKER_CONFIG/cli-plugins"
  curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
    -o "$DOCKER_CONFIG/cli-plugins/docker-compose"
  chmod +x "$DOCKER_CONFIG/cli-plugins/docker-compose"
  echo "   -> Installed: $(docker compose version)"
else
  echo "==> Docker Compose V2 already available: $(docker compose version)"
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

##################################
# 2. Generate Docker secrets     #
##################################

mkdir -p secrets

if [ ! -f "secrets/secret_key.txt" ]; then
  echo "==> Generating SECRET_KEY..."
  python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/secret_key.txt
  echo "   -> secrets/secret_key.txt created"
else
  echo "==> secrets/secret_key.txt already exists, skipping"
fi

if [ ! -f "secrets/postgres_password.txt" ]; then
  echo "==> Generating POSTGRES_PASSWORD..."
  python3 -c "import secrets; print(secrets.token_hex(24))" > secrets/postgres_password.txt
  echo "   -> secrets/postgres_password.txt created"
else
  echo "==> secrets/postgres_password.txt already exists, skipping"
fi

#################################
# 3. Create & activate venv     #
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
# 4. Install Python dependencies #
#################################

echo "==> Installing Python dependencies from requirements.txt..."
python -m pip install --upgrade pip
pip install -r requirements.txt

#################################
# 5. Install Node deps & build CSS #
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
# 6. Run Python tests  #
########################

echo "==> Running tests with pytest..."
if ! pytest; then
  echo "!! Tests failed. Script will continue, but you should fix tests before deploying."
fi

####################################
# 7. Build and start with Compose  #
####################################

echo "==> Building and starting services with Docker Compose..."
docker compose up --build -d

echo "==> Waiting for app to be ready..."
for i in $(seq 1 20); do
  if curl -s -o /dev/null -w "%{http_code}" http://localhost:5000 | grep -qE "^(200|302)"; then
    echo "   -> App is up!"
    break
  fi
  sleep 2
  if [ "$i" -eq 20 ]; then
    echo "   -> App did not respond after 40s. Check logs with: docker compose logs app"
  fi
done

#################################
# 8. Final instructions summary #
#################################

cat <<EOF

========================================================
Setup complete for project at:
  $PROJECT_ROOT
========================================================

The app is running at:
  http://localhost:5000

Useful commands:

  # View live logs
  docker compose logs -f

  # Stop containers (data is preserved)
  docker compose down

  # Stop and delete all data
  docker compose down -v

  # Rebuild after code changes
  docker compose up --build

  # Local dev (without Docker)
  source .venv/bin/activate
  export FLASK_APP=app FLASK_RUN_HOST=0.0.0.0
  flask run

  # Run tests
  pytest

  # Rebuild CSS after editing SCSS
  npm run build-css

========================================================
IMPORTANT: secrets/ contains generated keys.
They are gitignored and must not be committed.
If you delete them, recreate them with:
  python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/secret_key.txt
  python3 -c "import secrets; print(secrets.token_hex(24))" > secrets/postgres_password.txt
Then run: docker compose down -v && docker compose up --build
========================================================

NOTE: If 'docker' commands fail with a permissions error,
log out and log back in so the 'docker' group change
takes effect, then try again.
========================================================

EOF
