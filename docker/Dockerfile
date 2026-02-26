# Multi-stage build: Node (dashboard) -> Python (runtime)

# --- Stage 1: Build React dashboard ---
FROM node:20-slim AS dashboard-build
WORKDIR /app/dashboard
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm ci --no-audit
COPY dashboard/ ./
RUN npm run build

# --- Stage 2: Python runtime ---
FROM python:3.12-slim AS runtime
LABEL maintainer="Oubliette Security <info@oubliettesecurity.com>"
LABEL description="Oubliette Dungeon - AI Red Team Engine"

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python package
COPY pyproject.toml LICENSE README.md ./
COPY src/ src/
RUN pip install --no-cache-dir ".[flask,pdf]"

# Copy built dashboard
COPY --from=dashboard-build /app/dashboard/dist/ /app/dashboard/dist/

# Create non-root user
RUN groupadd -r dungeon && useradd -r -g dungeon -d /app -s /sbin/nologin dungeon
RUN mkdir -p /app/redteam_results && chown -R dungeon:dungeon /app

USER dungeon

# Environment defaults
ENV DUNGEON_DB_DIR=/app/redteam_results
ENV DUNGEON_TIMEOUT=30

EXPOSE 8666

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8666/api/dungeon/status || exit 1

ENTRYPOINT ["oubliette-dungeon"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8666"]
