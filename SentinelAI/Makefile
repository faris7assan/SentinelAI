# ============================================================
# SentinelAI — Makefile
# ============================================================
.PHONY: help setup start-local start-backend start-desktop health test lint format clean

PYTHON ?= python
ROOT := $(CURDIR)
DESKTOP_APP := $(ROOT)/../SentinelAI_Desktop_App/desktop-app/main.py

# Colors
GREEN  = \033[0;32m
YELLOW = \033[1;33m
RED    = \033[0;31m
NC     = \033[0m

help: ## Show this help message
	@echo "$(GREEN)SentinelAI Local Dev Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# ─── Local Dev ───────────────────────────────────────────────
setup: ## Create local config and data folders
	@echo "$(YELLOW)Preparing SentinelAI local dev...$(NC)"
	@[ -f .env ] || cp .env.example .env && echo "$(GREEN)✅ .env created$(NC)"
	@mkdir -p data/local-dev logs
	@echo "$(GREEN)✅ Local setup complete$(NC)"

start-local: ## Start the local backend and desktop app
	$(PYTHON) scripts/start_local_dev.py

start-backend: ## Start the local backend only
	$(PYTHON) scripts/start_local_dev.py --backend-only

start-desktop: ## Start the desktop app in local mode
	$(PYTHON) $(DESKTOP_APP)

health: ## Check the local backend health
	@curl -s http://127.0.0.1:8000/health | python -m json.tool

# ─── Testing ─────────────────────────────────────────────────
test: ## Run all Python tests
	pytest tests/ -v --tb=short --color=yes

test-unit: ## Run unit tests only
	pytest tests/ -v -m unit --tb=short

test-security: ## Run security-specific tests
	pytest tests/ -v -m security --tb=short

test-coverage: ## Run tests with coverage report
	pytest tests/ --cov=backend --cov-report=html --cov-report=term-missing

# ─── Code Quality ────────────────────────────────────────────
lint: ## Run linters (ruff + black)
	ruff check backend/
	black --check backend/

format: ## Auto-format Python code
	black backend/
	ruff check --fix backend/

lint-go: ## Lint Go code
	cd backend/go-metrics-service && go vet ./...

security-scan: ## Run security scans (bandit)
	bandit -r backend/ -ll -q

format: ## Auto-format Python code
	black backend/ scripts/
	ruff check --fix backend/ scripts/

# ─── Cleanup ─────────────────────────────────────────────────
clean: ## Remove local dev caches and generated files
	rm -rf .pytest_cache .ruff_cache data/local-dev/*.json logs
	@echo "$(GREEN)✅ Local cleanup complete$(NC)"
