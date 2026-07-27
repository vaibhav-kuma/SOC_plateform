.PHONY: help dev build test lint clean migrate docker-up docker-down

help:
	@echo "SOC Platform Commands:"
	@echo "  make dev          Start all services in development mode"
	@echo "  make build        Build all Docker images"
	@echo "  make test         Run all tests"
	@echo "  make lint         Run linters"
	@echo "  make clean        Clean build artifacts"
	@echo "  make migrate      Run database migrations"
	@echo "  make docker-up    Start all services with Docker Compose"
	@echo "  make docker-down  Stop all Docker services"

dev:
	cd backend && uvicorn core.main:app --reload --host 0.0.0.0 --port 8000

build:
	docker-compose -f infrastructure/docker/docker-compose.yml build

test:
	cd backend && pytest --cov=. --cov-report=term-missing

lint:
	cd backend && ruff check . && mypy .
	cd frontend && npm run lint

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name "node_modules" -exec rm -rf {} +
	find . -type d -name "dist" -exec rm -rf {} +

migrate:
	cd backend && alembic upgrade head

docker-up:
	docker-compose -f infrastructure/docker/docker-compose.yml up -d

docker-down:
	docker-compose -f infrastructure/docker/docker-compose.yml down
