# Define Python versions
PYTHON_VERSIONS := 3.10 3.11 3.12

# Default target
all: build

# Build target for all Python versions
build:
	@for version in $(PYTHON_VERSIONS); do \
		echo "Building for Python $$version"; \
		maturin build --release --interpreter python$$version; \
	done

# Clean target to remove build artifacts
clean:
	rm -rf target/


# Install target in venv
develop:
	maturin develop --uv

# Run tests
test:
	maturin develop --uv
	cargo test
	pytest


# Help target to explain usage
help:
	@echo "Available commands:"
	@echo "  make all        - Build the project for all Python versions"
	@echo "  make build      - Build the project for all Python versions"
	@echo "  make clean      - Remove build artifacts"
	@echo "  make develop	- Install the project in development mode"
	@echo "  make test       - Run tests"
	@echo "  make help       - Display this help message"
	

.PHONY: all build clean develop test help