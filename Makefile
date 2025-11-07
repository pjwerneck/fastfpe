# Define Python versions
PYTHON_VERSIONS := 3.8 3.9 3.10 3.11 3.12 3.13 3.14

# Default target
all: build

# Build target for all Python versions
# Note: Using abi3, one wheel per platform works for 3.8–3.14. We keep the loop
# but set PYO3_USE_ABI3_FORWARD_COMPATIBILITY to allow 3.14 builds with PyO3 0.22.
build:
	@for version in $(PYTHON_VERSIONS); do \
		echo "Building for Python $$version"; \
		PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 maturin build --release --interpreter python$$version; \
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


# Run tests for all Python versions
test-all:
	@for version in $(PYTHON_VERSIONS); do \
		echo "Testing for Python $$version"; \
		PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 maturin develop --release --uv; \
		uv run --python $$version --isolated --with-editable '.[test]' pytest; \
	done



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