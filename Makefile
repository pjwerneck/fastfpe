# Default target
all: build

# Build a single abi3 wheel for the current platform
# With abi3 (pyproject + Cargo enable abi3-py38), one wheel works for CPython 3.8+ (up to 3.14+).
build:
	PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 maturin build --release

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


# Run tests for multiple Python versions (optional; requires interpreters available via uv)
test-all:
	@for version in 3.8 3.9 3.10 3.11 3.12 3.13 3.14; do \
		echo "Testing for Python $$version"; \
		uv run --python $$version --isolated --with-editable '.[test]' pytest; \
	done



# Help target to explain usage
help:
	@echo "Available commands:"
	@echo "  make all        - Build a single abi3 wheel (3.8+) for this platform"
	@echo "  make build      - Build a single abi3 wheel (3.8+) for this platform"
	@echo "  make clean      - Remove build artifacts"
	@echo "  make develop	- Install the project in development mode"
	@echo "  make test       - Run tests"
	@echo "  make test-all   - Run tests across multiple Python versions (via uv)"
	@echo "  make help       - Display this help message"
	

.PHONY: all build clean develop test help