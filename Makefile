PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/sbin
LIBDIR ?= $(PREFIX)/lib/net-tap

export PYTHONDONTWRITEBYTECODE = 1
export PATH := $(HOME)/.local/bin:$(PATH)

UNAME_S := $(shell uname -s)
CC ?= gcc

ifeq ($(UNAME_S),Linux)
WATERMARK_LIB = lib/libnettap_watermark.so
CFLAGS_SHARED = -shared -fPIC -Wl,-soname,libnettap_watermark.so
LDFLAGS_SHARED = -ldl -lpthread
else ifeq ($(UNAME_S),Darwin)
WATERMARK_LIB = lib/libnettap_watermark.dylib
CFLAGS_SHARED = -dynamiclib -fPIC
LDFLAGS_SHARED = -ldl -lpthread
endif

TEST_WATERMARK_BIN = tests/test_socket_watermark

all: $(WATERMARK_LIB) $(TEST_WATERMARK_BIN) lint

$(WATERMARK_LIB): lib/libnettap_watermark.c
	$(CC) $(CFLAGS) -O2 -Wall -Wextra $(CFLAGS_SHARED) $< -o $@ $(LDFLAGS_SHARED)

$(TEST_WATERMARK_BIN): tests/test_socket_watermark.c
	$(CC) $(CFLAGS) -O2 -Wall $< -o $@

install: $(WATERMARK_LIB)
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 bin/net-tap.sh $(DESTDIR)$(BINDIR)/net-tap
	install -m 644 lib/*.sh $(DESTDIR)$(LIBDIR)/
	install -m 755 lib/*.py $(DESTDIR)$(LIBDIR)/
	install -m 755 $(WATERMARK_LIB) $(DESTDIR)$(LIBDIR)/

installcheck:
	@echo "Checking installed net-tap binary..."
	@$(DESTDIR)$(BINDIR)/net-tap -h >/dev/null && echo "installcheck passed!"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/net-tap
	rm -rf $(DESTDIR)$(LIBDIR)

lint:
	@echo "Running ShellCheck on scripts..."
	@if command -v shellcheck >/dev/null 2>&1; then \
		set -e; \
		shellcheck bin/net-tap.sh lib/*.sh tests/run_tests.sh && echo "ShellCheck passed!"; \
	else \
		echo "Error: shellcheck is not installed. Failing lint step." >&2; \
		exit 1; \
	fi
	@echo "Checking Python fixture generator and probe syntax..."
	@if command -v python3 >/dev/null 2>&1; then \
		python3 -B -c "import ast; [ast.parse(open(f).read()) for f in ['tests/generate_carrier_fixtures.py', 'lib/probe.py', 'tests/test_probe_unit.py']]" && echo "Python syntax passed!"; \
	fi
	@if command -v ruff >/dev/null 2>&1; then \
		ruff check lib/probe.py tests/*.py && echo "Ruff check passed!"; \
	fi
	@if command -v mypy >/dev/null 2>&1; then \
		mypy --ignore-missing-imports lib/probe.py && echo "Mypy type check passed!"; \
	fi
	@echo "Validating Draft-7 analysis JSON schema..."
	@if command -v python3 >/dev/null 2>&1; then \
		python3 -B -c "import json, jsonschema; s = json.load(open('tests/schema/analysis.schema.json')); jsonschema.Draft7Validator.check_schema(s); print('Schema valid!')"; \
	fi

fixtures:
	@echo "Regenerating synthetic carrier fixtures..."
	@if command -v python3 >/dev/null 2>&1; then \
		python3 -B tests/generate_carrier_fixtures.py; \
	else \
		echo "Python 3 is required to generate fixtures." >&2; \
		exit 1; \
	fi

test: $(WATERMARK_LIB) $(TEST_WATERMARK_BIN) lint fixtures
	@echo "Running Python probe mock unit tests..."
	@python3 -B tests/test_probe_unit.py
	@echo "Running automated compliance and unit tests..."
	@bash tests/run_tests.sh

SUDO ?= $(shell if [ "$$(id -u)" -ne 0 ]; then echo sudo; fi)

test-integration: $(WATERMARK_LIB) $(TEST_WATERMARK_BIN) lint fixtures
	@echo "Running integration tests (requires root)..."
	@$(SUDO) PYTHONDONTWRITEBYTECODE=1 bash tests/run_tests.sh

clean:
	@rm -rf lib/__pycache__ tests/__pycache__
	@rm -f lib/*.so lib/*.dylib tests/test_socket_watermark
	@find /tmp -maxdepth 1 -user "$$(id -u)" \( -name "net-tap-*" -o -name "net_tap_*" -o -name "wpa_*" \) -exec rm -rf {} + 2>/dev/null || true

.PHONY: all install installcheck uninstall lint fixtures test test-integration clean
