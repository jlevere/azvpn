# Convenience wrappers around the Dockerfile cross-compile.
#
# Targets:
#   make build         — invokes docker buildx build, drops openvpn.exe in ./out
#   make clean         — removes ./out
#   make strict        — same as build but enforces hash pins in SHASUMS256.txt
#
# Run from the worktree root (this Makefile is also invokable from
# its own directory via `make -C packaging/windows/build-openvpn`).

# Allow invocation from either the worktree root or this dir.
REPO_ROOT := $(shell git rev-parse --show-toplevel 2>/dev/null || pwd)
HERE      := $(REPO_ROOT)/packaging/windows/build-openvpn
OUT       := $(HERE)/out

DOCKER ?= docker
BUILDX_PLATFORM ?= linux/amd64

.PHONY: build strict clean

build:
	mkdir -p $(OUT)
	$(DOCKER) buildx build \
	    --platform $(BUILDX_PLATFORM) \
	    --output type=local,dest=$(OUT) \
	    -f $(HERE)/Dockerfile \
	    $(REPO_ROOT)
	@echo
	@echo "artifact: $(OUT)/openvpn.exe"
	@echo
	@cat $(OUT)/build-info.txt 2>/dev/null || true

# Same as build but the in-container build refuses to proceed on
# hash drift. Used by CI after SHASUMS256.txt has real (non-zero) hashes.
strict:
	mkdir -p $(OUT)
	$(DOCKER) buildx build \
	    --platform $(BUILDX_PLATFORM) \
	    --build-arg STRICT_HASHES=1 \
	    --output type=local,dest=$(OUT) \
	    -f $(HERE)/Dockerfile \
	    $(REPO_ROOT)

clean:
	rm -rf $(OUT)
