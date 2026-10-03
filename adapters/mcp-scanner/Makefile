IMAGE ?= ghcr.io/sira-labs/khandaq-adapter-mcp-scanner:4.8.5
.PHONY: build contract-test
build:
	docker build -t $(IMAGE) .
contract-test:
	pip install -q jsonschema pytest && pytest --import-mode=importlib tests -q
