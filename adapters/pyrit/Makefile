IMAGE ?= ghcr.io/sira-labs/khandaq-adapter-pyrit:1.1.0
.PHONY: build contract-test
build:
	docker build -t $(IMAGE) .
contract-test:
	pip install -q jsonschema pytest && pytest --import-mode=importlib tests -q
