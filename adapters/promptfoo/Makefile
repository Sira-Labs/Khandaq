IMAGE ?= ghcr.io/sira-labs/khandaq-adapter-promptfoo:0.118.0
.PHONY: build contract-test
build:
	docker build -t $(IMAGE) .
contract-test:
	pip install -q jsonschema pytest && pytest --import-mode=importlib tests -q
