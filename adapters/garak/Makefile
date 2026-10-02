# garak adapter (spec 006).
IMAGE ?= ghcr.io/sira-labs/khandaq-adapter-garak:0.17.0

.PHONY: build contract-test
build:
	docker build -t $(IMAGE) .

contract-test:
	pip install -q jsonschema pytest && pytest tests -q
