IMAGE ?= ghcr.io/sira-labs/khandaq-adapter-art:1.20.1
.PHONY: build contract-test
build:
	docker build -t $(IMAGE) .
contract-test:
	pip install -q jsonschema pytest -r requirements.txt && pytest --import-mode=importlib tests -q
