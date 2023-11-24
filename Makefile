CONTAINER_NAME=runtime-image-scanner
REGISTRY=$(CONTAINER_NAME)
VERSION_FILE=version.py
#Variable used only to download Trivy locally. For containers, the versions are declared in the Dockerfile.
TRIVY_VERSION=0.47.0

patch: build-patch git-push
minor: build-minor git-push
major: build-major git-push

export LOG_LEVEL=invalid

trivy:
	TRIVY_VERSION=$(TRIVY_VERSION) scripts/download_trivy.sh

test: unit-test test-reports badge min-coverage

unit-test:
	coverage run -m unittest tests.py

test-reports:
	coverage html

badge:
	coverage-badge -fo coverage.svg

min-coverage:
	scripts/min_coverage.sh

build-dev:
	docker build --network host -t $(CONTAINER_NAME):devel .
	@echo "Generated a local docker image with name: $(CONTAINER_NAME):devel"

build-patch:
	bumpversion patch

build-minor:
	bumpversion minor

build-major:
	bumpversion major

build:
	@$(eval VERSION=`cat $(VERSION_FILE) | grep "VERSION"|cut -d"=" -f2 | sed -e 's/"//g' -e 's/ //g'`)
	docker build -t $(REGISTRY):$(VERSION) .

clean-dev:
	docker rmi -f $(CONTAINER_NAME):devel

git-push:
	git push --all origin
	git push --tags origin