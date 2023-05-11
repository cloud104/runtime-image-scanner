CONTAINER_NAME=runtime-image-scanner
REGISTRY=$(CONTAINER_NAME)
VERSION_FILE=version.py
TRIVY_VERSION=0.41.0

patch: build-patch git-push
minor: build-minor git-push
major: build-major git-push

export LOG_LEVEL=invalid

trivy:
	wget https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz -O /tmp/trivy.tgz
	tar -xvzf /tmp/trivy.tgz -C /tmp

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