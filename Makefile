DOCKER_RUN = docker run --interactive --rm platsec/prowler:local

.PHONY: docker-build
docker-build:
	docker build -t platsec/prowler:local -f BuildEnv .

.PHONY: fmt-check
fmt-check: docker-build
	$(DOCKER_RUN) black .

.PHONY: test
test: docker-build
	$(DOCKER_RUN) pytest \
		-v \
		-p no:cacheprovider \
		--no-header \
		--cov=src \
		--cov-fail-under=90 \
		--no-cov-on-fail
