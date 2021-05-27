DOCKER_RUN = docker run --interactive --rm platsec/prowler:local

.PHONY: docker-build
docker-build:
	@docker build -t platsec/prowler:local -f BuildEnv . > /dev/null

.PHONY: fmt-check
fmt-check: docker-build
	@$(DOCKER_RUN) black .

.PHONY: test
test: docker-build
	@$(DOCKER_RUN) pytest \
		--setup-show \
		-v \
		-p no:cacheprovider \
		--no-header \
		--cov=src
		--cov-fail-under=100 \
		--no-cov-on-fail