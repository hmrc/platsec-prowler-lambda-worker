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

.PHONY: ecr-login
ecr-login:
	aws ecr get-login-password --region eu-west-2 --profile platsec_dev | docker login --username AWS --password-stdin 132732819912.dkr.ecr.eu-west-2.amazonaws.com/platsec-prowler