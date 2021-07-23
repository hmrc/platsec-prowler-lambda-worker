PIPENV_RUN = docker run --interactive --rm pipenv

.PHONY: docker-pipenv
docker-pipenv:
	docker build \
		--tag pipenv \
		--target pipenv \
		.

.PHONY: container-release
container-release:
	docker build \
		--tag container-release:local \
		--target container-release \
		.

.PHONY: fmt-check
fmt-check: docker-pipenv
	$(PIPENV_RUN) black .

.PHONY: test
test: docker-pipenv
	$(PIPENV_RUN) pytest \
		-v \
		-p no:cacheprovider \
		--no-header \
		--cov=src \
		--cov-fail-under=85 \
		--no-cov-on-fail

.PHONY: ecr-login
ecr-login:
	aws ecr get-login-password --region eu-west-2 --profile platsec_dev | docker login --username AWS --password-stdin 132732819912.dkr.ecr.eu-west-2.amazonaws.com/platsec-prowler