FROM public.ecr.aws/lambda/python:3.8 AS base
LABEL maintainer="PlatSec"
LABEL description="Prowler and dependencies for AWS Lambda"
ENV JQ_VERSION='1.5'
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN yum install wget unzip -y \
    && yum clean all \
    && rm -rf /var/cache/yum \
    && wget https://github.com/stedolan/jq/releases/download/jq-${JQ_VERSION}/jq-linux64 -O /usr/bin/jq \
    && wget https://raw.githubusercontent.com/stedolan/jq/master/sig/jq-release.key -O- \
        | gpg --import \
    && gpg --verify <(wget https://raw.githubusercontent.com/stedolan/jq/master/sig/v${JQ_VERSION}/jq-linux64.asc -O-) /usr/bin/jq \
    && chmod +x /usr/bin/jq \
    && pip install \
        awscli \
        pipenv

FROM base AS container-release
COPY install_prowler.sh Pipfile.lock ./
RUN bash install_prowler.sh && pipenv install --ignore-pipfile
COPY lambda_function.py ./
COPY src ./src
COPY custom_groups/* ./src/platsec/compliance/lib/prowler/groups/
CMD ["lambda_function.lambda_handler"]

FROM base AS pipenv
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN yum install shadow-utils -y
RUN /usr/sbin/useradd -ms /bin/bash prowler
WORKDIR /home/prowler/Development/PythonProwlerImplementation
COPY install_prowler.sh Pipfile.lock ./
RUN chown -R prowler:prowler /home/prowler/Development/PythonProwlerImplementation
USER prowler
RUN bash install_prowler.sh && pipenv install --ignore-pipfile  --dev
COPY --chown=prowler:prowler ./ ./
ENTRYPOINT ["/var/lang/bin/pipenv", "run"]
