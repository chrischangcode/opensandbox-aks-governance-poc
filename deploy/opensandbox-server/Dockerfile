FROM python:3.12-slim-bookworm

ARG OPENSANDBOX_SERVER_VERSION=0.2.0

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN python -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      "opensandbox-server==${OPENSANDBOX_SERVER_VERSION}"

WORKDIR /app

COPY deploy/opensandbox-server/k8s/batchsandbox-template.yaml ./batchsandbox-template.yaml

EXPOSE 8080

ENTRYPOINT ["opensandbox-server"]
CMD ["--config", "/app/sandbox.toml"]
