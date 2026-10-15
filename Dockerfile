# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE=python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170
FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

FROM base AS deps
COPY requirements.txt /tmp/
RUN pip install --prefix=/install -r /tmp/requirements.txt

FROM base
COPY --from=deps /install /usr/local
WORKDIR /srv
COPY app ./app
# pip wird zur Laufzeit nicht gebraucht und bringt eigene, oft veraltete Pakete mit (pip/_vendor)
RUN python -m pip uninstall -y pip \
 && useradd --uid 10001 --no-create-home --home-dir /data --shell /usr/sbin/nologin asnb \
 && mkdir -p /data && chown 10001:10001 /data
ENV DATA_DIR=/data
USER 10001
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"]
# Genau ein Worker: der Scheduler laeuft im Prozess
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-server-header"]
