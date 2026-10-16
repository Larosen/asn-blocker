# syntax=docker/dockerfile:1
# Literal FROM (not an ARG) so Dependabot can keep the digest current
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS base
# No user site-packages: nothing written to the data volume can ever be imported as code
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1 HOME=/tmp \
    PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

FROM base AS deps
COPY requirements.txt /tmp/
# Fully pinned and hash-checked (requirements.txt is compiled from requirements.in)
RUN pip install --prefix=/install --require-hashes --no-deps -r /tmp/requirements.txt

FROM base
COPY --from=deps /install /usr/local
WORKDIR /srv
COPY app ./app
# pip is not needed at runtime and ships its own, often outdated packages (pip/_vendor);
# setuid/setgid bits are removed so no binary in the image can gain privileges
RUN python -m pip uninstall -y pip \
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
 && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin asnb \
 && mkdir -p /data && chown 10001:10001 /data
ENV DATA_DIR=/data
USER 10001
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"]
# Exactly one worker: the scheduler runs in-process
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-server-header", "--no-proxy-headers"]
