FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_DEFAULT_TIMEOUT=120
WORKDIR /build
COPY pyproject.toml requirements.lock LICENSE ./
RUN pip install --upgrade "pip>=26.2" && pip wheel --wheel-dir /wheels --require-hashes -r requirements.lock
COPY app ./app
RUN pip wheel --wheel-dir /wheels --no-deps .

FROM python:3.12-slim AS production
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DEFAULT_TIMEOUT=120
WORKDIR /app
RUN pip install --upgrade "pip>=26.2"
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links=/wheels mydesk-server && \
    rm -rf /wheels && useradd --create-home --uid 1000 mydesk && chown mydesk /app
USER mydesk
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import httpx; httpx.get('http://127.0.0.1:8000/api/health', headers={'X-Forwarded-Proto':'https'}).raise_for_status()"
CMD ["python", "-m", "app.server"]
