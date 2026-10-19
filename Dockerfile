FROM python:3.11.9-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples

# SafePatch has no third-party runtime dependencies. Compile the application
# during the image build so broken source fails before deployment.
RUN python -m compileall -q src

EXPOSE 10000

CMD ["sh", "-c", "python -m safepatch web --host 0.0.0.0 --port ${PORT:-10000}"]
