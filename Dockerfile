# Image for the controlled authentication service and the test harness.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . psutil

COPY experiments ./experiments

EXPOSE 8000
# Default: run the auth service. The harness service overrides the command.
CMD ["uvicorn", "gr9_refresh_token_rotation.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
