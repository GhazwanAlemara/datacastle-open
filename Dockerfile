FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir -e .

EXPOSE 8090
CMD ["datacastle-open", "serve", "--port", "8090"]
