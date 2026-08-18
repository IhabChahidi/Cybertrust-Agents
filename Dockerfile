# Generator API image (web/generator_api.py + the rest of the existing
# mcp_server/ pipeline and CISO dashboard, unchanged). Does NOT bundle the
# llama.cpp server or the GGUF model -- see docker-compose.yml's separate
# llama-generator service and the "Do not automatically download a
# multi-gigabyte model" constraint (spec section 17).

FROM python:3.13-slim

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --home /app app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mcp_server ./mcp_server
COPY web ./web
COPY config ./config
COPY catalogue ./catalogue

# audit_journal/ is a separate top-level directory (NOT under mcp_server/,
# which is Python source) so a persistent named volume can be mounted there
# in docker-compose.yml without shadowing any package file.
RUN mkdir -p /app/mcp_server/rag_store /app/audit_journal && chown -R app:app /app

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health/live', timeout=3).status==200 else 1)"

CMD ["uvicorn", "web.backend:app", "--host", "0.0.0.0", "--port", "8000"]
