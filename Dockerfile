# Entra Agent Inventory MCP server - container image (for example for Azure Container Apps).
# Runs as a non-root user; health check uses Python, so no curl is needed in a slim image.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_TRANSPORT=streamable-http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY entra_agent_inventory ./entra_agent_inventory

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin mcp
USER 10001

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

# The server refuses to start on 0.0.0.0 without auth. Set MCP_AUTH_MODE=entra
# (with MCP_AUTH_TENANT_ID, MCP_AUTH_AUDIENCE, MCP_RESOURCE_URL) when you host it.
CMD ["python", "-m", "entra_agent_inventory"]
